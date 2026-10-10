/**
 * Conservative read of npm's `files` field.
 *
 * Returns a predicate that is true for paths the published tarball contains,
 * or undefined when the field is absent or a pattern cannot be parsed exactly.
 * Undefined means "do not filter": scanning a file that npm would omit is
 * safe, omitting a file npm would ship is not.
 *
 * Negated patterns (`!…`) and nested `.npmignore` files are ignored. Both only
 * remove files, so ignoring them keeps the extra file in the scan.
 */

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'] as const

/**
 * npm publishes these from the package root even when `files` omits them.
 * Keeping them is the same bias as ignoring negation: never drop a shipped file.
 */
const ALWAYS_PUBLISHED = /^(?:package\.json|readme|changes|changelog|history|license|licence|notice)(?:\.[^/]+)?$/i

/** Brace expansion, character classes, escapes, or extglob (`*(…)`, `!(…)`). */
const UNSUPPORTED_PATTERN = /[{}\[\]\\]|[+@?!*]\(/

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string')
}

function escapeRegExp(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')
}

/** `*` stays inside one segment; `**` crosses `/`. */
function globToRegExp(pattern: string): RegExp {
  let re = '^'
  let i = 0
  while (i < pattern.length) {
    if (pattern.startsWith('**/', i)) {
      re += '(?:[^/]+/)*'
      i += 3
      continue
    }
    if (pattern.startsWith('**', i)) {
      re += '.*'
      i += 2
      continue
    }
    const ch = pattern[i]
    if (ch === '*') {
      re += '[^/]*'
      i += 1
      continue
    }
    if (ch === '?') {
      re += '[^/]'
      i += 1
      continue
    }
    re += escapeRegExp(ch ?? '')
    i += 1
  }
  return new RegExp(`${re}$`)
}

function normalizePattern(raw: string): string {
  let pattern = raw.trim()
  while (pattern.startsWith('./')) pattern = pattern.slice(2)
  while (pattern.startsWith('/')) pattern = pattern.slice(1)
  while (pattern.endsWith('/')) pattern = pattern.slice(0, -1)
  return pattern
}

function normalizeRel(relPath: string): string {
  let path = relPath.split('\\').join('/')
  while (path.startsWith('./')) path = path.slice(2)
  return path
}

type Compiled =
  | { kind: 'skip' }
  | { kind: 'unsupported' }
  | { kind: 'match'; test: (relPath: string) => boolean }

function compilePattern(raw: string): Compiled {
  const trimmed = raw.trim()
  if (trimmed.startsWith('!')) return { kind: 'skip' }
  if (UNSUPPORTED_PATTERN.test(trimmed)) return { kind: 'unsupported' }
  let pattern = normalizePattern(trimmed)
  if (pattern === '' || pattern === '.') return { kind: 'unsupported' }
  // npm-packlist: `*` un-ignores every path, and a pattern ending in `/*`
  // is rewritten to `/**` before matching. `src*` stays one segment.
  if (pattern === '*') return { kind: 'match', test: () => true }
  if (pattern.endsWith('/*')) pattern += '*'
  if (!/[*?]/.test(pattern)) {
    // File or directory. A listed file has no children, so the prefix only
    // adds entries when the path is actually a directory.
    return {
      kind: 'match',
      test: relPath => relPath === pattern || relPath.startsWith(`${pattern}/`),
    }
  }
  const re = globToRegExp(pattern)
  return { kind: 'match', test: relPath => re.test(relPath) }
}

function shellTokens(command: string): string[] {
  const out: string[] = []
  for (const match of command.matchAll(/"([^"]*)"|'([^']*)'|([^\s;&|]+)/g)) {
    const token = match[1] ?? match[2] ?? match[3] ?? ''
    if (token !== '') out.push(token)
  }
  return out
}

/**
 * Relative files named by install-time scripts. npm does not publish these
 * automatically; the caller still scans them so a script payload is not missed
 * when the pattern match is unsure. `test` and `build` are not install-time.
 */
export function lifecycleScriptPaths(manifest: Record<string, unknown>): string[] {
  const scripts = manifest.scripts
  if (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts)) return []
  const out = new Set<string>()
  for (const key of LIFECYCLE_SCRIPTS) {
    const command = (scripts as Record<string, unknown>)[key]
    if (typeof command !== 'string') continue
    for (const token of shellTokens(command)) {
      if (token.startsWith('-') || token.includes('://') || token.includes('=')) continue
      if (!token.startsWith('.') && !token.includes('/')) continue
      let path = token
      while (path.startsWith('./')) path = path.slice(2)
      if (path === '' || path.startsWith('/') || path.startsWith('../') || path === '..') continue
      out.add(path)
    }
  }
  return [...out]
}

/**
 * True when `relPath` is included by `package.json` `files`, or named by an
 * install-time script. Undefined when `files` is missing or not safely parsed.
 */
export function shippedPredicate(
  manifest: Record<string, unknown>,
): ((relPath: string) => boolean) | undefined {
  if (!isStringArray(manifest.files)) return undefined
  const matchers: Array<(relPath: string) => boolean> = []
  for (const raw of manifest.files) {
    const compiled = compilePattern(raw)
    if (compiled.kind === 'unsupported') return undefined
    if (compiled.kind === 'match') matchers.push(compiled.test)
  }
  const lifecycle = new Set(lifecycleScriptPaths(manifest))
  return (relPath: string) => {
    const path = normalizeRel(relPath)
    if (!path.includes('/') && ALWAYS_PUBLISHED.test(path)) return true
    if (lifecycle.has(path)) return true
    return matchers.some(test => test(path))
  }
}
