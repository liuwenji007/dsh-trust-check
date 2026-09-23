/**
 * Filesystem collection: turn a plugin directory (node_modules/<name>) into
 * a PluginInput, and enumerate a profile's installed plugins. Shared by the
 * node half and the standalone CLI. Pure reads, no network.
 */

import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { isSkillFile } from './core/injection.ts'
import { stripComments } from './core/strip-comments.ts'
import type { PluginInput } from './core/types.ts'

/** In-box bundles the profile ships by default; never community plugins. */
export const INBOX_BUNDLES = new Set([
  '@deepseek-ai/dsh-base',
  '@deepseek-ai/dsh-web-app',
  '@deepseek-ai/dsh-headless',
])

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'])
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.history',
  '.pnpm',
  'tests',
  'test',
  '__tests__',
  'spec',
  'coverage',
  'docs',
  'examples',
  '.github',
])
export const SCAN_LIMITS = {
  maxFileBytes: 512 * 1024,
  maxFiles: 4000,
  maxTotalBytes: 8 * 1024 * 1024,
} as const

export interface ScanLimits {
  maxFileBytes: number
  maxFiles: number
  maxTotalBytes: number
}

export interface CollectOptions {
  limits?: ScanLimits
}

const MAX_COVERAGE_NOTES = 20

/** Files that are build/test artifacts, never runtime code worth auditing. */
const SKIP_FILE_RE = /(?:^|\/)(?:tsdown|vitest|jest|eslint|prettier)\.config\.|(?:^|\/)tsconfig[^/]*\.json$|\.spec\.|\.test\.|\.d\.ts$|\.map$|\.snap$/

interface WalkBudget {
  bytes: number
  files: number
}

/** Relative path with `/` separators so reports and skip rules are OS-stable. */
function posixRel(from: string, to: string): string {
  return relative(from, to).split('\\').join('/')
}

function extOf(path: string): string {
  const idx = path.lastIndexOf('.')
  return idx === -1 ? '' : path.slice(idx).toLowerCase()
}

/** True when `target` resolves to a regular file inside `packageDir`. */
function isInsidePackage(packageDir: string, target: string): boolean {
  const rel = relative(packageDir, target)
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)
}

function collectExportTarget(value: unknown, out: Set<string>): void {
  if (typeof value === 'string') {
    out.add(value)
    return
  }
  if (typeof value === 'object' && value !== null) {
    const obj = value as Record<string, unknown>
    for (const key of ['import', 'default', 'require', 'node', 'types']) {
      const entry = obj[key]
      if (typeof entry === 'string') out.add(entry)
    }
  }
}

/** Relative paths declared by package.json entry points (main / exports / bin). */
export function manifestEntryPaths(manifest: Record<string, unknown>): string[] {
  const paths = new Set<string>()

  const main = manifest.main
  if (typeof main === 'string') paths.add(main)

  const bin = manifest.bin
  if (typeof bin === 'string') {
    paths.add(bin)
  } else if (typeof bin === 'object' && bin !== null && !Array.isArray(bin)) {
    for (const value of Object.values(bin as Record<string, unknown>)) {
      if (typeof value === 'string') paths.add(value)
    }
  }

  const exports = manifest.exports
  if (typeof exports === 'string') {
    paths.add(exports)
  } else if (typeof exports === 'object' && exports !== null && !Array.isArray(exports)) {
    for (const [key, value] of Object.entries(exports as Record<string, unknown>)) {
      if (key === './package.json') continue
      collectExportTarget(value, paths)
    }
  }

  return [...paths]
}

function codeTargets(value: unknown, out: Set<string>): void {
  if (typeof value === 'string') {
    out.add(value)
    return
  }
  if (typeof value === 'object' && value !== null) {
    const obj = value as Record<string, unknown>
    for (const key of ['import', 'default', 'require', 'node']) {
      if (typeof obj[key] === 'string') out.add(obj[key] as string)
    }
  }
}

/** Primary runtime entries. Optional export subpaths are not included. */
export function primaryEntryPaths(manifest: Record<string, unknown>): string[] {
  const paths = new Set<string>()
  if (typeof manifest.main === 'string') paths.add(manifest.main)
  const bin = manifest.bin
  if (typeof bin === 'string') paths.add(bin)
  else if (typeof bin === 'object' && bin !== null && !Array.isArray(bin)) {
    for (const value of Object.values(bin as Record<string, unknown>)) {
      if (typeof value === 'string') paths.add(value)
    }
  }
  const exportsField = manifest.exports
  if (typeof exportsField === 'string') paths.add(exportsField)
  else if (typeof exportsField === 'object' && exportsField !== null && !Array.isArray(exportsField)) {
    codeTargets((exportsField as Record<string, unknown>)['.'], paths)
  }
  return [...paths]
}

function walk(
  dir: string,
  root: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
): void {
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return
  }
  for (const name of entries) {
    const abs = join(dir, name)
    let stat
    try {
      stat = lstatSync(abs)
    } catch {
      continue
    }
    if (stat.isSymbolicLink()) continue
    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue
      walk(abs, root, sources, skillFiles, budget, limits)
      continue
    }
    if (!stat.isFile()) continue
    readScannedFile(abs, root, sources, skillFiles, budget, limits, stat.size)
  }
}

function readScannedFile(
  abs: string,
  root: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
  size?: number,
): void {
  const rel = posixRel(root, abs)
  if (sources[rel] !== undefined || skillFiles[rel] !== undefined) return
  if (SKIP_FILE_RE.test(rel)) return
  const ext = extOf(rel)
  const isSkill = isSkillFile(rel) && (ext === '.md' || ext === '.prompt' || ext === '.txt')
  if (ext !== '' && !CODE_EXT.has(ext) && !isSkill) return
  const bytes = size ?? lstatSync(abs).size
  if (bytes > limits.maxFileBytes) {
    throw new Error(`file too large: ${rel} (${bytes} bytes)`)
  }
  if (budget.files >= limits.maxFiles) {
    throw new Error(`scan aborted: more than ${limits.maxFiles} files`)
  }
  if (budget.bytes + bytes > limits.maxTotalBytes) {
    throw new Error(`scan aborted: total size exceeds ${limits.maxTotalBytes} bytes`)
  }
  let content: string
  try {
    content = readFileSync(abs, 'utf8')
  } catch (err) {
    throw new Error(`unreadable: ${rel}: ${err instanceof Error ? err.message : String(err)}`)
  }
  budget.bytes += bytes
  budget.files += 1
  if (isSkill) skillFiles[rel] = content
  else sources[rel] = content
}

/** Resolve a manifest entry path to an in-package file, if any. */
function resolveManifestEntry(packageDir: string, raw: string): string | undefined {
  const resolved = resolve(packageDir, raw)
  if (!isInsidePackage(packageDir, resolved)) return undefined
  let stat
  try {
    stat = lstatSync(resolved)
  } catch {
    return undefined
  }
  if (!stat.isFile()) return undefined
  return resolved
}

function pushNote(notes: string[], omitted: { count: number }, message: string): void {
  if (notes.length < MAX_COVERAGE_NOTES - 1) notes.push(message)
  else omitted.count += 1
}

function sealNotes(notes: string[], omitted: number): void {
  if (omitted > 0) notes.push(`${omitted} additional coverage limits omitted`)
}

function scanDeclaredEntries(
  packageDir: string,
  manifest: Record<string, unknown>,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
  coverageNotes: string[],
  omitted: { count: number },
): void {
  const primary = new Set(primaryEntryPaths(manifest))
  for (const raw of manifestEntryPaths(manifest)) {
    const resolved = resolve(packageDir, raw)
    if (!isInsidePackage(packageDir, resolved)) continue
    const abs = resolveManifestEntry(packageDir, raw)
    if (abs === undefined) {
      if (primary.has(raw)) {
        throw new Error(`primary entry unreadable or missing: ${raw}`)
      }
      pushNote(coverageNotes, omitted, `optional export not found: ${raw}`)
      continue
    }
    readScannedFile(abs, packageDir, sources, skillFiles, budget, limits)
  }
  for (const raw of primary) {
    if (manifestEntryPaths(manifest).includes(raw)) continue
    const resolved = resolve(packageDir, raw)
    if (!isInsidePackage(packageDir, resolved)) continue
    if (resolveManifestEntry(packageDir, raw) === undefined) {
      throw new Error(`primary entry unreadable or missing: ${raw}`)
    }
  }
}

/** Resolve a profile name to its directory under DSH_HOME (default ~/.dsh). */
export function resolveProfileDir(profile: string): string {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(home, 'profiles', profile)
}

/** Community plugins installed in a profile: name -> install spec. */
export function readInstalled(profileDir: string): Record<string, string> {
  const pkgPath = join(profileDir, 'package.json')
  if (!existsSync(profileDir)) {
    throw new Error(`profile directory does not exist: ${profileDir}`)
  }
  if (!existsSync(pkgPath)) {
    throw new Error(`profile package.json missing: ${pkgPath}`)
  }
  let manifest: { dependencies?: Record<string, string> }
  try {
    manifest = JSON.parse(readFileSync(pkgPath, 'utf8')) as { dependencies?: Record<string, string> }
  } catch (err) {
    throw new Error(`profile package.json corrupt: ${err instanceof Error ? err.message : String(err)}`)
  }
  const installed: Record<string, string> = {}
  for (const [name, spec] of Object.entries(manifest.dependencies ?? {})) {
    if (!INBOX_BUNDLES.has(name)) installed[name] = spec
  }
  return installed
}

function readPatch(manifest: Record<string, unknown>, dir: string): { text: string; path: string } | undefined {
  let declared: string | undefined
  const dsh = manifest.dsh
  if (typeof dsh === 'object' && dsh !== null) {
    const bundle = (dsh as Record<string, unknown>).bundle
    if (typeof bundle === 'object' && bundle !== null) {
      const patch = (bundle as Record<string, unknown>).patch
      if (typeof patch === 'string') declared = patch
    }
  }
  const candidates = declared !== undefined
    ? [resolve(dir, declared)]
    : [join(dir, 'cordis.patch.yml')]
  for (const candidate of candidates) {
    if (!isInsidePackage(dir, candidate)) continue
    if (!existsSync(candidate)) continue
    let stat
    try {
      stat = lstatSync(candidate)
    } catch {
      continue
    }
    if (!stat.isFile()) continue
    if (stat.size > SCAN_LIMITS.maxFileBytes) {
      throw new Error(`file too large: ${posixRel(dir, candidate)} (${stat.size} bytes)`)
    }
    try {
      const text = readFileSync(candidate, 'utf8')
      return { text, path: posixRel(dir, candidate) }
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Directories to scan inside a plugin. Compiled output is the runtime truth,
 * so `lib/`/`dist/` win over `src/` when present; `bin/`, `scripts/`, and
 * shipped skill dirs are always scanned. When nothing compiled exists, fall
 * back to the package root (a `link:`/source install still gets a useful read).
 * Manifest entry files (`main` / `exports` / `bin`) are always read too.
 */
function scanRoots(dir: string): string[] {
  const roots: string[] = []
  if (existsSync(join(dir, 'lib'))) roots.push('lib')
  if (existsSync(join(dir, 'dist'))) roots.push('dist')
  if (roots.length === 0) roots.push('.')
  if (existsSync(join(dir, 'bin'))) roots.push('bin')
  if (existsSync(join(dir, 'scripts'))) roots.push('scripts')
  for (const skillDir of ['skills', 'prompts']) {
    if (existsSync(join(dir, skillDir))) roots.push(skillDir)
  }
  return roots
}

/** Read one installed plugin directory into the engine's input shape. */
export function collectPlugin(dir: string, spec: string, options?: CollectOptions): PluginInput {
  const limits = options?.limits ?? SCAN_LIMITS
  let manifest: Record<string, unknown> = {}
  try {
    manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>
  } catch {
    // Missing or invalid package.json → empty manifest; may still audit source files.
  }

  const sources: Record<string, string> = {}
  const skillFiles: Record<string, string> = {}
  const coverageNotes: string[] = []
  const omitted = { count: 0 }
  const budget: WalkBudget = { bytes: 0, files: 0 }
  for (const root of scanRoots(dir)) {
    walk(join(dir, root), dir, sources, skillFiles, budget, limits)
  }
  scanDeclaredEntries(dir, manifest, sources, skillFiles, budget, limits, coverageNotes, omitted)
  followStaticImports(dir, sources, skillFiles, budget, limits, coverageNotes, omitted)
  sealNotes(coverageNotes, omitted.count)

  const patch = readPatch(manifest, dir)

  const hasManifest = Object.keys(manifest).length > 0
  const hasContent = Object.keys(sources).length > 0
    || Object.keys(skillFiles).length > 0
    || patch?.text !== undefined
  if (!hasManifest && !hasContent) {
    throw new Error(
      `nothing to audit in ${dir}: no readable package.json and no scannable source files`,
    )
  }

  return {
    manifest,
    sources,
    skillFiles,
    patchText: patch?.text,
    patchPath: patch?.path,
    spec,
    coverageNotes,
  }
}

const STATIC_RELATIVE = /(?:(?:import|export)\s+(?:[^'"\n]+?\s+from\s+)?|import\s*\(\s*|require\s*\(\s*)['"](\.[^'"]+)['"]/g
const DYNAMIC_IMPORT = /(?:^|[^\w$])import\s*\(\s*(?!['"])/g
const DYNAMIC_REQUIRE = /(?:^|[^\w$])require\s*\(\s*(?!['"])/g

function extractRelativeSpecifiers(source: string): string[] {
  const out: string[] = []
  for (const match of stripComments(source).matchAll(STATIC_RELATIVE)) {
    if (match[1] !== undefined) out.push(match[1])
  }
  return out
}

function resolveInPackage(packageDir: string, fromFile: string, spec: string): string | 'escape' | 'node_modules' | undefined {
  const base = resolve(dirname(fromFile), spec)
  const candidates = [
    base,
    `${base}.js`, `${base}.mjs`, `${base}.cjs`,
    `${base}.ts`, `${base}.mts`, `${base}.cts`,
    `${base}.jsx`, `${base}.tsx`,
    join(base, 'index.js'),
    join(base, 'index.ts'),
  ]
  for (const candidate of candidates) {
    if (!isInsidePackage(packageDir, candidate)) return 'escape'
    const rel = posixRel(packageDir, candidate)
    if (rel === 'node_modules' || rel.startsWith('node_modules/') || rel.includes('/node_modules/')) {
      return 'node_modules'
    }
    try {
      if (lstatSync(candidate).isFile()) return candidate
    } catch {
      // try the next candidate
    }
  }
  return undefined
}

function followStaticImports(
  packageDir: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
  coverageNotes: string[],
  omitted: { count: number },
): void {
  const seen = new Set<string>()
  const queue = Object.keys(sources).map(rel => resolve(packageDir, rel))
  while (queue.length > 0) {
    const abs = queue.pop()
    if (abs === undefined || seen.has(abs)) continue
    seen.add(abs)
    const rel = posixRel(packageDir, abs)
    const content = sources[rel]
    if (content === undefined) continue
    const stripped = stripComments(content)
    if (DYNAMIC_IMPORT.test(stripped)) {
      DYNAMIC_IMPORT.lastIndex = 0
      pushNote(coverageNotes, omitted, `dynamic import target in ${rel}`)
    } else {
      DYNAMIC_IMPORT.lastIndex = 0
    }
    if (DYNAMIC_REQUIRE.test(stripped)) {
      DYNAMIC_REQUIRE.lastIndex = 0
      pushNote(coverageNotes, omitted, `dynamic require target in ${rel}`)
    } else {
      DYNAMIC_REQUIRE.lastIndex = 0
    }
    for (const spec of extractRelativeSpecifiers(content)) {
      const target = resolveInPackage(packageDir, abs, spec)
      if (target === 'escape') {
        pushNote(coverageNotes, omitted, `import escapes package from ${rel}: ${spec}`)
        continue
      }
      if (target === 'node_modules') {
        pushNote(coverageNotes, omitted, `dependency import not expanded from ${rel}: ${spec}`)
        continue
      }
      if (target === undefined) {
        pushNote(coverageNotes, omitted, `unresolvable runtime target from ${rel}: ${spec}`)
        continue
      }
      const targetRel = posixRel(packageDir, target)
      if (sources[targetRel] === undefined && skillFiles[targetRel] === undefined) {
        readScannedFile(target, packageDir, sources, skillFiles, budget, limits)
      }
      queue.push(target)
    }
  }
}
