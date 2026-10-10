/**
 * Filesystem collection: turn a plugin directory (node_modules/<name>) into
 * a PluginInput, and enumerate a profile's installed plugins. Shared by the
 * node half and the standalone CLI. Pure reads, no network.
 */

import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { isSkillFile } from './core/injection.ts'
import { lifecycleScriptPaths, shippedPredicate } from './core/packlist.ts'
import { extractRelativeSpecifiers } from './core/specifiers.ts'
import { blankComments } from './core/strip-comments.ts'
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
/**
 * Bounds against hostile oversized packages, not against normal ones:
 * published client bundles reach ~8 MB per file and ~12 MB per package, so
 * each limit keeps at least 2x headroom over that.
 */
export const SCAN_LIMITS = {
  maxFileBytes: 16 * 1024 * 1024,
  maxFiles: 4000,
  maxTotalBytes: 64 * 1024 * 1024,
} as const

/** A patch is a small YAML roster parsed as a whole, not a code bundle. */
const MAX_PATCH_BYTES = 512 * 1024

/** Sourcemaps are display-only. A hostile package must not blow the scan with them. */
const SOURCE_MAP_MAX_BYTES = 8 * 1024 * 1024
const SOURCE_MAP_MAX_TOTAL_BYTES = 16 * 1024 * 1024

export interface ScanLimits {
  maxFileBytes: number
  maxFiles: number
  maxTotalBytes: number
}

export interface CollectOptions {
  limits?: ScanLimits
}

const MAX_COVERAGE_NOTES = 20

/**
 * Files that are build/test artifacts, never runtime code worth auditing.
 * Only applies to the directory walk: a file reached from a manifest entry or
 * a relative import is runtime code whatever it is named.
 */
const SKIP_FILE_RE = /(?:^|\/)(?:tsdown|vitest|jest|eslint|prettier)\.config\.|(?:^|\/)tsconfig[^/]*\.json$|\.spec\.|\.test\.|\.d\.ts$|\.map$|\.snap$/

/** Parsed as data by every loader, never executed. */
const DATA_EXT = new Set(['.json'])

/**
 * Binary targets a text scan cannot read. CommonJS `require` would still
 * execute any of these as JavaScript, so reaching one is a coverage note,
 * never a silent skip.
 */
const OPAQUE_EXT = new Set([
  '.node', '.wasm',
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.avif',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm',
  '.zip', '.gz', '.tgz',
])

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
    for (const key of ['import', 'default', 'require', 'node']) {
      const entry = obj[key]
      if (typeof entry === 'string') out.add(entry)
    }
  }
}

/** Relative paths declared by package.json entry points (main / exports / bin / browser). */
export function manifestEntryPaths(manifest: Record<string, unknown>): string[] {
  const paths = new Set<string>()

  const main = manifest.main
  if (typeof main === 'string') paths.add(main)

  // String form only. An object map is not packed as extra files by npm 10.
  const browser = manifest.browser
  if (typeof browser === 'string') paths.add(browser)

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
  seen: Set<string> = new Set(),
): void {
  let realDir = dir
  try {
    realDir = realpathSync(dir)
  } catch {
    realDir = dir
  }
  if (seen.has(realDir)) return
  seen.add(realDir)
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
    if (stat.isSymbolicLink()) {
      const located = locatePackagePath(root, abs)
      if (located.kind === 'escape') {
        throw new Error(`symlink escapes package: ${posixRel(root, abs)}`)
      }
      if (located.kind === 'dir') walk(located.abs, root, sources, skillFiles, budget, limits, seen)
      else if (located.kind === 'file') {
        readScannedFile(located.abs, root, sources, skillFiles, budget, limits, located.size)
      }
      continue
    }
    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue
      walk(abs, root, sources, skillFiles, budget, limits, seen)
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
  readIntoBudget(abs, rel, isSkill ? skillFiles : sources, budget, limits, size)
}

/**
 * Read a file reached from a manifest entry or a relative import. Name and
 * extension skip rules do not apply here: whatever the loader will execute
 * gets scanned, or is reported as a coverage limit.
 */
function readRuntimeTarget(
  abs: string,
  root: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
  coverageNotes: string[],
  omitted: { count: number },
  size?: number,
): void {
  const rel = posixRel(root, abs)
  if (sources[rel] !== undefined) return
  const skillText = skillFiles[rel]
  if (skillText !== undefined) {
    sources[rel] = skillText
    return
  }
  const ext = extOf(rel)
  if (DATA_EXT.has(ext)) return
  if (OPAQUE_EXT.has(ext)) {
    pushNote(coverageNotes, omitted, `binary runtime target not scanned: ${rel}`)
    return
  }
  readIntoBudget(abs, rel, sources, budget, limits, size)
}

function readIntoBudget(
  abs: string,
  rel: string,
  into: Record<string, string>,
  budget: WalkBudget,
  limits: ScanLimits,
  size?: number,
): void {
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
  into[rel] = content
}

type LocatedPath =
  | { kind: 'file'; abs: string; size: number }
  | { kind: 'dir'; abs: string }
  | { kind: 'escape' }
  | { kind: 'missing' }

/** Follow a symlink only when its real path stays inside the package. */
function locatePackagePath(packageDir: string, candidate: string): LocatedPath {
  if (!isInsidePackage(packageDir, candidate)) return { kind: 'escape' }
  let stat
  try {
    stat = lstatSync(candidate)
  } catch {
    return { kind: 'missing' }
  }
  if (stat.isSymbolicLink()) {
    let real: string
    try {
      real = realpathSync(candidate)
    } catch {
      return { kind: 'missing' }
    }
    if (!isInsidePackage(packageDir, real)) return { kind: 'escape' }
    try {
      stat = lstatSync(real)
    } catch {
      return { kind: 'missing' }
    }
    if (stat.isDirectory()) return { kind: 'dir', abs: real }
    if (!stat.isFile()) return { kind: 'missing' }
    return { kind: 'file', abs: real, size: stat.size }
  }
  if (stat.isDirectory()) return { kind: 'dir', abs: candidate }
  if (!stat.isFile()) return { kind: 'missing' }
  return { kind: 'file', abs: candidate, size: stat.size }
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
  const declared = new Set([...manifestEntryPaths(manifest), ...primary])
  for (const raw of declared) {
    const located = locatePackagePath(packageDir, resolve(packageDir, raw))
    if (located.kind === 'escape') {
      if (primary.has(raw)) throw new Error(`primary entry escapes package: ${raw}`)
      continue
    }
    if (located.kind !== 'file') {
      if (primary.has(raw)) throw new Error(`primary entry unreadable or missing: ${raw}`)
      pushNote(coverageNotes, omitted, `optional export not found: ${raw}`)
      continue
    }
    readRuntimeTarget(
      located.abs, packageDir, sources, skillFiles, budget, limits, coverageNotes, omitted, located.size,
    )
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
  const raw = declared ?? 'cordis.patch.yml'
  const located = locatePackagePath(dir, resolve(dir, raw))
  if (located.kind === 'escape') throw new Error(`patch escapes package: ${raw}`)
  if (located.kind === 'missing') return undefined
  if (located.kind === 'dir') throw new Error(`patch is a directory: ${raw}`)
  const rel = posixRel(dir, located.abs)
  if (located.size > MAX_PATCH_BYTES) {
    throw new Error(`file too large: ${rel} (${located.size} bytes)`)
  }
  try {
    return { text: readFileSync(located.abs, 'utf8'), path: rel }
  } catch (err) {
    throw new Error(`unreadable: ${rel}: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/**
 * Directories to scan inside a plugin. Compiled output is the runtime truth,
 * so `lib/`/`dist/` win over `src/` when present; `bin/`, `scripts/`, and
 * shipped skill dirs are always walked. When nothing compiled exists, fall
 * back to the package root (a `link:`/source install still gets a useful read).
 * After the walk, `package.json` `files` drops paths npm would not publish.
 * Manifest entry files (`main` / `exports` / `bin`, and a string `browser`) are always read too.
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
  try {
    dir = realpathSync(dir)
  } catch {
    // Keep the caller path when the directory cannot be canonicalized.
  }
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
  const shipped = shippedPredicate(manifest)
  const walked = shipped === undefined
    ? undefined
    : new Set([...Object.keys(sources), ...Object.keys(skillFiles)])
  if (shipped !== undefined) {
    for (const bucket of [sources, skillFiles]) {
      for (const rel of Object.keys(bucket)) {
        if (!shipped(rel)) delete bucket[rel]
      }
    }
    for (const raw of lifecycleScriptPaths(manifest)) {
      const located = locatePackagePath(dir, resolve(dir, raw))
      if (located.kind === 'escape') {
        pushNote(coverageNotes, omitted, `lifecycle script target escapes package: ${raw}`)
        continue
      }
      if (located.kind !== 'file') continue
      readRuntimeTarget(
        located.abs, dir, sources, skillFiles, budget, limits, coverageNotes, omitted, located.size,
      )
    }
  }
  scanDeclaredEntries(dir, manifest, sources, skillFiles, budget, limits, coverageNotes, omitted)
  followStaticImports(dir, sources, skillFiles, budget, limits, coverageNotes, omitted)
  if (walked !== undefined) {
    const dropped = [...walked]
      .filter(rel => sources[rel] === undefined && skillFiles[rel] === undefined)
      .sort()
    if (dropped.length > 0) {
      const shown = dropped.slice(0, 5).join(', ')
      const suffix = dropped.length > 5 ? ', …' : ''
      pushNote(
        coverageNotes,
        omitted,
        `filtered by package.json files: ${dropped.length} dev-only file(s) not counted (${shown}${suffix})`,
      )
    }
  }
  const sourceMaps = readSourceMaps(dir, sources, coverageNotes, omitted)
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
    sourceMaps,
  }
}

const SOURCE_MAP_URL = /(?:\/\/[#@]\s*sourceMappingURL=|\/\*[#@]\s*sourceMappingURL=)(?!data:)([^\s*]+)/

function sourceMapUrl(content: string): string | undefined {
  const match = SOURCE_MAP_URL.exec(content.slice(-1024))
  const url = match?.[1]
  if (url === undefined || url.startsWith('data:') || url.includes('://')) return undefined
  return url
}

/** External sourcemaps whose URL stays inside the package. Inline maps are skipped. */
function readSourceMaps(
  packageDir: string,
  sources: Record<string, string>,
  coverageNotes: string[],
  omitted: { count: number },
): Record<string, string> | undefined {
  const out: Record<string, string> = {}
  let total = 0
  for (const rel of Object.keys(sources)) {
    const content = sources[rel]
    if (content === undefined) continue
    const url = sourceMapUrl(content)
    if (url === undefined) continue
    let decoded = url
    try {
      decoded = decodeURIComponent(url)
    } catch {
      pushNote(coverageNotes, omitted, `sourcemap url not decoded: ${rel}`)
      continue
    }
    const located = locatePackagePath(packageDir, resolve(packageDir, dirname(rel), decoded))
    if (located.kind === 'escape') {
      pushNote(coverageNotes, omitted, `sourcemap escapes package from ${rel}`)
      continue
    }
    if (located.kind !== 'file') continue
    if (located.size > SOURCE_MAP_MAX_BYTES || total + located.size > SOURCE_MAP_MAX_TOTAL_BYTES) {
      pushNote(coverageNotes, omitted, `sourcemap skipped (too large): ${posixRel(packageDir, located.abs)}`)
      continue
    }
    try {
      out[rel] = readFileSync(located.abs, 'utf8')
      total += located.size
    } catch {
      pushNote(coverageNotes, omitted, `sourcemap unreadable: ${posixRel(packageDir, located.abs)}`)
    }
  }
  return Object.keys(out).length > 0 ? out : undefined
}

/** A static template literal (`…` with no `${`) is a real specifier, not a dynamic one. */
const STATIC_TEMPLATE = '`[^`$]*`'
const DYNAMIC_IMPORT = new RegExp(`(?:^|[^\\w$])import\\s*\\(\\s*(?!['"]|${STATIC_TEMPLATE})`, 'g')
const DYNAMIC_REQUIRE = new RegExp(`(?:^|[^\\w$])require\\s*\\(\\s*(?!['"]|${STATIC_TEMPLATE})`, 'g')
/**
 * `require("literal" + …)` — the module name is built, not written out.
 * The escape and plain-character branches must stay disjoint: overlapping
 * branches backtrack exponentially on a long run of backslashes.
 */
const COMPUTED_MODULE = /\brequire\s*\(\s*(['"`])(?:\\[^\n]|(?!\1)[^\\\n])*\1\s*\+/g
const NATIVE_BINDING = /\bprocess\.(?:binding|dlopen)\s*\(/g
/** `eval` / `Function` whose argument starts with a decode call. */
const DECODED_EVAL = /\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(/g

const RESOLVE_EXTS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']

function locateFile(packageDir: string, candidate: string): string | 'escape' | undefined {
  const located = locatePackagePath(packageDir, candidate)
  if (located.kind === 'escape') return 'escape'
  if (located.kind === 'file') return located.abs
  return undefined
}

/** Metadata only. Node loads this file and skips the directory `index.js`. */
function outsideFileExists(target: string): boolean {
  try {
    return statSync(target).isFile()
  } catch {
    return false
  }
}

/**
 * `main` of a directory specifier. Node loads this before `index.js`.
 * One hop: `main` itself is not resolved through another package.json.
 * A missing or unreadable manifest falls through to `index.js`.
 * A `main` outside the package does too, unless that file exists: Node
 * loads an existing outside file, and a missing one falls through after
 * DEP0128. The outside file is never read.
 */
function packageMainTarget(packageDir: string, dirAbs: string): string | 'escape' | undefined {
  const located = locatePackagePath(packageDir, join(dirAbs, 'package.json'))
  if (located.kind === 'escape') return 'escape'
  if (located.kind !== 'file' || located.size > SCAN_LIMITS.maxFileBytes) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(located.abs, 'utf8')) as unknown
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
  const main = (parsed as Record<string, unknown>).main
  if (typeof main !== 'string' || main.trim() === '') return undefined
  const target = resolve(dirAbs, main.trim())
  if (!isInsidePackage(packageDir, target)) {
    return outsideFileExists(target) ? 'escape' : undefined
  }
  return target
}

function resolveModulePath(
  packageDir: string,
  base: string,
  packageMainHops: number,
): string | 'escape' | undefined {
  const exact = locateFile(packageDir, base)
  if (exact !== undefined) return exact
  for (const ext of RESOLVE_EXTS) {
    const hit = locateFile(packageDir, `${base}${ext}`)
    if (hit !== undefined) return hit
  }
  const located = locatePackagePath(packageDir, base)
  if (located.kind === 'escape') return 'escape'
  if (located.kind === 'dir' && packageMainHops > 0) {
    const main = packageMainTarget(packageDir, located.abs)
    if (main === 'escape') return 'escape'
    if (typeof main === 'string') {
      const resolved = resolveModulePath(packageDir, main, packageMainHops - 1)
      if (resolved !== undefined) return resolved
    }
  }
  for (const indexName of ['index.js', 'index.ts']) {
    const hit = locateFile(packageDir, join(base, indexName))
    if (hit !== undefined) return hit
  }
  return undefined
}

function resolveInPackage(packageDir: string, fromFile: string, spec: string): string | 'escape' | undefined {
  return resolveModulePath(packageDir, resolve(dirname(fromFile), spec), 1)
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
    const blanked = blankComments(content, rel)
    if (blanked.fallback) {
      pushNote(coverageNotes, omitted, `comment stripping fell back to raw text in ${rel}`)
    }
    const stripped = blanked.text
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
    if (COMPUTED_MODULE.test(stripped)) {
      COMPUTED_MODULE.lastIndex = 0
      pushNote(coverageNotes, omitted, `computed module name in ${rel}`)
    } else {
      COMPUTED_MODULE.lastIndex = 0
    }
    if (NATIVE_BINDING.test(stripped)) {
      NATIVE_BINDING.lastIndex = 0
      pushNote(coverageNotes, omitted, `native binding in ${rel}`)
    } else {
      NATIVE_BINDING.lastIndex = 0
    }
    if (DECODED_EVAL.test(stripped)) {
      DECODED_EVAL.lastIndex = 0
      pushNote(coverageNotes, omitted, `decoded eval in ${rel}`)
    } else {
      DECODED_EVAL.lastIndex = 0
    }
    for (const spec of extractRelativeSpecifiers(stripped)) {
      const target = resolveInPackage(packageDir, abs, spec)
      if (target === 'escape') {
        pushNote(coverageNotes, omitted, `import escapes package from ${rel}: ${spec}`)
        continue
      }
      if (target === undefined) {
        pushNote(coverageNotes, omitted, `unresolvable runtime target from ${rel}: ${spec}`)
        continue
      }
      readRuntimeTarget(target, packageDir, sources, skillFiles, budget, limits, coverageNotes, omitted)
      queue.push(target)
    }
  }
}
