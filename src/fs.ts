/**
 * Filesystem collection: turn a plugin directory (node_modules/<name>) into
 * a PluginInput, and enumerate a profile's installed plugins. Shared by the
 * node half and the standalone CLI. Pure reads, no network.
 */

import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { isSkillFile } from './core/injection.ts'
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
const MAX_TOTAL_BYTES = 8 * 1024 * 1024
const MAX_FILES = 4000
const MAX_FILE_BYTES = 512 * 1024

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

function walk(
  dir: string,
  root: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
): void {
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return
  }
  for (const name of entries) {
    if (budget.files >= MAX_FILES || budget.bytes >= MAX_TOTAL_BYTES) return
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
      walk(abs, root, sources, skillFiles, budget)
      continue
    }
    if (!stat.isFile()) continue
    readScannedFile(abs, root, sources, skillFiles, budget)
  }
}

function readScannedFile(
  abs: string,
  root: string,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
): void {
  if (budget.files >= MAX_FILES || budget.bytes >= MAX_TOTAL_BYTES) return
  const rel = posixRel(root, abs)
  if (SKIP_FILE_RE.test(rel)) return
  const ext = extOf(rel)
  const isSkill = isSkillFile(rel) && (ext === '.md' || ext === '.prompt' || ext === '.txt')
  if (ext !== '' && !CODE_EXT.has(ext) && !isSkill) return
  let content: string
  try {
    content = readFileSync(abs, 'utf8')
  } catch {
    return
  }
  const bytes = Buffer.byteLength(content, 'utf8')
  if (bytes > MAX_FILE_BYTES) return
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

function scanManifestEntries(
  packageDir: string,
  manifest: Record<string, unknown>,
  sources: Record<string, string>,
  skillFiles: Record<string, string>,
  budget: WalkBudget,
): void {
  for (const raw of manifestEntryPaths(manifest)) {
    const abs = resolveManifestEntry(packageDir, raw)
    if (abs === undefined) continue
    readScannedFile(abs, packageDir, sources, skillFiles, budget)
  }
}

/** Resolve a profile name to its directory under DSH_HOME (default ~/.dsh). */
export function resolveProfileDir(profile: string): string {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(home, 'profiles', profile)
}

/** Community plugins installed in a profile: name -> install spec. */
export function readInstalled(profileDir: string): Record<string, string> {
  try {
    const manifest = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>
    }
    const installed: Record<string, string> = {}
    for (const [name, spec] of Object.entries(manifest.dependencies ?? {})) {
      if (!INBOX_BUNDLES.has(name)) installed[name] = spec
    }
    return installed
  } catch {
    return {}
  }
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
    try {
      const text = readFileSync(candidate, 'utf8')
      if (Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES) continue
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
export function collectPlugin(dir: string, spec: string): PluginInput {
  let manifest: Record<string, unknown> = {}
  try {
    manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>
  } catch {
    // Missing package.json → empty manifest; provenance reports "unknown".
  }

  const sources: Record<string, string> = {}
  const skillFiles: Record<string, string> = {}
  const budget: WalkBudget = { bytes: 0, files: 0 }
  for (const root of scanRoots(dir)) {
    walk(join(dir, root), dir, sources, skillFiles, budget)
  }
  scanManifestEntries(dir, manifest, sources, skillFiles, budget)

  const patch = readPatch(manifest, dir)

  return {
    manifest,
    sources,
    skillFiles,
    patchText: patch?.text,
    patchPath: patch?.path,
    spec,
  }
}
