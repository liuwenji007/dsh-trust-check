/**
 * Display-only file context: which package entry can reach a file, and
 * whether a generated line maps into a bundled dependency.
 * Nothing here is consulted by the score, red lines, or ack fingerprint.
 */

import { posix } from 'node:path'
import { linePackages } from './sourcemap.ts'
import { extractRelativeSpecifiers } from './specifiers.ts'
import { blankComments } from './strip-comments.ts'
import type {
  AuditReport,
  FindingContext,
  PluginInput,
  Runtime,
} from './types.ts'

const CODE_EXTS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']
const RUNTIME_ORDER: readonly Runtime[] = ['server', 'client', 'cli']

function pushCodeTarget(value: unknown, out: Set<string>): void {
  if (typeof value === 'string') {
    out.add(value)
    return
  }
  if (typeof value === 'object' && value !== null) {
    const obj = value as Record<string, unknown>
    for (const key of ['import', 'default', 'require', 'node']) {
      if (typeof obj[key] === 'string') out.add(obj[key])
    }
  }
}

function exportTargets(manifest: Record<string, unknown>, key: string): string[] {
  const exportsField = manifest.exports
  if (typeof exportsField !== 'object' || exportsField === null || Array.isArray(exportsField)) return []
  const out = new Set<string>()
  pushCodeTarget((exportsField as Record<string, unknown>)[key], out)
  return [...out]
}

function binTargets(manifest: Record<string, unknown>): string[] {
  const bin = manifest.bin
  if (typeof bin === 'string') return [bin]
  if (typeof bin !== 'object' || bin === null || Array.isArray(bin)) return []
  return Object.values(bin as Record<string, unknown>).filter((value): value is string => typeof value === 'string')
}

/** Entry paths grouped by where they run. `./client` is the browser root. */
export function runtimeEntryPaths(manifest: Record<string, unknown>): Record<Runtime, string[]> {
  const server = new Set<string>()
  if (typeof manifest.main === 'string') server.add(manifest.main)
  const exportsField = manifest.exports
  if (typeof exportsField === 'string') {
    server.add(exportsField)
  } else if (typeof exportsField === 'object' && exportsField !== null && !Array.isArray(exportsField)) {
    for (const [key, value] of Object.entries(exportsField as Record<string, unknown>)) {
      if (key === './package.json' || key === './client') continue
      pushCodeTarget(value, server)
    }
  }
  return {
    server: [...server],
    client: exportTargets(manifest, './client'),
    cli: binTargets(manifest),
  }
}

function normalizeKey(raw: string): string {
  let path = posix.normalize(raw.split('\\').join('/'))
  while (path.startsWith('./')) path = path.slice(2)
  return path
}

function existingKey(raw: string, keys: ReadonlySet<string>): string | undefined {
  const base = normalizeKey(raw)
  if (base === '' || base.startsWith('..')) return undefined
  const candidates = [base]
  if (!CODE_EXTS.some(ext => base.endsWith(ext))) {
    for (const ext of CODE_EXTS) candidates.push(`${base}${ext}`)
    candidates.push(`${base}/index.js`, `${base}/index.ts`)
  }
  for (const candidate of candidates) {
    if (keys.has(candidate)) return candidate
  }
  return undefined
}

function resolveImport(fromFile: string, spec: string, keys: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith('.')) return undefined
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec))
  return existingKey(base, keys)
}

/** File → runtimes that can reach it by a static relative import from an entry. */
export function runtimeByFile(
  manifest: Record<string, unknown>,
  sources: Record<string, string>,
): Map<string, Runtime[]> {
  const keys = new Set(Object.keys(sources))
  const reach = new Map<string, Set<Runtime>>()
  const entries = runtimeEntryPaths(manifest)
  for (const runtime of RUNTIME_ORDER) {
    const seen = new Set<string>()
    const queue: string[] = []
    for (const raw of entries[runtime]) {
      const key = existingKey(raw, keys)
      if (key !== undefined) queue.push(key)
    }
    while (queue.length > 0) {
      const file = queue.pop()
      if (file === undefined || seen.has(file)) continue
      seen.add(file)
      const set = reach.get(file) ?? new Set<Runtime>()
      set.add(runtime)
      reach.set(file, set)
      const content = sources[file]
      if (content === undefined) continue
      const stripped = blankComments(content, file).text
      for (const spec of extractRelativeSpecifiers(stripped)) {
        const target = resolveImport(file, spec, keys)
        if (target !== undefined) queue.push(target)
      }
    }
  }
  const out = new Map<string, Runtime[]>()
  for (const [file, set] of reach) {
    out.set(file, RUNTIME_ORDER.filter(runtime => set.has(runtime)))
  }
  return out
}

function originByLine(sourceMaps: Record<string, string> | undefined): Map<string, string> {
  const out = new Map<string, string>()
  if (sourceMaps === undefined) return out
  for (const [file, text] of Object.entries(sourceMaps)) {
    const lines = linePackages(text)
    if (lines === undefined) continue
    for (const [line, pkg] of lines) out.set(`${file}:${line}`, pkg)
  }
  return out
}

function contextFor(
  file: string,
  line: number,
  runtime: Map<string, Runtime[]>,
  origin: Map<string, string>,
): FindingContext | undefined {
  const ctx: FindingContext = {}
  const reached = runtime.get(file)
  if (reached !== undefined && reached.length > 0) ctx.runtime = reached
  const pkg = origin.get(`${file}:${line}`)
  if (pkg !== undefined) ctx.origin = { kind: 'dependency', package: pkg }
  if (ctx.runtime === undefined && ctx.origin === undefined) return undefined
  return ctx
}

function apply<T extends { file: string; line: number; context?: FindingContext }>(
  row: T,
  runtime: Map<string, Runtime[]>,
  origin: Map<string, string>,
): void {
  const ctx = contextFor(row.file, row.line, runtime, origin)
  if (ctx !== undefined) row.context = ctx
}

/**
 * Fill `context` on the report that will be shown. Call only after the score
 * and ack fingerprint have been computed.
 */
export function attachContext(report: AuditReport, input: PluginInput): void {
  const runtime = runtimeByFile(input.manifest, input.sources)
  const origin = originByLine(input.sourceMaps)
  for (const row of report.evidence) apply(row, runtime, origin)
  for (const row of report.secretTouches ?? []) apply(row, runtime, origin)
  for (const row of report.destinations) {
    apply(row, runtime, origin)
    for (const site of row.sites ?? []) {
      const ctx = contextFor(site.file, site.line, runtime, origin)
      if (ctx !== undefined) site.context = ctx
    }
  }
}
