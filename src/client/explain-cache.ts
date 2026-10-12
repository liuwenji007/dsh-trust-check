/**
 * Last AI reading per plugin, kept so a reload does not cost another model call.
 * An entry only applies while its key (version, risk fingerprint, locale) still
 * matches the current report; nothing here feeds the verdict or acknowledgment.
 */
import type { AuditReport } from '../core/types.ts'

const STORAGE_KEY = 'dsh.trust-check.explain.v1'

export interface ExplainEntry {
  key: string
  text: string
  at: number
  truncated?: boolean
}

export function explainCacheKey(report: AuditReport, locale: string): string {
  return [report.version, report.ackFingerprint ?? '', locale].join('\n')
}

function storage(): Storage | undefined {
  try {
    return typeof localStorage === 'undefined' ? undefined : localStorage
  } catch {
    return undefined
  }
}

function isEntry(value: unknown): value is ExplainEntry {
  if (typeof value !== 'object' || value === null) return false
  const entry = value as Record<string, unknown>
  return typeof entry.key === 'string' && typeof entry.text === 'string' && typeof entry.at === 'number'
    && (entry.truncated === undefined || typeof entry.truncated === 'boolean')
}

function readAll(): Record<string, ExplainEntry> {
  const raw = storage()?.getItem(STORAGE_KEY)
  if (raw === null || raw === undefined) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {}
    const out: Record<string, ExplainEntry> = {}
    for (const [name, entry] of Object.entries(parsed)) {
      if (isEntry(entry)) out[name] = entry
    }
    return out
  } catch {
    return {}
  }
}

function writeAll(all: Record<string, ExplainEntry>): void {
  try {
    storage()?.setItem(STORAGE_KEY, JSON.stringify(all))
  } catch {
    // Quota or privacy mode: the reading still shows for this session.
  }
}

export function readExplain(name: string, key: string): ExplainEntry | undefined {
  const entry = readAll()[name]
  return entry?.key === key ? entry : undefined
}

export function writeExplain(name: string, entry: ExplainEntry): void {
  writeAll({ ...readAll(), [name]: entry })
}

/** Drop readings for plugins that are no longer in the report. */
export function pruneExplains(names: readonly string[]): void {
  const all = readAll()
  const keep = new Set(names)
  const stale = Object.keys(all).filter(name => !keep.has(name))
  if (stale.length === 0) return
  for (const name of stale) delete all[name]
  writeAll(all)
}
