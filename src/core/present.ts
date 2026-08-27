/**
 * Presentation layer: maps AuditReport JSON to human-facing verdicts and
 * concern lists. Shared by the settings UI and CLI; no DOM, no locale strings.
 */

import { ackMatchesReport } from './ack-fingerprint.ts'
import { destinationTier } from './destination-priority.ts'
import { CAPABILITY_WEIGHT } from './score.ts'
import type { AuditReport, Capability, Evidence, InjectionKind, TrustAckEntry } from './types.ts'

export type Verdict = 'red' | 'review' | 'expected' | 'clear'

export type RedLineCode =
  | 'install-script'
  | 'core-tamper'
  | 'creds-network'
  | 'plaintext-http'
  | 'literal-ip'
  | 'raw'

export type ConcernCode = RedLineCode | Capability | 'external-dest' | 'secret-touch'

export interface Concern {
  code: ConcernCode
  /** Original red-line text when code is `raw`. */
  detail?: string
}

/** Classify a scanner red-line string into a stable presentation code. */
export function classifyRedLine(line: string): RedLineCode {
  if (line.startsWith('runs code at install time')) return 'install-script'
  if (line.startsWith('tampers with a core bundle')) return 'core-tamper'
  if (line === 'reads credentials/secrets AND has network access') return 'creds-network'
  if (line.startsWith('uses plaintext http://')) return 'plaintext-http'
  if (line.startsWith('uses literal IP')) return 'literal-ip'
  return 'raw'
}

/**
 * User-facing verdict. Unlike `band`, low scores without red lines are `review`, not `red`.
 */
export function verdict(report: AuditReport, ack?: TrustAckEntry): Verdict {
  if (report.redLines.length > 0) return 'red'
  if (ack !== undefined && ackMatchesReport(report, ack)) return 'expected'
  const hasPatchChange = report.injections.some(
    inj => inj.kind === 'override' || inj.kind === 'disable',
  )
  if (report.capabilities.length > 0 || hasPatchChange) return 'review'
  return 'clear'
}

/** True when there is an outbound destination that is not on the safe allowlist. */
function externalDestinations(report: AuditReport): boolean {
  return (report.destinations ?? []).some(d => {
    if (d.kind !== 'https-host' && d.kind !== 'http-host' && d.kind !== 'ip') return false
    return destinationTier(d) !== 'safe'
  })
}

const CONCERN_EN: Partial<Record<ConcernCode, string>> = {
  'install-script': 'May run arbitrary code at install time',
  'core-tamper': 'Tamper with a core bundle',
  'creds-network': 'Read credentials and access the network',
  'plaintext-http': 'Uses plaintext HTTP outbound',
  'literal-ip': 'Uses literal IP outbound',
  'external-dest': 'External destination literals in source',
  'secret-touch': 'May touch secrets or sensitive env vars',
  shell: 'Execute system commands',
  'fs-write': 'Write local files',
  'fs-read': 'Read local files',
  network: 'Access the network',
  credentials: 'Read credentials or secrets',
  env: 'Read environment variables',
  subagent: 'Spawn sub-agents',
  'host-runtime': 'Call host runtime APIs',
  llm: 'Call language models',
}

/** English one-liner for CLI / non-UI consumers. */
export function concernText(concern: Concern): string {
  if (concern.code === 'raw') return concern.detail ?? ''
  return CONCERN_EN[concern.code] ?? concern.code
}

/** Up to `max` concern bullets: red lines first, then shape, then capabilities by weight. */
export function concerns(report: AuditReport, max = 3): Concern[] {
  const result: Concern[] = []
  for (const line of report.redLines) {
    if (result.length >= max) break
    const code = classifyRedLine(line)
    result.push(code === 'raw' ? { code, detail: line } : { code })
  }
  if (result.length >= max) return result

  if (externalDestinations(report) && !result.some(c => c.code === 'external-dest')) {
    result.push({ code: 'external-dest' })
  }
  if (result.length >= max) return result

  if ((report.secretTouches ?? []).length > 0 && !result.some(c => c.code === 'secret-touch')) {
    result.push({ code: 'secret-touch' })
  }
  if (result.length >= max) return result

  const ranked = [...report.capabilities].sort(
    (a, b) => (CAPABILITY_WEIGHT[b] ?? 0) - (CAPABILITY_WEIGHT[a] ?? 0),
  )
  for (const cap of ranked) {
    if (result.length >= max) break
    if (!result.some(item => item.code === cap)) result.push({ code: cap })
  }
  return result
}

/** Group evidence rows by capability for the collapsible evidence panel. */
export function groupEvidence(evidence: Evidence[]): Map<Capability, Evidence[]> {
  const map = new Map<Capability, Evidence[]>()
  for (const row of evidence) {
    const list = map.get(row.capability) ?? []
    list.push(row)
    map.set(row.capability, list)
  }
  return map
}

export interface EvidenceFileGroup {
  file: string
  rows: Evidence[]
}

/** Group evidence by file; collapse import-only rows when calls exist in same file. */
export function groupEvidenceByFile(evidence: Evidence[]): EvidenceFileGroup[] {
  const byFile = new Map<string, Evidence[]>()
  for (const row of evidence) {
    const list = byFile.get(row.file) ?? []
    list.push(row)
    byFile.set(row.file, list)
  }

  const groups: EvidenceFileGroup[] = []
  for (const [file, rows] of byFile.entries()) {
    const hasCall = rows.some(r => !isImportOnlySnippet(r.snippet))
    const filtered = hasCall ? rows.filter(r => !isImportOnlySnippet(r.snippet)) : rows
    groups.push({ file, rows: filtered })
  }
  return groups.sort((a, b) => b.rows.length - a.rows.length)
}

function isImportOnlySnippet(snippet: string): boolean {
  const s = snippet.trim()
  return /^import\s/.test(s)
    || /^from\s+['"]/.test(s)
    || /^(?:require|import)\s*\(/.test(s)
}

/** Highest-weight capabilities for collapsed row chips. */
export function topCapabilities(report: AuditReport, max = 3): Capability[] {
  return [...report.capabilities]
    .sort((a, b) => (CAPABILITY_WEIGHT[b] ?? 0) - (CAPABILITY_WEIGHT[a] ?? 0))
    .slice(0, max)
}

/** Strip engine prefixes from injection detail strings for display. */
export function formatInjectionDetail(detail: string): string {
  const prefix = 'skill ships instruction text '
  if (detail.startsWith(prefix)) return detail.slice(prefix.length)
  return detail
}

/** Group injections by kind for the expanded injection panel. */
export function groupInjections(
  report: AuditReport,
): Map<InjectionKind, typeof report.injections> {
  const map = new Map<InjectionKind, typeof report.injections>()
  for (const finding of report.injections) {
    const list = map.get(finding.kind) ?? []
    list.push(finding)
    map.set(finding.kind, list)
  }
  return map
}

/** Count verdicts across a plugin list (for the page overview line). */
export function countVerdicts(
  reports: AuditReport[],
  acks?: Record<string, TrustAckEntry>,
): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { red: 0, review: 0, expected: 0, clear: 0 }
  for (const report of reports) counts[verdict(report, acks?.[report.name])]++
  return counts
}

/** Chip severity tier for styling: high / medium / neutral. */
export function capabilityTier(cap: Capability): 'high' | 'medium' | 'neutral' {
  if (cap === 'shell' || cap === 'credentials') return 'high'
  if (cap === 'fs-write') return 'medium'
  return 'neutral'
}

/** Whether ack exists but fingerprint drifted from current scan. */
export function ackDrifted(report: AuditReport, ack?: TrustAckEntry): boolean {
  if (ack === undefined) return false
  if (report.redLines.length > 0) return false
  return !ackMatchesReport(report, ack)
}
