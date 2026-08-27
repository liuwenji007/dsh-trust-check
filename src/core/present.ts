/**
 * Presentation layer: maps AuditReport JSON to human-facing verdicts and
 * concern lists. Shared by the settings UI and CLI; no DOM, no locale strings.
 */

import { CAPABILITY_WEIGHT } from './score.ts'
import type { AuditReport, Capability, Evidence, InjectionKind } from './types.ts'

export type Verdict = 'red' | 'review' | 'clear'

export type RedLineCode = 'install-script' | 'core-tamper' | 'creds-network' | 'raw'

export type ConcernCode = RedLineCode | Capability

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
  return 'raw'
}

/**
 * User-facing verdict. Unlike `band`, low scores without red lines are `review`, not `red`.
 */
export function verdict(report: AuditReport): Verdict {
  if (report.redLines.length > 0) return 'red'
  const hasPatchChange = report.injections.some(
    inj => inj.kind === 'override' || inj.kind === 'disable',
  )
  if (report.capabilities.length > 0 || hasPatchChange) return 'review'
  return 'clear'
}

/** Up to `max` concern bullets: red lines first, then capabilities by weight. */
export function concerns(report: AuditReport, max = 3): Concern[] {
  const result: Concern[] = []
  for (const line of report.redLines) {
    if (result.length >= max) break
    const code = classifyRedLine(line)
    result.push(code === 'raw' ? { code, detail: line } : { code })
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
export function countVerdicts(reports: AuditReport[]): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { red: 0, review: 0, clear: 0 }
  for (const report of reports) counts[verdict(report)]++
  return counts
}

/** Chip severity tier for styling: high / medium / neutral. */
export function capabilityTier(cap: Capability): 'high' | 'medium' | 'neutral' {
  if (cap === 'shell' || cap === 'credentials') return 'high'
  if (cap === 'fs-write') return 'medium'
  return 'neutral'
}
