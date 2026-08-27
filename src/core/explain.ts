/**
 * Build a bounded prompt for optional LLM explanation. Does not call the model.
 */

import { groupEvidence, presentInjection } from './present.ts'
import type { AuditReport } from './types.ts'

export const EXPLAIN_SYSTEM = `You are helping a developer read ONE specific DeepSeek Harness plugin audit.
This is reading assistance only — NOT a security verdict and must not change any badge.

Do:
- Talk about THIS plugin by name: what it appears to be doing, based on the concrete red lines, hosts, paths, scripts, and evidence snippets provided.
- Tie each concern to a specific finding (host, path, file:line, script name). Prefer "because it calls X / connects to Y" over definitions.
- Separate: (a) findings that look consistent with the plugin's likely job, vs (b) findings that deserve extra caution for THIS report.
- Note static-analysis limits briefly (runtime-built URLs / behavior are invisible).

Do not:
- Define what "capabilities", "red lines", "destinations", or "path escapes" mean in the abstract.
- Dump a glossary or section-by-section dictionary of the report UI.
- Say the plugin is safe, trusted, or harmless.
- Tell the user to ignore red lines.

Style: concise prose (under 280 words), no markdown headings if you can avoid them, user's language when asked.`

const EVIDENCE_PER_CAP = 4

export function buildExplainPrompt(report: AuditReport, locale?: string): string {
  const lines: string[] = []
  lines.push(`Analyze this plugin audit as a case study of "${report.name}", not a glossary of audit terms.`)
  lines.push(`Plugin: ${report.name}@${report.version}`)
  lines.push(`Install spec: ${report.spec}`)
  if (report.repository !== undefined) lines.push(`Repository: ${report.repository}`)
  lines.push(`Pinned: ${report.pinned ? 'yes' : 'no'}`)
  if (report.hasBuildScript) {
    lines.push(`Install scripts: ${report.buildScripts.join(', ') || '(declared)'}`)
  }
  if (report.summary !== '') lines.push(`Scanner summary: ${report.summary}`)
  if (locale !== undefined && locale !== '') lines.push(`Respond in: ${locale}`)
  lines.push('')
  lines.push(`Capabilities detected: ${report.capabilities.length === 0 ? 'none' : report.capabilities.join(', ')}`)
  if (report.redLines.length > 0) {
    lines.push('Red lines (code-judged):')
    for (const line of report.redLines) lines.push(`- ${line}`)
  }
  const destinations = (report.destinations ?? []).filter(d => d.kind !== 'relative')
  if (destinations.length > 0) {
    lines.push('Literal destinations in source:')
    for (const d of destinations.slice(0, 18)) {
      lines.push(`- ${d.kind}: ${d.value} @ ${d.file}:${d.line}`)
    }
  }
  const pathEscapes = report.pathEscapes ?? []
  if (pathEscapes.length > 0) {
    lines.push('Workspace path escapes in source:')
    for (const p of pathEscapes.slice(0, 12)) {
      lines.push(`- ${p.kind}: ${p.value} @ ${p.file}:${p.line}`)
    }
  }
  if ((report.secretTouches ?? []).length > 0) {
    lines.push('Secret / credential touches:')
    for (const s of report.secretTouches.slice(0, 10)) {
      lines.push(`- ${s.kind}: ${s.value} @ ${s.file}:${s.line}`)
    }
  }
  if (report.injections.length > 0) {
    lines.push('Injections:')
    for (const inj of report.injections.slice(0, 8)) {
      const view = presentInjection(inj.detail)
      const detail = view.packages?.join(', ')
        ?? view.target
        ?? view.fallback
        ?? inj.detail
      lines.push(`- ${inj.kind}: ${detail}`)
    }
  }
  const grouped = groupEvidence(report.evidence)
  if (grouped.size > 0) {
    lines.push('Evidence snippets (highest-weight capabilities first is not guaranteed — use what is listed):')
    for (const [cap, rows] of grouped.entries()) {
      lines.push(`[${cap}]`)
      for (const ev of rows.slice(0, EVIDENCE_PER_CAP)) {
        lines.push(`  ${ev.file}:${ev.line} ${ev.snippet}`)
      }
    }
  }
  lines.push('')
  lines.push(
    [
      'Write a short case analysis for this plugin only:',
      '1) Likely purpose inferred from name + findings.',
      '2) Which specific findings are the main reasons for caution, with concrete values.',
      '3) Which findings might be normal for this kind of tool (say so tentatively).',
      'Do not redefine report sections. Do not change any verdict.',
    ].join(' '),
  )
  return lines.join('\n')
}
