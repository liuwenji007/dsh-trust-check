/**
 * Build a bounded prompt for optional LLM explanation. Does not call the model.
 */

import { groupEvidence } from './present.ts'
import type { AuditReport } from './types.ts'

export const EXPLAIN_SYSTEM = `You explain a static plugin audit report in plain language.
Rules:
- This is reading assistance only, NOT a security verdict.
- Never say the plugin is safe, trusted, or harmless.
- Never tell the user to ignore red lines or capabilities.
- Explain what the listed capabilities, destinations, and evidence snippets likely mean.
- Acknowledge static analysis limits: runtime-built URLs and hidden behavior are invisible.
- Be concise (under 300 words). Use the user's language if indicated in the user message.`

const EVIDENCE_PER_CAP = 5

export function buildExplainPrompt(report: AuditReport, locale?: string): string {
  const lines: string[] = []
  lines.push(`Plugin: ${report.name}@${report.version}`)
  lines.push(`Install spec: ${report.spec}`)
  if (locale !== undefined && locale !== '') lines.push(`Respond in: ${locale}`)
  lines.push('')
  lines.push(`Capabilities: ${report.capabilities.length === 0 ? 'none' : report.capabilities.join(', ')}`)
  if (report.redLines.length > 0) {
    lines.push('Red lines:')
    for (const line of report.redLines) lines.push(`- ${line}`)
  }
  if (report.destinations.length > 0) {
    lines.push('Literal destinations (source only):')
    for (const d of report.destinations.slice(0, 15)) {
      lines.push(`- ${d.kind}: ${d.value} (${d.file}:${d.line})`)
    }
  }
  if (report.secretTouches.length > 0) {
    lines.push('Secret touches:')
    for (const s of report.secretTouches.slice(0, 10)) {
      lines.push(`- ${s.kind}: ${s.value} (${s.file}:${s.line})`)
    }
  }
  const grouped = groupEvidence(report.evidence)
  if (grouped.size > 0) {
    lines.push('Evidence samples:')
    for (const [cap, rows] of grouped.entries()) {
      lines.push(`[${cap}]`)
      for (const ev of rows.slice(0, EVIDENCE_PER_CAP)) {
        lines.push(`  ${ev.file}:${ev.line} ${ev.snippet}`)
      }
    }
  }
  lines.push('')
  lines.push('Explain what the user should understand from this report. Do not change any verdict.')
  return lines.join('\n')
}
