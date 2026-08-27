/**
 * Audit orchestrator: one pure function from PluginInput to AuditReport.
 * This is the single entry point shared by the node half, the CLI, tests,
 * and any future CI gate.
 */

import { scanCapabilities } from './capability.ts'
import { scanInjections } from './injection.ts'
import { readProvenance } from './provenance.ts'
import { scoreTrust } from './score.ts'
import type { AuditReport, Capability, Evidence, PluginInput } from './types.ts'

/** Cap evidence rows so hostile plugins cannot explode JSON responses. */
export const MAX_EVIDENCE = 40

const CAPABILITY_SHORT: Readonly<Record<Capability, string>> = {
  shell: 'shell',
  'fs-write': 'file writes',
  'fs-read': 'file reads',
  network: 'network',
  credentials: 'secrets',
  env: 'env reads',
  subagent: 'sub-agents',
  'host-runtime': 'host runtime',
  llm: 'LLM calls',
}

function buildSummary(report: Omit<AuditReport, 'summary'>): string {
  const parts: string[] = []
  if (report.redLines.length > 0) {
    parts.push(`${report.redLines.length} red line(s)`)
  } else if (report.capabilities.length > 0) {
    parts.push('review suggested')
  } else {
    parts.push('no red lines')
  }
  if (report.capabilities.length === 0) {
    parts.push('no privileged capabilities')
  } else {
    parts.push(report.capabilities.map(c => CAPABILITY_SHORT[c]).join('+'))
  }
  if (report.injectedTokensEstimate > 0) parts.push(`~${report.injectedTokensEstimate} injected tokens`)
  parts.push(report.pinned ? 'pinned' : 'unpinned')
  return parts.join(' · ')
}

function capEvidence(evidence: Evidence[]): Evidence[] {
  if (evidence.length <= MAX_EVIDENCE) return evidence
  return evidence.slice(0, MAX_EVIDENCE)
}

export function auditPlugin(input: PluginInput): AuditReport {
  const { capabilities, evidence } = scanCapabilities(input)
  const { injections, skillBytes } = scanInjections(input)
  const provenance = readProvenance(input)

  const promptBytes = injections
    .filter(inj => inj.kind === 'system-prompt')
    .reduce((sum, inj) => sum + inj.bytes, 0)

  // Coarse estimate: ~4 UTF-8 bytes per token for instruction-style text.
  const injectedTokensEstimate = Math.round((skillBytes + promptBytes) / 4)

  const { score, band, redLines, deductions } = scoreTrust({
    capabilities,
    injectedTokensEstimate,
    injections,
    hasBuildScript: provenance.hasBuildScript,
    buildScripts: provenance.buildScripts,
    repository: provenance.repository,
    pinned: provenance.pinned,
  })

  const report = {
    name: provenance.name,
    version: provenance.version,
    spec: input.spec,
    capabilities,
    evidence: capEvidence(evidence),
    injections,
    injectedTokensEstimate,
    hasBuildScript: provenance.hasBuildScript,
    buildScripts: provenance.buildScripts,
    repository: provenance.repository,
    pinned: provenance.pinned,
    score,
    band,
    redLines,
    deductions,
  }

  return { ...report, summary: buildSummary(report) } as AuditReport
}
