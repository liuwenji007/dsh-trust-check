/**
 * Audit orchestrator: one pure function from PluginInput to AuditReport.
 * This is the single entry point shared by the node half, the CLI, tests,
 * and any future CI gate.
 */

import { scanCapabilities } from './capability.ts'
import { scanInjections } from './injection.ts'
import { readProvenance } from './provenance.ts'
import { scoreTrust } from './score.ts'
import type { AuditReport, Capability, PluginInput } from './types.ts'

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
  const parts: string[] = [`${report.band} · ${report.score}`]
  if (report.redLines.length > 0) parts.push(`${report.redLines.length} red line(s)`)
  if (report.capabilities.length === 0) {
    parts.push('no privileged capabilities')
  } else {
    parts.push(report.capabilities.map(c => CAPABILITY_SHORT[c]).join('+'))
  }
  if (report.injectedTokensEstimate > 0) parts.push(`~${report.injectedTokensEstimate} injected tokens`)
  parts.push(report.pinned ? 'pinned' : 'unpinned')
  return parts.join(' · ')
}

export function auditPlugin(input: PluginInput): AuditReport {
  const { capabilities, evidence } = scanCapabilities(input)
  const { injections, skillBytes } = scanInjections(input)
  const provenance = readProvenance(input)

  // Coarse estimate: ~4 UTF-8 bytes per token for instruction-style text.
  const injectedTokensEstimate = Math.round(skillBytes / 4)

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
    evidence,
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
