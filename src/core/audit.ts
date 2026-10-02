/**
 * Audit orchestrator: one pure function from PluginInput to AuditReport.
 * This is the single entry point shared by the node half, the CLI, tests,
 * and any future CI gate.
 */

import { sha256Hex } from '../host/content-hash.ts'
import { scanCapabilities } from './capability.ts'
import { injectionFingerprint, scanInjections } from './injection.ts'
import { readProvenance } from './provenance.ts'
import { scoreTrust } from './score.ts'
import { destinationFingerprint, pathEscapeFingerprint, presentShapeFindings, scanShape, secretTouchFingerprint } from './shape.ts'
import type { AuditReport, Capability, Evidence, Fact, PluginInput } from './types.ts'

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
  'dynamic-code': 'dynamic code',
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

/**
 * Cap evidence round-robin across capabilities, riskiest first, so a plugin
 * cannot bury its `shell` rows under forty harmless `llm` ones. `capabilities`
 * arrives pre-sorted by risk.
 */
function capEvidence(evidence: Evidence[], capabilities: Capability[]): Evidence[] {
  if (evidence.length <= MAX_EVIDENCE) return evidence

  const byCapability = new Map<Capability, Evidence[]>()
  for (const row of evidence) {
    const rows = byCapability.get(row.capability)
    if (rows === undefined) byCapability.set(row.capability, [row])
    else rows.push(row)
  }

  const queues = capabilities
    .map(capability => byCapability.get(capability) ?? [])
    .filter(queue => queue.length > 0)

  const kept = new Set<Evidence>()
  for (let round = 0; kept.size < MAX_EVIDENCE; round++) {
    let progressed = false
    for (const queue of queues) {
      if (round >= queue.length) continue
      kept.add(queue[round])
      progressed = true
      if (kept.size >= MAX_EVIDENCE) break
    }
    if (!progressed) break
  }

  return evidence.filter(row => kept.has(row))
}

const COVERAGE_FACTS: ReadonlyArray<{ prefix: string, id: string }> = [
  { prefix: 'computed module name in ', id: 'computed-module-name' },
  { prefix: 'native binding in ', id: 'native-binding' },
  { prefix: 'decoded eval in ', id: 'decoded-eval' },
  { prefix: 'comment stripping fell back to raw text in ', id: 'comment-strip-fallback' },
]

function buildFacts(evidence: Evidence[], notes: string[]): Fact[] {
  const groups = new Map<string, Fact>()
  for (const row of evidence) {
    if (row.rule === undefined) continue
    const fact = groups.get(row.rule) ?? { id: row.rule, value: row.capability, evidence: [] }
    fact.evidence.push({ file: row.file, line: row.line, snippet: row.snippet })
    groups.set(row.rule, fact)
  }
  const facts = [...groups.values()]
  for (const note of notes) {
    for (const kind of COVERAGE_FACTS) {
      if (!note.startsWith(kind.prefix)) continue
      facts.push({ id: kind.id, value: note.slice(kind.prefix.length), evidence: [] })
    }
  }
  return facts
}

function evidenceQueueOrder(capabilities: Capability[]): Capability[] {
  const shell = capabilities.filter(capability => capability === 'shell')
  const reads = capabilities.filter(capability => capability === 'fs-read')
  const rest = capabilities.filter(capability => capability !== 'shell' && capability !== 'fs-read')
  return [...shell, ...reads, ...rest]
}

export function auditPlugin(input: PluginInput): AuditReport {
  const { capabilities, evidence } = scanCapabilities(input)
  const { injections, skillBytes } = scanInjections(input)
  const fullShape = scanShape(input)
  const provenance = readProvenance(input)

  const promptBytes = injections
    .filter(inj => inj.kind === 'system-prompt')
    .reduce((sum, inj) => sum + inj.bytes, 0)

  // Coarse estimate: ~4 UTF-8 bytes per token for instruction-style text.
  const injectedTokensEstimate = Math.round((skillBytes + promptBytes) / 4)

  const { score, band, redLines, deductions } = scoreTrust({
    capabilities,
    secretTouches: fullShape.secretTouches,
    destinations: fullShape.destinations,
    injectedTokensEstimate,
    injections,
    hasBuildScript: provenance.hasBuildScript,
    buildScripts: provenance.buildScripts,
    prepareScripts: provenance.prepareScripts,
    repository: provenance.repository,
    pinned: provenance.pinned,
  })

  const presented = presentShapeFindings(fullShape)
  const ackFingerprint = sha256Hex(JSON.stringify({
    capabilities: [...capabilities].sort(),
    destinations: destinationFingerprint(fullShape.destinations),
    secretTouches: secretTouchFingerprint(fullShape.secretTouches),
    pathEscapes: pathEscapeFingerprint(fullShape.pathEscapes),
    injections: injectionFingerprint(injections),
    redLines: [...redLines].sort(),
  }))

  const report = {
    name: provenance.name,
    version: provenance.version,
    spec: input.spec,
    capabilities,
    evidence: capEvidence(evidence, evidenceQueueOrder(capabilities)),
    facts: buildFacts(capEvidence(evidence, evidenceQueueOrder(capabilities)), input.coverageNotes ?? []),
    destinations: presented.destinations,
    pathEscapes: presented.pathEscapes,
    secretTouches: presented.secretTouches,
    injections,
    injectedTokensEstimate,
    hasBuildScript: provenance.hasBuildScript,
    buildScripts: provenance.buildScripts,
    prepareScripts: provenance.prepareScripts,
    repository: provenance.repository,
    pinned: provenance.pinned,
    score,
    band,
    redLines,
    deductions,
    coverageNotes: input.coverageNotes ?? [],
    ackFingerprint,
  }

  return { ...report, summary: buildSummary(report) } as AuditReport
}
