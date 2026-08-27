/**
 * Trust scoring: a deterministic, code-only model. No LLM, no network —
 * every deduction is reproducible from the evidence the scanner produced.
 */

import type { Band, Capability, Deduction, InjectionFinding } from './types.ts'

export const CAPABILITY_WEIGHT: Readonly<Record<Capability, number>> = {
  shell: 25,
  'fs-write': 15,
  network: 10,
  credentials: 20,
  'fs-read': 5,
  env: 2,
  subagent: 8,
  'host-runtime': 5,
  llm: 4,
}

/** Max token-cost deduction, so a docs-heavy plugin is not scored like malware. */
const MAX_TOKEN_DEDUCTION = 20
/** Token discount step: 1 point per this many estimated injected tokens. */
const TOKEN_DEDUCTION_STEP = 50

export interface ScoreInput {
  capabilities: Capability[]
  injectedTokensEstimate: number
  injections: InjectionFinding[]
  hasBuildScript: boolean
  buildScripts: string[]
  repository: string | undefined
  pinned: boolean
}

export interface ScoreResult {
  score: number
  band: Band
  redLines: string[]
  deductions: Deduction[]
}

function bundleIdOf(finding: InjectionFinding): string | undefined {
  const match = /(?:overrides|disables) bundle ([^\s]+)/.exec(finding.detail)
  return match?.[1]
}

export function scoreTrust(input: ScoreInput): ScoreResult {
  const redLines: string[] = []
  const deductions: Deduction[] = []
  let total = 0

  for (const capability of input.capabilities) {
    const weight = CAPABILITY_WEIGHT[capability] ?? 0
    if (weight > 0) {
      total += weight
      deductions.push({ reason: `uses ${capability}`, amount: weight })
    }
  }

  // Build scripts: arbitrary code at install time.
  if (input.hasBuildScript) {
    redLines.push(`runs code at install time (${input.buildScripts.join(', ')})`)
  }

  // Patch tampering: override/disable another bundle.
  for (const finding of input.injections) {
    if (finding.kind !== 'override' && finding.kind !== 'disable') continue
    const id = bundleIdOf(finding)
    if (id !== undefined && id.startsWith('@deepseek-ai/')) {
      redLines.push(`tampers with a core bundle (${finding.detail})`)
    } else {
      total += 10
      deductions.push({ reason: finding.detail, amount: 10 })
    }
  }

  // Secrets + network together is the classic exfiltration shape.
  if (input.capabilities.includes('credentials') && input.capabilities.includes('network')) {
    redLines.push('reads credentials/secrets AND has network access')
  }

  // Token cost of injected content.
  if (input.injectedTokensEstimate > 0) {
    const amount = Math.min(
      MAX_TOKEN_DEDUCTION,
      Math.floor(input.injectedTokensEstimate / TOKEN_DEDUCTION_STEP),
    )
    if (amount > 0) {
      total += amount
      deductions.push({ reason: `injects ~${input.injectedTokensEstimate} tokens`, amount })
    }
  }

  if (input.repository === undefined) {
    total += 5
    deductions.push({ reason: 'no repository/homepage declared', amount: 5 })
  }

  if (!input.pinned) {
    total += 10
    deductions.push({ reason: 'install spec is not pinned (moving target)', amount: 10 })
  }

  const score = Math.max(0, Math.min(100, 100 - total))
  const band: Band = redLines.length > 0 || score < 50 ? 'red' : score < 80 ? 'yellow' : 'green'

  return { score, band, redLines, deductions }
}
