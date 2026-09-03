/**
 * Trust scoring: a deterministic, code-only model. No LLM, no network —
 * every deduction is reproducible from the evidence the scanner produced.
 */

import type { Band, Capability, Deduction, DestinationFinding, InjectionFinding } from './types.ts'
import { shapeRedLines } from './shape.ts'

export const CAPABILITY_WEIGHT: Readonly<Record<Capability, number>> = {
  shell: 25,
  'dynamic-code': 18,
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
  destinations: DestinationFinding[]
  injectedTokensEstimate: number
  injections: InjectionFinding[]
  hasBuildScript: boolean
  buildScripts: string[]
  /** `prepare` only — runs on publish/pack or git install, not registry install. */
  prepareScripts: string[]
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
  const id = match?.[1]
  if (id === undefined || id === '(unknown)') return undefined
  return id
}

/** When any red line fires, the numeric score cannot exceed this value. */
export const RED_LINE_SCORE_CAP = 49

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

  // Build scripts: arbitrary code at install time. Only preinstall/install/
  // postinstall run on a consumer's machine during a registry install, so
  // only those are a red line.
  if (input.hasBuildScript) {
    redLines.push(`runs code at install time (${input.buildScripts.join(', ')})`)
  }

  // `prepare` does not run on a registry install, but it DOES run when the
  // package is installed from git. A small deduction (not a red line) keeps
  // the signal without crying wolf on the market's npm install path.
  if ((input.prepareScripts?.length ?? 0) > 0) {
    total += 5
    deductions.push({ reason: `runs prepare on pack/git install (${input.prepareScripts.join(', ')})`, amount: 5 })
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

  for (const line of shapeRedLines(input.capabilities, input.destinations)) {
    if (!redLines.includes(line)) redLines.push(line)
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

  let score = Math.max(0, Math.min(100, 100 - total))
  if (redLines.length > 0 && score > RED_LINE_SCORE_CAP) {
    deductions.push({ reason: 'red line cap', amount: score - RED_LINE_SCORE_CAP })
    score = RED_LINE_SCORE_CAP
  }
  const band: Band = redLines.length > 0 || score < 50 ? 'red' : score < 80 ? 'yellow' : 'green'

  return { score, band, redLines, deductions }
}
