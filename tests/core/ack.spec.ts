import { describe, expect, it } from 'vitest'
import { ackMatchesReport, fingerprintFromReport } from '../../src/core/ack-fingerprint.ts'
import type { AuditReport, Capability } from '../../src/core/types.ts'

const report = (): AuditReport => ({
  name: 'p',
  version: '1.0.0',
  spec: 'npm:p@1',
  capabilities: ['network', 'fs-read'],
  evidence: [],
  destinations: [{ kind: 'relative', value: '/x', file: 'a.js', line: 1 }],
  secretTouches: [{ kind: 'env-key', value: 'FOO', file: 'a.js', line: 2 }],
  injections: [],
  injectedTokensEstimate: 0,
  hasBuildScript: false,
  buildScripts: [],
  repository: undefined,
  pinned: true,
  score: 80,
  band: 'yellow',
  redLines: [],
  deductions: [],
  summary: '',
})

describe('ack fingerprint', () => {
  it('matches when capabilities destinations and secrets equal', () => {
    const r = report()
    const fp = fingerprintFromReport(r)
    expect(ackMatchesReport(r, fp)).toBe(true)
  })

  it('fails when capability added', () => {
    const r = report()
    const fp = fingerprintFromReport(r)
    const changed = { ...r, capabilities: [...r.capabilities, 'shell'] as Capability[] }
    expect(ackMatchesReport(changed, fp)).toBe(false)
  })
})
