import { describe, expect, it } from 'vitest'
import {
  ackMatchesReport,
  fingerprintFromReport,
  normalizeAuditReport,
} from '../../src/core/ack-fingerprint.ts'
import type { AuditReport } from '../../src/core/types.ts'

describe('normalizeAuditReport', () => {
  it('backfills shape fields on older cached JSON', () => {
    const legacy = {
      name: 'old-plugin',
      version: '1.0.0',
      spec: 'npm:old@1',
      capabilities: ['network'],
      evidence: [],
      injections: [],
      injectedTokensEstimate: 0,
      hasBuildScript: false,
      buildScripts: [],
      repository: undefined,
      pinned: true,
      score: 90,
      band: 'yellow',
      redLines: [],
      deductions: [],
      summary: '',
    } as AuditReport

    const normalized = normalizeAuditReport(legacy)
    expect(normalized.destinations).toEqual([])
    expect(normalized.pathEscapes).toEqual([])
    expect(normalized.secretTouches).toEqual([])
  })

  it('strips legacy relative destinations', () => {
    const withRelative = {
      name: 'old-plugin',
      version: '1.0.0',
      spec: 'npm:old@1',
      capabilities: [],
      evidence: [],
      destinations: [{ kind: 'relative' as const, value: '/api', file: 'a.js', line: 1 }],
      injections: [],
      injectedTokensEstimate: 0,
      hasBuildScript: false,
      buildScripts: [],
      repository: undefined,
      pinned: true,
      score: 100,
      band: 'green' as const,
      redLines: [],
      deductions: [],
      summary: '',
    } as AuditReport
    expect(normalizeAuditReport(withRelative).destinations).toEqual([])
  })
})

describe('ackMatchesReport', () => {
  const report = (injections: AuditReport['injections']): AuditReport => ({
    name: 'p',
    version: '1.0.0',
    spec: 'npm:p@1.0.0',
    capabilities: [],
    evidence: [],
    destinations: [],
    pathEscapes: [],
    secretTouches: [],
    injections,
    injectedTokensEstimate: 0,
    hasBuildScript: false,
    buildScripts: [],
    repository: undefined,
    pinned: true,
    score: 100,
    band: 'green',
    redLines: [],
    deductions: [],
    summary: '',
  })

  it('drifts when an acknowledged plugin rewrites an injected skill file', () => {
    const before = report([{ kind: 'skill', detail: 'skills/a/SKILL.md', bytes: 100 }])
    const ack = fingerprintFromReport(before)
    expect(ackMatchesReport(before, ack)).toBe(true)

    const rewritten = report([{ kind: 'skill', detail: 'skills/a/SKILL.md', bytes: 900 }])
    expect(ackMatchesReport(rewritten, ack)).toBe(false)

    const added = report([
      { kind: 'skill', detail: 'skills/a/SKILL.md', bytes: 100 },
      { kind: 'system-prompt', detail: 'ctx.systemPrompt.section', bytes: 40 },
    ])
    expect(ackMatchesReport(added, ack)).toBe(false)
  })
})
