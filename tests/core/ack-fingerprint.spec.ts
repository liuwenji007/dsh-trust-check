import { describe, expect, it } from 'vitest'
import { normalizeAuditReport } from '../../src/core/ack-fingerprint.ts'
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
    expect(normalized.secretTouches).toEqual([])
  })
})
