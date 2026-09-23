import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import {
  ackMatchesReport,
  fingerprintFromReport,
  normalizeAuditReport,
} from '../../src/core/ack-fingerprint.ts'
import { auditPlugin } from '../../src/core/audit.ts'
import { injectionFingerprint, scanInjections } from '../../src/core/injection.ts'
import { verdict } from '../../src/core/present.ts'
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

  it('does not treat an old byte-sized ack as a match', () => {
    const before = report([{ kind: 'skill', detail: 'skills/a/SKILL.md', path: 'skills/a/SKILL.md', bytes: 7, contentHash: 'abc' }])
    before.ackFingerprint = 'current'
    const stale = {
      capabilities: [] as AuditReport['capabilities'],
      destinations: [],
      secretTouches: [],
      pathEscapes: [],
      injections: ['skill:ships instruction text skills/a/SKILL.md:7'],
      redLines: [],
      at: '2020-01-01T00:00:00.000Z',
    }
    expect(ackMatchesReport(before, stale)).toBe(false)
    expect(verdict(before, stale)).toBe('clear')
  })

  it('fingerprints skill text by kind, path, and sha256', () => {
    const text = 'do evil'
    const hash = createHash('sha256').update(text, 'utf8').digest('hex')
    const scan = scanInjections({
      manifest: {},
      sources: {},
      skillFiles: { 'skills/a/SKILL.md': text },
      patchText: undefined,
      patchPath: undefined,
      spec: 'npm:x@1',
    })
    expect(scan.injections[0]?.contentHash).toBe(hash)
    expect(scan.injections[0]?.bytes).toBe(Buffer.byteLength(text))
    expect(injectionFingerprint(scan.injections)).toEqual([`skill:skills/a/SKILL.md:${hash}`])
  })

  it('requires a renewed acknowledgement when the stored ack has no digest', () => {
    const audited = auditPlugin({
      manifest: { name: 'skilled', version: '1.0.0', repository: 'https://example.com/skilled' },
      sources: { 'lib/index.js': "fetch('https://evil.test/x')\n" },
      skillFiles: { 'skills/a/SKILL.md': 'do evil' },
      patchText: undefined,
      patchPath: undefined,
      spec: 'npm:skilled@1.0.0',
    })
    const stale = {
      capabilities: [],
      destinations: [],
      secretTouches: [],
      pathEscapes: [],
      injections: ['skill:ships instruction text skills/a/SKILL.md:7'],
      redLines: [],
      at: '2020-01-01T00:00:00.000Z',
    }
    expect(ackMatchesReport(audited, stale)).toBe(false)
    expect(verdict(audited, stale)).toBe('review')
  })

  it('keeps hash helpers out of the browser fingerprint module', () => {
    const ackSource = readFileSync(new URL('../../src/core/ack-fingerprint.ts', import.meta.url), 'utf8')
    const injectionSource = readFileSync(new URL('../../src/core/injection.ts', import.meta.url), 'utf8')
    expect(ackSource.includes('node:crypto')).toBe(false)
    expect(injectionSource.includes('node:crypto')).toBe(false)
  })
})
