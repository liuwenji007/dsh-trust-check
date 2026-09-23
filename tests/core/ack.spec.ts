import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ackPath, readAckStore, removeAck, setAck } from '../../src/core/ack.ts'
import { ackMatchesReport, fingerprintFromReport } from '../../src/core/ack-fingerprint.ts'
import { verdict } from '../../src/core/present.ts'
import { auditPlugin } from '../../src/core/audit.ts'
import { decideAckSave } from '../../src/index.ts'
import type { AuditReport } from '../../src/core/types.ts'

const report = (): AuditReport => ({
  name: 'p',
  version: '1.0.0',
  spec: 'npm:p@1',
  capabilities: ['network', 'fs-read'],
  evidence: [],
  destinations: [{ kind: 'https-host', value: 'api.example.com', file: 'a.js', line: 1 }],
  pathEscapes: [{ kind: 'absolute', value: '/etc/passwd', file: 'a.js', line: 3 }],
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
  it('matches when the stored digest equals the report fingerprint', () => {
    const r = { ...report(), ackFingerprint: 'abc' }
    const fp = fingerprintFromReport(r)
    expect(fp.digest).toBe('abc')
    expect(ackMatchesReport(r, fp)).toBe(true)
  })

  it('fails when the report digest changes', () => {
    const r = { ...report(), ackFingerprint: 'abc' }
    const fp = fingerprintFromReport(r)
    expect(ackMatchesReport({ ...r, ackFingerprint: 'def' }, fp)).toBe(false)
  })

  it('fails when the ack has no digest', () => {
    const r = { ...report(), ackFingerprint: 'abc' }
    const fp = fingerprintFromReport(r)
    expect(ackMatchesReport(r, { ...fp, digest: undefined })).toBe(false)
  })
})

describe('decideAckSave', () => {
  const plain = () => auditPlugin({
    manifest: { name: 'plain', version: '1.0.0', repository: 'https://example.com/plain' },
    sources: { 'lib/index.js': 'export const ok = 1\n' },
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'npm:plain@1.0.0',
  })

  const shelled = () => auditPlugin({
    manifest: { name: 'shelled', version: '1.0.0' },
    sources: { 'lib/index.js': "import { execSync } from 'node:child_process'\nexecSync('id')\n" },
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'npm:shelled@1.0.0',
  })

  it('returns 409 before acceptRisk when the submitted digest is stale', () => {
    const fresh = shelled()
    const decision = decideAckSave(fresh, '0'.repeat(64), true)
    expect(decision.status).toBe(409)
    if (decision.status === 409) expect(decision.report.ackFingerprint).toBe(fresh.ackFingerprint)
  })

  it('saves only when the submitted digest matches the fresh scan', () => {
    const fresh = plain()
    expect(decideAckSave(fresh, fresh.ackFingerprint, false).status).toBe(200)
  })

  it('rejects a matching red-line digest without acceptRisk', () => {
    const fresh = auditPlugin({
      manifest: { name: 'installs', version: '1.0.0', scripts: { postinstall: 'node setup.js' } },
      sources: { 'lib/index.js': 'export const ok = 1\n' },
      skillFiles: {},
      patchText: undefined,
      patchPath: undefined,
      spec: 'npm:installs@1.0.0',
    })
    expect(fresh.redLines.length).toBeGreaterThan(0)
    expect(decideAckSave(fresh, fresh.ackFingerprint, false).status).toBe(400)
  })
})

describe('ack store', () => {
  const withProfile = (run: (dir: string) => void) => {
    const dir = mkdtempSync(join(tmpdir(), 'trust-ack-'))
    try {
      run(dir)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  const fresh = (): AuditReport => ({ ...report(), ackFingerprint: 'abc' })

  it('refuses to overwrite a corrupt store instead of wiping other acks', () => {
    withProfile(dir => {
      writeFileSync(ackPath(dir), '{"other": {"digest": "x"}, broken')
      expect(() => setAck(dir, fresh())).toThrow(/corrupt/)
      expect(() => removeAck(dir, 'other')).toThrow(/corrupt/)
      expect(readFileSync(ackPath(dir), 'utf8')).toContain('broken')
    })
  })

  it('reads a corrupt store as empty for display', () => {
    withProfile(dir => {
      writeFileSync(ackPath(dir), 'not json')
      expect(readAckStore(dir)).toEqual({})
    })
  })

  it('drops malformed entries so verdict never dereferences null', () => {
    withProfile(dir => {
      writeFileSync(ackPath(dir), JSON.stringify({ p: null, q: 'str', r: { digest: 'abc' } }))
      const store = readAckStore(dir)
      expect(Object.keys(store)).toEqual(['r'])
      expect(verdict(fresh(), store.p)).toBe('review')
    })
  })

  it('writes atomically and keeps other entries', () => {
    withProfile(dir => {
      writeFileSync(ackPath(dir), JSON.stringify({ other: { digest: 'x' } }))
      setAck(dir, fresh())
      const store = readAckStore(dir)
      expect(Object.keys(store).sort()).toEqual(['other', 'p'])
      expect(store.p?.digest).toBe('abc')
      expect(readdirSync(dir).filter(name => name.endsWith('.tmp'))).toEqual([])
    })
  })

  it('does not create a store when removing from a missing one', () => {
    withProfile(dir => {
      removeAck(dir, 'p')
      expect(existsSync(ackPath(dir))).toBe(false)
    })
  })
})
