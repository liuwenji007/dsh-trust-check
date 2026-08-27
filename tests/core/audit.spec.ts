import { describe, expect, it } from 'vitest'
import { auditPlugin, MAX_EVIDENCE } from '../../src/core/audit.ts'
import type { Evidence, PluginInput } from '../../src/core/types.ts'

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

describe('auditPlugin', () => {
  it('reports a clean client-only plugin as green and high-scoring', () => {
    const report = auditPlugin(input({
      manifest: { name: 'dsh-muyu', version: '0.1.4', repository: 'https://github.com/liuwenji007/dsh-muyu' },
      sources: { 'lib/client.js': 'export function apply() {}' },
    }))
    expect(report.band).toBe('green')
    expect(report.score).toBe(100)
    expect(report.capabilities).toEqual([])
    expect(report.summary).toContain('green')
  })

  it('reports a shell+network+install-script plugin as red with red lines', () => {
    const report = auditPlugin(input({
      manifest: { name: 'bad-plugin', version: '0.0.1', scripts: { postinstall: 'node setup.js' } },
      sources: { 'lib/index.js': "import { exec } from 'node:child_process'\nfetch('https://x.com')\n" },
      spec: 'npm:bad-plugin@latest',
    }))
    expect(report.band).toBe('red')
    expect(report.redLines).toContain('runs code at install time (postinstall)')
    expect(report.score).toBeLessThanOrEqual(49)
    expect(report.capabilities).toEqual(expect.arrayContaining(['shell', 'network']))
    expect(report.pinned).toBe(false)
  })

  it('estimates injected tokens from skill bytes', () => {
    const skill = '# Rule\nRun tests.\n'
    const report = auditPlugin(input({
      manifest: { name: 'skill-plugin', version: '1.0.0', repository: 'https://github.com/x/y' },
      skillFiles: { 'skills/test/SKILL.md': skill },
    }))
    expect(report.injectedTokensEstimate).toBe(Math.round(Buffer.byteLength(skill, 'utf8') / 4))
  })

  it('treats a missing manifest as an unknown-name plugin, not a crash', () => {
    const report = auditPlugin(input({ manifest: {}, spec: 'github:owner/repo' }))
    expect(report.name).toBe('unknown')
    expect(report.band).toBeDefined()
  })

  it('includes system-prompt bytes in injected token estimate', () => {
    const report = auditPlugin(input({
      manifest: { name: 'prompt-plugin', version: '1.0.0', repository: 'https://github.com/x/y' },
      sources: {
        'lib/index.js': `ctx.systemPrompt.section({ text: \`${'A'.repeat(400)}\` })\n`,
      },
    }))
    expect(report.injectedTokensEstimate).toBeGreaterThan(0)
  })

  it('caps evidence rows in the report', () => {
    const evidence: Evidence[] = Array.from({ length: MAX_EVIDENCE + 10 }, (_, i) => ({
      capability: 'network',
      file: 'lib/index.js',
      line: i + 1,
      snippet: `fetch(${i})`,
    }))
    const sources: Record<string, string> = {
      'lib/index.js': evidence.map(e => e.snippet).join('\n'),
    }
    const report = auditPlugin(input({ sources }))
    expect(report.evidence.length).toBe(MAX_EVIDENCE)
  })
})
