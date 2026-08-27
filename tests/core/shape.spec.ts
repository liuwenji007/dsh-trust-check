import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { scanShape, shapeRedLines } from '../../src/core/shape.ts'
import { scoreTrust } from '../../src/core/score.ts'
import type { PluginInput } from '../../src/core/types.ts'

function input(sources: Record<string, string>): PluginInput {
  return {
    manifest: { name: 'shape-test', version: '1.0.0' },
    sources,
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'dir:.',
  }
}

describe('scanShape', () => {
  it('finds relative paths without red lines', () => {
    const { destinations } = scanShape(input({
      'client.js': 'await fetch("/dsh-trust-check/audit")',
    }))
    expect(destinations.some(d => d.kind === 'relative' && d.value === '/dsh-trust-check/audit')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('records https host without red line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("https://api.github.com/repos/x")',
    }))
    expect(destinations.some(d => d.kind === 'https-host' && d.value === 'api.github.com')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('flags plaintext http host as red line when network present', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://evil.test/leak")',
    }))
    const lines = shapeRedLines(['network'], destinations)
    expect(lines.some(l => l.startsWith('uses plaintext http://'))).toBe(true)
  })

  it('flags non-loopback literal IP with network', () => {
    const { destinations } = scanShape(input({
      'a.js': 'const u = "203.0.113.1/api"',
    }))
    const lines = shapeRedLines(['network'], destinations)
    expect(lines.some(l => l.startsWith('uses literal IP'))).toBe(true)
  })

  it('skips private IP range-table boundaries (SSRF denylist)', () => {
    const { destinations } = scanShape(input({
      'a.js': 'return inRange(value, "10.0.0.0", "10.255.255.255") || inRange(value, "192.168.0.0", "192.168.255.255")',
    }))
    expect(destinations.filter(d => d.kind === 'ip')).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('still records a lone literal IP used as a destination', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://203.0.113.50/x")',
    }))
    // http URL takes host path; also ensure raw IP on its own line is kept
    const alone = scanShape(input({ 'b.js': 'const host = "203.0.113.50"' }))
    expect(alone.destinations.some(d => d.kind === 'ip' && d.value === '203.0.113.50')).toBe(true)
    expect(destinations.some(d => d.kind === 'http-host' && d.value === '203.0.113.50')).toBe(true)
  })

  it('skips placeholder URL bases and example hosts', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'new URL(request.url ?? "", "http://local")',
        'fetch("https://dav.example/x")',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === 'local' || d.value.includes('example'))).toBe(false)
  })

  it('skips shell switches and filesystem absolute paths', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        "spawn(COMSPEC, ['/d', '/s', '/c', cmd])",
        "dirs.push('/opt/homebrew/bin', '/usr/local/bin')",
        'await fetch("/dsh-market/check")',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === '/c' || d.value.startsWith('/opt/') || d.value.startsWith('/usr/'))).toBe(false)
    expect(destinations.some(d => d.kind === 'relative' && d.value === '/dsh-market/check')).toBe(true)
  })

  it('skips template http hosts that are not literals', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch(`http://${host}/x`)',
    }))
    expect(destinations.some(d => d.kind === 'http-host')).toBe(false)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('captures sensitive env key names', () => {
    const { secretTouches } = scanShape(input({
      'a.js': 'const k = process.env.OPENAI_API_KEY',
    }))
    expect(secretTouches.some(s => s.kind === 'env-key' && s.value === 'OPENAI_API_KEY')).toBe(true)
  })
})

describe('auditPlugin shape integration', () => {
  it('does not red-line relative audit fetch', () => {
    const report = auditPlugin(input({
      'client.js': [
        'import { readFileSync } from "fs"',
        'await fetch("/dsh-trust-check/audit")',
      ].join('\n'),
    }))
    expect(report.capabilities).toContain('network')
    expect(report.destinations.some(d => d.value === '/dsh-trust-check/audit')).toBe(true)
    expect(report.redLines).toEqual([])
  })

  it('red-lines http evil host with network', () => {
    const report = auditPlugin(input({
      'a.js': 'fetch("http://evil.test/x")',
    }))
    expect(report.redLines.some(l => l.startsWith('uses plaintext http://'))).toBe(true)
    expect(report.band).toBe('red')
  })
})

describe('scoreTrust destinations', () => {
  it('merges shape red lines', () => {
    const result = scoreTrust({
      capabilities: ['network'],
      destinations: [{ kind: 'http-host', value: 'evil.test', file: 'a.js', line: 1 }],
      injectedTokensEstimate: 0,
      injections: [],
      hasBuildScript: false,
      buildScripts: [],
      repository: 'https://github.com/x/y',
      pinned: true,
    })
    expect(result.redLines.some(l => l.includes('evil.test'))).toBe(true)
  })
})
