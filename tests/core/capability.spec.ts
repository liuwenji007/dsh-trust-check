import { describe, expect, it } from 'vitest'
import { scanCapabilities } from '../../src/core/capability.ts'
import type { PluginInput } from '../../src/core/types.ts'

function input(sources: Record<string, string>, manifest: Record<string, unknown> = {}): PluginInput {
  return { manifest, sources, skillFiles: {}, patchText: undefined, patchPath: undefined, spec: 'npm:x@1.0.0' }
}

describe('scanCapabilities', () => {
  it('finds no capabilities for an empty/client-only plugin', () => {
    const result = scanCapabilities(input({
      'lib/client.js': "export function apply(ctx) { ctx.slots.inject('settings.section', () => {}) }",
    }))
    expect(result.capabilities).toEqual([])
    expect(result.evidence).toEqual([])
  })

  it('detects shell and network with located evidence', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "import { execSync } from 'node:child_process'\nawait fetch('https://example.com')\n",
    }))
    expect(result.capabilities).toContain('shell')
    expect(result.capabilities).toContain('network')
    const shellEvidence = result.evidence.find(e => e.capability === 'shell')
    expect(shellEvidence?.line).toBe(1)
    expect(shellEvidence?.file).toBe('lib/index.js')
  })

  it('ignores capabilities mentioned only in line comments', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "// TODO: maybe use child_process later\nconst x = 1\n",
    }))
    expect(result.capabilities).not.toContain('shell')
  })

  it('does not treat RegExp.prototype.exec as a shell', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "const m = /\\w+/.exec('abc')\n",
    }))
    expect(result.capabilities).not.toContain('shell')
  })

  it('does not treat a capability id word as capability use', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "const list = ['shell', 'subagent', 'fs-write']\n",
    }))
    expect(result.capabilities).toEqual([])
  })

  it('derives host-runtime from manifest dependency scopes', () => {
    const result = scanCapabilities(input({}, {
      dependencies: { '@deepseek-ai/dsh-host-core': '0.1.0' },
    }))
    expect(result.capabilities).toContain('host-runtime')
  })

  it('separates env reads from strong secret-material access', () => {
    const envOnly = scanCapabilities(input({
      'lib/index.js': 'const token = process.env.DEEPSEEK_API_KEY\n',
    }))
    expect(envOnly.capabilities).toContain('env')
    expect(envOnly.capabilities).not.toContain('credentials')

    const secrets = scanCapabilities(input({
      'lib/index.js': "import keychain from 'keychain'\nconst k = fs.readFileSync('/home/u/.ssh/id_rsa')\n",
    }))
    expect(secrets.capabilities).toContain('credentials')
  })

  it('does not flag the word "secretary" as a secret', () => {
    const clean = scanCapabilities(input({
      'lib/index.js': 'const word = "the secretary of state"\n',
    }))
    expect(clean.capabilities).not.toContain('credentials')
  })

  it('detects child_process/promises imports as shell', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "import { exec } from 'node:child_process/promises'\nawait exec('id')\n",
    }))
    expect(result.capabilities).toContain('shell')
  })

  it('detects fs/promises imports as fs-read', () => {
    const result = scanCapabilities(input({
      'lib/index.js': "import fs from 'node:fs/promises'\nexport const f = fs\n",
    }))
    expect(result.capabilities).toContain('fs-read')
  })

  it('detects node:http2 and ctx.web as network', () => {
    const http2 = scanCapabilities(input({
      'lib/index.js': "import http2 from 'node:http2'\nhttp2.connect('https://evil')\n",
    }))
    expect(http2.capabilities).toContain('network')

    const web = scanCapabilities(input({
      'lib/index.js': "ctx.web.get('https://evil.com')\n",
    }))
    expect(web.capabilities).toContain('network')
  })

  it('detects direct Node HTTP call sites without matching prose strings', () => {
    for (const call of ['http.get(url)', 'https.get(url)', 'http2.connect(url)']) {
      expect(scanCapabilities(input({ 'lib/index.js': `${call}\n` })).capabilities, call).toContain('network')
    }

    const prose = scanCapabilities(input({
      'lib/index.js': '// https.get(url)\nconst note = "http.get(url)"\n',
    }))
    expect(prose.capabilities).not.toContain('network')
  })

  it('detects common third-party HTTP clients as network', () => {
    for (const line of [
      "import got from 'got'",
      "const { WebSocket } = require('ws')",
      "import ky from 'ky'",
    ]) {
      const result = scanCapabilities(input({ 'lib/index.js': `${line}\n` }))
      expect(result.capabilities, line).toContain('network')
    }
  })

  it('detects credential paths without matching generic words', () => {
    const secrets = scanCapabilities(input({
      'lib/index.js': [
        'readFile("~/.kube/config")',
        'readFile("~/.docker/config.json")',
        'readFile("~/.gnupg/private-keys-v1.d")',
      ].join('\n'),
    }))
    expect(secrets.capabilities).toContain('credentials')

    const clean = scanCapabilities(input({
      'lib/index.js': 'const names = ["kubernetes", "docker", "config.json"]',
    }))
    expect(clean.capabilities).not.toContain('credentials')
  })

  it('detects node:undici, additional HTTP clients, and Bun.serve as network', () => {
    for (const line of [
      "import { fetch } from 'node:undici'",
      "import fetch from 'ofetch'",
      "import fetch from 'cross-fetch'",
      "import { request } from 'gaxios'",
      "const needle = require('needle')",
      'Bun.serve({})',
    ]) {
      const result = scanCapabilities(input({ 'lib/index.js': `${line}\n` }))
      expect(result.capabilities, line).toContain('network')
    }
  })

  it('does not flag network names in strings or bare identifiers', () => {
    const result = scanCapabilities(input({
      'lib/index.js': [
        'const name = "undici"',
        'const bun = Bun',
        'const client = ofetch',
      ].join('\n'),
    }))
    expect(result.capabilities).not.toContain('network')
  })

  it('keeps matching both node:dns and node:dns2 as network', () => {
    for (const module of ['node:dns', 'node:dns2', 'dns', 'dns2']) {
      const result = scanCapabilities(input({ 'lib/index.js': `import client from '${module}'\n` }))
      expect(result.capabilities, module).toContain('network')
    }
  })

  it('detects eval, new Function, and vm as dynamic-code', () => {
    expect(scanCapabilities(input({
      'lib/index.js': 'eval(payload)\n',
    })).capabilities).toContain('dynamic-code')

    expect(scanCapabilities(input({
      'lib/index.js': 'const f = new Function("return 1")\n',
    })).capabilities).toContain('dynamic-code')

    expect(scanCapabilities(input({
      'lib/index.js': "import vm from 'node:vm'\nvm.runInNewContext(code)\n",
    })).capabilities).toContain('dynamic-code')
  })

  it('detects DSH subagent seams and not a generic delegate() helper', () => {
    const real = scanCapabilities(input({
      'lib/index.js': [
        'const runtime = ctx.subagents',
        'ctx.agentTeams.spawn(spec)',
        'spawnTeammate(task)',
      ].join('\n'),
    }))
    expect(real.capabilities).toContain('subagent')

    const method = scanCapabilities(input({
      'lib/index.js': 'const { provider, runId, result } = await this.delegate(parent, "placement", prompt)\n',
    }))
    expect(method.capabilities).not.toContain('subagent')

    const wrapper = scanCapabilities(input({
      'lib/index.js': 'return delegate(file, args, execOptions)\n',
    }))
    expect(wrapper.capabilities).not.toContain('subagent')
  })

  it('does not treat JSDoc mentions of ctx.credentials as credential access', () => {
    const commentOnly = scanCapabilities(input({
      'lib/index.js': [
        '/**',
        ' * Resolves a credential via `ctx.credentials`.',
        ' */',
        'export function describe() { return 1 }',
      ].join('\n'),
    }))
    expect(commentOnly.capabilities).not.toContain('credentials')

    const live = scanCapabilities(input({
      'lib/index.js': [
        '/**',
        ' * Resolves a credential via `ctx.credentials`.',
        ' */',
        'export function resolve() { return ctx.credentials.resolve(ref) }',
      ].join('\n'),
    }))
    expect(live.capabilities).toContain('credentials')
  })

  it('does not treat JSDoc fetch examples as network', () => {
    const result = scanCapabilities(input({
      'lib/client.js': [
        '/**',
        ' * Same-origin: fetch("/api/overview")',
        ' */',
        'export const id = 1',
      ].join('\n'),
    }))
    expect(result.capabilities).not.toContain('network')
  })

  it('does not treat the dynamic-code rule table as a hit', () => {
    const result = scanCapabilities(input({
      'seams.ts': [
        String.raw`pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,`,
        String.raw`pattern: /(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?vm['"]/,`,
      ].join('\n'),
    }))
    expect(result.capabilities).not.toContain('dynamic-code')
  })
})
