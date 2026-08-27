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
})
