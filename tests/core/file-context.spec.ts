import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { runtimeByFile, runtimeEntryPaths } from '../../src/core/file-context.ts'
import { capabilityContext } from '../../src/core/present.ts'
import type { PluginInput } from '../../src/core/types.ts'

const manifest = {
  name: 'ctx',
  version: '1.0.0',
  main: './lib/index.js',
  bin: { tool: './bin/cli.js' },
  exports: {
    '.': './lib/index.js',
    './client': './lib/client.js',
    './package.json': './package.json',
  },
}

describe('runtimeByFile', () => {
  const sources = {
    'lib/index.js': "import { shared } from './shared.js'\nimport { execSync } from 'node:child_process'\nexecSync('id')\n",
    'lib/client.js': "import { shared } from './shared.js'\nnew Function('return 1')\n",
    'lib/shared.js': 'export const shared = 1\n',
    'lib/orphan.js': 'export const orphan = 1\n',
    'bin/cli.js': "import { execFileSync } from 'node:child_process'\nexecFileSync('ls')\n",
  }

  it('labels client, server, cli, and a file reached from two entries', () => {
    expect(runtimeEntryPaths(manifest).client).toEqual(['./lib/client.js'])
    const runtime = runtimeByFile(manifest, sources)
    expect(runtime.get('lib/index.js')).toEqual(['server'])
    expect(runtime.get('lib/client.js')).toEqual(['client'])
    expect(runtime.get('lib/shared.js')).toEqual(['server', 'client'])
    expect(runtime.get('bin/cli.js')).toEqual(['cli'])
    expect(runtime.has('lib/orphan.js')).toBe(false)
  })
})

describe('attachContext', () => {
  function plugin(sourceMaps?: Record<string, string>): PluginInput {
    return {
      manifest,
      sources: {
        'lib/index.js': "import { execSync } from 'node:child_process'\nexecSync('id')\n",
        'lib/client.js': "new Function('return process')\n",
      },
      skillFiles: {},
      patchText: undefined,
      patchPath: undefined,
      spec: 'npm:ctx@1.0.0',
      sourceMaps,
    }
  }

  const map = JSON.stringify({
    version: 3,
    sources: ['../node_modules/.pnpm/schemastery@3.8.0/node_modules/schemastery/lib/index.js'],
    mappings: 'AAAA',
  })

  it('adds runtime and origin without changing score, red lines, or the ack fingerprint', () => {
    const plain = auditPlugin(plugin())
    const labeled = auditPlugin(plugin({ 'lib/client.js': map }))
    expect(labeled.score).toBe(plain.score)
    expect(labeled.redLines).toEqual(plain.redLines)
    expect(labeled.ackFingerprint).toBe(plain.ackFingerprint)
    expect(labeled.capabilities).toEqual(plain.capabilities)

    const shell = labeled.evidence.find(row => row.capability === 'shell')
    const dynamic = labeled.evidence.find(row => row.capability === 'dynamic-code')
    expect(shell?.context?.runtime).toEqual(['server'])
    expect(shell?.context?.origin).toBeUndefined()
    expect(dynamic?.context?.runtime).toEqual(['client'])
    expect(dynamic?.context?.origin).toEqual({ kind: 'dependency', package: 'schemastery' })
    expect(dynamic?.line).toBe(1)

    expect(capabilityContext(labeled, 'dynamic-code')).toEqual({
      runtime: 'client',
      packageName: 'schemastery',
    })
    expect(capabilityContext(labeled, 'shell')).toEqual({ runtime: 'server' })
    expect(capabilityContext(plain, 'dynamic-code').packageName).toBeUndefined()
  })
})
