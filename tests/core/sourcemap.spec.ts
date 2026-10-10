import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { linePackages, packageFromSource } from '../../src/core/sourcemap.ts'
import { collectPlugin } from '../../src/fs.ts'

describe('packageFromSource', () => {
  it('reads the package after the last node_modules segment', () => {
    expect(packageFromSource('../node_modules/left-pad/index.js')).toBe('left-pad')
    expect(packageFromSource(
      '../node_modules/.pnpm/schemastery@3.8.0/node_modules/schemastery/lib/index.js',
    )).toBe('schemastery')
    expect(packageFromSource(
      '../node_modules/.pnpm/@scope+pkg@1.0.0/node_modules/@scope/pkg/index.js',
    )).toBe('@scope/pkg')
    expect(packageFromSource('../src/client.tsx')).toBeUndefined()
  })
})

describe('linePackages', () => {
  it('labels a generated line from a single dependency and skips plugin source', () => {
    const lines = linePackages(JSON.stringify({
      version: 3,
      sources: [
        '../node_modules/.pnpm/schemastery@3.8.0/node_modules/schemastery/lib/index.js',
        '../src/client.tsx',
      ],
      mappings: 'AAAA;AAAA',
    }))
    expect(lines?.get(1)).toBe('schemastery')
    expect(lines?.get(2)).toBe('schemastery')

    const pluginOnly = linePackages(JSON.stringify({
      version: 3,
      sources: ['../src/client.tsx'],
      mappings: 'AAAA',
    }))
    expect(pluginOnly?.get(1)).toBeUndefined()
    expect(linePackages('not-json')).toBeUndefined()
  })

  it('omits a line whose segments tie between two dependencies', () => {
    // Second segment: generated col +0 (A), source index +1 (C), orig line 0 (A), orig col 0 (A).
    const lines = linePackages(JSON.stringify({
      version: 3,
      sources: [
        '../node_modules/left-pad/index.js',
        '../node_modules/schemastery/lib/index.js',
      ],
      mappings: 'AAAA,ACAA',
    }))
    expect(lines?.has(1)).toBe(false)
  })
})

describe('collectPlugin sourcemaps', () => {
  it('reads an in-package map and notes one that is too large', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-map-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'map-pkg',
        version: '1',
        main: './lib/index.js',
      }))
      writeFileSync(join(root, 'lib', 'index.js'), 'export const ok = 1\n//# sourceMappingURL=index.js.map\n')
      writeFileSync(join(root, 'lib', 'index.js.map'), JSON.stringify({
        version: 3,
        sources: ['../node_modules/left-pad/index.js'],
        mappings: 'AAAA',
      }))
      const collected = collectPlugin(root, 'npm:map-pkg@1')
      expect(collected.sourceMaps?.['lib/index.js']).toContain('left-pad')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('skips a sourcemap that leaves the package', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-map-out-'))
    try {
      mkdirSync(join(root, 'pkg', 'lib'), { recursive: true })
      writeFileSync(join(root, 'outside.js.map'), '{"version":3,"sources":[],"mappings":""}')
      writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({ name: 'map-out', version: '1' }))
      writeFileSync(join(root, 'pkg', 'lib', 'index.js'), 'export const ok = 1\n//# sourceMappingURL=../../outside.js.map\n')
      const collected = collectPlugin(join(root, 'pkg'), 'npm:map-out@1')
      expect(collected.sourceMaps).toBeUndefined()
      expect(collected.coverageNotes?.some(note => note.includes('escapes package'))).toBe(true)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
