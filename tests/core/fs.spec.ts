import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { collectPlugin, manifestEntryPaths } from '../../src/fs.ts'
import { verdict } from '../../src/core/present.ts'

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

  it('throws when a patch file exceeds the size limit', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-'))
    try {
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'patch-huge', version: '1' }))
      writeFileSync(join(root, 'cordis.patch.yml'), 'x'.repeat(512 * 1024 + 1))
      expect(() => collectPlugin(root, 'npm:x@1')).toThrow(/file too large/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('throws before reading when a file exceeds the size limit', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-huge-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'huge', version: '1', main: './lib/big.js' }))
      writeFileSync(join(root, 'lib', 'big.js'), 'x'.repeat(64))
      expect(() => collectPlugin(root, 'npm:huge@1', {
        limits: { maxFileBytes: 32, maxFiles: 100, maxTotalBytes: 10_000 },
      })).toThrow(/file too large/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('throws when the file count limit is exceeded', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-count-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'count', version: '1' }))
      writeFileSync(join(root, 'lib', 'a.js'), 'export const a = 1\n')
      writeFileSync(join(root, 'lib', 'b.js'), 'export const b = 1\n')
      writeFileSync(join(root, 'lib', 'c.js'), 'export const c = 1\n')
      expect(() => collectPlugin(root, 'npm:count@1', {
        limits: { maxFileBytes: 1000, maxFiles: 2, maxTotalBytes: 10_000 },
      })).toThrow(/scan aborted: more than 2 files/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('throws when the total size limit is exceeded', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-bytes-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'bytes', version: '1' }))
      writeFileSync(join(root, 'lib', 'a.js'), 'export const a = 1\n')
      writeFileSync(join(root, 'lib', 'b.js'), 'export const b = 2\n')
      expect(() => collectPlugin(root, 'npm:bytes@1', {
        limits: { maxFileBytes: 1000, maxFiles: 10, maxTotalBytes: 10 },
      })).toThrow(/total size exceeds/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('throws when a primary entry is missing', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-entry-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'bad-entry', version: '1', main: './missing.js',
      }))
      writeFileSync(join(root, 'lib', 'ok.js'), 'export const ok = 1\n')
      expect(() => collectPlugin(root, 'npm:bad-entry@1')).toThrow(/primary entry unreadable or missing: \.\/missing\.js/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('does not throw when an optional export subpath is missing', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-opt-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'opt',
        version: '1.0.0',
        main: './lib/index.js',
        exports: { '.': './lib/index.js', './client': './missing-client.js' },
      }))
      writeFileSync(join(root, 'lib', 'index.js'), 'export const ok = 1\n')
      const collected = collectPlugin(root, 'npm:opt@1.0.0')
      expect(collected.coverageNotes?.some(note => note.includes('missing-client.js'))).toBe(true)
      expect(verdict(auditPlugin(collected))).toBe('clear')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a static import into runtime/ and reviews shell', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-rt-'))
    try {
      mkdirSync(join(root, 'lib'), { recursive: true })
      mkdirSync(join(root, 'runtime'), { recursive: true })
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'rt-hide', version: '1.0.0', main: './lib/index.js',
      }))
      writeFileSync(join(root, 'lib', 'index.js'), "import { boom } from '../runtime/payload.js'\nboom()\n")
      writeFileSync(join(root, 'runtime', 'payload.js'), "import { execSync } from 'node:child_process'\nexport const boom = () => execSync('id')\n")
      const collected = collectPlugin(root, 'npm:rt-hide@1.0.0')
      const report = auditPlugin(collected)
      expect(Object.keys(collected.sources).sort()).toEqual(['lib/index.js', 'runtime/payload.js'])
      expect(report.capabilities).toContain('shell')
      expect(verdict(report)).toBe('review')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('notes an unresolvable relative target without leaving clear', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-unres-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'u', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'lib', 'index.js'), "import './nope.js'\n")
      const collected = collectPlugin(root, 'npm:u@1.0.0')
      expect(collected.coverageNotes?.some(note => note.includes('nope.js'))).toBe(true)
      expect(verdict(auditPlugin(collected))).toBe('clear')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('notes a dynamic import without changing the verdict', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-dyn-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'dyn', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'lib', 'index.js'), 'import(rel)\nrequire(name)\n')
      const collected = collectPlugin(root, 'npm:dyn@1.0.0')
      expect(collected.coverageNotes?.some(note => /dynamic import/.test(note))).toBe(true)
      expect(collected.coverageNotes?.some(note => /dynamic require/.test(note))).toBe(true)
      expect(verdict(auditPlugin(collected))).toBe('clear')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('does not read a relative import outside the package', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-out-'))
    try {
      mkdirSync(join(root, 'pkg', 'lib'), { recursive: true })
      writeFileSync(join(root, 'outside.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({ name: 'out', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'pkg', 'lib', 'index.js'), "import '../../outside.js'\n")
      const collected = collectPlugin(join(root, 'pkg'), 'npm:out@1.0.0')
      expect(Object.keys(collected.sources)).toEqual(['lib/index.js'])
      expect(auditPlugin(collected).capabilities).not.toContain('shell')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a relative import inside the package node_modules', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-nm-'))
    try {
      mkdirSync(join(root, 'lib'))
      mkdirSync(join(root, 'node_modules', 'hidden'), { recursive: true })
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'nm', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'lib', 'index.js'), "import '../node_modules/hidden/payload.js'\n")
      writeFileSync(join(root, 'node_modules', 'hidden', 'payload.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      const collected = collectPlugin(root, 'npm:nm@1.0.0')
      const report = auditPlugin(collected)
      expect(collected.sources['node_modules/hidden/payload.js']).toContain('execSync')
      expect(report.capabilities).toContain('shell')
      expect(verdict(report)).toBe('review')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('does not expand a bare package import', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-bare-'))
    try {
      mkdirSync(join(root, 'lib'))
      mkdirSync(join(root, 'node_modules', 'lodash'), { recursive: true })
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'bare', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'lib', 'index.js'), "import 'lodash'\n")
      writeFileSync(join(root, 'node_modules', 'lodash', 'index.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      const collected = collectPlugin(root, 'npm:bare@1.0.0')
      expect(collected.sources['node_modules/lodash/index.js']).toBeUndefined()
      expect(auditPlugin(collected).capabilities).not.toContain('shell')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a formatted multiline import into runtime', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-multi-'))
    try {
      mkdirSync(join(root, 'lib'))
      mkdirSync(join(root, 'runtime'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'multi', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'lib', 'index.js'), "import {\n  boom\n} from '../runtime/payload.js'\nboom()\n")
      writeFileSync(join(root, 'runtime', 'payload.js'), "import { execSync } from 'node:child_process'\nexport const boom = () => execSync('id')\n")
      const collected = collectPlugin(root, 'npm:multi@1.0.0')
      const report = auditPlugin(collected)
      expect(Object.keys(collected.sources).sort()).toEqual(['lib/index.js', 'runtime/payload.js'])
      expect(report.capabilities).toContain('shell')
      expect(verdict(report)).toBe('review')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('scans a symlink whose real path stays inside the package', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-link-'))
    try {
      mkdirSync(join(root, 'lib'))
      mkdirSync(join(root, 'hidden'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'link', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'hidden', 'payload.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      symlinkSync(join(root, 'hidden', 'payload.js'), join(root, 'lib', 'payload.js'))
      writeFileSync(join(root, 'lib', 'index.js'), "import './payload.js'\n")
      const collected = collectPlugin(root, 'npm:link@1.0.0')
      const report = auditPlugin(collected)
      expect(collected.sources['hidden/payload.js']).toContain('execSync')
      expect(report.capabilities).toContain('shell')
      expect(verdict(report)).toBe('review')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('fails the scan when a symlink escapes the package', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-link-out-'))
    try {
      mkdirSync(join(root, 'pkg', 'lib'), { recursive: true })
      writeFileSync(join(root, 'outside.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      symlinkSync(join(root, 'outside.js'), join(root, 'pkg', 'lib', 'payload.js'))
      writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({ name: 'link-out', version: '1.0.0', main: './lib/index.js' }))
      writeFileSync(join(root, 'pkg', 'lib', 'index.js'), 'export const ok = 1\n')
      expect(() => collectPlugin(join(root, 'pkg'), 'npm:link-out@1.0.0')).toThrow(/symlink escapes package/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('fails the scan when a primary entry resolves outside the package', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-main-out-'))
    try {
      mkdirSync(join(root, 'pkg', 'lib'), { recursive: true })
      writeFileSync(join(root, 'outside.js'), "import { execSync } from 'node:child_process'\nexecSync('id')\n")
      writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({ name: 'main-out', version: '1.0.0', main: '../outside.js' }))
      writeFileSync(join(root, 'pkg', 'lib', 'index.js'), 'export const ok = 1\n')
      expect(() => collectPlugin(join(root, 'pkg'), 'npm:main-out@1.0.0')).toThrow(/primary entry escapes package/)
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

  it('fails closed on an empty directory (no silent clear report)', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-empty-'))
    try {
      expect(() => collectPlugin(root, 'dir:.')).toThrow(/nothing to audit/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('fails closed when package.json is unreadable and there is no source', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-badjson-'))
    try {
      writeFileSync(join(root, 'package.json'), 'not-json{')
      expect(() => collectPlugin(root, 'dir:.')).toThrow(/nothing to audit/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('still audits a package.json-only minimal plugin', () => {
    const root = mkdtempSync(join(tmpdir(), 'trust-fs-pkgonly-'))
    try {
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'minimal', version: '1.0.0' }))
      const collected = collectPlugin(root, 'npm:minimal@1.0.0')
      const report = auditPlugin(collected)
      expect(collected.manifest.name).toBe('minimal')
      expect(Object.keys(collected.sources)).toEqual([])
      expect(report.capabilities).toEqual([])
      expect(report.redLines).toEqual([])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
