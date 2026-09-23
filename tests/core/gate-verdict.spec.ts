import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { verdict } from '../../src/core/present.ts'
import { collectPlugin } from '../../src/fs.ts'
import { runAudit } from '../../src/index.ts'

const previousHome = process.env.DSH_HOME

afterEach(() => {
  if (previousHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousHome
})

describe('pre-install gate', () => {
  it('puts an oversized plugin in errors and reviews runtime shell', () => {
    const home = mkdtempSync(join(tmpdir(), 'dsh-gate-'))
    process.env.DSH_HOME = home
    try {
      const profileDir = join(home, 'profiles', 'web')
      const hugeDir = join(profileDir, 'node_modules', 'huge-plugin', 'lib')
      const shellDir = join(profileDir, 'node_modules', 'shell-plugin')
      mkdirSync(hugeDir, { recursive: true })
      mkdirSync(join(shellDir, 'lib'), { recursive: true })
      mkdirSync(join(shellDir, 'runtime'), { recursive: true })
      writeFileSync(join(profileDir, 'package.json'), JSON.stringify({
        dependencies: {
          'huge-plugin': 'npm:huge-plugin@1.0.0',
          'shell-plugin': 'npm:shell-plugin@1.0.0',
        },
      }))
      writeFileSync(join(profileDir, 'node_modules', 'huge-plugin', 'package.json'), JSON.stringify({
        name: 'huge-plugin', version: '1.0.0', main: './lib/big.js',
      }))
      writeFileSync(join(hugeDir, 'big.js'), 'x'.repeat(512 * 1024 + 1))
      writeFileSync(join(shellDir, 'package.json'), JSON.stringify({
        name: 'shell-plugin', version: '1.0.0', main: './lib/index.js',
      }))
      writeFileSync(join(shellDir, 'lib', 'index.js'), "import { boom } from '../runtime/payload.js'\n")
      writeFileSync(join(shellDir, 'runtime', 'payload.js'), "import { execSync } from 'node:child_process'\nexport const boom = () => execSync('id')\n")

      const audited = runAudit('web')
      expect(audited.plugins.map(plugin => plugin.name)).toEqual(['shell-plugin'])
      expect(audited.errors.some(error => error.name === 'huge-plugin')).toBe(true)
      expect(verdict(audited.plugins[0]!)).toBe('review')
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('stays clear for same-origin fetch and for coverage notes alone', () => {
    const root = mkdtempSync(join(tmpdir(), 'dsh-gate-clear-'))
    try {
      mkdirSync(join(root, 'lib'))
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name: 'same', version: '1.0.0', main: './lib/index.js',
      }))
      writeFileSync(join(root, 'lib', 'index.js'), "await fetch('/api/ok')\nimport './missing.js'\n")
      const report = auditPlugin(collectPlugin(root, 'npm:same@1.0.0'))
      expect(report.coverageNotes?.length).toBeGreaterThan(0)
      expect(verdict(report)).toBe('clear')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
