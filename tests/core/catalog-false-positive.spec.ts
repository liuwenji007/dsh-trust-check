import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { auditPlugin, collectPlugin, verdict } from '../../src/index.ts'

const root = resolve(import.meta.dirname, '../../.cache/catalog-sample/extracted')
const has = (folder: string) => existsSync(resolve(root, folder))

describe('catalog false-positive fixes (optional fixtures)', () => {
  it.skipIf(!has('dsh-pocket'))(
    'drops dsh-pocket dsh.invalid parser base from destinations and red lines',
    () => {
      const report = auditPlugin(collectPlugin(resolve(root, 'dsh-pocket'), 'npm:dsh-pocket'))
      expect(report.destinations.some(d => d.value === 'dsh.invalid')).toBe(false)
      expect(report.redLines.some(l => l.includes('dsh.invalid'))).toBe(false)
      expect(verdict(report)).not.toBe('red')
    },
  )

  it.skipIf(!has('nanmicoder-dsh-agent-teams') || !has('dsh-auto-classifier'))(
    'does not red-line agent-teams / auto-classifier deny-list id_rsa',
    () => {
      for (const [folder, spec] of [
        ['nanmicoder-dsh-agent-teams', 'npm:@nanmicoder/dsh-agent-teams'],
        ['dsh-auto-classifier', 'npm:dsh-auto-classifier'],
      ] as const) {
        const report = auditPlugin(collectPlugin(resolve(root, folder), spec))
        expect(report.capabilities, spec).not.toContain('credentials')
        expect(report.redLines, spec).not.toContain('reads credentials/secrets AND has network access')
      }
    },
  )

  it.skipIf(!has('dsh-shareone-plugin') || !has('anionex-dsh-vision-toolkit'))(
    'still red-lines real credential+network plugins',
    () => {
      for (const [folder, spec] of [
        ['dsh-shareone-plugin', 'npm:dsh-shareone-plugin'],
        ['anionex-dsh-vision-toolkit', 'npm:@anionex/dsh-vision-toolkit'],
      ] as const) {
        const report = auditPlugin(collectPlugin(resolve(root, folder), spec))
        expect(report.capabilities, spec).toContain('credentials')
        expect(report.redLines, spec).toContain('reads credentials/secrets AND has network access')
        expect(verdict(report), spec).toBe('red')
      }
    },
  )
})
