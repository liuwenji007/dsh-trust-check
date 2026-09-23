import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { runAudit } from '../../src/index.ts'

const previousHome = process.env.DSH_HOME

afterEach(() => {
  if (previousHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousHome
})

describe('runAudit', () => {
  it('reports an error when the profile directory does not exist', () => {
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-missing-'))
    process.env.DSH_HOME = home
    try {
      const res = runAudit('web')
      expect(res.plugins).toEqual([])
      expect(res.errors.some(error => /profile directory does not exist/.test(error.message))).toBe(true)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('reports an error when profile package.json is corrupt', () => {
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-bad-'))
    process.env.DSH_HOME = home
    try {
      const profileDir = join(home, 'profiles', 'web')
      mkdirSync(profileDir, { recursive: true })
      writeFileSync(join(profileDir, 'package.json'), '{not-json')
      const res = runAudit('web')
      expect(res.errors.some(error => /profile package.json corrupt/.test(error.message))).toBe(true)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('reports an error when profile package.json is missing', () => {
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-empty-'))
    process.env.DSH_HOME = home
    try {
      mkdirSync(join(home, 'profiles', 'web'), { recursive: true })
      const res = runAudit('web')
      expect(res.errors.some(error => /profile package.json missing/.test(error.message))).toBe(true)
      expect(res.errors.some(error => /corrupt/.test(error.message))).toBe(false)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('reports an error when a declared plugin directory is missing', () => {
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-plugin-'))
    process.env.DSH_HOME = home
    try {
      const profileDir = join(home, 'profiles', 'web')
      mkdirSync(profileDir, { recursive: true })
      writeFileSync(join(profileDir, 'package.json'), JSON.stringify({
        dependencies: { 'missing-plugin': 'npm:missing-plugin@1.0.0' },
      }))
      const res = runAudit('web')
      expect(res.plugins).toEqual([])
      expect(res.errors).toEqual([
        expect.objectContaining({ name: 'missing-plugin' }),
      ])
      expect(res.errors[0]?.message).toMatch(/declared plugin directory missing/)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })
})
