import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { resolveActiveProfile, resolveInstalledKey, runAudit } from '../../src/index.ts'

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

describe('runAudit with a host-owned profile directory', () => {
  it('reads the directory it is given, not the one derived from the name', () => {
    const elsewhere = mkdtempSync(join(tmpdir(), 'dsh-desktop-profile-'))
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-unused-'))
    process.env.DSH_HOME = home
    try {
      writeFileSync(join(elsewhere, 'package.json'), JSON.stringify({ dependencies: {} }))
      const res = runAudit('desktop', elsewhere)
      expect(res.profile).toBe('desktop')
      expect(res.errors).toEqual([])
    } finally {
      rmSync(elsewhere, { recursive: true, force: true })
      rmSync(home, { recursive: true, force: true })
    }
  })
})

describe('resolveActiveProfile', () => {
  const home = join(tmpdir(), 'dsh-home-resolve')
  const desktopDir = join(tmpdir(), 'desktop-owned', 'desktop')
  const services = (map: Record<string, unknown>) => (name: string) => map[name]

  it('follows the launcher profileContext when DSH Desktop passes no --profile flag', () => {
    process.env.DSH_HOME = home
    const active = resolveActiveProfile(
      services({ profileContext: { name: 'desktop', dir: desktopDir } }),
      undefined,
      ['node', 'launcher.js'],
    )
    expect(active).toEqual({ name: 'desktop', dir: desktopDir })
  })

  it('lets a desktop shell profile win over cordis.yml and the launcher', () => {
    const shellDir = join(tmpdir(), 'shell', 'work')
    const active = resolveActiveProfile(
      services({
        desktopProfiles: { current: { name: 'work', dir: shellDir } },
        profileContext: { name: 'desktop', dir: desktopDir },
      }),
      { profile: 'web' },
      [],
    )
    expect(active).toEqual({ name: 'work', dir: shellDir })
  })

  it('prefers cordis.yml over the launcher, keeping the launcher dir when the names agree', () => {
    process.env.DSH_HOME = home
    const launcher = services({ profileContext: { name: 'desktop', dir: desktopDir } })
    expect(resolveActiveProfile(launcher, { profile: 'web' }, [])).toEqual({ name: 'web', dir: join(home, 'profiles', 'web') })
    expect(resolveActiveProfile(launcher, { profile: 'desktop' }, [])).toEqual({ name: 'desktop', dir: desktopDir })
  })

  it('ignores host profiles with a traversal name or a relative dir', () => {
    process.env.DSH_HOME = home
    for (const bad of [{ name: '..', dir: desktopDir }, { name: 'desktop', dir: 'profiles/desktop' }, { name: 'desktop' }]) {
      expect(resolveActiveProfile(services({ profileContext: bad }), undefined, [])).toEqual({
        name: 'web',
        dir: join(home, 'profiles', 'web'),
      })
    }
  })

  it('falls through an unusable desktop shell, and lets the launcher win over --profile', () => {
    const active = resolveActiveProfile(
      services({
        desktopProfiles: { current: { name: '', dir: '' } },
        profileContext: { name: ' desktop ', dir: desktopDir },
      }),
      undefined,
      ['dsh', '--profile', 'work'],
    )
    expect(active).toEqual({ name: 'desktop', dir: desktopDir })
  })

  it('falls back to the --profile flag, then web', () => {
    process.env.DSH_HOME = home
    expect(resolveActiveProfile(services({}), undefined, ['dsh', '--profile', 'work'])).toEqual({
      name: 'work',
      dir: join(home, 'profiles', 'work'),
    })
    expect(resolveActiveProfile(services({}), undefined, ['dsh'])).toEqual({
      name: 'web',
      dir: join(home, 'profiles', 'web'),
    })
  })
})

describe('resolveInstalledKey', () => {
  function profileWith(plugins: Record<string, string | undefined>): { home: string; profileDir: string; installed: Record<string, string> } {
    const home = mkdtempSync(join(tmpdir(), 'dsh-home-key-'))
    const profileDir = join(home, 'profiles', 'web')
    const installed: Record<string, string> = {}
    for (const [key, manifestName] of Object.entries(plugins)) {
      installed[key] = `npm:${key}@1.0.0`
      mkdirSync(join(profileDir, 'node_modules', key), { recursive: true })
      writeFileSync(join(profileDir, 'node_modules', key, 'package.json'), JSON.stringify(
        manifestName === undefined ? { version: '1.0.0' } : { name: manifestName, version: '1.0.0' },
      ))
    }
    return { home, profileDir, installed }
  }

  it('finds an aliased install by its manifest name', () => {
    const { home, profileDir, installed } = profileWith({ alias: 'real-name' })
    try {
      expect(resolveInstalledKey(profileDir, installed, 'real-name')).toEqual({ key: 'alias' })
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('falls back to the dependency key', () => {
    const { home, profileDir, installed } = profileWith({ nameless: undefined })
    try {
      expect(resolveInstalledKey(profileDir, installed, 'nameless')).toEqual({ key: 'nameless' })
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('refuses a manifest name claimed by two installs', () => {
    const { home, profileDir, installed } = profileWith({ a: 'same', b: 'same' })
    try {
      expect(resolveInstalledKey(profileDir, installed, 'same')).toEqual({ ambiguous: true })
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('returns undefined for an unknown name', () => {
    const { home, profileDir, installed } = profileWith({ a: 'a' })
    try {
      expect(resolveInstalledKey(profileDir, installed, 'nope')).toBeUndefined()
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })
})
