import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const root = fileURLToPath(new URL('..', import.meta.url))

beforeAll(() => {
  // Run tsdown's entry with this Node: spawning `pnpm.cmd` without a shell throws EINVAL on Windows.
  const tsdownPkg = createRequire(import.meta.url).resolve('tsdown/package.json')
  const bin = (JSON.parse(readFileSync(tsdownPkg, 'utf8')) as { bin: { tsdown: string } }).bin.tsdown
  execFileSync(process.execPath, [join(dirname(tsdownPkg), bin)], { cwd: root, stdio: 'pipe' })
}, 60_000)

function run(args: string[], env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [join(root, 'bin/trust-check.mjs'), ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  })
}

function packageDir(manifest: unknown, files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'trust-cli-'))
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest))
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(dir, rel)
    mkdirSync(join(abs, '..'), { recursive: true })
    writeFileSync(abs, text)
  }
  return dir
}

describe('cli --exit-code', () => {
  const dirs: string[] = []
  const keep = (dir: string) => {
    dirs.push(dir)
    return dir
  }

  it('stays 0 without the flag, even for a red-line package', () => {
    const dir = keep(packageDir({ name: 'installs', version: '1.0.0', scripts: { postinstall: 'node x' } }))
    expect(run(['--dir', dir]).status).toBe(0)
  })

  it('exits 2 for a red line, 1 for review, 0 for a minimal package', () => {
    const red = keep(packageDir({ name: 'installs', version: '1.0.0', scripts: { postinstall: 'node x' } }))
    const review = keep(packageDir(
      { name: 'shelled', version: '1.0.0', main: 'index.js' },
      { 'index.js': "require('child_process').execSync('id')\n" },
    ))
    const clear = keep(packageDir({ name: 'minimal', version: '1.0.0' }))
    expect(run(['--dir', red, '--exit-code']).status).toBe(2)
    expect(run(['--dir', review, '--exit-code']).status).toBe(1)
    expect(run(['--dir', clear, '--exit-code']).status).toBe(0)
  })

  it('exits 3 when --dir has nothing to audit', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'trust-cli-empty-')))
    expect(run(['--dir', dir, '--exit-code']).status).toBe(3)
  })

  it('flushes a complete JSON document before exiting', () => {
    const dir = keep(packageDir(
      { name: 'shelled', version: '1.0.0', main: 'index.js' },
      { 'index.js': "require('child_process').execSync('id')\n" },
    ))
    const result = run(['--dir', dir, '--json', '--exit-code'])
    expect(result.status).toBe(1)
    expect(JSON.parse(result.stdout).plugins[0].name).toBe('shelled')
  })

  it('exits 0 for an empty profile and 2 when any plugin is red', () => {
    const home = keep(mkdtempSync(join(tmpdir(), 'trust-cli-home-')))
    const profile = join(home, 'profiles', 'web')
    mkdirSync(profile, { recursive: true })
    writeFileSync(join(profile, 'package.json'), JSON.stringify({ dependencies: {} }))
    expect(run(['--exit-code'], { DSH_HOME: home }).status).toBe(0)

    const plugin = join(profile, 'node_modules', 'installs')
    mkdirSync(plugin, { recursive: true })
    writeFileSync(join(plugin, 'package.json'), JSON.stringify({
      name: 'installs', version: '1.0.0', scripts: { postinstall: 'node x' },
    }))
    writeFileSync(join(profile, 'package.json'), JSON.stringify({
      dependencies: { installs: 'npm:installs@1.0.0' },
    }))
    expect(run(['--exit-code'], { DSH_HOME: home }).status).toBe(2)
  })

  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
  })
})
