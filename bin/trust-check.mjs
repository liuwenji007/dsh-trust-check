#!/usr/bin/env node
/**
 * Standalone audit CLI: audits every community plugin installed in a profile.
 *
 *   npx dsh-trust-check                  # default profile `web`
 *   npx dsh-trust-check --profile work   # another profile
 *   npx dsh-trust-check --json           # machine-readable output
 *
 * No DSH host needed — this reads the profile directory directly.
 */
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { auditPlugin, collectPlugin, readInstalled, resolveProfileDir } from '../lib/index.js'

function parseArgs(argv) {
  const args = { profile: process.env.DSH_PROFILE ?? 'web', json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--profile' && argv[i + 1] !== undefined) {
      args.profile = argv[i + 1]
      i++
    } else if (arg === '--json') {
      args.json = true
    } else if (arg === '--help' || arg === '-h') {
      console.log('Usage: dsh-trust-check [--profile <name>] [--json]')
      process.exit(0)
    }
  }
  return args
}

const BAND_ICON = { green: '✓', yellow: '▲', red: '✗' }

function humanReport(profile, plugins, errors) {
  const counts = { green: 0, yellow: 0, red: 0 }
  for (const p of plugins) counts[p.band]++
  console.log(`profile: ${profile}`)
  console.log(`${plugins.length} plugin(s) · ${counts.red} red, ${counts.yellow} yellow, ${counts.green} green`)
  console.log('')
  for (const p of plugins) {
    console.log(`${BAND_ICON[p.band]} ${p.name} ${p.version} — ${p.band} · ${p.score}`)
    console.log(`  capabilities: ${p.capabilities.length === 0 ? 'none' : p.capabilities.join(', ')}`)
    if (p.injections.length > 0) {
      console.log(`  injections: ${p.injections.map(i => `${i.kind}: ${i.detail}`).join('; ')}`)
    }
    if (p.injectedTokensEstimate > 0) console.log(`  est. injected tokens: ~${p.injectedTokensEstimate}`)
    const source = [p.pinned ? 'pinned' : 'unpinned']
    if (p.repository === undefined) source.push('no repository')
    else source.push(p.repository)
    if (p.hasBuildScript) source.push(`install scripts: ${p.buildScripts.join(', ')}`)
    console.log(`  source: ${source.join(' | ')}`)
    for (const line of p.redLines) console.log(`  ⚠ ${line}`)
    console.log('')
  }
  if (errors.length > 0) {
    console.log(`${errors.length} plugin(s) could not be read:`)
    for (const e of errors) console.log(`  - ${e.name}: ${e.message}`)
  }
}

const args = parseArgs(process.argv.slice(2))
const profileDir = resolveProfileDir(args.profile)
const installed = readInstalled(profileDir)
const plugins = []
const errors = []

for (const [name, spec] of Object.entries(installed)) {
  const dir = join(profileDir, 'node_modules', name)
  if (!existsSync(dir)) continue
  try {
    plugins.push(auditPlugin(collectPlugin(dir, spec)))
  } catch (error) {
    errors.push({ name, spec, message: error instanceof Error ? error.message : String(error) })
  }
}

plugins.sort((a, b) => a.score - b.score)

if (args.json) {
  console.log(JSON.stringify({
    profile: args.profile,
    generatedAt: new Date().toISOString(),
    plugins,
    errors,
  }, null, 2))
} else {
  humanReport(args.profile, plugins, errors)
}
