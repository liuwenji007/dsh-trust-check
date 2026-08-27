#!/usr/bin/env node
/**
 * Standalone audit CLI: audits installed profile plugins or one package directory.
 *
 *   npx dsh-trust-check                         # default profile `web`
 *   npx dsh-trust-check --profile work          # another profile
 *   npx dsh-trust-check --dir ./my-plugin       # audit one package tree
 *   npx dsh-trust-check --dir ./pkg --spec npm:x@1.0.0 --json
 *
 * No DSH host needed for profile or --dir mode.
 */
import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { auditPlugin, collectPlugin, readInstalled, resolveProfileDir } from '../lib/index.js'

function parseArgs(argv) {
  const args = {
    profile: process.env.DSH_PROFILE ?? 'web',
    json: false,
    dir: undefined,
    spec: 'dir:.',
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--profile' && argv[i + 1] !== undefined) {
      args.profile = argv[i + 1]
      i++
    } else if (arg === '--dir' && argv[i + 1] !== undefined) {
      args.dir = resolve(argv[i + 1])
      i++
    } else if (arg === '--spec' && argv[i + 1] !== undefined) {
      args.spec = argv[i + 1]
      i++
    } else if (arg === '--json') {
      args.json = true
    } else if (arg === '--help' || arg === '-h') {
      console.log(`Usage:
  dsh-trust-check [--profile <name>] [--json]
  dsh-trust-check --dir <package-dir> [--spec <install-spec>] [--json]

Options:
  --profile <name>   Profile to audit (default: web or DSH_PROFILE)
  --dir <path>       Audit one package directory (mutually exclusive with --profile)
  --spec <spec>      Install spec label for --dir (default: dir:.)
  --json             Machine-readable AuditResponse JSON
`)
      process.exit(0)
    }
  }
  if (args.dir !== undefined && argv.includes('--profile')) {
    console.error('error: --dir and --profile are mutually exclusive')
    process.exit(1)
  }
  return args
}

function statusLabel(report) {
  if (report.redLines.length > 0 || report.band === 'red') return 'red line(s)'
  if (report.capabilities.length > 0 || report.band === 'yellow') return 'review suggested'
  return 'no red lines'
}

function printPlugin(p) {
  console.log(`${p.name} ${p.version} — ${statusLabel(p)}`)
  console.log(`  summary: ${p.summary}`)
  console.log(`  sort score: ${p.score}`)
  if (p.redLines.length > 0) {
    console.log('  red lines:')
    for (const line of p.redLines) console.log(`    ⚠ ${line}`)
  }
  console.log(`  capabilities: ${p.capabilities.length === 0 ? 'none' : p.capabilities.join(', ')}`)
  if (p.injections.length > 0) {
    console.log(`  injections: ${p.injections.map(i => `${i.kind}: ${i.detail}`).join('; ')}`)
  }
  if (p.injectedTokensEstimate > 0) {
    console.log(`  est. injected tokens (cost hint): ~${p.injectedTokensEstimate}`)
  }
  const source = [p.pinned ? 'pinned' : 'unpinned']
  if (p.repository === undefined) source.push('no repository')
  else source.push(p.repository)
  if (p.hasBuildScript) source.push(`install scripts: ${p.buildScripts.join(', ')}`)
  console.log(`  source: ${source.join(' | ')}`)
  console.log('')
}

function humanReport(contextLabel, plugins, errors) {
  const counts = { clear: 0, review: 0, red: 0 }
  for (const p of plugins) {
    const label = statusLabel(p)
    if (label === 'red line(s)') counts.red++
    else if (label === 'review suggested') counts.review++
    else counts.clear++
  }
  console.log(contextLabel)
  console.log(`${plugins.length} plugin(s) · ${counts.red} with red lines, ${counts.review} review, ${counts.clear} clear`)
  console.log('')
  for (const p of plugins) printPlugin(p)
  if (errors.length > 0) {
    console.log(`${errors.length} plugin(s) could not be read:`)
    for (const e of errors) console.log(`  - ${e.name}: ${e.message}`)
  }
}

const args = parseArgs(process.argv.slice(2))
const plugins = []
const errors = []
let response

if (args.dir !== undefined) {
  if (!existsSync(args.dir)) {
    console.error(`error: directory not found: ${args.dir}`)
    process.exit(1)
  }
  try {
    plugins.push(auditPlugin(collectPlugin(args.dir, args.spec)))
  } catch (error) {
    errors.push({
      name: args.dir,
      spec: args.spec,
      message: error instanceof Error ? error.message : String(error),
    })
  }
  response = {
    profile: '',
    dir: args.dir,
    generatedAt: new Date().toISOString(),
    plugins,
    errors,
  }
} else {
  const profileDir = resolveProfileDir(args.profile)
  const installed = readInstalled(profileDir)
  for (const [name, spec] of Object.entries(installed)) {
    const dir = join(profileDir, 'node_modules', name)
    if (!existsSync(dir)) continue
    try {
      plugins.push(auditPlugin(collectPlugin(dir, spec)))
    } catch (error) {
      errors.push({ name, spec, message: error instanceof Error ? error.message : String(error) })
    }
  }
  response = {
    profile: args.profile,
    generatedAt: new Date().toISOString(),
    plugins,
    errors,
  }
}

plugins.sort((a, b) => a.score - b.score)

if (args.json) {
  console.log(JSON.stringify(response, null, 2))
} else {
  const label = args.dir !== undefined
    ? `dir: ${args.dir}`
    : `profile: ${args.profile}`
  humanReport(label, plugins, errors)
}
