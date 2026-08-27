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
import {
  auditPlugin,
  collectPlugin,
  concernText,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  partitionDestinations,
  readAckStore,
  readInstalled,
  resolveProfileDir,
  verdict,
} from '../lib/index.js'

const ACTION_EN = {
  red: 'Stop by default; confirm the risk before continuing.',
  review: 'No hard red lines; if capabilities match why you installed it, mark as expected in Settings.',
  expected: 'Capabilities marked as expected in Settings.',
  clear: 'No red lines or privileged capabilities detected.',
}

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

function printPlugin(p, ack) {
  const v = verdict(p, ack)
  console.log(`${p.name} ${p.version} — ${v}`)
  console.log(`  ${ACTION_EN[v] ?? ''}`)
  const list = concerns(p)
  if (list.length > 0 && v !== 'expected') {
    console.log('  why be careful:')
    for (const item of list) console.log(`    · ${concernText(item)}`)
  }
  const caps = p.capabilities.length === 0
    ? 'none'
    : p.capabilities.join(', ')
  console.log(`  capabilities: ${caps}`)
  if (p.destinations?.length > 0) {
    const { priority, safe } = partitionDestinations(p.destinations)
    console.log('  destinations (literal):')
    for (const d of priority.slice(0, 8)) console.log(`    ${d.kind}: ${d.value}`)
    if (safe.length > 0) {
      console.log(`    … + ${safe.length} allowlisted/relative/loopback destination(s)`)
    }
  }
  if (p.secretTouches?.length > 0) {
    console.log('  secret touches:')
    for (const s of p.secretTouches.slice(0, 8)) console.log(`    ${s.kind}: ${s.value}`)
  }
  if (p.injections.length > 0) {
    const tokenPart = p.injectedTokensEstimate > 0 ? ` · ~${p.injectedTokensEstimate} tokens (cost)` : ''
    console.log(`  injections: ${p.injections.length} item(s)${tokenPart}`)
    for (const inj of p.injections.slice(0, 5)) {
      console.log(`    ${inj.kind}: ${formatInjectionDetail(inj.detail)}`)
    }
    if (p.injections.length > 5) console.log(`    … and ${p.injections.length - 5} more`)
  }
  const source = [p.pinned ? 'pinned' : 'unpinned']
  if (p.repository === undefined) source.push('no repository')
  else source.push(p.repository)
  if (p.hasBuildScript) source.push(`install scripts: ${p.buildScripts.join(', ')}`)
  console.log(`  source: ${source.join(' | ')}`)
  if (p.evidence.length > 0) console.log(`  evidence: ${p.evidence.length} hit(s)`)
  console.log('')
}

function humanReport(contextLabel, plugins, errors, acks) {
  const counts = countVerdicts(plugins, acks)
  console.log(contextLabel)
  console.log(`${plugins.length} plugin(s) · ${counts.red} red · ${counts.review} review · ${counts.expected} expected · ${counts.clear} clear`)
  console.log('')
  for (const p of plugins) printPlugin(p, acks?.[p.name])
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
  const acks = readAckStore(profileDir)
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
    acks,
  }
}

plugins.sort((a, b) => a.score - b.score)

if (args.json) {
  console.log(JSON.stringify(response, null, 2))
} else {
  const label = args.dir !== undefined
    ? `dir: ${args.dir}`
    : `profile: ${args.profile}`
  humanReport(label, plugins, errors, response.acks)
}
