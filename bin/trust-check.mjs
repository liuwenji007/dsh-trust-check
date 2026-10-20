#!/usr/bin/env node
/**
 * Standalone audit CLI: audits installed profile plugins or one package directory.
 *
 *   npx dsh-trust-check                         # default profile `web`
 *   npx dsh-trust-check --profile work          # another profile
 *   npx dsh-trust-check --dir ./my-plugin       # audit one package tree
 *   npx dsh-trust-check --dir ./pkg --spec npm:x@1.0.0 --json
 *   npx dsh-trust-check --verbose               # full per-plugin dump
 *   npx dsh-trust-check --lang en               # English (default: zh unless LANG=en*)
 *
 * No DSH host needed for profile or --dir mode.
 */
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  auditPlugin,
  buildAuditResponse,
  collectPlugin,
  formatHumanReport,
  resolveCliColor,
  resolveCliLang,
  runAudit,
  verdict,
} from '../lib/index.js'

function parseArgs(argv) {
  const args = {
    profile: process.env.DSH_PROFILE ?? 'web',
    json: false,
    exitCode: false,
    verbose: false,
    lang: undefined,
    colorFlag: undefined,
    dir: undefined,
    spec: 'dir:.',
  }
  const valueOf = (flag, i) => {
    const value = argv[i + 1]
    if (value === undefined || value === '' || value.startsWith('--')) {
      console.error(`error: ${flag} requires a non-empty value`)
      process.exit(1)
    }
    return value
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--profile') {
      args.profile = valueOf(arg, i)
      i++
    } else if (arg === '--dir') {
      args.dir = resolve(valueOf(arg, i))
      i++
    } else if (arg === '--spec') {
      args.spec = valueOf(arg, i)
      i++
    } else if (arg === '--lang') {
      const lang = valueOf(arg, i).toLowerCase()
      if (lang !== 'zh' && lang !== 'en') {
        console.error('error: --lang must be zh or en')
        process.exit(1)
      }
      args.lang = lang
      i++
    } else if (arg === '--json') {
      args.json = true
    } else if (arg === '--exit-code') {
      args.exitCode = true
    } else if (arg === '--verbose' || arg === '-v') {
      args.verbose = true
    } else if (arg === '--color') {
      args.colorFlag = true
    } else if (arg === '--no-color') {
      args.colorFlag = false
    } else if (arg === '--help' || arg === '-h') {
      console.log(`Usage:
  dsh-trust-check [--profile <name>] [--json] [--exit-code] [--verbose] [--lang zh|en] [--color|--no-color]
  dsh-trust-check --dir <package-dir> [--spec <install-spec>] [--json] [--exit-code] [--verbose] [--lang zh|en] [--color|--no-color]

Options:
  --profile <name>   Profile to audit (default: web or DSH_PROFILE)
  --dir <path>       Audit one package directory (mutually exclusive with --profile)
  --spec <spec>      Install spec label for --dir (default: dir:.)
  --json             Machine-readable AuditResponse JSON (marketplace / CI must use this)
  --verbose, -v      Expand every plugin (default: compact — red/review/accepted/reconfirm)
  --lang zh|en       Human-report language (default: zh, or en when LANG starts with en)
  --color            Force ANSI colors (even when piped)
  --no-color         Disable ANSI colors (also honors NO_COLOR)
  --exit-code        Exit 0 clear/accepted/expected, 1 review, 2 red, 3 scan failed.
                     Off by default. Exit 0 is "nothing detected", not a safety claim.
`)
      process.exit(0)
    } else {
      console.error(`error: unknown argument: ${arg} (see --help)`)
      process.exit(1)
    }
  }
  if (args.dir !== undefined && argv.includes('--profile')) {
    console.error('error: --dir and --profile are mutually exclusive')
    process.exit(1)
  }
  return args
}

/** Worst verdict across the response. Scan failure outranks every verdict. */
function gateExitCode(response, dirMode) {
  if (response.errors.length > 0) return 3
  // An empty --dir result is a failed scan. An empty profile just has no plugins.
  if (response.plugins.length === 0) return dirMode ? 3 : 0
  const rank = { clear: 0, expected: 0, accepted: 0, review: 1, red: 2 }
  let worst = 0
  for (const plugin of response.plugins) {
    worst = Math.max(worst, rank[verdict(plugin, response.acks?.[plugin.name])] ?? 3)
  }
  return worst
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
  plugins.sort((a, b) => a.score - b.score)
  response = buildAuditResponse({
    profile: '',
    dir: args.dir,
    plugins,
    errors,
  })
} else {
  response = runAudit(args.profile)
}

if (args.json) {
  console.log(JSON.stringify(response, null, 2))
} else {
  const label = args.dir !== undefined
    ? `dir: ${args.dir}`
    : `profile: ${args.profile}`
  const lang = resolveCliLang({
    langFlag: args.lang,
    envLang: process.env.LC_ALL || process.env.LANG,
  })
  const color = resolveCliColor({
    tty: Boolean(process.stdout.isTTY),
    noColor: process.env.NO_COLOR,
    colorFlag: args.colorFlag,
  })
  process.stdout.write(formatHumanReport({
    contextLabel: label,
    plugins: response.plugins,
    errors: response.errors,
    acks: response.acks,
    lang,
    verbose: args.verbose,
    dirMode: args.dir !== undefined,
    color,
    columns: process.stdout.columns || 88,
  }))
}

// Assigned, not process.exit(): a piped stdout write is async, and exiting
// immediately can truncate the JSON a gate is about to parse.
if (args.exitCode) process.exitCode = gateExitCode(response, args.dir !== undefined)
