#!/usr/bin/env node
/**
 * Simulated dsh-market pre-install gate — implemented ONLY from
 * docs/INTEGRATION.md (Path A: spawn CLI). This is the "am I the integrator"
 * smoke test: if a fresh reader can wire a gate from the doc alone, the
 * contract is usable. It deliberately does NOT import dsh-trust-check's API.
 *
 * Usage:
 *   node scripts/market-gate-demo.mjs <extracted-dir> [--spec <spec>]
 *
 * Exit codes (gate semantics):
 *   0 = clear (may install silently)
 *   1 = review (show capabilities, suggest confirm)
 *   2 = red   (block by default)
 *   3 = scan failed (errors non-empty / empty plugins) → fail closed
 */

import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const [, , dirArg] = process.argv
const specFlag = process.argv.indexOf('--spec')
const spec = specFlag !== -1 && process.argv[specFlag + 1]
  ? process.argv[specFlag + 1]
  : 'dir:.'

if (dirArg === undefined || !existsSync(dirArg)) {
  console.error('usage: node scripts/market-gate-demo.mjs <extracted-dir> [--spec <spec>]')
  process.exit(3)
}

// --- spawn the scanner exactly as INTEGRATION.md Path A shows ------------
const cli = resolve(import.meta.dirname, '../bin/trust-check.mjs')
const run = spawnSync(process.execPath, [cli, '--dir', resolve(dirArg), '--spec', spec, '--json'], {
  encoding: 'utf8',
})
if (run.status !== 0) {
  // Doc does not mention exit codes; treat non-zero as scan failure.
  console.error(`scanner exited ${run.status}: ${run.stderr?.trim() || run.stdout?.trim()}`)
  process.exit(3)
}

let body
try {
  body = JSON.parse(run.stdout)
} catch (error) {
  console.error(`cannot parse scanner output: ${error.message}`)
  process.exit(3)
}

// --- doc: always check schemaVersion, then errors ------------------------
if (body.schemaVersion !== 1) {
  console.error(`unsupported audit schema ${body.schemaVersion}`)
  process.exit(3)
}
if (body.errors?.length > 0) {
  console.error(`scan failed: ${body.errors[0].message}`)
  process.exit(3)
}
const report = body.plugins?.[0]
if (report === undefined) {
  console.error('no audit report')
  process.exit(3)
}

// --- contract shape check: gate fields must exist (fail closed) ----------
// audit-schema.md: plugins[0] always carries name/version/spec/capabilities/
// redLines (injections included). A report missing them is malformed — treat
// as scan failure, never silently downgrade to a friendlier gate.
const requiredArrays = ['capabilities', 'redLines', 'injections']
const missing = requiredArrays.filter(key => !Array.isArray(report[key]))
if (missing.length > 0) {
  console.error(`malformed audit report: missing array field(s): ${missing.join(', ')}`)
  process.exit(3)
}
if (typeof report.name !== 'string' || report.name === '') {
  console.error('malformed audit report: missing name')
  process.exit(3)
}

// --- three-state gate (mirrors verdict(); no ack pre-install) ------------
const hasPatch = report.injections.some(
  i => i.kind === 'override' || i.kind === 'disable',
)
const gate = report.redLines.length > 0
  ? 'red'
  : report.capabilities.length > 0 || hasPatch
    ? 'review'
    : 'clear'

console.log(`plugin: ${report.name}@${report.version}`)
console.log(`schemaVersion: ${body.schemaVersion}`)
console.log(`capabilities: ${report.capabilities.join(', ') || '(none)'}`)
if (report.redLines.length > 0) console.log(`red lines: ${report.redLines.join(' | ')}`)
console.log(`gate: ${gate}`)

process.exit(gate === 'clear' ? 0 : gate === 'review' ? 1 : 2)
