#!/usr/bin/env node
/**
 * Prints the CHANGELOG.md section for one version, without its heading.
 * The release workflow uses it as the GitHub Release body, which is what the
 * catalog fetches and dsh-market shows as the update notes.
 *
 * Usage: node scripts/release-notes.mjs 0.2.0
 * Exits 1 when CHANGELOG.md has no `## <version>` section.
 */
import { readFileSync } from 'node:fs'

const version = (process.argv[2] ?? '').replace(/^v/, '')
if (version === '') {
  console.error('usage: node scripts/release-notes.mjs <version>')
  process.exit(1)
}

const lines = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8').split('\n')
const heading = new RegExp(`^## ${version.replace(/\./g, '\\.')}(?:\\s|$)`)
const start = lines.findIndex(line => heading.test(line))
if (start === -1) {
  console.error(`CHANGELOG.md has no "## ${version}" section`)
  process.exit(1)
}
const rest = lines.slice(start + 1)
const end = rest.findIndex(line => line.startsWith('## '))
const section = (end === -1 ? rest : rest.slice(0, end)).join('\n').trim()
if (section === '') {
  console.error(`CHANGELOG.md "## ${version}" section is empty`)
  process.exit(1)
}
console.log(section)
