#!/usr/bin/env node
/**
 * Catalog noise sample for dsh-market #401.
 *
 *   node scripts/catalog-noise.mjs sample   # write Top20 + Random20 + download list
 *   node scripts/catalog-noise.mjs expand   # append next Top/Random batch (keeps existing)
 *   node scripts/catalog-noise.mjs scan     # extract local tarballs, scan, write report
 *   node scripts/catalog-noise.mjs review   # write REVIEW.md checklist (TP/FP/FN)
 *
 * This script never downloads. Put .tgz files in work/downloads/ yourself,
 * then run scan (extract + dsh-trust-check --dir).
 */
import { execFileSync, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_CATALOG = resolve(ROOT, '../dsh-market/data/registry-snapshot.json')

function scannerLabel() {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  const version = typeof pkg.version === 'string' ? pkg.version : 'unknown'
  return `dsh-trust-check@${version}`
}
const WORK = join(ROOT, '.cache/catalog-sample')
const SEED = 20260830
const TOP_N = 20
const RANDOM_N = 20
const EXCLUDE_NPM = new Set(['dshmarket'])
const EXCLUDE_NAME = new Set(['dsh-market', 'dshmarket'])

const args = process.argv.slice(2)
const command = args[0]
const catalogPath = flagValue(args, '--catalog') ?? DEFAULT_CATALOG
const workDir = flagValue(args, '--work') ?? WORK
const expandTopN = Number(flagValue(args, '--top') ?? '40')
const expandRandomN = Number(flagValue(args, '--random') ?? '40')
const expandSeed = Number(flagValue(args, '--seed') ?? '20260907')

if (command !== 'sample' && command !== 'scan' && command !== 'expand' && command !== 'review') {
  console.error(`Usage:
  node scripts/catalog-noise.mjs sample  [--catalog <plugins.json>] [--work <dir>]
  node scripts/catalog-noise.mjs expand  [--catalog <plugins.json>] [--work <dir>]
                                         [--top 40] [--random 40] [--seed 20260907]
  node scripts/catalog-noise.mjs scan    [--work <dir>]
  node scripts/catalog-noise.mjs review  [--work <dir>]
`)
  process.exit(1)
}

if (command === 'sample') writeSample(catalogPath, workDir)
else if (command === 'expand') expandSample(catalogPath, workDir, expandTopN, expandRandomN, expandSeed)
else if (command === 'review') writeReview(workDir)
else scanWork(workDir)

/** Flatten every cohort list on a sample.json (top / random / top2 / …). */
function allEntries(sample) {
  const out = []
  for (const [key, value] of Object.entries(sample)) {
    if (!Array.isArray(value) || value.length === 0) continue
    if (typeof value[0] !== 'object' || value[0] === null || !('id' in value[0])) continue
    out.push(...value)
  }
  return out
}

function cohortLists(sample) {
  const lists = []
  for (const [key, value] of Object.entries(sample)) {
    if (!Array.isArray(value) || value.length === 0) continue
    if (typeof value[0] !== 'object' || value[0] === null || !('id' in value[0])) continue
    lists.push([key, value])
  }
  return lists
}

function flagValue(argv, name) {
  const i = argv.indexOf(name)
  return i >= 0 && argv[i + 1] ? argv[i + 1] : undefined
}

function loadCatalog(path) {
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  const plugins = Array.isArray(raw) ? raw : raw.plugins
  if (!Array.isArray(plugins)) throw new Error(`no plugins array in ${path}`)
  return {
    updated: raw.updated ?? null,
    count: plugins.length,
    plugins,
  }
}

function pluginId(plugin) {
  const raw = plugin.npm || `${plugin.owner}/${plugin.name}`
  return String(raw).replace(/^@/, '').replace(/[/@]/g, '-')
}

function isExcluded(plugin) {
  return EXCLUDE_NAME.has(plugin.name) || (plugin.npm != null && EXCLUDE_NPM.has(plugin.npm))
}

function downloadHint(plugin) {
  if (plugin.npm) {
    return {
      method: 'npm-pack',
      command: `npm pack ${plugin.npm} --pack-destination downloads`,
    }
  }
  if (plugin.tarball) {
    return {
      method: 'tarball-url',
      command: `curl -L -o downloads/${pluginId(plugin)}.tgz '${plugin.tarball}'`,
    }
  }
  if (plugin.url) {
    return {
      method: 'git-clone',
      command: `git clone --depth 1 '${plugin.url}' extracted/${pluginId(plugin)}`,
    }
  }
  return { method: 'none', command: null }
}

function toEntry(plugin, cohort) {
  return {
    id: pluginId(plugin),
    cohort,
    name: plugin.name,
    owner: plugin.owner,
    npm: plugin.npm ?? null,
    url: plugin.url ?? null,
    tarball: plugin.tarball ?? null,
    category: plugin.category ?? null,
    downloads: plugin.downloads ?? null,
    stars: plugin.stars ?? null,
    download: downloadHint(plugin),
  }
}

function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a += 0x6D2B79F5
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function pickRandom(items, n, seed) {
  const copy = items.slice()
  const rand = mulberry32(seed)
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    ;[copy[i], copy[j]] = [copy[j], copy[i]]
  }
  return copy.slice(0, n)
}

function writeSample(path, work) {
  const catalog = loadCatalog(path)
  const eligible = catalog.plugins.filter(p => !isExcluded(p))
  const withDownloads = eligible
    .filter(p => typeof p.downloads === 'number' && p.npm)
    .sort((a, b) => b.downloads - a.downloads)
  const top = withDownloads.slice(0, TOP_N).map(p => toEntry(p, 'top'))
  const topIds = new Set(top.map(e => e.id))
  const randomPool = eligible.filter(p => {
    if (topIds.has(pluginId(p))) return false
    return Boolean(p.npm)
  })
  const random = pickRandom(randomPool, RANDOM_N, SEED).map(p => toEntry(p, 'random'))

  mkdirSync(join(work, 'downloads'), { recursive: true })
  mkdirSync(join(work, 'extracted'), { recursive: true })
  mkdirSync(join(work, 'reports'), { recursive: true })

  const sample = {
    generatedAt: new Date().toISOString(),
    seed: SEED,
    catalog: { path, updated: catalog.updated, count: catalog.count },
    scanner: scannerLabel(),
    notes: [
      'Exclude dshmarket itself from Top 20.',
      'Random is shuffled from remaining npm-published plugins (same download path as Top 20) with a fixed seed.',
      'Download is manual: put .tgz in downloads/ or a package root in extracted/<id>/.',
    ],
    top,
    random,
  }
  writeFileSync(join(work, 'sample.json'), `${JSON.stringify(sample, null, 2)}\n`)
  writeFileSync(join(work, 'DOWNLOAD.md'), renderDownloadMd(sample))
  writeFileSync(join(work, 'download.sh'), renderDownloadSh(sample), { mode: 0o755 })

  console.log(`wrote ${join(work, 'sample.json')}`)
  console.log(`Top ${top.length} / Random ${random.length}`)
  console.log(`manual list: ${join(work, 'DOWNLOAD.md')}`)
  console.log(`when the network works: bash ${join(work, 'download.sh')}`)
}

/**
 * Append a second (or Nth) batch without wiping the original Top/Random 20.
 * New cohorts: top2 / random2 (or top3… if those keys already exist).
 */
function expandSample(path, work, topN, randomN, seed) {
  const samplePath = join(work, 'sample.json')
  if (!existsSync(samplePath)) {
    console.error(`missing ${samplePath}; run sample first`)
    process.exit(1)
  }
  if (!Number.isFinite(topN) || topN < 0 || !Number.isFinite(randomN) || randomN < 0) {
    console.error('--top / --random must be non-negative numbers')
    process.exit(1)
  }
  if (!Number.isFinite(seed)) {
    console.error('--seed must be a number')
    process.exit(1)
  }

  const sample = JSON.parse(readFileSync(samplePath, 'utf8'))
  const existing = allEntries(sample)
  const existingIds = new Set(existing.map(e => e.id))

  const catalog = loadCatalog(path)
  const eligible = catalog.plugins.filter(p => !isExcluded(p))
  const withDownloads = eligible
    .filter(p => typeof p.downloads === 'number' && p.npm)
    .sort((a, b) => b.downloads - a.downloads)

  let topKey = 'top2'
  let randomKey = 'random2'
  let n = 2
  while (Array.isArray(sample[topKey]) || Array.isArray(sample[randomKey])) {
    n += 1
    topKey = `top${n}`
    randomKey = `random${n}`
  }

  const top = withDownloads
    .filter(p => !existingIds.has(pluginId(p)))
    .slice(0, topN)
    .map(p => toEntry(p, topKey))
  for (const e of top) existingIds.add(e.id)

  const randomPool = eligible.filter(p => {
    if (!p.npm) return false
    return !existingIds.has(pluginId(p))
  })
  const random = pickRandom(randomPool, randomN, seed).map(p => toEntry(p, randomKey))

  sample[topKey] = top
  sample[randomKey] = random
  sample.scanner = scannerLabel()
  sample.expandedAt = new Date().toISOString()
  sample.expand = {
    ...(sample.expand && typeof sample.expand === 'object' ? sample.expand : {}),
    [String(n)]: { seed, topN, randomN, topKey, randomKey, added: top.length + random.length },
  }
  sample.catalog = { path, updated: catalog.updated, count: catalog.count }
  sample.notes = [
    ...(Array.isArray(sample.notes) ? sample.notes : []),
    `Batch ${n}: ${topKey}=${top.length} (next-by-downloads), ${randomKey}=${random.length} (seed ${seed}); excludes all prior sample ids.`,
  ]

  mkdirSync(join(work, 'downloads'), { recursive: true })
  mkdirSync(join(work, 'extracted'), { recursive: true })
  mkdirSync(join(work, 'reports'), { recursive: true })

  writeFileSync(samplePath, `${JSON.stringify(sample, null, 2)}\n`)
  writeFileSync(join(work, 'DOWNLOAD.md'), renderDownloadMd(sample))
  writeFileSync(join(work, 'download.sh'), renderDownloadSh(sample), { mode: 0o755 })
  writeReview(work)

  console.log(`appended ${topKey}=${top.length}, ${randomKey}=${random.length} (seed ${seed})`)
  console.log(`total entries: ${allEntries(sample).length}`)
  console.log(`download only the new packs, then: node scripts/catalog-noise.mjs scan`)
  console.log(`review sheet: ${join(work, 'REVIEW.md')}`)
}

function renderDownloadMd(sample) {
  const lines = [
    '# 手动下载清单（#401 噪音样本）',
    '',
    `目录更新：${sample.catalog.updated ?? 'unknown'} · seed=${sample.seed} · 扫描器 ${sample.scanner}`,
    '',
    '下载完成后把 **npm pack 产出的 .tgz** 放进本目录的 `downloads/`（文件名随意，scan 会按包名匹配）。',
    'git-only 条目请 clone 到 `extracted/<id>/`，目录里要有 `package.json`。',
    '',
    '然后：',
    '',
    '```sh',
    'node scripts/catalog-noise.mjs scan',
    'node scripts/catalog-noise.mjs review   # 更新复盘表',
    '```',
    '',
  ]
  for (const [key, list] of cohortLists(sample)) {
    lines.push(`## ${cohortTitle(key, list.length)}`, '')
    for (const [i, e] of list.entries()) {
      lines.push(`### ${i + 1}. ${e.name} \`${e.id}\``)
      lines.push('')
      lines.push(`- 分类：${e.category ?? '—'} · downloads：${e.downloads ?? '—'} · stars：${e.stars ?? '—'}`)
      if (e.npm) lines.push(`- npm：\`${e.npm}\``)
      if (e.url) lines.push(`- repo：${e.url}`)
      if (e.tarball) lines.push(`- 目录 tarball：${e.tarball}`)
      lines.push(`- 推荐：\`${e.download.command}\``)
      lines.push('')
    }
  }
  return `${lines.join('\n')}\n`
}

function cohortTitle(key, n) {
  if (key === 'top') return `A. 下载量 Top ${n}（排除 dshmarket）`
  if (key === 'random') return `B. 随机 ${n}（有 npm、排除 Top）`
  if (key.startsWith('top')) return `${key}. 下载量续批 ${n}（排除已采样）`
  if (key.startsWith('random')) return `${key}. 随机续批 ${n}（排除已采样）`
  return `${key} (${n})`
}

function renderDownloadSh(sample) {
  const lines = [
    '#!/bin/sh',
    '# Run this yourself when the network works. The Node script never fetches.',
    'set -eu',
    'cd "$(dirname "$0")"',
    'mkdir -p downloads extracted',
    '',
  ]
  for (const e of allEntries(sample)) {
    lines.push(`echo "=== ${e.cohort} ${e.id} ==="`)
    if (e.download.method === 'npm-pack') {
      lines.push(e.download.command)
    } else if (e.download.method === 'tarball-url') {
      lines.push(e.download.command)
    } else if (e.download.method === 'git-clone') {
      lines.push(`if [ ! -f extracted/${e.id}/package.json ]; then ${e.download.command}; fi`)
    } else {
      lines.push(`echo "skip ${e.id}: no download method" >&2`)
    }
    lines.push('')
  }
  lines.push('echo "done. run: node scripts/catalog-noise.mjs scan"')
  return `${lines.join('\n')}\n`
}

function scanWork(work) {
  const samplePath = join(work, 'sample.json')
  if (!existsSync(samplePath)) {
    console.error(`missing ${samplePath}; run sample first`)
    process.exit(1)
  }
  const sample = JSON.parse(readFileSync(samplePath, 'utf8'))
  const downloadsDir = join(work, 'downloads')
  const extractedDir = join(work, 'extracted')
  const reportsDir = join(work, 'reports')
  mkdirSync(downloadsDir, { recursive: true })
  mkdirSync(extractedDir, { recursive: true })
  mkdirSync(reportsDir, { recursive: true })

  const bin = join(ROOT, 'bin/trust-check.mjs')
  if (!existsSync(bin) || !existsSync(join(ROOT, 'lib/index.js'))) {
    console.error('build dsh-trust-check first: npm run build')
    process.exit(1)
  }

  const tarballs = existsSync(downloadsDir)
    ? readdirSync(downloadsDir).filter(f => f.endsWith('.tgz') || f.endsWith('.tar.gz'))
    : []

  const rows = []
  for (const entry of allEntries(sample)) {
    const row = scanOne(entry, { work, extractedDir, downloadsDir, tarballs, bin, reportsDir })
    rows.push(row)
    const mark = row.status === 'ok' ? 'ok' : row.status
    console.log(`${mark.padEnd(10)} ${entry.cohort.padEnd(8)} ${entry.id}`)
  }

  const report = {
    generatedAt: new Date().toISOString(),
    scanner: scannerLabel(),
    seed: sample.seed,
    catalog: sample.catalog,
    rows,
    summary: summarize(rows),
  }
  writeFileSync(join(work, 'report.json'), `${JSON.stringify(report, null, 2)}\n`)
  writeFileSync(join(work, 'REPORT.md'), renderReportMd(report))
  writeReview(work)
  console.log(`\nwrote ${join(work, 'REPORT.md')}`)
  console.log(`review sheet: ${join(work, 'REVIEW.md')}`)
}

function findTarball(entry, tarballs) {
  const exact = `${entry.id}.tgz`
  if (tarballs.includes(exact)) return exact
  if (entry.npm) {
    const prefix = String(entry.npm).replace(/^@/, '').replace(/\//g, '-')
    const hit = tarballs.find(f => f === `${prefix}.tgz` || f.startsWith(`${prefix}-`))
    if (hit) return hit
  }
  return tarballs.find(f => f.startsWith(`${entry.id}-`) || f.startsWith(`${entry.id}.`))
}

function scanOne(entry, ctx) {
  const dest = join(ctx.extractedDir, entry.id)
  const destPkg = join(dest, 'package.json')
  let source = null

  if (existsSync(destPkg)) {
    source = 'extracted'
  } else {
    const tarball = findTarball(entry, ctx.tarballs)
    if (tarball) {
      mkdirSync(dest, { recursive: true })
      try {
        execFileSync('tar', ['-xzf', join(ctx.downloadsDir, tarball), '-C', dest, '--strip-components=1'], {
          stdio: 'pipe',
        })
      } catch (error) {
        return fail(entry, 'extract-failed', error.message)
      }
      if (!existsSync(destPkg)) return fail(entry, 'extract-failed', 'no package.json after extract')
      source = `tarball:${tarball}`
    } else {
      return fail(entry, 'missing', 'put a .tgz in downloads/ or a package root in extracted/<id>/')
    }
  }

  const spec = entry.npm ? `npm:${entry.npm}` : `github:${entry.owner}/${entry.name}`
  const ran = spawnSync(process.execPath, [ctx.bin, '--dir', dest, '--spec', spec, '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (ran.status !== 0) {
    return fail(entry, 'scan-failed', (ran.stderr || ran.stdout || 'scanner exited non-zero').slice(0, 400))
  }

  let body
  try {
    body = JSON.parse(ran.stdout)
  } catch (error) {
    return fail(entry, 'scan-failed', `invalid json: ${error.message}`)
  }
  writeFileSync(join(ctx.reportsDir, `${entry.id}.json`), `${JSON.stringify(body, null, 2)}\n`)
  const plugin = body.plugins?.[0]
  if (!plugin) {
    const message = body.errors?.[0]?.message ?? 'empty plugins[]'
    return fail(entry, 'scan-failed', message)
  }

  const hosts = uniqueHosts(plugin.destinations ?? [])
  return {
    id: entry.id,
    cohort: entry.cohort,
    name: entry.name,
    npm: entry.npm,
    category: entry.category,
    downloads: entry.downloads,
    status: 'ok',
    source,
    version: plugin.version,
    capabilities: plugin.capabilities ?? [],
    chipCount: (plugin.capabilities ?? []).length,
    hosts,
    hostCount: hosts.length,
    hasBuildScript: Boolean(plugin.hasBuildScript),
    buildScripts: plugin.buildScripts ?? [],
    redLines: plugin.redLines ?? [],
    verdict: plugin.capabilities?.length || plugin.redLines?.length ? (plugin.redLines?.length ? 'red' : 'review') : 'clear',
    error: null,
  }
}

function uniqueHosts(destinations) {
  const hosts = new Set()
  for (const d of destinations) {
    if (d.kind === 'https-host' || d.kind === 'http-host' || d.kind === 'ip') hosts.add(d.value)
  }
  return [...hosts].sort()
}

function fail(entry, status, error) {
  return {
    id: entry.id,
    cohort: entry.cohort,
    name: entry.name,
    npm: entry.npm,
    category: entry.category,
    downloads: entry.downloads,
    status,
    source: null,
    version: null,
    capabilities: [],
    chipCount: 0,
    hosts: [],
    hostCount: 0,
    hasBuildScript: false,
    buildScripts: [],
    redLines: [],
    verdict: null,
    error,
  }
}

function summarize(rows) {
  const ok = rows.filter(r => r.status === 'ok')
  const cohorts = [...new Set(rows.map(r => r.cohort))]
  const byCohort = {}
  for (const cohort of cohorts) {
    byCohort[cohort] = chipStats(ok.filter(r => r.cohort === cohort))
  }
  return {
    total: rows.length,
    scanned: ok.length,
    missing: rows.filter(r => r.status === 'missing').length,
    failed: rows.filter(r => r.status !== 'ok' && r.status !== 'missing').length,
    byCohort,
    overall: chipStats(ok),
  }
}

function chipStats(rows) {
  const chips = {}
  let withNetwork = 0
  let withAnyChip = 0
  let withBuild = 0
  let withRed = 0
  let empty = 0
  for (const row of rows) {
    if (row.capabilities.length === 0) empty++
    else withAnyChip++
    if (row.capabilities.includes('network')) withNetwork++
    if (row.hasBuildScript) withBuild++
    if (row.redLines.length > 0) withRed++
    for (const cap of row.capabilities) chips[cap] = (chips[cap] ?? 0) + 1
  }
  return {
    n: rows.length,
    withAnyChip,
    empty,
    withNetwork,
    networkRate: rows.length ? withNetwork / rows.length : 0,
    withBuild,
    withRed,
    chips,
  }
}

function renderReportMd(report) {
  const lines = [
    '# dsh-trust-check catalog noise (#401)',
    '',
    `- scanner: ${report.scanner}`,
    `- catalog: ${report.catalog.updated ?? 'unknown'} (${report.catalog.count} entries)`,
    `- seed: ${report.seed}`,
    `- scanned: ${report.summary.scanned}/${report.summary.total} (missing ${report.summary.missing}, failed ${report.summary.failed})`,
    '',
    'UI rule under test: show chips only when something was found; an empty card area is *no information*, not a safety claim.',
    '',
    '## Chip rates',
    '',
    '| cohort | n | any chip | no chip | network | install script | red line |',
    '|---|---:|---:|---:|---:|---:|---:|',
  ]
  const cohortKeys = Object.keys(report.summary.byCohort)
  for (const key of cohortKeys) {
    const s = report.summary.byCohort[key]
    lines.push(`| ${key} | ${s.n} | ${s.withAnyChip} | ${s.empty} | ${pct(s.withNetwork, s.n)} | ${s.withBuild} | ${s.withRed} |`)
  }
  {
    const s = report.summary.overall
    lines.push(`| all scanned | ${s.n} | ${s.withAnyChip} | ${s.empty} | ${pct(s.withNetwork, s.n)} | ${s.withBuild} | ${s.withRed} |`)
  }
  lines.push('', '### Capability histogram (scanned only)', '')
  const chips = report.summary.overall.chips
  const keys = Object.keys(chips).sort((a, b) => chips[b] - chips[a])
  if (keys.length === 0) {
    lines.push('_no chips yet — download the packs and re-run scan_')
  } else {
    lines.push('| capability | count |', '|---|---:|')
    for (const key of keys) lines.push(`| ${key} | ${chips[key]} |`)
  }

  for (const cohort of cohortKeys) {
    lines.push('', `## ${cohortTitle(cohort, report.rows.filter(r => r.cohort === cohort).length)}`, '')
    lines.push('| plugin | version | chips | hosts | install script | red | status |')
    lines.push('|---|---|---|---:|---|---|---|')
    for (const row of report.rows.filter(r => r.cohort === cohort)) {
      const chipsCell = row.status === 'ok' ? (row.capabilities.join(', ') || '—') : '—'
      const red = row.redLines.length ? 'yes' : (row.status === 'ok' ? '' : '—')
      const build = row.status === 'ok' ? (row.hasBuildScript ? row.buildScripts.join(', ') : '') : '—'
      const status = row.status === 'ok' ? row.verdict : `${row.status}: ${row.error}`
      lines.push(`| ${row.name} | ${row.version ?? ''} | ${chipsCell} | ${row.hostCount} | ${build} | ${red} | ${status} |`)
    }
  }

  lines.push(
    '',
    '## Notes',
    '',
    '- `--dir` on an extracted package; `node_modules` is not installed and not scanned.',
    '- Known misses stay: concatenated URLs, dynamic `import()`, obfuscated `eval`.',
    '- Human review sheet: `REVIEW.md` (TP / FP / FN — prefer rule fixes over allowlists).',
    '',
  )
  return `${lines.join('\n')}\n`
}

/**
 * Checklist for slow human review. Prefer fixing rules for FP / adding call-site
 * rules for FN; allowlist only as a last resort (see CONTRIBUTING.md).
 */
function writeReview(work) {
  const samplePath = join(work, 'sample.json')
  if (!existsSync(samplePath)) {
    console.error(`missing ${samplePath}; run sample first`)
    process.exit(1)
  }
  const sample = JSON.parse(readFileSync(samplePath, 'utf8'))
  const reportPath = join(work, 'report.json')
  const report = existsSync(reportPath) ? JSON.parse(readFileSync(reportPath, 'utf8')) : null
  const byId = new Map((report?.rows ?? []).map(r => [r.id, r]))

  const lines = [
    '# Catalog review sheet',
    '',
    'Fill one row at a time. Goal: classify scanner output against threat-model “presence” claims — not CVE hunting.',
    '',
    '| Label | Meaning | Next step |',
    '|---|---|---|',
    '| **TP** | Finding is real / expected for this plugin | keep |',
    '| **FP** | Finding should not fire | fix rule / fixture; allowlist only if CONTRIBUTING allows |',
    '| **FN** | Should have proven a capability / red-line shape and did not | add call-site rule + test |',
    '| **OK-clear** | Empty chips is fine (truly minimal / no privileged shape) | keep; remember clear ≠ safe |',
    '',
    'Do **not** bulk-fill destination allowlists to clear the board.',
    '',
    `- sample entries: ${allEntries(sample).length}`,
    `- report: ${report
      ? `${report.summary.scanned}/${report.summary.total} in last scan`
        + (report.summary.total < allEntries(sample).length
          ? ` (sample grew — re-run scan after downloading new packs)`
          : '')
      : '_run scan first for gate columns_'}`,
    '',
  ]

  for (const [key, list] of cohortLists(sample)) {
    lines.push(`## ${cohortTitle(key, list.length)}`, '')
    lines.push('| plugin | gate | caps | red | class (TP/FP/FN/OK-clear) | notes |')
    lines.push('|---|---|---|---|---|---|')
    for (const e of list) {
      const row = byId.get(e.id)
      if (!row || row.status !== 'ok') {
        const status = row?.status ?? 'pending'
        lines.push(`| ${e.name} (\`${e.id}\`) | ${status} | — | — |  |  |`)
        continue
      }
      const caps = row.capabilities.join(', ') || '—'
      const red = row.redLines.length ? row.redLines.join('; ') : '—'
      lines.push(`| ${e.name} (\`${e.id}\`) | ${row.verdict} | ${caps} | ${red} |  |  |`)
    }
    lines.push('')
  }

  writeFileSync(join(work, 'REVIEW.md'), `${lines.join('\n')}\n`)
  console.log(`wrote ${join(work, 'REVIEW.md')}`)
}

function pct(part, total) {
  if (!total) return '0 (0%)'
  return `${part} (${Math.round((part / total) * 100)}%)`
}
