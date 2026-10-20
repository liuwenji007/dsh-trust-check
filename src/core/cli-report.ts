/**
 * Human-readable CLI report. Compact by default for personal review;
 * `--verbose` expands every plugin. Shared strings stay aligned with Settings.
 * TTY gets ANSI hierarchy; pipes / tests stay plain unless `color: true`.
 */

import { partitionDestinations } from './destination-priority.ts'
import {
  ackDrifted,
  capabilityDelta,
  concerns,
  concernText,
  countVerdicts,
  formatInjectionDetail,
  groupEvidenceByFile,
  networkReach,
  verdict,
  type Concern,
  type PresentLang,
  type Verdict,
} from './present.ts'
import type { AuditReport, Capability, TrustAckEntry } from './types.ts'

export type CliLang = PresentLang

export interface HumanReportOptions {
  contextLabel: string
  plugins: AuditReport[]
  errors: Array<{ name: string, message: string }>
  acks?: Record<string, TrustAckEntry>
  lang: CliLang
  verbose: boolean
  /** `--dir` mode: action copy must not point at Settings. */
  dirMode: boolean
  /** ANSI hierarchy for TTY. Off by default (tests / pipes). */
  color?: boolean
  /** Terminal columns; used to size cards. Defaults to 88. */
  columns?: number
}

interface Style {
  enabled: boolean
  bold: (s: string) => string
  dim: (s: string) => string
  red: (s: string) => string
  yellow: (s: string) => string
  green: (s: string) => string
  cyan: (s: string) => string
  magenta: (s: string) => string
}

function wrap(enabled: boolean, code: string, s: string): string {
  if (!enabled || s === '') return s
  return `\u001B[${code}m${s}\u001B[0m`
}

function createStyle(enabled: boolean): Style {
  return {
    enabled,
    bold: s => wrap(enabled, '1', s),
    dim: s => wrap(enabled, '2', s),
    red: s => wrap(enabled, '31', s),
    yellow: s => wrap(enabled, '33', s),
    green: s => wrap(enabled, '32', s),
    cyan: s => wrap(enabled, '36', s),
    magenta: s => wrap(enabled, '35', s),
  }
}

/** TTY color unless NO_COLOR; `--color` / `--no-color` override. */
export function resolveCliColor(input: {
  tty: boolean
  noColor?: string
  colorFlag?: boolean
}): boolean {
  if (input.colorFlag === true) return true
  if (input.colorFlag === false) return false
  if (input.noColor !== undefined) return false
  return input.tty
}

const VERDICT_ZH: Record<Verdict, string> = {
  red: '有红线',
  accepted: '风险已确认',
  review: '需确认',
  expected: '能力如预期',
  clear: '未检出项目',
}

const VERDICT_EN: Record<Verdict, string> = {
  red: 'red',
  accepted: 'accepted',
  review: 'review',
  expected: 'expected',
  clear: 'clear',
}

/** Prefer `--lang`; English only when the env is clearly English; otherwise zh. */
export function resolveCliLang(input: {
  langFlag?: string
  envLang?: string
}): CliLang {
  const flag = input.langFlag?.trim().toLowerCase()
  if (flag === 'en' || flag === 'zh') return flag
  const env = (input.envLang ?? '').toLowerCase()
  if (env.startsWith('en')) return 'en'
  return 'zh'
}

function verdictLabel(v: Verdict, lang: CliLang, drifted: boolean): string {
  if (drifted && v !== 'red') {
    return lang === 'zh' ? '需重新确认' : 'reconfirm'
  }
  return (lang === 'zh' ? VERDICT_ZH : VERDICT_EN)[v]
}

function paintVerdict(label: string, v: Verdict, drifted: boolean, style: Style): string {
  if (v === 'red') return style.red(label)
  if (drifted || v === 'review') return style.yellow(label)
  if (v === 'accepted') return style.magenta(label)
  if (v === 'expected') return style.green(label)
  return style.dim(label)
}

function fieldLines(label: string, value: string, style: Style): string[] {
  return [`  ${style.dim(label)}`, `    ${value}`]
}

/** Evidence as two lines: snippet, then cyan @loc — avoids cramped wraps. */
function paintEvidenceLines(line: string, style: Style): string[] {
  const at = line.lastIndexOf('  @ ')
  if (at < 0) return [style.dim(`      ${line}`)]
  return [
    style.dim(`      ${line.slice(0, at)}`),
    style.cyan(`        @ ${line.slice(at + 4)}`),
  ]
}

function blank(): string {
  return ''
}

const ANSI_RE = /\u001B\[[0-9;]*m/g

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, '')
}

/** Cell width of one code point. Box-drawing and a few punctuation marks are 1. */
function cellWidth(code: number): number {
  if (code <= 0xff || code === 0x2026 || code === 0x2022) return 1
  if (code >= 0x2500 && code <= 0x259f) return 1
  return 2
}

/** Terminal columns for a string (CJK ≈ 2). Ignores ANSI. */
function visibleWidth(s: string): number {
  let width = 0
  for (const ch of stripAnsi(s)) {
    width += cellWidth(ch.codePointAt(0) ?? 0)
  }
  return width
}

function padVisible(s: string, width: number): string {
  const gap = width - visibleWidth(s)
  return gap > 0 ? `${s}${' '.repeat(gap)}` : s
}

/**
 * Soft-wrap to `width` columns (preserves ANSI). Break after spaces / commas
 * that are not leading indent — a leading space must not become the wrap point,
 * or the remainder overflows and the indent is flushed as an empty line.
 */
export function wrapVisible(s: string, width: number): string[] {
  if (width < 8 || visibleWidth(s) <= width) return [s]
  const lines: string[] = []
  let rest = s
  while (visibleWidth(rest) > width) {
    const { head, tail } = splitAt(rest, width)
    if (head === '' || tail === rest) {
      lines.push(rest)
      return lines
    }
    lines.push(head)
    rest = tail
  }
  if (rest !== '') lines.push(rest)
  return lines
}

function splitAt(s: string, width: number): { head: string, tail: string } {
  let current = ''
  let currentW = 0
  let i = 0
  let lastBreak = -1
  let seenContent = false
  const advance = (cp: number) => (cp > 0xffff ? 2 : 1)

  while (i < s.length) {
    if (s[i] === '\u001B') {
      const end = s.indexOf('m', i)
      if (end === -1) break
      current += s.slice(i, end + 1)
      i = end + 1
      continue
    }
    const cp = s.codePointAt(i) ?? 0
    const ch = String.fromCodePoint(cp)
    const w = cellWidth(cp)
    if (currentW + w > width && currentW > 0) {
      const restStart = i + advance(cp)
      if (lastBreak > 0) {
        const head = current.slice(0, lastBreak).trimEnd()
        const leftover = `${current.slice(lastBreak)}${ch}${s.slice(restStart)}`.replace(/^\s+/, '')
        return { head: head === '' ? current : head, tail: leftover === '' ? '' : `  ${leftover}` }
      }
      const leftover = `${ch}${s.slice(restStart)}`
      return { head: current, tail: leftover === '' ? '' : `  ${leftover}` }
    }
    current += ch
    currentW += w
    if (ch !== ' ') seenContent = true
    if (seenContent && (ch === ' ' || ch === '·' || ch === ',')) lastBreak = current.length
    i += advance(cp)
  }
  return { head: current + s.slice(i), tail: '' }
}

/**
 * Spacious card: empty top/bottom padding, soft-wrapped body, width from columns.
 */
function wrapBlock(body: string[], style: Style, columns = 88): string[] {
  const inner = Math.max(8, Math.min(92, columns - 4))
  const top = style.dim(`╭${'─'.repeat(inner)}╮`)
  const bottom = style.dim(`╰${'─'.repeat(inner)}╯`)
  const mid = style.dim(`├${'─'.repeat(inner)}┤`)
  const empty = `${style.dim('│')}${padVisible('', inner)}${style.dim('│')}`
  const rows: string[] = [top, empty]
  for (const line of body) {
    if (line === '---') {
      rows.push(mid)
      continue
    }
    // One space from the border; body lines carry their own indent.
    const padded = line === '' ? '' : ` ${line}`
    for (const part of wrapVisible(padded, inner)) {
      rows.push(`${style.dim('│')}${padVisible(part, inner)}${style.dim('│')}`)
    }
  }
  rows.push(empty)
  rows.push(bottom)
  rows.push('')
  return rows
}

function actionLine(v: Verdict, lang: CliLang, dirMode: boolean): string {
  if (lang === 'zh') {
    if (v === 'red') {
      return dirMode
        ? '请先复核具体事实（红线、能力与证据），再决定是否安装。'
        : '请先复核具体事实；了解后可在设置页确认风险，或移除该插件。'
    }
    if (v === 'accepted') return '已在设置页确认当前红线风险；升级后若变化会再次提示。'
    if (v === 'review') {
      return dirMode
        ? '未见硬红线；请对照装它的目的复核这些能力后再决定是否安装。'
        : '未见硬红线；若这些能力符合你装它的目的，可在设置页记为预期。'
    }
    if (v === 'expected') return '已在设置页确认当前能力与去向符合预期。'
    return '静态扫描未检出需要提示的项目（不是安全背书）。'
  }
  if (v === 'red') {
    return dirMode
      ? 'Review these facts before install.'
      : 'Stop by default; confirm the risk in Settings if you still want to keep it.'
  }
  if (v === 'accepted') return 'Red-line risk acknowledged in Settings; upgrade may prompt again.'
  if (v === 'review') {
    return dirMode
      ? 'No hard red lines; review these facts before install.'
      : 'No hard red lines; if capabilities match why you installed it, mark as expected in Settings.'
  }
  if (v === 'expected') return 'Capabilities marked as expected in Settings.'
  return 'No red lines or privileged capabilities detected.'
}

function needsDetail(v: Verdict, drifted: boolean, verbose: boolean): boolean {
  if (verbose) return true
  if (drifted) return true
  return v === 'red' || v === 'review' || v === 'accepted'
}

function loc(file: string, line: number): string {
  return line > 0 ? `${file}:${line}` : file
}

function pushEvidence(
  lines: string[],
  max: number,
  value: string,
  file?: string,
  line?: number,
): void {
  if (lines.length >= max) return
  // Soft-wrap in the card handles length; keep snippets readable.
  const shown = value.length > 100 ? `${value.slice(0, 97)}…` : value
  if (file !== undefined) {
    lines.push(`${shown}  @ ${loc(file, line ?? 0)}`)
  } else {
    lines.push(shown)
  }
}

function pushCapabilityEvidence(
  lines: string[],
  report: AuditReport,
  caps: Capability[],
  max: number,
): void {
  const rows = report.evidence.filter(row => caps.includes(row.capability))
  for (const group of groupEvidenceByFile(rows)) {
    for (const row of group.rows) {
      if (lines.length >= max) break
      const snippet = row.snippet.trim().replace(/\s+/g, ' ')
      pushEvidence(lines, max, snippet || row.capability, row.file, row.line)
    }
    if (lines.length >= max) break
  }
}

/** Up to `max` evidence pointers for one concern bullet. */
export function concernEvidenceLines(report: AuditReport, concern: Concern, max = 2): string[] {
  const lines: string[] = []

  if (concern.code === 'install-script') {
    const scripts = report.buildScripts.length > 0
      ? report.buildScripts
      : report.hasBuildScript
        ? ['install script']
        : []
    for (const script of scripts) pushEvidence(lines, max, script)
    return lines
  }
  if (concern.code === 'core-tamper') {
    for (const inj of report.injections) {
      if (inj.kind !== 'override' && inj.kind !== 'disable') continue
      pushEvidence(lines, max, formatInjectionDetail(inj.detail))
    }
    return lines
  }
  if (concern.code === 'plaintext-http') {
    for (const d of report.destinations ?? []) {
      if (d.kind !== 'http-host') continue
      pushEvidence(lines, max, d.value, d.file, d.line)
    }
    return lines
  }
  if (concern.code === 'literal-ip') {
    for (const d of report.destinations ?? []) {
      if (d.kind !== 'ip') continue
      pushEvidence(lines, max, d.value, d.file, d.line)
    }
    return lines
  }
  if (concern.code === 'creds-network') {
    pushCapabilityEvidence(lines, report, ['credentials', 'network'], max)
    return lines
  }
  if (concern.code === 'raw') {
    if (concern.detail) pushEvidence(lines, max, concern.detail)
    return lines
  }
  if (concern.code === 'external-dest') {
    const { priority } = partitionDestinations(report.destinations ?? [])
    for (const d of priority) pushEvidence(lines, max, d.value, d.file, d.line)
    return lines
  }
  if (concern.code === 'path-escape') {
    for (const pe of report.pathEscapes ?? []) {
      pushEvidence(lines, max, pe.value, pe.file, pe.line)
    }
    return lines
  }
  if (concern.code === 'secret-touch') {
    for (const s of report.secretTouches ?? []) {
      pushEvidence(lines, max, s.value, s.file, s.line)
    }
    return lines
  }

  pushCapabilityEvidence(lines, report, [concern.code as Capability], max)
  return lines
}

function formatCaps(report: AuditReport, lang: CliLang): string {
  if (report.capabilities.length === 0) return lang === 'zh' ? '无' : 'none'
  return report.capabilities.map(c => {
    if (c !== 'network') return c
    const reach = networkReach(report)
    if (reach === 'outbound') return lang === 'zh' ? 'network (外连)' : 'network (outbound)'
    if (reach === 'same-origin') return lang === 'zh' ? 'network (同源)' : 'network (same-origin)'
    return c
  }).join(', ')
}

function formatDestSummary(
  report: AuditReport,
  lang: CliLang,
  verbose: boolean,
  style: Style,
): string[] {
  const destinations = report.destinations ?? []
  if (destinations.length === 0) return []
  const { priority, safe } = partitionDestinations(destinations)
  const out: string[] = []
  if (!verbose) {
    const hosts = priority.slice(0, 5).map(d => d.value)
    const more = priority.length > hosts.length ? ` (+${priority.length - hosts.length})` : ''
    const safeNote = safe.length > 0
      ? (lang === 'zh' ? ` · 另有 ${safe.length} 个白名单/本机` : ` · +${safe.length} allowlisted/loopback`)
      : ''
    if (hosts.length > 0) {
      out.push(...fieldLines(lang === 'zh' ? '去向' : 'destinations', `${hosts.join(', ')}${more}${safeNote}`, style))
    } else if (safe.length > 0) {
      out.push(...fieldLines(
        lang === 'zh' ? '去向' : 'destinations',
        lang === 'zh' ? `${safe.length} 个白名单/本机` : `${safe.length} allowlisted/loopback`,
        style,
      ))
    }
    return out
  }
  out.push(`  ${style.dim(lang === 'zh' ? '去向（字面量）' : 'destinations (literal)')}`)
  for (const d of priority.slice(0, 8)) {
    out.push(`    ${d.kind}: ${d.value}${style.cyan(`  @ ${loc(d.file, d.line)}`)}`)
  }
  if (safe.length > 0) {
    out.push(style.dim(lang === 'zh'
      ? `    … + ${safe.length} 个白名单/本机去向`
      : `    … + ${safe.length} allowlisted/loopback destination(s)`))
  }
  return out
}

function formatShapeSummaries(
  report: AuditReport,
  lang: CliLang,
  verbose: boolean,
  listed: Concern[],
  style: Style,
): string[] {
  const out: string[] = []
  const covered = new Set(listed.map(c => c.code))
  const paths = report.pathEscapes ?? []
  const secrets = report.secretTouches ?? []

  if (verbose) {
    if (paths.length > 0) {
      out.push(`  ${style.dim(lang === 'zh' ? '工作区外路径' : 'workspace path escapes')}`)
      for (const pe of paths.slice(0, 8)) {
        out.push(`    ${pe.kind}: ${pe.value}${style.cyan(`  @ ${loc(pe.file, pe.line)}`)}`)
      }
    }
    if (secrets.length > 0) {
      out.push(`  ${style.dim(lang === 'zh' ? '密钥触摸' : 'secret touches')}`)
      for (const s of secrets.slice(0, 8)) {
        out.push(`    ${s.kind}: ${s.value}${style.cyan(`  @ ${loc(s.file, s.line)}`)}`)
      }
    }
    return out
  }

  if (paths.length > 0 && !covered.has('path-escape')) {
    const sample = paths.slice(0, 3).map(p => p.value).join(', ')
    const more = paths.length > 3 ? ` (+${paths.length - 3})` : ''
    out.push(...fieldLines(lang === 'zh' ? '工作区外路径' : 'path escapes', `${sample}${more}`, style))
  }
  if (secrets.length > 0 && !covered.has('secret-touch')) {
    const sample = secrets.slice(0, 3).map(s => s.value).join(', ')
    const more = secrets.length > 3 ? ` (+${secrets.length - 3})` : ''
    out.push(...fieldLines(lang === 'zh' ? '密钥触摸' : 'secret touches', `${sample}${more}`, style))
  }
  return out
}

function formatInjections(
  report: AuditReport,
  lang: CliLang,
  verbose: boolean,
  style: Style,
): string[] {
  if (report.injections.length === 0) return []
  const out: string[] = []
  const tokenPart = report.injectedTokensEstimate > 0
    ? (lang === 'zh'
      ? ` · ~${report.injectedTokensEstimate} tokens（成本）`
      : ` · ~${report.injectedTokensEstimate} tokens (cost)`)
    : ''
  out.push(`  ${style.dim(lang === 'zh' ? '注入' : 'injections')}`)
  out.push(lang === 'zh'
    ? `    ${report.injections.length} 项${tokenPart}`
    : `    ${report.injections.length} item(s)${tokenPart}`)

  const patch = report.injections.filter(i => i.kind === 'override' || i.kind === 'disable')
  const rest = report.injections.filter(i => i.kind !== 'override' && i.kind !== 'disable')
  const show = verbose
    ? report.injections.slice(0, 5)
    : [...patch, ...rest].slice(0, 3)
  for (const inj of show) {
    const detail = formatInjectionDetail(inj.detail)
    const kind = inj.kind === 'override' || inj.kind === 'disable'
      ? style.yellow(inj.kind)
      : style.dim(inj.kind)
    out.push(`    ${kind}  ${detail}`)
  }
  if (report.injections.length > show.length) {
    out.push(style.dim(lang === 'zh'
      ? `    … 另有 ${report.injections.length - show.length} 项`
      : `    … and ${report.injections.length - show.length} more`))
  }
  return out
}

function formatPluginDetail(
  report: AuditReport,
  ack: TrustAckEntry | undefined,
  lang: CliLang,
  verbose: boolean,
  dirMode: boolean,
  style: Style,
  columns: number,
): string[] {
  const v = verdict(report, ack)
  const drifted = ackDrifted(report, ack)
  const label = verdictLabel(v, lang, drifted)
  const badge = paintVerdict(label, v, drifted, style)
  const body: string[] = []

  // Title row inside the card
  body.push(`${style.bold(report.name)}  ${style.dim(report.version)}`)
  body.push(badge)
  body.push(blank())
  body.push(style.dim(actionLine(v, lang, dirMode)))

  if (drifted) {
    const delta = capabilityDelta(report, ack)
    const bits: string[] = []
    for (const c of delta.added) bits.push(style.yellow(`+${c}`))
    for (const c of delta.removed) bits.push(style.dim(`−${c}`))
    if (bits.length > 0) {
      body.push(blank())
      body.push(...fieldLines(lang === 'zh' ? '与上次确认相比' : 'since last ack', bits.join(' '), style))
    }
  }

  const list = concerns(report)
  if (list.length > 0 && v !== 'expected' && v !== 'accepted') {
    body.push(blank())
    body.push('---')
    body.push(blank())
    body.push(style.dim(lang === 'zh' ? '为什么要小心' : 'why be careful'))
    body.push(blank())
    const bullet = v === 'red' ? style.red('•') : style.yellow('•')
    for (const item of list) {
      body.push(`  ${bullet}  ${concernText(item, lang)}`)
      for (const ev of concernEvidenceLines(report, item)) {
        body.push(...paintEvidenceLines(ev, style))
      }
      body.push(blank())
    }
  }

  body.push('---')
  body.push(blank())
  body.push(...fieldLines(lang === 'zh' ? '能力' : 'capabilities', formatCaps(report, lang), style))
  body.push(blank())
  const dest = formatDestSummary(report, lang, verbose, style)
  if (dest.length > 0) {
    body.push(...dest)
    body.push(blank())
  }
  const shape = formatShapeSummaries(report, lang, verbose, list, style)
  if (shape.length > 0) {
    body.push(...shape)
    body.push(blank())
  }
  const inj = formatInjections(report, lang, verbose, style)
  if (inj.length > 0) {
    body.push(...inj)
    body.push(blank())
  }

  const source = [report.pinned
    ? (lang === 'zh' ? '已锁版本' : 'pinned')
    : (lang === 'zh' ? '未锁版本' : 'unpinned')]
  if (report.repository === undefined) source.push(lang === 'zh' ? '未声明仓库' : 'no repository')
  else source.push(report.repository)
  if (report.hasBuildScript) {
    source.push(lang === 'zh'
      ? `安装脚本: ${report.buildScripts.join(', ')}`
      : `install scripts: ${report.buildScripts.join(', ')}`)
  }
  body.push(...fieldLines(lang === 'zh' ? '来源' : 'source', source.join(' · '), style))

  if (verbose && report.evidence.length > 0) {
    body.push(blank())
    body.push(...fieldLines(
      lang === 'zh' ? '证据' : 'evidence',
      lang === 'zh' ? `${report.evidence.length} 处` : `${report.evidence.length} hit(s)`,
      style,
    ))
  }

  // Drop trailing blank lines before the box pads its own bottom.
  while (body.length > 0 && body[body.length - 1] === '') body.pop()

  return wrapBlock(body, style, columns)
}

function formatPluginOneLiner(
  report: AuditReport,
  ack: TrustAckEntry | undefined,
  lang: CliLang,
  style: Style,
): string {
  const v = verdict(report, ack)
  const drifted = ackDrifted(report, ack)
  const label = verdictLabel(v, lang, drifted)
  const badge = paintVerdict(label, v, drifted, style)
  return `${style.dim(`${report.name} ${report.version}`)}  ${badge}`
}

function formatOverview(
  plugins: AuditReport[],
  counts: Record<Verdict, number>,
  lang: CliLang,
  style: Style,
): string {
  if (lang === 'zh') {
    return [
      `${plugins.length} 个插件`,
      style.red(`${counts.red} 有红线`),
      style.magenta(`${counts.accepted} 风险已确认`),
      style.yellow(`${counts.review} 需确认`),
      style.green(`${counts.expected} 能力如预期`),
      style.dim(`${counts.clear} 未检出项目`),
    ].join(style.dim(' · '))
  }
  return [
    `${plugins.length} plugin(s)`,
    style.red(`${counts.red} red`),
    style.magenta(`${counts.accepted} accepted`),
    style.yellow(`${counts.review} review`),
    style.green(`${counts.expected} expected`),
    style.dim(`${counts.clear} clear`),
  ].join(style.dim(' · '))
}

/** Full human report as a single string (trailing newline included). */
export function formatHumanReport(options: HumanReportOptions): string {
  const { contextLabel, plugins, errors, acks, lang, verbose, dirMode } = options
  const style = createStyle(options.color === true)
  const columns = options.columns ?? 88
  const counts = countVerdicts(plugins, acks)
  const lines: string[] = []
  lines.push(style.bold(contextLabel))
  lines.push(formatOverview(plugins, counts, lang, style))
  if (!verbose) {
    lines.push(style.dim(lang === 'zh'
      ? '默认紧凑 · 展开需处理项 · --verbose 全量 · 机器集成用 --json'
      : 'compact · details for attention items · --verbose full · machine: --json'))
  }
  lines.push('')

  let afterQuiet = false
  for (const plugin of plugins) {
    const ack = acks?.[plugin.name]
    const v = verdict(plugin, ack)
    const drifted = ackDrifted(plugin, ack)
    if (needsDetail(v, drifted, verbose)) {
      if (afterQuiet) lines.push('')
      lines.push(...formatPluginDetail(plugin, ack, lang, verbose, dirMode, style, columns))
      afterQuiet = false
    } else {
      lines.push(formatPluginOneLiner(plugin, ack, lang, style))
      afterQuiet = true
    }
  }

  if (errors.length > 0) {
    lines.push('')
    lines.push(style.red(lang === 'zh'
      ? `${errors.length} 个插件无法读取`
      : `${errors.length} plugin(s) could not be read`))
    for (const e of errors) lines.push(style.dim(`  - ${e.name}: ${e.message}`))
  }

  return `${lines.join('\n').replace(/\n+$/, '')}\n`
}
