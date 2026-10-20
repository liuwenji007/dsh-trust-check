import { describe, expect, it } from 'vitest'
import { concernEvidenceLines, formatHumanReport, resolveCliColor, resolveCliLang, wrapVisible } from '../../src/core/cli-report.ts'
import type { AuditReport, Capability, TrustAckEntry } from '../../src/core/types.ts'

const baseReport = (over: Partial<AuditReport> = {}): AuditReport => ({
  name: 'demo',
  version: '1.0.0',
  spec: 'npm:demo@1.0.0',
  capabilities: [],
  evidence: [],
  destinations: [],
  pathEscapes: [],
  secretTouches: [],
  injections: [],
  injectedTokensEstimate: 0,
  hasBuildScript: false,
  buildScripts: [],
  prepareScripts: [],
  repository: 'https://github.com/x/y',
  pinned: true,
  score: 100,
  band: 'green',
  redLines: [],
  deductions: [],
  summary: 'ok',
  ...over,
})

describe('resolveCliLang', () => {
  it('prefers --lang, then treats non-English locales as zh (product default)', () => {
    expect(resolveCliLang({ langFlag: 'en', envLang: 'zh_CN.UTF-8' })).toBe('en')
    expect(resolveCliLang({ langFlag: undefined, envLang: 'en_US.UTF-8' })).toBe('en')
    expect(resolveCliLang({ langFlag: undefined, envLang: 'C.UTF-8' })).toBe('zh')
    expect(resolveCliLang({ langFlag: undefined, envLang: 'zh_CN.UTF-8' })).toBe('zh')
  })
})

describe('resolveCliColor', () => {
  it('is off when not a TTY, when NO_COLOR is set, or when --no-color', () => {
    expect(resolveCliColor({ tty: true, noColor: undefined, colorFlag: undefined })).toBe(true)
    expect(resolveCliColor({ tty: false, noColor: undefined, colorFlag: undefined })).toBe(false)
    expect(resolveCliColor({ tty: true, noColor: '1', colorFlag: undefined })).toBe(false)
    expect(resolveCliColor({ tty: true, noColor: undefined, colorFlag: false })).toBe(false)
    expect(resolveCliColor({ tty: false, noColor: undefined, colorFlag: true })).toBe(true)
    expect(resolveCliColor({ tty: true, noColor: '', colorFlag: undefined })).toBe(false)
  })
})

const ANSI_RE = /\u001B\[[0-9;]*m/g

function cellWidth(code: number): number {
  if (code <= 0xff || code === 0x2026 || code === 0x2022) return 1
  if (code >= 0x2500 && code <= 0x259f) return 1
  return 2
}

function visibleWidth(s: string): number {
  let width = 0
  for (const ch of s.replace(ANSI_RE, '')) {
    width += cellWidth(ch.codePointAt(0) ?? 0)
  }
  return width
}

function boxLineWidths(text: string): number[] {
  return text.split('\n')
    .filter(line => /^[╭╰├│]/.test(line.replace(ANSI_RE, '')))
    .map(visibleWidth)
}

describe('wrapVisible', () => {
  it('does not treat leading indent as a wrap point', () => {
    const zh = ' 未见硬红线；若这些能力符合你装它的目的，可在设置页记为预期。'
    const lines = wrapVisible(zh, 40)
    expect(lines.every(line => visibleWidth(line) <= 40)).toBe(true)
    expect(lines.some(line => line.trim() === '')).toBe(false)
    expect(lines.join('')).toContain('记为预期')
  })

  it('keeps indented evidence on wrap instead of flushing the indent as its own line', () => {
    const path = `      ${'/aaaa'.repeat(20)}`
    const lines = wrapVisible(path, 36)
    expect(lines[0]?.trim()).not.toBe('')
    expect(lines.every(line => visibleWidth(line) <= 36)).toBe(true)
  })
})

describe('formatHumanReport', () => {
  it('prints a Chinese compact overview and one-liners for expected/clear', () => {
    const review = baseReport({
      name: 'needs-look',
      capabilities: ['shell'] as Capability[],
      evidence: [{ capability: 'shell', file: 'index.js', line: 3, snippet: "exec('id')" }],
      score: 70,
      band: 'yellow',
    })
    const expected = baseReport({
      name: 'known-ok',
      capabilities: ['fs-read'] as Capability[],
      evidence: [{ capability: 'fs-read', file: 'a.js', line: 1, snippet: "readFile('x')" }],
      ackFingerprint: 'match-ok',
    })
    const clear = baseReport({ name: 'quiet' })
    const ack: Record<string, TrustAckEntry> = {
      'known-ok': {
        at: '2026-10-01T00:00:00.000Z',
        digest: 'match-ok',
        capabilities: ['fs-read'],
        destinations: [],
        secretTouches: [],
        pathEscapes: [],
        injections: [],
      },
    }
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [review, expected, clear],
      errors: [],
      acks: ack,
      lang: 'zh',
      verbose: false,
      dirMode: false,
    })
    expect(text).toContain('3 个插件')
    expect(text).toContain('需确认')
    expect(text).toMatch(/needs-look/)
    expect(text).toMatch(/╭/)
    expect(text).toMatch(/│/)
    expect(text).toMatch(/╰/)
    expect(text).toContain('为什么要小心')
    expect(text).toContain('会执行系统命令')
    expect(text).toContain('index.js:3')
    expect(text).toMatch(/known-ok 1\.0\.0\s+能力如预期/)
    expect(text).toMatch(/quiet 1\.0\.0\s+未检出项目/)
    expect(text).not.toMatch(/quiet[\s\S]*能力/)
    // Quiet plugins stay outside boxes
    expect(text).not.toMatch(/╭[^\n]*quiet/)
  })

  it('marks drifted ack as 需重新确认 and shows capability delta', () => {
    const report = baseReport({
      name: 'drifted',
      capabilities: ['shell', 'network'] as Capability[],
      evidence: [
        { capability: 'shell', file: 'a.js', line: 1, snippet: 'spawn(x)' },
        { capability: 'network', file: 'b.js', line: 2, snippet: 'fetch(u)' },
      ],
      ackFingerprint: 'fresh',
    })
    const ack: TrustAckEntry = {
      at: '2026-10-01T00:00:00.000Z',
      digest: 'stale',
      capabilities: ['network', 'env'],
      destinations: [],
      secretTouches: [],
      pathEscapes: [],
      injections: [],
    }
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      acks: { drifted: ack },
      lang: 'zh',
      verbose: false,
      dirMode: false,
    })
    expect(text).toContain('需重新确认')
    expect(text).toContain('+shell')
    expect(text).toContain('−env')
  })

  it('uses pre-install action copy in --dir mode, not Settings', () => {
    const report = baseReport({
      name: 'pkg',
      capabilities: ['shell'] as Capability[],
      evidence: [{ capability: 'shell', file: 'i.js', line: 1, snippet: 'exec(1)' }],
    })
    const text = formatHumanReport({
      contextLabel: 'dir: /tmp/pkg',
      plugins: [report],
      errors: [],
      lang: 'en',
      verbose: false,
      dirMode: true,
    })
    expect(text.toLowerCase()).not.toContain('settings')
    expect(text.toLowerCase()).toMatch(/before install|review these facts/)
  })

  it('adds ANSI hierarchy when color is on, and stays plain when off', () => {
    const report = baseReport({
      name: 'needs-look',
      capabilities: ['shell'] as Capability[],
      evidence: [{ capability: 'shell', file: 'index.js', line: 3, snippet: "exec('id')" }],
    })
    const plain = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'zh',
      verbose: false,
      dirMode: false,
      color: false,
    })
    const color = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'zh',
      verbose: false,
      dirMode: false,
      color: true,
    })
    expect(plain).not.toMatch(/\x1b\[/)
    expect(color).toMatch(/\x1b\[/)
    expect(color).toContain('需确认')
    expect(color.replace(/\x1b\[[0-9;]*m/g, '')).toMatch(/needs-look\s+1\.0\.0/)
  })

  it('expands expected plugins when verbose', () => {
    const report = baseReport({
      name: 'known-ok',
      capabilities: ['fs-read'] as Capability[],
      evidence: [{ capability: 'fs-read', file: 'a.js', line: 1, snippet: 'readFile' }],
      destinations: [{ kind: 'https-host', value: 'example.com', file: 'a.js', line: 2 }],
    })
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'en',
      verbose: true,
      dirMode: false,
    })
    expect(text).toMatch(/capabilities[\s\S]*fs-read/)
    expect(text).toContain('example.com')
  })

  it('keeps override injection detail and shape summaries in compact mode', () => {
    const report = baseReport({
      name: 'patched',
      redLines: [
        'runs code at install time (postinstall)',
        'uses plaintext http://',
        'reads credentials/secrets AND has network access',
      ],
      hasBuildScript: true,
      buildScripts: ['postinstall'],
      capabilities: ['credentials', 'network'] as Capability[],
      evidence: [
        { capability: 'credentials', file: 'c.js', line: 1, snippet: 'credentials.readRecord(id)' },
        { capability: 'network', file: 'n.js', line: 2, snippet: 'fetch(u)' },
      ],
      destinations: [{ kind: 'http-host', value: 'evil.example', file: 'n.js', line: 2 }],
      pathEscapes: [{ kind: 'absolute', value: '/etc/passwd', file: 'p.js', line: 3 }],
      secretTouches: [{ kind: 'env-key', value: 'AWS_SECRET_ACCESS_KEY', file: 's.js', line: 4 }],
      injections: [{ kind: 'override', detail: 'overrides bundle @deepseek-ai/dsh-core', bytes: 0 }],
      score: 0,
      band: 'red',
    })
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'en',
      verbose: false,
      dirMode: false,
    })
    expect(text).toMatch(/override\s+@deepseek-ai\/dsh-core/)
    expect(text).toMatch(/path escapes[\s\S]*\/etc\/passwd/)
    expect(text).toMatch(/secret touches[\s\S]*AWS_SECRET_ACCESS_KEY/)
    expect(text).toContain('postinstall')
    expect(text).toContain('evil.example')
  })

  it('keeps card borders aligned for a Chinese review at a mid-width terminal', () => {
    const report = baseReport({
      name: 'needs-look',
      capabilities: ['shell'] as Capability[],
      evidence: [{ capability: 'shell', file: 'index.js', line: 3, snippet: "exec('id')" }],
    })
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'zh',
      verbose: false,
      dirMode: false,
      columns: 60,
    })
    const widths = boxLineWidths(text)
    expect(widths.length).toBeGreaterThan(4)
    expect(new Set(widths).size).toBe(1)
    expect(widths[0]).toBeLessThanOrEqual(60)
    expect(text).toMatch(/记为/)
    expect(text).toMatch(/预期/)
  })

  it('sizes the card to a narrow terminal instead of a 56-column floor', () => {
    const report = baseReport({
      name: 'needs-look',
      capabilities: ['shell'] as Capability[],
      evidence: [{ capability: 'shell', file: 'index.js', line: 3, snippet: "exec('id')" }],
    })
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'zh',
      verbose: false,
      dirMode: false,
      columns: 40,
    })
    const widths = boxLineWidths(text)
    expect(widths[0]).toBeLessThanOrEqual(40)
    expect(new Set(widths).size).toBe(1)
  })

  it('caps compact injection details at three even when many are overrides', () => {
    const report = baseReport({
      name: 'patched',
      redLines: ['tampers with a core bundle'],
      injections: [1, 2, 3, 4].map(n => ({
        kind: 'override' as const,
        detail: `overrides bundle @deepseek-ai/core-${n}`,
        bytes: 0,
      })),
      score: 0,
      band: 'red',
    })
    const text = formatHumanReport({
      contextLabel: 'profile: web',
      plugins: [report],
      errors: [],
      lang: 'en',
      verbose: false,
      dirMode: false,
    })
    expect(text).toContain('@deepseek-ai/core-1')
    expect(text).toContain('@deepseek-ai/core-3')
    expect(text).not.toContain('@deepseek-ai/core-4')
    expect(text).toMatch(/and 1 more/)
  })
})

describe('concernEvidenceLines', () => {
  it('maps red-line concerns to destinations, scripts, and credential evidence', () => {
    const report = baseReport({
      hasBuildScript: true,
      buildScripts: ['postinstall'],
      redLines: [
        'runs code at install time (postinstall)',
        'uses plaintext http://',
        'uses literal IP',
        'reads credentials/secrets AND has network access',
      ],
      destinations: [
        { kind: 'http-host', value: 'plain.example', file: 'a.js', line: 1 },
        { kind: 'ip', value: '203.0.113.9', file: 'b.js', line: 2 },
      ],
      evidence: [
        { capability: 'credentials', file: 'c.js', line: 3, snippet: 'credentials.resolve(k)' },
        { capability: 'network', file: 'n.js', line: 4, snippet: 'fetch(u)' },
      ],
      capabilities: ['credentials', 'network'] as Capability[],
    })
    expect(concernEvidenceLines(report, { code: 'install-script' }).join('\n')).toContain('postinstall')
    expect(concernEvidenceLines(report, { code: 'plaintext-http' }).join('\n')).toContain('plain.example')
    expect(concernEvidenceLines(report, { code: 'literal-ip' }).join('\n')).toContain('203.0.113.9')
    expect(concernEvidenceLines(report, { code: 'creds-network' }).join('\n')).toMatch(/c\.js:3/)
  })
})
