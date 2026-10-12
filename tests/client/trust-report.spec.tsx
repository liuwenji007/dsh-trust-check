/** @vitest-environment jsdom */
import { readFileSync } from 'node:fs'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TrustReport } from '../../src/client/TrustReport.tsx'
import { en, zh, type TrustKey } from '../../src/client/locales.ts'
import type { AuditReport, AuditResponse, Capability, TrustAckEntry } from '../../src/core/types.ts'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
  Element.prototype.scrollIntoView = vi.fn()
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function plugin(patch: Partial<AuditReport> = {}): AuditReport {
  return {
    name: 'demo-plugin',
    version: '1.2.3',
    spec: 'npm:demo-plugin@1.2.3',
    capabilities: ['network', 'shell'] as Capability[],
    evidence: [
      { capability: 'network', file: 'lib/index.js', line: 4, snippet: 'fetch("https://example.test")', rule: 'network.fetch' },
      { capability: 'shell', file: 'lib/index.js', line: 8, snippet: 'execFile("ls")', rule: 'shell.execFile' },
    ],
    destinations: [],
    pathEscapes: [],
    secretTouches: [],
    injections: [],
    injectedTokensEstimate: 0,
    hasBuildScript: false,
    buildScripts: [],
    repository: 'https://github.com/example/demo-plugin',
    pinned: true,
    score: 40,
    band: 'yellow',
    redLines: [],
    deductions: [],
    summary: 'review',
    ackFingerprint: 'fp-1',
    ...patch,
  }
}

function response(plugins: AuditReport[], extra: Partial<AuditResponse> = {}): AuditResponse {
  return {
    schemaVersion: 2,
    profile: 'web',
    generatedAt: '2026-10-10T00:00:00.000Z',
    plugins,
    errors: [],
    ...extra,
  }
}

function renderReport(report: AuditResponse | null, dictionary: Record<TrustKey, string> = zh) {
  const state = { report, fetchedAt: report === null ? null : 1_700_000_000_000 }
  const setReport = vi.fn((next: AuditResponse, at: number) => {
    state.report = next
    state.fetchedAt = at
  })
  const view = render(
    <TrustReport
      useStore={selector => selector(state)}
      actions={{ setReport }}
      t={key => dictionary[key]}
    />,
  )
  return { ...view, setReport, state }
}

describe('settings card reading order', () => {
  it('shows findings, detail, evidence, folded limits, then acknowledgment on a first scan', async () => {
    const user = userEvent.setup()
    renderReport(response([plugin({
      coverageNotes: ['dynamic import target in lib/index.js', 'computed module name in lib/index.js'],
    })]))

    expect(screen.queryByText(zh['drift.title'])).toBeNull()
    expect(screen.getByText(zh['postInstall.note']).closest('details')).toBeNull()
    const limitsFold = screen.getByText(zh['coverage.title']).closest('details') as HTMLDetailsElement
    expect(limitsFold.open).toBe(false)
    expect(screen.getByText('2 项需要留意')).toBeTruthy()
    await user.click(screen.getByText(zh['coverage.title']))
    expect(limitsFold.open).toBe(true)
    expect(screen.getByText('dynamic import target in lib/index.js')).toBeTruthy()
    expect(screen.getByText('computed module name in lib/index.js')).toBeTruthy()
    expect(screen.getByText(zh['coverage.plain'])).toBeTruthy()

    const decision = screen.getByRole('heading', { name: zh['decision.review'] })
    const findings = screen.getByText(/未见硬红线/)
    const caps = screen.getByRole('heading', { name: zh.capabilities })
    const evidence = screen.getAllByRole('button', { name: new RegExp(zh['feedback.evidence']) })[0] as HTMLElement
    const limits = screen.getByText(zh['coverage.title'])
    const accept = screen.getByRole('button', { name: zh['ack.accept'] })
    const aid = screen.getByRole('button', { name: zh['explain.button'] })
    const ack = screen.getByText(zh['ack.scope'])
    const follows = (earlier: Element, later: Element) =>
      (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
    expect(follows(decision, findings)).toBe(true)
    expect(follows(findings, caps)).toBe(true)
    expect(follows(caps, evidence)).toBe(true)
    expect(follows(evidence, limits)).toBe(true)
    expect(follows(limits, accept)).toBe(true)
    expect(follows(accept, aid)).toBe(true)
    expect(follows(aid, ack)).toBe(true)
    expect(screen.getByRole('button', { name: zh['ack.accept'] })).toBeTruthy()
    expect(screen.queryByRole('button', { name: zh['ack.acceptRisk'] })).toBeNull()
  })

  it('asks for the AI reading from the acknowledgment bar and shows it under the findings', async () => {
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe('/dsh-trust-check/explain')
      expect(JSON.parse(String(init?.body)).name).toBe('demo-plugin')
      return { status: 200, ok: true, json: async () => ({ text: '它会调用 ls。' }) }
    })
    renderReport(response([plugin()]))
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()

    await user.click(screen.getByRole('button', { name: zh['explain.button'] }))

    const panel = await screen.findByRole('region', { name: zh['explain.title'] })
    expect(panel.textContent).toContain('它会调用 ls。')
    expect(panel.textContent).toContain(zh['explain.disclaimer'])
    const follows = (earlier: Element, later: Element) =>
      (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
    expect(follows(screen.getByRole('heading', { name: zh['decision.review'] }), panel)).toBe(true)
    expect(follows(panel, screen.getByRole('heading', { name: zh.capabilities }))).toBe(true)
    expect(screen.getByRole('button', { name: zh['ack.accept'] })).toBeTruthy()
    await waitFor(() => expect(document.activeElement).toBe(panel))

    panel.blur()
    await user.click(screen.getByRole('button', { name: zh['explain.view'] }))
    expect(document.activeElement).toBe(panel)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('keeps the AI reading across reloads until the version or findings change', async () => {
    const user = userEvent.setup()
    let reply = '第一次解读。'
    fetchMock.mockImplementation(async () => ({ status: 200, ok: true, json: async () => ({ text: reply }) }))
    const first = renderReport(response([plugin()]))
    await user.click(screen.getByRole('button', { name: zh['explain.button'] }))
    expect((await screen.findByRole('region', { name: zh['explain.title'] })).textContent).toContain('第一次解读。')
    first.unmount()

    const second = renderReport(response([plugin()]))
    const panel = screen.getByRole('region', { name: zh['explain.title'] })
    expect(panel.textContent).toContain('第一次解读。')
    expect(panel.textContent).toMatch(/生成于 \d{2}:\d{2}/)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    reply = '重新生成的解读。'
    await user.click(screen.getByRole('button', { name: zh['explain.regenerate'] }))
    await waitFor(() => expect(panel.textContent).toContain('重新生成的解读。'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
    second.unmount()

    renderReport(response([plugin({ ackFingerprint: 'fp-2' })]))
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()
    expect(screen.getByRole('button', { name: zh['explain.button'] })).toBeTruthy()
    cleanup()

    renderReport(response([plugin({ version: '1.2.4' })]))
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()
  })

  it('says so when the AI reading was cut off', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue({ status: 200, ok: true, json: async () => ({ text: '可能属于本职的：三段', truncated: true }) })
    renderReport(response([plugin()]))
    await user.click(screen.getByRole('button', { name: zh['explain.button'] }))
    const panel = await screen.findByRole('region', { name: zh['explain.title'] })
    expect(panel.textContent).toContain(zh['explain.truncated'])
    cleanup()

    fetchMock.mockResolvedValue({ status: 200, ok: true, json: async () => ({ text: '完整。', truncated: false }) })
    renderReport(response([plugin()]))
    expect(screen.getByRole('region', { name: zh['explain.title'] }).textContent).toContain(zh['explain.truncated'])
    await user.click(screen.getByRole('button', { name: zh['explain.regenerate'] }))
    await waitFor(() => expect(screen.getByRole('region', { name: zh['explain.title'] }).textContent).toContain('完整。'))
    expect(screen.getByRole('region', { name: zh['explain.title'] }).textContent).not.toContain(zh['explain.truncated'])
  })

  it('forgets AI readings for plugins that left the report', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue({ status: 200, ok: true, json: async () => ({ text: '解读。' }) })
    const first = renderReport(response([plugin()]))
    await user.click(screen.getByRole('button', { name: zh['explain.button'] }))
    await screen.findByRole('region', { name: zh['explain.title'] })
    first.unmount()

    const other = renderReport(response([plugin({ name: 'other-plugin', spec: 'npm:other-plugin@1.2.3' })]))
    other.unmount()
    renderReport(response([plugin()]))
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()
  })

  it('ignores a corrupted AI reading cache', () => {
    localStorage.setItem('dsh.trust-check.explain.v1', '{not json')
    renderReport(response([plugin()]))
    expect(screen.getByRole('button', { name: zh['explain.button'] })).toBeTruthy()
    localStorage.setItem('dsh.trust-check.explain.v1', JSON.stringify({ 'demo-plugin': { key: 1, text: [] } }))
    cleanup()
    renderReport(response([plugin()]))
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()
  })

  it('reports an unavailable AI reading next to the button', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue({ status: 503, ok: false, json: async () => ({}) })
    renderReport(response([plugin()]))
    await user.click(screen.getByRole('button', { name: zh['explain.button'] }))
    expect(await screen.findByText(zh['explain.error'])).toBeTruthy()
    expect(screen.queryByRole('region', { name: zh['explain.title'] })).toBeNull()
  })

  it('hides the change note when the acknowledgment still matches', async () => {
    const user = userEvent.setup()
    const row = plugin()
    const ack: TrustAckEntry = {
      capabilities: ['network', 'shell'],
      destinations: [],
      secretTouches: [],
      digest: 'fp-1',
      at: '2026-10-01T00:00:00.000Z',
    }
    renderReport(response([row], { acks: { [row.name]: ack } }))
    await user.click(screen.getByRole('button', { name: /展开插件详情/ }))
    expect(screen.queryByText(zh['drift.title'])).toBeNull()
    expect(screen.getByRole('button', { name: zh['ack.revoke'] })).toBeTruthy()
  })

  it('shows the capability delta against the last acknowledgment, including a possible rule update', () => {
    const row = plugin({ capabilities: ['network', 'shell', 'env'] })
    const ack = {
      capabilities: ['network', 'fs-read'],
      destinations: [],
      secretTouches: [],
      digest: 'older',
      at: '2026-10-01T00:00:00.000Z',
    } as TrustAckEntry
    renderReport(response([row], { acks: { [row.name]: ack } }))
    expect(screen.getByText(zh['drift.title'])).toBeTruthy()
    const addedRow = screen.getByText(zh['drift.added']).parentElement
    const removedRow = screen.getByText(zh['drift.removed']).parentElement
    expect(addedRow?.textContent).toContain(zh['cap.shell'])
    expect(addedRow?.textContent).toContain(zh['cap.env'])
    expect(addedRow?.textContent).not.toContain(zh['cap.network'])
    expect(removedRow?.textContent).toContain(zh['cap.fs-read'])
    expect(screen.getByText(zh['drift.ruleNote'])).toBeTruthy()
    expect(screen.getByRole('button', { name: `${zh['cap.shell']} · ${zh['capabilities.new']}` })).toBeTruthy()
    expect(screen.queryByRole('button', { name: new RegExp(`${zh['cap.network']}.*${zh['capabilities.new']}`) })).toBeNull()
  })

  it('names the install channel without a local path and opens all evidence from the acknowledgment bar', async () => {
    const user = userEvent.setup()
    renderReport(response([plugin({ spec: 'link:/Users/hidden/dev/demo-plugin', pinned: false })]))
    const toggle = screen.getByRole('button', { expanded: true })
    expect(toggle.textContent).toContain('来源：link · 未锁版本')
    expect(toggle.textContent).not.toContain('/Users/hidden')

    const group = (cap: string) => document.getElementById(`trust-evidence-demo-plugin-${cap}`)
    expect(group('shell')?.textContent).toContain('execFile("ls")')
    expect(group('network')).toBeNull()
    await user.click(screen.getByRole('button', { name: zh['ack.viewEvidence'] }))
    expect(group('network')?.textContent).toContain('fetch("https://example.test")')
    expect(group('shell')).toBeTruthy()
    expect(document.activeElement).toBe(document.getElementById('trust-evidence-demo-plugin'))

    const chip = (cap: string) => document.querySelector(`[aria-controls="trust-evidence-demo-plugin-${cap}"]`)
    expect(chip('shell')?.className).toContain('tier-high')
    expect(chip('network')?.className ?? '').not.toMatch(/tier-(high|medium)/)
  })

  it('asks for a fact review on a red line and keeps risk confirmation distinct', () => {
    renderReport(response([plugin({
      redLines: ['runs code at install time (install)'],
      hasBuildScript: true,
      buildScripts: ['install'],
    })]))
    expect(screen.getByText(/请先复核具体事实/)).toBeTruthy()
    expect(screen.queryByText(/默认应停用/)).toBeNull()
    expect(screen.getByRole('heading', { name: zh['decision.red'] })).toBeTruthy()
    const concernsList = screen.getByRole('list', { name: zh['concerns.title'] })
    const [first, second] = [...concernsList.querySelectorAll('li')]
    expect(first?.className).toContain('concernRed')
    expect(second?.className ?? '').not.toContain('concernRed')
    expect(screen.getByRole('button', { name: zh['ack.acceptRisk'] })).toBeTruthy()
    expect(screen.queryByRole('button', { name: zh['ack.accept'] })).toBeNull()
  })

  it('keeps an old cached report readable when notes, rule ids, and context are absent', () => {
    const row = plugin({
      evidence: [{ capability: 'shell', file: 'old.js', line: 1, snippet: 'spawn("x")' }],
      capabilities: ['shell'],
    })
    delete row.coverageNotes
    renderReport(response([row]))
    expect(screen.queryByText(zh['coverage.title'])).toBeNull()
    expect(screen.getByText('spawn("x")')).toBeTruthy()
  })

  it('shows the chosen capability evidence right under the chips, keeping focus on the chip', async () => {
    const user = userEvent.setup()
    renderReport(response([plugin()]))
    const chip = screen.getByRole('button', { name: '网络 · 同源' })
    expect(chip.getAttribute('aria-pressed')).toBe('false')
    expect(document.getElementById('trust-evidence-demo-plugin-network')).toBeNull()
    chip.focus()
    await user.keyboard('{Enter}')
    const group = document.getElementById('trust-evidence-demo-plugin-network')
    expect(group?.textContent).toContain('fetch("https://example.test")')
    expect(chip.getAttribute('aria-pressed')).toBe('true')
    expect(document.getElementById('trust-evidence-demo-plugin-shell')).toBeNull()
    const chips = chip.parentElement as HTMLElement
    expect(chips.compareDocumentPosition(group as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(document.activeElement).toBe(chip)
    await waitFor(() => {
      expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({ behavior: 'auto', block: 'nearest' })
    })
  })

  it('switches to every group from the chip row and folds long evidence back', async () => {
    const user = userEvent.setup()
    const shellRows = Array.from({ length: 5 }, (_, i) => ({
      capability: 'shell' as Capability,
      file: 'lib/run.js',
      line: 10 + i,
      snippet: `execFile("step-${i}")`,
      rule: 'shell.execFile',
    }))
    renderReport(response([plugin({
      evidence: [
        { capability: 'network', file: 'lib/index.js', line: 4, snippet: 'fetch("https://example.test")', rule: 'network.fetch' },
        ...shellRows,
      ],
    })]))
    const group = (cap: string) => document.getElementById(`trust-evidence-demo-plugin-${cap}`)
    expect(group('shell')?.querySelectorAll('li')).toHaveLength(3)
    expect(group('network')).toBeNull()

    const more = screen.getByRole('button', { name: zh['evidence.showRest'].replace('{count}', '2') })
    await user.click(more)
    expect(group('shell')?.querySelectorAll('li')).toHaveLength(5)
    expect(more.textContent).toBe(zh['evidence.collapse'])
    expect(more.getAttribute('aria-expanded')).toBe('true')
    const scrollName = zh['evidence.scrollRegion'].replace('{cap}', zh['cap.shell'])
    expect(screen.getByRole('region', { name: scrollName }).querySelectorAll('li')).toHaveLength(5)
    await user.click(more)
    expect(group('shell')?.querySelectorAll('li')).toHaveLength(3)
    expect(screen.queryByRole('region', { name: scrollName })).toBeNull()
    expect(document.activeElement).toBe(more)

    const all = screen.getByRole('button', { name: zh['evidence.all'] })
    await user.click(all)
    expect(all.getAttribute('aria-pressed')).toBe('true')
    expect(group('network')).toBeTruthy()
    expect(group('shell')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: '网络 · 同源' }))
    expect(all.getAttribute('aria-pressed')).toBe('false')
    expect(group('shell')).toBeNull()
  })

  it('rejects a stale acknowledgment with the existing fingerprint check', async () => {
    const user = userEvent.setup()
    const row = plugin({
      redLines: ['runs code at install time (install)'],
      ackFingerprint: 'old-fp',
    })
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe('/dsh-trust-check/ack')
      expect(init?.method).toBe('POST')
      expect(JSON.parse(String(init?.body))).toEqual({
        name: 'demo-plugin',
        acceptRisk: true,
        fingerprint: 'old-fp',
      })
      return {
        status: 409,
        ok: false,
        json: async () => ({ report: { ...row, ackFingerprint: 'new-fp' } }),
      }
    })
    const { setReport } = renderReport(response([row]))
    await user.click(screen.getByRole('button', { name: zh['ack.acceptRisk'] }))
    expect(await screen.findByText(zh['ack.stale'])).toBeTruthy()
    expect(setReport).toHaveBeenCalledTimes(1)
    const next = setReport.mock.calls[0]?.[0] as AuditResponse
    expect(next.plugins[0]?.ackFingerprint).toBe('new-fp')
    expect(row.ackFingerprint).toBe('old-fp')
  })

  it('after recording, folds only that card and returns focus to its header without opening the next one', async () => {
    const user = userEvent.setup()
    const first = plugin({ name: 'first-plugin' })
    const second = plugin({ name: 'second-plugin' })
    const ack: TrustAckEntry = {
      capabilities: ['network', 'shell'],
      destinations: [],
      secretTouches: [],
      digest: 'fp-1',
      at: '2026-10-11T00:00:00.000Z',
    }
    let finishAudit = () => {}
    const auditDone = new Promise<void>(resolve => { finishAudit = resolve })
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === '/dsh-trust-check/ack') return { status: 200, ok: true, json: async () => ({}) }
      await auditDone
      return { status: 200, ok: true, json: async () => response([first, second], { acks: { [first.name]: ack } }) }
    })
    renderReport(response([first, second]))
    const header = (name: string) =>
      document.querySelector<HTMLElement>(`[data-plugin="${name}"] [aria-expanded]`)
    expect(header('first-plugin')?.getAttribute('aria-expanded')).toBe('true')
    expect(header('second-plugin')?.getAttribute('aria-expanded')).toBe('false')

    await user.click(screen.getByRole('button', { name: zh['ack.accept'] }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/dsh-trust-check/audit'))
    const saving = screen.getByRole('button', { name: zh['ack.saving'] }) as HTMLButtonElement
    expect(saving.disabled).toBe(true)
    expect(header('first-plugin')?.getAttribute('aria-expanded')).toBe('true')
    finishAudit()

    await waitFor(() => expect(header('first-plugin')?.getAttribute('aria-expanded')).toBe('false'))
    expect(header('second-plugin')?.getAttribute('aria-expanded')).toBe('false')
    expect(header('first-plugin')?.textContent).toContain(zh['verdict.expected'])
    expect(document.activeElement).toBe(header('first-plugin'))

    const card = document.querySelector<HTMLElement>('[data-plugin="first-plugin"]')
    expect(card?.className).toContain('pluginSettled')
    expect(card?.className).not.toContain('pluginOpen')
    for (const type of ['animationend', 'webkitAnimationEnd']) {
      fireEvent(card as HTMLElement, new Event(type, { bubbles: true }))
    }
    expect(card?.className).not.toContain('pluginSettled')
  })

  it('marks the open card as the current one', async () => {
    const user = userEvent.setup()
    renderReport(response([plugin({ name: 'first-plugin' }), plugin({ name: 'second-plugin' })]))
    const card = (name: string) => document.querySelector<HTMLElement>(`[data-plugin="${name}"]`)
    expect(card('first-plugin')?.className).toContain('pluginOpen')
    expect(card('second-plugin')?.className).not.toContain('pluginOpen')
    await user.click(card('second-plugin')?.querySelector('[aria-expanded]') as HTMLElement)
    expect(card('second-plugin')?.className).toContain('pluginOpen')
  })

  it('shows a partial failure beside plugins, and does not offer the install-empty state when every plugin failed', () => {
    const { unmount } = renderReport(response([plugin()], {
      errors: [{ name: 'broken-one', spec: 'npm:broken-one', message: 'unreadable' }],
    }))
    expect(screen.getByText('demo-plugin')).toBeTruthy()
    expect(screen.getByText(/broken-one: unreadable/)).toBeTruthy()
    expect(screen.queryByText(zh.empty)).toBeNull()
    unmount()

    renderReport(response([], {
      errors: [{ name: 'broken-all', spec: 'npm:broken-all', message: 'missing' }],
    }))
    expect(screen.getByText(/broken-all: missing/)).toBeTruthy()
    expect(screen.queryByText(zh.empty)).toBeNull()
    expect(screen.queryByText(zh.loadError)).toBeNull()
  })

  it('shows a failed scan without the install-empty state', async () => {
    fetchMock.mockRejectedValue(new Error('offline'))
    renderReport(null)
    expect(await screen.findByText(zh.loadError)).toBeTruthy()
    expect(screen.queryByText(zh.empty)).toBeNull()
  })

  it('does not repeat what the chips, header, and fold title already say', () => {
    const server = { runtime: ['server' as const] }
    renderReport(response([plugin({
      capabilities: ['shell', 'network'] as Capability[],
      evidence: [
        { capability: 'shell', file: 'lib/a.js', line: 1, snippet: 'spawn("a")', rule: 'shell.spawn', context: server },
        { capability: 'shell', file: 'lib/b.js', line: 2, snippet: 'spawn("b")', rule: 'shell.spawn', context: server },
        { capability: 'network', file: 'lib/c.js', line: 3, snippet: 'fetch(u)', rule: 'network.fetch', context: server },
        { capability: 'network', file: 'client/d.js', line: 4, snippet: 'fetch(v)', rule: 'network.fetch', context: { runtime: ['client'] } },
      ],
      destinations: [
        { kind: 'https-host', value: 'api.example.test', file: 'lib/c.js', line: 3 },
        { kind: 'http-host', value: 'plain.example.test', file: 'lib/c.js', line: 9 },
        { kind: 'https-host', value: 'registry.npmjs.org', file: 'lib/u.js', line: 1 },
      ],
    })]))

    expect(screen.queryByRole('list', { name: zh['concerns.title'] })?.textContent ?? '').not.toContain(zh['concern.shell'])
    expect(screen.getByRole('button', { name: `${zh['cap.shell']}` })).toBeTruthy()
    expect(document.body.textContent).not.toContain(zh['context.runtimeOnly.server'])

    const group = (cap: string) => document.getElementById(`trust-evidence-demo-plugin-${cap}`) as HTMLElement
    expect(group('shell').textContent).toContain(`${zh['evidence.rule']} shell.spawn`)
    const ruleName = screen.getByText('shell.spawn')
    const tip = document.getElementById(ruleName.getAttribute('aria-describedby') ?? '')
    expect(tip?.getAttribute('role')).toBe('tooltip')
    expect(tip?.textContent).toContain(zh['rule.unknown'])
    expect(tip?.textContent).toContain(zh['rule.idNote'])
    expect(group('shell').querySelectorAll('li [class*="evidenceRule"]')).toHaveLength(0)
    expect(group('shell').textContent).not.toContain(zh['context.runtime.server'])

    const overview = document.querySelector('[class*="overview"]')?.textContent ?? ''
    expect(overview).toContain(`1 ${zh['verdict.review']}`)
    expect(overview).not.toMatch(/(^|· )0 /)

    const destinations = screen.getByRole('heading', { name: zh.destinations }).closest('section') as HTMLElement
    expect(destinations.textContent).not.toContain(zh['destKind.https-host'])
    expect(destinations.textContent).toContain(zh['destinations.plaintext'])
    expect(destinations.textContent).not.toContain(zh['destKind.http-host'])
  })

  it('tags runtime per row only where a capability group is mixed', async () => {
    const user = userEvent.setup()
    renderReport(response([plugin({
      capabilities: ['network'] as Capability[],
      evidence: [
        { capability: 'network', file: 'lib/c.js', line: 3, snippet: 'fetch(u)', rule: 'network.fetch', context: { runtime: ['server'] } },
        { capability: 'network', file: 'client/d.js', line: 4, snippet: 'fetch(v)', rule: 'network.fetch', context: { runtime: ['client'] } },
      ],
    })]))
    await user.click(screen.getByRole('button', { name: /^网络/ }))
    const group = document.getElementById('trust-evidence-demo-plugin-network') as HTMLElement
    expect(group.textContent).toContain(zh['context.runtime.server'])
    expect(group.textContent).toContain(zh['context.runtime.client'])
  })

  it('uses the English finding wording and wraps long paths', () => {
    const longFile = `${'nested/'.repeat(20)}payload.js`
    renderReport(response([plugin({
      evidence: [{ capability: 'network', file: longFile, line: 2, snippet: 'fetch("https://example.test")' }],
      capabilities: ['network'],
      redLines: ['uses literal IP for egress: 1.2.3.4'],
    })]), en)
    expect(screen.getByText(/Review the specific facts/)).toBeTruthy()
    expect(screen.queryByText(/Stop by default/)).toBeNull()
    expect(screen.getByText(`${longFile}:2`)).toBeTruthy()
    const css = readFileSync('src/client/TrustReport.module.css', 'utf8')
    expect(css).toContain('overflow-wrap: anywhere')
  })
})
