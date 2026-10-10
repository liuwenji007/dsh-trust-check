/** @vitest-environment jsdom */
import { readFileSync } from 'node:fs'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TrustReport } from '../../src/client/TrustReport.tsx'
import { en, zh, type TrustKey } from '../../src/client/locales.ts'
import type { AuditReport, AuditResponse, Capability, TrustAckEntry } from '../../src/core/types.ts'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
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
    const evidence = screen.getAllByRole('button', { name: zh['feedback.evidence'] })[0] as HTMLElement
    const aid = screen.getByText(zh['explain.aid'])
    const limits = screen.getByText(zh['coverage.title'])
    const ack = screen.getByText(zh['ack.scope'])
    const follows = (earlier: Element, later: Element) =>
      (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
    expect(follows(decision, findings)).toBe(true)
    expect(follows(findings, caps)).toBe(true)
    expect(follows(caps, evidence)).toBe(true)
    expect(follows(evidence, aid)).toBe(true)
    expect(follows(aid, limits)).toBe(true)
    expect(follows(limits, ack)).toBe(true)
    expect(screen.getByRole('button', { name: zh['ack.accept'] })).toBeTruthy()
    expect(screen.queryByRole('button', { name: zh['ack.acceptRisk'] })).toBeNull()
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
