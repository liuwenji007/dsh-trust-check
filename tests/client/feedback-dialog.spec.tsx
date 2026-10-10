/** @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TrustReport } from '../../src/client/TrustReport.tsx'
import { zh, type TrustKey } from '../../src/client/locales.ts'
import { GITHUB_ADVISORY_URL, GITHUB_BLANK_ISSUE_URL, GITHUB_ISSUE_TEMPLATE } from '../../src/client/feedback-draft.ts'
import type { AuditReport, AuditResponse, Capability } from '../../src/core/types.ts'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  Element.prototype.scrollIntoView = vi.fn()
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
    capabilities: ['network'] as Capability[],
    evidence: [
      { capability: 'network', file: 'lib/index.js', line: 4, snippet: 'fetch("https://example.test")', rule: 'network.fetch' },
    ],
    destinations: [{ kind: 'https-host', value: 'example.test', file: 'lib/index.js', line: 4 }],
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

function response(row: AuditReport): AuditResponse {
  return {
    schemaVersion: 2,
    profile: 'secret-profile',
    dir: '/Users/hidden/plugins/demo-plugin',
    generatedAt: '2026-10-10T00:00:00.000Z',
    plugins: [row],
    errors: [{ name: 'broken', spec: 'npm:broken', message: 'SECRET_ERROR_TEXT' }],
  }
}

function renderReport(row: AuditReport = plugin()) {
  const state = { report: response(row), fetchedAt: 1_700_000_000_000 }
  const view = render(
    <TrustReport
      useStore={selector => selector(state)}
      actions={{ setReport: () => {} }}
      t={(key: TrustKey) => zh[key]}
    />,
  )
  return { ...view, state }
}

async function openEvidence(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByText(zh.evidence))
  await user.click(screen.getByRole('button', { name: zh['feedback.evidence'] }))
}

describe('detection feedback dialog', () => {
  it('requires a description, keeps edits, and returns to the form', async () => {
    const user = userEvent.setup()
    renderReport()
    await openEvidence(user)
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    expect(screen.getByRole('status').textContent).toContain(zh['feedback.note.required'])

    await user.type(screen.getByLabelText(zh['feedback.note']), '注释里的示例 URL')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    const body = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    expect(body.value).toContain('能力：network')
    expect(body.value).toContain('规则 ID：network.fetch')
    expect(body.value).toContain('注释里的示例 URL')
    expect(body.value).not.toContain('demo-plugin')
    expect(body.value).not.toContain('secret-profile')
    expect(body.value).not.toContain('SECRET_ERROR_TEXT')
    expect(body.value).not.toContain('/Users/hidden')
    expect(fetchMock).not.toHaveBeenCalled()

    await user.clear(body)
    await user.type(body, '改过的正文 & <tag>')
    await user.click(screen.getByRole('button', { name: zh['feedback.back'] }))
    expect((screen.getByLabelText(zh['feedback.note']) as HTMLTextAreaElement).value).toBe('注释里的示例 URL')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    expect((screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement).value).toBe('改过的正文 & <tag>')
  })

  it('keeps a redacted preview when the form is unchanged', async () => {
    const user = userEvent.setup()
    renderReport()
    await openEvidence(user)
    await user.click(screen.getByLabelText(zh['feedback.attach.path']))
    await user.type(screen.getByLabelText(zh['feedback.note']), '注释里有内部域名')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    const body = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    expect(body.value).toContain('example.test')
    expect(body.value).toContain('fetch("https://example.test")')

    const title = screen.getByLabelText(zh['feedback.titleField']) as HTMLInputElement
    await user.clear(title)
    await user.type(title, '脱敏后的标题')
    await user.clear(body)
    await user.type(body, '已删除内部域名，只保留脱敏说明')
    await user.click(screen.getByRole('button', { name: zh['feedback.back'] }))
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))

    const keptBody = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    const keptTitle = screen.getByLabelText(zh['feedback.titleField']) as HTMLInputElement
    expect(keptTitle.value).toBe('脱敏后的标题')
    expect(keptBody.value).toBe('已删除内部域名，只保留脱敏说明')
    const link = screen.getByRole('link', { name: zh['feedback.github'] })
    const url = new URL(link.getAttribute('href') ?? '')
    expect(url.searchParams.get('title')).toBe('脱敏后的标题')
    expect(url.searchParams.get('body')).toBe('已删除内部域名，只保留脱敏说明')
    expect(url.searchParams.get('body')).not.toContain('example.test')

    await user.click(screen.getByRole('button', { name: zh['feedback.back'] }))
    await user.type(screen.getByLabelText(zh['feedback.note']), '补充')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    const refreshed = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    expect(refreshed.value).toContain('注释里有内部域名补充')
    expect(refreshed.value).toContain('example.test')
  })

  it('freezes the finding from the moment the dialog opened', async () => {
    const user = userEvent.setup()
    const { state, rerender } = renderReport()
    await openEvidence(user)
    state.report = response(plugin({
      capabilities: ['shell'],
      evidence: [{ capability: 'shell', file: 'other.js', line: 1, snippet: 'spawn("x")', rule: 'shell.spawn' }],
    }))
    rerender(
      <TrustReport
        useStore={selector => selector(state)}
        actions={{ setReport: () => {} }}
        t={(key: TrustKey) => zh[key]}
      />,
    )
    await user.type(screen.getByLabelText(zh['feedback.note']), '仍然是打开时那条')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    const body = (screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement).value
    expect(body).toContain('能力：network')
    expect(body).toContain('规则 ID：network.fetch')
    expect(body).not.toContain('shell.spawn')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('asks before discarding, restores focus, and keeps the draft when copy fails', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    renderReport()
    const opener = screen.getByRole('button', { name: zh['feedback.general'] })
    await user.click(opener)
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    const dialog = screen.getByRole('dialog')
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(dialog.parentElement?.parentElement).toBe(document.body)
    expect(dialog.style.background).not.toBe('')
    expect(dialog.style.background).not.toMatch(/transparent|rgba\(0,\s*0,\s*0,\s*0\)/)
    expect(document.querySelector('[inert]')).not.toBeNull()
    const kindRadio = screen.getByRole('radio', { name: zh['feedback.kind.inaccurate'] }) as HTMLInputElement
    expect(kindRadio.name).not.toBe('feedback-kind')
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.querySelector('[inert]')).toBeNull()
    expect(document.activeElement).toBe(opener)

    await user.click(opener)
    await user.click(screen.getByLabelText(zh['feedback.kind.missed']))
    await user.type(screen.getByLabelText(zh['feedback.note']), '漏了一处调用')
    await user.keyboard('{Escape}')
    expect(screen.getByText(zh['feedback.discard.title'])).toBeTruthy()
    await user.click(screen.getByRole('button', { name: zh['feedback.discard.stay'] }))
    expect((screen.getByLabelText(zh['feedback.note']) as HTMLTextAreaElement).value).toBe('漏了一处调用')

    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    await user.click(screen.getByRole('button', { name: zh['feedback.copy'] }))
    expect(await screen.findByText(zh['feedback.copyFailed'])).toBeTruthy()
    const body = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    expect(body.value).toContain('漏了一处调用')
    expect(document.activeElement).toBe(body)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('puts the edited draft on the public issue link and keeps an exploitable miss private', async () => {
    const user = userEvent.setup()
    renderReport()
    await openEvidence(user)
    await user.type(screen.getByLabelText(zh['feedback.note']), '误报说明')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    const warning = screen.getByText(zh['feedback.sendWarning'])
    const body = screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement
    await user.clear(body)
    await user.type(body, '最终正文 & 符号')
    const link = screen.getByRole('link', { name: zh['feedback.github'] })
    expect(warning.compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    const url = new URL(link.getAttribute('href') ?? '')
    expect(url.origin + url.pathname).toBe(GITHUB_BLANK_ISSUE_URL)
    expect(url.searchParams.get('template')).toBe(GITHUB_ISSUE_TEMPLATE)
    expect(url.searchParams.get('body')).toBe((screen.getByLabelText(zh['feedback.bodyField']) as HTMLTextAreaElement).value)
    expect(fetchMock).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: zh['feedback.back'] }))
    await user.click(screen.getByLabelText(zh['feedback.kind.missed']))
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    expect(screen.queryByRole('link', { name: zh['feedback.github'] })).toBeNull()
    const priv = screen.getByRole('link', { name: zh['feedback.private'] })
    expect(priv.getAttribute('href')).toBe(GITHUB_ADVISORY_URL)
    const privateNote = screen.getByText(zh['feedback.privateNote'])
    expect(privateNote.compareDocumentPosition(priv) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    await user.click(screen.getByRole('button', { name: zh['feedback.back'] }))
    await user.click(screen.getByLabelText(zh['feedback.gap']))
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    expect(screen.getByRole('link', { name: zh['feedback.github'] })).toBeTruthy()
  })

  it('requires a type on the general entry', async () => {
    const user = userEvent.setup()
    renderReport()
    await user.click(screen.getByRole('button', { name: zh['feedback.general'] }))
    await user.type(screen.getByLabelText(zh['feedback.note']), '说不清')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    expect(screen.getByRole('status').textContent).toContain(zh['feedback.kind.required'])
    expect(screen.queryByLabelText(zh['feedback.bodyField'])).toBeNull()
  })

  it('shows an oversized draft before the link and lets that link open', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    renderReport()
    await openEvidence(user)
    await user.type(screen.getByLabelText(zh['feedback.note']), '长草稿')
    await user.click(screen.getByRole('button', { name: zh['feedback.next'] }))
    fireEvent.change(screen.getByLabelText(zh['feedback.bodyField']), { target: { value: '字'.repeat(4000) } })
    const note = screen.getByText(zh['feedback.overflow'])
    const link = screen.getByRole('link', { name: zh['feedback.github'] })
    expect(note.compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    const url = new URL(link.getAttribute('href') ?? '')
    expect(url.searchParams.get('template')).toBe(GITHUB_ISSUE_TEMPLATE)
    expect(url.searchParams.get('title')).toBeNull()
    expect(url.searchParams.get('body')).toBeNull()
    await user.click(link)
    expect(open).not.toHaveBeenCalled()
    expect(writeText).toHaveBeenCalled()
    open.mockRestore()
  })
})
