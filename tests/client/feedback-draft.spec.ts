import { describe, expect, it } from 'vitest'
import {
  GITHUB_ADVISORY_URL,
  GITHUB_BLANK_ISSUE_URL,
  GITHUB_ISSUE_TEMPLATE,
  ISSUE_URL_LIMIT,
  blankIssueUrl,
  buildFeedbackDraft,
  draftClipboardText,
  emptyAttachments,
  issueCreateUrl,
  privateReportUrl,
  publicIssueAllowed,
  type DraftLabels,
  type FrozenFinding,
} from '../../src/client/feedback-draft.ts'
import { pageVersion } from '../../src/client/page-version.ts'

const labels: DraftLabels = {
  kind: '问题类型',
  capability: '能力',
  rule: '规则 ID',
  schema: 'schemaVersion',
  page: '页面版本',
  scannerMissing: '报告未记录扫描器版本。',
  situation: '实际情况',
  plugin: '插件',
  source: '安装来源',
  repository: '仓库',
  path: '相对路径',
  snippet: '代码片段',
  values: '实际检测值',
}

function finding(patch: Partial<FrozenFinding> = {}): FrozenFinding {
  return {
    entry: 'evidence',
    pluginName: 'demo-plugin',
    pluginVersion: '1.2.3',
    spec: 'npm:demo-plugin@1.2.3',
    repository: 'https://github.com/example/demo-plugin',
    schemaVersion: 2,
    capability: 'network',
    ruleId: 'network.fetch',
    file: 'lib/index.js',
    line: 4,
    snippet: 'fetch("https://example.test")',
    destinations: ['example.test', '1.2.3.4'],
    ...patch,
  }
}

function draft(patch: Partial<Parameters<typeof buildFeedbackDraft>[0]> = {}) {
  return buildFeedbackDraft({
    kind: 'inaccurate',
    kindLabel: '检测不准确',
    finding: finding(),
    note: '这行只是注释里的例子',
    attachments: emptyAttachments(),
    pageVersion: '0.2.1',
    labels,
    ...patch,
  })
}

describe('feedback draft', () => {
  it('includes the type, capability, rule, schema, page version, and note, and leaves attachments out', () => {
    const result = draft()
    expect(result.body).toContain('问题类型：检测不准确')
    expect(result.body).toContain('能力：network')
    expect(result.body).toContain('规则 ID：network.fetch')
    expect(result.body).toContain('schemaVersion：2')
    expect(result.body).toContain('页面版本：0.2.1')
    expect(result.body).toContain('报告未记录扫描器版本。')
    expect(result.body).toContain('实际情况：\n这行只是注释里的例子')
    expect(result.body).not.toContain('demo-plugin')
    expect(result.body).not.toContain('npm:demo-plugin')
    expect(result.body).not.toContain('lib/index.js')
    expect(result.body).not.toContain('example.test')
    expect(result.body).not.toContain('fetch(')
    expect(result.title).toBe('检测不准确')
    expect(result.body).not.toContain('扫描器版本：0.2.1')
  })

  it('omits a missing rule id instead of inventing one', () => {
    const result = draft({ finding: finding({ ruleId: undefined }) })
    expect(result.body).not.toContain('规则 ID')
    expect(result.body).not.toMatch(/network\.fetch|shell\./)
  })

  it('still drafts an old report that has no schema version', () => {
    const result = draft({ finding: finding({ schemaVersion: undefined, ruleId: undefined, capability: undefined }) })
    expect(result.body).toContain('schemaVersion：')
    expect(result.body).not.toContain('schemaVersion：2')
    expect(result.body).toContain('页面版本：0.2.1')
  })

  it('adds only the attachments the user checked', () => {
    const result = draft({
      attachments: {
        pluginIdentity: true,
        installSource: true,
        pathAndSnippet: true,
        detectedValues: true,
      },
    })
    expect(result.title).toBe('检测不准确：demo-plugin')
    expect(result.body).toContain('插件：demo-plugin@1.2.3')
    expect(result.body).toContain('安装来源：npm:demo-plugin@1.2.3')
    expect(result.body).toContain('仓库：https://github.com/example/demo-plugin')
    expect(result.body).toContain('相对路径：lib/index.js:4')
    expect(result.body).toContain('fetch("https://example.test")')
    expect(result.body).toContain('- example.test')
    expect(result.body).toContain('- 1.2.3.4')
    expect(result.body).not.toContain('profile')
    expect(result.body).not.toContain('ackFingerprint')
    expect(result.body).not.toContain('/Users/')
  })

  it('round-trips special characters into the blank issue URL', () => {
    const title = '检测不准确 & a=b?'
    const body = '行1\n<script>"q"</script> 100%'
    const issue = issueCreateUrl(title, body)
    const parsed = new URL(issue.href)
    expect(issue.overflow).toBe(false)
    expect(parsed.origin + parsed.pathname).toBe(GITHUB_BLANK_ISSUE_URL)
    expect(parsed.searchParams.get('template')).toBe(GITHUB_ISSUE_TEMPLATE)
    expect(parsed.searchParams.get('title')).toBe(title)
    expect(parsed.searchParams.get('body')).toBe(body)
  })

  it('does not truncate a long draft; the URL falls back to a page with no body', () => {
    const body = '字'.repeat(4000)
    const full = draftClipboardText({ title: '标题', body })
    const issue = issueCreateUrl('标题', body)
    expect(full.length).toBeGreaterThan(4000)
    expect(issue.overflow).toBe(true)
    expect(issue.href).toBe(blankIssueUrl())
    expect(new URL(issue.href).searchParams.get('template')).toBe(GITHUB_ISSUE_TEMPLATE)
    expect(new URL(issue.href).searchParams.get('title')).toBeNull()
    expect(new URL(issue.href).searchParams.get('body')).toBeNull()
    expect(issue.href.length).toBeLessThan(ISSUE_URL_LIMIT)
    expect(issue.href).not.toContain(encodeURIComponent(body.slice(0, 20)))
  })

  it('keeps an exploitable miss off the public issue until the user says it is an ordinary gap', () => {
    expect(publicIssueAllowed('missed', false)).toBe(false)
    expect(publicIssueAllowed('missed', true)).toBe(true)
    expect(publicIssueAllowed('inaccurate', false)).toBe(true)
    expect(publicIssueAllowed('unclear', false)).toBe(true)
    expect(privateReportUrl()).toBe(GITHUB_ADVISORY_URL)
    expect(new URL(privateReportUrl()).search).toBe('')
  })

  it('does not treat the page build version as a scanner version outside the client build', () => {
    expect(pageVersion()).toBe('dev')
  })
})
