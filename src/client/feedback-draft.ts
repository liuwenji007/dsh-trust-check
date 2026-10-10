/**
 * Client-only draft for a detection-feedback issue.
 * Nothing here is an audit field, a fingerprint, or a stored record.
 */

export const FEEDBACK_KINDS = ['inaccurate', 'missed', 'unclear'] as const

export type FeedbackKind = (typeof FEEDBACK_KINDS)[number]

export type FeedbackEntry = 'evidence' | 'plugin'

/** Snapshot taken when the dialog opens. Later scans must not replace it. */
export interface FrozenFinding {
  entry: FeedbackEntry
  pluginName: string
  pluginVersion: string
  spec: string
  repository?: string
  schemaVersion?: number
  capability?: string
  /** Omitted when the report has no rule id. Never invented. */
  ruleId?: string
  file?: string
  line?: number
  snippet?: string
  /** Destination literals the user may opt to include. Not a full report. */
  destinations: string[]
}

export interface FeedbackAttachments {
  pluginIdentity: boolean
  installSource: boolean
  pathAndSnippet: boolean
  detectedValues: boolean
}

export const EMPTY_ATTACHMENTS: FeedbackAttachments = {
  pluginIdentity: false,
  installSource: false,
  pathAndSnippet: false,
  detectedValues: false,
}

export interface DraftLabels {
  kind: string
  capability: string
  rule: string
  schema: string
  page: string
  scannerMissing: string
  situation: string
  plugin: string
  source: string
  repository: string
  path: string
  snippet: string
  values: string
}

export interface FeedbackDraftInput {
  kind: FeedbackKind
  kindLabel: string
  finding: FrozenFinding
  note: string
  attachments: FeedbackAttachments
  /** Settings page build. Never described as the scanner version. */
  pageVersion: string
  labels: DraftLabels
}

export interface FeedbackDraft {
  title: string
  body: string
}

/** Issue editor path. YAML forms drop a prefilled body, so every link names the markdown template below. */
export const GITHUB_BLANK_ISSUE_URL = 'https://github.com/liuwenji007/dsh-trust-check/issues/new'

/**
 * Classic title-and-body editor. An empty markdown template keeps `title` and `body`
 * query parameters; the repo's YAML issue forms do not.
 */
export const GITHUB_ISSUE_TEMPLATE = 'detection-feedback.md'

/** Private vulnerability report from SECURITY.md. The draft is never placed on this URL. */
export const GITHUB_ADVISORY_URL = 'https://github.com/liuwenji007/dsh-trust-check/security/advisories/new'

/** Stay under common browser and GitHub URL limits without cutting the draft text. */
export const ISSUE_URL_LIMIT = 6000

export function emptyAttachments(): FeedbackAttachments {
  return { ...EMPTY_ATTACHMENTS }
}

/**
 * Public Issue is withheld for a miss until the user says it is an ordinary
 * rule gap and not an exploitable bypass.
 */
export function publicIssueAllowed(kind: FeedbackKind, ordinaryRuleGap: boolean): boolean {
  if (kind === 'missed') return ordinaryRuleGap
  return true
}

export function buildFeedbackDraft(input: FeedbackDraftInput): FeedbackDraft {
  const { finding, attachments, labels } = input
  const lines: string[] = [
    `${labels.kind}：${input.kindLabel}`,
  ]
  if (finding.capability !== undefined && finding.capability !== '') {
    lines.push(`${labels.capability}：${finding.capability}`)
  }
  if (finding.ruleId !== undefined && finding.ruleId !== '') {
    lines.push(`${labels.rule}：${finding.ruleId}`)
  }
  lines.push(
    finding.schemaVersion === undefined
      ? `${labels.schema}：`
      : `${labels.schema}：${finding.schemaVersion}`,
    `${labels.page}：${input.pageVersion}`,
    labels.scannerMissing,
    '',
    `${labels.situation}：`,
    input.note,
  )

  if (attachments.pluginIdentity) {
    lines.push('', `${labels.plugin}：${finding.pluginName}@${finding.pluginVersion}`)
  }
  if (attachments.installSource) {
    lines.push(`${labels.source}：${finding.spec}`)
    if (finding.repository !== undefined && finding.repository !== '') {
      lines.push(`${labels.repository}：${finding.repository}`)
    }
  }
  if (attachments.pathAndSnippet) {
    const where = finding.file === undefined
      ? ''
      : finding.line === undefined
        ? finding.file
        : `${finding.file}:${finding.line}`
    lines.push(`${labels.path}：${where}`)
    if (finding.snippet !== undefined) lines.push(`${labels.snippet}：`, finding.snippet)
  }
  if (attachments.detectedValues) {
    lines.push(`${labels.values}：`)
    if (finding.destinations.length === 0) lines.push('')
    else for (const value of finding.destinations) lines.push(`- ${value}`)
  }

  const title = attachments.pluginIdentity
    ? `${input.kindLabel}：${finding.pluginName}`
    : input.kindLabel
  return { title, body: lines.join('\n') }
}

export function draftClipboardText(draft: FeedbackDraft): string {
  return `${draft.title}\n\n${draft.body}`
}

export interface IssueUrl {
  href: string
  /** True when the body was left off the URL because encoding it would pass the limit. */
  overflow: boolean
}

/** Markdown editor with no title or body, for the overflow fallback. */
export function blankIssueUrl(): string {
  const url = new URL(GITHUB_BLANK_ISSUE_URL)
  url.searchParams.set('template', GITHUB_ISSUE_TEMPLATE)
  return url.toString()
}

/** Encode the edited title and body. On overflow, return the editor with no body and no title. */
export function issueCreateUrl(title: string, body: string): IssueUrl {
  const url = new URL(GITHUB_BLANK_ISSUE_URL)
  url.searchParams.set('template', GITHUB_ISSUE_TEMPLATE)
  url.searchParams.set('title', title)
  url.searchParams.set('body', body)
  const href = url.toString()
  if (href.length <= ISSUE_URL_LIMIT) return { href, overflow: false }
  return { href: blankIssueUrl(), overflow: true }
}

/** Advisory page with no draft query. */
export function privateReportUrl(): string {
  return GITHUB_ADVISORY_URL
}
