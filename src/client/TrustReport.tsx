/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Reading order: change note, findings, capabilities with their evidence, detail, scan limits, acknowledgment.
 */
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse, Capability, DestinationUsage, Evidence, FindingContext, InjectionKind, TrustAckEntry } from '../core/types.ts'
import {
  ackDrifted,
  capabilityContext,
  capabilityTier,
  capabilityDelta,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  groupEvidence,
  groupInjections,
  networkReach,
  presentInjection,
  repositoryHref,
  topCapabilities,
  verdict,
  type Concern,
  type Verdict,
} from '../core/present.ts'
import { CAPABILITY_WEIGHT } from '../core/score.ts'
import { normalizeAuditReport, normalizeAuditResponse } from '../core/ack-fingerprint.ts'
import {
  destinationHighlight,
  destinationWhitelistReason,
  partitionDestinations,
} from '../core/destination-priority.ts'
import type { TrustKey } from './locales.ts'
import type { createTrustStore } from './stores.ts'
import { resolveDialogTheme } from './dialog-theme.ts'
import { explainCacheKey, pruneExplains, readExplain, writeExplain, type ExplainEntry } from './explain-cache.ts'
import { ExplainMarkdown } from './explain-markdown.tsx'
import { FeedbackDialog } from './FeedbackDialog.tsx'
import type { FrozenFinding } from './feedback-draft.ts'
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

const EVIDENCE_PREVIEW = 3

/** Concerns the capability chips do not already say. */
const SHAPE_CONCERNS: ReadonlySet<Concern['code']> = new Set([
  'install-script',
  'core-tamper',
  'creds-network',
  'plaintext-http',
  'literal-ip',
  'raw',
  'external-dest',
  'secret-touch',
  'path-escape',
])

function decisionConcerns(report: AuditReport): Concern[] {
  return concerns(report, report.redLines.length + 3).filter(c => SHAPE_CONCERNS.has(c.code))
}

/** Runtime tags per row are only worth showing when rows in the group disagree. */
function runtimesAgree(rows: { context?: FindingContext }[]): boolean {
  const key = (row: { context?: FindingContext }) => (row.context?.runtime ?? []).join(',')
  const first = rows[0]
  return first === undefined || rows.every(row => key(row) === key(first))
}

export const EXPLAINED_RULES: ReadonlySet<string> = new Set([
  'shell.import-or-call',
  'fs-write.call',
  'fs-read.import-or-call',
  'network.import-or-call',
  'network.fetch',
  'credentials.material',
  'credentials.read',
  'env.read',
  'subagent.spawn',
  'llm.call',
  'dynamic-code.eval',
  'host-runtime.manifest',
])

function RuleTip({ rule, t, className }: { rule: string; t: T; className?: string }) {
  const id = useId()
  const key = (EXPLAINED_RULES.has(rule) ? `rule.${rule}` : 'rule.unknown') as TrustKey
  return (
    <span className={css.ruleTip}>
      <code
        className={`${css.ruleCode} ${className ?? ''}`}
        tabIndex={0}
        aria-describedby={id}
        onKeyDown={event => {
          if (event.key === 'Escape') event.currentTarget.blur()
        }}
      >
        {rule}
      </code>
      <span role="tooltip" id={id} className={css.ruleTipBody}>
        {t(key)}
        <span className={css.ruleTipNote}>{t('rule.idNote')}</span>
      </span>
    </span>
  )
}

function sharedRule(rows: Evidence[]): string | undefined {
  const first = rows[0]?.rule
  if (first === undefined || first === '' || rows.length < 2) return undefined
  return rows.every(row => row.rule === first) ? first : undefined
}

function evidenceDomId(pluginName: string, cap: Capability): string {
  const safe = pluginName.replace(/[^A-Za-z0-9_-]/g, '-')
  return `trust-evidence-${safe}-${cap}`
}

function evidenceRegionId(pluginName: string): string {
  const safe = pluginName.replace(/[^A-Za-z0-9_-]/g, '-')
  return `trust-evidence-${safe}`
}

function formatExplainTime(at: number): string {
  const date = new Date(at)
  const pad = (n: number) => String(n).padStart(2, '0')
  const time = `${pad(date.getHours())}:${pad(date.getMinutes())}`
  const day = `${date.getMonth() + 1}/${date.getDate()}`
  return date.toDateString() === new Date().toDateString() ? time : `${day} ${time}`
}

function SparkIcon() {
  return (
    <svg className={css.sparkIcon} viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M8 1.5c.3 2.9 1.6 4.2 4.5 4.5-2.9.3-4.2 1.6-4.5 4.5C7.7 7.6 6.4 6.3 3.5 6 6.4 5.7 7.7 4.4 8 1.5Zm4.5 8c.15 1.45.8 2.1 2.25 2.25-1.45.15-2.1.8-2.25 2.25-.15-1.45-.8-2.1-2.25-2.25 1.45-.15 2.1-.8 2.25-2.25Z"
      />
    </svg>
  )
}

function scrollContainer(el: HTMLElement): HTMLElement | null {
  for (let node = el.parentElement; node !== null; node = node.parentElement) {
    if (node === document.body || node === document.documentElement) return null
    if (/(auto|scroll|overlay)/.test(getComputedStyle(node).overflowY)) return node
  }
  return null
}

/** Bring evidence into view, optionally moving focus. Reduced-motion users get an instant scroll. */
function revealEvidence(el: HTMLElement | null, focus: boolean): void {
  if (el === null) return
  const reduce = typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (focus) el.focus({ preventScroll: true })
  el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'nearest' })
}

function freezeEvidence(report: AuditReport, schemaVersion: number, ev: Evidence): FrozenFinding {
  return {
    entry: 'evidence',
    pluginName: report.name,
    pluginVersion: report.version,
    spec: report.spec,
    repository: report.repository,
    schemaVersion,
    capability: ev.capability,
    ruleId: ev.rule !== undefined && ev.rule !== '' ? ev.rule : undefined,
    file: ev.file,
    line: ev.line,
    snippet: ev.snippet,
    destinations: (report.destinations ?? []).map(item => item.value),
  }
}

function freezePlugin(report: AuditReport, schemaVersion: number): FrozenFinding {
  return {
    entry: 'plugin',
    pluginName: report.name,
    pluginVersion: report.version,
    spec: report.spec,
    repository: report.repository,
    schemaVersion,
    destinations: (report.destinations ?? []).map(item => item.value),
  }
}

function CoverageNotes({ notes, t }: { notes: string[]; t: T }) {
  if (notes.length === 0) return null
  return (
    <section className={css.section}>
      <details className={css.limits}>
        <summary className={css.foldSummary}>
          <span className={css.sectionTitleInline}>{t('coverage.title')}</span>
          <span className={css.foldMeta}>{t('coverage.count').replace('{count}', String(notes.length))}</span>
        </summary>
        <p className={css.sectionHint}>{t('coverage.plain')}</p>
        <ol className={css.coverageList}>
          {notes.map((note, index) => (
            <li key={index} className={css.coverageNote}>{note}</li>
          ))}
        </ol>
      </details>
    </section>
  )
}

function ruleMatch(snippet: string, rule?: string): ReactNode {
  const name = rule?.split('.').pop()
  if (name === undefined || name.length < 3) return snippet
  const index = snippet.search(new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`))
  if (index < 0) return snippet
  return (
    <>
      {snippet.slice(0, index)}
      <mark className={css.codeMatch}>{snippet.slice(index, index + name.length)}</mark>
      {snippet.slice(index + name.length)}
    </>
  )
}

/** Existence/stat checks prove fs-read capability but are low-signal for review. */
function isPresenceOnlyFsRead(snippet: string): boolean {
  return /\bexistsSync\s*\(/.test(snippet) || /\bstatSync\s*\(/.test(snippet)
}

function sortEvidenceRows(rows: Evidence[]): Evidence[] {
  return [...rows].sort((a, b) => {
    const wa = isPresenceOnlyFsRead(a.snippet) ? 1 : 0
    const wb = isPresenceOnlyFsRead(b.snippet) ? 1 : 0
    if (wa !== wb) return wa - wb
    return a.line - b.line
  })
}

function EvidenceRow({
  ev,
  t,
  onFeedback,
  showRule = true,
  showRuntime = true,
}: {
  ev: Evidence
  t: T
  onFeedback: (ev: Evidence, opener: HTMLElement) => void
  showRule?: boolean
  showRuntime?: boolean
}) {
  return (
    <li className={css.evidenceItem}>
      <div className={css.evidenceTop}>
        <span className={css.evidenceMeta}>
          <code className={css.evidenceFile}>{ev.file}:{ev.line}</code>
          <ContextTags context={ev.context} t={t} showRuntime={showRuntime} />
          {showRule && ev.rule !== undefined && ev.rule !== '' && (
            <RuleTip rule={ev.rule} t={t} className={css.evidenceRule} />
          )}
        </span>
        <button
          type="button"
          className={css.evidenceReport}
          title={t('feedback.evidence')}
          onClick={event => onFeedback(ev, event.currentTarget)}
        >
          {t('feedback.evidenceShort')}
          <span className={css.srOnly}>：{t('feedback.evidence')}</span>
        </button>
      </div>
      <pre className={css.evidenceSnippet}>
        <span className={css.lineNo} aria-hidden="true">{ev.line}</span>
        <code>{ruleMatch(ev.snippet, ev.rule)}</code>
      </pre>
    </li>
  )
}

/**
 * Height-capped scroller for an expanded evidence list. Edge fades only show where
 * more rows are hidden; it becomes a keyboard stop only when it actually overflows.
 */
function EvidenceScroll({ label, children }: { label: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const [edge, setEdge] = useState({ overflow: false, top: true, bottom: true })
  const measure = () => {
    const el = ref.current
    if (el === null) return
    const next = {
      overflow: el.scrollHeight > el.clientHeight + 1,
      top: el.scrollTop <= 1,
      bottom: el.scrollTop + el.clientHeight >= el.scrollHeight - 1,
    }
    setEdge(prev => (prev.overflow === next.overflow && prev.top === next.top && prev.bottom === next.bottom ? prev : next))
  }
  useLayoutEffect(measure)
  return (
    <div className={css.evidenceFrame}>
      <div
        ref={ref}
        role="region"
        aria-label={label}
        tabIndex={edge.overflow ? 0 : undefined}
        className={`${css.evidenceScroll} ${edge.top ? '' : css.fadeTop} ${edge.bottom ? '' : css.fadeBottom}`}
        onScroll={measure}
      >
        {children}
      </div>
    </div>
  )
}

function CapabilityEvidence({
  report,
  t,
  added,
  onFeedback,
  revealSeq,
}: {
  report: AuditReport
  t: T
  /** Capabilities new since the last acknowledgment; the first one with evidence is selected first. */
  added: Capability[]
  onFeedback: (ev: Evidence, opener: HTMLElement) => void
  /** Bumped by "view all evidence": show every group and move focus here. */
  revealSeq: number
}) {
  const groups = useMemo(() => groupEvidence(report.evidence), [report.evidence])
  const evidenceCaps = useMemo(
    () => [...groups.keys()].sort((a, b) => (CAPABILITY_WEIGHT[b] ?? 0) - (CAPABILITY_WEIGHT[a] ?? 0)),
    [groups],
  )
  const [selected, setSelected] = useState<Capability | null>(
    () => added.find(cap => groups.has(cap)) ?? evidenceCaps[0] ?? report.capabilities[0] ?? null,
  )
  const [showEvery, setShowEvery] = useState(false)
  const [expandedCaps, setExpandedCaps] = useState<Set<Capability>>(new Set())
  const regionRef = useRef<HTMLElement>(null)
  const groupRefs = useRef(new Map<Capability, HTMLDivElement>())

  useEffect(() => {
    if (revealSeq === 0) return
    setShowEvery(true)
    setExpandedCaps(new Set(evidenceCaps))
    revealEvidence(regionRef.current, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealSeq])

  const choose = (cap: Capability) => {
    setSelected(cap)
    setShowEvery(false)
    requestAnimationFrame(() => revealEvidence(groupRefs.current.get(cap) ?? null, false))
  }

  const toggleRows = (cap: Capability) => {
    const wasExpanded = expandedCaps.has(cap)
    setExpandedCaps(prev => {
      const next = new Set(prev)
      if (wasExpanded) next.delete(cap)
      else next.add(cap)
      return next
    })
    if (wasExpanded) requestAnimationFrame(() => revealEvidence(groupRefs.current.get(cap) ?? null, false))
  }

  const shown = showEvery ? evidenceCaps : selected !== null && groups.has(selected) ? [selected] : []

  return (
    <section className={css.section} id={evidenceRegionId(report.name)} tabIndex={-1} ref={regionRef}>
      <header className={css.sectionHead}>
        <h3 className={css.sectionTitle}>{t('capabilities')}</h3>
        {report.evidence.length > 0 && <p className={css.sectionHint}>{t('evidence.hint')}</p>}
      </header>
      {report.capabilities.length === 0
        ? <div className={css.muted}>{t('none')}</div>
        : (
            <div className={css.chips}>
              {report.capabilities.map(cap => {
                const pressed = !showEvery && selected === cap
                return (
                  <button
                    key={cap}
                    type="button"
                    className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`] ?? ''} ${css.chipBtn} ${pressed ? css.chipOn : ''}`}
                    aria-pressed={pressed}
                    aria-controls={evidenceDomId(report.name, cap)}
                    onClick={() => choose(cap)}
                  >
                    {capChipText(cap, t, report)}
                    {added.includes(cap) && ` · ${t('capabilities.new')}`}
                    {groups.has(cap) && <span className={css.chipCount} aria-hidden="true">{groups.get(cap)?.length}</span>}
                  </button>
                )
              })}
              {evidenceCaps.length > 1 && (
                <button
                  type="button"
                  className={`${css.chip} ${css.chipBtn} ${css.chipAll} ${showEvery ? css.chipOn : ''}`}
                  aria-pressed={showEvery}
                  aria-controls={evidenceRegionId(report.name)}
                  onClick={() => setShowEvery(true)}
                >
                  {t('evidence.all')}
                  <span className={css.chipCount} aria-hidden="true">{report.evidence.length}</span>
                </button>
              )}
            </div>
          )}

      {!showEvery && selected !== null && !groups.has(selected) && (
        <p className={`${css.sectionEmpty} ${css.evidenceEmpty}`}>{t('evidence.none')}</p>
      )}
      {shown.length > 0 && (
        <div className={css.evidenceGroups}>
          {shown.map(cap => {
            const rows = sortEvidenceRows(groups.get(cap) ?? [])
            const expanded = expandedCaps.has(cap)
            const primary = rows.filter(r => !isPresenceOnlyFsRead(r.snippet))
            const weak = rows.filter(r => isPresenceOnlyFsRead(r.snippet))
            const main = primary.length > 0 ? primary : rows
            const visible = expanded ? main : main.slice(0, EVIDENCE_PREVIEW)
            const rule = sharedRule(main)
            const rowRuntime = !runtimesAgree(main)
            const list = (
              <ul className={css.evidenceList}>
                {visible.map((ev, i) => (
                  <EvidenceRow
                    key={`${ev.file}:${ev.line}:${i}`}
                    ev={ev}
                    t={t}
                    onFeedback={onFeedback}
                    showRule={rule === undefined}
                    showRuntime={rowRuntime}
                  />
                ))}
              </ul>
            )
            return (
              <div
                key={cap}
                id={evidenceDomId(report.name, cap)}
                tabIndex={-1}
                className={css.evidenceGroup}
                ref={el => {
                  if (el === null) groupRefs.current.delete(cap)
                  else groupRefs.current.set(cap, el)
                }}
              >
                {(showEvery || rule !== undefined) && (
                  <div className={css.evidenceGroupHead}>
                    {showEvery && (
                      <>
                        <span className={css.groupLabel}>{capChipText(cap, t, report)}</span>
                        <span className={css.countPill}>{rows.length}</span>
                      </>
                    )}
                    {rule !== undefined && (
                      <span className={css.groupRule}>
                        {t('evidence.rule')} <RuleTip rule={rule} t={t} />
                      </span>
                    )}
                  </div>
                )}
                {expanded && main.length > EVIDENCE_PREVIEW
                  ? <EvidenceScroll label={t('evidence.scrollRegion').replace('{cap}', capChipText(cap, t, report))}>{list}</EvidenceScroll>
                  : list}
                {main.length > EVIDENCE_PREVIEW && (
                  <button
                    type="button"
                    className={css.evidenceToggle}
                    aria-expanded={expanded}
                    onClick={() => toggleRows(cap)}
                  >
                    {expanded
                      ? t('evidence.collapse')
                      : t('evidence.showRest').replace('{count}', String(main.length - EVIDENCE_PREVIEW))}
                  </button>
                )}
                {weak.length > 0 && primary.length > 0 && (
                  <details className={css.evidenceWeak}>
                    <summary>
                      {t('evidence.presenceOnly')} ({weak.length})
                    </summary>
                    <ul className={css.evidenceList}>
                      {weak.map((ev, i) => (
                        <EvidenceRow key={`w-${ev.file}:${ev.line}:${i}`} ev={ev} t={t} onFeedback={onFeedback} />
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

type AckChange = 'ack' | 'revoke'

function defaultExpandedNames(plugins: AuditReport[], acks?: Record<string, TrustAckEntry>): Set<string> {
  const names = new Set<string>()
  for (const plugin of plugins) {
    if (verdict(plugin, acks?.[plugin.name]) === 'red') names.add(plugin.name)
  }
  if (names.size === 0) {
    const firstReview = plugins.find(p => verdict(p, acks?.[p.name]) === 'review')
    if (firstReview !== undefined) names.add(firstReview.name)
  }
  return names
}

function verdictKey(v: Verdict): TrustKey {
  if (v === 'red') return 'verdict.red'
  if (v === 'accepted') return 'verdict.accepted'
  if (v === 'review') return 'verdict.review'
  if (v === 'expected') return 'verdict.expected'
  return 'verdict.clear'
}

function decisionKey(v: Verdict): TrustKey {
  return `decision.${v}` as TrustKey
}

/** Install channel only (`npm`, `link`, `git`, …) — never the local path in a `link:` spec. */
function sourceKind(spec: string): string {
  const scheme = /^([a-z][a-z0-9+.-]+):/i.exec(spec)?.[1]?.toLowerCase()
  if (scheme === undefined) return 'npm'
  return scheme.startsWith('git') ? 'git' : scheme
}

function actionKey(v: Verdict): TrustKey {
  if (v === 'red') return 'action.red'
  if (v === 'accepted') return 'action.accepted'
  if (v === 'review') return 'action.review'
  if (v === 'expected') return 'action.expected'
  return 'action.clear'
}

function capLabelKey(cap: Capability): TrustKey {
  return `cap.${cap}` as TrustKey
}

function capChipText(cap: Capability, t: T, report: AuditReport): string {
  const parts = [t(capLabelKey(cap))]
  if (cap === 'network') {
    const reach = networkReach(report)
    if (reach === 'outbound') parts.push(t('cap.network.outbound'))
    else if (reach === 'same-origin') parts.push(t('cap.network.sameOrigin'))
  }
  const ctx = capabilityContext(report, cap)
  if (ctx.runtime !== undefined && ctx.runtime !== 'server') parts.push(t(`context.runtimeOnly.${ctx.runtime}`))
  if (ctx.packageName !== undefined) {
    parts.push(t('context.originAll').replace('{package}', ctx.packageName))
  }
  return parts.join(' · ')
}

function ContextTags({ context, t, showRuntime = true }: { context?: FindingContext; t: T; showRuntime?: boolean }) {
  if (context === undefined) return null
  return (
    <>
      {showRuntime && context.runtime?.map(runtime => (
        <span key={runtime} className={`${css.tag} ${css.tagContext}`}>{t(`context.runtime.${runtime}`)}</span>
      ))}
      {context.origin !== undefined && (
        <span className={`${css.tag} ${css.tagContext}`}>
          {t('context.origin').replace('{package}', context.origin.package)}
        </span>
      )}
    </>
  )
}

function distinctUsages(sites: NonNullable<AuditReport['destinations'][number]['sites']>): DestinationUsage[] {
  const seen = new Set<DestinationUsage>()
  const out: DestinationUsage[] = []
  for (const site of sites) {
    if (seen.has(site.usage)) continue
    seen.add(site.usage)
    out.push(site.usage)
  }
  return out
}

function concernLabel(concern: Concern, t: T): string {
  if (concern.code === 'raw') return concern.detail ?? ''
  const key = `concern.${concern.code}` as TrustKey
  return t(key)
}

function injKindKey(kind: InjectionKind): TrustKey {
  return `injKind.${kind}` as TrustKey
}

function destKindKey(kind: AuditReport['destinations'][number]['kind']): TrustKey {
  return `destKind.${kind}` as TrustKey
}

function secretKindKey(kind: AuditReport['secretTouches'][number]['kind']): TrustKey {
  return `secretKind.${kind}` as TrustKey
}

function DestinationsPanel({ report, t }: { report: AuditReport; t: T }) {
  const destinations = useMemo(
    () => (report.destinations ?? []).filter(d => d.kind !== 'relative'),
    [report.destinations],
  )
  const { priority, safe } = useMemo(
    () => partitionDestinations(destinations),
    [destinations],
  )

  if (destinations.length === 0) {
    return (
      <section className={css.section}>
        <header className={css.sectionHead}>
          <h3 className={css.sectionTitle}>{t('destinations')}</h3>
        </header>
        <p className={css.sectionEmpty}>{t('destinations.none')}</p>
      </section>
    )
  }

  const renderRow = (d: AuditReport['destinations'][number], key: string, showWhitelistNote: boolean) => {
    const highlight = destinationHighlight(d)
    const whitelist = showWhitelistNote ? destinationWhitelistReason(d) : undefined
    const rowClass = [
      css.destRow,
      highlight !== undefined ? css.destRowHigh : '',
      whitelist !== undefined ? css.destRowSafe : '',
    ].filter(Boolean).join(' ')
    const usages = distinctUsages(d.sites ?? [])
    return (
      <li key={key} className={rowClass}>
        <div className={css.destBody}>
          <div className={css.destValueLine}>
            <code className={css.destValue}>{d.value}</code>
            {d.kind !== 'https-host' && highlight !== 'plaintext' && (
              <span className={css.tag}>{t(destKindKey(d.kind))}</span>
            )}
            {highlight === 'plaintext' && (
              <span className={`${css.tag} ${css.tagPlain}`}>{t('destinations.plaintext')}</span>
            )}
            {highlight === 'private-ip' && (
              <span className={`${css.tag} ${css.tagWarn}`}>{t('destinations.private')}</span>
            )}
            {highlight === 'public-ip' && (
              <span className={`${css.tag} ${css.tagWarn}`}>{t('destinations.publicIp')}</span>
            )}
          </div>
          {whitelist !== undefined && (
            <div className={css.destNote}>{t(`destWhitelist.${whitelist}` as TrustKey)}</div>
          )}
          {(d.sites?.length ?? 0) > 0 && (
            <div className={css.destNote}>
              <code>{d.sites?.[0]?.file}:{d.sites?.[0]?.line}</code>
              {(d.siteCount ?? 0) > 1 && (
                <details className={css.destSites}>
                  <summary>{t('destinations.sites').replace('{count}', String(d.siteCount))}</summary>
                  <ul className={css.destSiteList}>
                    {d.sites?.map((site, index) => (
                      <li key={`${site.file}:${site.line}:${index}`}>
                        <code>{site.file}:{site.line}</code>
                        {' '}
                        {t(`destUsage.${site.usage}`)}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          )}
        </div>
        {usages.length > 0 && (
          <span className={css.destUsages}>
            <span className={css.srOnly}>{t('destinations.usage')}</span>
            {usages.map(usage => (
              <span
                key={usage}
                className={[
                  css.destUsage,
                  usage === 'request' ? css.destUsageRequest : '',
                  usage === 'unknown' ? css.destUsageUnknown : '',
                ].filter(Boolean).join(' ')}
              >
                {t(`destUsage.${usage}`)}
              </span>
            ))}
          </span>
        )}
      </li>
    )
  }

  return (
    <section className={css.section}>
      <header className={css.sectionHead}>
        <h3 className={css.sectionTitle}>{t('destinations')}</h3>
        <p className={css.sectionHint}>{t('destinations.literal')}</p>
      </header>
      {priority.length > 0 && (
        <ul className={css.destList}>
          {priority.map((d, i) => renderRow(d, `p-${i}`, false))}
        </ul>
      )}
      {safe.length > 0 && (
        <details className={css.fold} open={priority.length === 0}>
          <summary className={css.foldSummary}>
            {t('destinations.safeFold').replace('{count}', String(safe.length))}
          </summary>
          <ul className={css.destList}>
            {safe.map((d, i) => renderRow(d, `s-${i}`, true))}
          </ul>
        </details>
      )}
    </section>
  )
}

function PathEscapesPanel({ report, t }: { report: AuditReport; t: T }) {
  const pathEscapes = report.pathEscapes ?? []
  if (pathEscapes.length === 0) return null
  return (
    <section className={css.section}>
      <header className={css.sectionHead}>
        <h3 className={css.sectionTitle}>{t('pathEscapes')}</h3>
        <p className={css.sectionHint}>{t('pathEscapes.hint')}</p>
      </header>
      <ul className={css.destList}>
        {pathEscapes.map((p, i) => (
          <li key={i} className={css.destRow}>
            <div className={css.destBody}>
              <div className={css.destValueLine}>
                <code className={css.destValue}>{p.value}</code>
                <span className={`${css.tag} ${css.tagWarn}`}>{t(`pathEscape.${p.kind}` as TrustKey)}</span>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}

function SecretTouchesPanel({ report, t }: { report: AuditReport; t: T }) {
  const secretTouches = report.secretTouches ?? []
  if (secretTouches.length === 0) return null
  const rowRuntime = !runtimesAgree(secretTouches)
  return (
    <section className={css.section}>
      <header className={css.sectionHead}>
        <h3 className={css.sectionTitle}>{t('secretTouches')}</h3>
      </header>
      <ul className={css.destList}>
        {secretTouches.map((s, i) => (
          <li key={i} className={css.destRow}>
            <div className={css.destBody}>
              <div className={css.destValueLine}>
                <code className={css.destValue}>{s.value}</code>
                <span className={css.tag}>{t(secretKindKey(s.kind))}</span>
                <ContextTags context={s.context} t={t} showRuntime={rowRuntime} />
              </div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}

function InjectionPanel({ report, t }: { report: AuditReport; t: T }) {
  const grouped = groupInjections(report)
  const count = report.injections.length
  const tokens = report.injectedTokensEstimate

  if (count === 0) {
    return (
      <section className={css.section}>
        <header className={css.sectionHead}>
          <h3 className={css.sectionTitle}>{t('injections')}</h3>
          <p className={css.sectionHint}>{t('injections.hint')}</p>
        </header>
        <p className={css.sectionEmpty}>{t('noInjection')}</p>
      </section>
    )
  }

  return (
    <section className={css.section}>
      <details className={css.fold}>
        <summary className={css.foldSummary}>
          <span className={css.sectionTitleInline}>{t('injections')}</span>
          <span className={css.countPill}>{count}</span>
          {tokens > 0 && (
            <span className={css.foldMeta}>~{tokens} {t('injectedTokens')}</span>
          )}
        </summary>
        <p className={css.sectionHint}>{t('injections.hint')}</p>
        <div className={css.injectionGroups}>
          {[...grouped.entries()].map(([kind, findings]) => (
            <div key={kind} className={css.injectionGroup}>
              <div className={css.injKindHead}>{t(injKindKey(kind))}</div>
              <div className={css.injItems}>
                {findings.map((inj, i) => {
                  const view = presentInjection(inj.detail)
                  return (
                    <div key={i} className={css.injItem}>
                      <div className={css.injSummary}>
                        {view.summaryKey !== undefined
                          ? t(view.summaryKey as TrustKey)
                          : (view.fallback ?? formatInjectionDetail(inj.detail))}
                      </div>
                      {view.packages !== undefined && view.packages.length > 0 && (
                        <ul className={css.injPackages}>
                          {view.packages.map(pkg => (
                            <li key={pkg}><code>{pkg}</code></li>
                          ))}
                        </ul>
                      )}
                      {view.target !== undefined && view.packages === undefined && (
                        <code className={css.injTarget}>{view.target}</code>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </details>
    </section>
  )
}

function PluginCardBody({
  report,
  ack,
  profile,
  schemaVersion,
  t,
  onAckChange,
  onReplaceReport,
  onOpenFeedback,
}: {
  report: AuditReport
  ack?: TrustAckEntry
  profile: string
  schemaVersion: number
  t: T
  onAckChange: (kind: AckChange) => Promise<void>
  onReplaceReport: (report: AuditReport) => void
  onOpenFeedback: (finding: FrozenFinding, opener: HTMLElement) => void
}) {
  const v = verdict(report, ack)
  const concernList = decisionConcerns(report)
  const drift = ack !== undefined && ackDrifted(report, ack)
  const { added, removed } = capabilityDelta(report, ack)
  const repoHref = repositoryHref(report.repository)
  const [revealSeq, setRevealSeq] = useState(0)
  const [ackLoading, setAckLoading] = useState(false)
  const [ackError, setAckError] = useState(false)
  const [ackStale, setAckStale] = useState(false)
  const [explainLoading, setExplainLoading] = useState(false)
  const explainLocale = typeof document !== 'undefined' ? document.documentElement.lang : ''
  const explainKey = explainCacheKey(report, explainLocale)
  const [explainEntry, setExplainEntry] = useState<ExplainEntry | null>(
    () => readExplain(report.name, explainKey) ?? null,
  )
  const explainCurrent = explainEntry !== null && explainEntry.key === explainKey ? explainEntry : null
  const explainText = explainCurrent?.text ?? null
  const [explainError, setExplainError] = useState(false)
  const explainRef = useRef<HTMLElement>(null)
  const explainTitleId = `${evidenceRegionId(report.name)}-explain`
  const [explainSeq, setExplainSeq] = useState(0)

  useEffect(() => {
    if (explainSeq > 0) revealEvidence(explainRef.current, true)
  }, [explainSeq])

  const postAck = async (acceptRisk = false) => {
    setAckLoading(true)
    setAckError(false)
    try {
      const res = await fetch('/dsh-trust-check/ack', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: report.name,
          acceptRisk,
          fingerprint: report.ackFingerprint,
        }),
      })
      if (res.status === 409) {
        const data = await res.json() as { report?: AuditReport }
        setAckStale(true)
        if (data.report !== undefined) onReplaceReport(data.report)
        return
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setAckStale(false)
      await onAckChange('ack')
    } catch {
      setAckError(true)
    } finally {
      setAckLoading(false)
    }
  }

  const revokeAck = async () => {
    setAckLoading(true)
    setAckError(false)
    try {
      const res = await fetch(`/dsh-trust-check/ack?name=${encodeURIComponent(report.name)}`, {
        method: 'DELETE',
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      await onAckChange('revoke')
    } catch {
      setAckError(true)
    } finally {
      setAckLoading(false)
    }
  }

  const explain = async () => {
    setExplainLoading(true)
    setExplainError(false)
    try {
      const res = await fetch('/dsh-trust-check/explain', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: report.name, locale: explainLocale }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as { text?: string, truncated?: boolean }
      const entry: ExplainEntry = {
        key: explainKey,
        text: data.text ?? '',
        at: Date.now(),
        ...(data.truncated === true ? { truncated: true } : {}),
      }
      writeExplain(report.name, entry)
      setExplainEntry(entry)
      setExplainSeq(n => n + 1)
    } catch {
      setExplainError(true)
    } finally {
      setExplainLoading(false)
    }
  }

  return (
    <div className={css.cardBody}>
      {drift && (
        <section className={css.drift}>
          <p className={css.driftTitle}>
            <span>{t('drift.title')}</span>
            {added.length > 0 && (
              <span className={css.driftGroup}>
                <span className={css.srOnly}>{t('drift.added')}</span>
                {added.map(cap => (
                  <span key={cap} className={`${css.deltaPill} ${css.deltaAdded}`}>
                    <span aria-hidden="true">+ </span>{t(capLabelKey(cap))}
                  </span>
                ))}
              </span>
            )}
            {removed.length > 0 && (
              <span className={css.driftGroup}>
                <span className={css.srOnly}>{t('drift.removed')}</span>
                {removed.map(cap => (
                  <span key={cap} className={`${css.deltaPill} ${css.deltaRemoved}`}>
                    <span aria-hidden="true">− </span>{t(capLabelKey(cap))}
                  </span>
                ))}
              </span>
            )}
          </p>
          <p className={css.driftNote}>{t('drift.ruleNote')}</p>
        </section>
      )}

      <section className={css.decision}>
        <h3 className={css.srOnly}>{t(decisionKey(v))}</h3>
        <div className={css.decisionHead}>
          <p className={css.action}>
            {t(actionKey(v)).replace('{profile}', profile).replace('{name}', report.name)}
          </p>
          <button
            type="button"
            className={css.linkBtn}
            onClick={event => {
              onOpenFeedback(freezePlugin(report, schemaVersion), event.currentTarget)
            }}
          >
            {t('feedback.general')}
          </button>
        </div>
        {concernList.length > 0 && v !== 'expected' && (
          <ul className={css.concernList} aria-label={t('concerns.title')}>
            {concernList.map((item, i) => (
              <li key={i} className={i < report.redLines.length ? css.concernRed : undefined}>
                {concernLabel(item, t)}
              </li>
            ))}
          </ul>
        )}
      </section>

      {explainText !== null && (
        <section className={css.explainBox} tabIndex={-1} ref={explainRef} aria-labelledby={explainTitleId}>
          <div className={css.explainHead}>
            <h3 className={`${css.sectionTitle} ${css.explainTitleRow}`} id={explainTitleId}>
              <SparkIcon />
              {t('explain.title')}
            </h3>
            <span className={css.sectionHint}>{t('explain.disclaimer')}</span>
          </div>
          <ExplainMarkdown text={explainText} />
          {explainCurrent!.truncated === true && (
            <p className={css.explainCut}>{t('explain.truncated')}</p>
          )}
          <div className={css.explainFoot}>
            <span>{t('explain.generatedAt').replace('{time}', formatExplainTime(explainCurrent!.at))}</span>
            <button
              type="button"
              className={css.linkBtn}
              disabled={explainLoading}
              aria-busy={explainLoading || undefined}
              onClick={() => void explain()}
            >
              {explainLoading ? t('explain.loading') : t('explain.regenerate')}
            </button>
          </div>
        </section>
      )}

      <div className={css.scanStack}>
        <CapabilityEvidence
          report={report}
          t={t}
          added={drift ? added : []}
          onFeedback={(ev, opener) => {
            onOpenFeedback(freezeEvidence(report, schemaVersion, ev), opener)
          }}
          revealSeq={revealSeq}
        />

        <DestinationsPanel report={report} t={t} />
        <PathEscapesPanel report={report} t={t} />
        <SecretTouchesPanel report={report} t={t} />
        <InjectionPanel report={report} t={t} />

        <section className={css.section}>
          <header className={css.sectionHead}>
            <h3 className={css.sectionTitle}>{t('source')}</h3>
            <p className={css.sectionHint}>{t('source.hint')}</p>
          </header>
          <div className={css.meta}>
            {!report.pinned && <span className={`${css.tag} ${css.tagWarn}`}>{t('unpinned')}</span>}
            {report.repository === undefined && (
              <span className={`${css.tag} ${css.tagWarn}`}>{t('noRepo')}</span>
            )}
            {report.hasBuildScript && (
              <span className={`${css.tag} ${css.tagPlain}`}>{t('buildScript')}</span>
            )}
            {report.repository !== undefined && (
              repoHref !== undefined
                ? (
                    <a className={css.repoLink} href={repoHref} target="_blank" rel="noreferrer">
                      {report.repository}
                    </a>
                  )
                : <span className={css.repoPlain}>{report.repository}</span>
            )}
          </div>
          {report.hasBuildScript && (
            <div className={css.sourceRisk}>
              <p className={css.sourceRiskHint}>{t('buildScript.hint')}</p>
              {report.buildScripts.length > 0 && (
                <div className={css.sourceScripts}>
                  <span className={css.sourceScriptsLabel}>{t('buildScript.scripts')}</span>
                  <ul className={css.injPackages}>
                    {report.buildScripts.map(name => (
                      <li key={name}><code>{name}</code></li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>

      </div>

      <CoverageNotes notes={report.coverageNotes ?? []} t={t} />

      <section className={css.ackBar}>
        <div className={css.ackRow}>
          <div className={css.actions}>
            {v === 'review' && (
              <button type="button" className={css.actionBtn} disabled={ackLoading} onClick={() => void postAck()}>
                {ackLoading ? t('ack.saving') : t('ack.accept')}
              </button>
            )}
            {v === 'red' && (
              <button type="button" className={css.actionBtnSecondary} disabled={ackLoading} onClick={() => void postAck(true)}>
                {ackLoading ? t('ack.saving') : t('ack.acceptRisk')}
              </button>
            )}
            {(v === 'expected' || v === 'accepted') && (
              <button type="button" className={css.actionBtnSecondary} disabled={ackLoading} onClick={() => void revokeAck()}>
                {t('ack.revoke')}
              </button>
            )}
          </div>
          <div className={css.ackLinks}>
            <button
              type="button"
              className={css.aiBtn}
              disabled={explainLoading}
              aria-busy={explainLoading || undefined}
              onClick={() => {
                if (explainText !== null) revealEvidence(explainRef.current, true)
                else void explain()
              }}
            >
              <SparkIcon />
              {explainLoading
                ? t('explain.loading')
                : explainText !== null ? t('explain.view') : t('explain.button')}
            </button>
            {report.evidence.length > 0 && (
              <button type="button" className={css.linkBtn} onClick={() => setRevealSeq(n => n + 1)}>
                {t('ack.viewEvidence')}
              </button>
            )}
          </div>
        </div>
        {ackStale && <div className={css.errorInline} role="status">{t('ack.stale')}</div>}
        {ackError && <div className={css.errorInline} role="status">{t('ack.error')}</div>}
        {explainError && <div className={css.errorInline} role="status">{t('explain.error')}</div>}
      </section>
      <p className={css.ackNote}>{t('ack.scope')}</p>
    </div>
  )
}

function PluginRow({
  report,
  ack,
  profile,
  schemaVersion,
  t,
  expanded,
  settled,
  onSettledEnd,
  onToggle,
  onAckChange,
  onReplaceReport,
  onOpenFeedback,
}: {
  report: AuditReport
  ack?: TrustAckEntry
  profile: string
  schemaVersion: number
  t: T
  expanded: boolean
  /** Just acknowledged and folded: briefly highlight the card so the reader sees where it went. */
  settled: boolean
  onSettledEnd: () => void
  onToggle: () => void
  onAckChange: (kind: AckChange) => Promise<void>
  onReplaceReport: (report: AuditReport) => void
  onOpenFeedback: (finding: FrozenFinding, opener: HTMLElement) => void
}) {
  const v = verdict(report, ack)
  const previewCaps = topCapabilities(report, 3)
  const sourceLine = [
    t('card.source').replace('{kind}', sourceKind(report.spec)),
    t(report.pinned ? 'pinned' : 'unpinned'),
    ...(ack !== undefined ? [t('card.lastAck').replace('{date}', new Date(ack.at).toLocaleDateString())] : []),
  ].join(' · ')

  return (
    <article
      className={`${css.plugin} ${expanded ? css.pluginOpen : settled ? css.pluginSettled : ''}`}
      data-plugin={report.name}
      onAnimationEnd={event => {
        if (event.target === event.currentTarget) onSettledEnd()
      }}
    >
      <button type="button" className={css.pluginToggle} aria-expanded={expanded} onClick={onToggle}>
        <span className={css.toggleMain}>
          <span className={css.nameLine}>
            <span className={css.name}>{report.name}</span>
            <span className={css.version}>{report.version}</span>
          </span>
          <span className={`${css.statusBadge} ${css[`badge-${v}`]}`}>{t(verdictKey(v))}</span>
        </span>
        <span className={css.sourceLine}>{sourceLine}</span>
        {!expanded && previewCaps.length > 0 && (
          <span className={css.previewChips}>
            {previewCaps.map(cap => (
              <span key={cap} className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`] ?? ''}`}>{capChipText(cap, t, report)}</span>
            ))}
          </span>
        )}
        <span className={css.srOnly}>{expanded ? t('collapsePlugin') : t('expandPlugin')}</span>
      </button>
      {expanded && (
        <PluginCardBody
          report={report}
          ack={ack}
          profile={profile}
          schemaVersion={schemaVersion}
          t={t}
          onAckChange={onAckChange}
          onReplaceReport={onReplaceReport}
          onOpenFeedback={onOpenFeedback}
        />
      )}
    </article>
  )
}

export function TrustReport({ useStore, actions, t }: TrustReportProps) {
  const report = useStore(s => s.report)
  const normalizedReport = useMemo(
    () => (report === null ? null : normalizeAuditResponse(report)),
    [report],
  )
  const fetchedAt = useStore(s => s.fetchedAt)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [feedback, setFeedback] = useState<{ id: number, finding: FrozenFinding, opener: HTMLElement } | null>(null)
  const feedbackSeq = useRef(0)
  const rootRef = useRef<HTMLDivElement>(null)

  const openFeedback = (finding: FrozenFinding, opener: HTMLElement) => {
    feedbackSeq.current += 1
    setFeedback({ id: feedbackSeq.current, finding, opener })
  }

  const [settleName, setSettleName] = useState<string | null>(null)
  const [settledName, setSettledName] = useState<string | null>(null)

  /** `afterAck` keeps the reader's place instead of re-deriving which cards are open. */
  const refresh = async (afterAck?: { name: string, kind: AckChange }) => {
    setLoading(true)
    setError(false)
    try {
      const response = await fetch('/dsh-trust-check/audit')
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json() as AuditResponse
      actions.setReport(data, Date.now())
      if (afterAck === undefined) {
        setExpanded(defaultExpandedNames(data.plugins, data.acks))
      } else if (afterAck.kind === 'ack') {
        setExpanded(prev => {
          const next = new Set(prev)
          next.delete(afterAck.name)
          return next
        })
        setSettleName(afterAck.name)
        setSettledName(afterAck.name)
      }
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (normalizedReport !== null) pruneExplains(normalizedReport.plugins.map(p => p.name))
  }, [normalizedReport])

  useEffect(() => {
    if (report === null) void refresh()
    else if (expanded.size === 0 && normalizedReport !== null && normalizedReport.plugins.length > 0) {
      setExpanded(defaultExpandedNames(normalizedReport.plugins, normalizedReport.acks))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /**
   * The sticky acknowledgment bar needs an opaque plate (cards are transparent on some hosts) and
   * must offset the scroll container's bottom padding, which Chrome excludes from the sticky area.
   */
  useLayoutEffect(() => {
    const root = rootRef.current
    if (root === null) return
    const apply = () => {
      root.style.setProperty('--trust-plate', resolveDialogTheme(root).background)
      const scroller = scrollContainer(root)
      const padding = scroller === null ? 0 : parseFloat(getComputedStyle(scroller).paddingBottom) || 0
      root.style.setProperty('--trust-stick', `${-padding}px`)
    }
    apply()
    const observer = new MutationObserver(apply)
    for (const node of [document.documentElement, document.body]) {
      observer.observe(node, { attributes: true, attributeFilter: ['class', 'style', 'data-theme'] })
    }
    window.addEventListener('resize', apply)
    return () => {
      observer.disconnect()
      window.removeEventListener('resize', apply)
    }
  }, [])

  useEffect(() => {
    if (settleName === null) return
    setSettleName(null)
    const card = [...(rootRef.current?.querySelectorAll<HTMLElement>('[data-plugin]') ?? [])]
      .find(el => el.dataset.plugin === settleName)
    revealEvidence(card?.querySelector<HTMLElement>('[aria-expanded]') ?? null, true)
  }, [settleName])

  const overview = useMemo(() => {
    if (normalizedReport === null || normalizedReport.plugins.length === 0) return null
    const counts = countVerdicts(normalizedReport.plugins, normalizedReport.acks)
    const parts = (['red', 'accepted', 'review', 'expected', 'clear'] as const)
      .filter(v => counts[v] > 0)
      .map(v => `${counts[v]} ${t(verdictKey(v))}`)
    return [`${normalizedReport.plugins.length} ${t('overview.plugins')}`, ...parts].join(' · ')
  }, [normalizedReport, t])

  const togglePlugin = (name: string) => {
    setSettledName(current => (current === name ? null : current))
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  return (
    <div className={css.root} ref={rootRef}>
      <div className={css.head}>
        <div className={css.headText}>
          <h2 className={css.title}>{t('settings.title')}</h2>
          <p className={css.intro}>{t('intro')}</p>
          <p className={css.postInstall}>
            <span className={css.scopeDot} aria-hidden="true" />
            {t('postInstall.note')}
          </p>
          <details className={css.help}>
            <summary>{t('howToRead.title')}</summary>
            <p>{t('howToRead.body')}</p>
          </details>
        </div>
        <div className={css.headActions}>
          {fetchedAt !== null && (
            <div className={css.muted}>{new Date(fetchedAt).toLocaleString()}</div>
          )}
          <button className={css.refresh} onClick={() => void refresh()} disabled={loading}>
            {loading ? t('refreshing') : t('refresh')}
          </button>
        </div>
      </div>

      {overview !== null && <div className={css.overview}>{overview}</div>}

      {error && <div className={css.error} role="alert">{t('loadError')}</div>}

      {!error && normalizedReport !== null && normalizedReport.plugins.length === 0 && normalizedReport.errors.length === 0 && (
        <div className={css.empty}>{t('empty')}</div>
      )}

      {normalizedReport !== null && normalizedReport.plugins.map(plugin => (
        <PluginRow
          key={plugin.name}
          report={normalizeAuditReport(plugin)}
          ack={normalizedReport.acks?.[plugin.name]}
          profile={normalizedReport.profile === '' ? 'web' : normalizedReport.profile}
          schemaVersion={normalizedReport.schemaVersion}
          t={t}
          expanded={expanded.has(plugin.name)}
          settled={settledName === plugin.name}
          onSettledEnd={() => setSettledName(name => (name === plugin.name ? null : name))}
          onToggle={() => togglePlugin(plugin.name)}
          onAckChange={kind => refresh({ name: plugin.name, kind })}
          onOpenFeedback={openFeedback}
          onReplaceReport={next => {
            if (report === null) return
            actions.setReport({
              ...report,
              plugins: report.plugins.map(plugin => plugin.name === next.name ? next : plugin),
            }, Date.now())
          }}
        />
      ))}

      {normalizedReport !== null && normalizedReport.errors.length > 0 && (
        <section className={css.errors}>
          <div className={css.sectionTitle}>{t('errors.title')}</div>
          <div className={css.sectionHint}>{t('errors.hint')}</div>
          <ul className={css.list}>
            {normalizedReport.errors.map((err, i) => (
              <li key={i}>{err.name}: {err.message}</li>
            ))}
          </ul>
        </section>
      )}

      {feedback !== null && (
        <FeedbackDialog
          key={feedback.id}
          finding={feedback.finding}
          themeRoot={rootRef.current}
          returnFocus={feedback.opener}
          t={t}
          onClose={() => setFeedback(null)}
        />
      )}
    </div>
  )
}
