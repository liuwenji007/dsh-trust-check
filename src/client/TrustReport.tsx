/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Reading order: change note, findings, capabilities with their evidence, detail, scan limits, acknowledgment.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse, Capability, DestinationUsage, Evidence, FindingContext, InjectionKind, TrustAckEntry } from '../core/types.ts'
import {
  ackDrifted,
  capabilityContext,
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
import { ExplainMarkdown } from './explain-markdown.tsx'
import { FeedbackDialog } from './FeedbackDialog.tsx'
import type { FrozenFinding } from './feedback-draft.ts'
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

const EVIDENCE_PREVIEW = 2

function evidenceDomId(pluginName: string, cap: Capability): string {
  const safe = pluginName.replace(/[^A-Za-z0-9_-]/g, '-')
  return `trust-evidence-${safe}-${cap}`
}

function evidenceRegionId(pluginName: string): string {
  const safe = pluginName.replace(/[^A-Za-z0-9_-]/g, '-')
  return `trust-evidence-${safe}`
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
        <summary className={css.limitsSummary}>
          <span>{t('coverage.title')}</span>
          <span aria-hidden="true">·</span>
          <span>{t('coverage.count').replace('{count}', String(notes.length))}</span>
        </summary>
        <ul className={css.coverageList}>
          {notes.map((note, index) => (
            <li key={index} className={css.coverageNote}>{note}</li>
          ))}
        </ul>
        <p className={css.sectionHint}>{t('coverage.plain')}</p>
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
}: {
  ev: Evidence
  t: T
  onFeedback: (ev: Evidence, opener: HTMLElement) => void
}) {
  return (
    <li className={css.evidenceItem}>
      <div className={css.evidenceTop}>
        <span className={css.evidenceMeta}>
          <code className={css.evidenceFile}>{ev.file}:{ev.line}</code>
          <ContextTags context={ev.context} t={t} />
        </span>
        {ev.rule !== undefined && ev.rule !== '' && (
          <code className={css.evidenceRule}>{ev.rule}</code>
        )}
      </div>
      <pre className={css.evidenceSnippet}>
        <span className={css.lineNo} aria-hidden="true">{ev.line}</span>
        <code>{ruleMatch(ev.snippet, ev.rule)}</code>
      </pre>
      <div className={css.evidenceFoot}>
        <button
          type="button"
          className={css.linkBtn}
          onClick={event => onFeedback(ev, event.currentTarget)}
        >
          {t('feedback.evidence')}
        </button>
      </div>
    </li>
  )
}

function CapabilityEvidence({
  report,
  t,
  added,
  explainLoading,
  explainText,
  explainError,
  onExplain,
  onFeedback,
  revealSeq,
}: {
  report: AuditReport
  t: T
  /** Capabilities new since the last acknowledgment; the first one with evidence is selected first. */
  added: Capability[]
  explainLoading: boolean
  explainText: string | null
  explainError: boolean
  onExplain: () => void
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
                    className={`${css.chip} ${css.chipBtn} ${pressed ? css.chipOn : ''}`}
                    aria-pressed={pressed}
                    aria-controls={evidenceDomId(report.name, cap)}
                    onClick={() => choose(cap)}
                  >
                    {capChipText(cap, t, report)}
                    {added.includes(cap) && ` · ${t('capabilities.new')}`}
                  </button>
                )
              })}
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
                {showEvery && (
                  <div className={css.evidenceGroupHead}>
                    <span className={css.groupLabel}>{capChipText(cap, t, report)}</span>
                    <span className={css.countPill}>{rows.length}</span>
                  </div>
                )}
                <ul className={css.evidenceList}>
                  {visible.map((ev, i) => (
                    <EvidenceRow key={`${ev.file}:${ev.line}:${i}`} ev={ev} t={t} onFeedback={onFeedback} />
                  ))}
                </ul>
                {main.length > EVIDENCE_PREVIEW && !expanded && (
                  <button
                    type="button"
                    className={css.linkBtn}
                    onClick={() => setExpandedCaps(prev => new Set(prev).add(cap))}
                  >
                    {t('evidence.showAll')} ({main.length})
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
      {evidenceCaps.length > 1 && (
        <button type="button" className={css.linkBtn} onClick={() => setShowEvery(value => !value)}>
          {showEvery
            ? t('evidence.showSelected')
            : t('evidence.showEvery').replace('{count}', String(report.evidence.length))}
        </button>
      )}

      <div className={css.aidLabel}>{t('explain.aid')}</div>
      <button type="button" className={css.actionBtnSecondary} disabled={explainLoading} onClick={onExplain}>
        {explainLoading ? t('explain.loading') : t('explain.button')}
      </button>
      {explainError && <div className={css.muted}>{t('explain.error')}</div>}
      {explainText !== null && (
        <div className={css.explainBox}>
          <div className={css.muted}>{t('explain.disclaimer')}</div>
          <ExplainMarkdown text={explainText} />
        </div>
      )}
    </section>
  )
}

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
  if (ctx.runtime !== undefined) parts.push(t(`context.runtimeOnly.${ctx.runtime}`))
  if (ctx.packageName !== undefined) {
    parts.push(t('context.originAll').replace('{package}', ctx.packageName))
  }
  return parts.join(' · ')
}

function ContextTags({ context, t }: { context?: FindingContext; t: T }) {
  if (context === undefined) return null
  return (
    <>
      {context.runtime?.map(runtime => (
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
            <span className={css.tag}>{t(destKindKey(d.kind))}</span>
            {highlight === 'plaintext' && (
              <span className={`${css.tag} ${css.tagPlain}`}>{t('destinations.plaintext')}</span>
            )}
            {highlight === 'private-ip' && (
              <span className={`${css.tag} ${css.tagWarn}`}>{t('destinations.private')}</span>
            )}
            {highlight === 'public-ip' && (
              <span className={`${css.tag} ${css.tagWarn}`}>{t('destinations.publicIp')}</span>
            )}
            {whitelist !== undefined && (
              <span className={`${css.tag} ${css.tagSafe}`}>{t('destinations.allowlisted')}</span>
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
          <span className={css.destUsage}>{usages.map(usage => t(`destUsage.${usage}`)).join(' · ')}</span>
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
          <p className={css.sectionHint}>{t('destinations.safeHint')}</p>
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
                <ContextTags context={s.context} t={t} />
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
  onAckChange: () => void
  onReplaceReport: (report: AuditReport) => void
  onOpenFeedback: (finding: FrozenFinding, opener: HTMLElement) => void
}) {
  const v = verdict(report, ack)
  const concernList = concerns(report)
  const drift = ack !== undefined && ackDrifted(report, ack)
  const { added, removed } = capabilityDelta(report, ack)
  const repoHref = repositoryHref(report.repository)
  const [revealSeq, setRevealSeq] = useState(0)
  const [ackLoading, setAckLoading] = useState(false)
  const [ackError, setAckError] = useState(false)
  const [ackStale, setAckStale] = useState(false)
  const [explainLoading, setExplainLoading] = useState(false)
  const [explainText, setExplainText] = useState<string | null>(null)
  const [explainError, setExplainError] = useState(false)

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
      onAckChange()
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
      onAckChange()
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
      const locale = typeof document !== 'undefined' ? document.documentElement.lang : undefined
      const res = await fetch('/dsh-trust-check/explain', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: report.name, locale }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as { text?: string }
      setExplainText(data.text ?? '')
    } catch {
      setExplainError(true)
      setExplainText(null)
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
        <div className={css.decisionHead}>
          <h3 className={css.decisionTitle}>{t(decisionKey(v))}</h3>
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
        <p className={css.action}>
          {t(actionKey(v)).replace('{profile}', profile).replace('{name}', report.name)}
        </p>
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

      <div className={css.scanStack}>
        <CapabilityEvidence
          report={report}
          t={t}
          added={drift ? added : []}
          explainLoading={explainLoading}
          explainText={explainText}
          explainError={explainError}
          onExplain={() => void explain()}
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
            {report.pinned
              ? <span className={`${css.tag} ${css.tagSafe}`}>{t('pinned')}</span>
              : <span className={`${css.tag} ${css.tagWarn}`}>{t('unpinned')}</span>}
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
          {report.evidence.length > 0 && (
            <button type="button" className={css.linkBtn} onClick={() => setRevealSeq(n => n + 1)}>
              {t('ack.viewEvidence')}
            </button>
          )}
        </div>
        {ackStale && <div className={css.errorInline} role="status">{t('ack.stale')}</div>}
        {ackError && <div className={css.errorInline} role="status">{t('ack.error')}</div>}
        <p className={css.ackNote}>{t('ack.scope')}</p>
      </section>
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
  onToggle: () => void
  onAckChange: () => void
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
    <article className={css.plugin}>
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
              <span key={cap} className={css.chip}>{capChipText(cap, t, report)}</span>
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

  const refresh = async () => {
    setLoading(true)
    setError(false)
    try {
      const response = await fetch('/dsh-trust-check/audit')
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json() as AuditResponse
      actions.setReport(data, Date.now())
      setExpanded(defaultExpandedNames(data.plugins, data.acks))
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (report === null) void refresh()
    else if (expanded.size === 0 && normalizedReport !== null && normalizedReport.plugins.length > 0) {
      setExpanded(defaultExpandedNames(normalizedReport.plugins, normalizedReport.acks))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const overview = useMemo(() => {
    if (normalizedReport === null || normalizedReport.plugins.length === 0) return null
    const counts = countVerdicts(normalizedReport.plugins, normalizedReport.acks)
    return `${normalizedReport.plugins.length} ${t('overview.plugins')} · ${counts.red} ${t('verdict.red')} · ${counts.accepted} ${t('verdict.accepted')} · ${counts.review} ${t('verdict.review')} · ${counts.expected} ${t('verdict.expected')} · ${counts.clear} ${t('verdict.clear')}`
  }, [normalizedReport, t])

  const togglePlugin = (name: string) => {
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
          onToggle={() => togglePlugin(plugin.name)}
          onAckChange={() => void refresh()}
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
