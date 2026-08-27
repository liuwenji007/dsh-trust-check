/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Decision-first layout: verdict, shape, scan dimensions, evidence, ack, explain.
 */
import { useEffect, useMemo, useState } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse, Capability, Evidence, InjectionKind, TrustAckEntry } from '../core/types.ts'
import {
  ackDrifted,
  capabilityTier,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  groupEvidence,
  groupInjections,
  presentInjection,
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
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

const EVIDENCE_PREVIEW = 2

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

function EvidencePanel({
  report,
  t,
  focusCap,
  onClearFocus,
}: {
  report: AuditReport
  t: T
  focusCap: Capability | null
  onClearFocus: () => void
}) {
  const filtered = focusCap === null
    ? report.evidence
    : report.evidence.filter(e => e.capability === focusCap)

  const capGroups = useMemo(() => {
    const map = groupEvidence(filtered)
    const caps = [...map.keys()].sort(
      (a, b) => (CAPABILITY_WEIGHT[b] ?? 0) - (CAPABILITY_WEIGHT[a] ?? 0),
    )
    return caps.map(cap => ({
      cap,
      rows: sortEvidenceRows(map.get(cap) ?? []),
    }))
  }, [filtered])

  const [expandedCaps, setExpandedCaps] = useState<Set<Capability>>(new Set())

  useEffect(() => {
    if (focusCap !== null) setExpandedCaps(new Set([focusCap]))
  }, [focusCap])

  if (report.evidence.length === 0) return null

  return (
    <section className={css.section}>
      <details className={css.fold} open={focusCap !== null}>
        <summary className={css.foldSummary}>
          <span className={css.sectionTitleInline}>{t('evidence')}</span>
          <span className={css.countPill}>{filtered.length}</span>
          <span className={css.foldMeta}>
            {focusCap !== null ? t(capLabelKey(focusCap)) : t('evidence.grouped')}
          </span>
        </summary>
        <p className={css.sectionHint}>{t('evidence.hint')}</p>
        {focusCap !== null && (
          <button type="button" className={css.linkBtn} onClick={onClearFocus}>
            {t('evidence.clearFilter')}
          </button>
        )}
        <div className={css.evidenceGroups}>
          {capGroups.map(({ cap, rows }) => {
            const showAll = expandedCaps.has(cap) || focusCap === cap
            const primary = rows.filter(r => !isPresenceOnlyFsRead(r.snippet))
            const weak = rows.filter(r => isPresenceOnlyFsRead(r.snippet))
            const main = primary.length > 0 ? primary : rows
            const visible = showAll ? main : main.slice(0, EVIDENCE_PREVIEW)
            return (
              <div key={cap} className={css.evidenceGroup}>
                <div className={css.evidenceGroupHead}>
                  <span className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`]}`}>
                    {t(capLabelKey(cap))}
                  </span>
                  <span className={css.countPill}>{rows.length}</span>
                </div>
                <ul className={css.evidenceList}>
                  {visible.map((ev, i) => (
                    <li key={`${ev.file}:${ev.line}:${i}`} className={css.evidenceItem}>
                      <span className={css.evidenceMeta}>
                        <code>{ev.file}</code>:{ev.line}
                      </span>
                      <span className={css.evidenceSnippet}>{ev.snippet}</span>
                    </li>
                  ))}
                </ul>
                {main.length > EVIDENCE_PREVIEW && !showAll && (
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
                        <li key={`w-${ev.file}:${ev.line}:${i}`} className={css.evidenceItem}>
                          <span className={css.evidenceMeta}>
                            <code>{ev.file}</code>:{ev.line}
                          </span>
                          <span className={css.evidenceSnippet}>{ev.snippet}</span>
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            )
          })}
        </div>
      </details>
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

function CapabilityChips({
  caps,
  t,
  onSelect,
}: {
  caps: Capability[]
  t: T
  onSelect?: (cap: Capability) => void
}) {
  if (caps.length === 0) return <div className={css.muted}>{t('none')}</div>
  return (
    <div className={css.chips}>
      {caps.map(cap => (
        <button
          key={cap}
          type="button"
          className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`]} ${onSelect !== undefined ? css.chipBtn : ''}`}
          onClick={onSelect !== undefined ? () => onSelect(cap) : undefined}
          disabled={onSelect === undefined}
        >
          {t(capLabelKey(cap))}
        </button>
      ))}
    </div>
  )
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
    return (
      <li key={key} className={rowClass}>
        <span className={css.destKind}>{t(destKindKey(d.kind))}</span>
        <div className={css.destBody}>
          <div className={css.destValueLine}>
            <code className={css.destValue}>{d.value}</code>
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
        </div>
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
          <li key={i} className={`${css.destRow} ${css.destRowHigh}`}>
            <span className={css.destKind}>{t(`pathEscape.${p.kind}` as TrustKey)}</span>
            <div className={css.destBody}>
              <code className={css.destValue}>{p.value}</code>
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
            <span className={css.destKind}>{t(secretKindKey(s.kind))}</span>
            <div className={css.destBody}>
              <code className={css.destValue}>{s.value}</code>
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
  t,
  onAckChange,
}: {
  report: AuditReport
  ack?: TrustAckEntry
  t: T
  onAckChange: () => void
}) {
  const v = verdict(report, ack)
  const concernList = concerns(report)
  const drift = ackDrifted(report, ack)
  const [evidenceFocus, setEvidenceFocus] = useState<Capability | null>(null)
  const [ackLoading, setAckLoading] = useState(false)
  const [ackError, setAckError] = useState(false)
  const [explainLoading, setExplainLoading] = useState(false)
  const [explainText, setExplainText] = useState<string | null>(null)
  const [explainError, setExplainError] = useState(false)

  const postAck = async () => {
    setAckLoading(true)
    setAckError(false)
    try {
      const res = await fetch('/dsh-trust-check/ack', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: report.name }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
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
      <section className={`${css.decision} ${css[`decision-${v}`]}`}>
        <p className={css.action}>{t(actionKey(v))}</p>
        {drift && <div className={css.drift}>{t('drift.title')}</div>}
        {concernList.length > 0 && v !== 'expected' && (
          <div className={css.concerns}>
            <h3 className={css.concernTitle}>{t('concerns.title')}</h3>
            <ul className={css.concernList}>
              {concernList.map((item, i) => (
                <li key={i}>{concernLabel(item, t)}</li>
              ))}
            </ul>
          </div>
        )}
        <div className={css.actions}>
          {v === 'review' && (
            <button type="button" className={css.actionBtn} disabled={ackLoading} onClick={() => void postAck()}>
              {ackLoading ? t('ack.saving') : t('ack.accept')}
            </button>
          )}
          {v === 'red' && (
            <button type="button" className={css.actionBtnRisk} disabled={ackLoading} onClick={() => void postAck()}>
              {ackLoading ? t('ack.saving') : t('ack.acceptRisk')}
            </button>
          )}
          {(v === 'expected' || v === 'accepted') && (
            <button type="button" className={css.actionBtnSecondary} disabled={ackLoading} onClick={() => void revokeAck()}>
              {t('ack.revoke')}
            </button>
          )}
          <button type="button" className={css.actionBtnSecondary} disabled={explainLoading} onClick={() => void explain()}>
            {explainLoading ? t('explain.loading') : t('explain.button')}
          </button>
        </div>
        {ackError && <div className={css.errorInline}>{t('ack.error')}</div>}
        {explainError && <div className={css.muted}>{t('explain.error')}</div>}
        {explainText !== null && (
          <div className={css.explainBox}>
            <div className={css.muted}>{t('explain.disclaimer')}</div>
            <p className={css.explainText}>{explainText}</p>
          </div>
        )}
      </section>

      <div className={css.scanStack}>
        <section className={css.section}>
          <header className={css.sectionHead}>
            <h3 className={css.sectionTitle}>{t('capabilities')}</h3>
          </header>
          <CapabilityChips caps={report.capabilities} t={t} onSelect={cap => setEvidenceFocus(cap)} />
        </section>

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
              <a className={css.repoLink} href={report.repository} target="_blank" rel="noreferrer">
                {report.repository}
              </a>
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

        <EvidencePanel report={report} t={t} focusCap={evidenceFocus} onClearFocus={() => setEvidenceFocus(null)} />
      </div>
    </div>
  )
}

function PluginRow({
  report,
  ack,
  t,
  expanded,
  onToggle,
  onAckChange,
}: {
  report: AuditReport
  ack?: TrustAckEntry
  t: T
  expanded: boolean
  onToggle: () => void
  onAckChange: () => void
}) {
  const v = verdict(report, ack)
  const previewCaps = topCapabilities(report, 3)

  return (
    <article className={`${css.plugin} ${css[`verdict-${v}`]}`}>
      <button type="button" className={css.pluginToggle} aria-expanded={expanded} onClick={onToggle}>
        <span className={css.toggleMain}>
          <span className={css.nameLine}>
            <span className={css.name}>{report.name}</span>
            <span className={css.version}>{report.version}</span>
          </span>
          <span className={`${css.statusBadge} ${css[`badge-${v}`]}`}>{t(verdictKey(v))}</span>
        </span>
        {previewCaps.length > 0 && (
          <span className={css.previewChips}>
            {previewCaps.map(cap => (
              <span key={cap} className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`]}`}>
                {t(capLabelKey(cap))}
              </span>
            ))}
          </span>
        )}
        <span className={css.srOnly}>{expanded ? t('collapsePlugin') : t('expandPlugin')}</span>
      </button>
      {expanded && (
        <PluginCardBody report={report} ack={ack} t={t} onAckChange={onAckChange} />
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
    <div className={css.root}>
      <div className={css.head}>
        <div className={css.headText}>
          <h2 className={css.title}>{t('settings.title')}</h2>
          <p className={css.intro}>{t('intro')}</p>
          <details className={css.help}>
            <summary>{t('howToRead.title')}</summary>
            <p>{t('howToRead.body')}</p>
            <p className={css.muted}>{t('postInstall.note')}</p>
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

      {error && <div className={css.error}>{t('loadError')}</div>}

      {!error && normalizedReport !== null && normalizedReport.plugins.length === 0 && (
        <div className={css.empty}>{t('empty')}</div>
      )}

      {normalizedReport !== null && normalizedReport.plugins.map(plugin => (
        <PluginRow
          key={plugin.name}
          report={normalizeAuditReport(plugin)}
          ack={normalizedReport.acks?.[plugin.name]}
          t={t}
          expanded={expanded.has(plugin.name)}
          onToggle={() => togglePlugin(plugin.name)}
          onAckChange={() => void refresh()}
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
    </div>
  )
}
