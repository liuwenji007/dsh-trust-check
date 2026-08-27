/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Decision-first layout: verdict, concerns, scan dimensions, then evidence.
 */
import { useEffect, useMemo, useState } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse, Capability, InjectionKind } from '../core/types.ts'
import {
  capabilityTier,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  groupEvidence,
  groupInjections,
  topCapabilities,
  verdict,
  type Concern,
  type Verdict,
} from '../core/present.ts'
import type { TrustKey } from './locales.ts'
import type { createTrustStore } from './stores.ts'
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

const EVIDENCE_PREVIEW = 3

function defaultExpandedNames(plugins: AuditReport[]): Set<string> {
  const names = new Set<string>()
  for (const plugin of plugins) {
    if (verdict(plugin) === 'red') names.add(plugin.name)
  }
  if (names.size === 0) {
    const firstReview = plugins.find(plugin => verdict(plugin) === 'review')
    if (firstReview !== undefined) names.add(firstReview.name)
  }
  return names
}

function verdictKey(v: Verdict): TrustKey {
  if (v === 'red') return 'verdict.red'
  if (v === 'review') return 'verdict.review'
  return 'verdict.clear'
}

function actionKey(v: Verdict): TrustKey {
  if (v === 'red') return 'action.red'
  if (v === 'review') return 'action.review'
  return 'action.clear'
}

function capLabelKey(cap: Capability): TrustKey {
  return `cap.${cap}` as TrustKey
}

function concernLabel(concern: Concern, t: T): string {
  if (concern.code === 'raw') return concern.detail ?? ''
  return t(`concern.${concern.code}` as TrustKey)
}

function injKindKey(kind: InjectionKind): TrustKey {
  return `injKind.${kind}` as TrustKey
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

function EvidencePanel({
  report,
  t,
  focusCap,
}: {
  report: AuditReport
  t: T
  focusCap: Capability | null
}) {
  const grouped = useMemo(() => groupEvidence(report.evidence), [report.evidence])
  const [expandedGroups, setExpandedGroups] = useState<Set<Capability>>(new Set())

  useEffect(() => {
    if (focusCap !== null) setExpandedGroups(prev => new Set(prev).add(focusCap))
  }, [focusCap])

  if (report.evidence.length === 0) return null

  const entries = [...grouped.entries()].sort(
    (a, b) => b[1].length - a[1].length,
  )

  return (
    <details className={css.fold} open={focusCap !== null}>
      <summary className={css.foldSummary}>
        {t('evidence')} ({report.evidence.length}) · {t('evidence.grouped')}
      </summary>
      <div className={css.evidenceGroups}>
        {entries.map(([cap, rows]) => {
          const showAll = expandedGroups.has(cap)
          const visible = showAll ? rows : rows.slice(0, EVIDENCE_PREVIEW)
          return (
            <div key={cap} className={css.evidenceGroup} data-cap={cap}>
              <div className={css.evidenceGroupHead}>
                <span className={`${css.chip} ${css[`tier-${capabilityTier(cap)}`]}`}>{t(capLabelKey(cap))}</span>
                <span className={css.muted}>{rows.length}</span>
              </div>
              <ul className={css.evidenceList}>
                {visible.map((ev, i) => (
                  <li key={i} className={css.evidenceItem}>
                    <code>{ev.file}:{ev.line}</code>
                    <span className={css.evidenceSnippet}>{ev.snippet}</span>
                  </li>
                ))}
              </ul>
              {rows.length > EVIDENCE_PREVIEW && !showAll && (
                <button
                  type="button"
                  className={css.linkBtn}
                  onClick={() => setExpandedGroups(prev => new Set(prev).add(cap))}
                >
                  {t('evidence.showAll')} ({rows.length})
                </button>
              )}
            </div>
          )
        })}
      </div>
    </details>
  )
}

function InjectionPanel({ report, t }: { report: AuditReport; t: T }) {
  const grouped = groupInjections(report)
  const count = report.injections.length
  const tokens = report.injectedTokensEstimate

  if (count === 0) {
    return (
      <div className={css.scanRow}>
        <div className={css.subTitle}>{t('injections')}</div>
        <div className={css.muted}>{t('noInjection')}</div>
      </div>
    )
  }

  const summaryParts = [`${count} ${t('injections.count')}`]
  if (tokens > 0) summaryParts.push(`~${tokens} ${t('injectedTokens')}`)

  return (
    <details className={css.fold}>
      <summary className={css.foldSummary}>
        <span className={css.subTitleInline}>{t('injections')}</span>
        <span className={css.muted}>{summaryParts.join(' · ')}</span>
      </summary>
      <div className={css.injectionGroups}>
        {[...grouped.entries()].map(([kind, findings]) => (
          <div key={kind} className={css.injectionGroup}>
            <div className={css.injKindHead}>{t(injKindKey(kind))}</div>
            <ul className={css.list}>
              {findings.map((inj, i) => (
                <li key={i} className={css.injPath}>{formatInjectionDetail(inj.detail)}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </details>
  )
}

function PluginCardBody({
  report,
  t,
}: {
  report: AuditReport
  t: T
}) {
  const v = verdict(report)
  const concernList = concerns(report)
  const [evidenceFocus, setEvidenceFocus] = useState<Capability | null>(null)

  return (
    <div className={css.cardBody}>
      <div className={css.decision}>
        <p className={css.action}>{t(actionKey(v))}</p>
        {concernList.length > 0 && (
          <div className={css.concerns}>
            <div className={css.subTitle}>{t('concerns.title')}</div>
            <ul className={css.concernList}>
              {concernList.map((item, i) => (
                <li key={i}>{concernLabel(item, t)}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className={css.scanRow}>
        <div className={css.subTitle}>{t('capabilities')}</div>
        <CapabilityChips
          caps={report.capabilities}
          t={t}
          onSelect={cap => setEvidenceFocus(cap)}
        />
      </div>

      <InjectionPanel report={report} t={t} />

      <div className={css.scanRow}>
        <div className={css.subTitle}>{t('source')}</div>
        <div className={css.meta}>
          {report.pinned
            ? <span className={css.ok}>{t('pinned')}</span>
            : <span className={css.warn}>{t('unpinned')}</span>}
          {report.repository === undefined && <span className={css.warn}>{t('noRepo')}</span>}
          {report.hasBuildScript && <span className={css.warn}>{t('buildScript')}</span>}
          {report.repository !== undefined && (
            <a className={css.repoLink} href={report.repository} target="_blank" rel="noreferrer">
              {report.repository}
            </a>
          )}
        </div>
      </div>

      <EvidencePanel report={report} t={t} focusCap={evidenceFocus} />
    </div>
  )
}

function PluginRow({
  report,
  t,
  expanded,
  onToggle,
}: {
  report: AuditReport
  t: T
  expanded: boolean
  onToggle: () => void
}) {
  const v = verdict(report)
  const previewCaps = topCapabilities(report, 3)

  return (
    <article className={`${css.plugin} ${css[`verdict-${v}`]}`}>
      <button
        type="button"
        className={css.pluginToggle}
        aria-expanded={expanded}
        onClick={onToggle}
      >
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
      {expanded && <PluginCardBody report={report} t={t} />}
    </article>
  )
}

export function TrustReport({ useStore, actions, t }: TrustReportProps) {
  const report = useStore(s => s.report)
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
      setExpanded(defaultExpandedNames(data.plugins))
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (report === null) void refresh()
    else if (expanded.size === 0 && report.plugins.length > 0) {
      setExpanded(defaultExpandedNames(report.plugins))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const overview = useMemo(() => {
    if (report === null || report.plugins.length === 0) return null
    const counts = countVerdicts(report.plugins)
    return `${report.plugins.length} ${t('overview.plugins')} · ${counts.red} ${t('verdict.red')} · ${counts.review} ${t('verdict.review')} · ${counts.clear} ${t('verdict.clear')}`
  }, [report, t])

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

      {!error && report !== null && report.plugins.length === 0 && (
        <div className={css.empty}>{t('empty')}</div>
      )}

      {report !== null && report.plugins.map(plugin => (
        <PluginRow
          key={plugin.name}
          report={plugin}
          t={t}
          expanded={expanded.has(plugin.name)}
          onToggle={() => togglePlugin(plugin.name)}
        />
      ))}

      {report !== null && report.errors.length > 0 && (
        <section className={css.errors}>
          <div className={css.subTitle}>{t('errors.title')}</div>
          <div className={css.muted}>{t('errors.hint')}</div>
          <ul className={css.list}>
            {report.errors.map((err, i) => (
              <li key={i}>{err.name}: {err.message}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
