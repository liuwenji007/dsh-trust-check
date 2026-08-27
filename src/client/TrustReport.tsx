/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Decision-first layout: verdict, shape, scan dimensions, evidence, ack, explain.
 */
import { useEffect, useMemo, useState } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse, Capability, InjectionKind, TrustAckEntry } from '../core/types.ts'
import {
  ackDrifted,
  capabilityTier,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  groupEvidenceByFile,
  groupInjections,
  topCapabilities,
  verdict,
  type Concern,
  type Verdict,
} from '../core/present.ts'
import { normalizeAuditReport, normalizeAuditResponse } from '../core/ack-fingerprint.ts'
import type { TrustKey } from './locales.ts'
import type { createTrustStore } from './stores.ts'
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

const EVIDENCE_PREVIEW = 2

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
  if (v === 'review') return 'verdict.review'
  if (v === 'expected') return 'verdict.expected'
  return 'verdict.clear'
}

function actionKey(v: Verdict): TrustKey {
  if (v === 'red') return 'action.red'
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
  const destinations = report.destinations ?? []
  if (destinations.length === 0) {
    return (
      <div className={css.scanRow}>
        <div className={css.subTitle}>{t('destinations')}</div>
        <div className={css.muted}>{t('destinations.none')}</div>
      </div>
    )
  }
  return (
    <div className={css.scanRow}>
      <div className={css.subTitle}>{t('destinations')}</div>
      <div className={css.muted}>{t('destinations.literal')}</div>
      <ul className={css.shapeList}>
        {destinations.map((d, i) => (
          <li key={i}>
            <span className={css.shapeKind}>{t(destKindKey(d.kind))}</span>
            <code>{d.value}</code>
          </li>
        ))}
      </ul>
    </div>
  )
}

function SecretTouchesPanel({ report, t }: { report: AuditReport; t: T }) {
  const secretTouches = report.secretTouches ?? []
  if (secretTouches.length === 0) return null
  return (
    <div className={css.scanRow}>
      <div className={css.subTitle}>{t('secretTouches')}</div>
      <ul className={css.shapeList}>
        {secretTouches.map((s, i) => (
          <li key={i}>
            <span className={css.shapeKind}>{t(secretKindKey(s.kind))}</span>
            <code>{s.value}</code>
          </li>
        ))}
      </ul>
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
  const filtered = focusCap === null
    ? report.evidence
    : report.evidence.filter(e => e.capability === focusCap)
  const fileGroups = useMemo(() => groupEvidenceByFile(filtered), [filtered])
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (focusCap !== null && fileGroups.length > 0) {
      setExpandedFiles(new Set(fileGroups.map(g => g.file)))
    }
  }, [focusCap, fileGroups])

  if (report.evidence.length === 0) return null

  return (
    <details className={css.fold} open={focusCap !== null}>
      <summary className={css.foldSummary}>
        {t('evidence')} ({report.evidence.length}) · {t('evidence.byFile')}
      </summary>
      <div className={css.evidenceGroups}>
        {fileGroups.map(({ file, rows }) => {
          const showAll = expandedFiles.has(file)
          const visible = showAll ? rows : rows.slice(0, EVIDENCE_PREVIEW)
          return (
            <div key={file} className={css.evidenceGroup}>
              <div className={css.evidenceGroupHead}>
                <code>{file}</code>
                <span className={css.muted}>{rows.length}</span>
              </div>
              <ul className={css.evidenceList}>
                {visible.map((ev, i) => (
                  <li key={i} className={css.evidenceItem}>
                    <span className={css.evidenceMeta}>{ev.line} · {t(capLabelKey(ev.capability))}</span>
                    <span className={css.evidenceSnippet}>{ev.snippet}</span>
                  </li>
                ))}
              </ul>
              {rows.length > EVIDENCE_PREVIEW && !showAll && (
                <button
                  type="button"
                  className={css.linkBtn}
                  onClick={() => setExpandedFiles(prev => new Set(prev).add(file))}
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
  const [explainLoading, setExplainLoading] = useState(false)
  const [explainText, setExplainText] = useState<string | null>(null)
  const [explainError, setExplainError] = useState(false)

  const postAck = async () => {
    setAckLoading(true)
    try {
      const res = await fetch('/dsh-trust-check/ack', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: report.name }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      onAckChange()
    } finally {
      setAckLoading(false)
    }
  }

  const revokeAck = async () => {
    setAckLoading(true)
    try {
      const res = await fetch(`/dsh-trust-check/ack?name=${encodeURIComponent(report.name)}`, {
        method: 'DELETE',
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      onAckChange()
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
      <div className={css.decision}>
        <p className={css.action}>{t(actionKey(v))}</p>
        {drift && <div className={css.drift}>{t('drift.title')}</div>}
        {concernList.length > 0 && v !== 'expected' && (
          <div className={css.concerns}>
            <div className={css.subTitle}>{t('concerns.title')}</div>
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
          {v === 'expected' && (
            <button type="button" className={css.actionBtnSecondary} disabled={ackLoading} onClick={() => void revokeAck()}>
              {t('ack.revoke')}
            </button>
          )}
          <button type="button" className={css.actionBtnSecondary} disabled={explainLoading} onClick={() => void explain()}>
            {explainLoading ? t('explain.loading') : t('explain.button')}
          </button>
        </div>
        {explainError && <div className={css.muted}>{t('explain.error')}</div>}
        {explainText !== null && (
          <div className={css.explainBox}>
            <div className={css.muted}>{t('explain.disclaimer')}</div>
            <p className={css.explainText}>{explainText}</p>
          </div>
        )}
      </div>

      <div className={css.scanRow}>
        <div className={css.subTitle}>{t('capabilities')}</div>
        <CapabilityChips caps={report.capabilities} t={t} onSelect={cap => setEvidenceFocus(cap)} />
      </div>

      <DestinationsPanel report={report} t={t} />
      <SecretTouchesPanel report={report} t={t} />
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
    return `${normalizedReport.plugins.length} ${t('overview.plugins')} · ${counts.red} ${t('verdict.red')} · ${counts.review} ${t('verdict.review')} · ${counts.expected} ${t('verdict.expected')} · ${counts.clear} ${t('verdict.clear')}`
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
          <div className={css.subTitle}>{t('errors.title')}</div>
          <div className={css.muted}>{t('errors.hint')}</div>
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
