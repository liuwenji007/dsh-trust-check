/**
 * Settings section: renders the cached audit report and offers a rescan.
 * Static code judgment, so every figure is reproducible from the evidence
 * listed under each plugin.
 */
import { useEffect, useState } from 'react'
import type { PropsLocale, PropsStore } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuditReport, AuditResponse } from '../core/types.ts'
import type { TrustKey } from './locales.ts'
import type { createTrustStore } from './stores.ts'
import css from './TrustReport.module.css'

export type TrustReportProps =
  & PropsStore<ReturnType<typeof createTrustStore>>
  & PropsLocale<'trust'>

type T = (key: TrustKey) => string

function statusKey(report: AuditReport): TrustKey {
  if (report.redLines.length > 0 || report.band === 'red') return 'statusRed'
  if (report.capabilities.length > 0 || report.band === 'yellow') return 'statusReview'
  return 'statusClear'
}

function CapabilityChips({ report, t }: { report: AuditReport; t: T }) {
  if (report.capabilities.length === 0) {
    return <div className={css.muted}>{t('none')}</div>
  }
  return (
    <div className={css.chips}>
      {report.capabilities.map(cap => (
        <span key={cap} className={`${css.chip} ${css[`cap-${cap}`]}`}>{cap}</span>
      ))}
    </div>
  )
}

function PluginCard({ report, t }: { report: AuditReport; t: T }) {
  const band = report.band
  const status = statusKey(report)
  return (
    <section className={`${css.card} ${css[`card-${band}`]}`}>
      <div className={css.cardHead}>
        <div className={css.nameLine}>
          <span className={css.name}>{report.name}</span>
          <span className={css.version}>{report.version}</span>
        </div>
        <span className={`${css.statusBadge} ${css[`status-${band}`]}`}>{t(status)}</span>
      </div>

      <div className={css.summary}>{report.summary}</div>
      <div className={css.scoreMeta}>
        {t('score.label')}: {report.score}
      </div>

      {report.redLines.length > 0 && (
        <div className={css.redLines}>
          <div className={css.subTitle}>{t('redLines')}</div>
          {report.redLines.map(line => (
            <div key={line} className={css.redLine}>⚠ {line}</div>
          ))}
        </div>
      )}

      <div className={css.section}>
        <div className={css.subTitle}>{t('capabilities')}</div>
        <CapabilityChips report={report} t={t} />
      </div>

      <div className={css.section}>
        <div className={css.subTitle}>{t('injections')}</div>
        {report.injections.length === 0 ? (
          <div className={css.muted}>{t('noInjection')}</div>
        ) : (
          <ul className={css.list}>
            {report.injections.map((inj, i) => (
              <li key={i} className={css.inj}>
                <span className={css.injKind}>{inj.kind}</span>
                <span>{inj.detail}</span>
              </li>
            ))}
          </ul>
        )}
        {report.injectedTokensEstimate > 0 && (
          <div className={css.muted}>{t('injectedTokens')}: ~{report.injectedTokensEstimate}</div>
        )}
      </div>

      <div className={css.section}>
        <div className={css.subTitle}>{t('source')}</div>
        <div className={css.meta}>
          {report.pinned ? <span className={css.ok}>{t('pinned')}</span> : <span className={css.warn}>{t('unpinned')}</span>}
          {report.repository === undefined && <span className={css.warn}>{t('noRepo')}</span>}
          {report.hasBuildScript && <span className={css.warn}>{t('buildScript')}</span>}
          {report.repository !== undefined && <span className={css.muted}>{report.repository}</span>}
        </div>
      </div>

      {report.evidence.length > 0 && (
        <details className={css.evidence}>
          <summary>{t('evidence')} ({report.evidence.length})</summary>
          <ul className={css.evidenceList}>
            {report.evidence.map((ev, i) => (
              <li key={i} className={css.evidenceItem}>
                <code>{ev.file}:{ev.line}</code>
                <span className={css.evidenceSnippet}>{ev.snippet}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}

export function TrustReport({ useStore, actions, t }: TrustReportProps) {
  const report = useStore(s => s.report)
  const fetchedAt = useStore(s => s.fetchedAt)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(false)

  const refresh = async () => {
    setLoading(true)
    setError(false)
    try {
      const response = await fetch('/dsh-trust-check/audit')
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json() as AuditResponse
      actions.setReport(data, Date.now())
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (report === null) void refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className={css.root}>
      <div className={css.head}>
        <div>
          <h2 className={css.title}>{t('settings.title')}</h2>
          <p className={css.intro}>{t('intro')}</p>
        </div>
        <button className={css.refresh} onClick={() => void refresh()} disabled={loading}>
          {loading ? t('refreshing') : t('refresh')}
        </button>
      </div>

      {fetchedAt !== null && <div className={css.muted}>{new Date(fetchedAt).toLocaleString()}</div>}

      {error && <div className={css.error}>{t('loadError')}</div>}

      {!error && report !== null && report.plugins.length === 0 && (
        <div className={css.empty}>{t('empty')}</div>
      )}

      {report !== null && report.plugins.map(plugin => (
        <PluginCard key={plugin.name} report={plugin} t={t} />
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
