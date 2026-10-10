/**
 * In-memory detection feedback. The draft is not stored, and nothing is submitted
 * from this page: public issues open the markdown issue editor; private reports
 * open the advisory page with no draft on the URL.
 */
import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { TrustKey } from './locales.ts'
import { resolveDialogTheme } from './dialog-theme.ts'
import { pageVersion } from './page-version.ts'
import {
  buildFeedbackDraft,
  draftClipboardText,
  emptyAttachments,
  issueCreateUrl,
  privateReportUrl,
  publicIssueAllowed,
  type FeedbackAttachments,
  type FeedbackDraft,
  type FeedbackKind,
  type FrozenFinding,
} from './feedback-draft.ts'
import css from './FeedbackDialog.module.css'

type T = (key: TrustKey) => string

const KINDS: FeedbackKind[] = ['inaccurate', 'missed', 'unclear']

/** One tab stop per radio group: the checked radio, or the first if none is checked. */
function tabbables(root: HTMLElement): HTMLElement[] {
  const nodes = [...root.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
  )]
  const radios = new Map<string, HTMLInputElement>()
  const picked: HTMLElement[] = []
  for (const node of nodes) {
    if (node.hasAttribute('disabled') || node.tabIndex < 0) continue
    if (node instanceof HTMLInputElement && node.type === 'radio') {
      const chosen = radios.get(node.name)
      if (node.checked || chosen === undefined) radios.set(node.name, node)
      continue
    }
    picked.push(node)
  }
  return [...picked, ...radios.values()].sort((a, b) => {
    const pos = a.compareDocumentPosition(b)
    if (pos & Node.DOCUMENT_POSITION_FOLLOWING) return -1
    if (pos & Node.DOCUMENT_POSITION_PRECEDING) return 1
    return 0
  })
}

/** Mark ancestor siblings inert. Leave any element that was already inert alone. */
function inertOutside(keep: HTMLElement): () => void {
  const changed: HTMLElement[] = []
  let current: HTMLElement | null = keep
  while (current !== null && current.parentElement !== null) {
    const parent: HTMLElement = current.parentElement
    for (const sibling of parent.children) {
      if (sibling === current || !(sibling instanceof HTMLElement)) continue
      if (sibling.hasAttribute('inert')) continue
      sibling.setAttribute('inert', '')
      changed.push(sibling)
    }
    if (parent === document.body) break
    current = parent
  }
  return () => {
    for (const el of changed) el.removeAttribute('inert')
  }
}

export function FeedbackDialog({
  finding,
  themeRoot,
  returnFocus,
  t,
  onClose,
}: {
  finding: FrozenFinding
  themeRoot: HTMLElement | null
  returnFocus: HTMLElement | null
  t: T
  onClose: () => void
}) {
  const titleId = useId()
  const errorId = useId()
  const kindName = useId()
  const dialogRef = useRef<HTMLDivElement>(null)
  const backdropRef = useRef<HTMLDivElement>(null)
  const previewSource = useRef<string | null>(null)
  const onKeyRef = useRef<(event: KeyboardEvent) => void>(() => {})
  const returnFocusRef = useRef(returnFocus)
  returnFocusRef.current = returnFocus
  const [kind, setKind] = useState<FeedbackKind | null>(finding.entry === 'evidence' ? 'inaccurate' : null)
  const [note, setNote] = useState('')
  const [attachments, setAttachments] = useState<FeedbackAttachments>(emptyAttachments)
  const [ordinaryGap, setOrdinaryGap] = useState(false)
  const [step, setStep] = useState<'form' | 'preview'>('form')
  const [draft, setDraft] = useState<FeedbackDraft | null>(null)
  const [noteError, setNoteError] = useState(false)
  const [kindError, setKindError] = useState(false)
  const [discarding, setDiscarding] = useState(false)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')

  const dirty = note.trim() !== ''
    || ordinaryGap
    || attachments.pluginIdentity
    || attachments.installSource
    || attachments.pathAndSnippet
    || attachments.detectedValues
    || step === 'preview'

  const theme = resolveDialogTheme(themeRoot)
  const discardReturn = useRef<HTMLElement | null>(null)
  const stepMounted = useRef(false)

  useEffect(() => {
    const node = dialogRef.current?.querySelector<HTMLElement>('[data-autofocus]')
    node?.focus()
  }, [])

  useEffect(() => {
    if (!stepMounted.current) {
      stepMounted.current = true
      return
    }
    dialogRef.current?.querySelector<HTMLElement>('[data-step-focus]')?.focus()
  }, [step])

  useEffect(() => {
    const root = dialogRef.current
    if (root === null) return
    if (discarding) {
      root.querySelector<HTMLElement>('[data-discard-focus]')?.focus()
      return
    }
    const back = discardReturn.current
    discardReturn.current = null
    if (back === null) return
    if (back.isConnected && root.contains(back)) back.focus()
    else root.querySelector<HTMLElement>('[data-step-focus]')?.focus()
  }, [discarding])

  const requestClose = () => {
    if (!dirty) {
      onClose()
      return
    }
    discardReturn.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    setDiscarding(true)
  }

  onKeyRef.current = (event: KeyboardEvent) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      if (discarding) setDiscarding(false)
      else requestClose()
      return
    }
    if (event.key !== 'Tab') return
    const root = dialogRef.current
    if (root === null) return
    const items = tabbables(root)
    const first = items[0]
    const last = items[items.length - 1]
    if (first === undefined || last === undefined) return
    const active = document.activeElement
    if (!(active instanceof HTMLElement) || !root.contains(active)) {
      event.preventDefault()
      ;(event.shiftKey ? last : first).focus()
      return
    }
    if (event.shiftKey && active === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && active === last) {
      event.preventDefault()
      first.focus()
    }
  }

  useLayoutEffect(() => {
    const root = backdropRef.current
    const undo = root === null ? () => {} : inertOutside(root)
    const onKey = (event: KeyboardEvent) => onKeyRef.current(event)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      undo()
      returnFocusRef.current?.focus()
    }
  }, [])

  const labels = {
    kind: t('feedback.field.kind'),
    capability: t('feedback.field.capability'),
    rule: t('feedback.field.rule'),
    schema: t('feedback.field.schema'),
    page: t('feedback.field.page'),
    scannerMissing: t('feedback.scannerMissing'),
    situation: t('feedback.field.situation'),
    plugin: t('feedback.field.plugin'),
    source: t('feedback.field.source'),
    repository: t('feedback.field.repository'),
    path: t('feedback.field.path'),
    snippet: t('feedback.field.snippet'),
    values: t('feedback.field.values'),
  }

  const previewSourceKey = (nextKind: FeedbackKind) => JSON.stringify({
    kind: nextKind,
    note,
    pluginIdentity: attachments.pluginIdentity,
    installSource: attachments.installSource,
    pathAndSnippet: attachments.pathAndSnippet,
    detectedValues: attachments.detectedValues,
  })

  const goPreview = () => {
    const missingKind = kind === null
    const missingNote = note.trim() === ''
    setKindError(missingKind)
    setNoteError(missingNote)
    if (missingKind || missingNote || kind === null) return
    const source = previewSourceKey(kind)
    setCopyState('idle')
    setStep('preview')
    if (draft !== null && previewSource.current === source) return
    previewSource.current = source
    setDraft(buildFeedbackDraft({
      kind,
      kindLabel: t(`feedback.kind.${kind}`),
      finding,
      note,
      attachments,
      pageVersion: pageVersion(),
      labels,
    }))
  }

  const updateDraft = (patch: Partial<FeedbackDraft>) => {
    setDraft(current => current === null ? current : { ...current, ...patch })
    setCopyState('idle')
  }

  const copyDraft = async () => {
    if (draft === null) return
    const text = draftClipboardText(draft)
    try {
      if (navigator.clipboard?.writeText === undefined) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(text)
      setCopyState('copied')
    } catch {
      setCopyState('failed')
      dialogRef.current?.querySelector<HTMLTextAreaElement>('[data-draft-body]')?.focus()
    }
  }

  const issue = draft === null ? null : issueCreateUrl(draft.title, draft.body)
  const allowPublic = kind !== null && publicIssueAllowed(kind, ordinaryGap)

  const copyOverflowDraft = () => {
    if (issue?.overflow !== true || draft === null) return
    const text = draftClipboardText(draft)
    const write = navigator.clipboard?.writeText
    if (write === undefined) {
      setCopyState('failed')
      dialogRef.current?.querySelector<HTMLTextAreaElement>('[data-draft-body]')?.focus()
      return
    }
    void write.call(navigator.clipboard, text).then(() => {
      setCopyState('copied')
    }, () => {
      setCopyState('failed')
      dialogRef.current?.querySelector<HTMLTextAreaElement>('[data-draft-body]')?.focus()
    })
  }

  const toggle = (key: keyof FeedbackAttachments) => {
    setAttachments(current => ({ ...current, [key]: !current[key] }))
  }

  const capabilityLabel = finding.capability === undefined || finding.capability === ''
    ? undefined
    : (t(`cap.${finding.capability}` as TrustKey) ?? finding.capability)
  const findingLabel = finding.entry === 'plugin'
    ? t('feedback.context.plugin')
    : [capabilityLabel, finding.ruleId].filter(Boolean).join(' · ')
  const versionLabel = `schemaVersion ${finding.schemaVersion ?? '—'} · ${pageVersion()}`
  const privatePrimary = kind === 'missed'

  return createPortal(
    <div ref={backdropRef} className={css.backdrop}>
      <div
        ref={dialogRef}
        className={css.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={noteError || kindError ? errorId : undefined}
        style={{
          color: theme.color,
          background: theme.background,
          colorScheme: theme.scheme,
        }}
      >
        <header className={css.header}>
          <div className={css.headText}>
            <h2 id={titleId} className={css.title}>{t('feedback.title')}</h2>
            <p className={css.subtitle}>
              {t(finding.entry === 'evidence' ? 'feedback.subtitle.evidence' : 'feedback.subtitle.plugin')}
            </p>
          </div>
          <button type="button" className={css.close} aria-label={t('feedback.close')} onClick={requestClose}>
            <span aria-hidden="true">×</span>
          </button>
        </header>

        <div className={css.body}>
          <ol className={css.steps} aria-label={t('feedback.steps')}>
            <li className={step === 'form' ? css.stepActive : undefined} aria-current={step === 'form' ? 'step' : undefined}>
              <span className={css.stepNo}>01</span>{t('feedback.step.fill')}
            </li>
            <li className={step === 'preview' ? css.stepActive : undefined} aria-current={step === 'preview' ? 'step' : undefined}>
              <span className={css.stepNo}>02</span>{t('feedback.step.preview')}
            </li>
          </ol>

        {step === 'form' ? (
          <div>
            <dl className={css.context}>
              <div>
                <dt>{t('feedback.context.finding')}</dt>
                <dd>{findingLabel === '' ? '—' : findingLabel}</dd>
              </div>
              <div>
                <dt>{t('feedback.context.version')}</dt>
                <dd>{versionLabel}</dd>
              </div>
            </dl>

            <fieldset className={css.fieldset}>
              <legend className={css.label}>{t('feedback.kind.legend')}</legend>
              <div className={css.types}>
                {KINDS.map((value, index) => (
                  <label key={value} className={`${css.type} ${kind === value ? css.typeActive : ''}`}>
                    <input
                      type="radio"
                      className={css.typeInput}
                      name={kindName}
                      value={value}
                      checked={kind === value}
                      data-autofocus={index === 0 ? '' : undefined}
                      onChange={() => {
                        setKind(value)
                        setKindError(false)
                        if (value !== 'missed') setOrdinaryGap(false)
                      }}
                    />
                    <span>{t(`feedback.kind.${value}`)}</span>
                  </label>
                ))}
              </div>
            </fieldset>

            <label className={css.field}>
              <span className={css.label}>{t('feedback.note')}</span>
              <textarea
                value={note}
                data-step-focus=""
                aria-invalid={noteError}
                onChange={event => {
                  setNote(event.target.value)
                  setNoteError(false)
                }}
              />
            </label>

            <fieldset className={css.fieldset}>
              <legend className={css.label}>{t('feedback.attach.legend')}</legend>
              <label className={css.choice}>
                <input type="checkbox" checked={attachments.pluginIdentity} onChange={() => toggle('pluginIdentity')} />
                {t('feedback.attach.plugin')}
              </label>
              <label className={css.choice}>
                <input type="checkbox" checked={attachments.installSource} onChange={() => toggle('installSource')} />
                {t('feedback.attach.source')}
              </label>
              <label className={css.choice}>
                <input
                  type="checkbox"
                  checked={attachments.pathAndSnippet}
                  disabled={finding.file === undefined && finding.snippet === undefined}
                  onChange={() => toggle('pathAndSnippet')}
                />
                {t('feedback.attach.path')}
              </label>
              <label className={css.choice}>
                <input
                  type="checkbox"
                  checked={attachments.detectedValues}
                  disabled={finding.destinations.length === 0}
                  onChange={() => toggle('detectedValues')}
                />
                {t('feedback.attach.values')}
              </label>
            </fieldset>

            {kind === 'missed' && (
              <label className={`${css.choice} ${css.gap}`}>
                <input type="checkbox" checked={ordinaryGap} onChange={event => setOrdinaryGap(event.target.checked)} />
                {t('feedback.gap')}
              </label>
            )}

            <p className={css.privacy}>{t('feedback.privacy')}</p>

            <div id={errorId} className={css.live} role="status">
              {kindError && <p>{t('feedback.kind.required')}</p>}
              {noteError && <p>{t('feedback.note.required')}</p>}
            </div>
          </div>
        ) : draft !== null && issue !== null && (
          <div>
            <label className={css.field}>
              <span className={css.label}>{t('feedback.titleField')}</span>
              <input
                data-step-focus=""
                value={draft.title}
                onChange={event => updateDraft({ title: event.target.value })}
              />
            </label>
            <label className={css.field}>
              <span className={css.label}>{t('feedback.bodyField')}</span>
              <textarea
                className={css.draftBody}
                data-draft-body=""
                value={draft.body}
                onChange={event => updateDraft({ body: event.target.value })}
              />
            </label>
            {kind === 'missed' && <p className={css.note}>{t('feedback.privateNote')}</p>}
            {allowPublic && <p className={css.note}>{t('feedback.sendWarning')}</p>}
            {issue.overflow && <p className={css.note}>{t('feedback.overflow')}</p>}
            <div className={css.live} role="status">
              {copyState === 'copied' && <p>{t('feedback.copied')}</p>}
              {copyState === 'failed' && <p>{t('feedback.copyFailed')}</p>}
            </div>
          </div>
        )}
        </div>

        <footer className={css.footer}>
          {discarding ? (
            <div className={css.confirm} role="group" aria-label={t('feedback.discard.title')}>
              <p>{t('feedback.discard.title')}</p>
              <div className={css.footerGroup}>
                <button type="button" className={css.btn} onClick={onClose}>{t('feedback.discard.leave')}</button>
                <button
                  type="button"
                  className={`${css.btn} ${css.primary}`}
                  data-discard-focus=""
                  onClick={() => setDiscarding(false)}
                >
                  {t('feedback.discard.stay')}
                </button>
              </div>
            </div>
          ) : step === 'form' ? (
            <>
              <button type="button" className={css.btn} onClick={requestClose}>{t('feedback.cancel')}</button>
              <button type="button" className={`${css.btn} ${css.primary}`} onClick={goPreview}>
                {t('feedback.next')}
              </button>
            </>
          ) : issue !== null && (
            <>
              <button type="button" className={css.btn} onClick={() => setStep('form')}>{t('feedback.back')}</button>
              <div className={css.footerGroup}>
                <button type="button" className={css.btn} onClick={() => void copyDraft()}>{t('feedback.copy')}</button>
                {kind === 'missed' && (
                  <a
                    className={`${css.btn} ${privatePrimary ? css.primary : ''}`}
                    href={privateReportUrl()}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {t('feedback.private')}
                  </a>
                )}
                {allowPublic && (
                  <a
                    className={`${css.btn} ${privatePrimary ? '' : css.primary}`}
                    href={issue.href}
                    target="_blank"
                    rel="noreferrer"
                    onClick={copyOverflowDraft}
                  >
                    {t('feedback.github')}
                  </a>
                )}
              </div>
            </>
          )}
        </footer>
      </div>
    </div>,
    document.body,
  )
}
