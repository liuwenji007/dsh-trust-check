/**
 * Render the AI reading-aid reply as a small Markdown subset.
 * Bold, inline code, lists, and paragraphs only — no HTML, links, or images.
 */
import type { ReactNode } from 'react'
import css from './TrustReport.module.css'

function inlineNodes(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = []
  const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*)/g
  let last = 0
  let match: RegExpExecArray | null
  let index = 0
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) {
      nodes.push(text.slice(last, match.index))
    }
    const token = match[0]
    if (token.startsWith('`')) {
      nodes.push(
        <code key={`${keyPrefix}-c${index}`} className={css.explainCode}>
          {token.slice(1, -1)}
        </code>,
      )
    } else {
      nodes.push(
        <strong key={`${keyPrefix}-b${index}`} className={css.explainStrong}>
          {token.slice(2, -2)}
        </strong>,
      )
    }
    last = match.index + token.length
    index += 1
  }
  if (last < text.length) nodes.push(text.slice(last))
  return nodes
}

function isBullet(line: string): boolean {
  return /^[-*]\s+\S/.test(line)
}

function bulletText(line: string): string {
  return line.replace(/^[-*]\s+/, '')
}

/** A line that is only bold markdown becomes a short section title. */
function isTitleLine(line: string): boolean {
  return /^\*\*[^*\n]+\*\*$/.test(line.trim())
}

export function ExplainMarkdown({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, '\n').trim().split('\n')
  const children: ReactNode[] = []
  let index = 0
  let key = 0

  while (index < lines.length) {
    const raw = lines[index] ?? ''
    const line = raw.trimEnd()
    if (line.trim() === '') {
      index += 1
      continue
    }

    if (isBullet(line.trim())) {
      const items: string[] = []
      while (index < lines.length && isBullet((lines[index] ?? '').trim())) {
        items.push(bulletText((lines[index] ?? '').trim()))
        index += 1
      }
      const listKey = key
      key += 1
      children.push(
        <ul key={`ul-${listKey}`} className={css.explainList}>
          {items.map((item, itemIndex) => (
            <li key={`li-${listKey}-${itemIndex}`}>
              {inlineNodes(item, `l${listKey}-${itemIndex}`)}
            </li>
          ))}
        </ul>,
      )
      continue
    }

    if (isTitleLine(line)) {
      const titleKey = key
      key += 1
      children.push(
        <p key={`h-${titleKey}`} className={css.explainTitle}>
          {line.trim().slice(2, -2)}
        </p>,
      )
      index += 1
      continue
    }

    const paragraph: string[] = []
    while (index < lines.length) {
      const current = lines[index] ?? ''
      if (current.trim() === '') break
      if (isBullet(current.trim()) || isTitleLine(current)) break
      paragraph.push(current)
      index += 1
    }
    const paragraphKey = key
    key += 1
    const rendered: ReactNode[] = []
    for (let lineIndex = 0; lineIndex < paragraph.length; lineIndex += 1) {
      if (lineIndex > 0) rendered.push(<br key={`br-${paragraphKey}-${lineIndex}`} />)
      rendered.push(...inlineNodes(paragraph[lineIndex] ?? '', `p${paragraphKey}-${lineIndex}`))
    }
    children.push(
      <p key={`p-${paragraphKey}`} className={css.explainParagraph}>
        {rendered}
      </p>,
    )
  }

  return <div className={css.explainText}>{children}</div>
}
