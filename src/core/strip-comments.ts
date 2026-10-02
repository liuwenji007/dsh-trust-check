/**
 * Comment blanking for literal scanning. Comments are not shipped behaviour,
 * yet bundlers keep JSDoc, so an example URL in a doc block otherwise reads as
 * a real destination.
 *
 * Tokenization comes from js-tokens so regex literals and template
 * interpolations stay in sync with the source. An unclosed template, block
 * comment, or regex — or a tokenizer error — returns the original text, so a
 * failure adds comments back into the scan instead of deleting real code.
 */

import jsTokens from 'js-tokens'

const CODE_FILE = /\.(?:[cm]?[jt]sx?)$/i
const JSX_FILE = /\.[jt]sx$/i
const COMMENT_TYPES = new Set(['MultiLineComment', 'SingleLineComment', 'HashbangComment'])

/** Only code files have comment syntax; prose and skill files are scanned raw. */
export function isCodeFile(file: string): boolean {
  return CODE_FILE.test(file)
}

export interface CommentBlank {
  text: string
  /** True when `text` is the original source because tokenization could not be trusted. */
  fallback: boolean
}

function blanksComment(value: string): string {
  return value.replace(/[^\n\r\u2028\u2029]/g, ' ')
}

function unclosedSpan(token: { type: string, closed?: boolean }): boolean {
  if (token.closed !== false) return false
  return token.type === 'NoSubstitutionTemplate'
    || token.type === 'TemplateTail'
    || token.type === 'MultiLineComment'
    || token.type === 'RegularExpressionLiteral'
    || token.type === 'JSXString'
}

/**
 * Blank comments, preserving every line break so reported line numbers still
 * point at the original source. `file` selects JSX tokenization for `.jsx` / `.tsx`.
 */
export function blankComments(text: string, file?: string): CommentBlank {
  try {
    const parts: string[] = []
    let fallback = false
    const tokens = JSX_FILE.test(file ?? '') ? jsTokens(text, { jsx: true }) : jsTokens(text)
    for (const token of tokens) {
      if (unclosedSpan(token)) fallback = true
      parts.push(COMMENT_TYPES.has(token.type) ? blanksComment(token.value) : token.value)
    }
    const joined = parts.join('')
    if (fallback || joined.length !== text.length) return { text, fallback: true }
    return { text: joined, fallback: false }
  } catch {
    return { text, fallback: true }
  }
}

/**
 * Blank `//` and block comments. Same result as `blankComments`, without the
 * fallback flag. Callers that can record coverage should use `blankComments`.
 */
export function stripComments(text: string, file?: string): string {
  return blankComments(text, file).text
}
