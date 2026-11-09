/**
 * The trust-check mark as a React glyph for `settings.section.icon` (dsh 0.2.2+).
 * Geometry stays in trust-mark.ts so the CSS-mask stand-in and this seat stay
 * in lockstep.
 */
import type { CSSProperties } from 'react'
import {
  MARK_HANDLE,
  MARK_LENS,
  MARK_PUZZLE,
  MARK_STROKE,
  MARK_STROKE_DETAIL,
  MARK_VIEW_BOX,
} from './trust-mark.ts'

/** Nav / heading mark; colour follows `currentColor`. */
export function TrustLogo({ size = 16, style }: {
  size?: number
  style?: CSSProperties
}) {
  const { cx, cy, r } = MARK_LENS
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${MARK_VIEW_BOX} ${MARK_VIEW_BOX}`}
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      style={style}
    >
      <path d={MARK_PUZZLE} strokeWidth={MARK_STROKE} />
      <circle cx={cx} cy={cy} r={r} strokeWidth={MARK_STROKE_DETAIL} />
      <path d={MARK_HANDLE} strokeWidth={MARK_STROKE_DETAIL} />
    </svg>
  )
}
