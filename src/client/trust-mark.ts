/**
 * The trust-check mark as geometry rather than a component.
 *
 * Source of truth: `assets/trust-nav-mark.svg` — a 64×64 monoline mark
 * (puzzle + glass; ECG path kept but not drawn). Settings-nav paints it as a CSS mask; paths are
 * inlined so the client bundle needs no raw-asset loader. The suite asserts
 * lockstep with the asset.
 *
 * Drawn as strokes (not a Potrace fill dump): a 1254pt filled tracing
 * collapses into a speck under a 16px CSS mask.
 */

/** The square every coordinate in the mark is expressed in. */
export const MARK_VIEW_BOX = 64

/** Stroke weight for the puzzle outline. */
export const MARK_STROKE = 5

/** Stroke weight for the glass detail (finer than the puzzle). */
export const MARK_STROKE_DETAIL = 3.6

/**
 * Puzzle outline (plugin), left open where the lens overlaps it.
 * Coordinates from the Figma export (`trust-nav-mark 1.svg`).
 */
export const MARK_PUZZLE = 'M47.6 27V20C47.6 18.4 46.4 17.2 44.8 17.2H36.3C35.3 17.2 35.1 16.2 35.5 15.2C35.9168 14.1825 36.0768 13.078 35.9658 11.984C35.8548 10.89 35.4762 9.84016 34.8635 8.92708C34.2508 8.01399 33.4228 7.26574 32.4526 6.74835C31.4823 6.23095 30.3996 5.96031 29.3 5.96031C28.2004 5.96031 27.1177 6.23095 26.1474 6.74835C25.1772 7.26574 24.3492 8.01399 23.7365 8.92708C23.1238 9.84016 22.7452 10.89 22.6342 11.984C22.5232 13.078 22.6832 14.1825 23.1 15.2C23.5 16.2 23.3 17.2 22.3 17.2H14.6C13 17.2 11.8 18.4 11.8 20V29C11.8 30 11.4 30.4 10.8 30C9.87197 29.5992 8.85886 29.4353 7.85178 29.523C6.8447 29.6108 5.87522 29.9474 5.0305 30.5027C4.18578 31.058 3.49231 31.8146 3.01243 32.7043C2.53256 33.594 2.28133 34.5891 2.28133 35.6C2.28133 36.6109 2.53256 37.6059 3.01243 38.4957C3.49231 39.3854 4.18578 40.1419 5.0305 40.6972C5.87522 41.2525 6.8447 41.5892 7.85178 41.677C8.85886 41.7647 9.87197 41.6008 10.8 41.2C11.4 40.8 11.8 41.2 11.8 42.2V49.2C11.8 50.8 13 52 14.6 52H30.3'

/** Magnifying-glass lens (Figma exported a circle path; kept as native circle). */
export const MARK_LENS = { cx: '45.3', cy: '44', r: '12.3' } as const

/** Magnifying-glass handle. */
export const MARK_HANDLE = 'M54.8 53.3 L61.8 58.2'

/**
 * ECG pulse inside the lens (kept for easy restore; not drawn while hidden).
 */
export const MARK_PULSE = 'M37 45 H40.6 L41.8 46.8 L45.6 38.5 L47.6 49.8 L49.6 46 H53.6'

/**
 * The mark as standalone SVG for a CSS `mask-image`.
 *
 * Stroke is pure black on purpose: a mask reads alpha only, and the visible
 * colour comes from the element's `background-color: currentColor`.
 */
export function trustMarkSvg(): string {
  const { cx, cy, r } = MARK_LENS
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '
    + `${MARK_VIEW_BOX} ${MARK_VIEW_BOX}" fill="none" stroke="#000"`
    + ' stroke-linecap="round" stroke-linejoin="round">'
    + `<path d="${MARK_PUZZLE}" stroke-width="${MARK_STROKE}"/>`
    + `<circle cx="${cx}" cy="${cy}" r="${r}" stroke-width="${MARK_STROKE_DETAIL}"/>`
    + `<path d="${MARK_HANDLE}" stroke-width="${MARK_STROKE_DETAIL}"/>`
    + '</svg>'
}
