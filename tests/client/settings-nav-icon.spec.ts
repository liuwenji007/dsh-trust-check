/**
 * Pure helpers for the settings-nav trust mark (owner SVG).
 * DOM install behaviour mirrors dsh-market; geometry is what we own here.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  isOwnNavRow,
  navIconCss,
  trustMaskSvg,
  trustMaskUrl,
  NAV_ICON_MARKER,
} from '../../src/client/settings-nav-icon.ts'
import {
  MARK_HANDLE,
  MARK_LENS,
  MARK_PUZZLE,
  MARK_STROKE,
  MARK_STROKE_DETAIL,
  MARK_VIEW_BOX,
  trustMarkSvg,
} from '../../src/client/trust-mark.ts'

describe('trust mark geometry', () => {
  it('embeds the owner monoline SVG for the CSS mask', () => {
    const svg = trustMaskSvg()
    expect(svg).toBe(trustMarkSvg())
    expect(svg).toContain(`viewBox="0 0 ${MARK_VIEW_BOX} ${MARK_VIEW_BOX}"`)
    expect(svg).toContain(`stroke-width="${MARK_STROKE}"`)
    expect(svg).toContain(`stroke-width="${MARK_STROKE_DETAIL}"`)
    expect(svg).toContain(MARK_PUZZLE)
    expect(svg).toContain(`cx="${MARK_LENS.cx}" cy="${MARK_LENS.cy}" r="${MARK_LENS.r}"`)
    expect(svg).toContain(MARK_HANDLE)
    expect(svg).not.toContain('M37 45')
    expect(svg).toContain('stroke="#000"')
    expect(svg).not.toContain('currentColor')
  })

  it('stays in lockstep with assets/trust-nav-mark.svg', () => {
    const asset = readFileSync(resolve('assets/trust-nav-mark.svg'), 'utf8')
    expect(asset).toContain(`viewBox="0 0 ${MARK_VIEW_BOX} ${MARK_VIEW_BOX}"`)
    expect(asset).toContain(`stroke-width="${MARK_STROKE}"`)
    expect(asset).toContain(`stroke-width="${MARK_STROKE_DETAIL}"`)
    expect(asset.replace(/\s+/g, ' ')).toContain(MARK_PUZZLE)
    expect(asset).toContain(`cx="${MARK_LENS.cx}" cy="${MARK_LENS.cy}" r="${MARK_LENS.r}"`)
    expect(asset).toContain(MARK_HANDLE)
    expect(asset).not.toContain('M37 45')
    // Asset keeps currentColor for standalone preview; mask forces #000.
    expect(asset).toContain('currentColor')
  })
})

describe('settings nav glyph helpers', () => {
  it('matches only the exact section label', () => {
    expect(isOwnNavRow('插件体检', '插件体检')).toBe(true)
    expect(isOwnNavRow('插件市场', '插件体检')).toBe(false)
    expect(isOwnNavRow('插件体检', '')).toBe(false)
    expect(isOwnNavRow('  Plugin Trust  ', 'Plugin Trust')).toBe(true)
  })

  it('hides the shell gear and paints through a currentColor mask', () => {
    const css = navIconCss(trustMaskUrl())
    expect(css).toContain(`[${NAV_ICON_MARKER}] > svg { display: none; }`)
    expect(css).toContain('background-color: currentColor')
    expect(css).toContain('-webkit-mask-image: url("data:image/svg+xml,')
    expect(css).toContain('mask-image: url("data:image/svg+xml,')
  })
})
