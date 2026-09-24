/**
 * The trust-check mark in the settings navigation (puzzle + glass + pulse).
 *
 * The settings shell picks nav glyphs from a closed list of section ids
 * (`models`, `agent-presets`, `plugins`) and falls back to its own gear for
 * every other id; `settings.section` projects only `id` / `order` / `label`,
 * so a registrant has no icon to pass. Third-party sections therefore wear
 * the gear unless they claim their own row — same pattern as dsh-market.
 *
 * Scope, deliberately narrow:
 *
 * - only the row whose visible text equals this plugin's own localized
 *   section label is marked; no shell structure is touched;
 * - the marker and the injected stylesheet belong to a `ctx.effect`, so they
 *   are removed with the fiber;
 * - a locale switch re-claims the row through the MutationObserver.
 *
 * Delete this module (and its call in index.ts) the day `settings.section`
 * grows an `icon` field.
 */
import { trustMarkSvg } from './trust-mark.ts'

/** Marks the one nav row this plugin owns. */
export const NAV_ICON_MARKER = 'data-dsh-trust-check-nav-icon'

/**
 * The nav rows of the settings dialog. The shell renders each
 * `settings.section` entry as a `<button>` inside the panel's `<nav>`.
 */
export const NAV_ROW_SELECTOR = '[role="dialog"] nav button'

/**
 * Glyph box in px. The shell renders every nav icon at this size and ships no
 * media query at all.
 */
export const NAV_ICON_SIZE = 16

/**
 * The mark as standalone SVG for a CSS `mask-image`.
 *
 * Delegates to the owner mark in trust-mark.ts (stroke black; colour comes
 * from `background-color: currentColor` on the host element).
 */
export function trustMaskSvg(): string {
  return trustMarkSvg()
}

/** The mask URL for the mark (encoded at runtime, never hand-escaped). */
export function trustMaskUrl(svg: string = trustMaskSvg()): string {
  return `data:image/svg+xml,${encodeURIComponent(svg)}`
}

/**
 * Whether a nav row is this plugin's own.
 *
 * Pure: the row whose visible text is the section label the shell is
 * currently projecting. An empty label matches nothing.
 */
export function isOwnNavRow(rowText: string | null | undefined, wantedLabel: string | null | undefined): boolean {
  const wanted = String(wantedLabel ?? '').trim()
  if (wanted.length === 0) return false
  return String(rowText ?? '').trim() === wanted
}

/** Stylesheet for the marked row: hide the shell's gear, draw the mark. */
export function navIconCss(maskUrl: string): string {
  return [
    `[${NAV_ICON_MARKER}] > svg { display: none; }`,
    `[${NAV_ICON_MARKER}]::before {`,
    `  content: '';`,
    `  flex: none;`,
    `  width: ${NAV_ICON_SIZE}px;`,
    `  height: ${NAV_ICON_SIZE}px;`,
    `  background-color: currentColor;`,
    `  -webkit-mask-image: url("${maskUrl}");`,
    `  mask-image: url("${maskUrl}");`,
    `  -webkit-mask-repeat: no-repeat;`,
    `  mask-repeat: no-repeat;`,
    `  -webkit-mask-position: center;`,
    `  mask-position: center;`,
    `  -webkit-mask-size: ${NAV_ICON_SIZE}px ${NAV_ICON_SIZE}px;`,
    `  mask-size: ${NAV_ICON_SIZE}px ${NAV_ICON_SIZE}px;`,
    `}`,
  ].join('\n')
}

/** The slice of the client context this feature needs. */
export interface NavIconContext {
  effect(callback: () => unknown, label?: string): void
}

/**
 * Install the nav glyph.
 *
 * @param ctx - client context, for effect ownership.
 * @param resolveLabel - this plugin's current section label (the same thunk
 *   the `settings.section` registration passes), re-read on every sync so a
 *   locale switch is picked up without re-registering.
 */
export function installSettingsNavIcon(ctx: NavIconContext, resolveLabel: () => string): void {
  if (typeof document === 'undefined') return

  ctx.effect(() => {
    const tag = document.createElement('style')
    tag.dataset.plugin = 'dsh-trust-check'
    tag.dataset.pluginCss = 'dsh-trust-check/settings-nav-icon'
    tag.textContent = navIconCss(trustMaskUrl())
    document.head.appendChild(tag)

    let disposed = false
    let scheduled = false

    const sync = () => {
      scheduled = false
      if (disposed) return
      const wanted = resolveLabel()
      for (const row of document.querySelectorAll(NAV_ROW_SELECTOR)) {
        if (isOwnNavRow(row.textContent, wanted)) row.setAttribute(NAV_ICON_MARKER, '')
        else row.removeAttribute(NAV_ICON_MARKER)
      }
    }

    const schedule = () => {
      if (scheduled || disposed) return
      scheduled = true
      queueMicrotask(sync)
    }

    sync()
    const observer = new MutationObserver(schedule)
    observer.observe(document.body, { childList: true, subtree: true, characterData: true })

    return () => {
      disposed = true
      observer.disconnect()
      for (const row of document.querySelectorAll(`[${NAV_ICON_MARKER}]`)) row.removeAttribute(NAV_ICON_MARKER)
      tag.remove()
    }
  }, 'dsh-trust-check: settings nav icon')
}
