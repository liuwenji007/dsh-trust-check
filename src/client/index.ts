/**
 * dsh-trust-check browser half: one `settings.section` page that renders the
 * audit report fetched from the node half's route.
 */
import { createElement as h } from 'react'
import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import { TrustReport } from './TrustReport.tsx'
import { TrustLogo } from './TrustLogo.tsx'
import { createTrustStore } from './stores.ts'
import { installSettingsNavIcon } from './settings-nav-icon.ts'
import { UI_en, UI_ru, UI_zh, type TrustKey } from './locales.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Trust report copy. */
    trust: TrustKey
  }

  /**
   * dsh 0.2.2+ nav glyph seat. Declared until published slots types catch
   * up; runtime detection is still `slots.inject`.
   */
  interface SlotMap {
    'settings.section.icon': {
      kind: 'list'
      scope: 'root'
      owner: { size?: number }
    }
  }
}

/** Dictionary namespace owned by this plugin. */
const NS = 'trust'

/** Required services: the slot registry and report copy. */
export const inject = ['slots', 'locale']

type LocaleFace = {
  language?: string
  locale?: string
  /** Published snapshot; the only field that names the active locale on its own. */
  getLocale?: () => { active?: string }
  t?: (ns: string, key: string) => string
  text?: (ns: string, key: string) => string
}

/**
 * The active locale id, snapshot first: `language` is absent until the
 * preference scope has answered, which is exactly the window the nav label is
 * first resolved in.
 * @param locale - optional locale face.
 * @returns a lowercase locale id, empty when nothing knows it yet.
 */
function activeLocale(locale: LocaleFace | undefined): string {
  const active = locale?.getLocale?.()?.active ?? locale?.language ?? locale?.locale ?? ''
  return String(active).toLowerCase()
}

/**
 * Nav label that follows the live UI language.
 * @param ctx - client context with an optional locale service.
 */
function sectionLabel(ctx: ClientContext): string {
  const locale = ctx.get('locale') as LocaleFace | undefined
  const translated = locale?.t?.(NS, 'settings.nav') ?? locale?.text?.(NS, 'settings.nav')
  if (typeof translated === 'string' && translated !== '' && translated !== 'settings.nav') {
    return translated
  }
  const lang = activeLocale(locale)
  if (lang.startsWith('ru')) return UI_ru['settings.nav']
  return lang.startsWith('en') ? UI_en['settings.nav'] : UI_zh['settings.nav']
}

/**
 * Client plugin body: register dictionaries and the settings page.
 * @param ctx - client root context.
 */
export function apply(ctx: ClientContext): void {
  const handle = createTrustStore()
  const store = () => handle

  // One dictionary per locale: the pinned client-locale types still list only
  // zh/en, while the host ships a wider built-in set (de, en, es, fr, ja, pt,
  // ru, zh), so the per-locale overload keeps `ru` typed and registered.
  ctx.effect(() => {
    const disposers = [
      ctx.locale.register(NS, 'zh', UI_zh),
      ctx.locale.register(NS, 'en', UI_en),
      ctx.locale.register(NS, 'ru', UI_ru),
    ]
    return () => {
      for (const dispose of disposers) dispose()
    }
  }, 'dsh-trust-check: dictionaries')

  // The section's nav glyph. Before dsh 0.2.2 the shell picked icons from its
  // own ids and a registration had nothing to pass, so this package claimed
  // its row and swapped the gear for the trust mark. 0.2.2 wraps that gear and
  // offers `settings.section.icon` (same id as the section); registering the
  // mark there is the one glyph, and leaving the stand-in up paints a second
  // one beside it (#15). The slot is the detection, and it can arrive with the
  // settings shell after the stand-in is already in place.
  let stopNavStandIn: (() => void) | undefined
  let hostPaintsNavIcon = false
  ctx.slots.inject('settings.section.icon', () => {
    hostPaintsNavIcon = true
    stopNavStandIn?.()
    stopNavStandIn = undefined
    const off = ctx.slots.register({
      name: 'settings.section.icon',
      id: 'trust',
    }, (owner: { size?: number } = {}) => h(TrustLogo, { size: owner.size ?? 16 }))
    return typeof off === 'function' ? off as () => void : () => {}
  })
  if (!hostPaintsNavIcon) stopNavStandIn = installSettingsNavIcon(ctx, () => sectionLabel(ctx))

  // The shell freezes a section's label when it builds the settings nav, so a
  // label taken in that first pass outlives every later locale change: the page
  // follows the live language while its own row in the list keeps the language
  // it was first read in. Dictionary registrations only bump the locale
  // revision and never emit `locale/change`, so this listens for the real
  // switch and re-registers the section, which is the refresh the shell reacts
  // to. Registering before the switch stays the inject's job.
  const section: { stop?: () => void } = {}

  const mountSection = () => {
    const registered = ctx.slots.register({
      name: 'settings.section',
      id: 'trust',
      order: 80,
      locale: NS,
      label: () => sectionLabel(ctx),
      store,
    }, TrustReport)
    section.stop = typeof registered === 'function' ? registered as () => void : () => {}
  }

  ctx.slots.inject('settings.section', () => {
    mountSection()
    return () => {
      section.stop?.()
      section.stop = undefined
    }
  })

  const on = (ctx as unknown as {
    on?: (event: 'locale/change', listener: () => void) => (() => void) | void
  }).on
  if (typeof on === 'function') {
    ctx.effect(() => {
      const stopListening = on.call(ctx, 'locale/change', () => {
        if (section.stop === undefined) return
        section.stop()
        mountSection()
      })
      return () => {
        if (typeof stopListening === 'function') stopListening()
      }
    }, 'dsh-trust-check: section label follows the locale')
  }
}
