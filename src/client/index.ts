/**
 * dsh-trust-check browser half: one `settings.section` page that renders the
 * audit report fetched from the node half's route.
 */
import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import { TrustReport } from './TrustReport.tsx'
import { createTrustStore } from './stores.ts'
import { en, zh, type TrustKey } from './locales.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Trust report copy. */
    trust: TrustKey
  }
}

/** Dictionary namespace owned by this plugin. */
const NS = 'trust'

/** Required services: the slot registry and report copy. */
export const inject = ['slots', 'locale']

type LocaleFace = {
  language?: string
  locale?: string
  t?: (ns: string, key: string) => string
  text?: (ns: string, key: string) => string
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
  const lang = locale?.language ?? locale?.locale ?? ''
  return lang.toLowerCase().startsWith('en') ? en['settings.nav'] : zh['settings.nav']
}

/**
 * Client plugin body: register dictionaries and the settings page.
 * @param ctx - client root context.
 */
export function apply(ctx: ClientContext): void {
  const handle = createTrustStore()
  const store = () => handle

  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-trust-check: dictionaries')

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'trust',
    order: 80,
    locale: NS,
    label: () => sectionLabel(ctx),
    store,
  }, TrustReport))
}
