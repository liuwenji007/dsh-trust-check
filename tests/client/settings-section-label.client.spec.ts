// @vitest-environment jsdom
/**
 * The settings shell reads a section label once, while it builds the nav, and
 * keeps it: a label resolved before the dictionaries or the language were in
 * place then stays in that language for the life of the page, while the page
 * itself follows the live locale. Re-registering the section on
 * `locale/change` is the refresh the shell reacts to.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

// Optional peer; not installed in this checkout. apply() only needs a handle.
vi.mock('@deepseek-ai/dsh-client-store', () => ({
  defineStore: () => ({}),
}))

const { apply } = await import('../../src/client/index.ts')
const { UI_zh, UI_ru, UI_en } = await import('../../src/client/locales.ts')

interface Entry {
  options: { name: string; id: string; label: () => string }
  render: unknown
}

/**
 * Host double: a locale face whose active id can move, plus one event bus.
 * @param active - active locale id the face reports at first.
 */
function host(active: string) {
  const entries: Entry[] = []
  const disposed: number[] = []
  const listeners = { 'locale/change': [] as Array<() => void> }
  const face = {
    getLocale: () => ({ active }),
    // No dictionary answer: forces the language-based fallback under test.
    t: () => 'settings.nav',
  }
  const ctx = {
    effect: (run: () => unknown) => { run() },
    get: (service: string) => (service === 'locale' ? face : undefined),
    on: (event: 'locale/change', listener: () => void) => {
      listeners[event].push(listener)
      return () => { listeners[event] = listeners[event].filter(entry => entry !== listener) }
    },
    locale: { register: () => () => {} },
    slots: {
      inject: (_slot: string, register: () => unknown) => { register() },
      register: (options: Entry['options'], render: unknown) => {
        if (options.name !== 'settings.section') return () => {}
        const index = entries.push({ options, render }) - 1
        return () => { disposed.push(index) }
      },
    },
  }
  apply(ctx as unknown as Parameters<typeof apply>[0])
  return {
    entries,
    disposed,
    switchTo: (next: string) => {
      active = next
      for (const listener of [...listeners['locale/change']]) listener()
    },
  }
}

afterEach(() => {
  document.querySelectorAll('style[data-plugin="dsh-trust-check"]').forEach(tag => tag.remove())
})

describe('settings section label follows the locale', () => {
  it('registers the section once, with the label of the locale known at boot', () => {
    const { entries } = host('zh')

    expect(entries.map(entry => entry.options.name)).toEqual(['settings.section'])
    expect(entries[0]?.options.label()).toBe(UI_zh['settings.nav'])
  })

  it('re-registers the section on a locale change so the frozen label is re-read', () => {
    const { entries, disposed, switchTo } = host('zh')
    expect(entries).toHaveLength(1)

    switchTo('ru')

    expect(entries).toHaveLength(2)
    expect(disposed).toEqual([0])
    expect(entries[1]?.options.label()).toBe(UI_ru['settings.nav'])
    expect(entries[1]?.options.id).toBe('trust')
  })

  it('keeps the live label on every later switch', () => {
    const { entries, switchTo } = host('ru')
    expect(entries[0]?.options.label()).toBe(UI_ru['settings.nav'])

    switchTo('en')
    expect(entries.at(-1)?.options.label()).toBe(UI_en['settings.nav'])
  })
})
