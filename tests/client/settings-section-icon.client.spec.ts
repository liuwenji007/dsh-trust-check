// @vitest-environment jsdom
/**
 * dsh 0.2.2 wraps every settings-nav glyph and adds `settings.section.icon`.
 * The stand-in (hide `button > svg`, paint a mask) then leaves the gear beside
 * the mark — #15. Hosts that declare the slot must receive the mark through it
 * and must not also install the stand-in.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'

// Optional peer; not installed in this checkout. apply() only needs a handle.
vi.mock('@deepseek-ai/dsh-client-store', () => ({
  defineStore: () => ({}),
}))

const { apply } = await import('../../src/client/index.ts')
const { TrustLogo } = await import('../../src/client/TrustLogo.tsx')

const STYLESHEET = 'style[data-plugin-css="dsh-trust-check/settings-nav-icon"]'

interface Registration {
  options: Record<string, unknown>
  render: (props?: { size?: number }) => unknown
}

function host(declared: readonly string[], late: string[] = []) {
  const registrations: Registration[] = []
  const slots = new Set(declared)
  const waiting = new Map<string, () => unknown>()
  apply({
    effect: (run: () => unknown) => { run() },
    get: () => undefined,
    locale: {
      register: () => () => {},
      t: () => 'settings.nav',
    },
    slots: {
      inject: (slot: string, register: () => unknown) => {
        if (slots.has(slot)) register()
        else if (late.includes(slot)) waiting.set(slot, register)
      },
      register: (options: Record<string, unknown>, render: Registration['render']) => {
        registrations.push({ options, render })
        return () => {}
      },
    },
  } as Parameters<typeof apply>[0])
  return {
    registrations,
    arrive: (slot: string) => { waiting.get(slot)?.() },
  }
}

const iconOf = (registrations: Registration[]) =>
  registrations.find(entry => entry.options.name === 'settings.section.icon')

afterEach(() => {
  document.querySelectorAll(STYLESHEET).forEach(tag => tag.remove())
})

describe('settings nav icon on dsh 0.2.2 (#15)', () => {
  it('registers the trust mark under the section id and does not paint a second glyph', () => {
    const { registrations } = host(['settings.section', 'settings.section.icon'])

    const icon = iconOf(registrations)
    expect(icon?.options.id).toBe('trust')
    expect(icon?.render({ size: 20 })).toEqual(createElement(TrustLogo, { size: 20 }))
    expect(document.head.querySelector(STYLESHEET)).toBeNull()
  })

  it('keeps the stand-in glyph on hosts that have no icon slot', () => {
    const { registrations } = host(['settings.section'])

    expect(iconOf(registrations)).toBeUndefined()
    expect(document.head.querySelector(STYLESHEET)).not.toBeNull()
  })

  it('retires the stand-in once the icon slot shows up after mount', () => {
    const { registrations, arrive } = host(['settings.section'], ['settings.section.icon'])
    expect(document.head.querySelector(STYLESHEET)).not.toBeNull()

    arrive('settings.section.icon')

    expect(iconOf(registrations)?.options.id).toBe('trust')
    expect(document.head.querySelector(STYLESHEET)).toBeNull()
  })
})
