/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { isOpaqueCssColor, plateFromInk, resolveDialogTheme } from '../../src/client/dialog-theme.ts'

describe('dialog theme plate', () => {
  it('treats near-opaque and solid colors as usable plates', () => {
    expect(isOpaqueCssColor('rgb(255, 255, 255)')).toBe(true)
    expect(isOpaqueCssColor('rgba(12, 12, 12, 0.96)')).toBe(true)
    expect(isOpaqueCssColor('rgb(12 12 12 / 96%)')).toBe(true)
    expect(isOpaqueCssColor('#112233')).toBe(true)
    expect(isOpaqueCssColor('transparent')).toBe(false)
    expect(isOpaqueCssColor('rgba(0, 0, 0, 0)')).toBe(false)
    expect(isOpaqueCssColor('rgba(0, 0, 0, 0.4)')).toBe(false)
  })

  it('picks a dark plate for light ink and a light plate for dark ink', () => {
    expect(plateFromInk('rgb(245, 245, 245)')).toBe('#1a1a1a')
    expect(plateFromInk('rgb(20, 20, 20)')).toBe('#ffffff')
  })

  it('uses an ancestor surface when the settings root itself is transparent', () => {
    const host = document.createElement('div')
    host.style.backgroundColor = 'rgb(248, 248, 246)'
    host.style.color = 'rgb(24, 24, 24)'
    const root = document.createElement('div')
    root.style.backgroundColor = 'transparent'
    root.style.color = 'rgb(24, 24, 24)'
    host.append(root)
    document.body.append(host)
    expect(resolveDialogTheme(root)).toEqual({
      color: 'rgb(24, 24, 24)',
      background: 'rgb(248, 248, 246)',
    })
    host.remove()
  })

  it('falls back to an ink-based plate when every ancestor is transparent', () => {
    const root = document.createElement('div')
    root.style.color = 'rgb(240, 240, 240)'
    root.style.backgroundColor = 'transparent'
    document.body.append(root)
    expect(resolveDialogTheme(root).color).toBe('rgb(240, 240, 240)')
    expect(resolveDialogTheme(root).background).toBe('#1a1a1a')
    root.remove()
  })
})
