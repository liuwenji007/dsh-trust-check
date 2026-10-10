/**
 * Resolve an opaque dialog plate from the settings host.
 * Cards in this page are intentionally transparent, so walking up may still
 * find nothing; then the plate is chosen from the ink luminance.
 */

function parseCssRgb(value: string): { r: number, g: number, b: number, a: number } | null {
  const legacy = value.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)(?:\s*,\s*([\d.]+))?\s*\)$/i)
  if (legacy !== null) {
    return {
      r: Number(legacy[1]),
      g: Number(legacy[2]),
      b: Number(legacy[3]),
      a: legacy[4] === undefined ? 1 : Number(legacy[4]),
    }
  }
  const modern = value.match(/^rgba?\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+%?))?\s*\)$/i)
  if (modern !== null) {
    const alpha = modern[4]
    return {
      r: Number(modern[1]),
      g: Number(modern[2]),
      b: Number(modern[3]),
      a: alpha === undefined
        ? 1
        : alpha.endsWith('%')
          ? Number(alpha.slice(0, -1)) / 100
          : Number(alpha),
    }
  }
  return null
}

export function isOpaqueCssColor(value: string): boolean {
  if (value === 'transparent' || value === '') return false
  const rgb = parseCssRgb(value)
  if (rgb !== null) return rgb.a >= 0.95
  if (/^#[0-9a-f]{6}$/i.test(value)) return true
  if (/^#[0-9a-f]{8}$/i.test(value)) {
    return Number.parseInt(value.slice(7, 9), 16) >= 242
  }
  if (/^#[0-9a-f]{3}$/i.test(value)) return true
  return false
}

/** Light ink means a dark host; dark ink means a light host. */
export function plateFromInk(color: string): string {
  const rgb = parseCssRgb(color)
  if (rgb === null) return '#ffffff'
  const luminance = (0.2126 * rgb.r + 0.7152 * rgb.g + 0.0722 * rgb.b) / 255
  return luminance > 0.55 ? '#1a1a1a' : '#ffffff'
}

function isDarkCssColor(value: string): boolean {
  const rgb = parseCssRgb(value)
    ?? (/^#[0-9a-f]{6}$/i.test(value)
      ? {
          r: Number.parseInt(value.slice(1, 3), 16),
          g: Number.parseInt(value.slice(3, 5), 16),
          b: Number.parseInt(value.slice(5, 7), 16),
          a: 1,
        }
      : null)
  if (rgb === null) return false
  return (0.2126 * rgb.r + 0.7152 * rgb.g + 0.0722 * rgb.b) / 255 < 0.45
}

export interface DialogTheme {
  color?: string
  background: string
  /** Native checkboxes, radios, and scrollbars follow this. */
  scheme: 'light' | 'dark'
}

export function resolveDialogTheme(root: HTMLElement | null): DialogTheme {
  if (root === null) return { background: '#ffffff', scheme: 'light' }
  const color = getComputedStyle(root).color
  let node: HTMLElement | null = root
  while (node !== null) {
    const background = getComputedStyle(node).backgroundColor
    if (isOpaqueCssColor(background)) {
      return { color, background, scheme: isDarkCssColor(background) ? 'dark' : 'light' }
    }
    node = node.parentElement
  }
  const background = plateFromInk(color)
  return { color, background, scheme: isDarkCssColor(background) ? 'dark' : 'light' }
}
