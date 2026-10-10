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

export function resolveDialogTheme(root: HTMLElement | null): { color?: string, background: string } {
  if (root === null) return { background: '#ffffff' }
  const color = getComputedStyle(root).color
  let node: HTMLElement | null = root
  while (node !== null) {
    const background = getComputedStyle(node).backgroundColor
    if (isOpaqueCssColor(background)) return { color, background }
    node = node.parentElement
  }
  return { color, background: plateFromInk(color) }
}
