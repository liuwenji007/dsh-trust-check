/**
 * Just enough of a source map to answer "which dependency, if any, did this
 * generated line come from?" Column-accurate blame is not required: evidence
 * only has a line number. Display only.
 */

const VLQ_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function decodeVlq(text: string, index: number): { value: number; index: number } {
  let value = 0
  let shift = 0
  let continuation = true
  while (continuation && index < text.length) {
    const digit = VLQ_CHARS.indexOf(text[index] ?? '')
    index += 1
    if (digit < 0) break
    continuation = (digit & 32) !== 0
    value |= (digit & 31) << shift
    shift += 5
  }
  const negative = (value & 1) !== 0
  const magnitude = value >> 1
  return { value: negative ? -magnitude : magnitude, index }
}

/**
 * Package name after the last real `node_modules/` segment.
 * pnpm's `.pnpm/<pkg>@version/node_modules/<pkg>` keeps the inner name.
 */
export function packageFromSource(source: string): string | undefined {
  const parts = source.split(/[/\\]/)
  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i] !== 'node_modules') continue
    const next = parts[i + 1]
    if (next === undefined || next === '' || next === '.pnpm') continue
    if (next.startsWith('@')) {
      const name = parts[i + 2]
      if (name === undefined || name === '') return undefined
      return `${next}/${name}`
    }
    return next
  }
  return undefined
}

/**
 * 1-based generated line → dependency package, when that line's mappings
 * have a single clear dependency. A tie between two packages is omitted
 * rather than guessed. Undefined when the text is not a source map.
 */
export function linePackages(mapText: string): Map<number, string> | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(mapText) as unknown
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined
  const record = parsed as Record<string, unknown>
  if (!Array.isArray(record.sources) || typeof record.mappings !== 'string') return undefined
  const sources = record.sources.filter((source): source is string => typeof source === 'string')
  const out = new Map<number, string>()
  let sourceIndex = 0
  const lines = record.mappings.split(';')
  for (let line = 0; line < lines.length; line++) {
    const counts = new Map<string, number>()
    const segments = lines[line]?.split(',') ?? []
    for (const segment of segments) {
      if (segment === '') continue
      let index = 0
      const generated = decodeVlq(segment, index)
      index = generated.index
      if (index >= segment.length) continue
      const sourceDelta = decodeVlq(segment, index)
      index = sourceDelta.index
      sourceIndex += sourceDelta.value
      const pkg = packageFromSource(sources[sourceIndex] ?? '')
      if (pkg !== undefined) counts.set(pkg, (counts.get(pkg) ?? 0) + 1)
      if (index < segment.length) index = decodeVlq(segment, index).index
      if (index < segment.length) index = decodeVlq(segment, index).index
      if (index < segment.length) decodeVlq(segment, index)
    }
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1])
    const winner = ranked[0]
    const runner = ranked[1]
    if (winner !== undefined && (runner === undefined || winner[1] > runner[1])) {
      out.set(line + 1, winner[0])
    }
  }
  return out
}
