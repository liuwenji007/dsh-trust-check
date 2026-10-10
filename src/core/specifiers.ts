/**
 * Static relative import/require specifiers. Shared by the collector (which
 * then reads the target) and the runtime-context walk (which only labels
 * files already in `sources`).
 */

const RELATIVE_SPECIFIERS = [
  /\bfrom\s+['"](\.[^'"]+)['"]/g,
  /\bfrom\s+`(\.[^`$]+)`/g,
  /\bimport\s+['"](\.[^'"]+)['"]/g,
  /\bimport\s+`(\.[^`$]+)`/g,
  /\bimport\s*\(\s*['"](\.[^'"]+)['"]/g,
  /\bimport\s*\(\s*`(\.[^`$]+)`/g,
  /\brequire\s*\(\s*['"](\.[^'"]+)['"]/g,
  /\brequire\s*\(\s*`(\.[^`$]+)`/g,
]

/** Relative specifiers in comment-stripped source. Bare packages are ignored. */
export function extractRelativeSpecifiers(stripped: string): string[] {
  const out: string[] = []
  for (const pattern of RELATIVE_SPECIFIERS) {
    for (const match of stripped.matchAll(pattern)) {
      if (match[1] !== undefined) out.push(match[1])
    }
  }
  return out
}
