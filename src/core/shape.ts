/**
 * Shape scanner: literal destinations, workspace path escapes, and secret touches.
 * Proves presence only; runtime-constructed URLs are invisible.
 */

import { isCodeFile, stripComments } from './strip-comments.ts'
import type {
  DestinationFinding,
  DestinationKind,
  PathEscapeFinding,
  PathEscapeKind,
  PluginInput,
  SecretTouchFinding,
  SecretTouchKind,
} from './types.ts'

export const MAX_DESTINATIONS = 20
export const MAX_SECRET_TOUCHES = 20
export const MAX_PATH_ESCAPES = 20

const URL_LITERAL = /['"`](https?:\/\/[^'"`\s]+)['"`]/g
/** Slash-leading string literals: may be HTTP routes or absolute FS paths. */
const SLASH_PATH = /['"`](\/[^'"`\s]+)['"`]/g
const IPV4_LITERAL = /['"`]((\d{1,3}\.){3}\d{1,3})(?:\/[^'"`]*)?['"`]/g
const ENV_SENSITIVE = /process\.env\.([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)/g
const SECRET_PATH = /~\/\.ssh|\.aws\/credentials|\.netrc|\.gnupg(?:\/|\\|$)|\.docker\/config\.json|\.kube\/config|\bid_rsa\b|\bid_ed25519\b/g
const CREDENTIALS_IMPORT = /(?:require\(|from\s+|import\s*\(\s*)['"](?:keychain|keytar|dotenv)['"]|\bkeychain\.\w+|\bkeytar\.\w+|\bdotenv\.config\b|\bctx\.credentials\b/g
const HOME_ESCAPE = /['"`](~\/[^'"`]+|\$\{?HOME\}?\/[^'"`]+)['"`]/g
const WIN_ABS = /['"`]([A-Za-z]:\\[^'"`]+)['"`]/g
/** Two or more `../` segments — likely leaving a package/workspace tree. */
const TRAVERSAL = /['"`]((?:\.\.\/|\.\.\\){2,}[^'"`]*)['"`]/g

/** Windows / cmd.exe style switches often mistaken for HTTP paths. */
const SHELL_SWITCH_PATHS = new Set([
  '/a', '/b', '/c', '/d', '/e', '/f', '/g', '/k', '/p', '/q', '/r', '/s', '/t', '/v', '/y',
  '/pid', '/im', '/fi',
])

/** Absolute filesystem roots that leave a typical project workspace. */
const FS_ROOT_PREFIX = /^\/(?:etc|usr|opt|home|Users|var|tmp|private|root|System|Library|Windows|Program Files|Applications)\b/

/**
 * RFC 2606 / 6761 reserved documentation hosts — not real outbound targets.
 *
 * Generic single-label names (`proxy`, `server`) do NOT belong here: they
 * resolve for real on a LAN with a DNS search domain, so listing them would
 * hide both the destination and its plaintext-HTTP red line. Doc examples are
 * excluded by blanking comments before the scan instead.
 */
const PLACEHOLDER_HOST_EXACT = new Set([
  'localhost',
  'local',
  'example',
  'example.com',
  'example.org',
  'example.net',
])

/** Documentation TLD only (`.test` / `.invalid` still count as outbound literals). */
const PLACEHOLDER_TLD = /\.example$/i

/**
 * Standards-body hosts that appear as XML/SVG namespace identifiers
 * (`xmlns="http://www.w3.org/2000/svg"`) rather than as requests. Matching on
 * the host rather than on nearby `xmlns` text is deliberate: an attacker
 * cannot register these, so the exemption cannot be borrowed, whereas a
 * syntactic check could be by writing `xmlns` beside an exfil URL.
 */
const IDENTIFIER_HOST_EXACT = new Set([
  'www.w3.org',
  'www.sitemaps.org',
  'schemas.xmlsoap.org',
  'purl.org',
  'json-schema.org',
])

/**
 * Harness loopback-style names. Shown as destinations (facts) but not as
 * plaintext-HTTP red lines. Exact hosts only — `fileserver.local` still flags.
 */
const HARNESS_INTERNAL_HOST_EXACT = new Set([
  'dsh.internal',
  'dsh.local',
  'dsh.localhost',
])

const RFC2606_EXAMPLE_DOMAINS = ['example.com', 'example.net', 'example.org'] as const

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]'
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/:\d+$/, '')
}

function isLoopbackIp(ip: string): boolean {
  return ip === '127.0.0.1' || ip.startsWith('127.')
}

/** Bind / unspecified address — not an outbound target. */
export function isUnspecifiedIp(ip: string): boolean {
  const v = ip.trim().toLowerCase()
  return v === '0.0.0.0' || v === '::' || v === '[::]'
}

function isRfc2606ExampleHost(host: string): boolean {
  const h = normalizeHost(host)
  for (const domain of RFC2606_EXAMPLE_DOMAINS) {
    if (h === domain || h.endsWith(`.${domain}`)) return true
  }
  return false
}

/** One-character labels are doc stubs (`http://x`), unlike resolvable names like `proxy`. */
function isSingleCharHost(host: string): boolean {
  return /^[a-z0-9]$/i.test(normalizeHost(host))
}

export function isHarnessInternalHost(host: string): boolean {
  return HARNESS_INTERNAL_HOST_EXACT.has(normalizeHost(host))
}

function classifyUrl(url: string): DestinationFinding['kind'] {
  try {
    const parsed = new URL(url)
    if (isLoopbackHost(parsed.hostname)) return 'loopback'
    if (parsed.protocol === 'http:') return 'http-host'
    return 'https-host'
  } catch {
    return 'https-host'
  }
}

function destinationKey(kind: DestinationFinding['kind'], value: string): string {
  return `${kind}:${value}`
}

/**
 * Truncation order. A hostile plugin can pad the top of its first file with
 * harmless literals, so the cap must drop the least interesting rows rather
 * than whatever comes last in source order — red lines are derived from the
 * capped list.
 */
const DESTINATION_RANK: Readonly<Record<DestinationKind, number>> = {
  ip: 0,
  'http-host': 1,
  'https-host': 2,
  loopback: 3,
  relative: 4,
}

const PATH_ESCAPE_RANK: Readonly<Record<PathEscapeKind, number>> = {
  home: 0,
  absolute: 1,
  'windows-abs': 2,
  traversal: 3,
}

const SECRET_TOUCH_RANK: Readonly<Record<SecretTouchKind, number>> = {
  path: 0,
  'env-key': 1,
  api: 2,
}

function dedupeByKey<T>(rows: T[], keyOf: (row: T) => string, max: number): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const row of rows) {
    const key = keyOf(row)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(row)
    if (out.length >= max) break
  }
  return out
}

/** Dedupe riskiest-first, keeping source order within one rank. */
function rankedDedupe<T>(
  rows: T[],
  keyOf: (row: T) => string,
  rankOf: (row: T) => number,
  max: number,
): T[] {
  const ordered = rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => rankOf(a.row) - rankOf(b.row) || a.index - b.index)
    .map(entry => entry.row)
  return dedupeByKey(ordered, keyOf, max)
}

/** Line looks like a private/special IP range table, not an outbound target. */
export function isIpRangeTableLine(line: string): boolean {
  const ipCount = [...line.matchAll(/['"`]((\d{1,3}\.){3}\d{1,3})['"`]/g)].length
  if (ipCount >= 2) return true
  return /\binRange\s*\(|\bisPrivate|\bisReserved|\bipRange|specialRanges|PRIVATE_RANGES|CIDR/i.test(line)
}

/** Documentation / parser base hosts that are not real destinations. */
export function isPlaceholderHost(host: string): boolean {
  const h = normalizeHost(host)
  if (h === '') return true
  // Schema ellipsis: "https://..." in LLM prompt / docs examples.
  if (/^\.+$/.test(h)) return true
  if (isSingleCharHost(h)) return true
  if (PLACEHOLDER_HOST_EXACT.has(h)) return true
  if (isRfc2606ExampleHost(h)) return true
  if (PLACEHOLDER_TLD.test(h)) return true
  return false
}

/** Namespace/schema hosts that name a vocabulary instead of a request target. */
export function isIdentifierHost(host: string): boolean {
  return IDENTIFIER_HOST_EXACT.has(normalizeHost(host))
}

export function isPlaceholderUrl(url: string): boolean {
  try {
    return isPlaceholderHost(new URL(url).hostname)
  } catch {
    return false
  }
}

export function isShellSwitchPath(path: string): boolean {
  return SHELL_SWITCH_PATHS.has(path.toLowerCase())
}

export function isFsAbsolutePath(path: string): boolean {
  return FS_ROOT_PREFIX.test(path)
}

/**
 * Same-origin HTTP API routes (`/dsh-market/check`) are not network destinations
 * and are not workspace escapes — omit them from the report.
 */
export function isHttpRoutePath(path: string): boolean {
  if (path === '/' || path === '//' || path.startsWith('//')) return false
  if (isShellSwitchPath(path)) return false
  if (isFsAbsolutePath(path)) return false
  if (/^\/\$\{/.test(path)) return false
  return path.startsWith('/')
}

/** @deprecated Use isHttpRoutePath / isFsAbsolutePath. Kept for older imports. */
export function isNonHttpRelativePath(path: string): boolean {
  if (path === '/' || path === '//' || path.startsWith('//')) return true
  if (isShellSwitchPath(path)) return true
  if (isFsAbsolutePath(path)) return true
  if (/^\/\$\{/.test(path)) return true
  return false
}

function isModulePathLine(line: string): boolean {
  const trimmed = line.trim()
  return /^(?:import|export)\b/.test(trimmed)
    || /\b(?:require|import)\s*\(/.test(trimmed)
    || /\bfrom\s+['"]/.test(trimmed)
}

export interface ShapeScan {
  destinations: DestinationFinding[]
  pathEscapes: PathEscapeFinding[]
  secretTouches: SecretTouchFinding[]
}

export function scanShape(input: PluginInput): ShapeScan {
  const destinations: DestinationFinding[] = []
  const pathEscapes: PathEscapeFinding[] = []
  const secretTouches: SecretTouchFinding[] = []

  for (const [file, content] of Object.entries(input.sources)) {
    const scanned = isCodeFile(file) ? stripComments(content) : content
    const lines = scanned.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const lineNo = i + 1
      const rangeTable = isIpRangeTableLine(line)

      for (const match of line.matchAll(URL_LITERAL)) {
        const url = match[1]
        if (url === undefined) continue
        if (url.includes('${')) continue
        if (isPlaceholderUrl(url)) continue
        const kind = classifyUrl(url)
        let value = url
        if (kind === 'https-host' || kind === 'http-host' || kind === 'loopback') {
          try {
            value = new URL(url).host
          } catch {
            value = url
          }
        }
        if (isPlaceholderHost(value) || isIdentifierHost(value)) continue
        destinations.push({ kind, value, file, line: lineNo })
      }

      for (const match of line.matchAll(SLASH_PATH)) {
        const path = match[1]
        if (path === undefined) continue
        if (isShellSwitchPath(path) || path === '/' || path.startsWith('//') || /^\/\$\{/.test(path)) {
          continue
        }
        if (isFsAbsolutePath(path)) {
          pathEscapes.push({ kind: 'absolute', value: path, file, line: lineNo })
          continue
        }
        // Same-origin HTTP routes — not shown as destinations.
      }

      for (const match of line.matchAll(HOME_ESCAPE)) {
        const value = match[1]
        if (value === undefined) continue
        pathEscapes.push({ kind: 'home', value, file, line: lineNo })
      }

      for (const match of line.matchAll(WIN_ABS)) {
        const value = match[1]
        if (value === undefined) continue
        pathEscapes.push({ kind: 'windows-abs', value, file, line: lineNo })
      }

      if (!isModulePathLine(line)) {
        for (const match of line.matchAll(TRAVERSAL)) {
          const value = match[1]
          if (value === undefined) continue
          pathEscapes.push({ kind: 'traversal', value, file, line: lineNo })
        }
      }

      if (!rangeTable) {
        for (const match of line.matchAll(IPV4_LITERAL)) {
          const ip = match[1]
          if (ip === undefined) continue
          destinations.push({
            kind: isLoopbackIp(ip) ? 'loopback' : 'ip',
            value: ip,
            file,
            line: lineNo,
          })
        }
      }

      for (const match of line.matchAll(ENV_SENSITIVE)) {
        const key = match[1]
        if (key === undefined) continue
        secretTouches.push({ kind: 'env-key', value: key, file, line: lineNo })
      }

      if (SECRET_PATH.test(line)) {
        SECRET_PATH.lastIndex = 0
        const paths = line.match(SECRET_PATH) ?? []
        for (const p of paths) {
          secretTouches.push({ kind: 'path', value: p, file, line: lineNo })
        }
      }

      if (CREDENTIALS_IMPORT.test(line)) {
        CREDENTIALS_IMPORT.lastIndex = 0
        secretTouches.push({ kind: 'api', value: 'credential API', file, line: lineNo })
      }
    }
  }

  return {
    destinations: rankedDedupe(
      destinations,
      d => destinationKey(d.kind, d.value),
      d => DESTINATION_RANK[d.kind],
      MAX_DESTINATIONS,
    ),
    pathEscapes: rankedDedupe(
      pathEscapes,
      p => `${p.kind}:${p.value}`,
      p => PATH_ESCAPE_RANK[p.kind],
      MAX_PATH_ESCAPES,
    ),
    secretTouches: rankedDedupe(
      secretTouches,
      s => `${s.kind}:${s.value}`,
      s => SECRET_TOUCH_RANK[s.kind],
      MAX_SECRET_TOUCHES,
    ),
  }
}

/** Fingerprint tokens for ack comparison. */
export function destinationFingerprint(destinations: DestinationFinding[]): string[] {
  // Ignore legacy same-origin HTTP routes still present in older cached reports.
  return destinations
    .filter(d => d.kind !== 'relative')
    .map(d => destinationKey(d.kind, d.value))
    .sort()
}

export function secretTouchFingerprint(secretTouches: SecretTouchFinding[]): string[] {
  return secretTouches.map(s => `${s.kind}:${s.value}`).sort()
}

export function pathEscapeFingerprint(pathEscapes: PathEscapeFinding[]): string[] {
  return pathEscapes.map(p => `${p.kind}:${p.value}`).sort()
}

/** Whether shape findings should contribute shape-based red lines. */
export function shapeRedLines(
  capabilities: import('./types.ts').Capability[],
  destinations: DestinationFinding[],
): string[] {
  const lines: string[] = []
  if (!capabilities.includes('network')) return lines

  for (const dest of destinations) {
    if (dest.kind === 'http-host'
      && !isLoopbackHost(dest.value)
      && !isPlaceholderHost(dest.value)
      && !isIdentifierHost(dest.value)
      && !isHarnessInternalHost(dest.value)) {
      lines.push(`uses plaintext http:// to ${dest.value}`)
      break
    }
  }

  for (const dest of destinations) {
    if (dest.kind === 'ip' && !isLoopbackIp(dest.value) && !isUnspecifiedIp(dest.value)) {
      lines.push(`uses literal IP ${dest.value} for network access`)
      break
    }
  }

  return lines
}
