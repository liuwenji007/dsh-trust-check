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
/**
 * Path-shaped secret material only. Bare `id_rsa` / `.netrc` inside deny-list
 * regex strings or `startsWith('id_rsa')` checks are not credential reads.
 * `.netrc` requires a path prefix (`~/`, `./`, `/`) — a bare quoted
 * `'.netrc'` is indistinguishable from a deny-list array entry (`['.netrc']`)
 * and is therefore not flagged (deny-list false positives punish exactly the
 * safety code this scanner exists to support).
 *
 * `.ssh` / `.aws/credentials` must appear inside a *path-only* quoted string
 * (no whitespace): `"~/.ssh/config"`, `"/Users/x/.ssh/config"`, `'.ssh/config'`.
 * UI prose (`"Uses … ~/.ssh/config when empty"`) has spaces and does not match.
 * A deny-list bare `'.ssh'` also does not match (needs `~/`/`/` prefix or `.ssh/…`).
 */
const SECRET_PATH = /['"`]((?:~\/|\.\/|\/|[A-Za-z]:\\)[^'"`\s]*\.ssh[^'"`\s]*|\.ssh\/[^'"`\s]+)['"`]|['"`]((?:~\/|\.\/|\/|[A-Za-z]:\\)[^'"`\s]*\.aws\/credentials[^'"`\s]*|\.aws\/credentials)['"`]|(?:~\/|\.\/|\/)\.netrc\b|\.gnupg(?:\/|\\|$)|\.docker\/config\.json|\.kube\/config|[/\\]id_rsa\b|[/\\]id_ed25519\b/g
const CREDENTIALS_IMPORT = /(?:require\(|from\s+|import\s*\(\s*)['"](?:keychain|keytar|dotenv)['"]|\bkeychain\.\w+|\bkeytar\.\w+|\bdotenv\.config\b|\bctx\.credentials\b/g
/**
 * Credential API calls that return secret *material* (`resolve('API_KEY')`
 * yields the value). Handle access and `describe`/`set`/`unset` do not.
 *
 * Not anchored to the literal token `credentials`: the seam is routinely
 * aliased (`const x = ctx.get('credentials')`), and requiring the name let a
 * real read-and-post shape pass as `review`.
 *
 * A bare `read(` / `getXxx(` is also not matched: those names are ordinary DOM
 * and collection methods (`getItem`, `getBoundingClientRect`,
 * `getRandomValues`), which red-lined `dsh-pocket` and `agent-teams`.
 * Destructuring the seam (`const { resolve } = ctx.credentials`), aliasing it
 * to a differently named local (`const x = …; x.resolve(…)`) and reading a
 * secret path held in a variable stay known misses: telling those from
 * ordinary calls needs scope tracking, not a line regex.
 */
const CREDENTIALS_READ = /(?<![\w$])credentials\s*\.\s*(?:resolve|read|readRecord|get[A-Z]\w*)\s*\(|(?<![\w$])readRecord\s*\(/g
/** Keychain libraries: these calls return the secret itself, not a handle. */
const KEYCHAIN_READ = /\b(?:keytar|keychain)\.(?:getPassword|getCredentials|findCredentials|findPassword)\s*\(/g
/** A read call on the same line as a secret-path literal lifts it to a read. */
const SECRET_FILE_READ = /\b(?:readFile|readFileSync|createReadStream)\s*\(/
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

/**
 * RFC 2606 reserved documentation TLDs: `.example`, `.invalid`, `.test`.
 * These never resolve on the public Internet (RFC 2606 reserves them for
 * testing and documentation), so a literal to any of them — parser base,
 * fetch target, or docs example — cannot exfiltrate data: DNS resolution
 * fails before anything is sent. An attacker cannot use them as a real
 * exfil target for the same reason. Reporting them would be noise, so all
 * three are skipped, matching `.example`'s existing treatment.
 */
const PLACEHOLDER_TLD = /\.(?:example|invalid|test)$/i

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

/** Bind / unspecified / broadcast — not an outbound unicast target. */
export function isUnspecifiedIp(ip: string): boolean {
  const v = ip.trim().toLowerCase()
  return v === '0.0.0.0' || v === '255.255.255.255' || v === '::' || v === '[::]'
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

function escapeForRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// The seam is reached off a context object, which callers name `ctx`,
// `hostCtx`, `appCtx`, `this.ctx`, and so on. Matching any `*Ctx` receiver keeps
// the alias pass from depending on one naming convention; the property being
// read is what makes the binding a credential source.
const CTX_RECEIVER = /(?:[A-Za-z_$][\w$]*\.)?(?:ctx|[a-z][\w$]*Ctx)|this\.ctx/
const SEAM_RECEIVERS = new RegExp(`(?:${CTX_RECEIVER.source})\\s*\\.\\s*get\\(\\s*['"]credentials['"]\\s*\\)|(?:${CTX_RECEIVER.source})\\s*\\.\\s*credentials\\b`)
const KEYCHAIN_MODULE_NAMES = ['keytar', 'keychain']
const SEAM_METHODS = 'resolve|read|readRecord|get[A-Z]\\w*'
const KEYCHAIN_METHODS = 'getPassword|getCredentials|getSecret|getToken|findCredentials|findPassword|findAnyCredential'

/**
 * Identifiers a file binds to the credential seam. Covers all the shapes that
 * reach the seam, because a miss here is a missed secret read:
 *
 *   const x = ctx.get('credentials')       // seam service
 *   const x = await ctx.get('credentials') // await does not break the binding
 *   const x = ctx.credentials              // property access
 *   const { credentials } = ctx            // destructured off ctx
 *   import kt from 'keytar'                // renamed keychain module
 *
 * A `ctx.credentials.resolve(…)` direct call binds nothing and is matched by
 * the call patterns instead.
 */
export function collectSeamAliases(lines: readonly string[]): string[] {
  const names = new Set<string>([...KEYCHAIN_MODULE_NAMES])
  const seam = new Set<string>()
  const keychain = new Set<string>(KEYCHAIN_MODULE_NAMES)
  const assignAwait = new RegExp(`\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*await\\s+(?:${SEAM_RECEIVERS.source})`, 'g')
  const assignDirect = new RegExp(`\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:${SEAM_RECEIVERS.source})(?!\\s*\\()`, 'g')
  for (const line of lines) {
    for (const m of line.matchAll(assignAwait)) {
      if (m[1] !== undefined) { names.add(m[1]); seam.add(m[1]) }
    }
    for (const m of line.matchAll(assignDirect)) {
      if (m[1] !== undefined) { names.add(m[1]); seam.add(m[1]) }
    }
    const destructured = new RegExp(`\\b(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*(?:${CTX_RECEIVER.source})`).exec(line)
    if (destructured?.[1] !== undefined && /\bcredentials\b/.test(destructured[1])) {
      names.add('credentials'); seam.add('credentials')
    }
    const rebound = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*$/.exec(line)
    if (rebound?.[1] !== undefined && rebound[2] !== undefined && names.has(rebound[2])) {
      names.add(rebound[1])
      if (seam.has(rebound[2])) seam.add(rebound[1])
      if (keychain.has(rebound[2])) keychain.add(rebound[1])
    }
    const namedImport = /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*['"](?:keytar|keychain)['"]/.exec(line)
    if (namedImport?.[1] !== undefined) { names.add(namedImport[1]); keychain.add(namedImport[1]) }
    const required = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?:keytar|keychain)['"]\s*\)/.exec(line)
    if (required?.[1] !== undefined) { names.add(required[1]); keychain.add(required[1]) }
  }
  // The prefix keeps the alias kind with the name; a single string[] keeps the
  // public signature and the call site simple. The module names themselves are
  // already unambiguous, so only renamed aliases carry the prefix.
  return [...names].map(name =>
    (keychain.has(name) && name !== 'keytar' && name !== 'keychain' ? `${KEYCHAIN_PREFIX}${name}` : name))
}

/** Marks a keychain-module alias so the call regex uses the keychain method set. */
const KEYCHAIN_PREFIX = 'keychain:'

/**
 * Value-returning credential calls on one line, including calls through a local
 * seam alias (`const x = ctx.get('credentials')` → `x.resolve(…)`) and through
 * a renamed keychain module (`import kt from 'keytar'` → `kt.getPassword(…)`).
 *
 * Bare `resolve(` / `read(` / `getXxx(` are excluded because Promise executors
 * and DOM accessors use those names.
 */
export function credentialReadCalls(line: string, seamAliases: readonly string[] = []): string[] {
  CREDENTIALS_READ.lastIndex = 0
  const calls = [...(line.match(CREDENTIALS_READ) ?? [])]
  for (const entry of seamAliases) {
    const isKeychain = entry.startsWith(KEYCHAIN_PREFIX) || entry === 'keytar' || entry === 'keychain'
    const alias = isKeychain ? entry.slice(KEYCHAIN_PREFIX.length) : entry
    if (!line.includes(`${alias}.`)) continue
    const methods = isKeychain ? KEYCHAIN_METHODS : SEAM_METHODS
    const re = new RegExp(`(?<![\\w$])${escapeForRegExp(alias)}\\s*\\.\\s*(?:${methods})\\s*\\(`, 'g')
    calls.push(...(line.match(re) ?? []))
  }
  return calls
}

/**
 * True when this URL literal is only the second argument of `new URL(...)` —
 * the base-URL idiom for parsing a request target. The origin is never
 * contacted, so it is not a destination. Structural rather than a host
 * denylist: `.local` resolves, and `new URL('/x', 'http://evil')` followed by
 * a fetch is still a real destination shaped exactly like this.
 */
export function isUrlParserBase(line: string, url: string): boolean {
  return new RegExp(`new\\s+URL\\s*\\([^)]*,\\s*['"\`]${escapeForRegExp(url)}['"\`]`).test(line)
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
  read: 3,
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

/**
 * Line looks like a private/special IP *network* range table, not an outbound
 * unicast target.
 *
 * Narrow on purpose: a bare "two IPs on one line" or a `PRIVATE_RANGES` /
 * `CIDR` token must not wipe real destinations (`exfil("8.8.8.8","1.1.1.1")`,
 * `const PRIVATE_RANGES = "8.8.8.8"`). Host routes written as `["8.8.8.8", 32]`
 * are also kept — only network-aligned prefixes (< 32) count as table rows.
 */
export function isIpRangeTableLine(line: string): boolean {
  for (const match of line.matchAll(/\[\s*['"`]((?:\d{1,3}\.){3}\d{1,3})['"`]\s*,\s*(\d{1,2})\s*\]/g)) {
    const ip = match[1]
    const prefix = Number(match[2])
    if (ip !== undefined && Number.isFinite(prefix) && isNetworkCidrTuple(ip, prefix)) return true
  }
  // inRange(value, "10.0.0.0", "10.255.255.255") — endpoints, not destinations.
  if (/\binRange\s*\(/.test(line)) {
    const ipCount = [...line.matchAll(/['"`]((?:\d{1,3}\.){3}\d{1,3})['"`]/g)].length
    if (ipCount >= 2) return true
  }
  return false
}

/** True when [ip, prefix] names a network block (SSRF denylist row), not a /32 host. */
export function isNetworkCidrTuple(ip: string, prefix: number): boolean {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix >= 32) return false
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const addr = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
  return (addr & ~mask) === 0
}

/**
 * RFC 5737 documentation IPv4 ranges (TEST-NET-1/2/3). Same role as RFC 2606
 * `.example` / `.invalid` hosts: never routable on the public Internet, used
 * only in examples. An attacker cannot exfiltrate to them.
 */
export function isDocumentationIp(ip: string): boolean {
  const v = ip.trim().toLowerCase().replace(/^\[|\]$/g, '')
  return (
    v.startsWith('192.0.2.')
    || v.startsWith('198.51.100.')
    || v.startsWith('203.0.113.')
  )
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
  if (isDocumentationIp(h)) return true
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
    // Locals bound to the credential seam in this file (`const x =
    // ctx.get('credentials')`). Reads through them are real reads, but matching
    // a bare `resolve(` instead would also catch every Promise executor, so the
    // names are collected first and only those receivers count.
    const seamAliases = collectSeamAliases(lines)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const lineNo = i + 1
      const rangeTable = isIpRangeTableLine(line)

      for (const match of line.matchAll(URL_LITERAL)) {
        const url = match[1]
        if (url === undefined) continue
        if (url.includes('${')) continue
        if (isPlaceholderUrl(url)) continue
        // `new URL(req.url, 'http://anything')` uses the base only to parse a
        // request target; the origin is never contacted. Without this the base
        // host reads as a plaintext-http destination (`dsh-remote.local`,
        // `gateway.local`). Deliberately not a host denylist: `.local` resolves
        // and `new URL('/path', 'http://evil')` + fetch is still a real one.
        if (isUrlParserBase(line, url)) continue
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
          if (isDocumentationIp(ip)) continue
          // `'10.0.0.0/8'` is a network block, not a destination — `IPV4_LITERAL`
          // captures the address and leaves the prefix outside the group. `/32`
          // is a single host and stays a destination.
          const cidr = /['"`]\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})['"`]$/.exec(match[0])
          if (cidr !== null && isNetworkCidrTuple(ip, Number(cidr[1]))) continue
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
        // A path inside a read call is a secret read; a bare path literal is
        // only a reference. Same distinction as the credential API below.
        const kind: SecretTouchKind = SECRET_FILE_READ.test(line) ? 'read' : 'path'
        for (const p of paths) {
          secretTouches.push({ kind, value: p, file, line: lineNo })
        }
      }

      if (CREDENTIALS_IMPORT.test(line)) {
        CREDENTIALS_IMPORT.lastIndex = 0
        secretTouches.push({ kind: 'api', value: 'credential API', file, line: lineNo })
      }

      // Reading the *value* is the risky half of the credential surface;
      // holding the handle (`const c = ctx.credentials`) or asking for
      // metadata (`describe`) is disclosure, not a secret read. The red line
      // keys off this rather than off the capability chip.
      const readCalls = credentialReadCalls(line, seamAliases)
      if (readCalls.length > 0) {
        for (const call of readCalls) {
          secretTouches.push({ kind: 'read', value: call, file, line: lineNo })
        }
      }

      if (KEYCHAIN_READ.test(line)) {
        KEYCHAIN_READ.lastIndex = 0
        const calls = line.match(KEYCHAIN_READ) ?? []
        for (const call of calls) {
          secretTouches.push({ kind: 'read', value: call, file, line: lineNo })
        }
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
    if (dest.kind === 'ip'
      && !isLoopbackIp(dest.value)
      && !isUnspecifiedIp(dest.value)
      && !isDocumentationIp(dest.value)) {
      lines.push(`uses literal IP ${dest.value} for network access`)
      break
    }
  }

  return lines
}
