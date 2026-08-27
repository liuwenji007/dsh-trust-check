/**
 * Shape scanner: literal destinations and secret-touch patterns in source.
 * Proves presence only; runtime-constructed URLs are invisible.
 */

import type { DestinationFinding, PluginInput, SecretTouchFinding } from './types.ts'

export const MAX_DESTINATIONS = 20
export const MAX_SECRET_TOUCHES = 20

const URL_LITERAL = /['"`](https?:\/\/[^'"`\s]+)['"`]/g
const RELATIVE_PATH = /['"`](\/[^'"`\s]+)['"`]/g
const IPV4_LITERAL = /['"`]((\d{1,3}\.){3}\d{1,3})(?:\/[^'"`]*)?['"`]/g
const ENV_SENSITIVE = /process\.env\.([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)/g
const SECRET_PATH = /~\/\.ssh|\.aws\/credentials|\.netrc|\bid_rsa\b|\bid_ed25519\b/g
const CREDENTIALS_IMPORT = /(?:require\(|from\s+|import\s*\(\s*)['"](?:keychain|keytar|dotenv)['"]|\bkeychain\.\w+|\bkeytar\.\w+|\bdotenv\.config\b|\bctx\.credentials\b/g

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]'
}

function isLoopbackIp(ip: string): boolean {
  return ip === '127.0.0.1' || ip.startsWith('127.')
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

function dedupeDestinations(rows: DestinationFinding[]): DestinationFinding[] {
  const seen = new Set<string>()
  const out: DestinationFinding[] = []
  for (const row of rows) {
    const key = destinationKey(row.kind, row.value)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(row)
    if (out.length >= MAX_DESTINATIONS) break
  }
  return out
}

function dedupeSecretTouches(rows: SecretTouchFinding[]): SecretTouchFinding[] {
  const seen = new Set<string>()
  const out: SecretTouchFinding[] = []
  for (const row of rows) {
    const key = `${row.kind}:${row.value}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(row)
    if (out.length >= MAX_SECRET_TOUCHES) break
  }
  return out
}

export interface ShapeScan {
  destinations: DestinationFinding[]
  secretTouches: SecretTouchFinding[]
}

export function scanShape(input: PluginInput): ShapeScan {
  const destinations: DestinationFinding[] = []
  const secretTouches: SecretTouchFinding[] = []

  for (const [file, content] of Object.entries(input.sources)) {
    const lines = content.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const lineNo = i + 1

      for (const match of line.matchAll(URL_LITERAL)) {
        const url = match[1]
        if (url === undefined) continue
        const kind = classifyUrl(url)
        let value = url
        if (kind === 'https-host' || kind === 'http-host' || kind === 'loopback') {
          try {
            value = new URL(url).host
          } catch {
            value = url
          }
        }
        destinations.push({ kind, value, file, line: lineNo })
      }

      for (const match of line.matchAll(RELATIVE_PATH)) {
        const path = match[1]
        if (path === undefined) continue
        destinations.push({ kind: 'relative', value: path, file, line: lineNo })
      }

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
    destinations: dedupeDestinations(destinations),
    secretTouches: dedupeSecretTouches(secretTouches),
  }
}

/** Fingerprint tokens for ack comparison. */
export function destinationFingerprint(destinations: DestinationFinding[]): string[] {
  return destinations.map(d => destinationKey(d.kind, d.value)).sort()
}

export function secretTouchFingerprint(secretTouches: SecretTouchFinding[]): string[] {
  return secretTouches.map(s => `${s.kind}:${s.value}`).sort()
}

/** Whether shape findings should contribute shape-based red lines. */
export function shapeRedLines(
  capabilities: import('./types.ts').Capability[],
  destinations: DestinationFinding[],
): string[] {
  const lines: string[] = []
  if (!capabilities.includes('network')) return lines

  for (const dest of destinations) {
    if (dest.kind === 'http-host' && !isLoopbackHost(dest.value)) {
      lines.push(`uses plaintext http:// to ${dest.value}`)
      break
    }
  }

  for (const dest of destinations) {
    if (dest.kind === 'ip' && !isLoopbackIp(dest.value)) {
      lines.push(`uses literal IP ${dest.value} for network access`)
      break
    }
  }

  return lines
}
