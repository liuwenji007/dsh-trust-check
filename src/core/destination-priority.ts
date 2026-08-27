/**
 * Destination presentation tiers: prioritize risky / private endpoints,
 * collapse relatively safe relative paths, loopback, and whitelisted hosts.
 */

import type { DestinationFinding } from './types.ts'

export type DestinationTier = 'critical' | 'notable' | 'safe'

export type DestinationHighlight = 'plaintext' | 'private-ip' | 'public-ip'

/**
 * Stable reason codes for known-benign HTTPS hosts.
 * Locale maps `destWhitelist.<code>` for display.
 */
export type DestWhitelistReason =
  | 'github'
  | 'npm'
  | 'npm-mirror'
  | 'deepseek'
  | 'openai'
  | 'anthropic'
  | 'google-ai'
  | 'dsh-catalog'
  | 'gh-proxy'
  | 'jsdelivr'
  | 'unpkg'

export interface DestWhitelistEntry {
  /** Bare host or parent host; subdomains match (api.github.com → github.com). */
  host: string
  reason: DestWhitelistReason
}

/**
 * Built-in allowlist of common package / source / model API hosts.
 * Only applies to `https-host` (never downgrades plaintext http).
 */
export const DEST_WHITELIST: readonly DestWhitelistEntry[] = [
  { host: 'github.com', reason: 'github' },
  { host: 'githubusercontent.com', reason: 'github' },
  { host: 'raw.githubusercontent.com', reason: 'github' },
  { host: 'gitlab.com', reason: 'github' },
  { host: 'registry.npmjs.org', reason: 'npm' },
  { host: 'npmjs.com', reason: 'npm' },
  { host: 'npmjs.org', reason: 'npm' },
  { host: 'registry.npmmirror.com', reason: 'npm-mirror' },
  { host: 'npmmirror.com', reason: 'npm-mirror' },
  { host: 'mirrors.cloud.tencent.com', reason: 'npm-mirror' },
  { host: 'cdn.jsdelivr.net', reason: 'jsdelivr' },
  { host: 'unpkg.com', reason: 'unpkg' },
  { host: 'api.deepseek.com', reason: 'deepseek' },
  { host: 'chat.deepseek.com', reason: 'deepseek' },
  { host: 'api.openai.com', reason: 'openai' },
  { host: 'openai.com', reason: 'openai' },
  { host: 'api.anthropic.com', reason: 'anthropic' },
  { host: 'anthropic.com', reason: 'anthropic' },
  { host: 'generativelanguage.googleapis.com', reason: 'google-ai' },
  { host: 'aiplatform.googleapis.com', reason: 'google-ai' },
  { host: 'aistudio.google.com', reason: 'google-ai' },
  { host: 'awesome-dsh-plugin.com', reason: 'dsh-catalog' },
  { host: 'gh-proxy.com', reason: 'gh-proxy' },
]

function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/:\d+$/, '')
}

/** Match exact host or subdomain of a whitelist parent. */
export function matchDestWhitelist(host: string): DestWhitelistEntry | undefined {
  const h = normalizeHost(host)
  if (h === '') return undefined
  for (const entry of DEST_WHITELIST) {
    const parent = entry.host
    if (h === parent || h.endsWith(`.${parent}`)) return entry
  }
  return undefined
}

/** RFC1918, link-local, and common LAN ranges. */
export function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(p => Number.parseInt(p, 10))
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false
  const [a, b] = parts
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  return false
}

export function isLoopbackIp(ip: string): boolean {
  return ip === '127.0.0.1' || ip.startsWith('127.')
}

export function destinationTier(d: DestinationFinding): DestinationTier {
  if (d.kind === 'relative' || d.kind === 'loopback') return 'safe'
  if (d.kind === 'https-host' && matchDestWhitelist(d.value) !== undefined) return 'safe'
  if (d.kind === 'http-host' || d.kind === 'ip') return 'critical'
  return 'notable'
}

export function destinationHighlight(d: DestinationFinding): DestinationHighlight | undefined {
  if (d.kind === 'http-host') return 'plaintext'
  if (d.kind === 'ip') {
    if (isLoopbackIp(d.value)) return undefined
    return isPrivateIp(d.value) ? 'private-ip' : 'public-ip'
  }
  return undefined
}

export function destinationWhitelistReason(d: DestinationFinding): DestWhitelistReason | undefined {
  if (d.kind !== 'https-host') return undefined
  return matchDestWhitelist(d.value)?.reason
}

/** Lower sort keys appear first in the priority list. */
export function destinationSortKey(d: DestinationFinding): number {
  if (d.kind === 'http-host') return 0
  if (d.kind === 'ip' && isPrivateIp(d.value)) return 1
  if (d.kind === 'ip') return 2
  if (d.kind === 'https-host') return 3
  if (d.kind === 'loopback') return 10
  return 11
}

function safeSortKey(d: DestinationFinding): number {
  if (d.kind === 'https-host') return 0
  if (d.kind === 'loopback') return 1
  return 2
}

export function partitionDestinations(destinations: readonly DestinationFinding[]): {
  priority: DestinationFinding[]
  safe: DestinationFinding[]
} {
  const priority: DestinationFinding[] = []
  const safe: DestinationFinding[] = []
  for (const d of destinations) {
    if (destinationTier(d) === 'safe') safe.push(d)
    else priority.push(d)
  }
  priority.sort((a, b) => {
    const diff = destinationSortKey(a) - destinationSortKey(b)
    return diff !== 0 ? diff : a.value.localeCompare(b.value)
  })
  safe.sort((a, b) => {
    const diff = safeSortKey(a) - safeSortKey(b)
    return diff !== 0 ? diff : a.value.localeCompare(b.value)
  })
  return { priority, safe }
}
