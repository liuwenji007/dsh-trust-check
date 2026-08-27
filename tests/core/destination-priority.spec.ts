import { describe, expect, it } from 'vitest'
import {
  destinationHighlight,
  destinationTier,
  destinationWhitelistReason,
  isPrivateIp,
  matchDestWhitelist,
  partitionDestinations,
} from '../../src/core/destination-priority.ts'
import type { DestinationFinding } from '../../src/core/types.ts'

const d = (kind: DestinationFinding['kind'], value: string): DestinationFinding => ({
  kind,
  value,
  file: 'a.js',
  line: 1,
})

describe('destination priority', () => {
  it('detects private IPv4 ranges', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true)
    expect(isPrivateIp('192.168.1.5')).toBe(true)
    expect(isPrivateIp('8.8.8.8')).toBe(false)
  })

  it('tiers relative and loopback as safe', () => {
    expect(destinationTier(d('relative', '/context'))).toBe('safe')
    expect(destinationTier(d('loopback', 'localhost'))).toBe('safe')
  })

  it('whitelists common HTTPS hosts including subdomains', () => {
    expect(matchDestWhitelist('github.com')?.reason).toBe('github')
    expect(matchDestWhitelist('api.github.com')?.reason).toBe('github')
    expect(matchDestWhitelist('registry.npmjs.org')?.reason).toBe('npm')
    expect(matchDestWhitelist('registry.npmmirror.com')?.reason).toBe('npm-mirror')
    expect(matchDestWhitelist('api.anthropic.com')?.reason).toBe('anthropic')
    expect(matchDestWhitelist('generativelanguage.googleapis.com')?.reason).toBe('google-ai')
    expect(matchDestWhitelist('api.openai.com')?.reason).toBe('openai')
    expect(matchDestWhitelist('evil.example')).toBeUndefined()
  })

  it('collapses model vendor APIs into the safe fold', () => {
    const { priority, safe } = partitionDestinations([
      d('https-host', 'api.anthropic.com'),
      d('https-host', 'generativelanguage.googleapis.com'),
      d('https-host', 'evil.zxyz'),
    ])
    expect(priority.map(x => x.value)).toEqual(['evil.zxyz'])
    expect(safe.map(x => x.value)).toEqual([
      'api.anthropic.com',
      'generativelanguage.googleapis.com',
    ])
    expect(destinationWhitelistReason(d('https-host', 'api.anthropic.com'))).toBe('anthropic')
  })

  it('treats whitelisted https as safe, but never plaintext http', () => {
    expect(destinationTier(d('https-host', 'github.com'))).toBe('safe')
    expect(destinationWhitelistReason(d('https-host', 'github.com'))).toBe('github')
    expect(destinationTier(d('http-host', 'github.com'))).toBe('critical')
    expect(destinationWhitelistReason(d('http-host', 'github.com'))).toBeUndefined()
  })

  it('highlights plaintext http and private ip', () => {
    expect(destinationHighlight(d('http-host', 'evil.test'))).toBe('plaintext')
    expect(destinationHighlight(d('ip', '192.168.0.9'))).toBe('private-ip')
    expect(destinationHighlight(d('ip', '203.0.113.1'))).toBe('public-ip')
  })

  it('partitions whitelist + relative into safe; keeps unknown https in priority', () => {
    const rows = [
      d('relative', '/releases'),
      d('https-host', 'github.com'),
      d('https-host', 'evil.example'),
      d('http-host', 'insecure.test'),
      d('relative', '/context'),
      d('ip', '192.168.1.2'),
      d('https-host', 'registry.npmjs.org'),
    ]
    const { priority, safe } = partitionDestinations(rows)
    expect(safe.map(x => x.value)).toEqual([
      'github.com',
      'registry.npmjs.org',
      '/context',
      '/releases',
    ])
    expect(priority.map(x => x.value)).toEqual([
      'insecure.test',
      '192.168.1.2',
      'evil.example',
    ])
  })
})
