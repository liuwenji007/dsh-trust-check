import { describe, expect, it } from 'vitest'
import { ackAllowed, isLoopbackRequest, trustedAuditRequest } from '../../src/index.ts'
import type { AuditReport } from '../../src/core/types.ts'

function requestOf(overrides: {
  method?: string
  remoteAddress?: string
  origin?: string
  host?: string
  forwarded?: string
}): import('node:http').IncomingMessage {
  return {
    method: overrides.method ?? 'GET',
    socket: { remoteAddress: overrides.remoteAddress ?? '127.0.0.1' },
    headers: {
      ...(overrides.host !== undefined ? { host: overrides.host } : { host: '127.0.0.1:3000' }),
      ...(overrides.origin !== undefined ? { origin: overrides.origin } : {}),
      ...(overrides.forwarded !== undefined ? { forwarded: overrides.forwarded } : {}),
    },
  } as import('node:http').IncomingMessage
}

describe('trustedAuditRequest', () => {
  it('allows loopback GET without Origin', () => {
    expect(trustedAuditRequest(requestOf({}))).toBe(true)
  })

  it('allows loopback GET when Origin matches Host', () => {
    expect(trustedAuditRequest(requestOf({
      origin: 'http://127.0.0.1:3000',
      host: '127.0.0.1:3000',
    }))).toBe(true)
  })

  it('rejects non-loopback peers', () => {
    expect(isLoopbackRequest(requestOf({ remoteAddress: '10.0.0.1' }))).toBe(false)
    expect(trustedAuditRequest(requestOf({ remoteAddress: '10.0.0.1' }))).toBe(false)
  })

  it('rejects mismatched Origin', () => {
    expect(trustedAuditRequest(requestOf({
      origin: 'http://evil.example',
      host: '127.0.0.1:3000',
    }))).toBe(false)
  })

  it('rejects forwarded proxy headers', () => {
    expect(trustedAuditRequest(requestOf({ forwarded: 'for=1.2.3.4' }))).toBe(false)
  })
})

describe('ackAllowed', () => {
  const reportWith = (redLines: string[]) => ({ redLines } as AuditReport)

  it('accepts an ordinary plugin without an opt-in', () => {
    expect(ackAllowed(reportWith([]), false)).toBe(true)
  })

  it('requires the opt-in before a red line can be acknowledged', () => {
    expect(ackAllowed(reportWith(['runs install scripts']), false)).toBe(false)
    expect(ackAllowed(reportWith(['runs install scripts']), true)).toBe(true)
  })
})
