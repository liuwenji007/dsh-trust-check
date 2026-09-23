import { Readable } from 'node:stream'
import { describe, expect, it } from 'vitest'
import { BodyTooLarge, ackAllowed, isLoopbackRequest, readJsonBody, requestBodyStatus, trustedAuditRequest } from '../../src/index.ts'
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

  it('rejects a DNS-rebound name even when Origin matches Host', () => {
    expect(trustedAuditRequest(requestOf({
      origin: 'http://rebind.attacker.test:3000',
      host: 'rebind.attacker.test:3000',
    }))).toBe(false)
  })

  it('accepts localhost and [::1] Host names', () => {
    expect(trustedAuditRequest(requestOf({ host: 'localhost:3000', origin: 'http://localhost:3000' }))).toBe(true)
    expect(trustedAuditRequest(requestOf({ host: '[::1]:3000', remoteAddress: '::1' }))).toBe(true)
  })

  it('rejects a loopback-looking name that is not loopback', () => {
    expect(trustedAuditRequest(requestOf({ host: '127.0.0.1.attacker.test:3000' }))).toBe(false)
    expect(trustedAuditRequest(requestOf({ host: 'localhost.attacker.test' }))).toBe(false)
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

describe('readJsonBody', () => {
  const asRequest = (payload: Buffer | string) =>
    Readable.from([Buffer.isBuffer(payload) ? payload : Buffer.from(payload)]) as unknown as import('node:http').IncomingMessage

  it('parses a JSON object and treats an empty body as {}', async () => {
    await expect(readJsonBody(asRequest('{"name":"a"}'))).resolves.toEqual({ name: 'a' })
    await expect(readJsonBody(asRequest(''))).resolves.toEqual({})
  })

  it('rejects an oversized body as 413 and invalid JSON as 400', async () => {
    const tooLarge = readJsonBody(asRequest(Buffer.alloc(64 * 1024 + 1)))
    await expect(tooLarge).rejects.toBeInstanceOf(BodyTooLarge)
    await expect(tooLarge).rejects.toThrow(/exceeds/)
    expect(requestBodyStatus(new BodyTooLarge(1))).toBe(413)

    const invalid = readJsonBody(asRequest('{'))
    await expect(invalid).rejects.toBeInstanceOf(SyntaxError)
    expect(requestBodyStatus(new SyntaxError('bad'))).toBe(400)
    expect(requestBodyStatus(new Error('other'))).toBeUndefined()
  })
})
