/**
 * Local trust-ack store: user-acknowledged capability/shape fingerprints per profile.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { AuditReport, TrustAckEntry } from './types.ts'

export type TrustAckStore = Record<string, TrustAckEntry>

export { ackMatchesReport, fingerprintFromReport, normalizeAuditReport, normalizeAuditResponse } from './ack-fingerprint.ts'

export function ackPath(profileDir: string): string {
  return join(profileDir, 'trust-ack.json')
}

function isAckEntry(value: unknown): value is TrustAckEntry {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Throws on a corrupt file, so a write never replaces acks it could not read. */
function readAckStoreStrict(profileDir: string): TrustAckStore {
  const path = ackPath(profileDir)
  if (!existsSync(path)) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown
  } catch (err) {
    throw new Error(`trust-ack.json is corrupt, refusing to overwrite it: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('trust-ack.json is not an object, refusing to overwrite it')
  }
  const store: TrustAckStore = {}
  for (const [name, entry] of Object.entries(parsed)) {
    if (isAckEntry(entry)) store[name] = entry
  }
  return store
}

/** Lenient read for display: an unreadable store means "no acks", never a crash. */
export function readAckStore(profileDir: string): TrustAckStore {
  try {
    return readAckStoreStrict(profileDir)
  } catch {
    return {}
  }
}

export function writeAckStore(profileDir: string, store: TrustAckStore): void {
  const path = ackPath(profileDir)
  const temp = `${path}.${process.pid}.tmp`
  writeFileSync(temp, `${JSON.stringify(store, null, 2)}\n`, 'utf8')
  renameSync(temp, path)
}

export function setAck(profileDir: string, report: AuditReport): TrustAckEntry {
  const store = readAckStoreStrict(profileDir)
  const entry: TrustAckEntry = {
    digest: report.ackFingerprint,
    capabilities: [...report.capabilities],
    destinations: [],
    secretTouches: [],
    pathEscapes: [],
    injections: [],
    redLines: [...report.redLines],
    at: new Date().toISOString(),
  }
  store[report.name] = entry
  writeAckStore(profileDir, store)
  return entry
}

export function removeAck(profileDir: string, name: string): void {
  const store = readAckStoreStrict(profileDir)
  if (!(name in store)) return
  delete store[name]
  writeAckStore(profileDir, store)
}
