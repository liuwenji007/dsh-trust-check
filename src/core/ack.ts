/**
 * Local trust-ack store: user-acknowledged capability/shape fingerprints per profile.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fingerprintFromReport } from './ack-fingerprint.ts'
import type { AuditReport, TrustAckEntry } from './types.ts'

export type TrustAckStore = Record<string, TrustAckEntry>

export { ackMatchesReport, fingerprintFromReport, normalizeAuditReport, normalizeAuditResponse } from './ack-fingerprint.ts'

export function ackPath(profileDir: string): string {
  return join(profileDir, 'trust-ack.json')
}

export function readAckStore(profileDir: string): TrustAckStore {
  const path = ackPath(profileDir)
  if (!existsSync(path)) return {}
  try {
    const raw = readFileSync(path, 'utf8')
    const parsed = JSON.parse(raw) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {}
    return parsed as TrustAckStore
  } catch {
    return {}
  }
}

export function writeAckStore(profileDir: string, store: TrustAckStore): void {
  writeFileSync(ackPath(profileDir), `${JSON.stringify(store, null, 2)}\n`, 'utf8')
}

export function setAck(profileDir: string, report: AuditReport): TrustAckEntry {
  const store = readAckStore(profileDir)
  const entry = fingerprintFromReport(report)
  store[report.name] = entry
  writeAckStore(profileDir, store)
  return entry
}

export function removeAck(profileDir: string, name: string): void {
  const store = readAckStore(profileDir)
  delete store[name]
  writeAckStore(profileDir, store)
}
