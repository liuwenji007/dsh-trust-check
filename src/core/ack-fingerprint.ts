/**
 * Pure ack fingerprint helpers — safe for browser bundles (no filesystem).
 */

import {
  destinationFingerprint,
  pathEscapeFingerprint,
  secretTouchFingerprint,
} from './shape.ts'
import type { AuditReport, AuditResponse, Capability, TrustAckEntry } from './types.ts'

/** Backfill fields added after v0.1 shape layer for older cached JSON. */
export function normalizeAuditReport(report: AuditReport): AuditReport {
  return {
    ...report,
    destinations: (report.destinations ?? []).filter(d => d.kind !== 'relative'),
    pathEscapes: report.pathEscapes ?? [],
    secretTouches: report.secretTouches ?? [],
    capabilities: report.capabilities ?? [],
    evidence: report.evidence ?? [],
    injections: report.injections ?? [],
    redLines: report.redLines ?? [],
    buildScripts: report.buildScripts ?? [],
    deductions: report.deductions ?? [],
  }
}

export function normalizeAuditResponse(response: AuditResponse): AuditResponse {
  return {
    ...response,
    acks: response.acks ?? {},
    plugins: response.plugins.map(normalizeAuditReport),
    errors: response.errors ?? [],
  }
}

export function fingerprintFromReport(report: AuditReport): TrustAckEntry {
  const normalized = normalizeAuditReport(report)
  return {
    capabilities: [...normalized.capabilities].sort() as Capability[],
    destinations: destinationFingerprint(normalized.destinations),
    secretTouches: secretTouchFingerprint(normalized.secretTouches),
    pathEscapes: pathEscapeFingerprint(normalized.pathEscapes),
    at: new Date().toISOString(),
  }
}

function sortedEqual(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

export function ackMatchesReport(report: AuditReport, ack: TrustAckEntry): boolean {
  const current = fingerprintFromReport(report)
  return sortedEqual(current.capabilities, ack.capabilities ?? [])
    && sortedEqual(current.destinations, ack.destinations ?? [])
    && sortedEqual(current.secretTouches, ack.secretTouches ?? [])
    && sortedEqual(current.pathEscapes ?? [], ack.pathEscapes ?? [])
}
