/**
 * Pure ack fingerprint helpers — safe for browser bundles (no filesystem).
 */

import { AUDIT_SCHEMA_VERSION } from './response.ts'
import type { AuditReport, AuditResponse, Capability, TrustAckEntry } from './types.ts'

/** Backfill fields added after v0.1 shape layer for older cached JSON. */
export function normalizeAuditReport(report: AuditReport): AuditReport {
  return {
    ...report,
    destinations: (report.destinations ?? []).filter(d => d.kind !== 'relative'),
    pathEscapes: report.pathEscapes ?? [],
    secretTouches: report.secretTouches ?? [],
    coverageNotes: report.coverageNotes ?? [],
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
    schemaVersion: response.schemaVersion ?? AUDIT_SCHEMA_VERSION,
    acks: response.acks ?? {},
    plugins: response.plugins.map(normalizeAuditReport),
    errors: response.errors ?? [],
  }
}

export function fingerprintFromReport(report: AuditReport): TrustAckEntry {
  return {
    digest: report.ackFingerprint,
    capabilities: [...report.capabilities].sort() as Capability[],
    destinations: [],
    secretTouches: [],
    pathEscapes: [],
    injections: [],
    redLines: [...(report.redLines ?? [])].sort(),
    at: new Date().toISOString(),
  }
}

export function ackMatchesReport(report: AuditReport, ack: TrustAckEntry): boolean {
  return ack.digest !== undefined
    && report.ackFingerprint !== undefined
    && ack.digest === report.ackFingerprint
}
