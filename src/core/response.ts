/**
 * Shared AuditResponse constructor — CLI and host runAudit must not diverge.
 */

import type { AuditReport, AuditResponse, TrustAckEntry } from './types.ts'

/**
 * JSON contract version. Bump when the output shape breaks parsers, or when a
 * field becomes a stable contract integrators may gate on (schema 2:
 * `facts[].id`). Detection-rule changes do not bump this. See docs/audit-schema.md.
 */
export const AUDIT_SCHEMA_VERSION = 2

export interface BuildAuditResponseInput {
  profile: string
  dir?: string
  plugins: AuditReport[]
  errors: AuditResponse['errors']
  acks?: Record<string, TrustAckEntry>
  /** Override clock in tests; defaults to now. */
  generatedAt?: string
}

/** Single place that stamps schemaVersion + generatedAt onto an audit payload. */
export function buildAuditResponse(input: BuildAuditResponseInput): AuditResponse {
  const response: AuditResponse = {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    profile: input.profile,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    plugins: input.plugins,
    errors: input.errors,
  }
  if (input.dir !== undefined) response.dir = input.dir
  if (input.acks !== undefined) response.acks = input.acks
  return response
}
