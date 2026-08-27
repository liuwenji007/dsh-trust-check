/**
 * Cached audit report: the settings page holds the last scan so reopening it
 * is instant and offline. The store is root-scoped; the handle is created
 * once in `apply`.
 */
import { defineStore, type EngineStoreHandle } from '@deepseek-ai/dsh-client-runtime/client'
import { normalizeAuditResponse } from '../core/ack-fingerprint.ts'
import type { AuditResponse } from '../core/types.ts'

export interface TrustStoreState {
  report: AuditResponse | null
  fetchedAt: number | null
}

export type TrustStoreActions = {
  setReport: (draft: TrustStoreState, report: AuditResponse, at: number) => void
}

export function createTrustStore(): EngineStoreHandle<TrustStoreState, TrustStoreActions> {
  return defineStore({
    init: (): TrustStoreState => ({ report: null, fetchedAt: null }),
    persist: 'dsh.trust-check.report.v2',
    actions: {
      setReport: (draft, report, at) => {
        draft.report = normalizeAuditResponse(report)
        draft.fetchedAt = at
      },
    },
  })
}
