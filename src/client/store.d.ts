/**
 * Type-only seam: defineStore lives on the host module table.
 * The package is an optional peer and is not installed in this checkout.
 */
declare module '@deepseek-ai/dsh-client-store' {
  import type { DefineStore, StoreHandle } from '@deepseek-ai/dsh-client-ui-slots'

  export type EngineStoreHandle<T, A extends Record<string, (draft: T, ...args: any[]) => void>> =
    StoreHandle<T, A>

  export const defineStore: DefineStore
}
