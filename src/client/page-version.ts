/**
 * Page build version, replaced in the client bundle by tsdown `define`.
 * This is the settings page build, not the scanner engine version.
 * Cached reports do not record a scanner version, so callers must not
 * present this string as one.
 */
declare const __DSH_TRUST_PAGE_VERSION__: string | undefined

/** Page build version injected by the client build, or `dev` outside that build. */
export function pageVersion(): string {
  try {
    const value = __DSH_TRUST_PAGE_VERSION__
    return typeof value === 'string' && value.length > 0 ? value : 'dev'
  } catch {
    return 'dev'
  }
}
