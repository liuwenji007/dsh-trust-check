/**
 * Shared audit data model. Everything here is serializable JSON so the
 * node half can hand it to the client half unchanged.
 */

/** A coarse capability a plugin may exercise at runtime. */
export type Capability =
  | 'shell'
  | 'fs-read'
  | 'fs-write'
  | 'network'
  | 'credentials'
  | 'env'
  | 'subagent'
  | 'host-runtime'
  | 'llm'
  | 'dynamic-code'

/** One located piece of evidence for a capability. */
export interface Evidence {
  capability: Capability
  /** Path relative to the plugin package root. */
  file: string
  /** 1-based line number, when the file is a scanned source file. */
  line: number
  /** The matched source line, trimmed. */
  snippet: string
}

/** A literal network destination found in source (not runtime-built). */
export type DestinationKind = 'relative' | 'loopback' | 'https-host' | 'http-host' | 'ip'

export interface DestinationFinding {
  kind: DestinationKind
  /** Host, IP, or (legacy) relative path string. */
  value: string
  file: string
  line: number
}

/**
 * Filesystem path literals that may leave the workspace.
 * Same-origin HTTP routes like `/dsh-market/check` are not included.
 */
export type PathEscapeKind = 'absolute' | 'home' | 'traversal' | 'windows-abs'

export interface PathEscapeFinding {
  kind: PathEscapeKind
  value: string
  file: string
  line: number
}

export type SecretTouchKind = 'path' | 'env-key' | 'api'

export interface SecretTouchFinding {
  kind: SecretTouchKind
  value: string
  file: string
  line: number
}

/** What a plugin injects into the host or the user's context. */
export type InjectionKind =
  | 'system-prompt'
  | 'skill'
  | 'client-inject'
  | 'override'
  | 'disable'

export interface InjectionFinding {
  kind: InjectionKind
  detail: string
  /** Estimated raw bytes injected; 0 means "flagged, size unknown". */
  bytes: number
}

export type Band = 'green' | 'yellow' | 'red'

/** One point deduction in the trust score, with a human reason. */
export interface Deduction {
  reason: string
  amount: number
}

export interface AuditReport {
  /** npm package name. */
  name: string
  version: string
  /** Install spec from the profile manifest, e.g. `npm:dsh-muyu@0.1.4`. */
  spec: string
  capabilities: Capability[]
  evidence: Evidence[]
  /** Literal destinations in source (URLs, IPs). Same-origin HTTP routes are omitted. */
  destinations: DestinationFinding[]
  /** Filesystem path literals that may leave the workspace. */
  pathEscapes: PathEscapeFinding[]
  /** Literal secret/credential touch patterns. */
  secretTouches: SecretTouchFinding[]
  injections: InjectionFinding[]
  /** Coarse token estimate of injected content (bytes / 4). */
  injectedTokensEstimate: number
  /** Whether the package declares install-time build scripts. */
  hasBuildScript: boolean
  buildScripts: string[]
  /** `prepare` only — runs on publish/pack or git install, not registry install. */
  prepareScripts: string[]
  repository: string | undefined
  /** Whether the install spec is pinned to a version or commit. */
  pinned: boolean
  /** 0–100, code-computed. */
  score: number
  band: Band
  /** Reasons the band is forced to red. */
  redLines: string[]
  /** Every point deduction, for the report view. */
  deductions: Deduction[]
  /** One-line human summary. */
  summary: string
}

/**
 * The inputs the audit engine reads from a plugin directory. Pure data so
 * the engine stays a pure function and is trivially testable.
 */
export interface PluginInput {
  /** Parsed package.json. */
  manifest: Record<string, unknown>
  /** Relative path -> content for every code file worth scanning. */
  sources: Record<string, string>
  /** Relative path -> content for shipped skill/instruction text. */
  skillFiles: Record<string, string>
  /** Raw cordis.patch.yml, when present. */
  patchText: string | undefined
  /** Relative path of the patch file. */
  patchPath: string | undefined
  /** Install spec from the profile manifest. */
  spec: string
}

/** User-acknowledged capability/shape fingerprint for one plugin. */
export interface TrustAckEntry {
  capabilities: Capability[]
  destinations: string[]
  secretTouches: string[]
  /** Optional for older ack files written before path-escape scanning. */
  pathEscapes?: string[]
  /** Optional for older ack files; absence re-prompts once so injections get reviewed. */
  injections?: string[]
  /** Optional for older ack files; required for red-line risk acceptance to re-prompt on change. */
  redLines?: string[]
  at: string
}

/** The payload the audit route returns to the client. */
export interface AuditResponse {
  /** Profile name; empty when the scan target was `--dir` only. */
  profile: string
  /** Set when auditing a single package directory via CLI `--dir`. */
  dir?: string
  generatedAt: string
  plugins: AuditReport[]
  errors: { name: string; spec: string; message: string }[]
  /** Plugin name → ack fingerprint loaded from profile store. */
  acks?: Record<string, TrustAckEntry>
}
