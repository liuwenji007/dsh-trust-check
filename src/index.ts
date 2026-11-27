/**
 * dsh-trust-check host entry: audit, ack, and optional explain routes.
 */

import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { readAckStore, removeAck, setAck } from './core/ack.ts'
import { auditPlugin } from './core/audit.ts'
import { explainWithLlmResult, type ExplainResult } from './host/llm-explain.ts'
import { buildExplainPrompt } from './core/explain.ts'
import { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'
import { buildAuditResponse } from './core/response.ts'
import type { AuditReport, AuditResponse, TrustAckEntry } from './core/types.ts'

export type { AuditReport, AuditResponse, TrustAckEntry } from './core/types.ts'
export { AUDIT_SCHEMA_VERSION, buildAuditResponse } from './core/response.ts'
export { auditPlugin, MAX_EVIDENCE } from './core/audit.ts'
export {
  ackDrifted,
  capabilityContext,
  capabilityDelta,
  capabilityTier,
  classifyRedLine,
  concerns,
  concernText,
  countVerdicts,
  formatInjectionDetail,
  groupEvidence,
  groupEvidenceByFile,
  groupInjections,
  networkReach,
  repositoryHref,
  topCapabilities,
  verdict,
} from './core/present.ts'
export {
  DEST_WHITELIST,
  destinationHighlight,
  destinationTier,
  destinationWhitelistReason,
  isPrivateIp,
  matchDestWhitelist,
  partitionDestinations,
} from './core/destination-priority.ts'
export { fingerprintFromReport, readAckStore, removeAck, setAck } from './core/ack.ts'
export {
  ackMatchesReport,
  normalizeAuditReport,
  normalizeAuditResponse,
} from './core/ack-fingerprint.ts'
export { injectionFingerprint } from './core/injection.ts'
export { blankComments, isCodeFile, stripComments } from './core/strip-comments.ts'
export { buildExplainPrompt, EXPLAIN_SYSTEM } from './core/explain.ts'
export { explainWithLlm, explainWithLlmResult, resolveExplainRoute, type ExplainResult } from './host/llm-explain.ts'
export type { Concern, ConcernCode, NetworkReach, PresentLang, RedLineCode, Verdict } from './core/present.ts'
export { formatHumanReport, resolveCliColor, resolveCliLang, concernEvidenceLines } from './core/cli-report.ts'
export type { CliLang, HumanReportOptions } from './core/cli-report.ts'
export { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'
export { readNpmProvenance } from './npm-provenance.ts'
export type { NpmProvenance, NpmProvenanceOptions } from './npm-provenance.ts'

export const name = 'dsh-trust-check'

/** Host services required for audit routes and optional LLM explanation. */
export const inject = ['webServer', 'loader', 'llm', 'agents', 'agentDefaultModel']

/** Optional cordis.yml configuration; profile defaults to the host's active profile. */
export type Config = {
  profile?: string
}

interface WebServerService {
  register(route: {
    kind: 'exact' | 'prefix'
    path: string
    handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>
  }): () => void
}

interface Host {
  webServer: WebServerService
  loader: { entries(): Iterable<unknown> }
  effect(callback: () => (() => void | Promise<void>) | void, label: string): void
  logger?: { warn(message: string): void; info?(message: string): void }
}

function argvProfile(argv: readonly string[]): string | undefined {
  const flag = argv.indexOf('--profile')
  if (flag !== -1 && flag + 1 < argv.length && !argv[flag + 1].startsWith('-')) return argv[flag + 1]
  return undefined
}

/** A profile by name, and the directory its manifest and plugins live in. */
export interface ActiveProfile {
  name: string
  dir: string
}

/**
 * Same rule as DSH's own profile names: only empty, traversal-shaped,
 * launcher-owned, or separator-bearing names are refused.
 */
function isProfileName(name: string): boolean {
  return name !== ''
    && name !== '.'
    && name !== '..'
    && name !== 'node_modules'
    && !name.includes('/')
    && !name.includes('\\')
    && !name.includes('\0')
}

/** A host-published `{ name, dir }`, or undefined when either field is unusable. */
function hostProfile(value: unknown): ActiveProfile | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const { name, dir } = value as { name?: unknown; dir?: unknown }
  if (typeof name !== 'string' || typeof dir !== 'string') return undefined
  const trimmedName = name.trim()
  const trimmedDir = dir.trim()
  if (!isProfileName(trimmedName) || !isAbsolute(trimmedDir)) return undefined
  return { name: trimmedName, dir: trimmedDir }
}

/**
 * The profile this host process serves. DSH Desktop starts a profile through
 * the launcher, not the CLI, so there is no `--profile` flag to read; the
 * host names the profile and owns where it lives. A desktop shell's
 * `desktopProfiles` wins, then `profile` from cordis.yml, then the launcher's
 * `profileContext`, then the flag, then `web`.
 */
export function resolveActiveProfile(
  service: (name: string) => unknown,
  config?: Config,
  argv: readonly string[] = process.argv,
): ActiveProfile {
  const shell = service('desktopProfiles') as { current?: unknown } | null | undefined
  const shellProfile = hostProfile(shell?.current)
  if (shellProfile !== undefined) return shellProfile
  const launched = hostProfile(service('profileContext'))
  if (config?.profile !== undefined) {
    return launched?.name.toLowerCase() === config.profile.toLowerCase()
      ? launched
      : { name: config.profile, dir: resolveProfileDir(config.profile) }
  }
  if (launched !== undefined) return launched
  const name = argvProfile(argv) ?? 'web'
  return { name, dir: resolveProfileDir(name) }
}

function sendJson(response: ServerResponse, status: number, payload: unknown): void {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  })
  response.end(JSON.stringify(payload))
}

export function isLoopbackRequest(request: IncomingMessage): boolean {
  const address = request.socket.remoteAddress
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

/** Whole 127.0.0.0/8, plus the names the host fence treats as loopback. */
function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true
  const parts = hostname.split('.')
  return parts.length === 4
    && parts[0] === '127'
    && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function headerValue(headers: IncomingMessage['headers'], name: string): string | undefined {
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

function parseAuthority(authority: string): URL | undefined {
  try {
    return new URL(`http://${authority}`)
  } catch {
    return undefined
  }
}

/**
 * Canonical `host` or `host:port`. A written port is kept even when it is a
 * scheme default (`:80` / `:443`), matching the host `/api` fence.
 */
function canonicalAuthority(entry: string, entryUrl: URL): string {
  const port = entryUrl.port !== '' ? entryUrl.port : new URL(`https://${entry}`).port
  return port === '' ? entryUrl.hostname : `${entryUrl.hostname}:${port}`
}

/** Port-less entries match the hostname on any port; `host:port` is exact. */
function isTrustedAuthority(hostUrl: URL, trustedHosts: readonly string[]): boolean {
  return trustedHosts.some(entry => {
    const entryUrl = parseAuthority(entry)
    if (entryUrl === undefined) return false
    return canonicalAuthority(entry, entryUrl) === entryUrl.hostname
      ? entryUrl.hostname === hostUrl.hostname
      : entryUrl.host === hostUrl.host
  })
}

/**
 * Same reachability rule as the host's ordinary `/api` fence
 * (`isTrustedApiRequest`): loopback hostname or a declared trusted authority,
 * then `Sec-Fetch-Site: cross-site` and Origin-host checks. Not authentication,
 * and not the host's privileged-RPC (loopback-only) fence. Peer address and
 * forwarding headers are ignored — a reverse proxy is a trusted-host deployment.
 *
 * Semantics are copied because `@deepseek-ai/dsh-client-connection` does not
 * export the function. Keep this in step with that implementation.
 */
export function trustedAuditRequest(
  request: IncomingMessage,
  trustedHosts: readonly string[] = [],
): boolean {
  const host = headerValue(request.headers, 'host')
  if (host === undefined) return false
  const hostUrl = parseAuthority(host)
  if (hostUrl === undefined) return false
  if (!isLoopbackHostname(hostUrl.hostname) && !isTrustedAuthority(hostUrl, trustedHosts)) return false
  if (headerValue(request.headers, 'sec-fetch-site') === 'cross-site') return false
  const origin = headerValue(request.headers, 'origin')
  if (origin === undefined) return true
  try {
    return new URL(origin).host === hostUrl.host
  } catch {
    return false
  }
}

/**
 * `webRuntime.trustedHosts` (LAN literals plus `--trusted-host`) when the host
 * has published it; otherwise `webStartup.trustedHosts`; otherwise none.
 * Read on each request: Cordis has no optional inject, and `ctx.get` sees
 * services in the same isolation scope without waiting on them at mount.
 */
export function auditTrustedHosts(get: (name: string) => unknown): readonly string[] {
  const listOf = (name: string): readonly string[] | undefined => {
    const service = get(name)
    if (service === undefined || service === null || typeof service !== 'object') return undefined
    const list = (service as { trustedHosts?: unknown }).trustedHosts
    if (!Array.isArray(list)) return undefined
    return list.filter((entry): entry is string => typeof entry === 'string')
  }
  return listOf('webRuntime') ?? listOf('webStartup') ?? []
}

/**
 * Red lines take a deliberate opt-in, so a plain ack call — replayed, or made
 * by anything else on the loopback origin — cannot quietly silence one.
 */
export function ackAllowed(report: AuditReport, acceptRisk: boolean): boolean {
  return report.redLines.length === 0 || acceptRisk
}

/**
 * @deprecated The `entry` on the 200 branch is unused; the route persists via `setAck`.
 * Schema v2 will return `{ status: 200 }` only.
 */
export function decideAckSave(
  fresh: AuditReport,
  clientFingerprint: string | undefined,
  acceptRisk: boolean,
): { status: 200; entry: TrustAckEntry } | { status: 400; error: string } | { status: 409; report: AuditReport } {
  if (clientFingerprint !== fresh.ackFingerprint) {
    return { status: 409, report: fresh }
  }
  if (!ackAllowed(fresh, acceptRisk)) {
    return { status: 400, error: 'acknowledging a plugin with red lines requires acceptRisk: true' }
  }
  return {
    status: 200,
    entry: {
      digest: fresh.ackFingerprint,
      capabilities: fresh.capabilities,
      destinations: [],
      secretTouches: [],
      at: new Date().toISOString(),
    },
  }
}

const MAX_BODY_BYTES = 64 * 1024

export class BodyTooLarge extends Error {
  constructor(limit: number) {
    super(`request body exceeds ${limit} bytes`)
    this.name = 'BodyTooLarge'
  }
}

/** Status for a body-read failure; undefined means the caller handles it. */
export function requestBodyStatus(error: unknown): 413 | 400 | undefined {
  if (error instanceof BodyTooLarge) return 413
  if (error instanceof SyntaxError) return 400
  return undefined
}

export async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_BODY_BYTES) throw new BodyTooLarge(MAX_BODY_BYTES)
    chunks.push(buffer)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text === '') return {}
  return JSON.parse(text) as unknown
}

function sendBodyError(response: ServerResponse, error: unknown): boolean {
  const status = requestBodyStatus(error)
  if (status === undefined) return false
  const message = error instanceof Error ? error.message : String(error)
  sendJson(response, status, { error: status === 400 ? 'request body is not valid JSON' : message })
  return true
}

function manifestName(dir: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: unknown }
    return typeof parsed.name === 'string' ? parsed.name : undefined
  } catch {
    return undefined
  }
}

/**
 * Reports (and the acks keyed off them) carry the plugin's own manifest name,
 * which need not equal its dependency key in the profile — npm aliases, or a
 * plugin that simply names itself differently. Match on the manifest name
 * first; fall back to the dependency key for API callers that use it.
 */
export function resolveInstalledKey(
  profileDir: string,
  installed: Record<string, string>,
  name: string,
): { key: string } | { ambiguous: true } | undefined {
  const matches = Object.keys(installed).filter(key =>
    manifestName(join(profileDir, 'node_modules', key)) === name)
  if (matches.length > 1) return { ambiguous: true }
  if (matches.length === 1) return { key: matches[0] }
  return installed[name] !== undefined ? { key: name } : undefined
}

type PluginLookup = { report: AuditReport } | { ambiguous: true } | undefined

function findPluginReport(profileDir: string, name: string): PluginLookup {
  const installed = readInstalled(profileDir)
  const resolved = resolveInstalledKey(profileDir, installed, name)
  if (resolved === undefined || 'ambiguous' in resolved) return resolved
  const dir = join(profileDir, 'node_modules', resolved.key)
  if (!existsSync(dir)) return undefined
  return { report: auditPlugin(collectPlugin(dir, installed[resolved.key])) }
}

function sendLookupFailure(response: ServerResponse, lookup: Exclude<PluginLookup, { report: AuditReport }>): void {
  if (lookup === undefined) sendJson(response, 404, { error: 'plugin not found' })
  else sendJson(response, 400, { error: 'plugin-name-ambiguous' })
}

export function runAudit(profile: string, profileDir: string = resolveProfileDir(profile)): AuditResponse {
  const plugins: AuditReport[] = []
  const errors: AuditResponse['errors'] = []
  let installed: Record<string, string>
  try {
    installed = readInstalled(profileDir)
  } catch (error) {
    errors.push({
      name: '(profile)',
      spec: profile,
      message: error instanceof Error ? error.message : String(error),
    })
    return buildAuditResponse({ profile, plugins, errors, acks: {} })
  }

  for (const [name, spec] of Object.entries(installed)) {
    const dir = join(profileDir, 'node_modules', name)
    if (!existsSync(dir)) {
      errors.push({ name, spec, message: `declared plugin directory missing: ${dir}` })
      continue
    }
    try {
      plugins.push(auditPlugin(collectPlugin(dir, spec)))
    } catch (error) {
      errors.push({ name, spec, message: error instanceof Error ? error.message : String(error) })
    }
  }

  plugins.sort((a, b) => a.score - b.score)
  const acks = readAckStore(profileDir)

  return buildAuditResponse({ profile, plugins, errors, acks })
}

async function llmExplain(ctx: Context, prompt: string): Promise<ExplainResult> {
  return explainWithLlmResult(ctx, prompt)
}

function guard(
  request: IncomingMessage,
  response: ServerResponse,
  trustedHosts: readonly string[],
): boolean {
  if (!trustedAuditRequest(request, trustedHosts)) {
    sendJson(response, 403, { error: 'audit is limited to loopback or host-trusted same-origin requests' })
    return false
  }
  return true
}

export function apply(ctx: Context, config?: Config): void {
  ctx.inject(['webServer', 'loader', 'llm', 'agents', 'agentDefaultModel'], (hostCtx: Context) => {
    const host = hostCtx as unknown as Host
    // Per request: the launcher may publish profileContext after this plugin mounts.
    const activeProfile = (): ActiveProfile => resolveActiveProfile(name => ctx.get(name), config)
    const trustedHosts = (): readonly string[] => auditTrustedHosts(name => ctx.get(name))

    host.effect(() => {
      const disposers = [
        host.webServer.register({
          kind: 'exact',
          path: '/dsh-trust-check/audit',
          handler: (request, response) => {
            if (request.method !== undefined && request.method !== 'GET') {
              response.writeHead(405, { allow: 'GET' })
              response.end()
              return
            }
            if (!guard(request, response, trustedHosts())) return
            const profile = activeProfile()
            sendJson(response, 200, runAudit(profile.name, profile.dir))
          },
        }),
        host.webServer.register({
          kind: 'exact',
          path: '/dsh-trust-check/ack',
          handler: async (request, response) => {
            if (!guard(request, response, trustedHosts())) return
            const method = request.method ?? 'GET'
            if (method === 'POST') {
              try {
                const body = await readJsonBody(request) as {
                  name?: string
                  acceptRisk?: boolean
                  fingerprint?: string
                }
                if (typeof body.name !== 'string' || body.name === '') {
                  sendJson(response, 400, { error: 'name is required' })
                  return
                }
                const profileDir = activeProfile().dir
                const lookup = findPluginReport(profileDir, body.name)
                if (lookup === undefined || 'ambiguous' in lookup) {
                  sendLookupFailure(response, lookup)
                  return
                }
                const { report } = lookup
                const decision = decideAckSave(report, body.fingerprint, body.acceptRisk === true)
                if (decision.status === 409) {
                  sendJson(response, 409, { error: 'plugin-content-changed', report: decision.report })
                  return
                }
                if (decision.status === 400) {
                  sendJson(response, 400, { error: decision.error })
                  return
                }
                const entry = setAck(profileDir, report)
                sendJson(response, 200, { name: body.name, ack: entry })
              } catch (error) {
                if (sendBodyError(response, error)) return
                sendJson(response, 500, { error: error instanceof Error ? error.message : String(error) })
              }
              return
            }
            if (method === 'DELETE') {
              const url = new URL(request.url ?? '', 'http://local')
              const name = url.searchParams.get('name')
              if (name === null || name === '') {
                sendJson(response, 400, { error: 'name query param is required' })
                return
              }
              try {
                removeAck(activeProfile().dir, name)
              } catch (error) {
                sendJson(response, 500, { error: error instanceof Error ? error.message : String(error) })
                return
              }
              sendJson(response, 200, { ok: true })
              return
            }
            response.writeHead(405, { allow: 'POST, DELETE' })
            response.end()
          },
        }),
        host.webServer.register({
          kind: 'exact',
          path: '/dsh-trust-check/explain',
          handler: async (request, response) => {
            if ((request.method ?? 'GET') !== 'POST') {
              response.writeHead(405, { allow: 'POST' })
              response.end()
              return
            }
            if (!guard(request, response, trustedHosts())) return
            try {
              const body = await readJsonBody(request) as { name?: string; locale?: string }
              if (typeof body.name !== 'string' || body.name === '') {
                sendJson(response, 400, { error: 'name is required' })
                return
              }
              const lookup = findPluginReport(activeProfile().dir, body.name)
              if (lookup === undefined || 'ambiguous' in lookup) {
                sendLookupFailure(response, lookup)
                return
              }
              const prompt = buildExplainPrompt(lookup.report, body.locale)
              const { text, truncated } = await llmExplain(hostCtx, prompt)
              sendJson(response, 200, { name: body.name, text, truncated, disclaimer: 'explanation only, not a security verdict' })
            } catch (error) {
              if (sendBodyError(response, error)) return
              const message = error instanceof Error ? error.message : String(error)
              if (message.includes('not available') || message.includes('no model configured')) {
                sendJson(response, 503, { error: message })
                return
              }
              sendJson(response, 500, { error: message })
            }
          },
        }),
      ]
      return () => {
        for (const dispose of disposers) dispose()
      }
    }, 'dsh-trust-check: routes')
  })
}
