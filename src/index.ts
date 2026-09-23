/**
 * dsh-trust-check host entry: audit, ack, and optional explain routes.
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { readAckStore, removeAck, setAck } from './core/ack.ts'
import { auditPlugin } from './core/audit.ts'
import { explainWithLlm } from './host/llm-explain.ts'
import { buildExplainPrompt } from './core/explain.ts'
import { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'
import { buildAuditResponse } from './core/response.ts'
import type { AuditReport, AuditResponse, TrustAckEntry } from './core/types.ts'

export type { AuditReport, AuditResponse, TrustAckEntry } from './core/types.ts'
export { AUDIT_SCHEMA_VERSION, buildAuditResponse } from './core/response.ts'
export { auditPlugin, MAX_EVIDENCE } from './core/audit.ts'
export {
  ackDrifted,
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
export { isCodeFile, stripComments } from './core/strip-comments.ts'
export { buildExplainPrompt, EXPLAIN_SYSTEM } from './core/explain.ts'
export { explainWithLlm, resolveExplainRoute } from './host/llm-explain.ts'
export type { Concern, ConcernCode, NetworkReach, RedLineCode, Verdict } from './core/present.ts'
export { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'

export const name = 'dsh-trust-check'

/** Host services required for audit routes and optional LLM explanation. */
export const inject = ['webServer', 'loader', 'llm', 'agents']

/** Optional cordis.yml configuration; profile defaults to `web`. */
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

function argvProfile(): string | undefined {
  const argv = process.argv
  const flag = argv.indexOf('--profile')
  if (flag !== -1 && flag + 1 < argv.length && !argv[flag + 1].startsWith('-')) return argv[flag + 1]
  return undefined
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

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])

/**
 * A loopback peer is not enough: a DNS-rebound page reaches 127.0.0.1 with
 * its own name in Host and a matching Origin. Only loopback names pass.
 */
function loopbackHostHeader(host: string): boolean {
  try {
    return LOOPBACK_HOSTNAMES.has(new URL(`http://${host}`).hostname)
  } catch {
    return false
  }
}

export function trustedAuditRequest(request: IncomingMessage): boolean {
  if (!isLoopbackRequest(request)) return false
  if (request.headers.forwarded !== undefined
    || request.headers['x-forwarded-for'] !== undefined
    || request.headers['x-real-ip'] !== undefined) return false
  const origin = request.headers.origin
  const host = request.headers.host
  if (host === undefined || !loopbackHostHeader(host)) return false
  if (origin === undefined) return true
  try {
    const parsed = new URL(origin)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.host === host
  } catch {
    return false
  }
}

/**
 * Red lines take a deliberate opt-in, so a plain ack call — replayed, or made
 * by anything else on the loopback origin — cannot quietly silence one.
 */
export function ackAllowed(report: AuditReport, acceptRisk: boolean): boolean {
  return report.redLines.length === 0 || acceptRisk
}

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

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_BODY_BYTES) throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`)
    chunks.push(buffer)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text === '') return {}
  return JSON.parse(text) as unknown
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

function findPluginReport(profile: string, name: string): PluginLookup {
  const profileDir = resolveProfileDir(profile)
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

export function runAudit(profile: string): AuditResponse {
  const profileDir = resolveProfileDir(profile)
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

async function llmExplain(ctx: Context, prompt: string): Promise<string> {
  return explainWithLlm(ctx, prompt)
}

function guard(request: IncomingMessage, response: ServerResponse): boolean {
  if (!trustedAuditRequest(request)) {
    sendJson(response, 403, { error: 'audit is limited to same-origin loopback requests' })
    return false
  }
  return true
}

export function apply(ctx: Context, config?: Config): void {
  ctx.inject(['webServer', 'loader', 'llm', 'agents'], (hostCtx: Context) => {
    const host = hostCtx as unknown as Host
    const profile = config?.profile ?? argvProfile() ?? 'web'

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
            if (!guard(request, response)) return
            sendJson(response, 200, runAudit(profile))
          },
        }),
        host.webServer.register({
          kind: 'exact',
          path: '/dsh-trust-check/ack',
          handler: async (request, response) => {
            if (!guard(request, response)) return
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
                const lookup = findPluginReport(profile, body.name)
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
                const entry = setAck(resolveProfileDir(profile), report)
                sendJson(response, 200, { name: body.name, ack: entry })
              } catch (error) {
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
                removeAck(resolveProfileDir(profile), name)
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
            if (!guard(request, response)) return
            try {
              const body = await readJsonBody(request) as { name?: string; locale?: string }
              if (typeof body.name !== 'string' || body.name === '') {
                sendJson(response, 400, { error: 'name is required' })
                return
              }
              const lookup = findPluginReport(profile, body.name)
              if (lookup === undefined || 'ambiguous' in lookup) {
                sendLookupFailure(response, lookup)
                return
              }
              const prompt = buildExplainPrompt(lookup.report, body.locale)
              const text = await llmExplain(hostCtx, prompt)
              sendJson(response, 200, { name: body.name, text, disclaimer: 'explanation only, not a security verdict' })
            } catch (error) {
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
