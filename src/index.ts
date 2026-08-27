/**
 * dsh-trust-check host entry: audit, ack, and optional explain routes.
 */

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { readAckStore, removeAck, setAck } from './core/ack.ts'
import { auditPlugin } from './core/audit.ts'
import { explainWithLlm } from './host/llm-explain.ts'
import { buildExplainPrompt } from './core/explain.ts'
import { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'
import type { AuditReport, AuditResponse } from './core/types.ts'

export type { AuditReport, AuditResponse, TrustAckEntry } from './core/types.ts'
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

export function trustedAuditRequest(request: IncomingMessage): boolean {
  if (!isLoopbackRequest(request)) return false
  if (request.headers.forwarded !== undefined
    || request.headers['x-forwarded-for'] !== undefined
    || request.headers['x-real-ip'] !== undefined) return false
  const origin = request.headers.origin
  const host = request.headers.host
  if (host === undefined) return false
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

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(Buffer.from(chunk))
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text === '') return {}
  return JSON.parse(text) as unknown
}

function findPluginReport(profile: string, name: string): AuditReport | undefined {
  const profileDir = resolveProfileDir(profile)
  const installed = readInstalled(profileDir)
  const spec = installed[name]
  if (spec === undefined) return undefined
  const dir = join(profileDir, 'node_modules', name)
  if (!existsSync(dir)) return undefined
  return auditPlugin(collectPlugin(dir, spec))
}

export function runAudit(profile: string): AuditResponse {
  const profileDir = resolveProfileDir(profile)
  const installed = readInstalled(profileDir)
  const plugins: AuditReport[] = []
  const errors: AuditResponse['errors'] = []

  for (const [name, spec] of Object.entries(installed)) {
    const dir = join(profileDir, 'node_modules', name)
    if (!existsSync(dir)) continue
    try {
      plugins.push(auditPlugin(collectPlugin(dir, spec)))
    } catch (error) {
      errors.push({ name, spec, message: error instanceof Error ? error.message : String(error) })
    }
  }

  plugins.sort((a, b) => a.score - b.score)
  const acks = readAckStore(profileDir)

  return { profile, generatedAt: new Date().toISOString(), plugins, errors, acks }
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
                const body = await readJsonBody(request) as { name?: string; acceptRisk?: boolean }
                if (typeof body.name !== 'string' || body.name === '') {
                  sendJson(response, 400, { error: 'name is required' })
                  return
                }
                const report = findPluginReport(profile, body.name)
                if (report === undefined) {
                  sendJson(response, 404, { error: 'plugin not found' })
                  return
                }
                if (!ackAllowed(report, body.acceptRisk === true)) {
                  sendJson(response, 400, {
                    error: 'acknowledging a plugin with red lines requires acceptRisk: true',
                  })
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
              removeAck(resolveProfileDir(profile), name)
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
              const report = findPluginReport(profile, body.name)
              if (report === undefined) {
                sendJson(response, 404, { error: 'plugin not found' })
                return
              }
              const prompt = buildExplainPrompt(report, body.locale)
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
