/**
 * dsh-trust-check host entry: a single read-only audit route mounted once the
 * profile composes the webServer service. No mutation, no network.
 */

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { auditPlugin } from './core/audit.ts'
import { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'
import type { AuditReport, AuditResponse } from './core/types.ts'

export type { AuditReport, AuditResponse } from './core/types.ts'
export { auditPlugin } from './core/audit.ts'
export { collectPlugin, readInstalled, resolveProfileDir } from './fs.ts'

export const name = 'dsh-trust-check'

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

/** The profile this host booted (`--profile <name>`), like dsh-market. */
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

function runAudit(profile: string): AuditResponse {
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

  return { profile, generatedAt: new Date().toISOString(), plugins, errors }
}

export function apply(ctx: Context, config?: Config): void {
  ctx.inject(['webServer', 'loader'], (hostCtx: Context) => {
    const host = hostCtx as unknown as Host
    host.effect(() => {
      const profile = config?.profile ?? argvProfile() ?? 'web'
      return host.webServer.register({
        kind: 'exact',
        path: '/dsh-trust-check/audit',
        handler: (_request, response) => {
          sendJson(response, 200, runAudit(profile))
        },
      })
    }, 'dsh-trust-check: audit route')
  })
}
