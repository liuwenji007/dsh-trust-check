/**
 * Optional audit explanation via the harness llm service (ctx.llm.stream).
 */

import type { Context } from '@deepseek-ai/cordis'
import { EXPLAIN_SYSTEM } from '../core/explain.ts'
import { collectStreamText } from './stream-text.ts'

type LlmRuntime = {
  listProviders(): readonly { id: string }[]
  listModels(provider: string): Promise<readonly { id: string }[]>
  stream(options: Record<string, unknown>): AsyncIterable<Record<string, unknown>>
}

type AgentFace = {
  readonly id: string
  readonly options: { provider?: string; model?: string }
  readonly session: {
    requestHeader(): { config?: { provider?: string; model?: string } } | undefined
  }
}

type AgentsRegistry = {
  list(): readonly AgentFace[]
}

function routeFromAgent(agent: AgentFace): { provider: string; model: string } | undefined {
  const header = agent.session.requestHeader()?.config
  if (typeof header?.provider === 'string' && header.provider !== ''
    && typeof header?.model === 'string' && header.model !== '') {
    return { provider: header.provider, model: header.model }
  }
  const opts = agent.options
  if (typeof opts.provider === 'string' && opts.provider !== ''
    && typeof opts.model === 'string' && opts.model !== '') {
    return { provider: opts.provider, model: opts.model }
  }
  return undefined
}

/** Resolve provider/model from a live agent, else the first registered catalog entry. */
export async function resolveExplainRoute(ctx: Context): Promise<{ provider: string; model: string } | undefined> {
  const agents = (ctx as Context & { agents?: AgentsRegistry }).agents
  if (agents !== undefined) {
    for (const agent of agents.list()) {
      const route = routeFromAgent(agent)
      if (route !== undefined) return route
    }
  }

  const llm = (ctx as Context & { llm?: LlmRuntime }).llm
  if (llm === undefined) return undefined

  for (const provider of llm.listProviders()) {
    const models = await llm.listModels(provider.id)
    if (models.length > 0) {
      return { provider: provider.id, model: models[0].id }
    }
  }
  return undefined
}

/** Stream one bounded explanation; does not change audit verdict. */
export async function explainWithLlm(ctx: Context, prompt: string): Promise<string> {
  const llm = (ctx as Context & { llm?: LlmRuntime }).llm
  if (llm === undefined) {
    throw new Error('llm service is not available')
  }

  const route = await resolveExplainRoute(ctx)
  if (route === undefined) {
    throw new Error('no model configured')
  }

  const agents = (ctx as Context & { agents?: AgentsRegistry }).agents
  const sessionId = agents?.list()[0]?.id

  const text = await collectStreamText(llm.stream({
    provider: route.provider,
    model: route.model,
    system: EXPLAIN_SYSTEM,
    messages: [{
      id: `dsh-trust-check-explain-${Date.now()}`,
      role: 'user',
      content: [{ type: 'text', text: prompt }],
      source: { kind: 'plugin', plugin: 'dsh-trust-check' },
    }],
    maxTokens: 1200,
    temperature: 0.3,
    ...(sessionId === undefined ? {} : { sessionId }),
  }))

  const trimmed = text.trim()
  if (trimmed === '') throw new Error('llm returned empty response')
  return trimmed
}
