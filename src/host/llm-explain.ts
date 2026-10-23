/**
 * Optional audit explanation via the harness llm service (ctx.llm.stream).
 */

import type { Context } from '@deepseek-ai/cordis'
import { EXPLAIN_SYSTEM } from '../core/explain.ts'
import { collectStreamParts } from './stream-text.ts'

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

type DefaultModelService = {
  currentSelection(): { provider?: string; model?: string; reasoningEffort?: string }
}

type ExplainRoute = {
  provider: string
  model: string
  reasoningEffort?: string
}

type ExplainHost = Context & {
  agents?: AgentsRegistry
  agentDefaultModel?: DefaultModelService
  llm?: LlmRuntime
}

function asRoute(value: { provider?: string; model?: string; reasoningEffort?: string } | undefined): ExplainRoute | undefined {
  if (typeof value?.provider !== 'string' || value.provider === ''
    || typeof value?.model !== 'string' || value.model === '') {
    return undefined
  }
  return {
    provider: value.provider,
    model: value.model,
    ...(typeof value.reasoningEffort === 'string' && value.reasoningEffort !== ''
      ? { reasoningEffort: value.reasoningEffort }
      : {}),
  }
}

function routeFromAgent(agent: AgentFace): ExplainRoute | undefined {
  return asRoute(agent.session.requestHeader()?.config) ?? asRoute(agent.options)
}

function defaultModelService(ctx: ExplainHost): DefaultModelService | undefined {
  if (ctx.agentDefaultModel !== undefined) return ctx.agentDefaultModel
  try {
    const found = ctx.get('agentDefaultModel')
    if (found !== null && typeof found === 'object' && 'currentSelection' in found) {
      return found as DefaultModelService
    }
  } catch {
    return undefined
  }
  return undefined
}

function routeFromDefaultModel(ctx: ExplainHost): ExplainRoute | undefined {
  try {
    return asRoute(defaultModelService(ctx)?.currentSelection())
  } catch {
    return undefined
  }
}

/** User's current default model first, then a live session, then the catalog. */
export async function resolveExplainRoute(ctx: Context): Promise<ExplainRoute | undefined> {
  const host = ctx as ExplainHost
  const selected = routeFromDefaultModel(host)
  if (selected !== undefined) return selected

  if (host.agents !== undefined) {
    for (const agent of host.agents.list()) {
      const route = routeFromAgent(agent)
      if (route !== undefined) return route
    }
  }

  const llm = host.llm
  if (llm === undefined) return undefined

  for (const provider of llm.listProviders()) {
    const models = await llm.listModels(provider.id)
    if (models.length > 0) {
      return { provider: provider.id, model: models[0].id }
    }
  }
  return undefined
}

/**
 * Room for reasoning models, whose thinking counts against the same budget;
 * the prompt keeps the visible answer short.
 */
const EXPLAIN_MAX_TOKENS = 4096

export type ExplainResult = {
  readonly text: string
  /** The model hit the token budget, so the text ends mid-thought. */
  readonly truncated: boolean
}

/** Stream one bounded explanation; does not change audit verdict. */
export async function explainWithLlm(ctx: Context, prompt: string): Promise<string> {
  return (await explainWithLlmResult(ctx, prompt)).text
}

export async function explainWithLlmResult(ctx: Context, prompt: string): Promise<ExplainResult> {
  const llm = (ctx as Context & { llm?: LlmRuntime }).llm
  if (llm === undefined) {
    throw new Error('llm service is not available')
  }

  const route = await resolveExplainRoute(ctx)
  if (route === undefined) {
    throw new Error('no model configured')
  }

  const via = `${route.provider}/${route.model}`
  let parts
  try {
    parts = await collectStreamParts(llm.stream({
      provider: route.provider,
      model: route.model,
      ...(route.reasoningEffort === undefined ? {} : { reasoningEffort: route.reasoningEffort }),
      system: EXPLAIN_SYSTEM,
      messages: [{
        role: 'user',
        content: [{ type: 'text', text: prompt }],
      }],
      maxTokens: EXPLAIN_MAX_TOKENS,
      temperature: 0.3,
    }))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`${message} (${via})`)
  }

  const truncated = parts.finish === 'max-tokens'
  if (parts.text === '' && truncated) throw new Error(`llm used the whole token budget before answering (${via})`)
  const text = (parts.text || parts.reasoning).trim()
  if (text === '') throw new Error(`llm returned empty response (${via})`)
  return { text, truncated }
}
