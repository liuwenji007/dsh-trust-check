import { describe, expect, it, vi } from 'vitest'
import { explainWithLlm, resolveExplainRoute } from '../../src/host/llm-explain.ts'

describe('resolveExplainRoute', () => {
  it('prefers a live agent session header config', async () => {
    const ctx = {
      agents: {
        list: () => [{
          id: 's1',
          options: { provider: 'fallback-p', model: 'fallback-m' },
          session: {
            requestHeader: () => ({ config: { provider: 'deepseek', model: 'chat' } }),
          },
        }],
      },
      llm: { listProviders: () => [], listModels: vi.fn() },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'deepseek',
      model: 'chat',
    })
  })

  it('falls back to agent options then llm catalog', async () => {
    const ctx = {
      agents: {
        list: () => [{
          id: 's1',
          options: { provider: 'openai', model: 'gpt-4o-mini' },
          session: { requestHeader: () => ({ config: {} }) },
        }],
      },
      llm: { listProviders: () => [], listModels: vi.fn() },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'openai',
      model: 'gpt-4o-mini',
    })
  })

  it('uses first registered provider model when no agent route exists', async () => {
    const ctx = {
      agents: { list: () => [] },
      llm: {
        listProviders: () => [{ id: 'deepseek' }],
        listModels: vi.fn(async () => [{ id: 'reasoner' }]),
      },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'deepseek',
      model: 'reasoner',
    })
  })
})

describe('explainWithLlm', () => {
  it('streams assistant text through ctx.llm', async () => {
    async function* stream() {
      yield { type: 'text-delta', index: 0, text: 'Hello ' }
      yield { type: 'text-delta', index: 0, text: 'world' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    }

    const ctx = {
      agents: { list: () => [] },
      llm: {
        listProviders: () => [{ id: 'p' }],
        listModels: async () => [{ id: 'm' }],
        stream: vi.fn(() => stream()),
      },
    }

    await expect(explainWithLlm(ctx as never, 'explain this')).resolves.toBe('Hello world')
    expect(ctx.llm.stream).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'p',
      model: 'm',
      system: expect.stringContaining('NOT a security verdict'),
    }))
  })
})
