import { describe, expect, it, vi } from 'vitest'
import { explainWithLlm, explainWithLlmResult, resolveExplainRoute } from '../../src/host/llm-explain.ts'

describe('resolveExplainRoute', () => {
  it('falls back to a live session header when no default model is set', async () => {
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

  it('uses the user default model before the first catalog entry', async () => {
    const ctx = {
      agents: { list: () => [] },
      agentDefaultModel: {
        currentSelection: () => ({ provider: 'deepseek-account', model: 'deepseek-flash' }),
      },
      llm: {
        listProviders: () => [{ id: 'deepseek-official' }],
        listModels: vi.fn(async () => [{ id: 'deepseek-flash' }]),
      },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'deepseek-account',
      model: 'deepseek-flash',
    })
    expect(ctx.llm.listModels).not.toHaveBeenCalled()
  })

  it('prefers the user default model over a stale live session', async () => {
    const ctx = {
      agents: {
        list: () => [{
          id: 's1',
          options: { provider: 'deepseek-official', model: 'deepseek-flash' },
          session: { requestHeader: () => undefined },
        }],
      },
      agentDefaultModel: {
        currentSelection: () => ({ provider: 'deepseek-account', model: 'deepseek-flash' }),
      },
      llm: { listProviders: () => [], listModels: vi.fn() },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'deepseek-account',
      model: 'deepseek-flash',
    })
  })

  it('reads the default model through ctx.get when the property is missing', async () => {
    const ctx = {
      get: (name: string) => name === 'agentDefaultModel'
        ? { currentSelection: () => ({ provider: 'deepseek-account', model: 'deepseek-flash' }) }
        : undefined,
      agents: { list: () => [] },
      llm: {
        listProviders: () => [{ id: 'deepseek-official' }],
        listModels: vi.fn(async () => [{ id: 'deepseek-flash' }]),
      },
    }
    await expect(resolveExplainRoute(ctx as never)).resolves.toEqual({
      provider: 'deepseek-account',
      model: 'deepseek-flash',
    })
  })

  it('uses first registered provider model when no agent or default route exists', async () => {
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
  it('does not stamp a live chat session onto the one-shot reading', async () => {
    async function* stream() {
      yield { type: 'text-delta', index: 0, text: 'ok' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    }
    const ctx = {
      agents: {
        list: () => [{
          id: 'live-session',
          options: { provider: 'deepseek-official', model: 'deepseek-flash' },
          session: { requestHeader: () => undefined },
        }],
      },
      agentDefaultModel: {
        currentSelection: () => ({
          provider: 'deepseek-account',
          model: 'deepseek-flash',
          reasoningEffort: 'high',
        }),
      },
      llm: {
        listProviders: () => [],
        listModels: async () => [],
        stream: vi.fn(() => stream()),
      },
    }
    await expect(explainWithLlm(ctx as never, 'p')).resolves.toBe('ok')
    expect(ctx.llm.stream).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'deepseek-account',
      model: 'deepseek-flash',
      reasoningEffort: 'high',
    }))
    expect(ctx.llm.stream.mock.calls[0][0]).not.toHaveProperty('sessionId')
  })

  it('names the chosen route when the stream fails', async () => {
    async function* stream() {
      yield { type: 'finish', reason: { kind: 'error', failure: { message: 'Authentication Fails, Your api key: ****745f is invalid' } } }
    }
    const ctx = {
      agents: { list: () => [] },
      agentDefaultModel: {
        currentSelection: () => ({ provider: 'deepseek-account', model: 'deepseek-flash' }),
      },
      llm: {
        listProviders: () => [],
        listModels: async () => [],
        stream: vi.fn(() => stream()),
      },
    }
    await expect(explainWithLlm(ctx as never, 'p')).rejects.toThrow(
      /deepseek-account\/deepseek-flash/,
    )
  })

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

  function ctxWith(chunks: Record<string, unknown>[]) {
    async function* stream() {
      yield* chunks
    }
    return {
      agents: { list: () => [] },
      llm: {
        listProviders: () => [{ id: 'p' }],
        listModels: async () => [{ id: 'm' }],
        stream: vi.fn(() => stream()),
      },
    }
  }

  it('flags a reading cut off by the token budget', async () => {
    const ctx = ctxWith([
      { type: 'reasoning-delta', index: 0, text: 'thinking' },
      { type: 'text-delta', index: 1, text: '可能属于本职的：三段' },
      { type: 'finish', reason: { kind: 'max-tokens' } },
    ])
    await expect(explainWithLlmResult(ctx as never, 'p')).resolves.toEqual({ text: '可能属于本职的：三段', truncated: true })
    expect(ctx.llm.stream).toHaveBeenCalledWith(expect.objectContaining({ maxTokens: 4096 }))
  })

  it('refuses to show bare reasoning when the budget ran out before any answer', async () => {
    const ctx = ctxWith([
      { type: 'reasoning-delta', index: 0, text: 'still thinking' },
      { type: 'finish', reason: { kind: 'max-tokens' } },
    ])
    await expect(explainWithLlmResult(ctx as never, 'p')).rejects.toThrow(/token budget/)
  })

  it('reports a complete reading as not truncated', async () => {
    const ctx = ctxWith([
      { type: 'text-delta', index: 0, text: 'done.' },
      { type: 'finish', reason: { kind: 'stop' } },
    ])
    await expect(explainWithLlmResult(ctx as never, 'p')).resolves.toEqual({ text: 'done.', truncated: false })
  })
})
