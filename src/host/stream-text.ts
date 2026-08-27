/**
 * Collect assistant text from Harness llm.stream chunks.
 */

export type StreamChunkLike = {
  readonly type?: string
  readonly text?: string
  readonly delta?: string
  readonly index?: number
  readonly reason?: { kind?: string; failure?: { message?: string } }
  readonly block?: {
    readonly type?: string
    readonly text?: string
  }
}

export type CollectedStreamText = {
  readonly text: string
  readonly reasoning: string
}

/**
 * Collect visible assistant text from a Harness stream.
 * Prefers complete `block-end` payloads over duplicated `text-delta` + block-end.
 */
export async function collectStreamParts(
  stream: AsyncIterable<StreamChunkLike>,
  signal?: AbortSignal,
): Promise<CollectedStreamText> {
  const deltas = new Map<number, string>()
  const blocks = new Map<number, string>()
  let reasoning = ''
  let fallback = ''

  for await (const chunk of stream) {
    if (signal?.aborted) throw new Error('aborted')
    if (chunk.type === 'finish') {
      const kind = chunk.reason?.kind
      if (kind === 'error' || kind === 'aborted') {
        const message = chunk.reason?.failure?.message
        throw new Error(typeof message === 'string' && message !== '' ? message : kind ?? 'llm failed')
      }
    }
    const index = typeof chunk.index === 'number' ? chunk.index : 0
    switch (chunk.type) {
      case 'text-delta':
        if (typeof chunk.text === 'string') {
          deltas.set(index, (deltas.get(index) ?? '') + chunk.text)
        }
        break
      case 'reasoning-delta':
        if (typeof chunk.text === 'string') reasoning += chunk.text
        break
      case 'block-end':
        if (chunk.block?.type === 'text' && typeof chunk.block.text === 'string') {
          blocks.set(index, chunk.block.text)
        }
        break
      default:
        if (typeof chunk.delta === 'string') fallback += chunk.delta
        else if (typeof chunk.text === 'string') fallback += chunk.text
    }
  }

  const fromBlocks = joinIndexed(blocks)
  const fromDeltas = joinIndexed(deltas)
  const text = (fromBlocks || fromDeltas || fallback).trim()
  return { text, reasoning: reasoning.trim() }
}

function joinIndexed(map: Map<number, string>): string {
  if (map.size === 0) return ''
  return [...map.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, value]) => value)
    .join('')
}

/** Collect visible assistant text (text channel, then reasoning fallback). */
export async function collectStreamText(
  stream: AsyncIterable<StreamChunkLike>,
  signal?: AbortSignal,
): Promise<string> {
  const parts = await collectStreamParts(stream, signal)
  return parts.text || parts.reasoning
}
