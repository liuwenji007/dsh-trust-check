import { describe, expect, it } from 'vitest'
import { scanInjections } from '../../src/core/injection.ts'
import type { PluginInput } from '../../src/core/types.ts'

function input(partial: Partial<PluginInput>): PluginInput {
  return {
    manifest: {},
    sources: {},
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'npm:x@1.0.0',
    ...partial,
  }
}

describe('scanInjections', () => {
  it('detects override and disable rows in cordis.patch.yml', () => {
    const result = scanInjections(input({
      patchText: '- override:\n    - id: ui-shell\n- disable:\n    - id: ui-other\n',
    }))
    expect(result.injections).toContainEqual(
      expect.objectContaining({ kind: 'override', detail: 'overrides bundle ui-shell' }),
    )
    expect(result.injections).toContainEqual(
      expect.objectContaining({ kind: 'disable', detail: 'disables bundle ui-other' }),
    )
  })

  it('detects system-prompt registration and estimates literal bytes', () => {
    const result = scanInjections(input({
      sources: {
        'lib/index.js': "ctx.systemPrompt.register('You are a helpful assistant that always formats YAML')\n",
      },
    }))
    const finding = result.injections.find(i => i.kind === 'system-prompt')
    expect(finding).toBeDefined()
    expect(finding!.bytes).toBeGreaterThan(0)
  })

  it('sizes shipped skill text', () => {
    const content = '# Rule\nAlways run tests first.\n'.repeat(10)
    const result = scanInjections(input({
      skillFiles: { 'skills/test/SKILL.md': content },
    }))
    const skill = result.injections.find(i => i.kind === 'skill')
    expect(skill).toBeDefined()
    expect(skill!.bytes).toBe(Buffer.byteLength(content, 'utf8'))
    expect(result.skillBytes).toBe(Buffer.byteLength(content, 'utf8'))
  })

  it('records client inject lists without counting them as prompt cost', () => {
    const result = scanInjections(input({
      manifest: { dsh: { client: { inject: ['@deepseek-ai/dsh-client-locale'] } } },
    }))
    const finding = result.injections.find(i => i.kind === 'client-inject')
    expect(finding).toBeDefined()
    expect(finding!.bytes).toBe(0)
  })

  it('returns no findings for a plain plugin', () => {
    const result = scanInjections(input({}))
    expect(result.injections).toEqual([])
    expect(result.skillBytes).toBe(0)
  })
})
