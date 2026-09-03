import { describe, expect, it } from 'vitest'
import { scoreTrust } from '../../src/core/score.ts'

const base = {
  capabilities: [] as import('../../src/core/types.ts').Capability[],
  destinations: [] as import('../../src/core/types.ts').DestinationFinding[],
  injectedTokensEstimate: 0,
  injections: [] as import('../../src/core/types.ts').InjectionFinding[],
  hasBuildScript: false,
  buildScripts: [] as string[],
  prepareScripts: [] as string[],
  repository: 'https://github.com/x/y',
  pinned: true,
}

describe('scoreTrust', () => {
  it('scores a clean client-only plugin green', () => {
    const result = scoreTrust(base)
    expect(result.score).toBe(100)
    expect(result.band).toBe('green')
    expect(result.redLines).toEqual([])
  })

  it('deducts capability weights', () => {
    const result = scoreTrust({ ...base, capabilities: ['shell', 'network'] })
    expect(result.score).toBe(65)
  })

  it('deducts dynamic-code without treating it as a red line', () => {
    const result = scoreTrust({ ...base, capabilities: ['dynamic-code'] })
    expect(result.score).toBe(82)
    expect(result.redLines).toEqual([])
    expect(result.band).toBe('green')
  })

  it('forces red on install scripts', () => {
    const result = scoreTrust({ ...base, hasBuildScript: true, buildScripts: ['postinstall'] })
    expect(result.band).toBe('red')
    expect(result.redLines).toContain('runs code at install time (postinstall)')
    expect(result.score).toBe(49)
  })

  it('deducts for prepare without forcing red (registry install does not run it)', () => {
    const result = scoreTrust({ ...base, prepareScripts: ['prepare'] })
    expect(result.band).not.toBe('red')
    expect(result.redLines).toEqual([])
    expect(result.score).toBe(95) // 100 - 5 prepare deduction
  })

  it('does not double-count prepare as an install-time red line', () => {
    const result = scoreTrust({ ...base, hasBuildScript: true, buildScripts: ['postinstall'], prepareScripts: ['prepare'] })
    expect(result.redLines).toEqual(['runs code at install time (postinstall)'])
    expect(result.score).toBe(49) // red-line cap still applies
  })

  it('forces red when secrets and network combine', () => {
    const result = scoreTrust({ ...base, capabilities: ['credentials', 'network'] })
    expect(result.band).toBe('red')
    expect(result.redLines).toContain('reads credentials/secrets AND has network access')
    expect(result.score).toBe(49)
  })

  it('treats overriding a core bundle as a red line, community bundles as a deduction', () => {
    const core = scoreTrust({
      ...base,
      injections: [{ kind: 'override', detail: 'overrides bundle @deepseek-ai/dsh-base', bytes: 0 }],
    })
    expect(core.redLines).toContain('tampers with a core bundle (overrides bundle @deepseek-ai/dsh-base)')
    expect(core.score).toBe(49)

    const byName = scoreTrust({
      ...base,
      injections: [{ kind: 'override', detail: 'overrides bundle @deepseek-ai/dsh-base', bytes: 0 }],
    })
    expect(byName.redLines.length).toBeGreaterThan(0)
    expect(byName.score).toBe(49)

    const community = scoreTrust({
      ...base,
      injections: [{ kind: 'disable', detail: 'disables bundle ui-other', bytes: 0 }],
    })
    expect(community.redLines).toEqual([])
    expect(community.score).toBe(90)
  })

  it('caps the token-cost deduction', () => {
    const result = scoreTrust({ ...base, injectedTokensEstimate: 100000 })
    expect(result.score).toBe(80) // 100 - 20 (capped)
  })

  it('deducts for unpinned spec and missing repository', () => {
    const result = scoreTrust({ ...base, pinned: false, repository: undefined })
    expect(result.score).toBe(85)
  })

  it('clamps to zero and stays red', () => {
    const result = scoreTrust({
      ...base,
      capabilities: ['shell', 'fs-write', 'fs-read', 'network', 'credentials', 'subagent', 'host-runtime', 'llm'],
      pinned: false,
      repository: undefined,
    })
    expect(result.score).toBe(0)
    expect(result.band).toBe('red')
  })
})
