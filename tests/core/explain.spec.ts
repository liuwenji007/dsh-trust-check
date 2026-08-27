import { describe, expect, it } from 'vitest'
import { buildExplainPrompt, EXPLAIN_SYSTEM } from '../../src/core/explain.ts'
import type { AuditReport } from '../../src/core/types.ts'

const report: AuditReport = {
  name: 'demo',
  version: '1.0.0',
  spec: 'npm:demo@1',
  capabilities: ['network'],
  evidence: [{ capability: 'network', file: 'a.js', line: 1, snippet: 'fetch("/x")' }],
  destinations: [{ kind: 'https-host', value: 'api.example.com', file: 'a.js', line: 1 }],
  pathEscapes: [{ kind: 'home', value: '~/x', file: 'a.js', line: 2 }],
  secretTouches: [],
  injections: [],
  injectedTokensEstimate: 0,
  hasBuildScript: false,
  buildScripts: [],
  repository: undefined,
  pinned: true,
  score: 90,
  band: 'yellow',
  redLines: [],
  deductions: [],
  summary: '',
}

describe('buildExplainPrompt', () => {
  it('includes destinations and path escapes', () => {
    const prompt = buildExplainPrompt(report)
    expect(prompt).toContain('demo@1.0.0')
    expect(prompt).toContain('network')
    expect(prompt).toContain('fetch("/x")')
    expect(prompt).toContain('api.example.com')
    expect(prompt).toContain('Workspace path escapes')
    expect(prompt).toContain('~/x')
  })

  it('forbids changing verdict in system prompt', () => {
    expect(EXPLAIN_SYSTEM).toContain('NOT a security verdict')
  })
})
