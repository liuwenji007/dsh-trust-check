import { describe, expect, it } from 'vitest'
import { isPinned } from '../../src/core/provenance.ts'

describe('isPinned', () => {
  it('treats exact versions as pinned', () => {
    expect(isPinned('1.2.3')).toBe(true)
    expect(isPinned('^1.2.3')).toBe(false)
    expect(isPinned('~1.2.3')).toBe(false)
    expect(isPinned('latest')).toBe(false)
    expect(isPinned('*')).toBe(false)
  })

  it('treats npm aliases by their version', () => {
    expect(isPinned('npm:dsh-muyu@0.1.4')).toBe(true)
    expect(isPinned('npm:dsh-muyu@latest')).toBe(false)
  })

  it('treats a bare package name as unpinned', () => {
    expect(isPinned('dsh-muyu')).toBe(false)
    expect(isPinned('@scope/dsh-muyu')).toBe(false)
  })

  it('pins git targets only by commit sha', () => {
    expect(isPinned('github:owner/repo')).toBe(false)
    expect(isPinned('github:owner/repo#main')).toBe(false)
    expect(isPinned('github:owner/repo#' + 'a'.repeat(40))).toBe(true)
    expect(isPinned('git+https://github.com/owner/repo.git#' + 'b'.repeat(40))).toBe(true)
  })

  it('treats local targets as pinned', () => {
    expect(isPinned('link:../dsh-muyu')).toBe(true)
    expect(isPinned('file:./pkg')).toBe(true)
    expect(isPinned('workspace:*')).toBe(true)
  })
})
