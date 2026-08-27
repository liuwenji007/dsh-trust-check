import { describe, expect, it } from 'vitest'
import { isCodeFile, stripComments } from '../../src/core/strip-comments.ts'

describe('isCodeFile', () => {
  it('accepts JS/TS extensions and rejects prose', () => {
    for (const file of ['a.js', 'a.mjs', 'a.cjs', 'a.ts', 'a.mts', 'a.tsx', 'a.jsx']) {
      expect(isCodeFile(file)).toBe(true)
    }
    for (const file of ['SKILL.md', 'a.prompt', 'a.txt', 'noext']) {
      expect(isCodeFile(file)).toBe(false)
    }
  })
})

describe('stripComments', () => {
  it('blanks line and block comments while preserving line numbers', () => {
    const source = [
      'const a = 1 // https://evil.example.org',
      '/* https://also-evil.test */',
      'const b = 2',
    ].join('\n')
    const stripped = stripComments(source).split('\n')
    expect(stripped).toHaveLength(3)
    expect(stripped[0]).toContain('const a = 1')
    expect(stripped[0]).not.toContain('evil')
    expect(stripped[1].trim()).toBe('')
    expect(stripped[2]).toBe('const b = 2')
  })

  it('spans a block comment across lines', () => {
    const source = ['/**', ' * `https://host/app/`', ' */', 'run()'].join('\n')
    expect(stripComments(source)).not.toContain('host')
    expect(stripComments(source)).toContain('run()')
  })

  it('keeps URLs that live inside string literals', () => {
    const source = 'fetch("https://api.example.org//path") // gone'
    const stripped = stripComments(source)
    expect(stripped).toContain('https://api.example.org//path')
    expect(stripped).not.toContain('gone')
  })

  it('does not treat an apostrophe inside a template literal as a quote', () => {
    const source = ['const s = `it\'s', 'fine` // gone', 'const u = "https://kept.example.org"'].join('\n')
    const stripped = stripComments(source)
    expect(stripped).not.toContain('gone')
    expect(stripped).toContain('https://kept.example.org')
  })

  it('leaves a desynchronised line untouched rather than hiding code', () => {
    const source = ['const re = /[\'"]/', 'const u = "https://kept.example.org"'].join('\n')
    const stripped = stripComments(source).split('\n')
    expect(stripped[0]).toBe('const re = /[\'"]/')
    expect(stripped[1]).toContain('https://kept.example.org')
  })

  it('does not carry comment state out of a desynchronised line', () => {
    const source = ["const re = /'/  /* opened", 'const u = "https://kept.example.org"'].join('\n')
    expect(stripComments(source)).toContain('https://kept.example.org')
  })
})
