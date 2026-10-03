import { describe, expect, it } from 'vitest'
import { readNpmProvenance } from '../../src/npm-provenance.ts'

function payload(doc: unknown): string {
  return Buffer.from(JSON.stringify(doc), 'utf8').toString('base64')
}

function slsa(repository: string, commit: string): unknown {
  return {
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        externalParameters: { workflow: { repository, ref: 'refs/heads/main' } },
        resolvedDependencies: [{ uri: repository, digest: { gitCommit: commit } }],
      },
    },
  }
}

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status })) as typeof fetch
}

describe('readNpmProvenance', () => {
  it('reports the repository and commit the registry document names, without checking the signature', async () => {
    const result = await readNpmProvenance('semver', '7.8.5', {
      declaredRepository: 'git+https://github.com/npm/node-semver.git',
      fetch: fakeFetch(200, {
        attestations: [{ bundle: { dsseEnvelope: { payload: payload(slsa('https://github.com/npm/node-semver', 'abc123')) } } }],
      }),
    })
    expect(result.signatureChecked).toBe(false)
    expect(result.present).toBe(true)
    expect(result.repository).toBe('https://github.com/npm/node-semver')
    expect(result.commit).toBe('abc123')
    expect(result.ref).toBe('refs/heads/main')
    expect(result.repositoryMatches).toBe(true)
  })

  it('matches only when github.com is the declared host', async () => {
    const fetch = fakeFetch(200, {
      attestations: [{ bundle: { dsseEnvelope: { payload: payload(slsa('https://github.com/npm/node-semver', 'abc123')) } } }],
    })
    const cases: Array<[string, boolean | undefined]> = [
      ['git+https://evil.example/github.com/npm/node-semver.git', undefined],
      ['https://github.com.evil.example/npm/node-semver', undefined],
      ['git@github.com:npm/node-semver.git', true],
      ['github:npm/node-semver', true],
      ['git+https://github.com/npm/node-semver.git#main', true],
      ['https://github.com/npm/other', false],
    ]
    for (const [declaredRepository, expected] of cases) {
      const result = await readNpmProvenance('semver', '7.8.5', { declaredRepository, fetch })
      expect(result.repositoryMatches, declaredRepository).toBe(expected)
    }
  })

  it('does not treat a missing attestation as a failed lookup', async () => {
    const result = await readNpmProvenance('quiet', '1.0.0', { fetch: fakeFetch(404, {}) })
    expect(result).toEqual({ present: false, signatureChecked: false })
  })

  it('throws when the registry does not answer, so the caller can omit the field', async () => {
    await expect(readNpmProvenance('quiet', '1.0.0', { fetch: fakeFetch(500, {}) })).rejects.toThrow(/500/)
  })
})
