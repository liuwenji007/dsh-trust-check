/**
 * Read the provenance attestation npm publishes for one version.
 *
 * The scanner itself stays offline. Callers that already talk to the registry
 * (a catalog build) use this. The signature is NOT checked: the result says
 * what the registry document contains, not that the signature is valid.
 */

export interface NpmProvenance {
  /** A SLSA provenance attestation was in the registry response. */
  present: boolean
  /** Always false. This function does not check the signature. */
  signatureChecked: false
  /** Repository URL from the attestation, when present. */
  repository?: string
  /** Git commit from the attestation, when present. */
  commit?: string
  /** Workflow ref from the attestation, when present. */
  ref?: string
  /**
   * Whether `repository` and `declaredRepository` name the same GitHub
   * repository. Omitted when either side is missing.
   */
  repositoryMatches?: boolean
}

export interface NpmProvenanceOptions {
  /** `package.json` `repository`, a string or `{ url }`. */
  declaredRepository?: unknown
  fetch?: typeof fetch
  /** Registry origin, no trailing slash. */
  registry?: string
}

interface AttestationEnvelope {
  attestations?: Array<{
    bundle?: { dsseEnvelope?: { payload?: string } }
  }>
}

function githubRepo(value: string | undefined): string | undefined {
  if (value === undefined || value === '') return undefined
  const text = value.replace(/^git\+/, '').replace(/\.git$/, '')
  const match = /github\.com[/:]([^/\s]+)\/([^/#\s]+)/.exec(text)
  if (match === null) return undefined
  return `${match[1]}/${match[2]}`.toLowerCase()
}

function declaredUrl(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (typeof value === 'object' && value !== null && 'url' in value && typeof value.url === 'string') {
    return value.url
  }
  return undefined
}

function provenanceFromPayload(payload: string): { repository?: string, commit?: string, ref?: string } | undefined {
  let doc: unknown
  try {
    doc = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'))
  } catch {
    return undefined
  }
  if (typeof doc !== 'object' || doc === null) return undefined
  if ((doc as { predicateType?: unknown }).predicateType !== 'https://slsa.dev/provenance/v1') return undefined
  const predicate = (doc as { predicate?: unknown }).predicate
  if (typeof predicate !== 'object' || predicate === null) return undefined
  const build = (predicate as { buildDefinition?: unknown }).buildDefinition
  if (typeof build !== 'object' || build === null) return undefined
  const external = (build as { externalParameters?: unknown }).externalParameters
  const workflow = typeof external === 'object' && external !== null
    ? (external as { workflow?: unknown }).workflow
    : undefined
  const repository = typeof workflow === 'object' && workflow !== null
    && typeof (workflow as { repository?: unknown }).repository === 'string'
    ? (workflow as { repository: string }).repository
    : undefined
  const ref = typeof workflow === 'object' && workflow !== null
    && typeof (workflow as { ref?: unknown }).ref === 'string'
    ? (workflow as { ref: string }).ref
    : undefined
  const deps = (build as { resolvedDependencies?: unknown }).resolvedDependencies
  let commit: string | undefined
  if (Array.isArray(deps)) {
    for (const dep of deps) {
      const digest = typeof dep === 'object' && dep !== null
        ? (dep as { digest?: { gitCommit?: unknown } }).digest
        : undefined
      if (typeof digest?.gitCommit === 'string' && digest.gitCommit !== '') {
        commit = digest.gitCommit
        break
      }
    }
  }
  return { repository, commit, ref }
}

/**
 * Look up one published version. A 404 is `{ present: false }`. Any other
 * HTTP or network failure throws, so the caller can omit the field instead of
 * recording "no provenance" for a lookup that did not succeed.
 */
export async function readNpmProvenance(
  name: string,
  version: string,
  options: NpmProvenanceOptions = {},
): Promise<NpmProvenance> {
  const fetchImpl = options.fetch ?? fetch
  const registry = (options.registry ?? 'https://registry.npmjs.org').replace(/\/$/, '')
  const spec = name.replace('/', '%2F')
  const url = `${registry}/-/npm/v1/attestations/${spec}@${encodeURIComponent(version)}`
  const response = await fetchImpl(url)
  if (response.status === 404) return { present: false, signatureChecked: false }
  if (!response.ok) throw new Error(`provenance lookup failed: ${response.status}`)
  const body = await response.json() as AttestationEnvelope
  const attestations = Array.isArray(body.attestations) ? body.attestations : []
  let found: { repository?: string, commit?: string, ref?: string } | undefined
  for (const attestation of attestations) {
    const payload = attestation.bundle?.dsseEnvelope?.payload
    if (typeof payload !== 'string') continue
    const parsed = provenanceFromPayload(payload)
    if (parsed !== undefined) {
      found = parsed
      break
    }
  }
  if (found === undefined) return { present: false, signatureChecked: false }
  const declared = githubRepo(declaredUrl(options.declaredRepository))
  const attested = githubRepo(found.repository)
  const result: NpmProvenance = {
    present: true,
    signatureChecked: false,
    ...found,
  }
  if (declared !== undefined && attested !== undefined) result.repositoryMatches = declared === attested
  return result
}
