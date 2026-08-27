/**
 * Provenance signals from package.json and the install spec: version,
 * repository, install-time build scripts, and whether the spec is pinned.
 */

import type { PluginInput } from './types.ts'

export interface Provenance {
  name: string
  version: string
  repository: string | undefined
  hasBuildScript: boolean
  buildScripts: string[]
  pinned: boolean
}

const DANGEROUS_SCRIPTS = ['preinstall', 'install', 'postinstall'] as const

function repoOf(manifest: Record<string, unknown>): string | undefined {
  const repo = manifest.repository
  if (typeof repo === 'string') return repo
  if (typeof repo === 'object' && repo !== null) {
    const url = (repo as Record<string, unknown>).url
    if (typeof url === 'string') return url
  }
  const homepage = manifest.homepage
  if (typeof homepage === 'string') return homepage
  return undefined
}

/** Extract a git repository URL from a git-shaped install spec. */
function gitUrlFromSpec(spec: string): string | undefined {
  const s = spec.trim()
  if (s.startsWith('github:')) {
    return 'https://github.com/' + s.slice('github:'.length).replace(/#.*$/, '')
  }
  const gitMatch = /^git\+?(https:\/\/[^#]+)/.exec(s)
  if (gitMatch !== null) return gitMatch[1]
  return undefined
}

/** Exact semver only; a range (`^1.2.3`) or `latest`/`*` is not pinned. */
function isExactVersion(value: string): boolean {
  if (value === 'latest' || value === '*' || value === '') return false
  if (/^[vV]?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(value)) return true
  return false
}

/** A version/range leads with a digit, `v`, or a range operator. */
function looksLikeVersion(value: string): boolean {
  return /^[vV]?\d/.test(value) || /^[\^~<>=*]/.test(value)
}

/** Is an install spec pinned to a version or commit (not a moving target)? */
export function isPinned(spec: string): boolean {
  const s = spec.trim()
  if (s === '' || s === 'latest') return false

  // Local / workspace targets never move.
  if (s.startsWith('link:') || s.startsWith('file:') || s.startsWith('workspace:')) return true

  // npm aliases: npm:name@version
  const npmAlias = /^npm:[^@]+@(.+)$/.exec(s)
  if (npmAlias !== null) return isExactVersion(npmAlias[1])

  // git targets: github:owner/repo[#ref] or git+https://…[#ref]
  if (/^(?:github:|git\+|git:)/.test(s)) {
    const hash = s.indexOf('#')
    if (hash === -1) return false
    return /^[0-9a-f]{40}$/i.test(s.slice(hash + 1))
  }

  // Version strings (exact or a range).
  if (looksLikeVersion(s)) return isExactVersion(s)

  // Bare package name or scoped name without a version → resolves latest.
  return false
}

export function readProvenance(input: PluginInput): Provenance {
  const manifest = input.manifest
  const name = typeof manifest.name === 'string' ? manifest.name : 'unknown'
  const version = typeof manifest.version === 'string' ? manifest.version : 'unknown'

  const scripts = manifest.scripts
  const buildScripts: string[] = []
  if (typeof scripts === 'object' && scripts !== null) {
    for (const key of DANGEROUS_SCRIPTS) {
      if (typeof (scripts as Record<string, unknown>)[key] === 'string') buildScripts.push(key)
    }
  }

  return {
    name,
    version,
    repository: repoOf(manifest) ?? gitUrlFromSpec(input.spec),
    hasBuildScript: buildScripts.length > 0,
    buildScripts,
    pinned: isPinned(input.spec),
  }
}
