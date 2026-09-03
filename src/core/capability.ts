/**
 * Static capability scanner: turns a plugin's shipped sources and manifest
 * into a located capability list. Pure — no filesystem, no network.
 */

import { CAPABILITY_RULES, HOST_RUNTIME_PREFIXES } from './seams.ts'
import { stripComments } from './strip-comments.ts'
import type { Capability, Evidence, PluginInput } from './types.ts'

/** Does any manifest dependency key declare a host-runtime package? */
function manifestUsesHostRuntime(manifest: Record<string, unknown>): boolean {
  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = manifest[field]
    if (typeof deps !== 'object' || deps === null || Array.isArray(deps)) continue
    for (const key of Object.keys(deps as Record<string, unknown>)) {
      if (HOST_RUNTIME_PREFIXES.some(prefix => key.startsWith(prefix))) return true
    }
  }
  return false
}

/**
 * Decide whether a `fetch(` call on one source line is network egress.
 *
 * Static truth only: a literal first argument that is a same-origin relative
 * path (`/api/x`, `./x`, `../x`) cannot egress — the DSH host serves it.
 * Absolute URLs are egress. Anything we cannot resolve statically (template
 * literals, variables, concatenation) is treated as egress, because "only
 * detect presence, never absence" — an attacker builds URLs at runtime.
 */
function fetchIsOutbound(line: string): boolean {
  // Match `fetch(` then capture the first argument's opening quote (if any).
  const m = /(?:^|[^\w$])fetch\s*\(\s*(['"`])?/.exec(line)
  if (m === null) return false
  const quote = m[1]
  if (quote === undefined) return true // no literal first arg → variable / expr
  const rest = line.slice(m.index + m[0].length)
  const end = rest.indexOf(quote)
  if (end === -1) return false // unterminated literal on this line; skip
  const arg = rest.slice(0, end)
  if (/^https?:\/\//i.test(arg) || /^\/\//.test(arg)) return true
  // Same-origin: root-relative, or explicit relative path. Also treat scheme-
  // relative and protocol-absolute as outbound (covered above).
  if (arg.startsWith('/') || arg.startsWith('./') || arg.startsWith('../')) return false
  // Bare host-ish literals without scheme are ambiguous; treat as outbound.
  return true
}

export interface CapabilityScan {
  capabilities: Capability[]
  evidence: Evidence[]
}

/**
 * Scan one plugin's sources for capabilities. `host-runtime` is also derived
 * from the manifest's dependency scopes, because it is about *where* the
 * plugin runs, not a single API call.
 */
export function scanCapabilities(input: PluginInput): CapabilityScan {
  const evidence: Evidence[] = []
  const capabilities = new Set<Capability>()

  for (const [file, content] of Object.entries(input.sources)) {
    const originalLines = content.split('\n')
    const scannedLines = stripComments(content).split('\n')
    for (let i = 0; i < scannedLines.length; i++) {
      const stripped = scannedLines[i]
      for (const rule of CAPABILITY_RULES) {
        const match = rule.pattern.exec(stripped)
        if (match !== null) {
          capabilities.add(rule.capability)
          evidence.push({
            capability: rule.capability,
            file,
            line: i + 1,
            snippet: (originalLines[i] ?? stripped).trim().slice(0, 120),
          })
        }
      }
      // fetch() is special-cased (not in CAPABILITY_RULES): a same-origin
      // relative-path fetch is a call into the DSH host, not egress. Only
      // outbound fetch counts as `network`. At most one evidence per line.
      if (/fetch\s*\(/.test(stripped) && fetchIsOutbound(stripped)) {
        capabilities.add('network')
        evidence.push({
          capability: 'network',
          file,
          line: i + 1,
          snippet: (originalLines[i] ?? stripped).trim().slice(0, 120),
        })
      }
    }
  }

  if (manifestUsesHostRuntime(input.manifest)) {
    capabilities.add('host-runtime')
  }

  // Keep host-runtime evidence at least pointing somewhere useful.
  if (capabilities.has('host-runtime') && !evidence.some(e => e.capability === 'host-runtime')) {
    evidence.push({
      capability: 'host-runtime',
      file: 'package.json',
      line: 1,
      snippet: 'declares a @deepseek-ai/dsh-host* / dsh-app* / dsh-core* dependency',
    })
  }

  const ORDER: Capability[] = [
    'shell',
    'dynamic-code',
    'fs-write',
    'fs-read',
    'network',
    'credentials',
    'env',
    'subagent',
    'host-runtime',
    'llm',
  ]
  const ordered = ORDER.filter(c => capabilities.has(c))

  return { capabilities: ordered, evidence }
}
