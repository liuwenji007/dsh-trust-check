/**
 * Static capability scanner: turns a plugin's shipped sources and manifest
 * into a located capability list. Pure — no filesystem, no network.
 */

import { CAPABILITY_RULES, HOST_RUNTIME_PREFIXES } from './seams.ts'
import type { Capability, Evidence, PluginInput } from './types.ts'

/** Strip a `//…` line comment (not inside a string) and a full-line `/* … *​/`. */
function stripLineComment(line: string): string {
  // Conservative: only remove // and /* */ at their obvious forms; we accept
  // a few false positives over silently missing a capability.
  const block = line.replace(/\/\*[\s\S]*?\*\//g, '')
  // Split on '//' unless preceded by a quote/backtick (crude string guard).
  let out = ''
  let inSingle = false
  let inDouble = false
  let inTemplate = false
  for (let i = 0; i < block.length; i++) {
    const ch = block[i]
    const prev = i > 0 ? block[i - 1] : ''
    if (ch === "'" && prev !== '\\' && !inDouble && !inTemplate) inSingle = !inSingle
    else if (ch === '"' && prev !== '\\' && !inSingle && !inTemplate) inDouble = !inDouble
    else if (ch === '`' && prev !== '\\' && !inSingle && !inDouble) inTemplate = !inTemplate
    else if (ch === '/' && block[i + 1] === '/' && !inSingle && !inDouble && !inTemplate) break
    out += ch
  }
  return out
}

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
    const lines = content.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const stripped = stripLineComment(lines[i])
      for (const rule of CAPABILITY_RULES) {
        const match = rule.pattern.exec(stripped)
        if (match !== null) {
          capabilities.add(rule.capability)
          evidence.push({
            capability: rule.capability,
            file,
            line: i + 1,
            snippet: lines[i].trim().slice(0, 120),
          })
        }
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
