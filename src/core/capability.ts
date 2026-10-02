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
 * Decide whether any `fetch(` call on one source line is network egress.
 *
 * A complete relative path literal cannot egress. Absolute URLs, variables,
 * concatenation, method calls, and interpolated templates are egress. A comma
 * or closing parenthesis after the literal starts the next argument.
 */
function isCompleteRelativeLiteral(arg: string): boolean {
  if (arg.includes('${')) return false
  return arg.startsWith('/') || arg.startsWith('./') || arg.startsWith('../')
}

const VM_IMPORT = /(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?vm['"]/

/**
 * True when every `eval` / `new Function` on the line is a finished string
 * literal (no interpolation, no concatenation) and the line does not import `vm`.
 * A constant literal does not run outside code. A non-literal call still counts.
 */
function isConstantDynamicCode(line: string): boolean {
  if (VM_IMPORT.test(line)) return false
  const calls = [...line.matchAll(/\b(?:eval|new\s+Function)\s*\(/g)]
  if (calls.length === 0) return false
  for (const call of calls) {
    const rest = line.slice((call.index ?? 0) + call[0].length).trimStart()
    const quote = rest[0]
    if (quote !== '"' && quote !== "'" && quote !== '`') return false
    let i = 1
    let closed = false
    while (i < rest.length) {
      if (rest[i] === '\\') {
        i += 2
        continue
      }
      if (quote === '`' && rest[i] === '$' && rest[i + 1] === '{') return false
      if (rest[i] === quote) {
        closed = true
        break
      }
      i += 1
    }
    if (!closed) return false
    const trailing = rest.slice(i + 1).trimStart()
    if (trailing.startsWith('+') || trailing.startsWith('.') || trailing.startsWith('`')) return false
  }
  return true
}

function lineHasOutboundFetch(line: string): boolean {
  const re = /(?:^|[^\w$])fetch\s*\(\s*(['"`])?/g
  let match: RegExpExecArray | null
  while ((match = re.exec(line)) !== null) {
    const quote = match[1]
    if (quote === undefined) return true
    const start = match.index + match[0].length
    const rest = line.slice(start)
    const end = rest.indexOf(quote)
    if (end === -1) return true
    re.lastIndex = start + end + 1
    const arg = rest.slice(0, end)
    const trailing = rest.slice(end + 1).replace(/^\s*/, '')
    if (trailing.startsWith('+') || trailing.startsWith('.') || trailing.startsWith('`')) return true
    if (/^https?:\/\//i.test(arg) || arg.startsWith('//')) return true
    if (isCompleteRelativeLiteral(arg)) continue
    return true
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
    const originalLines = content.split('\n')
    const scannedLines = stripComments(content, file).split('\n')
    for (let i = 0; i < scannedLines.length; i++) {
      const stripped = scannedLines[i]
      for (const rule of CAPABILITY_RULES) {
        const match = rule.pattern.exec(stripped)
        if (match !== null) {
          if (rule.id === 'dynamic-code.eval' && isConstantDynamicCode(stripped)) continue
          capabilities.add(rule.capability)
          evidence.push({
            capability: rule.capability,
            file,
            line: i + 1,
            snippet: (originalLines[i] ?? stripped).trim().slice(0, 120),
            rule: rule.id,
          })
        }
      }
      // fetch() is special-cased (not in CAPABILITY_RULES): a same-origin
      // relative-path fetch is a call into the DSH host, not egress. Only
      // outbound fetch counts as `network`. At most one evidence per line.
      if (/fetch\s*\(/.test(stripped) && lineHasOutboundFetch(stripped)) {
        capabilities.add('network')
        evidence.push({
          capability: 'network',
          file,
          line: i + 1,
          snippet: (originalLines[i] ?? stripped).trim().slice(0, 120),
          rule: 'network.fetch',
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
      rule: 'host-runtime.manifest',
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
