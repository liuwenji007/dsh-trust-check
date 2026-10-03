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
 * Names that let constant code reach outside itself: `eval("require")` returns
 * the module loader, and `new Function("return process")` returns the process.
 */
const REACHES_OUT = /\b(?:require|import|process|module|exports|global|globalThis|window|self|Function|eval|constructor|Reflect|Proxy)\b/

/** Index just past the string literal at `start`, or -1 when it is unclosed or interpolated. */
function literalEnd(text: string, start: number): number {
  const quote = text[start]
  if (quote !== '"' && quote !== "'" && quote !== '`') return -1
  let i = start + 1
  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2
      continue
    }
    if (quote === '`' && text[i] === '$' && text[i + 1] === '{') return -1
    if (text[i] === quote) return i + 1
    i += 1
  }
  return -1
}

function skipSpace(text: string, i: number): number {
  while (i < text.length && /\s/.test(text[i])) i += 1
  return i
}

/**
 * True when every `eval` / `new Function` on the line takes only complete
 * string literals, closes on the same line, names nothing in `REACHES_OUT`,
 * and the line does not import `vm`. `new Function("a", body)` and
 * `eval("" || code)` still count, because an argument is not a literal.
 */
function isConstantDynamicCode(line: string): boolean {
  if (VM_IMPORT.test(line)) return false
  const calls = [...line.matchAll(/\b(?:eval|new\s+Function)\s*\(/g)]
  if (calls.length === 0) return false
  for (const call of calls) {
    let i = skipSpace(line, (call.index ?? 0) + call[0].length)
    for (;;) {
      const end = literalEnd(line, i)
      if (end === -1) return false
      if (REACHES_OUT.test(line.slice(i + 1, end - 1))) return false
      i = skipSpace(line, end)
      if (line[i] === ')') break
      if (line[i] !== ',') return false
      i = skipSpace(line, i + 1)
    }
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
