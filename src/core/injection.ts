/**
 * Injection surface: what a plugin changes about the host composition or the
 * model's context. Reads cordis.patch.yml (via js-yaml), scans sources for
 * system-prompt registration, and sizes shipped skill text.
 */

import { load as loadYaml } from 'js-yaml'
import type { InjectionFinding, PluginInput } from './types.ts'

/** A patch row `{ insert | override | disable: [...] }` at the top level. */
interface PatchRow {
  insert?: PatchEntry[]
  override?: PatchEntry[]
  disable?: PatchEntry[]
}
interface PatchEntry {
  id?: string
  name?: string
  disabled?: boolean
}

/** Byte length of quoted literals on one line, for a coarse prompt-size signal. */
function stringLiteralBytes(line: string): number {
  let bytes = 0
  const patterns = [
    /"(?:[^"\\]|\\.)*"/g,
    /'(?:[^'\\]|\\.)*'/g,
    /`(?:[^`\\]|\\.)*`/g,
  ]
  for (const pattern of patterns) {
    for (const match of line.matchAll(pattern)) bytes += Buffer.byteLength(match[0], 'utf8')
  }
  return bytes
}

/** Does a relative file path look like shipped skill/instruction text? */
export function isSkillFile(path: string): boolean {
  const lower = path.toLowerCase()
  return /(^|\/)skills?\//.test(lower)
    || /(^|\/)prompts?\//.test(lower)
    || /skill\.md$/.test(lower)
    || /\.prompt$/.test(lower)
    || /instructions?\.md$/.test(lower)
}

function parsePatchRows(text: string | undefined): PatchRow[] {
  if (text === undefined) return []
  try {
    const parsed = loadYaml(text)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((row): row is PatchRow => typeof row === 'object' && row !== null)
  } catch {
    return []
  }
}

export interface InjectionScan {
  injections: InjectionFinding[]
  /** Total injected bytes across skill/prompt findings. */
  skillBytes: number
}

/**
 * Fingerprint tokens for ack comparison. Size is part of the token because a
 * rewritten skill file keeps its path: without it, an acknowledged plugin
 * could swap its injected instructions without re-prompting.
 */
export function injectionFingerprint(injections: InjectionFinding[]): string[] {
  return injections.map(inj => `${inj.kind}:${inj.detail}:${inj.bytes}`).sort()
}

export function scanInjections(input: PluginInput): InjectionScan {
  const injections: InjectionFinding[] = []
  let skillBytes = 0

  // --- cordis.patch.yml tampering --------------------------------------
  for (const row of parsePatchRows(input.patchText)) {
    for (const entry of row.override ?? []) {
      injections.push({
        kind: 'override',
        detail: `overrides bundle ${entry.id ?? entry.name ?? '(unknown)'}`,
        bytes: 0,
      })
    }
    for (const entry of row.disable ?? []) {
      injections.push({
        kind: 'disable',
        detail: `disables bundle ${entry.id ?? entry.name ?? '(unknown)'}`,
        bytes: 0,
      })
    }
  }

  // --- system-prompt / skill / waterfall registration --------------------
  for (const [file, content] of Object.entries(input.sources)) {
    const lines = content.split('\n')
    for (const line of lines) {
      if (/\bsystemPrompt\b|\bsystem_prompt\b/.test(line)) {
        injections.push({
          kind: 'system-prompt',
          detail: `registers a system prompt (${file})`,
          bytes: stringLiteralBytes(line),
        })
      } else if (/\bctx\.skills\.register\b/.test(line)) {
        injections.push({
          kind: 'system-prompt',
          detail: `registers a runtime skill (${file})`,
          bytes: stringLiteralBytes(line),
        })
      } else if (/system-prompt\/assemble/.test(line)) {
        injections.push({
          kind: 'system-prompt',
          detail: `hooks the system-prompt assemble waterfall (${file})`,
          bytes: stringLiteralBytes(line),
        })
      }
    }
  }

  // --- shipped skill/instruction text ----------------------------------
  for (const [file, content] of Object.entries(input.skillFiles)) {
    const bytes = Buffer.byteLength(content, 'utf8')
    skillBytes += bytes
    injections.push({
      kind: 'skill',
      detail: `ships instruction text ${file}`,
      bytes,
    })
  }

  // --- client injection (informational, no prompt cost) -----------------
  const dsh = input.manifest.dsh
  if (typeof dsh === 'object' && dsh !== null) {
    const client = (dsh as Record<string, unknown>).client
    if (typeof client === 'object' && client !== null) {
      const inject = (client as Record<string, unknown>).inject
      if (Array.isArray(inject)) {
        const names = inject.filter((x): x is string => typeof x === 'string')
        if (names.length > 0) {
          injections.push({
            kind: 'client-inject',
            detail: `injects client deps: ${names.join(', ')}`,
            bytes: 0,
          })
        }
      }
    }
  }

  return { injections, skillBytes }
}
