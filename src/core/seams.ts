/**
 * The capability detection table: one rule per (capability, pattern) pair.
 *
 * This is deliberately a plain data table rather than code scattered through
 * the scanner — DSH is still v0.1 and seam names change. Updating a pattern
 * here updates every consumer (CLI, client view, future CI gate) at once.
 *
 * Pattern discipline (this is what keeps the scanner from flagging ITSELF,
 * because the rule table literally contains every dangerous API name):
 *   - API names match the CALL SITE (`\bname\s*\(`), never the bare
 *     identifier — a bare `name` inside a regex literal, a type union, or a
 *     string would otherwise match its own rule table.
 *   - Module access matches the IMPORT form (`require('x')` / `from 'x'`),
 *     not the word.
 *   - `\bexec\s*\(` is banned: `.exec(` is RegExp.prototype.exec, not a shell.
 *
 * Confidence is always "presence, never absence": we only claim "detected X",
 * never "guaranteed no X".
 */

import type { Capability } from './types.ts'

export interface CapabilityRule {
  capability: Capability
  pattern: RegExp
  label: string
}

export const CAPABILITY_RULES: readonly CapabilityRule[] = [
  // --- shell ------------------------------------------------------------
  {
    capability: 'shell',
    pattern: /(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?child_process(?:\/promises)?['"]|\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFileSync\s*\(|\bexecFile\s*\(|\bspawn\s*\(|\bctx\.bash\b/,
    label: 'Shell execution',
  },
  // --- filesystem --------------------------------------------------------
  {
    capability: 'fs-write',
    pattern: /\bwriteFileSync\s*\(|\bwriteFile\s*\(|\bappendFileSync\s*\(|\bappendFile\s*\(|\bmkdirSync\s*\(|\bunlinkSync\s*\(|\brmSync\s*\(|\brm\s*\(|\brenameSync\s*\(|\bcopyFileSync\s*\(|\bcpSync\s*\(|\bcreateWriteStream\s*\(/,
    label: 'Filesystem write',
  },
  {
    capability: 'fs-read',
    pattern: /(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?fs(?:\/promises)?['"]|\breadFileSync\s*\(|\breadFile\s*\(|\breaddirSync\s*\(|\breaddir\s*\(|\bstatSync\s*\(|\bexistsSync\s*\(|\bcreateReadStream\s*\(|\bctx\.fs\b/,
    label: 'Filesystem read',
  },
  // --- network -----------------------------------------------------------
  {
    capability: 'network',
    pattern: /(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?(?:http2|http|https|net|tls|dgram|dns2?)['"]|\bfetch\s*\(|\bnew\s+WebSocket\b|\bhttp\.request\b|\bhttps\.request\b|(?<!['"])\b(?:http|https)\.get\s*\(|(?<!['"])\bhttp2\.connect\s*\(|(?:require\(|from\s+|import\s*\(\s*)['"](?:axios|undici|node-fetch|got|ws|superagent|ky|request|phin)['"]|\bctx\.web\b/,
    label: 'Network access',
  },
  // --- credentials -------------------------------------------------------
  // Strong secret-material access only. `process.env` is its own low-weight
  // `env` rule below — every server plugin reads env vars, so it must not be
  // treated as "reads secrets". `keychain`/`keytar`/`dotenv` match imports or
  // method calls, not the word in prose ("a synced keychain" is not access).
  {
    capability: 'credentials',
    pattern: /(?:require\(|from\s+|import\s*\(\s*)['"](?:keychain|keytar|dotenv)['"]|\bkeychain\.\w+|\bkeytar\.\w+|\bdotenv\.config\b|\bctx\.credentials\b|~\/\.ssh|\b\.aws\/credentials\b|\b\.netrc\b|\bid_rsa\b|\bid_ed25519\b/,
    label: 'Credential / secret access',
  },
  // --- environment -------------------------------------------------------
  {
    capability: 'env',
    pattern: /\bprocess\.env\b/,
    label: 'Reads environment variables',
  },
  // --- subagent ----------------------------------------------------------
  {
    capability: 'subagent',
    pattern: /\bctx\.subagents\b|\bctx\.agentTeams\b|\bspawnTeammate\b|\bsubagent\s*\(|\bdelegate\s*\(/,
    label: 'Sub-agent spawning',
  },
  // --- llm ---------------------------------------------------------------
  {
    capability: 'llm',
    pattern: /\bctx\.llm\b|\bcreateChatCompletion\s*\(|\bchat\.completions\b|\bgenerateText\s*\(|\binvokeModel\s*\(/,
    label: 'Model (LLM) calls',
  },
  // --- dynamic code ------------------------------------------------------
  // Call-site / import form only, so this table does not match itself.
  {
    capability: 'dynamic-code',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(|(?:require\(|from\s+|import\s*\(\s*)['"](?:node:)?vm['"]/,
    label: 'Dynamic code execution',
  },
]

/** npm/package specifiers that imply a host-side (server) bundle. */
export const HOST_RUNTIME_PREFIXES: readonly string[] = [
  '@deepseek-ai/dsh-host',
  '@deepseek-ai/dsh-app',
  '@deepseek-ai/dsh-core',
]

export const CAPABILITY_LABELS: Readonly<Record<Capability, string>> = {
  shell: 'Shell execution',
  'fs-read': 'Filesystem read',
  'fs-write': 'Filesystem write',
  network: 'Network access',
  credentials: 'Credential / secret access',
  env: 'Reads environment variables',
  subagent: 'Sub-agent spawning',
  'host-runtime': 'Host runtime',
  llm: 'Model (LLM) calls',
  'dynamic-code': 'Dynamic code execution',
}
