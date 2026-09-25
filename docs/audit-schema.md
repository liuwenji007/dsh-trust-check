# Audit JSON schema (integrator contract)

Machine-readable output of `dsh-trust-check --json` and the host `/dsh-trust-check/audit` route. Same shape for both.

This document freezes what **dsh-market** (and similar gates) should parse. It is not a full encyclopedia of every report field.

## `schemaVersion`

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | `number` | **JSON shape version.** Current value: **`1`**. |

**Bump rules**

- Bump when fields are **added / removed / renamed** in a way that breaks parsers.
- Do **not** bump when detection rules change (capabilities, destinations, scores, evidence). Those are scanner behavior, not shape.

Integrators should reject or warn on an unknown `schemaVersion`, not on `package.json` version alone.

## Top-level: `AuditResponse`

| Field | Type | When |
|---|---|---|
| `schemaVersion` | `number` | Always |
| `profile` | `string` | Always. Empty string `""` in `--dir` mode |
| `dir` | `string` (optional) | `--dir` mode only: absolute path audited |
| `generatedAt` | `string` | Always: ISO-8601 timestamp |
| `plugins` | `AuditReport[]` | Always (may be empty) |
| `errors` | `{ name, spec, message }[]` | Always (may be empty). Non-empty ⇒ that package tree could not be read. A size limit, missing primary entry, missing profile, corrupt profile config, or missing declared directory is a scan failure, not `clear`. |
| `acks` | `Record<string, TrustAckEntry>` (optional) | Profile mode only, when ack store is loaded |

`AuditReport` may include optional `coverageNotes` (unexpanded static targets; not a verdict input) and `ackFingerprint` (SHA-256 of the full risk vectors, computed before display truncation). `schemaVersion` stays `1`.

Acknowledgement `POST /dsh-trust-check/ack` takes `{ name, acceptRisk?, fingerprint }`. `fingerprint` is the `ackFingerprint` string from the report the user is looking at. A mismatch returns **409** with `{ error: "plugin-content-changed", report }`. The same digest is stored as `digest` on `TrustAckEntry`. Older ack records without `digest` do not match and must be confirmed again. Pre-install gates do not use ack.

### `--dir` vs `--profile`

| Mode | How to invoke | Read as |
|---|---|---|
| Single package (pre-install) | `--dir <path> [--spec <spec>] --json` | `profile === ""`, `dir` set, use **`plugins[0]`** (or treat empty/`errors` as failure) |
| Installed profile | `--profile <name> --json` (default `web`) | Full `plugins` array; may include `acks` |

`--dir` and `--profile` are mutually exclusive.

## Stable gate surface on `AuditReport`

Pre-install gates should hard-depend only on these five fields:

| Field | Type | Role |
|---|---|---|
| `name` | `string` | Package name |
| `version` | `string` | Package version |
| `spec` | `string` | Install spec label (e.g. `npm:foo@1.0.0`) |
| `capabilities` | `string[]` | Detected capability ids — fixed values, see [wording contract](#wording-contract-capabilities-values-and-redlines-templates) |
| `redLines` | `string[]` | Hard red-line reasons (empty ⇒ no red line) — fixed templates, see [wording contract](#wording-contract-capabilities-values-and-redlines-templates) |

**Do not gate on** `score` or `band`. Numeric score can look “red” while the product verdict is only `review`. Gate with `verdict()` semantics below (or reimplement from `redLines` + `capabilities`).

## Wording contract: `capabilities` values and `redLines` templates

Integrators render these two fields as-is and translate them, so their wording is treated as part of the contract, not as free text.

**Guarantees while `schemaVersion` is `1`:**

- The `capabilities` values and the `redLines` templates below do not change wording.
- A new capability value or red-line template may be **added** (detection can grow). Treat an unknown capability value or a red line that `classifyRedLine()` maps to `raw` as “show the original English text”, not as an error.
- Removing or rewording an existing value or template is a breaking change: it bumps `schemaVersion`.
- Every change to these lists, including additions, is listed in [CHANGELOG.md](../CHANGELOG.md) under “Affects catalog results”.

Which plugins produce which values *does* change between releases (that is detection, see bump rules above). The wording of a value does not.

### `capabilities` values

| Value | Meaning |
|---|---|
| `shell` | Runs system commands |
| `fs-read` | Reads files |
| `fs-write` | Writes files |
| `network` | Network access |
| `credentials` | Reaches the credential / secret store |
| `env` | Reads environment variables |
| `subagent` | Starts sub-agents |
| `host-runtime` | Depends on a DSH host runtime package (`@deepseek-ai/dsh-core`, `@deepseek-ai/dsh-app`, …), derived from `package.json` |
| `llm` | Calls a model |
| `dynamic-code` | Evaluates code at runtime (`eval`, `new Function`, …) |

### `redLines` templates

Each red line is one English sentence built from a fixed template. `<…>` is filled from the package; everything else is literal. `classifyRedLine()` (exported) maps a sentence to its stable code, so a translation can key on the code and substitute the placeholder.

| Code | Template | Placeholder | Suggested Chinese |
|---|---|---|---|
| `install-script` | `runs code at install time (<scripts>)` | Declared script names, `, `-separated (`preinstall`, `install`, `postinstall`) | 安装时会执行脚本（<scripts>） |
| `core-tamper` | `tampers with a core bundle (<detail>)` | Patch finding, e.g. `overrides bundle @deepseek-ai/dsh-base` | 覆盖或禁用了 DSH 核心 bundle（<detail>） |
| `creds-network` | `reads credentials/secrets AND has network access` | — | 代码中检出：读取凭据的值，且有网络访问 |
| `plaintext-http` | `uses plaintext http:// to <host>` | Literal host, may include `:port` | 代码中检出：明文 http:// 连接 <host> |
| `literal-ip` | `uses literal IP <ip> for network access` | Literal IP. Loopback, RFC 1918 private, RFC 5737 documentation and bind/broadcast addresses never appear; link-local `169.254.x.x` (cloud metadata) does | 代码中检出：直接连接 IP 地址 <ip> |

A report carries at most one `plaintext-http` and one `literal-ip` sentence (the first match), so a count of red lines is not a count of hosts. The two “代码中检出” codes come from matching source text; the other two come from `package.json` / `cordis.patch.yml` declarations. Surfaces may want to present the two groups differently.

## Pre-install gate: three verdicts

Without a trust ack (`trust-ack.json`), `verdict(report)` is only:

| Verdict | Condition | Gate action |
|---|---|---|
| `red` | `redLines.length > 0` | Block by default; allow confirm-to-continue |
| `review` | no red lines, but `capabilities.length > 0` (or patch override/disable) | Show capability list; suggest confirm |
| `clear` | no red lines and no privileged capabilities | Nothing detected in this static pass; not a safety claim. Prompting is integrator policy |

`accepted` / `expected` require an ack fingerprint match — **post-install Settings only**. Market pre-install has no ack; do not branch on those two.

TypeScript:

```ts
import { auditPlugin, collectPlugin, verdict, buildAuditResponse } from 'dsh-trust-check'

const report = auditPlugin(collectPlugin(extractedDir, spec))
const gate = verdict(report) // 'red' | 'review' | 'clear' when no ack
```

CLI equivalent: spawn `npx dsh-trust-check --dir "$DIR" --spec "$SPEC" --json`, then read `plugins[0]`.

## Volatile / display-only fields

Safe to render; **do not** hard-depend for gating or parsing:

- `destinations`, `pathEscapes`, `secretTouches` — sets change as placeholder/noise rules evolve
- `evidence`, `injections`, `summary`, `deductions`
- `score`, `band`, `injectedTokensEstimate`
- `hasBuildScript`, `buildScripts`, `prepareScripts`, `repository`, `pinned`

## Example: clear

```json
{
  "schemaVersion": 1,
  "profile": "",
  "dir": "/tmp/extracted/quiet-plugin",
  "generatedAt": "2026-09-03T08:00:00.000Z",
  "plugins": [
    {
      "name": "quiet-plugin",
      "version": "1.0.0",
      "spec": "npm:quiet-plugin@1.0.0",
      "capabilities": [],
      "redLines": []
    }
  ],
  "errors": []
}
```

(Other report fields omitted for brevity; real payloads include them.)

## Example: red (plaintext HTTP)

```json
{
  "schemaVersion": 1,
  "profile": "",
  "dir": "/tmp/extracted/leaky-plugin",
  "generatedAt": "2026-09-03T08:00:00.000Z",
  "plugins": [
    {
      "name": "leaky-plugin",
      "version": "1.0.0",
      "spec": "npm:leaky-plugin@1.0.0",
      "capabilities": ["network"],
      "redLines": ["uses plaintext http:// to attacker.com"]
    }
  ],
  "errors": []
}
```

Gate: `redLines.length > 0` ⇒ `red` ⇒ block by default.

## Out of scope

- Remote tarball download (caller extracts, then `--dir`)
- Expanding bare package imports (`import 'lodash'`). A relative path inside this package, including under its own `node_modules`, is in scope
- Safety guarantees (“no risk”); this scanner proves **presence**, never absence

## Related

- [INTEGRATION.md](./INTEGRATION.md) — how to wire a pre-install gate (CLI or import)
- [CHANGELOG.md](../CHANGELOG.md) — per-release changes, with the ones that move catalog results listed first
- Package README § “For integrators”
- `verdict` / `buildAuditResponse` / `AUDIT_SCHEMA_VERSION` exports from `dsh-trust-check`
