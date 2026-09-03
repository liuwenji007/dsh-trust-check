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
| `errors` | `{ name, spec, message }[]` | Always (may be empty). Non-empty ⇒ that package tree could not be read |
| `acks` | `Record<string, TrustAckEntry>` (optional) | Profile mode only, when ack store is loaded |

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
| `capabilities` | `string[]` | Detected capability ids |
| `redLines` | `string[]` | Hard red-line reasons (empty ⇒ no red line) |

**Do not gate on** `score` or `band`. Numeric score can look “red” while the product verdict is only `review`. Gate with `verdict()` semantics below (or reimplement from `redLines` + `capabilities`).

## Pre-install gate: three verdicts

Without a trust ack (`trust-ack.json`), `verdict(report)` is only:

| Verdict | Condition | Gate action |
|---|---|---|
| `red` | `redLines.length > 0` | Block by default; allow confirm-to-continue |
| `review` | no red lines, but `capabilities.length > 0` (or patch override/disable) | Show capability list; suggest confirm |
| `clear` | no red lines and no privileged capabilities | May pass silently |

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
- Scanning `node_modules` inside the package
- Safety guarantees (“no risk”); this scanner proves **presence**, never absence

## Related

- [INTEGRATION.md](./INTEGRATION.md) — how to wire a pre-install gate (CLI or import)
- Package README § “For integrators”
- `verdict` / `buildAuditResponse` / `AUDIT_SCHEMA_VERSION` exports from `dsh-trust-check`
