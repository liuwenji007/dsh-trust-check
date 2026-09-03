# Integrating dsh-trust-check (for dsh-market and CI)

How to wire a **pre-install gate** (or CI check) against this package. Field-level JSON contract: **[audit-schema.md](./audit-schema.md)**.

This scanner discloses capabilities. It is not an antivirus and never claims absence of risk.

## What you are integrating

```text
you extract the package  →  audit the tree  →  read plugins[0]  →  three-state gate
```

**You** download / extract. **This package** only audits a directory it is given (`--dir` or `collectPlugin`). It does not fetch tarballs.

Pin a released `dsh-trust-check` version in CI / market. Prefer checking **`schemaVersion === 1`** on the JSON payload over guessing from the npm version alone. `schemaVersion` bumps only when the **output shape** breaks; detection-rule churn does not bump it.

## Two modes

| Mode | Command | Use for |
|---|---|---|
| **`--dir`** (pre-install) | `npx dsh-trust-check --dir <extracted> [--spec <spec>] --json` | Market confirm dialog, CI on a unpacked candidate |
| **`--profile`** (post-install) | `npx dsh-trust-check [--profile web] --json` | Settings “plugin checkup”; may include `acks` |

`--dir` and `--profile` are mutually exclusive.

### Reading `--json`

- Always check `schemaVersion` (currently `1`).
- Always check `errors`: non-empty means that tree (or installed entry) could not be read — treat as scan failure, not `clear`.
- **`--dir`**: `profile` is `""`, `dir` is the absolute path. Use **`plugins[0]`**. Empty `plugins` with `errors` ⇒ fail closed.
- **`--profile`**: iterate `plugins[]`. Optional `acks` is for Settings fingerprints only.

## Pre-install gate (three states only)

Market pre-install has **no** `trust-ack.json`. Call `verdict(report)` with no ack (or reimplement from the table).

| State | When (no ack) | Recommended UI |
|---|---|---|
| **`red`** | `redLines.length > 0` | Block by default; optional “confirm risk” to continue |
| **`review`** | no red lines, but privileged `capabilities` (or patch override/disable) | Show capability list; suggest confirm |
| **`clear`** | no red lines and no privileged capabilities | May pass silently |

**Do not use for pre-install:**

- `accepted` / `expected` — require a matching ack; Settings-only
- `score` / `band` — a low score can still be `review`; **gate follows `redLines` via `verdict()`, not the numeric band**

Stable fields to hard-parse: `name`, `version`, `spec`, `capabilities`, `redLines`.  
Everything else (`destinations`, `evidence`, `score`, …) is display-only and may change as noise rules evolve — see [audit-schema.md](./audit-schema.md).

## Path A — spawn CLI (no TypeScript import)

```sh
# After you extracted the candidate package:
npx dsh-trust-check@<pinned> --dir "$EXTRACTED_DIR" --spec "$INSTALL_SPEC" --json
```

Pseudo-parse:

```js
const body = JSON.parse(stdout)
if (body.schemaVersion !== 1) throw new Error('unsupported audit schema')
if (body.errors?.length) throw new Error(body.errors[0].message)
const report = body.plugins[0]
if (!report) throw new Error('no audit report')

// Gate logic mirrors verdict(); if you can import the package, call verdict(report) instead of re-deriving this.
const gate =
  report.redLines.length > 0 ? 'red'
  : (report.capabilities.length > 0
      || report.injections.some(i => i.kind === 'override' || i.kind === 'disable'))
    ? 'review'
  : 'clear'

if (gate === 'red') { /* block; allow confirm */ }
else if (gate === 'review') { /* show capabilities; suggest confirm */ }
else { /* may install silently */ }
```

Prefer importing `verdict` when you already depend on the package (Path B): the CLI JSON does not embed the verdict string; you derive it.

## Path B — import API (in-process)

```ts
import {
  auditPlugin,
  collectPlugin,
  verdict,
} from 'dsh-trust-check'

const report = auditPlugin(collectPlugin(extractedDir, installSpec))
const gate = verdict(report) // 'red' | 'review' | 'clear' without ack

switch (gate) {
  case 'red':
    // block by default
    break
  case 'review':
    // show report.capabilities (and optional destinations for disclosure)
    break
  case 'clear':
    // may pass
    break
}
```

`collectPlugin` reads the package tree from disk (same rules as CLI `--dir`). You still must extract first.

Optional: `buildAuditResponse` / `AUDIT_SCHEMA_VERSION` if you assemble a full `AuditResponse` yourself (host route and CLI already do).

## What not to do

- Do not treat empty chips / `clear` as “safe” — only “nothing detected in this static pass”.
- Do not gate on specific destination hosts; placeholder and allowlist rules change (e.g. RFC 2606 `.invalid`).
- Do not scan or trust `node_modules` inside the candidate — out of scope by design.
- Do not expect this tool to stop install scripts that already ran during your extract/install step; run `--dir` as early as your pipeline allows.

## Post-install (Settings) — brief

Profile mode + UI ack store can yield `accepted` / `expected` when the user confirms a fingerprint. That flow is owned by the dsh-trust-check Settings page, not by market’s install dialog. Market should not invent ack files for pre-install.

## Related

- [audit-schema.md](./audit-schema.md) — field contract and examples
- [THREAT-MODEL.md](../THREAT-MODEL.md) — what static analysis can and cannot claim
- Package README § For integrators
