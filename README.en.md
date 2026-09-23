# dsh-trust-check

[中文](README.md)

Static trust audit for DeepSeek Harness plugins: **capability disclosure** for permissions, injections, source, and install scripts — code-judged, reproducible, zero tokens.

> Not an antivirus, and it makes no safety promises. It proves only what is provable: what a plugin really touches, what it injects, and whether its source can be checked — with evidence (file + line + snippet) for every claim, so you can verify it yourself.

## Install

**The settings UI needs dsh ≥ 0.1.0-rc.8 (recommend 0.1.1-rc.2).** The Web UI depends on `@deepseek-ai/dsh-client-store` in the host module table. The market will not block a mismatched install; on an older host the settings page fails to load (`dsh-client-store` missed the module table).

**The CLI does not need a DSH host** — `npx dsh-trust-check` still works on older dsh.

Check the host first (settings UI only):

```sh
dsh --version
# if too old: npm i -g @deepseek-ai/dsh@latest
```

```sh
dsh plugin --profile web add dsh-trust-check
```

Restart `dsh web`, then open **Settings → Plugin Trust**. Already installed: update from Plugin Market, or `dsh plugin --profile web add dsh-trust-check@latest`, then restart.

A standalone CLI is also provided, independent of the DSH host:

```sh
npx dsh-trust-check                 # audit the default profile `web`
npx dsh-trust-check --profile work  # audit another profile
npx dsh-trust-check --json          # machine-readable output

# Audit any extracted package directory (no profile, no DSH)
npx dsh-trust-check --dir ./path/to/plugin
npx dsh-trust-check --dir ./pkg --spec npm:foo@1.0.0 --json
```

`--dir` and `--profile` are mutually exclusive. Both modes emit the same `AuditResponse` shape for `--json`: `{ schemaVersion, profile, dir?, generatedAt, plugins, errors }`; in single-directory mode `profile` is an empty string and `dir` is the absolute path. See [docs/audit-schema.md](docs/audit-schema.md) and [docs/INTEGRATION.md](docs/INTEGRATION.md).

| Settings → Plugin Trust | CLI `--dir --json` |
| --- | --- |
| ![Settings plugin trust](docs/dsh.png) | ![CLI JSON output](docs/cli.png) |

### Troubleshooting

| If | Then |
| --- | --- |
| Settings: `dsh-client-store` missed the module table | Host too old: upgrade **dsh ≥ 0.1.0-rc.8**, restart Web; use the CLI above for audits in the meantime |
| No “Plugin Trust” in Settings | Confirm `add` + restart; or the client failed to load on an old host |

## How to read the report

The settings UI and CLI use a **decision-first** layout. Reading order:

1. **Decision**: badge + action line + "why be careful" (up to 3 bullets)
2. **Scan**: capability chips → injection summary (collapsed) → source
3. **Evidence**: grouped by capability, collapsed by default

| Verdict | Meaning | When |
|---|---|---|
| **Red line(s)** | Hard red line hit; stop by default — or confirm risk to keep using | `redLines` non-empty, current fingerprint not acknowledged |
| **Risk accepted** | You confirmed the current red-line risk | Has red lines, `trust-ack.json` matches this scan |
| **Review** | No hard red lines, but privileged capabilities or patch changes | Has capabilities or override/disable, no red lines |
| **As expected** | You acknowledged the current capability/shape fingerprint | `trust-ack.json` matches this scan (no red lines) |
| **Nothing detected** | No red lines or privileged capabilities — not a safety guarantee | Everything else |

`score` / `summary` stay in JSON for sorting and integrators; the settings UI does not show them. Injected token estimates are labeled as **cost hints** only.

### Shape layer (code-judged)

Besides capability chips, the report extracts three kinds of literal facts from source:

- **Literal destinations**: URL / host / IP. Same-origin HTTP routes (e.g. `/dsh-market/check`) do not count as destinations.
- **Workspace path escapes**: absolute paths, home directory, traversal, …
- **Secret touches**: paths, sensitive env names.

These mean "we saw this string in source", not "this address/path is safe"; runtime-built URLs are invisible.

**Allowlist**: common host / registry domains (GitHub, npm, npmmirror, Tencent Cloud mirrors, …), the curated DSH catalog and GitHub proxies, and common model-vendor APIs (DeepSeek, OpenAI, Anthropic, Google Gemini). Allowlisted entries are collapsed by default with a short note; plaintext HTTP is never downgraded by the allowlist.

**Noise reduction and truncation**:

- Skips **network-aligned** CIDR table rows (e.g. `["10.0.0.0", 8]`, `inRange(a, "10.0.0.0", "10.255.255.255")`); host routes like `["8.8.8.8", 32]` still count as literal IPs. A `PRIVATE_RANGES` / `CIDR` token on the line, or two IPs on one call, does **not** wipe the line.
- Skips RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and `0.0.0.0` / `255.255.255.255` (bind / broadcast, not unicast outbound).
- Skips placeholder bases like `http://local` / `http://dsh.invalid`, RFC 2606 `.example` / `.invalid` / `.test`, and shell switches (`/c`).
- Comments are blanked before the scan, so an example URL in a JSDoc block is not a destination (bundlers usually keep those comments).
- Namespace identifiers such as `xmlns="http://www.w3.org/2000/svg"` are excluded by exact host — an attacker cannot register those domains, so the exemption cannot be borrowed.
- When findings exceed the cap, the riskiest are kept: plaintext HTTP and literal IPs cannot be crowded out by harmless addresses.
- Secret paths require a **path-only quoted string** (no whitespace): `"~/.ssh/config"`, `"/Users/x/.ssh/config"`, `'.ssh/config'`, `"~/.aws/credentials"`, or path forms like `/id_rsa` / `~/.netrc`. UI prose (`"Uses … ~/.ssh/config when empty"`), deny-list regexes, `startsWith('id_rsa')`, and a bare `'.ssh'` are not credential access.

### Mark as expected

After you confirm capabilities match why you installed the plugin, the fingerprint is stored in `~/.dsh/profiles/<profile>/trust-ack.json`. An upgrade that changes capabilities, destinations, path escapes, secrets, red lines, or skill text (by content hash, not byte length) must be confirmed again. The confirmation request sends the report's `ackFingerprint`; a mismatch returns 409 and asks you to review the refreshed report. Older acknowledgements without a `digest` no longer match. Accepting a red line still requires its own "confirm risk" action, and only after the fingerprint matches.

**AI explain**: optional button; uses your DSH-configured model to explain the report summary only, **does not change the verdict**; unavailable when no model is configured.

### Red lines (default block)

1. declares install / postinstall / preinstall scripts (**not** `prepare`: `prepare` runs on pack/git install only — a score deduction, not a red line);
2. `cordis.patch.yml` overrides/disables an `@deepseek-ai/*` core bundle (matched by `id` **or** `name`);
3. **reads** credential/secret *values* (`credentials.resolve` / `read` / `readRecord` / `get*`, including seam aliases and renamed destructures; keytar/keychain `getPassword` etc. including `import * as` / `default as`; or a secret path on the same line as a file read) **and** has network access — holding a handle only (`const c = ctx.credentials`, `ctx.get('credentials')`) or metadata (`describe`) is a capability chip, not a red line;
4. plaintext `http://` to non-localhost (literal) **and** has network;
5. non-loopback, non-documentation, non-bind/broadcast literal IP outbound **and** has network.

Red lines cap the numeric score at 49 (avoiding "100 + high risk"). **The verdict follows `redLines`, not the score**: a low score (e.g. 9) can come from shell + network + unpinned spec stacking and should show **review**, not red line(s). JSON `band` may still be `red` (score below 50), but UI/CLI use `verdict()` — do not mix them.

## What it audits

| Dimension | Reads | Judgement |
|---|---|---|
| **Capabilities** | `package.json` dependency scopes + static scan of `lib/`, `dist/`, `bin/`, `scripts/`, skill dirs, and `main` / `exports` / `bin` entry files | shell / file read / file write / network / credentials / sub-agents / LLM calls / env reads |
| **Injections** | `cordis.patch.yml` + `systemPrompt` / `ctx.skills.register` / `system-prompt/assemble` + skill text | who it overrides/disables (`id` or `name`), what it injects |
| **Cost** | skill text + system-prompt inline literal bytes | estimated injected tokens per request (bytes / 4, estimate only) |
| **Source** | `package.json` `repository` (falls back to the git install source) + install spec | pinned version / pinned commit |
| **Update risk** | install scripts (install/postinstall/preinstall; `prepare` is deduction-only) | arbitrary code at install time |

## For integrators (e.g. dsh-market)

How to wire a pre-install gate: **[docs/INTEGRATION.md](docs/INTEGRATION.md)**.  
JSON field contract: **[docs/audit-schema.md](docs/audit-schema.md)** (`schemaVersion`, stable gate fields, volatile fields).

Stable exports for pre-install confirmation or CI gates:

```ts
import { auditPlugin, collectPlugin, verdict } from 'dsh-trust-check'

const report = auditPlugin(collectPlugin(extractedDir, spec))

// Gate semantics (fixed — copy into market confirm dialog):
// verdict(report) === 'red'    → block by default; user may confirm to continue
// verdict(report) === 'review' → show capability list; suggest confirm
// verdict(report) === 'clear'  → may pass silently
```

CLI equivalent (market can spawn without DSH):

```sh
npx dsh-trust-check --dir "$EXTRACTED_DIR" --spec "$INSTALL_SPEC" --json
```

Parse `--json` uniformly: `plugins[0]` for single `--dir`, or the full `plugins` array for profile mode; non-empty `errors` means the directory could not be read — **treat as scan failure, not `clear`**. An empty / corrupt extract (no readable `package.json` and no scannable sources) lands in `errors` (fail closed). Top-level **`schemaVersion`** is currently `1` — bump only on breaking **shape** changes, not when detection rules change. See the two docs above; in-repo Path A smoke demo: `scripts/market-gate-demo.mjs`.

**Out of scope for this release**: remote tarball download (market's job). Workflow: extract to a temp dir, then `--dir`.

## Principles

- **Code-judged, not LLM-scored**: every judgement is code, zero tokens, reproducible.
- **Proves presence, never absence**: static analysis only claims "detected X"; it never claims "guaranteed no Y".
- **Evidence you can re-check**: every capability hit carries `file:line` and a snippet.
- **Hot-swappable seam table**: detection rules are a data table (`src/core/seams.ts`); DSH API changes mean editing the table, not the engine.

## Known limits

- **Post-install checkup**: profile mode audits plugins **already installed**; install/postinstall/prepare may have run before your first scan. `--dir` can scan an extracted tree before install (but install scripts may still run during market extract/install).
- Static scans miss/false-positive (runtime-loaded capabilities are invisible; dynamic `import('node:' + …)`, string concatenation, and obfuscated `eval`/`Function` can still bypass the rule table).
- **Does not scan `node_modules`**: dependency behavior is out of scope.
- **Credential-value reads cover**: seam service (`ctx.get('credentials')`, including `await` / optional `get?.`; receivers `ctx` / `this.ctx` / `*Ctx`), property access (`ctx.credentials`), destructuring off context (including `credentials: creds`), rebinds of those aliases (including `b = a`), and keytar/keychain password reads including default / `import * as` / `import { default as … }` / `require` renames. **Still missed on purpose**: destructuring down to a bare function name (`const { resolve } = ctx.credentials` then `resolve(…)`) — same shape as Promise executors and would red-line plugins like `dsh-pocket` / `agent-teams` without scope tracking; a secret path held in a variable then `readFileSync(p)`; receivers named neither `ctx` nor `*Ctx` (e.g. `context` / `Context`).
- **`new URL` base args are not destinations**, so `const u = new URL('/x', 'http://evil'); fetch(u.href)` has no plaintext-http red line — the known cost of that exemption; do not widen it.
- Client-side `fetch('/api')` same-origin calls are still flagged as network; the chip is labelled same-origin or outbound, but a missing outbound literal is not a proof of no outbound access, and the score is unchanged.
- Injected tokens are a byte / 4 estimate, not exact billing.
- `link:` / `file:` installs can't infer source from the spec; if the package.json lacks `repository`, it shows "no repository declared".
- The `repository` field is self-declared; it is not cross-checked against the npm package name, and a non-`http(s)` scheme is never rendered as a clickable link.

## Development

```sh
pnpm install
pnpm build       # tsdown: node half → lib/index.js, client half → lib/client.js
pnpm test        # vitest, covers the core engine
pnpm typecheck   # tsc --noEmit
```

Rule-table, skip-rule, and allowlist contributions: [CONTRIBUTING.md](CONTRIBUTING.md). **Widening a skip or allowlist is reviewed harder than adding a rule** — both can weaken detection; plaintext HTTP is never downgraded by the allowlist. False-positive fixes must include a fail-open probe. The attack classes rules are held against, and the three limits of static analysis, are in [THREAT-MODEL.md](THREAT-MODEL.md).

## Roadmap

- v1 (current): installed-plugin audit + CLI `--dir` + Web dimension-first report
- v2: PR to dsh-market for install confirmation (this package provides `--dir` / `auditPlugin` contract)
- v3: the data layer for Agent CI — "did this plugin's behavior drift on upgrade" regression assertions

## License

MIT
