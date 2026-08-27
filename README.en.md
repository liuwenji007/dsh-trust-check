# dsh-trust-check

[中文](README.md)

Static trust audit for DeepSeek Harness plugins: **capability disclosure** for permissions, injections, source, and install scripts — code-judged, reproducible, zero tokens.

> Not an antivirus, and it makes no safety promises. It proves only what is provable: what a plugin really touches, what it injects, and whether its source can be checked — with evidence (file + line + snippet) for every claim, so you can verify it yourself.

## Install

```sh
dsh plugin --profile web add dsh-trust-check
```

Restart `dsh web`, then open **Settings → Plugin Trust**. A standalone CLI is also provided, independent of the DSH host:

```sh
npx dsh-trust-check                 # audit the default profile `web`
npx dsh-trust-check --profile work  # audit another profile
npx dsh-trust-check --json          # machine-readable output

# Audit any extracted package directory (no profile, no DSH)
npx dsh-trust-check --dir ./path/to/plugin
npx dsh-trust-check --dir ./pkg --spec npm:foo@1.0.0 --json
```

`--dir` and `--profile` are mutually exclusive. Single-directory `--json` uses the same `AuditResponse` shape as profile mode: `{ profile, dir?, generatedAt, plugins, errors }` (`profile` is empty, `dir` is the absolute path).

## How to read the report

The settings UI and CLI use a **decision-first** layout: verdict, then capabilities / injections / source, with evidence collapsed by default.

| Verdict | Meaning | When |
|---|---|---|
| **Red line(s)** | Hard red line hit; stop by default | Only when `redLines.length > 0` |
| **Review** | No hard red lines, but privileged capabilities or patch changes | Has capabilities or override/disable, no red lines |
| **As expected** | You acknowledged the current capability/shape fingerprint | Local `trust-ack.json` matches this scan |
| **Clear** | No red lines or privileged capabilities | Everything else |

**Shape layer (code-judged)**: besides capability chips, the report lists **literal destinations** (URL/host/IP/relative paths) and **secret touches** (paths, sensitive env names) found in source. This is not “address safety” — only “we saw this string in source”; runtime-built URLs are invisible. Common host / registry domains (GitHub, npm, npmmirror, …) have a built-in allowlist: collapsed by default with a short note; plaintext HTTP is never downgraded by the allowlist. The scanner also skips IP range tables (e.g. SSRF private-IP checks), placeholder bases like `http://local`, shell switches (`/c`), and filesystem roots (`/usr`, `/opt`) to avoid false destinations.

**Mark as expected**: after you confirm capabilities match why you installed the plugin, the fingerprint is stored in `~/.dsh/profiles/<profile>/trust-ack.json`. Upgrades that change capabilities/destinations/secrets return to **review**.

**AI explain**: optional button; uses your DSH-configured model to explain the report summary only, **does not change the verdict**; unavailable when no model is configured.

**Important: "red line(s)" follows `redLines`, not a low score.** A low score (e.g. 9) can come from shell + network + unpinned spec stacking — the UI shows **review**, not red line(s). JSON `band` may still be `red` (score &lt; 50), but UI/CLI use `verdict()` — do not mix them.

Reading order:

1. **Decision**: badge + action line + "why be careful" (up to 3 bullets)
2. **Scan**: capability chips → injection summary (collapsed) → source
3. **Evidence**: grouped by capability, collapsed by default

`score` / `summary` stay in JSON for sorting and integrators; **the settings UI no longer shows them**. Injected token estimates are labeled as **cost hints** only.

### Red lines (default block)

1. declares install/postinstall/preinstall/**prepare** scripts;
2. `cordis.patch.yml` overrides/disables an `@deepseek-ai/*` core bundle (matched by `id` **or** `name`);
3. reads credential/secret material (keychain / keytar / dotenv / `~/.ssh` / `.aws/credentials` …) **and** has network access;
4. plaintext `http://` to non-localhost (literal) **and** has network;
5. non-loopback literal IP outbound **and** has network.

Red lines cap the numeric score at 49 (avoid "100 + high risk"), but UI/CLI verdicts follow `redLines`, not score or `band`.

## What it audits

| Dimension | Reads | Judgement |
|---|---|---|
| **Capabilities** | `package.json` dependency scopes + static scan of `lib/`, `dist/`, `bin/`, `scripts/`, skill dirs, and `main` / `exports` / `bin` entry files | shell / file read / file write / network / credentials / sub-agents / LLM calls / env reads |
| **Injections** | `cordis.patch.yml` + `systemPrompt` / `ctx.skills.register` / `system-prompt/assemble` + skill text | who it overrides/disables (`id` or `name`), what it injects |
| **Cost** | skill text + system-prompt inline literal bytes | estimated injected tokens per request (bytes / 4, estimate only) |
| **Source** | `package.json` `repository` (falls back to the git install source) + install spec | pinned version / pinned commit |
| **Update risk** | install scripts (install/postinstall/preinstall/prepare) | arbitrary code at install time |

## For integrators (e.g. dsh-market)

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

Parse `--json` uniformly: `plugins[0]` for single `--dir`, or the full `plugins` array for profile mode; non-empty `errors` means the directory could not be read.

**Out of scope for this release**: remote tarball download (market's job). Workflow: extract to a temp dir, then `--dir`.

## Principles

- **Code-judged, not LLM-scored**: every judgement is code, zero tokens, reproducible.
- **Proves presence, never absence**: static analysis only claims "detected X"; it never claims "guaranteed no Y".
- **Evidence you can re-check**: every capability hit carries `file:line` and a snippet.
- **Hot-swappable seam table**: detection rules are a data table (`src/core/seams.ts`); DSH API changes mean editing the table, not the engine.

## Known limits

- **Post-install checkup**: profile mode audits plugins **already installed**; install/postinstall/prepare may have run before your first scan. `--dir` can scan an extracted tree before install (but install scripts may still run during market extract/install).
- Static scans miss/false-positive (runtime-loaded capabilities are invisible; dynamic `import('node:' + …)`, `eval`, `Function`, third-party HTTP libs like `got`/`ws` are not in the rule table).
- **Does not scan `node_modules`**: dependency behavior is out of scope.
- Client-side `fetch('/api')` same-origin calls are also flagged as network, not separated from outbound access.
- Injected tokens are a byte / 4 estimate, not exact billing.
- `link:` / `file:` installs can't infer source from the spec; if the package.json lacks `repository`, it shows "no repository declared".
- The `repository` field is self-declared; it is not cross-checked against the npm package name.

## Development

```sh
pnpm install
pnpm build       # tsdown: node half → lib/index.js, client half → lib/client.js
pnpm test        # vitest, covers the core engine
pnpm typecheck   # tsc --noEmit
```

## Roadmap

- v1 (current): installed-plugin audit + CLI `--dir` + Web dimension-first report
- v2: PR to dsh-market for install confirmation (this package provides `--dir` / `auditPlugin` contract)
- v3: the data layer for Agent CI — "did this plugin's behavior drift on upgrade" regression assertions

## License

MIT
