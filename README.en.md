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

Reports lead with **four dimensions** — do not treat the 0–100 score as the primary conclusion. Settings UI and CLI use the same order:

| Dimension | What | How to read |
|---|---|---|
| **Red lines** | install scripts, core bundle overrides, credentials + network | Shown first when present; badge: red line(s) / review suggested / no red lines |
| **Capabilities** | shell / files / network / credentials / sub-agents / LLM / env | Chip list; proves presence only, never absence |
| **Injections** | patch override/disable, system-prompt, skill registration | Who is changed, what is injected |
| **Source** | pinned version, repository, install scripts | Whether pinned; `repository` is self-declared |

**Sort score** (`score` field) stays in JSON and card meta for list ordering only (red lines first). `summary` no longer starts with `green · 83`; e.g. `2 red line(s) · shell+network · unpinned` or `review suggested · file reads+network · pinned`.

Injected token estimates stay in the injection block as a **cost hint only**, not a trust signal.

### Red lines (default block)

1. declares install/postinstall/preinstall/**prepare** scripts;
2. `cordis.patch.yml` overrides/disables an `@deepseek-ai/*` core bundle (matched by `id` **or** `name`);
3. reads credential/secret material (keychain / keytar / dotenv / `~/.ssh` / `.aws/credentials` …) **and** has network access.

Red lines cap the numeric score at 49 (avoid "100 + high risk"), but UI/CLI rely on the red-line badge, not the score, for judgement.

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
import { auditPlugin, collectPlugin } from 'dsh-trust-check'

// extractedDir: unpacked package tree; spec: install spec label (e.g. npm:foo@1.0.0)
const report = auditPlugin(collectPlugin(extractedDir, spec))

// Gate semantics (fixed — copy into market confirm dialog):
// report.redLines.length > 0  → block by default; user may confirm to continue
// capabilities, no red lines (band yellow) → show capability list; suggest confirm
// no red lines, no privileged caps (band green) → may pass silently
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
