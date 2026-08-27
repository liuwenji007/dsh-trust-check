# dsh-trust-check

[中文](README.md)

A "pre-install checkup" for DeepSeek Harness plugins: statically audit an installed plugin's capabilities, injections, token cost, source, and update risk, and produce a **code-judged, reproducible, zero-token** 0–100 trust score.

> Not an antivirus, and it makes no safety promises. It proves only what is provable: what a plugin really touches, what it injects, and whether its source is trustworthy — with evidence (file + line + snippet) for every claim, so you can verify it yourself.

## Install

```sh
dsh plugin --profile web add dsh-trust-check
```

Restart `dsh web`, then open **Settings → Plugin Trust**. A standalone CLI is also provided, independent of the DSH host:

```sh
npx dsh-trust-check                 # audit the default profile `web`
npx dsh-trust-check --profile work  # audit another profile
npx dsh-trust-check --json          # machine-readable output
```

## What it audits

| Dimension | Reads | Judgement |
|---|---|---|
| **Capabilities** | `package.json` dependency scopes + static scan of `lib/*.js` | shell / file read / file write / network / credentials / sub-agents / LLM calls / env reads |
| **Injections** | `cordis.patch.yml` + `systemPrompt` registration + skill text | who it overrides/disables, what it injects |
| **Cost** | skill/instruction text bytes | estimated injected tokens per request (bytes / 4, estimate only) |
| **Source** | `package.json` `repository` (falls back to the git install source) + install spec | pinned version / pinned commit |
| **Update risk** | install scripts (install/postinstall/preinstall) | arbitrary code at install time |

## Trust score

```
score = 100 − capability weights − injection cost − source risk − update risk
```

- **≥ 80 green**: pure UI / read-only / trusted source.
- **50–79 yellow**: privileged or injecting — lists exactly what it wants.
- **< 50 red**: red line hit, or high risk.

Red lines (force red):

1. declares install/postinstall/preinstall scripts;
2. `cordis.patch.yml` overrides/disables an `@deepseek-ai/*` core bundle;
3. reads credential/secret material (keychain / keytar / dotenv / `~/.ssh` / `.aws/credentials` …) **and** has network access.

## Principles

- **Code-judged, not LLM-scored**: every judgement is code, zero tokens, reproducible.
- **Proves presence, never absence**: static analysis only claims "detected X"; it never claims "guaranteed no Y".
- **Evidence you can re-check**: every capability hit carries `file:line` and a snippet.
- **Hot-swappable seam table**: detection rules are a data table (`src/core/seams.ts`); DSH API changes mean editing the table, not the engine.

## Known limits

- Static scans miss/false-positive (runtime-loaded capabilities are invisible; a rule word inside a string can match). Precision patterns + comment stripping + presence-only keep false positives low, but treat results as a checkup, not a verdict.
- Injected tokens are a byte / 4 estimate, not exact billing.
- `link:` / `file:` installs can't infer source from the spec; if the package.json lacks `repository`, it shows "no repository declared".

## Development

```sh
pnpm install
pnpm build       # tsdown: node half → lib/index.js, client half → lib/client.js
pnpm test        # vitest, covers the core engine
pnpm typecheck   # tsc --noEmit
```

## Roadmap

- v1 (current): installed-plugin audit + CLI + Web report view
- v1.1: audit arbitrary targets (`npm:xxx` / `github:owner/repo`, download tarball and scan)
- v2: propose install-dialog integration to dsh-market (audit summary before install)
- v3: the data layer for Agent CI — "did this plugin's behavior drift on upgrade" regression assertions

## License

MIT
