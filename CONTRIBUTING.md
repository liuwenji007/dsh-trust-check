# Contributing / 贡献指南

This project is a static capability-disclosure scanner, not a security product. Contributions that enlarge what the scanner can *prove* are welcome. Contributions that enlarge what it *claims* are not.

本项目是静态能力披露扫描器，不是安全产品。欢迎扩大「能证明什么」的贡献；不要扩大「敢声称什么」。

## What to contribute / 贡献什么

The cheapest, highest-value unit is **one detection rule plus one test**. The engine (`src/core/audit.ts` and friends) is not the contribution surface.

最便宜、价值最高的贡献单元是 **一条检测规则 + 一个测试**。引擎本身不是贡献面。

| Kind / 类型 | File / 文件 | Review weight / 评审权重 |
|---|---|---|
| New capability pattern | [`src/core/seams.ts`](src/core/seams.ts) `CAPABILITY_RULES` | Normal. Must include a test that hits and a test that would have false-positived the old regex. |
| New secret-path / env pattern | [`src/core/shape.ts`](src/core/shape.ts) `SECRET_PATH` / `ENV_SENSITIVE` | Normal. Same test bar. See [Secret / path shape](#secret--path-shape--密钥路径形态). |
| False-positive fixture | `tests/core/*.spec.ts` | Light. A snippet that currently flags and should not. |
| Skip / narrow-detection (docs IP, CIDR table, placeholders) | [`src/core/shape.ts`](src/core/shape.ts) | **Heavy.** Widening a skip is fail-open risk — same bar as allowlists. See [Tightening without fail-open](#tightening-without-fail-open--收紧检测而不 fail-open). |
| Allowlist / identifier-host / placeholder-host | [`src/core/destination-priority.ts`](src/core/destination-priority.ts) `DEST_WHITELIST`; [`src/core/shape.ts`](src/core/shape.ts) `IDENTIFIER_HOST_EXACT` / `PLACEHOLDER_HOST_EXACT` / docs IPs | **Heavy.** These *weaken* detection. See [Allowlist governance](#allowlist-governance--白名单治理) below. |

Open an issue from the matching template before a non-trivial PR: **false positive**, **false negative**, or **new seam rule**. Small rule+test PRs can skip the issue.

非琐碎改动请先用对应模板开 issue：**误报**、**漏报**、**新 seam 规则**。规则 + 测试的小 PR 可以不先开 issue。

## Rule discipline / 规则纪律

Copied from the contract at the top of `src/core/seams.ts`. A PR that violates any of these is rejected, because the rule table contains every dangerous API name and will otherwise flag *itself*.

纪律写在 `src/core/seams.ts` 文件头。违反任一条的 PR 会被拒：规则表字面上含有每个危险 API 名，否则扫描器会命中自己。

1. Match the **call site** (`\bname\s*\(`), never the bare identifier. A bare `name` inside a regex literal, a type union, or a string must not match.
2. Match module access by the **import form** (`require('x')` / `from 'x'` / `import('x')`), not the word.
3. `\bexec\s*\(` is banned: `.exec(` is `RegExp.prototype.exec`, not a shell.
4. Confidence is presence, never absence: a rule claims "detected X", never "guaranteed no X".
5. Comments are stripped before the scan (`src/core/strip-comments.ts`). Do not add rules whose only purpose is to ignore comment text.

A contribution is: add one entry to `CAPABILITY_RULES` (or one alternative in an existing pattern) **and** a case in `tests/core/capability.spec.ts`. CI (`typecheck` / `test` / `build`) runs on Ubuntu and Windows; both must pass.

一次贡献 = 在 `CAPABILITY_RULES` 加一条（或在已有 pattern 里加一个分支）**并且**在 `tests/core/capability.spec.ts` 加一个用例。CI 在 Ubuntu 和 Windows 上跑 `typecheck` / `test` / `build`，两边都要通过。

## Secret / path shape / 密钥路径形态

Secret paths prove **touch shape**, not intent. Draw the boundary from “what a real path literal looks like”, not from “the opposite of one UI string we saw”.

密钥路径证的是**触碰形状**，不是意图。边界按「真路径字面量长什么样」画，不要按「某一个 UI 误报样例的反面」画。

| Match / 认 | Do not match / 不认 |
|---|---|
| Path-only quoted strings (no whitespace): `"~/.ssh/config"`, `"/Users/x/.ssh/config"`, `'.ssh/config'`, `"~/.aws/credentials"` | UI prose with spaces: `"Uses … ~/.ssh/config when empty"` |
| Path forms: `/id_rsa`, `~/.netrc`, `./.netrc` | Deny-list array bare `'.ssh'` / `'.netrc'`; `startsWith('id_rsa')`; regex deny strings |
| `ctx.credentials` / keychain / keytar / dotenv imports | The word “keychain” in ordinary prose |

When fixing a false positive, also add a **fail-open probe** that a hostile plugin would try after your fix (absolute path, string concat fragment, host `/32` tuple, …). See below.

修误报时，务必补一条敌对插件在你收紧后会试的 **fail-open 探针**（绝对路径、拼接片段、主机 `/32` 元组……）。见下节。

## Tightening without fail-open / 收紧检测而不 fail-open

Narrowing a detector or widening a skip both change the fail-open surface. Catalog “goes green” is not enough.

收紧检测或扩大跳过，都会改变 fail-open 面。catalog「变绿」不够。

**Required in the PR / PR 必须包含：**

1. **FP fixture** — the noise that must stop firing.  
2. **Still-hits fixture** — the real shape that must keep firing (including at least one rewrite an attacker would try: absolute path, concat, camouflage tuple, …).  
3. A one-line note: what shape you are proving, and what you are *not* claiming.

**Skip rules (CIDR / docs IP / placeholders) — allowed when:**

| Skip | Allowed when |
|---|---|
| Network CIDR table row | `["10.0.0.0", 8]`-style **network-aligned** prefix `< 32`, or `inRange(..., ip, ip)`. Not: two IPs on a call, not: `PRIVATE_RANGES = "8.8.8.8"`, not: `["8.8.8.8", 32]` host routes. |
| Documentation IPv4 | RFC 5737 only (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`). Same idea as RFC 2606 hosts — not routable as exfil. Do not skip all RFC1918. |
| Bind / broadcast | `0.0.0.0`, `255.255.255.255` — not unicast outbound. |
| Placeholder / identifier hosts | Existing tables only; see allowlist governance. |

Do not silence a false positive by stuffing `DEST_WHITELIST` unless the host belongs there under allowlist governance.

不要靠塞 `DEST_WHITELIST` 消误报，除非该主机本身符合白名单治理。

## Allowlist governance / 白名单治理

Three host tables hide destinations. They are not equivalent, and none of them is a safety claim. Documentation **IPv4** ranges live next to placeholders in `shape.ts` (`isDocumentationIp`), not in `DEST_WHITELIST`.

三张主机表会隐藏去向。它们不等价，也没有一张是安全承诺。文档 **IPv4** 网段在 `shape.ts`（`isDocumentationIp`），不在 `DEST_WHITELIST`。

| Table | Effect | Allowed when |
|---|---|---|
| `DEST_WHITELIST` | HTTPS hosts of known package/source/model APIs render as "common" and fold away. **Plaintext HTTP is never downgraded**, even if the host is listed. | The host is a public registry, source forge, CDN, or first-party model API that DSH plugins routinely talk to. Subdomains inherit. A new `DestWhitelistReason` also needs a locale key `destWhitelist.<code>` in both languages. |
| `IDENTIFIER_HOST_EXACT` | Exact host match for XML/SVG namespace identifiers (`www.w3.org`). Not a request. | The host is a standards-body namespace that an attacker cannot register. Exact match only — no subdomain inheritance. |
| `PLACEHOLDER_HOST_EXACT` (+ docs IPs / RFC 2606 TLDs) | Documentation / parser bases. | Documentation hosts and RFC 5737 docs IPv4 only. Generic single-label names (`proxy`, `server`, `host`) must **not** be added: they resolve on a LAN with a DNS search domain and would hide a real plaintext-HTTP red line. |

**Allowlist / skip PRs are reviewed differently from rule PRs.** An entry that hides destinations weakens detection. The PR body must state:

1. Why this host/IP/shape is not an exfiltration destination a hostile plugin would pick (or why the skip cannot be borrowed as camouflage).  
2. Which table / helper it belongs in, and why the others are wrong.  
3. That plaintext HTTP against allowlisted **hosts** still stays a red line (`DEST_WHITELIST` cannot change that; do not add code that does).

Do not add an allowlist entry to silence a false positive in *this* repo's own sources. Fix the scanner (comment stripping, identifier-host, path-only secrets, ranked truncation) instead.

**白名单 / 跳过类 PR 与加规则不同权。** 会隐藏去向的条目是在削弱检测。PR 正文必须说明：

1. 为什么这个主机/IP/形状不是敌对插件会选的外泄去向（或为什么跳过不能被借去伪装）。  
2. 它属于哪张表/哪个 helper，另外几张为什么不对。  
3. 针对白名单**主机**的明文 HTTP 仍然是红线（`DEST_WHITELIST` 做不到降级；不要加能做到的代码）。

不要靠加白名单来消掉本仓库源码里的误报。先修扫描器（抹注释、identifier-host、path-only 密钥、按风险截断）。

## Catalog samples / 样本复盘（可选）

For noise-rate work against the published catalog:

```sh
node scripts/catalog-noise.mjs sample   # or expand
# download packs yourself into .cache/catalog-sample/downloads/
node scripts/catalog-noise.mjs scan
node scripts/catalog-noise.mjs review   # TP / FP / FN sheet — prefer rule fixes over allowlists
```

See `scripts/catalog-noise.md`. Empty `clear` is *no information*, not a safety pass.

面向已发布目录的噪音率工作时，用上面脚本；见 `scripts/catalog-noise.md`。空的 `clear` 是**无信息**，不是安全通行证。

## Out of scope / 不接受

- Remote tarball download. Market's job; this package audits a directory it is given.
- Scanning `node_modules`. Dependency behavior is out of scope by design.
- LLM-scored verdicts, "safe" badges, or any wording that claims absence of risk.
- Changing `verdict()` to follow the numeric score. The verdict follows `redLines`.
- Runtime monitoring / intercepting other plugins' `fetch`/`exec`. Out of product scope for this package.

## Dev loop

```sh
pnpm install
pnpm test        # vitest, core engine
pnpm typecheck   # tsc --noEmit
pnpm build       # tsdown: node half → lib/index.js, client half → lib/client.js
```

Threat classes and static-analysis limits: [THREAT-MODEL.md](THREAT-MODEL.md). Integrator contract: [docs/INTEGRATION.md](docs/INTEGRATION.md).

License: MIT. By opening a PR you license the contribution under MIT.
