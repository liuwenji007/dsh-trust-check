# Contributing / 贡献指南

This project is a static capability-disclosure scanner, not a security product. Contributions that enlarge what the scanner can *prove* are welcome. Contributions that enlarge what it *claims* are not.

本项目是静态能力披露扫描器，不是安全产品。欢迎扩大「能证明什么」的贡献；不要扩大「敢声称什么」。

## What to contribute / 贡献什么

The cheapest, highest-value unit is **one detection rule plus one test**. The engine (`src/core/audit.ts` and friends) is not the contribution surface.

最便宜、价值最高的贡献单元是 **一条检测规则 + 一个测试**。引擎本身不是贡献面。

| Kind / 类型 | File / 文件 | Review weight / 评审权重 |
|---|---|---|
| New capability pattern | [`src/core/seams.ts`](src/core/seams.ts) `CAPABILITY_RULES` | Normal. Must include a test that hits and a test that would have false-positived the old regex. |
| New secret-path / env pattern | [`src/core/shape.ts`](src/core/shape.ts) `SECRET_PATH` / `ENV_SENSITIVE` | Normal. Same test bar. |
| False-positive fixture | `tests/core/*.spec.ts` | Light. A snippet that currently flags and should not. |
| Allowlist / identifier-host / placeholder-host | [`src/core/destination-priority.ts`](src/core/destination-priority.ts) `DEST_WHITELIST`; [`src/core/shape.ts`](src/core/shape.ts) `IDENTIFIER_HOST_EXACT` / `PLACEHOLDER_HOST_EXACT` | **Heavy.** These *weaken* detection. See [Allowlist governance](#allowlist-governance--白名单治理) below. |

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

## Allowlist governance / 白名单治理

Three tables hide destinations. They are not equivalent, and none of them is a safety claim.

三张表会隐藏去向。它们不等价，也没有一张是安全承诺。

| Table | Effect | Allowed when |
|---|---|---|
| `DEST_WHITELIST` | HTTPS hosts of known package/source/model APIs render as "common" and fold away. **Plaintext HTTP is never downgraded**, even if the host is listed. | The host is a public registry, source forge, CDN, or first-party model API that DSH plugins routinely talk to. Subdomains inherit. A new `DestWhitelistReason` also needs a locale key `destWhitelist.<code>` in both languages. |
| `IDENTIFIER_HOST_EXACT` | Exact host match for XML/SVG namespace identifiers (`www.w3.org`). Not a request. | The host is a standards-body namespace that an attacker cannot register. Exact match only — no subdomain inheritance. |
| `PLACEHOLDER_HOST_EXACT` | RFC 2606 / 6761 documentation hosts. | Documentation hosts only. Generic single-label names (`proxy`, `server`, `host`) must **not** be added: they resolve on a LAN with a DNS search domain and would hide a real plaintext-HTTP red line. |

**Allowlist PRs are reviewed differently from rule PRs.** An allowlist entry weakens detection. The PR body must state:

1. Why this host is not an exfiltration destination a hostile plugin would pick.
2. Which table it belongs in, and why the other two are wrong.
3. That plaintext HTTP against this host still stays a red line (`DEST_WHITELIST` cannot change that; do not add code that does).

Do not add an allowlist entry to silence a false positive in *this* repo's own sources. Fix the scanner (comment stripping, identifier-host, ranked truncation) instead.

**白名单 PR 与规则 PR 不同权。** 白名单是在削弱检测。PR 正文必须说明：

1. 为什么这个主机不是敌对插件会选的外泄去向。
2. 它属于哪张表，另外两张为什么不对。
3. 针对该主机的明文 HTTP 仍然是红线（`DEST_WHITELIST` 做不到降级；不要加能做到的代码）。

不要靠加白名单来消掉本仓库源码里的误报。先修扫描器（抹注释、identifier-host、按风险截断）。

## Out of scope / 不接受

- Remote tarball download. Market's job; this package audits a directory it is given.
- Scanning `node_modules`. Dependency behavior is out of scope by design.
- LLM-scored verdicts, "safe" badges, or any wording that claims absence of risk.
- Changing `verdict()` to follow the numeric score. The verdict follows `redLines`.

## Dev loop

```sh
pnpm install
pnpm test        # vitest, core engine
pnpm typecheck   # tsc --noEmit
pnpm build       # tsdown: node half → lib/index.js, client half → lib/client.js
```

License: MIT. By opening a PR you license the contribution under MIT.
