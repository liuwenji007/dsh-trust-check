# Security policy

[中文说明见下方](#中文)

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/liuwenji007/dsh-trust-check/security/advisories/new).
Do not open a public issue, pull request, or discussion for a working bypass
until a fixed version has been published.

Include, if you can:

- the smallest package tree that reproduces it (file layout + `package.json`);
- the command you ran and the JSON you got;
- the result you expected.

This is a volunteer-maintained project. Reports are handled on a best-effort
basis; a fix is released first, then the issue is described in the release
notes.

## What counts as a vulnerability here

This package makes a small set of **presence** claims (see
[THREAT-MODEL.md](THREAT-MODEL.md) and [docs/POSITIONING.md](docs/POSITIONING.md)).
A vulnerability is a way to make those claims silently wrong:

- **Fail-open on a high-confidence signal**: a package that should produce a
  red line (install script, core-bundle override/disable, credential read with
  network, plaintext `http://` or literal-IP egress) produces none, through a
  shape the documented rules are meant to cover.
- **Silent coverage loss**: code reachable from a declared entry point or a
  static relative import is skipped without landing in `errors` or
  `coverageNotes`.
- **Fail-closed bypass**: an unreadable, oversized, or escaping tree is
  reported as a normal result instead of a scan failure.
- **Local routes**: a request that is not same-origin loopback can read audit
  results, change acknowledgements, or trigger the explain route.

## What is not a vulnerability

- The limits listed under "Known limits" in the README and "What this scanner
  will never prove" in THREAT-MODEL.md (runtime-built URLs, dynamic
  `import()`, obfuscated `eval`, bare dependencies, skill-text intent,
  in-process tampering of the Settings page).
- False positives — use the
  [false-positive issue template](https://github.com/liuwenji007/dsh-trust-check/issues/new/choose).
- Disagreement with whether a capability is appropriate for a plugin. That is a
  policy question for the user or the integrator, not a scanner defect.

---

## 中文

**请通过 GitHub 的[私密漏洞报告](https://github.com/liuwenji007/dsh-trust-check/security/advisories/new)提交。** 在修复版本发布之前，请不要在公开的 issue、PR 或讨论区里贴出可用的绕过方法。

报告时尽量附上：能复现问题的最小包目录结构和 `package.json`、执行的命令和得到的 JSON，以及你预期的结果。本项目由个人维护，会尽力处理；流程是先发布修复版本，再在发布说明里描述问题。

**算作漏洞的情况**：本应命中的高置信度信号（安装脚本、覆盖或禁用核心 bundle、读到凭据且有网络、明文 HTTP 或字面量 IP 外连）没有命中；从入口或静态相对 import 可达的代码被静默跳过，既不进 `errors` 也不进 `coverageNotes`；本应 fail closed 的情况被当作正常结果输出；非同源、非本机的请求能够读取审计结果、修改确认记录或触发 AI 解释。

**不算漏洞的情况**：README “已知局限”和 THREAT-MODEL 里已经写明的静态分析边界；误报（请用误报 issue 模板）；对“某个能力对这个插件是否合理”的不同看法，这属于用户或集成方的策略判断。
