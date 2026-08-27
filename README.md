# dsh-trust-check

[English](README.en.md)

DeepSeek Harness 插件静态信任审计：对已安装插件做**能力披露**——权限、注入、来源、安装脚本——代码判定、可复现、零 token。

> 不是"杀毒软件"，也不做安全承诺。它只做能证明的事：把插件**真实会碰什么、注入了什么、来源是否可核对**摊开给你看，结论每一条都附证据（文件 + 行号 + 片段），你可以自己复核。

## 安装

```sh
dsh plugin --profile web add dsh-trust-check
```

重启 `dsh web`，打开 **设置 → 插件体检**。同时提供独立 CLI，不依赖 DSH 宿主：

```sh
npx dsh-trust-check                 # 审计默认 profile `web`
npx dsh-trust-check --profile work  # 审计其他 profile
npx dsh-trust-check --json          # 机器可读输出

# 审计任意已解压的包目录（无需 profile、无需 DSH）
npx dsh-trust-check --dir ./path/to/plugin
npx dsh-trust-check --dir ./pkg --spec npm:foo@1.0.0 --json
```

`--dir` 与 `--profile` 互斥。单目录 `--json` 输出与 profile 模式相同的 `AuditResponse` 形状：`{ profile, dir?, generatedAt, plugins, errors }`（单目录时 `profile` 为空字符串，`dir` 为绝对路径）。

## 怎么读报告

设置页与 CLI 采用**决策优先**布局：先看裁决，再看能力 / 注入 / 来源，证据默认折叠。

| 裁决 | 含义 | 何时出现 |
|---|---|---|
| **有红线** | 命中硬红线，默认应停用 | 仅当 `redLines.length > 0` |
| **需确认** | 未见硬红线，但有特权能力或 patch 改动 | 有能力或 override/disable，且无红线 |
| **能力如预期** | 你已确认当前能力与去向指纹 | 本机 `trust-ack.json` 与本次扫描一致 |
| **无红线** | 未见红线或特权能力 | 其余 |

**形状层（代码判定）**：除能力芯片外，报告会列出源码中的**字面量去向**（URL/host/IP/相对路径）和**密钥触摸**（路径、敏感 env 名）。这不代表「地址安全」，只代表「在源码里看到了什么」；运行时拼接的 URL 看不到。常见托管/registry 域名（GitHub、npm、npmmirror 等）以及常见模型厂商 API（DeepSeek、OpenAI、Anthropic、Google Gemini）有内置白名单：默认收起并附简短说明，明文 HTTP 永远不会因白名单降级。扫描器会跳过网段边界表（如 SSRF 私网判定）、`http://local` 一类占位 base、cmd 开关（`/c`）以及 `/usr` `/opt` 等文件系统路径，避免误判。

**记为预期**：在设置页确认「这些能力符合我装它的目的」后，写入 `~/.dsh/profiles/<profile>/trust-ack.json`。升级后能力/去向/密钥触摸变化会回到「需确认」。

**AI 解释**：可选按钮，通过 DSH 已配置的模型解释报告摘要，**不改裁决**；未配置模型时不可用。

**重要：`有红线` 只看 `redLines`，不看低分。** 分数低（如 9 分）可能只是因为 shell + 网络 + 未锁版本等叠加，此时应显示「需确认」而非「有红线」。JSON 里的 `band` 仍可能为 `red`（分数 &lt; 50），但 UI/CLI 用 `verdict()` 呈现，二者不要混读。

阅读顺序：

1. **决策**：徽章 + 动作句 +「为什么要小心」（最多 3 条）
2. **扫描**：能力芯片 → 注入摘要（默认折叠）→ 来源
3. **取证**：证据按能力分组，默认折叠

`score` / `summary` 仍留在 JSON 里供排序与集成方使用，**设置页不再展示**。注入 token 估算标明为**成本参考**，不是信任依据。

### 红线（有则默认应挡住）

1. 声明 install/postinstall/preinstall/**prepare** 安装脚本；
2. `cordis.patch.yml` override / disable 了 `@deepseek-ai/*` 核心 bundle（匹配 `id` **或** `name`）；
3. 读取凭据/密钥材料（keychain / keytar / dotenv / `~/.ssh` / `.aws/credentials` 等）**且**有网络访问；
4. 非 localhost 的明文 `http://` 外连（字面量）**且**有 network；
5. 非 loopback 的字面量 IP 外连 **且**有 network。

命中红线时数值分封顶 49（避免「100 分 + 高风险」的误导），但 UI/CLI 以 `redLines` 裁决，不以分数或 `band` 作标签。

## 审计什么

| 维度 | 读什么 | 判定 |
|---|---|---|
| **能力面** | `package.json` 依赖 scope + 静态扫 `lib/`、`dist/`、`bin/`、`scripts/`、技能目录，以及 `main` / `exports` / `bin` 入口文件 | shell / 文件读写 / 网络 / 凭据 / 子代理 / LLM 调用 / 环境变量 |
| **注入面** | `cordis.patch.yml` + `systemPrompt` / `ctx.skills.register` / `system-prompt/assemble` + 技能文本 | override / disable 了谁（`id` 或 `name`）、注入了什么 |
| **成本** | 技能文本 + system-prompt 行内字面量字节数 | 估算每请求注入 token（字节 / 4，仅估算） |
| **来源** | `package.json` 的 `repository`（缺失回退到 git 安装源）+ 安装 spec | 是否锁版本/锁 commit |
| **更新风险** | 安装脚本（install/postinstall/preinstall/prepare） | 是否在安装时执行任意代码 |

## 给集成方（如 dsh-market）

本包导出稳定 API，供安装前确认弹窗或 CI 闸门使用：

```ts
import { auditPlugin, collectPlugin, verdict } from 'dsh-trust-check'

const report = auditPlugin(collectPlugin(extractedDir, spec))

// 闸门语义（写死，可直接抄进 market 确认弹窗）：
// verdict(report) === 'red'   → 默认挡住，允许用户确认后继续
// verdict(report) === 'review'  → 展示能力清单，建议用户确认
// verdict(report) === 'clear'   → 可静默通过
```

CLI 等价调用（market 也可 spawn，无需 DSH）：

```sh
npx dsh-trust-check --dir "$EXTRACTED_DIR" --spec "$INSTALL_SPEC" --json
```

解析 `--json` 时统一读 `plugins[0]`（单目录）或 `plugins` 数组（profile 模式）；`errors` 非空表示目录不可读。

**本期不做**：远程 tarball 下载（拉包是 market 的职责）。独立验证姿势：先把包解到临时目录，再 `--dir`。

## 判定原则

- **代码判定，不是 LLM 打分**：判断全在代码里，不烧 token、结果可复现。
- **只证"有"，不证"无"**：静态分析只下"检测到了某能力"的结论，从不说"保证没有某能力"。
- **证据可复核**：每个能力命中都带 `文件:行号` 和原文片段。
- **seam 表可热更**：能力判定规则是一张数据表（`src/core/seams.ts`），DSH 接口变了改表不改引擎。

## 已知局限

- **装后体检**：profile 模式审计的是**已经安装**的插件；install/postinstall/prepare 在你第一次扫描前就可能已经跑过。`--dir` 模式可在安装前对解压目录扫描（但安装脚本本身仍可能在 market 解包/安装阶段已执行）。
- 静态扫描有漏判/误判（运行时才加载的能力看不到；动态 `import('node:' + …)`、`eval`、`Function`、第三方 HTTP 库如 `got`/`ws` 等不在规则表内）。
- **不扫 `node_modules`**：依赖里的行为不在审计范围内。
- 客户端 `fetch('/api')` 等同源调用也会记为 network，与真正的出网访问未分层。
- 注入 token 是字节 / 4 的粗估，不是精确计费。
- `link:` / `file:` 本地安装的插件无法从 spec 推断来源，若其 `package.json` 未声明 `repository`，会显示"未声明仓库"。
- `repository` 字段是插件自述，不与 npm 包名交叉验证。

## 开发

```sh
pnpm install
pnpm build       # tsdown：node half → lib/index.js，client half → lib/client.js
pnpm test        # vitest，覆盖 core 引擎
pnpm typecheck   # tsc --noEmit
```

## 路线图

- v1（当前）：已装插件体检 + CLI `--dir` + Web 分项报告
- v2：向 dsh-market 提安装确认 PR（本包已提供 `--dir` / `auditPlugin` 契约）
- v3：作为 Agent CI 的数据层——"插件升级后行为是否漂移"的回归断言

## License

MIT
