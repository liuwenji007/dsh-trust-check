# dsh-trust-check

[English](README.en.md)

DeepSeek Harness 插件「装前体检」：静态审计已装插件的能力面、注入面、成本、来源与更新风险，输出一个**代码判定、可复现、零 token** 的 0–100 信任分。

> 不是"杀毒软件"，也不做安全承诺。它只做能证明的事：把插件**真实会碰什么、注入了什么、来源可不可信**摊开给你看，结论每一条都附证据（文件 + 行号 + 片段），你可以自己复核。

## 安装

```sh
dsh plugin --profile web add dsh-trust-check
```

重启 `dsh web`，打开 **设置 → 插件体检**。同时提供独立 CLI，不依赖 DSH 宿主：

```sh
npx dsh-trust-check                 # 审计默认 profile `web`
npx dsh-trust-check --profile work  # 审计其他 profile
npx dsh-trust-check --json          # 机器可读输出
```

## 审计什么

| 维度 | 读什么 | 判定 |
|---|---|---|
| **能力面** | `package.json` 的依赖 scope + 静态扫 `lib/*.js` | shell / 文件读写 / 网络 / 凭据 / 子代理 / LLM 调用 / 环境变量 |
| **注入面** | `cordis.patch.yml` + 源码里的 `systemPrompt` 注册 + 技能文本 | override / disable 了谁、注入了什么 |
| **成本** | 技能/指令文本字节数 | 估算每请求注入 token（字节 / 4，仅估算） |
| **来源** | `package.json` 的 `repository`（缺失回退到 git 安装源）+ 安装 spec | 是否锁版本/锁 commit |
| **更新风险** | 安装脚本（install/postinstall/preinstall） | 是否在安装时执行任意代码 |

## 信任分

```
信任分 = 100 − 能力加权 − 注入成本 − 来源风险 − 更新风险
```

- **≥ 80 绿**：纯 UI / 只读 / 来源可信。
- **50–79 黄**：有权限或注入，列出"具体要什么"。
- **< 50 红**：命中红线或高风险。

红线（直接判红）：

1. 声明 install/postinstall/preinstall 安装脚本；
2. `cordis.patch.yml` override / disable 了 `@deepseek-ai/*` 核心 bundle；
3. 读取凭据/密钥材料（keychain / keytar / dotenv / `~/.ssh` / `.aws/credentials` 等）**且**有网络访问。

## 判定原则

- **代码判定，不是 LLM 打分**：判断全在代码里，不烧 token、结果可复现。
- **只证"有"，不证"无"**：静态分析只下"检测到了某能力"的结论，从不说"保证没有某能力"。
- **证据可复核**：每个能力命中都带 `文件:行号` 和原文片段；分数有异议，看证据就能定位。
- **seam 表可热更**：能力判定规则是一张数据表（`src/core/seams.ts`），DSH 接口变了改表不改引擎。

## 已知局限

- 静态扫描有漏判/误判（运行时才加载的能力看不到；字符串里恰好出现规则词）。已用"精确 pattern + 注释剥离 + 只证有"尽量压低误报，但请把结果当"体检参考"而非"裁决"。
- 注入 token 是字节 / 4 的粗估，不是精确计费。
- `link:` / `file:` 本地安装的插件无法从 spec 推断来源，若其 `package.json` 未声明 `repository`，会显示"未声明仓库"。

## 开发

```sh
pnpm install
pnpm build       # tsdown：node half → lib/index.js，client half → lib/client.js
pnpm test        # vitest，覆盖 core 引擎
pnpm typecheck   # tsc --noEmit
```

## 路线图

- v1（当前）：已装插件体检 + CLI + Web 报告视图
- v1.1：审计任意目标（`npm:xxx` / `github:owner/repo`，下载 tarball 扫描）
- v2：向 dsh-market 提议安装确认弹窗集成（安装前展示审计摘要）
- v3：作为 Agent CI 的数据层——"插件升级后行为是否漂移"的回归断言

## License

MIT
