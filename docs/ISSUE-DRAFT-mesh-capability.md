# 给 dsh-plugin-mesh 的 issue 草稿：能力事实（代码级）入图

> 交付形态：可直接粘贴到 https://github.com/WTStarMark/dsh-plugin-mesh/issues/new
> 配图/附件：见文末「附件」一节
> 纪律：不下结论、不评价采集口径、只给事实 + 一个选择题

---

## Title

```
[建议] 在图谱上加一维「代码级能力事实」：这个插件实际会碰什么（附实测样例）
```

---

## Body

````markdown
## 背景

图谱现在回答的是「谁和谁有关」（分类、共鸣、star、周更），这一维已经很完整。缺的是另一类问题：

- 这个插件实际会碰什么？（文件 / 网络 / 凭据 / 子进程 / 安装脚本）
- 我脚本里想筛「所有接触凭据且有网络外连的插件」——图谱现在筛不出来。

这类问题需要一个**代码级静态扫描**，README 和 topics 都答不了。

## 实测样例

拿图谱里已有的 `bowenliang123/dsh-context`（`panel/panel-side`）跑一次静态扫描（[dsh-trust-check](https://www.npmjs.com/package/dsh-trust-check)，MIT，无网络、不执行代码、毫秒级）：

```json
{
  "name": "dsh-context",
  "version": "0.66.1",
  "capabilities": ["fs-read", "network", "credentials"],
  "redLines": [],
  "destinations": [
    { "kind": "https-host", "value": "models.dev" },
    { "kind": "https-host", "value": "platform.deepseek.com" },
    { "kind": "https-host", "value": "registry.npmjs.org" }
  ],
  "hasBuildScript": false,
  "pinned": true
}
```

每条能力都带 `文件:行号` 证据，例如：

```
fs-read      lib/index.js:16    import { existsSync, readFileSync } from "node:fs";
credentials  lib/index.js:2219  const credentials = ctx.get("credentials");
network      lib/index.js:2260  const defaultFetcher = (url, init) => fetch(url, init);
```

**这是披露，不是判定。** 上例同时有 credentials 和 network，但按红线规则**没有命中红线**——因为它是通过官方 `ctx.get("credentials")` 取 key 再调 DeepSeek，属于正常调用。扫描器分不出"正常调用"和"外传"，所以它只报事实、不下结论。（同一批样本里 credentials+network 占全部红线的 73.3%，原因就是这条。）

## 为什么觉得可能对你有用

1. **它和现有判据同源。** `tools/categories.mjs` 明确不用模型判定（"模型读一遍就是瞎 token、结果不稳定、无法 diff"）。这个扫描器是同一路子：纯规则表 + 正则，可 diff、可手改、可复现。
2. **成本不在你这边。** 扫描是纯 CPU，无网络、无密钥、无模型调用；事实可以预计算进 `data/`，运行时零开销。
3. **多一个筛选维度。** 例如"只看不碰网络的插件"，比按分类名筛更实在。

## 想请你判断的

**这一维对你有没有用？**

如果有用，我倾向落在**人工策展层**（`tools/ecosystem.json`）而不是全量 28k 节点，因为：

- 那层只有 5 个基座、约 130 条关系，规模小、语料干净；
- 那里已经有 `signals`（`生态签:` / `README搜索:`）这类文本判据，代码事实正好补上"声称"与"实际"之间的差：**某插件 README 声称兼容某基座，但代码里没有任何该基座的 import 或注册**——这类事实你现在判不出来。

如果这一维不值得进图谱，也请直说，我就不占你时间了。

## 如果决定接，我会提供

- 输出契约：`schemaVersion` 版本化，稳定字段（`version` / `capabilities` / `redLines` / `scannedAt` / `tool`）只在一处命名，**换扫描器只改那一处**，你不会被锁定；
- 失败语义：扫不到就是"未检出/未扫描"，**绝不写成"干净"**（absence 不等于 clean）；
- 先例：[awesome-dsh-plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin) 已在目录构建期接同一套输出，适配层是一个文件（`scripts/lib/capabilities.mjs`），我把那份适配当作参考实现附上。

## 附件

- 单包实测 JSON（完整）：<附件 1>
- 扫描器输出契约：https://github.com/liuwenji007/dsh-trust-check/blob/main/docs/audit-schema.md
- 目录侧适配层（第三方已落地的参考实现）：https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/blob/main/scripts/lib/capabilities.mjs
````

---

## 发送前需要补的事

1. ~~核实 `dsh-context` 在图谱里的分类与 star~~ **已核实（2026-10-10）**：
   - GitHub：`bowenliang123/dsh-context`，**1,958 star**，创建 2026-08-14，今天还在推（10-10）；topics 含 `dsh-plugin`、`dsh-plugins`、`deepseek-harness-plugin`
   - 图谱记录：`界面面板 / 侧边面板`，1,955 star（图内缓存低 3 星，正常），`verdict: related`
   - 本地扫描到的 `spec: 0.66.1` 与包内 `repository` 字段均指向该仓库 → **样例与图谱条目是同一条**，指认成立
2. **附件 1**：把完整扫描 JSON 存成文件上传（`dsh-trust-check --dir <解包目录> --json > dsh-context.json`）。若不想上传文件，就把 `capabilities` / `destinations` / 三条 evidence 直接贴进正文（**已贴，可只用正文**）。
3. **可选**：附一张卡片或详情页的 mock，展示能力芯片加在什么位置。有视觉示例通常比文字好审。

## 这个样例为什么选得好（发送前自己心里有数）

- `bowenliang123/dsh-context` 是**图谱里 DSH 原生、高星、且在活跃维护**的插件（1,958 star，今天有推送），不是随便找的小仓库——他一看就知道是谁。
- 它**同时有 credentials + network 但不命中红线**（走官方 `ctx.get("credentials")` 调 DeepSeek）——这恰好一次性说清两件事：能力事实有用，以及为什么它只报事实不下结论。**不需要额外解释"我不会误报你"**。
- 它在你本地装的是 v0.66.1，所以这份数据是你**真的扫过**的，不是拿别人仓库拼的。

## 措辞上刻意做的三件事（别改坏）

1. **只给事实和选择题，不给结论**——结尾是"如果没用也请直说"，把拒绝成本降到一句话。
2. **不评价他的采集口径**，不提 `verdict`/`noise`/榜首污染（那是另一件事，混进来会让这条建议变味）。
3. **不派活给他**：明确说"事实预计算进 `data/`、运行时零开销、换扫描器只改一处"，让"接"的成本看起来是加一个文件而不是加一个依赖链。
