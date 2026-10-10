# dsh-trust-check 升级漂移（version drift）功能规格

> 交付对象：Cursor。本文件是**任务规格**，不是讨论稿。
> 目标版本：0.3.0。前置：`schemaVersion` 当前为 2（`src/core/response.ts` 的 `AUDIT_SCHEMA_VERSION`）。

---

## 0. 一句话

**同一插件的两个版本之间，能力/红线/去向/注入/安装脚本发生了什么变化——只报事实，不下结论，失败绝不静默。**

---

## 1. 先分清：不要和已有的 `capabilityDelta` 混淆

`src/core/present.ts:327` 已经有：

```ts
export function capabilityDelta(report, ack?): { added: Capability[], removed: Capability[] }
```

它比的是 **用户 ack 记录的内容 vs 当前扫描**，服务于「设置页插件体检」的提醒。**它不是版本间差分**，不要改它、不要复用它当 baseline。

本功能比的是 **`AuditReport`(baseline) vs `AuditReport`(current)**，两个不同的版本。

---

## 2. 必须遵守的既有契约（不要重新发明）

现有纪律（见 `docs/POSITIONING.md`、`docs/audit-schema.md`），新代码必须延续：

1. **只报事实，不报结论。** 不出现 `safe` / `trusted` / `verified` / `risky`。差分的输出里**不能有 score、band、verdict**——现有契约已明确 `score`/`band` 是内部排序用，集成方不得据此过滤。
2. **三态，不许压成两态。** 「未扫描」（`undefined`）与「扫描过、没检出」（`[]`）是两句不同的话。差分里任何一侧不可扫描时，**绝不允许写 `added: []`**，必须走 `unavailable` + 原因。
3. **每条结论都要有 `文件:行号` 证据。**
4. **稳定 id，不用句子。** 沿用 `seams.ts` 里 `CapabilityRule.id` 的风格（如 `shell.import-or-call`）；红线用 `classifyRedLine()` 的稳定 code（`install-script` / `core-tamper` / `creds-network` / `plaintext-http` / `literal-ip`）。
5. **引擎保持纯函数**：不联网、不下载 tarball、不展开依赖树（这是 `POSITIONING.md` 划定的边界）。baseline 由调用方提供。
6. **检测规则改动不 bump `schemaVersion`；输出形状变更才 bump。** 差分是**独立契约**，用独立的 `DRIFT_SCHEMA_VERSION`，不要和 `AUDIT_SCHEMA_VERSION` 混。

---

## 3. 最容易被做错的三点（先读这节再动手）

### 3.1 不可比：`tool` 不同 → 不许报警

如果两次扫描的 `tool`（形如 `dsh-trust-check@0.1.13`）不同，**检测规则可能变了，同一个版本也会报出漂移**。这是最危险的假阳性：每升级一次扫描器，全目录都变「新增了能力」。

- 必须记录并比较两边的 `tool`（目录侧适配层读的稳定字段之一就是 `tool`）。
- 两边 `tool` 不同时：`comparable: 'stale-baseline'`，`reasons` 写明两个版本号。
- **默认不因不可比而阻断**，但要显式标出，让集成方自己决定。

### 3.2 证据位置不算变化

同一份能力，文件重命名、行号挪了、snippet 变了 —— **这不是「能力变化」**，是重构。必须按**存在性与稳定 id** 比较，不能按 file/line 比较。否则每次 refactor 都会报漂移，这个功能就废了。

### 3.3 单侧不可用 ≠ 无变化

baseline 缺失/解析失败/baseline 里没有这个插件 → `unavailable`，不得降级成空差分。这与目录侧「失败降级留空、绝不写成干净」是同一条纪律，方向相反地必须成立。

---

## 4. 数据模型的实地约束

`AuditReport`（`src/core/types.ts`）里可用于差分的维度，以及比较键：

| 维度 | 类型 | 比较键 | 什么算变化 |
|---|---|---|---|
| `capabilities` | `Capability[]`（字符串联合，10 个固定值） | 值本身 | 进入/离开集合 |
| `redLines` | `string[]`（固定模板句） | `classifyRedLine()` 的 code | code 进入/离开集合 |
| `destinations` | `DestinationFinding[]` | `kind` + `value`（**不是** file/line） | 新出现/消失的主机或 IP |
| `secretTouches` | `SecretTouchFinding[]` | `kind` + `value` | 新出现/消失 |
| `pathEscapes` | `PathEscapeFinding[]` | `value` | 新出现/消失 |
| `injections` | `InjectionFinding[]` | `kind` + `detail`（`path` 参与，`bytes` 只做显示） | 新注入/移除注入 |
| `hasBuildScript` / `buildScripts` | `boolean` / `string[]` | 脚本名集合 | 新增安装脚本 |
| `pinned` | `boolean` | 值 | `true` → `false` 是**重要**变化（锁版本丢了） |
| `facts` | `Fact[]`（schema 2 起） | `id` + `value` | 新增/消失的事实 |

**注意**：`AuditReport` 目前**不带 `tool` 字段**。实现时必须把扫描器的 `tool` 标签带进 baseline 记录（目录侧 `probe-capabilities.mjs` 已经写 `tool: dsh-trust-check@<version>`），并保留给差分读取。

---

## 5. 输出形状（这是主要交付物，先定形状再写实现）

新增文件：`src/core/drift.ts`。新增独立 schema：`src/core/drift-schema.ts` 导出 `DRIFT_SCHEMA_VERSION = 1`。

```ts
/** 对齐目录侧适配层的稳定字段形状（见 awesome-dsh-plugin/scripts/lib/capabilities.mjs）。 */
export interface DriftRecord {
  name: string
  version: string
  spec: string
  capabilities: string[]
  redLines: string[]
  /** 扫描器标签，如 `dsh-trust-check@0.1.13`。用于可比性判断。 */
  tool: string
  scannedAt: string
}

export type DriftSeverity = 'new-red-line' | 'new-risk' | 'note'

export interface DriftItem {
  /** 稳定 id，沿用规则表风格：`capability.shell`、`redline.creds-network`、
   *  `dest.https-host:api.example.com`、`injection.system-prompt`。 */
  id: string
  severity: DriftSeverity
  kind: 'capability' | 'red-line' | 'destination' | 'secret-touch' | 'path-escape'
      | 'injection' | 'install-script' | 'pinning' | 'fact'
  /** 'added' | 'removed' | 'changed'；`changed` 仅用于 pinning / 已有条目的值变化。 */
  change: 'added' | 'removed' | 'changed'
  /** 一句话英文事实，措辞同样属于契约（集成方原样渲染 + 翻译）。 */
  text: string
  /** current 侧证据；`change: 'removed'` 时取 baseline 侧。 */
  evidence?: Array<{ file: string; line: number; snippet?: string }>
  /** 仅 changed：两侧的值。 */
  from?: string
  to?: string
}

export interface DriftDiff {
  schemaVersion: number
  name: string
  from: { version: string; tool: string; scannedAt: string }
  to: { version: string; tool: string; scannedAt: string }
  /** 'ok' | 'same' | 'stale-baseline' | 'unavailable'。 */
  comparable: 'ok' | 'same' | 'stale-baseline' | 'unavailable'
  /** comparable !== 'ok' 时必须非空，说明原因（含两侧 tool 版本）。 */
  reasons: string[]
  items: DriftItem[]
  /** 与 items 一致的计数，方便集成方不遍历就判断。 */
  counts: { 'new-red-line': number; 'new-risk': number; note: number }
}
```

### 5.1 措辞契约（和 `capabilities`/`redLines` 一样，是契约不是自由文本）

固定模板，`<…>` 从包里填：

| id | change | text 模板 |
|---|---|---|
| `redline.<code>` | added | `new red line: <原句>` |
| `redline.<code>` | removed | `red line no longer detected: <原句>` |
| `capability.<value>` | added | `now runs system commands` 等，**复用 audit-schema 的英文措辞表** |
| `capability.<value>` | removed | `no longer runs system commands` |
| `dest.<kind>:<value>` | added | `new network destination: <value>` |
| `injection.<kind>` | added | `new injection into <kind>: <detail>` |
| `install-script` | added | `now runs code at install time (<scripts>)` |
| `pinning` | changed | `install spec is no longer pinned (<spec>)` |
| 其余维度 | added/removed | `<kind> added: <value>` / `<kind> removed: <value>` |

加一条硬约束：**新增红线时必须带原句**，因为红线是集成方可能据此阻断的唯一东西。

---

## 6. 门禁语义（三态 + 退出码）

`verdict` 的现有语义（`docs/audit-schema.md`）已经定义了 `red` / `review` / `clear`。差分沿用同一套严重度，**不要新造一套**：

| 情形 | 映射 | 建议 gate |
|---|---|---|
| 无 items（`comparable: 'same'` 或 `items` 为空） | clear | 通过 |
| 只有 `note`（去向/注入/facts 变化） | review | 提示，不阻断 |
| 有 `new-risk`（新增能力、新注入、新增安装脚本、锁版本丢失） | review | 提示 + 需确认 |
| 有 `new-red-line` | red | **默认阻断**，允许确认继续 |
| 任一侧 `unavailable` | 扫描失败 | **阻断**（fail closed），不得当作 clear |

### 6.1 退出码

沿用现有 `--exit-code` 语义，不发明新的：

```
0  same / 无新增        1  有新增（note / new-risk）      2  有新红线      3  不可用（扫描失败）
```

与 `--dir` 模式现有约定一致（`0` 未检出 / `1` 需确认 / `2` 有红线 / `3` 扫描失败）。**默认仍为 0 退出**，只有加 `--exit-code` 才生效——不要让升级漂移在别人 CI 里突然开始失败。

### 6.2 默认策略必须是「只看新增的红线」

理由：升级漂移的价值在**罕见、可行动**的信号。95% 的插件本来就带特权能力（`POSITIONING.md` 实测），如果默认把「新增 shell」也当阻断，用户会养成无脑确认的习惯——这正是现有文档要避免的。所以：

- 默认 gate = 只对 `new-red-line` 阻断；
- `--include-notes` 才把 `note` 级也计入退出码；
- 这个默认值要写进 CHANGELOG 和 `docs/INTEGRATION.md`。

---

## 7. API 与 CLI

### 7.1 新增导出（`src/index.ts`）

```ts
export { diffRecords } from './core/drift.ts'
export { DRIFT_SCHEMA_VERSION } from './core/drift-schema.ts'
export type { DriftRecord, DriftItem, DriftDiff, DriftSeverity } from './core/drift.ts'
```

签名保持纯函数：

```ts
export function diffRecords(
  baseline: DriftRecord,
  current: DriftRecord,
): DriftDiff
```

如果需要 `AuditReport` → `DriftRecord` 的适配，另加一个薄函数 `toDriftRecord(report, tool, scannedAt)`，**不要让 `diffRecords` 依赖 filesystem**。

### 7.2 CLI

在 `bin/trust-check.mjs` 增加：

```
dsh-trust-check --diff --baseline <file.json> --dir <package-dir> [--json] [--exit-code]
dsh-trust-check --diff --baseline <file.json> --profile <name> [--json] [--exit-code]
```

- `--baseline`：一个 JSON 文件，内容为 `DriftRecord` 或 `DriftRecord` 数组（数组按 `name` + `spec` 匹配；找不到匹配项 → 该插件 `unavailable`）。
- `--diff` 与 `--json` 组合时输出 `{ schemaVersion: DRIFT_SCHEMA_VERSION, diffs: DriftDiff[], errors: [...] }`。
- `--baseline` 缺省或缺文件 → 报错退出 3，**不要静默当成无 baseline**。
- 更新 `--help` 文本。

### 7.3 与目录侧（awesome-dsh-plugin）的对接方式

**不要**要求目录改数据模型。目录现有记录已经是 per-version 覆盖式的，正确做法是：

> 目录在 `shouldRescan` 判定「插件版本变了」时，**保留旧记录**，把 `(旧记录, 新记录)` 一起交给 `diffRecords`。

也就是说 baseline 由调用方持有，我们只做纯比较。这一点写进 `docs/INTEGRATION.md` 的新章节。

---

## 8. 测试清单（每条都是必须的，含反例）

放在 `tests/core/drift.spec.ts`。**反例和正例同等重要**：

1. 同一插件、能力集合不变、**证据行号全变** → `items` 为空（这是 3.2 的回归测试）。
2. `credentials` + `network` 同时新增 → 产生 `redline.creds-network` 的 `new-red-line`，且 `text` 含原句。
3. 红线消失（v2 不再读凭据） → `removed`，severity 为 `note`，不能是 `new-risk`。
4. 新增 `destinations` 里同主机不同行号 → **不产生 item**；新增主机 → 产生 `dest.*` 的 `note`。
5. baseline `tool` = `dsh-trust-check@0.1.13`，current `tool` = `0.2.0` → `comparable: 'stale-baseline'`，`reasons` 含两个版本号，**且默认 gate 不因此阻断**。
6. baseline 缺失 / 该插件不在 baseline 里 → `comparable: 'unavailable'`，`items` 为空数组，退出码 3；**断言不得出现「无变化」的文案**。
7. `pinned: true → false` → `kind: 'pinning'`, `change: 'changed'`, severity `new-risk`。
8. 新增 `postinstall` → `kind: 'install-script'`, severity `new-risk`，`text` 含脚本名。
9. `facts[]`（schema 2）新增一个 id → `note`，且**不重复报**对应 capability（避免同一件事报两遍；若无法避免，在规格评审时明确）。
10. 幂等：`diffRecords(a, a)` → `comparable: 'same'`, `items: []`。
11. monorepo 子目录条目（目录侧 `subdirOf` 场景）→ 比较的是子包事实，不是仓库根。
12. 未知 capability 值（未来新增）→ 不报错，按原值进 `items`（对齐「未知值按原文展示」的既有纪律）。

---

## 9. 明确的非目标（不要做）

- ❌ 不下载 tarball、不查 registry、不比对 npm 上的历史版本（调用方提供 baseline）。
- ❌ 不产出新评分、新百分比、新等级。`score`/`band` 不参与、不出现。
- ❌ 不写「安全 / 危险 / 已验证」；不改写 `AuditReport` 现有字段语义。
- ❌ 不改 `capabilities` 取值表或 `redLines` 模板措辞（那是 `schemaVersion` 级别的事）。
- ❌ 不在 `--dir` 单次扫描时自动去找「上一版」——没有这种自动发现。
- ❌ 不做人工审阅、不做黑名单白名单（属策略层/背书层）。

---

## 10. 交付物清单

1. `src/core/drift.ts`（纯函数）+ `src/core/drift-schema.ts`（`DRIFT_SCHEMA_VERSION`）
2. `bin/trust-check.mjs` 的 `--diff` / `--baseline` 支持 + `--help` 更新
3. `src/index.ts` 导出
4. `tests/core/drift.spec.ts`（第 8 节 12 条）
5. `docs/drift-schema.md`（对外契约：字段、措辞模板、三态、退出码、可比性规则）
6. `docs/INTEGRATION.md` 新增一节：目录侧如何保留旧记录并提供 baseline
7. `CHANGELOG.md`：`0.3.0` 段落，**首行必须是 `Affects catalog results: None`**（本功能只新增输出，不改既有检测结果；若实际影响了既有字段，必须如实改这一行——目录的 bump 规则依赖它）
8. `README.md`：路线图里把「版本间升级漂移对比」从「接下来」移入已交付，并补一句 CLI 用法

---

## 11. 给 Cursor 的执行顺序

先做 5（契约文档），再做 1（纯函数），再做 8（测试），最后接 2/3（CLI 与导出）、6/7/8（集成文档与 CHANGELOG）。**形状没定死之前不要写 CLI**，否则改的是两个地方。

---

## 12. 待你决定的两点（做之前确认）

1. **`facts[]` 与 `capabilities` 重叠时是否去重**（测试第 9 条）。我倾向去重，但需要你定，因为它影响输出条数。
2. **`--include-notes` 这个开关要不要**（第 6.2 节）。如果不要，就把 `note` 级永远排除在退出码之外，只留给展示。
