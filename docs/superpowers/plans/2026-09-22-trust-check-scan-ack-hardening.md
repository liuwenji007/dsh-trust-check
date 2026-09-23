# dsh-trust-check 扫描完整性 → 风险判定 → 信任确认 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **修订：** 本稿取代原稿里互相冲突的写法。按下面「锁死的决定」实现，不要回到「所有相对入口都抛错」「coverage 改 verdict」「从展示列表重算指纹」「`node:crypto` 放进 `injection.ts`」。

**Goal:** 扫描不完整时进入 `errors`，不得产出 `clear`；包内静态依赖补进扫描并标明覆盖限制；每个 `fetch` 按字面量规则判外连；红线和确认摘要用全量结果，展示列表事后截断；技能指纹含内容哈希；确认绑定用户看到的报告摘要。

**Architecture:** `collectPlugin` 对资源超限和主入口失败抛错，由 `runAudit` / CLI 写入 `errors`。相对 import 只在包内展开。`auditPlugin` 先用全量 shape 算红线，再按种类轮转截断展示。确认摘要是全量向量的 SHA-256，由宿主写入 `report.ackFingerprint`；浏览器原样回传。指纹不一致先返回 409。

**Tech Stack:** TypeScript、vitest、现有 `src/core/*` + `src/fs.ts` + host routes。SHA-256 只出现在宿主模块。

**Phases:** Tasks 1–6 是前四项，做完即可用于装前拦截。Tasks 7–9 是后两项，决定确认是否可靠。

---

## 锁死的决定

| 主题 | 决定 |
|---|---|
| 硬失败 | 单文件超限、文件数超限、总字节超限、主入口缺失或不可读、profile 目录不存在、profile `package.json` 缺失或损坏、已声明插件目录缺失。抛错后进入 `errors`，不产生该插件的 `clear`。 |
| 主入口 | 只含 `main`、`exports` 为字符串或 `exports['.']` 的代码条件（`import` / `default` / `require` / `node`，不含 `types`）、以及 `bin` 的每个目标。其它 `exports` 子路径缺失只记 `coverageNotes`。 |
| 资源限制 | 数值不变：单文件 512 KiB、文件数 4000、总量 8 MiB。先 `stat.size` 再 `readFile`。测试通过 `collectPlugin(dir, spec, { limits })` 注入小上限。 |
| 覆盖说明 | 无法解析的相对目标、动态 `import()` / `require()`、指向 `node_modules` 的相对路径，写入 `coverageNotes`。**不改变** `verdict`。 |
| `fetch` | 同一行任一调用可能外连即记 `network`。同源只认完整相对路径字面量：`'` `"` 以及**不含** `${` 的 `` ` ``，且闭合引号后不能是 `+`。`,` 开始下一个参数，仍可同源。变量、拼接、带插值的模板都是外连。 |
| 风险与展示 | `scoreTrust` 和确认摘要使用截断前的全量结果。展示列表仍遵守现有条数上限，按种类轮转保留；`read` 在轮转顺序中排第一，但不能占满名额。 |
| 确认摘要 | 一个字段：`AuditReport.ackFingerprint: string`。材料是全量、已排序的 capabilities / destinations / secretTouches / pathEscapes / injections / redLines 的 JSON，再 SHA-256。不把全量列表放进响应或 `trust-ack.json`。 |
| 技能指纹 | 技能项 token 为 `skill:<path>:<sha256>`。`bytes` 只用于展示。没有 `digest` 的旧确认不匹配。 |
| 哈希位置 | `src/host/content-hash.ts` 提供 SHA-256。`injection.ts` 与 `ack-fingerprint.ts` 不 import `node:crypto`。 |
| 确认顺序 | 先比较客户端提交的摘要和重新扫描的 `ackFingerprint`。不同 → 409，响应带新报告，不写盘。相同后才检查 `acceptRisk`。 |
| CLI | profile 模式调用 `runAudit`，不再自己 `continue` 掉缺失目录。 |

---

## File map

| File | Responsibility |
|---|---|
| `src/fs.ts` | 限制、主入口失败、包内静态依赖、`coverageNotes` |
| `src/host/content-hash.ts` | 宿主 SHA-256 |
| `src/core/types.ts` | `coverageNotes`、`ackFingerprint`、`TrustAckEntry.digest` |
| `src/core/capability.ts` | 逐个 `fetch` 判定 |
| `src/core/shape.ts` | 全量结果；展示用按种类轮转 |
| `src/core/audit.ts` | 先评分再截断；写 `ackFingerprint` |
| `src/core/injection.ts` | 技能 `contentHash` 与 `skill:path:hash` token；无 crypto |
| `src/core/ack-fingerprint.ts` | 只比较 `digest` 与 `ackFingerprint` |
| `src/index.ts` | profile / 配置 / 缺失目录错误；ack 409 |
| `bin/trust-check.mjs` | profile 模式改走 `runAudit` |
| `src/client/TrustReport.tsx` + `locales.ts` | 原样提交摘要；409 提示指定文案 |
| `tests/core/*.spec.ts` | 断言最终 `verdict` 或 `errors`，不只断言内部函数 |

---

### Task 1: 扫描不完整时进入 errors

**Files:**
- Modify: `src/fs.ts`
- Modify: `tests/core/fs.spec.ts`

- [ ] **Step 1: Write the failing tests**

```ts
it('throws before reading when a file exceeds the size limit', () => {
  const root = mkdtempSync(join(tmpdir(), 'trust-fs-huge-'))
  try {
    mkdirSync(join(root, 'lib'))
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'huge', version: '1', main: './lib/big.js' }))
    writeFileSync(join(root, 'lib', 'big.js'), 'x'.repeat(64))
    expect(() => collectPlugin(root, 'npm:huge@1', {
      limits: { maxFileBytes: 32, maxFiles: 100, maxTotalBytes: 10_000 },
    })).toThrow(/file too large/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

it('throws when the file count limit is exceeded', () => {
  // 三个可扫描 js，limits.maxFiles = 2 → /scan aborted: more than 2 files/
})

it('throws when the total size limit is exceeded', () => {
  // 两个小文件，limits.maxTotalBytes 小于两者之和 → /total size exceeds/
})

it('throws when a primary entry is missing', () => {
  // package.json main: './missing.js'，目录里另有 lib/ok.js
  // throw /primary entry unreadable or missing: \.\/missing\.js/
})

it('does not throw when an optional export subpath is missing', () => {
  // main 指向存在的 lib/index.js；exports['./client'] = './missing-client.js'
  // collect 成功，coverageNotes 提到 missing-client.js
  // verdict(auditPlugin(collected)) === 'clear'
})
```

把现有 `skips patch files larger than MAX_FILE_BYTES` 改成抛 `file too large`。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/fs.spec.ts`

- [ ] **Step 3: Implement**

导出默认限制，并允许测试覆盖：

```ts
export const SCAN_LIMITS = {
  maxFileBytes: 512 * 1024,
  maxFiles: 4000,
  maxTotalBytes: 8 * 1024 * 1024,
} as const

export interface CollectOptions {
  limits?: { maxFileBytes: number; maxFiles: number; maxTotalBytes: number }
}

export function collectPlugin(dir: string, spec: string, options?: CollectOptions): PluginInput
```

`readScannedFile`：预算已满则抛 `scan aborted: more than N files` 或 `scan aborted: total size exceeds N bytes`。对目标 `lstat`，`stat.size > maxFileBytes` 则抛 `file too large: <rel> (<size> bytes)`，此时还没有 `readFile`。`readFile` 失败抛 `unreadable: <rel>`。

主入口收集：

```ts
function codeTargets(value: unknown, out: Set<string>): void {
  if (typeof value === 'string') {
    out.add(value)
    return
  }
  if (typeof value === 'object' && value !== null) {
    const obj = value as Record<string, unknown>
    for (const key of ['import', 'default', 'require', 'node']) {
      if (typeof obj[key] === 'string') out.add(obj[key] as string)
    }
  }
}

export function primaryEntryPaths(manifest: Record<string, unknown>): string[] {
  const paths = new Set<string>()
  if (typeof manifest.main === 'string') paths.add(manifest.main)
  const bin = manifest.bin
  if (typeof bin === 'string') paths.add(bin)
  else if (typeof bin === 'object' && bin !== null && !Array.isArray(bin)) {
    for (const value of Object.values(bin as Record<string, unknown>)) {
      if (typeof value === 'string') paths.add(value)
    }
  }
  const exports = manifest.exports
  if (typeof exports === 'string') paths.add(exports)
  else if (typeof exports === 'object' && exports !== null && !Array.isArray(exports)) {
    codeTargets((exports as Record<string, unknown>)['.'], paths)
  }
  return [...paths]
}
```

主入口在包内但文件不存在或不可读：抛 `primary entry unreadable or missing: <raw>`。包外路径维持现有拒绝，不读。可选子路径找不到：`coverageNotes.push('optional export not found: <raw>')`。

超限和主入口失败都不要吞掉。`collectPlugin` 抛出的错误由调用方放进 `errors`。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/fs.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/fs.ts tests/core/fs.spec.ts
git commit -m "$(cat <<'EOF'
fix: fail closed when a plugin scan exceeds its limits

Primary entry and size failures become errors instead of a clear report.
EOF
)"
```

---

### Task 2: Profile、配置、已声明目录分别报错

**Files:**
- Modify: `src/fs.ts`
- Modify: `src/index.ts`
- Modify: `bin/trust-check.mjs`
- Create: `tests/core/run-audit.spec.ts`

- [ ] **Step 1: Write the failing tests**

三条 `runAudit` 用例，临时目录通过 `DSH_HOME` 隔离，并在 `finally` 恢复环境变量：

- profile 目录不存在 → `errors` 含 `profile directory does not exist`，`plugins` 为空
- `package.json` 内容为 `{not-json` → `profile package.json corrupt`
- `package.json` 不存在 → `profile package.json missing`（与损坏不是同一句）
- `dependencies` 声明了 `missing-plugin` 但没有对应目录 → `errors` 为 `[{ name: 'missing-plugin', ... }]`，消息含 `declared plugin directory missing`，`plugins` 为空

不要让测试依赖开发机上的 `~/.dsh`。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/run-audit.spec.ts`

- [ ] **Step 3: Implement**

`readInstalled` 按上面四句原文抛错，不再在 catch 里返回 `{}`。`runAudit` 捕获 profile 级错误，放进 `errors` 后返回空 `plugins`。插件目录不存在时 push 该插件的 error 并 `continue`，不调用 `collectPlugin`。`collectPlugin` 的抛错仍然变成该插件的 error。

`bin/trust-check.mjs` 的 profile 分支删除自己的循环，改为 `runAudit(args.profile)`。`--dir` 保持现有 try/catch，把 `collectPlugin` 的抛错放进 `errors`。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/run-audit.spec.ts tests/core/fs.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/fs.ts src/index.ts bin/trust-check.mjs tests/core/run-audit.spec.ts
git commit -m "$(cat <<'EOF'
fix: report missing profiles, corrupt config, and absent plugin dirs

Profile scans use one path so a missing install cannot disappear into clear.
EOF
)"
```

---

### Task 3: 从已扫描文件递归解析包内静态依赖

**Files:**
- Modify: `src/fs.ts`
- Modify: `src/core/types.ts`
- Modify: `tests/core/fs.spec.ts`

- [ ] **Step 1: Write the failing tests**

```ts
it('follows a static import into runtime/ and reviews shell', () => {
  // lib/index.js imports ../runtime/payload.js，payload 调用 execSync
  // sources 含 lib/index.js 与 runtime/payload.js
  // verdict(report) === 'review'
})

it('notes an unresolvable relative target without leaving clear', () => {
  // import './nope.js'，没有其它能力
  // coverageNotes 提到 nope.js
  // verdict(report) === 'clear'
})

it('notes a dynamic import without executing a verdict change', () => {
  // import(rel) 与 require(name)
  // coverageNotes 提到 dynamic import 或 dynamic require
  // verdict(report) === 'clear'
})

it('does not read a relative import outside the package', () => {
  // import '../../outside.js'，outside.js 含 execSync
  // sources 不含该文件，capabilities 不含 shell
})

it('does not expand a relative import inside node_modules', () => {
  // import '../node_modules/hidden/payload.js'
  // 不读取 payload，coverageNotes 提到 node_modules
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/fs.spec.ts -t 'runtime/|unresolvable|dynamic import|outside|node_modules'`

- [ ] **Step 3: Implement**

`PluginInput` 与 `AuditReport` 增加 `coverageNotes: string[]`。

在 `stripComments` 之后的文本上提取说明符。静态相对目标：

```ts
const STATIC_RELATIVE = /(?:(?:import|export)\s+(?:[^'"\n]+?\s+from\s+)?|import\s*\(\s*|require\s*\(\s*)['"](\.[^'"]+)['"]/g
const DYNAMIC_TARGET = /(?:^|[^\w$])(?:import|require)\s*\(\s*(?!['"])/g
```

`import(rel)` 命中 `DYNAMIC_TARGET` 时追加 `dynamic import target in <rel>`。`require(name)` 同样。每个文件每种动态调用记一条即可。

解析候选：原路径、`.js` `.mjs` `.cjs` `.ts` `.mts` `.cts` `.jsx` `.tsx`、`index.js`、`index.ts`。用 `resolve` 后的真实路径做 `seen`。`relative` 逃出包目录则不读，记 `import escapes package from <file>: <spec>`。路径分段含 `node_modules` 则不读，记 `dependency import not expanded from <file>: <spec>`。候选都不存在则记 `unresolvable runtime target from <file>: <spec>`。

找到包内文件后走 `readScannedFile`（因此超限仍会整包失败），再入队。`seen` 在出队时判断，重复边直接跳过。

种子是目录扫描和 manifest 已经读入的代码文件。`coverageNotes` 最多保留 20 条，超出时最后一条为 `N additional coverage limits omitted`。

`auditPlugin` 把 notes 抄进报告。`verdict` 不读取 `coverageNotes`。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/fs.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/fs.ts src/core/types.ts src/core/audit.ts tests/core/fs.spec.ts
git commit -m "$(cat <<'EOF'
feat: follow in-package static imports during trust scans

Unresolved and dynamic targets are disclosed without changing the verdict.
EOF
)"
```

---

### Task 4: 检查每一个 fetch

**Files:**
- Modify: `src/core/capability.ts`
- Modify: `tests/core/capability.spec.ts`

- [ ] **Step 1: Write the failing tests**

```ts
it('reviews a line when any fetch may egress', () => {
  const source = 'await Promise.all([fetch("/api/ok"), fetch("https://evil.test/x")])\n'
  expect(verdict(auditPlugin(input({ 'lib/index.js': source })))).toBe('review')
})

it('reviews variable, concatenation, and interpolated templates', () => {
  const source = [
    'await fetch(url)',
    'await fetch("/api/" + id)',
    'await fetch(`/api/${id}`)',
  ].join('\n')
  expect(verdict(auditPlugin(input({ 'lib/index.js': source })))).toBe('review')
})

it('stays clear for complete relative literals, including a static template and extra args', () => {
  const source = [
    'await fetch("/api/ok")',
    'await fetch("./x.json")',
    'await fetch("../up.json")',
    'await fetch(`/api/ok`)',
    'await fetch("/api/ok", { method: "GET" })',
  ].join('\n')
  expect(verdict(auditPlugin(input({ 'lib/index.js': source })))).toBe('clear')
})
```

`input()` 需要带上 `auditPlugin` 所需字段，并给出无能力时能得到 `clear` 的 manifest（有 `name`、`version`、`repository`，spec 保持 pinned）。现有 capability 用例如果只断言 `scanCapabilities`，保留；新增用例必须走 `verdict`。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/capability.spec.ts -t 'any fetch|interpolated|complete relative'`

- [ ] **Step 3: Implement**

```ts
function isCompleteRelativeLiteral(arg: string): boolean {
  if (arg.includes('${')) return false
  return arg.startsWith('/') || arg.startsWith('./') || arg.startsWith('../')
}

function lineHasOutboundFetch(line: string): boolean {
  const re = /(?:^|[^\w$])fetch\s*\(\s*(['"`])?/g
  let match: RegExpExecArray | null
  while ((match = re.exec(line)) !== null) {
    const quote = match[1]
    if (quote === undefined) return true
    const start = match.index + match[0].length
    const rest = line.slice(start)
    const end = rest.indexOf(quote)
    if (end === -1) return true
    re.lastIndex = start + end + 1
    const arg = rest.slice(0, end)
    if (/^\s*\+/.test(rest.slice(end + 1))) return true
    if (/^https?:\/\//i.test(arg) || arg.startsWith('//')) return true
    if (isCompleteRelativeLiteral(arg)) continue
    return true
  }
  return false
}
```

一行最多记一条 `network` evidence。不要把 `,` 当成拼接。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/capability.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/core/capability.ts tests/core/capability.spec.ts
git commit -m "$(cat <<'EOF'
fix: classify every fetch call on a line

Only complete relative path literals stay same-origin.
EOF
)"
```

---

### Task 5: 先判定风险，再按种类截断展示

**Files:**
- Modify: `src/core/shape.ts`
- Modify: `src/core/audit.ts`
- Modify: `tests/core/shape.spec.ts`
- Modify: `tests/core/audit.spec.ts`

- [ ] **Step 1: Write the failing tests**

用源码而不是直接调用 `scoreTrust`：

```ts
it('stays red when credential reads sit past the display cap', () => {
  const pads = Array.from({ length: 25 }, (_, i) => `readFileSync('/tmp/pad-${i}')`).join('\n')
  const source = `${pads}\ncredentials.resolve('K')\nfetch('https://evil.test/x')\n`
  const report = auditPlugin(input({ 'lib/index.js': source }))
  expect(report.redLines).toContain('reads credentials/secrets AND has network access')
  expect(verdict(report)).toBe('red')
  expect(report.secretTouches.length).toBeLessThanOrEqual(20)
  expect(report.secretTouches.some(item => item.kind === 'read')).toBe(true)
  expect(report.secretTouches.some(item => item.kind !== 'read')).toBe(true)
})
```

垫片必须是会被收进 `secretTouches` 的非 `read` 种类；如果 `readFileSync('/tmp/...')` 不是 path touch，改成该扫描器已经承认的 path 字面量，并保持 25 条不同的值。断言同时要求展示列表里还有非 `read` 行。

evidence 用 30 条 `fs-read`、30 条 `llm`、1 条 `shell` 的真实源码走 `auditPlugin`。`report.evidence` 长度不超过 `MAX_EVIDENCE`，且三种 capability 各至少一条。`report.capabilities` 仍包含三者。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/audit.spec.ts -t 'display cap|three capabilities'`

- [ ] **Step 3: Implement**

`scanShape` 返回未截断数组。新增 `presentShapeFindings`：对 destinations、pathEscapes、secretTouches 各自按种类轮转，上限仍是 20。secret touch 的轮转顺序是 `read`、`path`、`env-key`、`api`。每一轮每种已出现的种类取一条，再进入下一轮。

`auditPlugin` 把未截断数组交给 `scoreTrust`。返回报告里的三个数组用 `presentShapeFindings` 的结果。`capEvidence` 保持按 capability 轮转；队列顺序把 `fs-read` 放在 `shell` 之后、其余能力之前。轮转本身保证每种已检出能力至少有机会留下一条。

此任务不写 `ackFingerprint`，留给 Task 7。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/shape.spec.ts tests/core/audit.spec.ts tests/core/score.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/core/shape.ts src/core/audit.ts tests/core/shape.spec.ts tests/core/audit.spec.ts
git commit -m "$(cat <<'EOF'
fix: derive red lines from the full scan before display caps

Kind rotation keeps credential reads visible without dropping other findings.
EOF
)"
```

---

### Task 6: 装前闸门回归

**Files:**
- Create: `tests/core/gate-verdict.spec.ts`
- Modify: `docs/INTEGRATION.md`

- [ ] **Step 1: Write the failing test**

一个临时 profile：

- 超限插件出现在 `errors`，不出现在 `plugins`
- `runtime/` 里的 `execSync` 经入口 import 后，`verdict` 为 `review`
- 只有同源 `fetch` 的插件为 `clear`
- 覆盖说明存在、没有能力也没有红线时仍为 `clear`

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/gate-verdict.spec.ts`

- [ ] **Step 3: Document the gate**

`docs/INTEGRATION.md` 写明：`errors` 非空是扫描失败，装前拦截，不能当成 `clear`。`coverageNotes` 只展示，不参与 `verdict()`。手写闸门继续只看 `errors`、`redLines`、`capabilities` 和 patch override/disable。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/gate-verdict.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add tests/core/gate-verdict.spec.ts docs/INTEGRATION.md
git commit -m "$(cat <<'EOF'
test: cover pre-install verdicts for incomplete and runtime scans

Document that coverage notes do not change the install gate.
EOF
)"
```

---

## Phase B — 信任确认

### Task 7: 技能内容哈希与报告摘要

**Files:**
- Create: `src/host/content-hash.ts`
- Modify: `src/core/injection.ts`
- Modify: `src/core/audit.ts`
- Modify: `src/core/ack-fingerprint.ts`
- Modify: `src/core/types.ts`
- Modify: `tests/core/injection.spec.ts`
- Modify: `tests/core/ack-fingerprint.spec.ts`

- [ ] **Step 1: Write the failing tests**

```ts
it('fingerprints skill text by kind, path, and sha256', () => {
  const text = 'do evil'
  const hash = createHash('sha256').update(text, 'utf8').digest('hex')
  const scan = scanInjections(/* skillFiles: { 'skills/a/SKILL.md': text } */)
  expect(scan.injections[0].contentHash).toBe(hash)
  expect(scan.injections[0].bytes).toBe(Buffer.byteLength(text))
  expect(injectionFingerprint(scan.injections)).toEqual([`skill:skills/a/SKILL.md:${hash}`])
})

it('does not treat an old byte-sized ack as expected', () => {
  const report = auditPlugin(/* 同一技能文本 */)
  const stale = {
    digest: undefined,
    capabilities: [],
    destinations: [],
    secretTouches: [],
    pathEscapes: [],
    injections: ['skill:ships instruction text skills/a/SKILL.md:7'],
    redLines: [],
    at: '2020-01-01T00:00:00.000Z',
  }
  expect(ackMatchesReport(report, stale)).toBe(false)
  expect(verdict(report, stale)).toBe('review')
})
```

断言 `src/core/injection.ts` 与 `src/core/ack-fingerprint.ts` 的源码不含 `node:crypto`。测试文件可以 import `node:crypto` 计算期望值。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/injection.spec.ts tests/core/ack-fingerprint.spec.ts`

- [ ] **Step 3: Implement**

`src/host/content-hash.ts`：

```ts
import { createHash } from 'node:crypto'

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}
```

`scanInjections` 从该模块取哈希，只给 `kind === 'skill'` 的项设置 `contentHash`。`InjectionFinding` 增加可选 `path` 与 `contentHash`。

```ts
export function injectionFingerprint(injections: InjectionFinding[]): string[] {
  return injections.map(inj => {
    if (inj.kind === 'skill' && inj.path !== undefined && inj.contentHash !== undefined) {
      return `skill:${inj.path}:${inj.contentHash}`
    }
    return `${inj.kind}:${inj.detail}:${inj.bytes}`
  }).sort()
}
```

`auditPlugin` 在截断展示之前，用全量 destination / secret / path 指纹、上面的 injection token、排序后的 capabilities 和 redLines 组成稳定 JSON，再 `sha256Hex`，写入 `report.ackFingerprint`。展示数组保持截断后的结果。

`TrustAckEntry` 增加可选 `digest?: string`。`ackMatchesReport` 改为：

```ts
export function ackMatchesReport(report: AuditReport, ack: TrustAckEntry): boolean {
  return ack.digest !== undefined && ack.digest === report.ackFingerprint
}
```

没有 `digest` 的旧记录一律不匹配。浏览器侧不重算摘要。

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/injection.spec.ts tests/core/ack-fingerprint.spec.ts tests/core/present.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/host/content-hash.ts src/core/injection.ts src/core/audit.ts src/core/ack-fingerprint.ts src/core/types.ts tests/core/injection.spec.ts tests/core/ack-fingerprint.spec.ts
git commit -m "$(cat <<'EOF'
feat: bind skill acknowledgements to a host-computed content digest

Legacy ack records without a digest must be confirmed again.
EOF
)"
```

---

### Task 8: 确认绑定用户看到的报告

**Files:**
- Modify: `src/index.ts`
- Modify: `src/core/ack.ts`
- Modify: `src/core/ack-fingerprint.ts`
- Modify: `src/client/TrustReport.tsx`
- Modify: `src/client/locales.ts`
- Modify: `tests/core/ack.spec.ts`

- [ ] **Step 1: Write the failing tests**

```ts
it('returns 409 before acceptRisk when the submitted digest is stale', () => {
  const fresh = auditPlugin(/* 含 shell 的当前树 */)
  const decision = decideAckSave(fresh, '0'.repeat(64), true)
  expect(decision.status).toBe(409)
  expect(decision.report?.ackFingerprint).toBe(fresh.ackFingerprint)
})

it('saves only when the submitted digest matches the fresh scan', () => {
  const fresh = auditPlugin(/* 无红线 */)
  expect(decideAckSave(fresh, fresh.ackFingerprint, false).status).toBe(200)
})

it('rejects a matching red-line digest without acceptRisk', () => {
  const fresh = auditPlugin(/* 有红线 */)
  expect(decideAckSave(fresh, fresh.ackFingerprint, false).status).toBe(400)
})
```

再加一个宿主级用例：磁盘上的插件比页面多一个 `shell`，POST 旧摘要和 `acceptRisk: true`，响应 409，`trust-ack.json` 不存在或没有该插件。响应文案由 UI 显示，不要求服务端正文等于中文。

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run tests/core/ack.spec.ts`

- [ ] **Step 3: Implement**

```ts
export function decideAckSave(
  fresh: AuditReport,
  clientFingerprint: string | undefined,
  acceptRisk: boolean,
): { status: 200; entry: TrustAckEntry } | { status: 400; error: string } | { status: 409; report: AuditReport } {
  if (clientFingerprint !== fresh.ackFingerprint) {
    return { status: 409, report: fresh }
  }
  if (!ackAllowed(fresh, acceptRisk)) {
    return { status: 400, error: 'acknowledging a plugin with red lines requires acceptRisk: true' }
  }
  return {
    status: 200,
    entry: { digest: fresh.ackFingerprint, capabilities: fresh.capabilities, destinations: [], secretTouches: [], at: new Date().toISOString() },
  }
}
```

保存进 `trust-ack.json` 的记录包含 `digest` 与 `at`。比较只看 `digest`。capabilities 等旧字段可以留空数组，以维持现有类型；不要为了保存而写入全量 destination 列表。

POST body 为 `{ name, acceptRisk, fingerprint }`，`fingerprint` 是字符串。缺失或与重扫不一致时：

```ts
sendJson(response, 409, { error: 'plugin-content-changed', report })
```

客户端提交 `report.ackFingerprint`，不要调用会重新拼向量的函数。收到 409 时用响应里的 `report` 替换该插件卡片，并显示：

- zh: `插件内容已变化，请重新确认`
- en: `Plugin content changed. Review the updated report and confirm again.`

- [ ] **Step 4: Run tests**

Run: `pnpm exec vitest run tests/core/ack.spec.ts tests/core/http.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/core/ack.ts src/core/ack-fingerprint.ts src/client/TrustReport.tsx src/client/locales.ts tests/core/ack.spec.ts
git commit -m "$(cat <<'EOF'
feat: reject trust acknowledgements that do not match a fresh scan

A stale report returns 409 and the updated scan before any risk acceptance.
EOF
)"
```

---

### Task 9: 契约说明与全量验证

**Files:**
- Modify: `docs/audit-schema.md`
- Modify: `docs/INTEGRATION.md`
- Modify: `README.md`
- Modify: `README.en.md`

- [ ] **Step 1: Document the contract**

写明可选字段 `coverageNotes` 与 `ackFingerprint`，ack POST 的 `fingerprint` 字符串，以及 409 代码 `plugin-content-changed`。`schemaVersion` 保持 `1`。旧的无 `digest` 确认需要重新确认。装前闸门不使用 ack。

- [ ] **Step 2: Run the suite**

Run: `pnpm test && pnpm typecheck && pnpm build`

Expected: 三个命令都通过。`lib/client.js` 中不出现 `createHash`。

- [ ] **Step 3: Commit**

```bash
git add docs/audit-schema.md docs/INTEGRATION.md README.md README.en.md
git commit -m "$(cat <<'EOF'
docs: describe scan errors, coverage notes, and ack digests

Keep the audit schema version while requiring old acknowledgements to be renewed.
EOF
)"
```

---

## 对照需求

| 需求 | 任务 |
|---|---|
| 超限、主入口失败进入 errors；先看大小再读 | Task 1 |
| profile 不存在、配置缺失或损坏、已声明目录缺失 | Task 2 |
| 包内静态 import / export from / require；真实路径；循环；动态目标只标明限制 | Task 3 |
| 同一行每个 fetch；只有完整相对路径字面量算同源 | Task 4 |
| 全量结果算红线，再截断；`read` 优先展示且不排掉其它种类 | Task 5 |
| 前四项用于装前拦截 | Task 6 |
| 技能 SHA-256；类型 + 路径 + 哈希；旧确认失效；宿主计算 | Task 7 |
| 客户端提交摘要；服务端重扫；不一致 409 并刷新 | Task 8 |
