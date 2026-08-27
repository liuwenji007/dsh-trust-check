/** `trust` namespace dictionaries. */

/** Simplified Chinese dictionary (the key-set source of truth). */
export const zh = {
  'settings.nav': '插件体检',
  'settings.title': '插件体检',
  'intro': '对已安装插件做静态信任审计：权限、注入、成本、来源、更新风险，全部由代码判定，可复现、零 token。',
  'refresh': '重新扫描',
  'refreshing': '扫描中…',
  'empty': '没有扫描到社区插件。先安装一个插件，再回来扫描。',
  'loadError': '扫描失败，请确认插件已正确安装并刷新。',
  'score.label': '信任分',
  'green': '可信',
  'yellow': '需留意',
  'red': '高风险',
  'capabilities': '能力',
  'none': '无特权能力',
  'injections': '注入',
  'noInjection': '无注入',
  'injectedTokens': '估算注入 token',
  'source': '来源',
  'unpinned': '未锁版本',
  'pinned': '已锁版本',
  'noRepo': '未声明仓库',
  'buildScript': '安装时执行脚本',
  'redLines': '红线',
  'evidence': '证据',
  'errors.title': '无法扫描的插件',
  'errors.hint': '以下插件读取失败（可能已损坏或已卸载）：',
} satisfies Record<string, string>

/** The trust namespace key union. */
export type TrustKey = keyof typeof zh

/** English dictionary, checked complete against the zh key set. */
export const en = {
  'settings.nav': 'Plugin Trust',
  'settings.title': 'Plugin Trust',
  'intro': 'Static trust audit of installed plugins: capabilities, injections, cost, source, and update risk — all code-judged, reproducible, zero tokens.',
  'refresh': 'Rescan',
  'refreshing': 'Scanning…',
  'empty': 'No community plugins found. Install one, then scan again.',
  'loadError': 'Scan failed. Check the plugin installed correctly, then refresh.',
  'score.label': 'Trust score',
  'green': 'Trusted',
  'yellow': 'Caution',
  'red': 'High risk',
  'capabilities': 'Capabilities',
  'none': 'No privileged capabilities',
  'injections': 'Injections',
  'noInjection': 'No injections',
  'injectedTokens': 'Est. injected tokens',
  'source': 'Source',
  'unpinned': 'Unpinned',
  'pinned': 'Pinned',
  'noRepo': 'No repository declared',
  'buildScript': 'Runs install scripts',
  'redLines': 'Red lines',
  'evidence': 'Evidence',
  'errors.title': 'Plugins that could not be scanned',
  'errors.hint': 'These failed to read (broken or already uninstalled):',
} satisfies Record<TrustKey, string>
