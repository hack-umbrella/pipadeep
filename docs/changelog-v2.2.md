# v2.2.0 — UI 重构 + 一键复测工作流

## 功能

### Web 面板重构（简洁专业工作台风格）
- 「渗透」视图收敛为三个功能页：探索链路 / 漏洞 / 资产。
- **漏洞页合并报告与复测**：
  - 顶部风险分布徽章 + 「📥 导出报告」一键下载 / 复制完整 Markdown 交付报告；
  - 详情面板含「详情 / 复测」子页签；复测子页签提供单条「一键复测」，执行后才展示本轮请求/响应分栏数据包。
- 所有代码内容（命令、JSON、HTTP 报文）以带行号代码查看器呈现，一键复制完整原文（不含行号）。
- URL/资产值行内等宽省略展示 + 复制图标。
- 请求/响应支持 Headers / Body / 完整 HTTP 三态切换与多交换切换。

### 一键复测引擎（`lib/reprobe.mjs`，新增）
- 声明式判定规格（`options.specs` 注入）：按漏洞标题匹配规则，重放判定请求并给出「仍存在 / 已修复 / 需人工确认」。引擎本体不内置任何目标特定规则，schema 与示例见 `dev/reprobe-specs.example.mjs`。
- 只读探测：写接口一律空体，请求间 0.22s 限速，证据落盘为分段格式 `.http`。
- 新增路由：
  - `GET /api/pipadeep-pentest/retest/one` — 单条现场复测（页面单条按钮）；
  - `GET /api/pipadeep-pentest/report.md` — 完整交付报告（内联全部证据原文，动态 fence 保证含反引号的载荷不破坏 Markdown）。
- 稳定性：网络失败/超时/5xx/429 一律判「需人工确认」，绝不误报已修复；目标域校验（spec 请求必须命中基线目标或其子域）；每次运行独立 runId 与证据目录。

## 修复

- `pentest_retest action=save/compare` 在 `store.view()` 无 `state.nodes` 字段时崩溃（`undefined.filter`）。
- 复测 key 对齐：`reprobeOne` 匹配扩展为四级（精确 key → 完整标题 → key 前缀 → 规则段），前端传标题也能命中基线。
- 复测面板竞态：请求返回后错误的 token 比较导致结果被静默丢弃。
- 报告证据不再截断：`.http` 证据原文完整内联（此前截 1200/1600 字符）。

## 开发资产

- `dev/pentest-ui-components.js`：可维护的 UI 组件源（ASCII-safe，Unicode 转义）。
- `dev/scripts/sync-pentest-ui.mjs`：组件源 → 打包产物的结构化同步（函数边界替换 + 结构断言 + 语法检查）。
- `docs/ui-design.md`：报告与复测界面设计规范。
- `test/ui/`：组件 VM 测试 11 项、复测引擎回归 3 项、路由回归 2 项。
