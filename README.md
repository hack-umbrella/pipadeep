# @pipadeep/dsh-pentest

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）的渗透测试模式 —— 一个**记录层 + 执行层**合并的自包含插件 bundle：

- **记录层**（来自 [howmp/dsh-pentest](https://github.com/howmp/dsh-pentest)）：把一次授权渗透测试建模成一张**带语义边的探索链路图**（goal → intent → fact → finding + 资产树），并在 Web 中以「探索链路 / 漏洞 / 资产 / 报告」四个视图实时可视化。
- **执行层**（本项目自研）：39 个真正动手的 `pentest_*` 工具（资产测绘 / JS·API 审计 / 敏感信息 / Web 漏洞发现 / 漏洞利用 / payload 生成 / WAF 指纹 / 自定义绕过库 / 范围门禁 / 绕过·技能管理），由**执行子 agent** 调用，结果经 `pentest_submit` 直写回父 intent。

一句话：dsh-pentest 缺「引擎」（它只记录、不扫描，探测靠裸 `bash`），本项目的 39 个执行工具补上了这一半，于是记录、执行、可视化形成闭环。

## 特性

| 面 | 内容 |
|---|---|
| 记录层 | `pentest` storage-domain（6 表：goals/intents/facts/findings/assets/edges）+ 确定性 id（`<kind>-<n>`）+ 会话投影纯重放 |
| 执行层 | 39 个 `pentest_*` 工具：portscan / banner / httpprobe / dirscan / dns / whois / ssl / nuclei / subdomains / wayback / linkcrawl / jsaudit / sensitive / paramfuzz / sqli_check·exploit / xss / lfi_check·read / rce / ssti / ssrf / xxe / jwt / idor / upload / deser / bruteforce / payload / bootstrap / submit_flag / **waf** / **bypass** / **scope** / **bypass_list·add·remove** / **skill_add·list** |
| Web 视图 | 探索链路（@xyflow/react 图，边带「意图链/产出/推导自/证实」关系胶囊）、漏洞（严重度/可复现步骤/影响资产）、资产（列表/图）、报告（Markdown 渲染·复制·保存） |
| 编排 | 指挥官（决策 agent）建 goal/intent，执行子 agent 只被授予 `pentest_submit` + 执行工具，`toolFilter.deny` 禁掉记录与委派工具 |
| 持久化 | 仅 `pentest` 域路由到 sqlite（`$DSH_HOME/storages/pentest-sessions.db`），宿主其它域仍走默认 json 后端 |
| 授权 | `pentest_add_goal` 的 `authorization` 参数记录授权说明（审计事实，非门禁；扫描/利用仍受部署沙箱与审批约束） |

## 安装

从本地 tarball 安装：

```powershell
dsh plugin --profile web add -w file:C:\path\to\pipadeep-dsh-pentest-0.4.2.tgz
```

> `-w` 是因为 web profile 是 pnpm workspace 根（pnpm 10 需要显式 `--workspace-root`）。

重启 dsh 后，在新会话中选择自动注册的「**渗透模式 Pro**」。

## 用法

1. 新会话选择「渗透模式 Pro」预设。
2. 用户只需给出**目标** + **目的**（例如「扫描 10.0.0.5，拿到尽可能多的 flag」）。
3. 指挥官（决策 agent）调用 `pentest_add_goal` 起头，随后沿链路推进：建 intent → 委派执行子 agent → 子 agent 用执行工具动手 → 每组确认结果立刻 `pentest_submit` 写回 → 派生新 intent 继续。
4. 右侧「渗透」标签实时显示探索链路图 / 漏洞 / 资产 / 报告。

## 架构速览

- **领域模型**（`lib/pentest.js`，vendored）：storage domain `pentest`（version 2）——`goals / intents / facts / findings / assets / edges` 六张表。边即链路词汇：`spawns`(goal→intent)、`yields`(intent→fact)、`derived_from`(fact→intent)、`proves`(intent→finding)、`parent`(asset→asset)。finding 必填 `reproducibleSteps`（至少一条）。
- **确定性 id**：节点/边 id 为 `<kind>-<n>`（按会话计数），工具返回 id 供模型跨调用引用；会话投影从日志纯重放同一张图，Web 端不读数据库。
- **记录工具**（9 个）：`pentest_submit` / `pentest_add_goal` / `pentest_add_intent` / `pentest_add_fact` / `pentest_add_finding` / `pentest_add_asset` / `pentest_state` / `pentest_graph` / `pentest_report`。
- **执行工具**（39 个，`lib/pentest-tools.js`）：本项目的自研源码，纯 JS、零外部 import。代理默认走 `127.0.0.1:8080`（可用 `PENTEST_PROXY` 覆盖/关闭）；关键扫描工具（portscan/dns/whois/ssl/banner/nuclei）带 **依赖检测**，缺装给明示。
- **协议**：`pentest:protocol` 系统提示段（指挥官沿链路推进、子 agent 经 `pentest_submit` 直写父 intent、与用户交互一律中文）+ `tool:pentest-tools` 速查段（SQLi/LFI/命令注入/上传绕过/Python 沙箱逃逸/flag 位置）。
- **Web 视图**（`lib/ui-pentest.client.js`，vendored）：按会话注册（当前会话或祖先链含 `pentest` 预设才显示，非渗透会话隐藏）；四个子标签。

## 执行层增强（本仓库增量）

在 vendored 记录层之上，`lib/pentest-tools.js`（自研、纯 JS、可改）提供 **39 个**执行工具，并新增「按需懒加载 / 对话式管理」能力：

- **`pentest_scope`**：查看/检查授权范围（来自 `PENTEST_SCOPE` 环境变量），配置后进入**工具级门禁**，白名单外的目标/URL 会被 block。
- **`pentest_waf`**：抓取目标响应头/正文，识别 Cloudflare/ModSecurity/Sucuri/F5/AWS WAF 等防护指纹。
- **`pentest_bypass`**：**读取你的自定义绕过库**（`PENTEST_BYPASS_FILE` 指向的 JSON，可从 `pentest-bypass.example.json` 复制开始），按漏洞类型 + WAF 返回你手动维护的手法。**不内置任何硬编码绕过**——手法由你添加/更新。

以上工具都不打进常驻提示，只在需要时调用，**节省每轮上下文 token**，也给模型留出更多推理空间。

**绕过库**：绕过思路完全由你控制。复制 `pentest-bypass.example.json` 为 `pentest-bypass.json`（或用 `PENTEST_BYPASS_FILE` 指向它），编辑 JSON 即可增删手法；改完无需重启，下轮 `pentest_bypass` 读取即生效。

**对话式管理（选择 / 添加）**：除了改文件，也能用对话直接管理——
- `pentest_bypass_list` / `pentest_bypass_add` / `pentest_bypass_remove`：列出/新增/删除绕过手法（写入你的绕过库）。
- `pentest_skill_list` / `pentest_skill_add`：列出/新建技能（写入 `PENTEST_SKILLS_DIR`，默认 `.dsh/skills`，dsh 自动发现免重启）。

## 可配置环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `PENTEST_PROXY` | HTTP 代理（`host` 或 `host:port`）；设 `none`/`off`/`direct` 直连 | `http://127.0.0.1:8080`（Burp） |
| `PENTEST_SCOPE` | 授权范围，逗号分隔的域名/IP/CIDR；配置后启用工具级门禁 | 未设置=放行（建议设置） |
| `PENTEST_BYPASS_FILE` | 你的自定义绕过库 JSON 路径 | `./pentest-bypass.json` |
| `PENTEST_SKILLS_DIR` | `pentest_skill_add` 写入技能目录（dsh 扫描根） | `.dsh/skills` |

## 技能库（自进化）

插件内置 `skills/` 目录（dsh 技能：`<name>/SKILL.md`，kebab-case 名 + `description` frontmatter），
包含 `pentest-bypass` / `pentest-recon` / `pentest-exploit` / `pentest-report` / `pentest-methodology` 五套技能。
- **按需加载**：由 `pentest-methodology`（指挥官准则）、`pentest-bypass`（WAF 绕过）、`pentest-recon`（侦察）、
  `pentest-exploit`（利用）、`pentest-report`（报告）组成，模型匹配到场景才加载正文，不占常驻上下文。
- **自进化**：dsh 的 `skill-filesystem` 扫描以下根目录，且**编辑技能正文无需重启/缓存失效**——
  直接改 `skills/<name>/SKILL.md` 即可被后续目录刷新吸收；**绕过手法**则编辑 `pentest-bypass.json` 即时生效。

**让插件自带的 `skills/` 生效**（任选其一）：
1. 在 `preset/pentest/agent.cordis.yml` 的 `skill-filesystem` 行加 `config.bundledSkillDir`（或 `customSkillDirs`）指向插件 `skills/` 的绝对路径；或
2. 把 `skills/*` 目录复制到任一扫描根：`<projectRoot>/.dsh/skills`、`<projectRoot>/.agents/skills`、`~/.dsh/skills`、`~/.agents/skills`。

> 更新技能=改 `SKILL.md` 文件即可（无需重装/重启）。

## 管理（选择 / 添加）

提供两层：

1. **对话式（主推，已可用、可测）**：`pentest_bypass_list/add/remove`、`pentest_skill_list/add` —— 直接对话即可增删绕过/技能。
2. **数据 API（已接线、已测）**：`lib/bypass-routes.js` 提供 `/api/pipadeep-pentest/bypass`(GET/POST)、`/bypass/remove`(POST)、`/skills`(GET/POST)，读写绕过库与技能；已在 `cordis.patch.yml` 注册 `bypass-routes` 行，供脚本/外部 UI 复用。

> 图形化「绕过/技能」面板（`ui-pentest-manager.client.js`）在 0.4.0 曾并入 client bundle，但二次注册 `conversation.view` 槽位会覆盖原有「渗透」面板，已在 0.4.1 回滚移除。后续若要图形面板，需在 `PentestView` 内部新增一个 tab（而非第二个 slot），待验证后再加。



## 记忆（跨会话 / 自进化）

插件**不自带分离的记忆工具**——跨会话记忆交给成熟的 dsh 记忆插件。推荐 **dsh-auto-memory**（自包含三层记忆：每轮自动沉淀、`memory_log`/`memory_recall`/`memory_consolidate`、低 token、把凭据挡在提示外，无需外部 server）：

```bash
cd ~/.dsh/profiles/web
pnpm add @a9i5k4/dsh-auto-memory
# 在 package.json 的 dsh.profile.bundles 追加 "@a9i5k4/dsh-auto-memory"，然后重启 dsh web
```

- 通用跨会话记忆（经验、约定、教训）→ 交给 **dsh-auto-memory**。
- 渗透**领域技法库** → 本插件的 `skills/*/SKILL.md`（可编辑、按需加载）+ `pentest-bypass.json`（绕过手法）。
- 避免两套记忆存同一类内容：`skills`/`pentest-bypass.json` 是技法知识，auto-memory 是通用记忆，各司其职。

## 目录结构

```
dsh-pentest/                       # bundle 根 = 包 @pipadeep/dsh-pentest
├── skills/                        # ★ 自进化技能库（<name>/SKILL.md）
│   ├── pentest-bypass/SKILL.md
│   ├── pentest-recon/SKILL.md
│   ├── pentest-exploit/SKILL.md
│   ├── pentest-report/SKILL.md
│   └── pentest-methodology/SKILL.md
├── package.json                   # bundle manifest：dsh.bundle.patch + dsh.client + exports 子路径
├── cordis.patch.yml               # 补丁层：UI、sqlite 后端、storage-domain 路由、preset root
├── lib/
│   ├── pentest-tools.js           # ★ 本项目源码：31 个执行工具（可直接改，无构建）
│   ├── pentest.js                 # vendored 自 howmp/dsh-pentest：记录层（领域模型/工具/投影/协议）
│   ├── storage-sqlite.js          # vendored：渗透记录专用 sqlite 后端（node:sqlite）
│   ├── ui-pentest.js              # vendored：Web 插件宿主半（空 apply）
│   ├── ui-pentest.client.js       # vendored：Web 插件浏览器半（4 个子标签，@xyflow/react 内联）
│   ├── preset-root.js             # vendored：注册包内只读预设目录
│   ├── index.js                   # vendored：包入口（空 apply）
│   └── invariant.js               # vendored：探索图不变量伴生（生产环境不加载）
├── preset/pentest/                # ★ 「渗透模式 Pro」agent 预设（指挥官 + 执行子 agent）
│   ├── agent.cordis.yml
│   └── preset.yml
└── README.md
```

## 与原 howmp/dsh-pentest 的关系

本项目**基于 [howmp/dsh-pentest](https://github.com/howmp/dsh-pentest)（MIT）增强**。记录层（`lib/pentest.js`）、Web 视图（`lib/ui-pentest*.js`）、sqlite 后端（`lib/storage-sqlite.js`）、预设根（`lib/preset-root.js`）均 vendored 自原项目构建产物；本项目的增量是：

- 新增 `lib/pentest-tools.js`（39 个执行工具，替换掉原「探测靠裸 bash」的空缺），含 WAF 指纹 / 自定义绕过库 / 范围门禁 / 绕过·技能管理，并支持代理可配置 + 依赖检测。
- `cordis.patch.yml` 不变地保留原四件事（sqlite 后端 / `pentest→sqlite` 路由 / Web 视图 row / preset root）。
- `preset/pentest/agent.cordis.yml` 在指挥官预设里追加 `pentest-tools` row，并让执行子 agent 显式使用这些工具。

## 已知边界

- **数据库**：渗透记录写入 `$DSH_HOME/storages/pentest-sessions.db`（sqlite，经 bundle 补丁路由）；宿主其它域不受影响。
- **授权**：`authorization` 是审计事实、不是门禁——扫描/利用动作仍受部署沙箱与审批约束。若设置 `PENTEST_SCOPE`，执行层会在工具级做**范围门禁**（白名单外目标被 block）。
- **记录按单会话作用域**，无跨会话/项目续跑；重新开始一次 engagement 需新的 `pentest_add_goal`。
- **图布局为静态分层**（可平移缩放，节点不可拖拽）。

## License

MIT，见 [LICENSE](./LICENSE)。记录层 / Web 视图 / sqlite 后端等 vendored 部分的版权归 howmp/dsh-pentest 原作者（MIT）。
