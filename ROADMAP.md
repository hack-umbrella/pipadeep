# 渗透能力补齐路线图（1-10）

来源：对现有能力的代码级盘点（16 个工具 / 8 件武器：nmap、nuclei、sqlmap、hydra、msfconsole、
ysuserial、java-chains、JNDIExploit；5 个技能共 202 行）。**不追求"更聪明的 Agent"，
优先补的是工程管线** —— 把确定性数据交给确定性代码。

约定：每项都写清「交付物 / 验收标准」，完成后勾选。每项独立发版，先过 `npm test` + `npm run check`。

---

## 1. 武器输出 → 结构化落库（P0）

**问题**：代码里没有任何解析器。nmap 扫完靠 agent 一条条 `pentest_add_asset`，漏/重/自由文本。

- [x] `lib/ingest.mjs`：纯函数解析器（零依赖、可复现、按稳定键去重）
  - [x] nmap：`-oX` XML → hosts/ports/services/scripts（含 `<hostnames>` 前缀陷阱修复）
  - [x] nuclei：JSONL → 候选（template-id / severity / matched-at；坏行留痕不静默丢）
  - [x] httpx：JSONL → 存活、状态码、标题、指纹
  - [x] ffuf：JSON → 目录/文件候选
  - [x] masscan / naabu：JSON → 端口
- [x] `pentest_ingest` 工具：`{ files, intentId, kind?: auto, rootAssetId? }` → 确定性写 assets/facts（决策层工具，已加入子 agent deny 列表）
- [x] 去重键：资产 `type|value`、事实 `kind|target|detail`；重复命中合并来源而不是新建节点（`sources` 记录全部来源）
- [~] 来源溯源：每条记录带 `sources=文件名@sha256前12位`；独立的 `ingest` 统计 fact 待做
- **验收**：同一份 nmap XML 解析两次得到完全相同的资产集合；解析结果可被 `pentest_graph` 读到；
  单测覆盖真实工具样例输出（各 1 份 fixture）。

## 2. OOB / 回连基础设施（P0）

**问题**：全库无回连能力（仅 UI 里有一处字样）。盲注、盲 SSRF、无回显 RCE、XXE 外带、
JNDI 注入的**打中验证**全部缺失 → "可复现 PoC"纪律无法闭环。

- [ ] `lib/oob.mjs`：Interactsh 客户端（自建或公共集群，可配 `PENTEST_OOB_SERVER`）
- [ ] `pentest_oob` 工具：`start` / `new <label>`（生成唯一子域）/ `poll` / `list` / `stop`
- [ ] 交互落库：每条 interaction → fact（`kind: oob`）+ evidence（原始请求/时间/来源 IP）
- [ ] 载荷模板注入：`pentest_arsenal` 调用武器时自动替换 `{{OOB}}` 占位符
- **验收**：本地起一个假 Interactsh 服务，`new`→模拟回连→`poll` 能落成 fact 并出现在报告里。

## 3. 攻击面武器扩容（P1）

- [ ] 容器内新增：subfinder、httpx、ffuf、katana（+ 版本矩阵与健康自检）
- [ ] `pentest_arsenal` 增加对应命令白名单与默认参数（限速/超时/UA）
- [ ] JS 抽取：站点 JS 里抽接口路径 / 参数 / 硬编码密钥 → fact（`kind: endpoint|secret`）
- [ ] 证书透明度：crt.sh 查询 → 子域候选（无武器依赖，直接 HTTP）
- **验收**：给一个真实域名，一条命令产出资产+端点+子域，全部结构化入库（不依赖 agent 手工搬）。

## 4. 认证 / 授权自动化（P1）

- [ ] `lib/authz.mjs`：会话矩阵（多登录态 × 接口 × 参数）
- [ ] BOLA/IDOR：双账号交叉访问，比较状态码/长度/字段差异，差异即候选（必须人工确认）
- [ ] JWT 专项：alg 混淆、`none`、弱密钥爆破（离线字典）、kid 注入
- [ ] 越权结论强制带 `poc`（两账号请求/响应摘要），否则只能算候选
- **验收**：本地靶场（两个账号）能自动产出越权候选并附可复现请求。

## 5. 交付物（P1）

- [ ] CVSS 3.1 计算器（`pentest_report` 里按 vector 生成分数）
- [ ] 导出格式：docx / PDF / 纯文本 / JSON（客户交付）
- [ ] 证据打包：截图 + HTTP 事务 + 命令输出 → 单个 zip，附 sha256 清单
- [ ] 修复建议库：按 CWE/规则族给可执行建议（不是"加强输入校验"这种废话）
- **验收**：`pentest_report(format:"docx")` 产出可直接发客户的报告，含 CVSS 与证据附件。

## 6. 复测 / 回归（P2）

- [ ] 两次评估 diff：新增/已修复/仍存在/回归（按 `(ruleId, target)` 对齐）
- [ ] 每条 finding 增加 `status: open|fixed|wontfix|retest_pending|regressed`
- [ ] 复测报告：只列变化 + 证据对比
- **验收**：同一目标两次评估能产出"已修复 12 / 仍存在 3 / 新增回归 1"的复测结论。

## 7. 降噪与质量度量（P2）

- [ ] KPI：candidate→confirmed 转化率、误报率、按规则族的命中分布、按资产的风险密度
- [ ] 跨引擎合并：同一位置 + 同一规则族合并，置信度提升（参考 SARIF 合并策略）
- [ ] 自动降噪：白名单（`pentest-bypass.json` 已有雏形）+ 已知误报学习
- **验收**：报告首屏给出 KPI 表；同一漏洞多引擎命中只算一条。

## 8. 内网 / AD / 云（P2，按需）

- [ ] impacket / NetExec 基础动作（SMB 枚举、Kerberoasting、PtH）
- [ ] 隧道与多会话：SOCKS/端口转发（chisel/frp）会话保持与复用
- [ ] 凭据管理：抓到的 hash/票/密钥落库并标注来源（敏感值脱敏存储）
- [ ] 云：AK/SK 校验、元数据（169.254.169.254）链路、对象存储枚举
- **验收**：本地 AD 靶场能产出域内攻击路径图（复用现有 assets/edges 模型）。

## 9. 工程化与 OPSEC（P2）

- [ ] 作业调度：限速、并发上限、断点续扫（长任务落 job，可恢复）
- [ ] 扫描策略模板：`快扫 / 全扫 / 隐蔽`（内置参数集）
- [ ] OPSEC：UA 轮换、代理池、请求节流、指纹伪装
- [ ] 企业门禁：可配策略（生产只读扫描 vs 允许利用），默认仍是"给出目标即开测"
- **验收**：一次 1000 目标的扫描能断点续跑，且全过程可控速。

## 10. 知识库沉淀（P3）

- [ ] 技能扩容：从 202 行扩到分场景手册（中间件/框架/云/AD/免杀/OPSEC）
- [ ] CVE/EXP 库对接（本地索引 + 在线复核）、payload 库（含编码/变形矩阵）
- [ ] 自进化闭环：每次实战结束自动提炼新 fact/绕过手法进技能库（人工审核后入库）
- **验收**：新增场景（如某中间件）能靠技能库独立完成，不依赖模型临场发挥。

---

## 推进顺序与状态

| 顺序 | 项 | 状态 |
| :-- | :-- | :-- |
| 0 | 旧会话日志修复（先决条件，v1.6.6） | ✅ 已完成（33/33 恢复） |
| 1 | 武器输出 → 结构化落库 | 🟡 主体完成（解析器+工具+30 项测试），端到端待验 |
| 2 | OOB / 回连 | ⏳ |
| 3 | 攻击面武器扩容 | ⏳ |
| 4 | 认证 / 授权自动化 | ⏳ |
| 5 | 交付物 | ⏳ |
| 6 | 复测 / 回归 | ⏳ |
| 7 | 降噪与质量度量 | ⏳ |
| 8 | 内网 / AD / 云 | ⏳ |
| 9 | 工程化与 OPSEC | ⏳ |
| 10 | 知识库沉淀 | ⏳ |
