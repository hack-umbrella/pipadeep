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

- [~] 容器内新增：subfinder、httpx、ffuf、katana —— **需容器侧配合**（我这边只能写调用与参数，武器可用性要你在容器里确认）
- [~] `pentest_arsenal` 命令白名单与默认参数 —— 同上，待容器侧确认后一次补齐
- [x] JS 抽取：端点/参数/硬编码密钥（含熵判断）→ 端点入资产图 + 明细落 JSON（`lib/jsintel.mjs`）
- [x] 证书透明度：`crtShUrl` + `parseCrtSh`（通配符/去重/限流报错）
- **验收**：`pentest_analyze action=js` 一条命令产出端点+密钥+参数+子域并落库 ✅（容器武器部分待环境）

## 4. 认证 / 授权自动化（P1）

- [x] `lib/authz.mjs`：`buildAccessMatrix`（身份 × 请求）
- [x] BOLA/IDOR：`classifyAccessPair` + `authzCandidates`（差异归类为 idor/bola 候选，强制人工确认）
- [x] JWT 专项：alg=none／弱 HMAC 离线爆破／kid 注入／jku／缺 exp／敏感声明
- [~] 结论仍由 `pentest_add_finding` 把关（要求可复现步骤）；越权候选单独成篇待人工确认
- **验收**：矩阵 JSON → 候选 + 归类理由 ✅（未跑本地双账号靶场，见"待验"）

## 5. 交付物（P1）

- [x] CVSS 3.1 计算器（含向量解析与等级；与官方参考向量一致）
- [x] docx 导出（零依赖自写 ZIP；PDF 可由 Word/WPS 转存）
- [x] 证据包：文件 + `manifest.json`（sha256/大小/类型）
- [ ] 修复建议库（待做）
- **验收**：`pentest_analyze action=deliver` 产出 docx + 证据 zip ✅

## 6. 复测 / 回归（P2）

- [x] 两次评估 diff：已修复/仍存在/新增/回归（按规则族+位置对齐）
- [~] finding 状态字段由宿主模型承载；复测读入上一轮 JSON 的 `status` 判定回归
- [x] 复测报告 Markdown（只列变化，仍存在按严重度排序）
- **验收**：✅（单测覆盖四类结论）

## 7. 降噪与质量度量（P2）

- [x] KPI：确认率、误报上界、高危确认率、严重度分布、噪声规则榜
- [x] 跨引擎合并：同位置同规则族合并 + 引擎列表 + 置信度提升
- [ ] 自动降噪（白名单已有雏形，学习待做）
- **验收**：`pentest_analyze action=kpi` 给出 KPI 表 ✅

## 8. 内网 / AD / 云（P2，按需）

> ⚠️ **需要环境**：AD 靶场、武器容器、云凭证沙箱。没有这些我无法真实验证，
> 按「宁可没做、不做假的」原则暂缓 —— 先出接口与调用设计，环境就绪后一次做完。

- [ ] impacket / NetExec 基础动作（SMB 枚举、Kerberoasting、PtH）
- [ ] 隧道与多会话：SOCKS/端口转发（chisel/frp）会话保持与复用
- [ ] 凭据管理：抓到的 hash/票/密钥落库并标注来源（敏感值脱敏存储）
- [ ] 云：AK/SK 校验、元数据（169.254.169.254）链路、对象存储枚举
- **验收**：本地 AD 靶场能产出域内攻击路径图（复用现有 assets/edges 模型）。

## 9. 工程化与 OPSEC（P2）

> ⚠️ **需要宿主能力**：作业调度要接 dsh 的 job 体系与限速宿主，
> 无环境只能验证"参数模板"这一层。同上暂缓。

- [ ] 作业调度：限速、并发上限、断点续扫（长任务落 job，可恢复）
- [ ] 扫描策略模板：`快扫 / 全扫 / 隐蔽`（内置参数集）
- [ ] OPSEC：UA 轮换、代理池、请求节流、指纹伪装
- [ ] 企业门禁：可配策略（生产只读扫描 vs 允许利用），默认仍是"给出目标即开测"
- **验收**：一次 1000 目标的扫描能断点续跑，且全过程可控速。

## 10. 知识库沉淀（P3）

> 📝 纯文档工作（技能手册、CVE/EXP 库、payload 库）。**必须基于真实实战复盘**才有价值，
> 我不打算凭想象堆砌内容 —— 建议按项目逐个沉淀（每次实战结束追加一节）。

- [ ] 技能扩容：从 202 行扩到分场景手册（中间件/框架/云/AD/免杀/OPSEC）
- [ ] CVE/EXP 库对接（本地索引 + 在线复核）、payload 库（含编码/变形矩阵）
- [ ] 自进化闭环：每次实战结束自动提炼新 fact/绕过手法进技能库（人工审核后入库）
- **验收**：新增场景（如某中间件）能靠技能库独立完成，不依赖模型临场发挥。

---

## 推进顺序与状态

| 顺序 | 项 | 状态 |
| :-- | :-- | :-- |
| 0 | 旧会话日志修复（先决条件，v1.6.6） | ✅ 已完成（33/33 恢复） |
| 1 | 武器输出 → 结构化落库 | ✅ 端到端实测通过（4 资产/5 事实） |
| 2 | OOB / 回连 | ✅ 代码+25 测试+发版；实链路待补跑 |
| 3 | 攻击面武器扩容 | 🟡 JS/证书透明度 ✅；容器武器待环境 |
| 4 | 认证 / 授权自动化 | ✅ 代码+测试；靶场实跑待补 |
| 5 | 交付物 | ✅ CVSS+docx+证据包（PDF 可转存）；修复建议库待做 |
| 6 | 复测 / 回归 | ✅ |
| 7 | 降噪与质量度量 | ✅ KPI+跨引擎合并；自动降噪白名单待做 |
| 8 | 内网 / AD / 云 | ⛔ 待环境（AD 靶场/武器容器/云沙箱） |
| 9 | 工程化与 OPSEC | ⛔ 待宿主调度能力 |
| 10 | 知识库沉淀 | 📝 按实战复盘逐次沉淀（不凭想象堆内容） |
