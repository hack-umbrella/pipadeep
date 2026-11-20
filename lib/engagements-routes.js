// 全局渗透任务数据路由（loopback-only、只读）：列出 pentest SQLite 存储中的
// 每一个 engagement（goal + 计数），供 Web「全部任务」面板在任何会话中浏览。
// 对标 bypass-routes 的 `/api/<plugin>/...` 挂载模式；存储库即唯一事实源，
// 不经过会话投影，因此不受任何会话 resume/投影状态影响。
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { extname, join, normalize, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { writeTopologyHtml } from "./topology.js";
import { buildSnapshot, diffAssessments, retestMarkdown, baselineFile, listBaselines, readBaseline } from "./retest.mjs";
import { runReprobe, reprobeOne, reprobeMarkdown } from "./reprobe.mjs";
import { parseHttpDump } from "./http-evidence.mjs";

const name = "engagements-routes";
const inject = ["webServer"];

const POINT = "/api/pipadeep-pentest";

/** Resolve the pentest SQLite store path from DSH_HOME (or the default home). */
function dbFile() {
	const home = process.env.DSH_HOME || join(homedir(), ".dsh");
	return join(home, "storages", "pentest-sessions.db");
}

function send(res, status, obj) {
	try {
		res.statusCode = status;
		res.setHeader("content-type", "application/json");
		res.end(JSON.stringify(obj));
	} catch (e) {
		/* noop */
	}
}

function readAll(db, table) {
	try {
		return db.prepare(`SELECT key, value FROM ${table}`).all();
	} catch (e) {
		return [];
	}
}

/** Evidence root — every screenshot/raw-packet artifact the shot tool writes lives under here. */
function evidenceRoot() {
	if (process.env.PENTEST_EVIDENCE_DIR) return process.env.PENTEST_EVIDENCE_DIR;
	const home = process.env.DSH_HOME || join(homedir(), ".dsh");
	return join(home, "storages", "evidence");
}

const EVIDENCE_MIME = {
	".png": "image/png",
	".jpg": "image/jpeg",
	".jpeg": "image/jpeg",
	".gif": "image/gif",
	".webp": "image/webp",
	".svg": "image/svg+xml",
	".json": "application/json; charset=utf-8",
	".http": "text/plain; charset=utf-8",
	".txt": "text/plain; charset=utf-8",
	".log": "text/plain; charset=utf-8",
	".mjs": "text/plain; charset=utf-8",
	".har": "application/json; charset=utf-8"
};

/** Serve one evidence file (read-only, confined to the evidence root — no traversal). */
function serveEvidence(req, res) {
	try {
		const url = new URL(req.url || "/", "http://127.0.0.1");
		const requested = url.searchParams.get("path") || "";
		if (!requested) return send(res, 400, { error: "path 参数必填" });
		const root = resolve(evidenceRoot());
		const target = resolve(root, normalize(requested));
		if (target !== root && !target.startsWith(root + sep)) return send(res, 403, { error: "越界：只能读取证据目录内的文件" });
		if (!existsSync(target) || !statSync(target).isFile()) return send(res, 404, { error: "未找到" });
		const bytes = readFileSync(target);
		res.statusCode = 200;
		res.setHeader("content-type", EVIDENCE_MIME[extname(target).toLowerCase()] || "application/octet-stream");
		res.setHeader("cache-control", "no-store");
		res.end(bytes);
	} catch (error) {
		send(res, 500, { error: String((error && error.message) || error) });
	}
}

/**
 * 一个会话的完整探索图（与「渗透」会话投影的 wire 视图同形）：
 * { goal, nodes, assets, edges, counts }；未初始化（无 goal）返回 null。
 * 直接读 durable 存储，**不依赖会话投影**——因为子 agent 经 pentest_submit 提交的结果
 * 只落存储、不在父会话日志里，投影拿不到；而且旧版插件往父会话注入合成 tool/call 会在
 * dsh 0.1.5 的会话格式迁移里被拒。改由本路由供 Web 视图取图，跨 dsh 版本稳定。
 */
function graphFor(sessionId) {
	const raw = String(sessionId || "");
	if (raw === "") return null;
	const sid = raw.replace(/^session-/, "");
	const prefix = "session-" + sid + ":";
	const file = dbFile();
	if (!existsSync(file)) return null;
	let db;
	try {
		db = new DatabaseSync(file, { readOnly: true });
	} catch (e) {
		return null;
	}
	try {
		const read = (table) => readAll(db, table).filter((row) => String(row.key).startsWith(prefix));
		const parse = (row) => {
			try {
				return JSON.parse(row.value);
			} catch (e) {
				return null;
			}
		};
		// goals 表的 key 就是 `session-<sid>`（无节点后缀）；其它表才是 `session-<sid>:<node>`。
		const goalRow = readAll(db, "u_pentest_goals").find((row) => String(row.key) === "session-" + sid);
		if (goalRow === void 0) return null;
		const g = parse(goalRow) || {};
		const goal = {
			id: typeof g.id === "string" ? g.id : "goal-1",
			target: typeof g.target === "string" ? g.target : "",
			objective: typeof g.objective === "string" ? g.objective : "",
			authorization: typeof g.authorization === "string" ? g.authorization : ""
		};
		const byIdNum = (a, b) => (parseInt(String(a.id).replace(/^\D+/, ""), 10) || 0) - (parseInt(String(b.id).replace(/^\D+/, ""), 10) || 0);
		const intents = read("u_pentest_intents").map(parse).filter(Boolean).map((x) => ({
			id: x.id,
			kind: "intent",
			title: typeof x.title === "string" ? x.title : "",
			detail: typeof x.detail === "string" ? x.detail : ""
		})).sort(byIdNum);
		const facts = read("u_pentest_facts").map(parse).filter(Boolean).map((x) => ({
			id: x.id,
			kind: "fact",
			factKind: x.kind,
			intentId: x.intentId,
			target: typeof x.target === "string" ? x.target : "",
			detail: typeof x.detail === "string" ? x.detail : "",
			confidence: typeof x.confidence === "number" ? x.confidence : 0.5
		})).sort(byIdNum);
		const findings = read("u_pentest_findings").map(parse).filter(Boolean).map((x) => {
			const evidence = Array.isArray(x.evidence) ? x.evidence.filter((item) => item && typeof item.path === "string") : [];
			return {
				id: x.id,
				kind: "finding",
				intentId: x.intentId,
				title: typeof x.title === "string" ? x.title : "",
				severity: x.severity,
				description: typeof x.description === "string" ? x.description : "",
				steps: Array.isArray(x.reproducibleSteps) ? x.reproducibleSteps : [],
				...(evidence.length === 0 ? {} : { evidence }),
				...(typeof x.affectedAssetId === "string" ? { affectedAssetId: x.affectedAssetId } : {})
			};
		}).sort(byIdNum);
		const assets = read("u_pentest_assets").map(parse).filter(Boolean).map((x) => ({
			id: x.id,
			type: x.type,
			value: x.value,
			meta: typeof x.meta === "string" ? x.meta : ""
		})).sort(byIdNum);
		const edges = read("u_pentest_edges").map(parse).filter(Boolean).map((x) => ({
			id: x.id,
			kind: x.kind,
			sourceId: x.sourceId,
			targetId: x.targetId
		})).sort(byIdNum);
		return {
			sessionId: "session-" + sid,
			goal,
			nodes: [...intents, ...facts, ...findings],
			assets,
			edges,
			counts: { intents: intents.length, facts: facts.length, findings: findings.length, assets: assets.length }
		};
	} finally {
		try {
			db.close();
		} catch (e) {
			/* noop */
		}
	}
}

/**
 * 复测对比（只读）：当前会话 findings + assets → 快照，与基线对比 → 差异 + Markdown。
 * 基线名缺省取该目标下最后一份（按文件名排序，约定 name 带日期/序号时即最新）。
 */
async function retestFor(sessionId, name, options = {}) {
	const graph = graphFor(sessionId);
	if (graph === null) return { status: 404, obj: { error: "该会话没有渗透图（尚未调用 pentest_add_goal）" } };
	const target = graph.goal?.target ?? "";
	const wanted = String(name ?? "").trim();
	let baselineName = wanted;
	let path;
	if (wanted === "") {
		const rows = listBaselines(target, {});
		if (rows.length === 0) return { status: 404, obj: { error: "该目标尚无基线，先调用 pentest_retest action=save 保存基线", target } };
		baselineName = rows[rows.length - 1].name;
		path = rows[rows.length - 1].path;
	} else {
		path = baselineFile(baselineName, target, {});
	}
	let baseline;
	try {
		baseline = readBaseline(path);
	} catch (error) {
		return { status: 404, obj: { error: `读取基线失败：${error && error.message}`, target, baselineName } };
	}
	const findings = (graph.nodes ?? []).filter((node) => node.kind === "finding");
	const current = buildSnapshot({ sessionId, goal: graph.goal, findings, assets: graph.assets ?? [] });
	const diff = diffAssessments(baseline, current);
	// 一键复测：现场重放判定请求（probe=0 可跳过，用于纯存储对比）
	let probe = null;
	if (options.probe !== false) {
		try {
			probe = await runReprobe(baseline, { sessionId, baselinePath: path });
		} catch (error) {
			probe = { ranAt: new Date().toISOString(), total: 0, open: 0, fixed: 0, unclear: 0, rows: [], error: String((error && error.message) || error) };
		}
	}
	const probeByKey = new Map((probe?.rows ?? []).map((row) => [row.key, row]));
	const attach = (row) => (row === undefined || row === null ? row : { ...row, probe: probeByKey.get(row.key) ?? null });
	return {
		status: 200,
		obj: {
			target,
			baselineName,
			baselinePath: path,
			baselineCreatedAt: baseline.createdAt ?? null,
			summary: diff.summary,
			probe: probe === null ? null : {
				ranAt: probe.ranAt,
				total: probe.total,
				open: probe.open,
				fixed: probe.fixed,
				unclear: probe.unclear,
				error: probe.error ?? null
			},
			diff: {
				fixed: diff.fixed.map((row) => attach(row.previous ?? row)),
				open: diff.open.map((row) => attach(row.current ?? row.previous ?? row)),
				added: diff.added.map((row) => attach(row.current ?? row)),
				regressed: diff.regressed.map((row) => attach(row.current ?? row.previous ?? row))
			},
			markdown: retestMarkdown(diff) + (probe === null ? "" : reprobeMarkdown(probe))
		}
	};
}

/**
 * 单条复测（页面「复测这一条」按钮）：只重放这一条的判定请求，返回结论 + 本轮原始包。
 * baseline 名缺省取该目标最近一份；key 为基线里的稳定对齐键（规则@资产值/URL）。
 */
async function retestOne(sessionId, key, name) {
	const graph = graphFor(sessionId);
	if (graph === null) return { status: 404, obj: { error: "该会话没有渗透图（尚未调用 pentest_add_goal）" } };
	if (String(key ?? "") === "") return { status: 400, obj: { error: "缺少 key（要复测的那条 finding 的稳定对齐键）" } };
	const target = graph.goal?.target ?? "";
	let path;
	const wanted = String(name ?? "").trim();
	if (wanted === "") {
		const rows = listBaselines(target, {});
		if (rows.length === 0) return { status: 404, obj: { error: "该目标尚无基线，先调用 pentest_retest action=save 保存基线", target } };
		path = rows[rows.length - 1].path;
	} else {
		path = baselineFile(wanted, target, {});
	}
	let baseline;
	try {
		baseline = readBaseline(path);
	} catch (error) {
		return { status: 404, obj: { error: `读取基线失败：${error && error.message}` } };
	}
	let result;
	try {
		// 传 baselinePath：reprobe 会据此从基线同目录的 reprobe-specs.mjs 自动加载判定规格
		result = await reprobeOne(baseline, key, { sessionId, baselinePath: path });
	} catch (error) {
		return { status: 500, obj: { error: String((error && error.message) || error) } };
	}
	if (result && result.error !== undefined) return { status: 404, obj: result };
	return { status: 200, obj: { baselinePath: path, ...result } };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function fenced(text) {
 const raw = String(text ?? '');
 const runs = raw.match(/`+/g) ?? [];
 const length = Math.max(3, ...runs.map((run) => run.length + 1));
 const fence = '`'.repeat(length);
 return [fence + 'http', raw, fence].join('\n');
}

function inlinePackets(evidence) {
 const blocks = [];
 for (const item of Array.isArray(evidence) ? evidence : []) {
  if (String(item?.kind ?? '') !== 'http') continue;
  const path = String(item?.path ?? '');
  if (path === '' || !existsSync(path)) continue;
  try {
   const raw = readFileSync(path, 'utf8');
   blocks.push('- ' + String(item.label || '原始 HTTP 流量'), '', fenced(raw), '');
  } catch {
   blocks.push('- 证据文件暂不可读', '');
  }
 }
 return blocks;
}

/**
 * 生成页面「报告」用的 Markdown：概览 + 按严重度排序的漏洞（含内联原始包）+ 链路 + 资产。
 * 与 pentest_report 的最终报告同源同结构，方便直接复制/下载交付。
 */
function sessionReportMarkdown(sessionId) {
	const graph = graphFor(sessionId);
	if (graph === null) return null;
	const goal = graph.goal ?? {};
	const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
	const assets = Array.isArray(graph.assets) ? graph.assets : [];
	const intents = nodes.filter((node) => node.kind === "intent");
	const facts = nodes.filter((node) => node.kind === "fact");
	const findings = nodes.filter((node) => node.kind === "finding")
		.sort((a, b) => (SEV_ORDER[String(a.severity ?? "unknown")] ?? 9) - (SEV_ORDER[String(b.severity ?? "unknown")] ?? 9));
	const bySeverity = {};
	for (const finding of findings) bySeverity[String(finding.severity ?? "unknown")] = (bySeverity[String(finding.severity ?? "unknown")] ?? 0) + 1;
	const counts = ["critical", "high", "medium", "low", "info"].filter((key) => bySeverity[key] !== undefined).map((key) => `${key} ${bySeverity[key]}`).join(" · ") || "无";
	const lines = [
		`# 渗透测试报告 · ${goal.target ?? ""}`,
		"",
		`- 目标: ${goal.target ?? ""}`,
		`- 目的: ${goal.objective ?? ""}`,
		`- 授权: ${goal.authorization ?? ""}`,
		"",
		"## 概览",
		"",
		`- 漏洞 ${findings.length} 条（${counts}）`,
		`- 意图 ${intents.length} · 事实 ${facts.length} · 资产 ${assets.length}`,
		""
	];
	if (findings.length === 0) {
		lines.push("## 漏洞发现", "", "本会话尚未记录漏洞。", "");
	} else {
		lines.push("## 漏洞发现", "");
		for (const finding of findings) {
			const asset = assets.find((candidate) => candidate.id === finding.affectedAssetId);
			const steps = Array.isArray(finding.steps) ? finding.steps : [];
			lines.push(`### [${finding.severity ?? "unknown"}] ${finding.title ?? ""}`, "");
			if (asset !== undefined) lines.push(`- 影响资产: [${asset.type}] ${asset.value}`);
			if (String(finding.description ?? "") !== "") lines.push(`- 描述: ${finding.description}`, "");
			if (steps.length > 0) {
				lines.push("- 复现步骤:", "");
				for (const [index, step] of steps.entries()) lines.push(`${index + 1}. ${step}`, "");
			}
			const packets = inlinePackets(finding.evidence);
			if (packets.length > 0) lines.push("- HTTP 流量证据:", "", ...packets);
		}
	}
	lines.push("## 探索链路", "", `- 目标 (goal) ${goal.target ?? ""} — ${goal.objective ?? ""}`);
	for (const intent of intents) lines.push(`- 意图 (${intent.id}) ${intent.title}${intent.detail === "" ? "" : `: ${intent.detail}`}`);
	for (const fact of facts) lines.push(`- 事实 (${fact.id}) [${fact.factKind ?? "info"}] ${fact.target === "" ? "" : `${fact.target}: `}${fact.detail}`);
	for (const finding of findings) lines.push(`- 漏洞 (${finding.id}) [${finding.severity}] ${finding.title}`);
	lines.push("", "## 资产", "");
	for (const asset of assets) {
		const edge = (graph.edges ?? []).find((candidate) => candidate.kind === "parent" && candidate.targetId === asset.id);
		const parent = edge === undefined ? undefined : assets.find((candidate) => candidate.id === edge.sourceId);
		lines.push(`- [${asset.type}] ${asset.value}${asset.meta === "" ? "" : ` — ${asset.meta}`}${parent === undefined ? "" : ` ← ${parent.value}`}`);
	}
	lines.push("");
	return lines.join("\n");
}

/** List every engagement with per-session counts, newest insert last→first. */
function listEngagements() {
	const file = dbFile();
	if (!existsSync(file)) {
		return { status: 200, obj: { engagements: [], db: file, note: "pentest store not created yet" } };
	}
	let db;
	try {
		db = new DatabaseSync(file, { readOnly: true });
	} catch (e) {
		return { status: 500, obj: { error: "open store failed: " + (e && e.message) } };
	}
	try {
		const countsBySession = {};
		const bump = (key, field) => {
			const session = key.split(":")[0];
			const bucket = countsBySession[session] || (countsBySession[session] = {
				intents: 0,
				facts: 0,
				findings: 0,
				assets: 0,
				edges: 0
			});
			bucket[field] += 1;
		};
		for (const row of readAll(db, "u_pentest_intents")) bump(row.key, "intents");
		for (const row of readAll(db, "u_pentest_facts")) bump(row.key, "facts");
		for (const row of readAll(db, "u_pentest_findings")) bump(row.key, "findings");
		for (const row of readAll(db, "u_pentest_assets")) bump(row.key, "assets");
		for (const row of readAll(db, "u_pentest_edges")) bump(row.key, "edges");
		const goals = readAll(db, "u_pentest_goals");
		const engagements = [];
		for (let index = goals.length - 1; index >= 0; index -= 1) {
			const row = goals[index];
			let goal = {};
			try {
				goal = JSON.parse(row.value);
			} catch (e) {
				goal = {};
			}
			engagements.push({
				sessionId: row.key,
				target: String(goal.target || ""),
				objective: String(goal.objective || ""),
				authorization: String(goal.authorization || ""),
				counts: countsBySession[row.key] || {
					intents: 0,
					facts: 0,
					findings: 0,
					assets: 0,
					edges: 0
				}
			});
		}
		return { status: 200, obj: { engagements } };
	} finally {
		try {
			db.close();
		} catch (e) {
			/* noop */
		}
	}
}

/**
 * 资产拓扑 HTML：按会话生成（或覆盖）后原样回传。
 * Web 视图点「拓扑图」即打开本路由；探测到新资产时插件已自动写盘，这里总是重算以确保最新。
 */
function serveTopology(req, res) {
	try {
		const url = new URL(req.url || "/", "http://127.0.0.1");
		const sessionId = url.searchParams.get("sessionId") || "";
		const graph = graphFor(sessionId);
		if (graph === null) {
			send(res, 404, {
				error: "该会话没有渗透图（尚未调用 pentest_add_goal）",
				sessionId
			});
			return;
		}
		const { path } = writeTopologyHtml(sessionId, graph);
		const bytes = readFileSync(path);
		res.statusCode = 200;
		res.setHeader("content-type", "text/html; charset=utf-8");
		res.setHeader("cache-control", "no-store");
		res.end(bytes);
	} catch (error) {
		send(res, 500, { error: String((error && error.message) || error) });
	}
}

function apply(ctx) {
	const disposers = [];
	const routes = [
		{
			path: POINT + "/engagements",
			method: "GET",
			handler: async (req, res) => {
				const result = listEngagements();
				send(res, result.status, result.obj);
			}
		},
		{
			path: POINT + "/graph",
			method: "GET",
			handler: async (req, res) => {
				try {
					const url = new URL(req.url || "/", "http://127.0.0.1");
					const graph = graphFor(url.searchParams.get("sessionId") || "");
					send(res, 200, { graph });
				} catch (error) {
					send(res, 500, { graph: null, error: String((error && error.message) || error) });
				}
			}
		},
		{
			path: POINT + "/retest",
			method: "GET",
			handler: async (req, res) => {
				try {
					const url = new URL(req.url || "/", "http://127.0.0.1");
					const result = await retestFor(url.searchParams.get("sessionId") || "", url.searchParams.get("baseline") || "", { probe: url.searchParams.get("probe") === "1" });
					send(res, result.status, result.obj);
				} catch (error) {
					send(res, 500, { error: String((error && error.message) || error) });
				}
			}
		},
		{
			path: POINT + "/retest.md",
			method: "GET",
			handler: async (req, res) => {
				try {
					const url = new URL(req.url || "/", "http://127.0.0.1");
					const result = await retestFor(url.searchParams.get("sessionId") || "", url.searchParams.get("baseline") || "", { probe: url.searchParams.get("probe") === "1" });
					if (result.status !== 200) {
						send(res, result.status, result.obj);
						return;
					}
					res.statusCode = 200;
					res.setHeader("content-type", "text/markdown; charset=utf-8");
					res.setHeader("cache-control", "no-store");
					res.end(result.obj.markdown);
				} catch (error) {
					send(res, 500, { error: String((error && error.message) || error) });
				}
			}
		},
		{
			path: POINT + "/retest/one",
			method: "GET",
			handler: async (req, res) => {
				try {
					const url = new URL(req.url || "/", "http://127.0.0.1");
					const result = await retestOne(url.searchParams.get("sessionId") || "", url.searchParams.get("key") || "", url.searchParams.get("baseline") || "");
					send(res, result.status, result.obj);
				} catch (error) {
					send(res, 500, { error: String((error && error.message) || error) });
				}
			}
		},
		{
			path: POINT + "/report.md",
			method: "GET",
			handler: async (req, res) => {
				try {
					const url = new URL(req.url || "/", "http://127.0.0.1");
					const markdown = sessionReportMarkdown(url.searchParams.get("sessionId") || "");
					if (markdown === null) {
						send(res, 404, { error: "该会话没有渗透图（尚未调用 pentest_add_goal）" });
						return;
					}
					res.statusCode = 200;
					res.setHeader("content-type", "text/markdown; charset=utf-8");
					res.setHeader("cache-control", "no-store");
					res.end(markdown);
				} catch (error) {
					send(res, 500, { error: String((error && error.message) || error) });
				}
			}
		},
		{
			path: POINT + "/topology",
			method: "GET",
			handler: async (req, res) => {
				serveTopology(req, res);
			}
		},
		{
			path: POINT + "/evidence",
			method: "GET",
			handler: async (req, res) => {
				serveEvidence(req, res);
			}
		}
	];
	for (const route of routes) {
		try {
			const disposer = ctx.webServer.register(route);
			if (disposer) disposers.push(disposer);
		} catch (e) {
			console.error("[pipadeep-engagements] register " + route.path + ":", e && e.message);
		}
	}
	return () => {
		for (const disposer of disposers) {
			try {
				disposer();
			} catch (e) {
				/* noop */
			}
		}
	};
}

export { name, inject, apply, listEngagements, graphFor, serveTopology, retestFor };
