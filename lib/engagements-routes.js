// 全局渗透任务数据路由（loopback-only、只读）：列出 pentest SQLite 存储中的
// 每一个 engagement（goal + 计数），供 Web「全部任务」面板在任何会话中浏览。
// 对标 bypass-routes 的 `/api/<plugin>/...` 挂载模式；存储库即唯一事实源，
// 不经过会话投影，因此不受任何会话 resume/投影状态影响。
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { extname, join, normalize, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";

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

export { name, inject, apply, listEngagements, graphFor };
