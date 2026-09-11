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

export { name, inject, apply, listEngagements };
