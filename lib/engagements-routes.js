// 全局渗透任务数据路由（loopback-only、只读）：列出 pentest SQLite 存储中的
// 每一个 engagement（goal + 计数），供 Web「全部任务」面板在任何会话中浏览。
// 对标 bypass-routes 的 `/api/<plugin>/...` 挂载模式；存储库即唯一事实源，
// 不经过会话投影，因此不受任何会话 resume/投影状态影响。
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
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
