// @pipadeep/dsh-pentest — 浏览器截图证据执行器（工具侧编排）
//
// 与 shot-runner.js（Playwright 子进程）配合，产出「截图 + 原始请求包 + 复现脚本」
// 三件套证据：
//   1. 校验 scope（复用 pentest-tools 的门禁）；2. 确保 mitmproxy 证据链在跑
//   （上游可转发 Burp）；3. 子进程跑 Playwright（headless=new）走代理截图；
//   4. 按 runId 从 mitmproxy 证据索引取回精确对应的原始请求/响应；
//   5. 落盘 evidence/<label>/：*.png / *.http / *.shot.mjs，路径回传模型写进 finding。
//
// 仅供已获书面授权的目标。未经授权禁止使用。
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(PLUGIN_DIR, "shot-runner.js");
const ADDON = join(PLUGIN_DIR, "mitm-addon.py");

function dshHome() {
	return process.env.DSH_HOME || join(homedir(), ".dsh");
}

/** Evidence root: every screenshot/raw-packet artifact lives under here. */
export function evidenceRoot() {
	if (process.env.PENTEST_EVIDENCE_DIR) return process.env.PENTEST_EVIDENCE_DIR;
	return join(dshHome(), "storages", "evidence");
}

/** Proxy working dir (index/flows/HAR/log) — one shared chain. */
export function proxyDir() {
	return join(evidenceRoot(), "_proxy");
}

export function evidenceIndexPath() {
	return process.env.PENTEST_SHOT_INDEX || join(proxyDir(), "evidence-index.jsonl");
}

export function defaultProxyUrl() {
	if (process.env.PENTEST_SHOT_PROXY) return process.env.PENTEST_SHOT_PROXY;
	return "http://127.0.0.1:" + String(process.env.PENTEST_SHOT_PORT || 8081);
}

/** Upstream proxy (Burp/Yakit); empty string disables forwarding (direct egress). */
export function defaultUpstream() {
	if (process.env.PENTEST_SHOT_UPSTREAM !== undefined) return process.env.PENTEST_SHOT_UPSTREAM;
	return "http://127.0.0.1:8080";
}

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function portListening(sh, port) {
	const r = await sh("lsof -nP -iTCP:" + Number(port) + " -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -1", 6000);
	return !!(r.stdout && r.stdout.trim());
}

async function haveBinary(sh, bin) {
	const r = await sh("command -v " + bin + " 2>/dev/null | head -1", 6000);
	return !!(r.stdout && r.stdout.trim());
}

/**
 * Ensure the mitmproxy evidence chain is up. Returns the proxy descriptor.
 * Non-fatal: on failure the caller still screenshots (without proxy evidence).
 */
export async function ensureProxy(sh, q) {
	const url = defaultProxyUrl();
	let port = 8081;
	try {
		port = Number(new URL(url).port || 8081);
	} catch (e) {
		/* keep default */
	}
	const index = evidenceIndexPath();
	if (await portListening(sh, port)) return { url, port, started: false, index, ok: true };
	const has = await haveBinary(sh, "mitmdump");
	if (!has) return { url, port, started: false, index, ok: false, error: "mitmdump 未安装（brew install mitmproxy）" };
	const dir = proxyDir();
	mkdirSync(dir, { recursive: true });
	const upstream = defaultUpstream();
	const log = join(dir, "mitm.log");
	let cmd = "PENTEST_SHOT_INDEX=" + q(index) + " PENTEST_SHOT_RAWDIR=" + q(join(dir, "raw")) + " nohup mitmdump --listen-port " + port + " ";
	if (upstream) cmd += "--mode upstream:" + upstream + " --set ssl_insecure=true ";
	cmd += "-s " + q(ADDON) + " -w " + q(join(dir, "flows.mitm")) + " --set hardump=" + q(join(dir, "flows.har")) + " > " + q(log) + " 2>&1 &";
	await sh(cmd, 12000);
	for (let i = 0; i < 25; i += 1) {
		if (await portListening(sh, port)) return { url, port, started: true, upstream, index, ok: true };
		await sleep(300);
	}
	return { url, port, started: false, index, ok: false, error: "mitmdump 启动超时，见 " + log };
}

/** Read the mitmproxy evidence index and return the rows for one runId. */
export function readEvidence(indexPath, runId) {
	if (!existsSync(indexPath)) return [];
	const rows = [];
	let text = "";
	try {
		text = readFileSync(indexPath, "utf8");
	} catch (e) {
		return [];
	}
	for (const line of text.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const row = JSON.parse(trimmed);
			if (row && row.evid === runId) rows.push(row);
		} catch (e) {
			/* skip malformed */
		}
	}
	return rows;
}

function renderHttp(rows) {
	return rows
		.map((row) => {
			const head = "=== " + row.method + " " + row.url + " -> " + (row.status === null ? "?" : row.status) + " (" + (row.durationMs === null ? "?" : row.durationMs + "ms") + ") ===";
			const reqHeaders = Object.entries(row.reqHeaders || {}).map(([k, v]) => k + ": " + v).join("\n");
			const respHeaders = Object.entries(row.respHeaders || {}).map(([k, v]) => k + ": " + v).join("\n");
			return [
				head,
				"--- request headers ---",
				reqHeaders,
				"--- request body ---",
				row.reqBody || "",
				"--- response headers ---",
				respHeaders,
				"--- response body ---",
				row.respBody || "",
				""
			].join("\n");
		})
		.join("\n");
}

function renderReproScript(config, proxyUrl) {
	const safe = (value) => JSON.stringify(value);
	return [
		"// 复现脚本（Playwright）— 由 @pipadeep/dsh-pentest 的 pentest_shot 自动生成",
		"// 运行: node <此文件>   （需 npm i -g playwright；目标需在授权范围内）",
		'import { chromium } from "playwright";',
		"",
		"const CFG = " + JSON.stringify({ url: config.url, steps: config.steps, fullPage: config.fullPage, proxy: proxyUrl, viewport: config.viewport, headers: config.headers, cookies: config.cookies }, null, 2) + ";",
		"",
		"const browser = await chromium.launch({ channel: \"chrome\", headless: true });",
		"const context = await browser.newContext({",
		"  viewport: CFG.viewport || { width: 1440, height: 900 },",
		"  ignoreHTTPSErrors: true,",
		"  extraHTTPHeaders: CFG.headers || {},",
		"  ...(CFG.proxy ? { proxy: { server: CFG.proxy } } : {})",
		"});",
		"if (CFG.cookies && CFG.cookies.length) await context.addCookies(CFG.cookies);",
		"const page = await context.newPage();",
		"for (const step of (CFG.steps && CFG.steps.length ? CFG.steps : [{ type: \"goto\" }])) {",
		"  const t = step.timeoutMs || 30000;",
		"  if (step.type === \"goto\") await page.goto(step.url || CFG.url, { waitUntil: \"domcontentloaded\", timeout: t });",
		"  else if (step.type === \"fill\") await page.fill(step.selector, String(step.value ?? \"\"), { timeout: t });",
		"  else if (step.type === \"click\") await page.click(step.selector, { timeout: t });",
		"  else if (step.type === \"press\") await page.press(step.selector || \"body\", String(step.key || \"Enter\"), { timeout: t });",
		"  else if (step.type === \"waitForSelector\") await page.waitForSelector(step.selector, { timeout: t });",
		"  else if (step.type === \"wait\") await page.waitForTimeout(Number(step.ms || 1000));",
		"  else if (step.type === \"screenshot\") await page.screenshot({ path: (step.name || \"shot\") + \".png\", fullPage: step.fullPage ?? CFG.fullPage });",
		"}",
		"await page.screenshot({ path: \"repro.png\", fullPage: CFG.fullPage !== false });",
		"await browser.close();",
		"console.log(\"repro done:\", page.url());",
		""
	].join("\n");
}

/**
 * Build the `pentest_shot` tool for the execution layer.
 * @param deps - shell runner, scope gate, JSON quoter, output renderer, note text.
 */
export function createShotTool({ sh, inScope, q, OUT, NOTE }) {
	return {
		name: "pentest_shot",
		description:
			"用本机无头浏览器（Playwright/Chrome, headless=new）打开目标并截图，作为漏洞证据。默认经 mitmproxy（上游可转发 Burp）取证：截图同时把该次操作对应的**原始请求/响应**从代理侧取回，落盘为 截图 + .http 原始包 + 可复现 Playwright 脚本，形成「有图有真相」的证据链。务必在已授权目标上使用；先过 pentest_scope。" +
			NOTE,
		parameters: {
			type: "object",
			properties: {
				url: { type: "string", description: "要打开/截图的目标 URL（会做 scope 门禁）。" },
				findingId: { type: "string", description: "可选：关联的 finding id（用于证据目录命名，如 finding-4）。" },
				label: { type: "string", description: "可选：证据标签（如 idor-越权读他人订单），用于文件名/报告说明。" },
				steps: {
					type: "array",
					description:
						"可选：交互步骤序列（默认仅打开 URL 后截图）。支持 {type:goto|fill|click|press|waitForSelector|wait|screenshot|hover|select|evaluate}，字段 selector/value/key/ms/name/fullPage。例：验证 XSS [{\"type\":\"fill\",\"selector\":\"#q\",\"value\":\"<script>alert(1)</script>\"},{\"type\":\"click\",\"selector\":\"#go\"},{\"type\":\"wait\",\"ms\":800},{\"type\":\"screenshot\",\"name\":\"xss\",\"fullPage\":false}]。",
					items: { type: "object", additionalProperties: true }
				},
				fullPage: { type: "boolean", description: "整页截图（默认 true；弹窗/局部证明可设 false）。" },
				headers: { type: "object", additionalProperties: true, description: "可选：附加请求头（如 Cookie、Authorization、X-API-KEY）。" },
				cookies: { type: "array", description: "可选：Cookie 字符串数组，元素形如 'name=value'。", items: { type: "string" } },
				viewport: { type: "object", additionalProperties: true, description: "可选：视口 {width,height}，默认 1440x900。" },
				proxy: { type: "string", description: "可选：覆盖代理地址（默认 mitmproxy http://127.0.0.1:8081）。传空字符串表示直连（无代理证据）。" },
				timeoutMs: { type: "number", description: "可选：单步超时，默认 30000。" }
			},
			required: ["url"]
		},
		output: OUT,
		async execute(args, exec) {
			const url = String(args.url || "").trim();
			if (!/^https?:\/\//i.test(url)) return { error: "url 必须是 http(s):// 开头" };
			if (!inScope(url)) return { error: "目标不在授权 scope 内（见 pentest_scope）", blocked: true };

			const runId = randomUUID();
			const label = String(args.label || "").trim();
			const findingId = String(args.findingId || "").trim();
			const stepList = Array.isArray(args.steps) ? args.steps : [];
			const root = evidenceRoot();
			const outDir = join(root, findingId || "unfiled");
			mkdirSync(outDir, { recursive: true });
			const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "T");
			const base = (label ? label.replace(/[^\w.\u4e00-\u9fa5-]+/g, "_").slice(0, 40) : "shot") + "-" + stamp;

			const proxyArg = args.proxy === undefined ? defaultProxyUrl() : String(args.proxy).trim();
			let proxyInfo = null;
			let proxyUrl = proxyArg;
			if (proxyArg) {
				proxyInfo = await ensureProxy(sh, q);
				proxyUrl = proxyInfo.url || proxyArg;
				if (!proxyInfo.ok) proxyUrl = proxyArg; // best effort: still try the configured proxy
			}

			const config = {
				url,
				runId,
				proxy: proxyUrl || undefined,
				outDir,
				fileBase: base,
				fullPage: args.fullPage !== false,
				steps: stepList.length > 0 ? stepList : [{ type: "goto" }, { type: "screenshot", name: "main" }],
				headers: args.headers && typeof args.headers === "object" ? args.headers : undefined,
				cookies: Array.isArray(args.cookies) ? args.cookies : undefined,
				viewport: args.viewport && typeof args.viewport === "object" ? args.viewport : undefined,
				timeoutMs: Number(args.timeoutMs || 30000),
				headless: true,
				channel: "chrome",
				ignoreHTTPSErrors: true
			};
			const cfgPath = join(outDir, "." + base + ".cfg.json");
			writeFileSync(cfgPath, JSON.stringify(config, null, 2));

			const r = await sh("node " + q(RUNNER) + " " + q(cfgPath) + " 2>" + q(join(outDir, "." + base + ".log")), Number(args.timeoutMs || 30000) + 60000, exec.signal);
			let result = null;
			try {
				result = JSON.parse((r.stdout || "").trim().split("\n").pop());
			} catch (e) {
				return { ok: false, error: "截图进程未返回 JSON", exitCode: r.exitCode, stdout: (r.stdout || "").slice(0, 1000), stderr: (r.stderr || "").slice(0, 1000) };
			}
			if (!result || result.ok !== true) {
				return { ok: false, error: (result && result.error) || "截图失败", exitCode: r.exitCode, stderr: (r.stderr || "").slice(0, 600), proxy: proxyInfo };
			}

			// 证据链：取回本次 runId 对应的原始请求/响应
			const rows = proxyUrl ? readEvidence(evidenceIndexPath(), runId) : [];
			const evidence = [];
			for (const shot of result.screenshots || []) {
				evidence.push({ kind: "screenshot", path: shot, label: label || basename(shot) });
			}
			if (rows.length > 0) {
				const httpPath = join(outDir, base + ".http");
				writeFileSync(httpPath, renderHttp(rows));
				evidence.push({ kind: "http", path: httpPath, label: "原始请求/响应 (" + rows.length + " 条)" });
			}
			const scriptPath = join(outDir, base + ".shot.mjs");
			writeFileSync(scriptPath, renderReproScript(config, proxyUrl));
			evidence.push({ kind: "script", path: scriptPath, label: "可复现 Playwright 脚本" });

			return {
				ok: true,
				runId,
				url: result.finalUrl || url,
				title: result.title || "",
				status: result.status,
				contentType: result.contentType || "",
				screenshots: result.screenshots || [],
				evidence,
				proxy: proxyInfo ? { url: proxyUrl, started: proxyInfo.started, upstream: proxyInfo.upstream || null, ok: proxyInfo.ok, index: evidenceIndexPath() } : { url: null, note: "已禁用代理（无代理证据）" },
				requests: rows.map((row) => ({ method: row.method, url: row.url, status: row.status, contentType: row.contentType })),
				consoleErrors: result.consoleErrors || [],
				hint: "把 evidence 数组原样传给 pentest_add_finding / pentest_submit 的 evidence 字段，报告会嵌入截图。",
				note: NOTE
			};
		}
	};
}

function basename(p) {
	return String(p).split("/").pop();
}
