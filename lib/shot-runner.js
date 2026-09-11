// @pipadeep/dsh-pentest — 浏览器截图执行器（本机 Playwright）
//
// 由 `pentest_shot` 工具以子进程方式调用：
//     node shot-runner.js <config.json>
// 只向 stdout 打印一行 JSON 结果（诊断信息一律走 stderr），供工具解析。
//
// 设计要点：
//   - 本机 Chrome（channel=chrome）+ headless=new（Playwright 默认），真实视口与字体；
//   - 经 --proxy-server 走 mitmproxy 链（上游可转发 Burp），并携带证据标记头
//     X-Pentest-Evidence=<runId>，让代理侧按标记精确关联本次截图与原始请求；
//   - ignoreHTTPSErrors 默认开（代理链多层 TLS，渗透场景可接受）；
//   - 截图落盘 + 记录 title/finalUrl/状态码/控制台错误，供报告与证据链使用。
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

function log(...args) {
	process.stderr.write("[shot-runner] " + args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ") + "\n");
}

async function loadPlaywright() {
	const require = createRequire(import.meta.url);
	const failures = [];
	const home = process.env.HOME || "";
	const searchPaths = [];
	if (home) searchPaths.push(home + "/node_modules", home + "/.local/lib/node_modules");
	if (process.env.PENTEST_NODE_PATH) searchPaths.push(...String(process.env.PENTEST_NODE_PATH).split(":").filter(Boolean));
	const attempts = [];
	if (process.env.PENTEST_PLAYWRIGHT) attempts.push({ spec: process.env.PENTEST_PLAYWRIGHT });
	attempts.push({ spec: "playwright" }, { spec: "playwright-core" });

	for (const attempt of attempts) {
		try {
			let entry = null;
			if (isAbsolute(attempt.spec)) {
				entry = attempt.spec;
			} else {
				const pkgPath = require.resolve(attempt.spec + "/package.json", { paths: searchPaths });
				const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
				const dot = pkg.exports && pkg.exports["."];
				const rel = (dot && (typeof dot === "object" ? dot.import || dot.default : dot)) || pkg.module || pkg.main || "index.js";
				entry = dirname(pkgPath) + "/" + String(rel).replace(/^\.\//, "");
			}
			const mod = await import(pathToFileURL(entry).href);
			const pw = mod.chromium ? mod : mod.default || mod;
			if (pw && pw.chromium) return pw;
			failures.push(attempt.spec + " -> 无 chromium 导出");
		} catch (error) {
			failures.push(attempt.spec + ": " + String((error && error.message) || error).split("\n")[0]);
		}
	}
	throw new Error("playwright 不可用（npm i -g playwright，或用 PENTEST_PLAYWRIGHT / PENTEST_NODE_PATH 指定）：" + failures.join("; "));
}

async function runStep(page, step, state) {
	const type = String(step.type || "");
	const timeout = Number(step.timeoutMs || state.timeoutMs);
	switch (type) {
		case "goto":
			await page.goto(step.url || state.url, { waitUntil: step.waitUntil || "domcontentloaded", timeout });
			return;
		case "fill":
			await page.fill(step.selector, String(step.value === undefined ? "" : step.value), { timeout });
			return;
		case "type":
			await page.locator(step.selector).pressSequentially(String(step.value === undefined ? "" : step.value), { timeout, delay: Number(step.delayMs || 0) });
			return;
		case "click":
			await page.click(step.selector, { timeout, button: step.button });
			return;
		case "press":
			if (step.selector) await page.press(step.selector, String(step.key || "Enter"), { timeout });
			else await page.keyboard.press(String(step.key || "Enter"));
			return;
		case "hover":
			await page.hover(step.selector, { timeout });
			return;
		case "select":
			await page.selectOption(step.selector, String(step.value === undefined ? "" : step.value), { timeout });
			return;
		case "waitForSelector":
			await page.waitForSelector(step.selector, { timeout, state: step.state || "visible" });
			return;
		case "waitForURL":
			await page.waitForURL(step.url || "**", { timeout });
			return;
		case "wait":
		case "waitForTimeout":
			await page.waitForTimeout(Number(step.ms || 1000));
			return;
		case "evaluate":
			await page.evaluate(String(step.script || "1"));
			return;
		case "screenshot": {
			const name = String(step.name || ("shot-" + (state.shots.length + 1)));
			await takeScreenshot(page, state, name, step.fullPage !== undefined ? step.fullPage : state.fullPage);
			return;
		}
		default:
			throw new Error("未知步骤类型: " + type);
	}
}

async function takeScreenshot(page, state, name, fullPage) {
	const file = state.outDir + "/" + state.fileBase + (name && name !== "shot-1" ? "-" + name.replace(/[^\w.-]+/g, "_") : "") + ".png";
	await page.screenshot({ path: file, fullPage: !!fullPage });
	state.shots.push(file);
	log("screenshot", file, "fullPage=" + !!fullPage);
}

async function main() {
	const configPath = process.argv[2];
	if (!configPath) throw new Error("用法: node shot-runner.js <config.json>");
	const cfg = JSON.parse(readFileSync(configPath, "utf8"));
	const outDir = cfg.outDir;
	mkdirSync(outDir, { recursive: true });

	const { chromium } = await loadPlaywright();
	const state = {
		url: cfg.url,
		timeoutMs: Number(cfg.timeoutMs || 30000),
		fullPage: cfg.fullPage !== false,
		outDir,
		fileBase: cfg.fileBase || "shot",
		shots: []
	};

	const launchOptions = {
		channel: cfg.channel || "chrome",
		headless: cfg.headless !== false
	};
	if (Array.isArray(cfg.launchArgs) && cfg.launchArgs.length > 0) launchOptions.args = cfg.launchArgs;
	const browser = await chromium.launch(launchOptions);
	let context;
	try {
		const contextOptions = {
			viewport: cfg.viewport || { width: 1440, height: 900 },
			ignoreHTTPSErrors: cfg.ignoreHTTPSErrors !== false,
			extraHTTPHeaders: Object.assign(
				{ "X-Pentest-Evidence": String(cfg.runId || "") },
				cfg.headers || {}
			)
		};
		if (cfg.proxy) contextOptions.proxy = { server: String(cfg.proxy) };
		if (cfg.locale) contextOptions.locale = String(cfg.locale);
		if (cfg.userAgent) contextOptions.userAgent = String(cfg.userAgent);
		if (cfg.storageState) contextOptions.storageState = cfg.storageState;
		context = await browser.newContext(contextOptions);
		if (Array.isArray(cfg.cookies) && cfg.cookies.length > 0) {
			const cookies = cfg.cookies.map((c) => (typeof c === "string" ? parseCookie(c, cfg.url) : c)).filter(Boolean);
			if (cookies.length > 0) await context.addCookies(cookies);
		}
		const page = await context.newPage();
		const consoleErrors = [];
		page.on("console", (m) => {
			if (m.type() === "error") consoleErrors.push(String(m.text()).slice(0, 300));
		});
		page.on("pageerror", (e) => consoleErrors.push("pageerror: " + String(e.message).slice(0, 300)));

		let response = null;
		page.on("response", (r) => {
			if (response === null && r.request().isNavigationRequest()) response = r;
		});

		const steps = Array.isArray(cfg.steps) && cfg.steps.length > 0 ? cfg.steps : [{ type: "goto" }];
		for (const step of steps) await runStep(page, step, state);
		if (state.shots.length === 0) await takeScreenshot(page, state, "shot-1", state.fullPage);

		const result = {
			ok: true,
			screenshots: state.shots,
			title: await page.title().catch(() => ""),
			finalUrl: page.url(),
			status: response ? response.status() : null,
			contentType: response ? (response.headers()["content-type"] || "") : "",
			consoleErrors: consoleErrors.slice(0, 10),
			proxy: cfg.proxy || null,
			runId: cfg.runId || null
		};
		process.stdout.write(JSON.stringify(result) + "\n");
	} finally {
		if (context) await context.close().catch(() => {});
		await browser.close().catch(() => {});
	}
}

/** Parse `name=value` (optionally `domain:name=value`) into a Playwright cookie. */
function parseCookie(raw, url) {
	const text = String(raw);
	const eq = text.indexOf("=");
	if (eq <= 0) return null;
	const name = text.slice(0, eq).trim();
	const value = text.slice(eq + 1).trim();
	let cookieUrl = url;
	try {
		cookieUrl = new URL(url).origin;
	} catch (e) {
		/* keep raw */
	}
	return { name, value, url: cookieUrl };
}

main().catch((error) => {
	process.stdout.write(
		JSON.stringify({
			ok: false,
			error: error && error.message ? error.message : String(error),
			stack: error && error.stack ? String(error.stack).split("\n").slice(0, 4) : undefined
		}) + "\n"
	);
	process.exitCode = 1;
});
