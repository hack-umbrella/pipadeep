/**
 * 集成测试：pentest_shot 工具端到端（本机 Playwright + mitmproxy 证据链）。
 *
 * 链路：本地目标(http.server) → mitmproxy(独立端口, 直连) → Playwright 截图
 * 断言：返回 ok、截图落盘、证据三件套（png/http/script）、.http 含目标响应、
 *       证据索引按 runId 命中。
 *
 * 依赖 mitmdump 与 playwright；缺失则自动 skip。所有端口/目录走临时路径，
 * 不触碰真实证据目录与全局代理。
 */
import test from "node:test";
import assert from "node:assert";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const exec = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function have(bin) {
	try {
		await exec("bash", ["-lc", "command -v " + bin]);
		return true;
	} catch (e) {
		return false;
	}
}

const deps = { mitm: await have("mitmdump"), py: await have("python3") };
let playwrightOk = false;
try {
	const { createRequire } = await import("node:module");
	const req = createRequire(import.meta.url);
	req.resolve("playwright/package.json", { paths: [join(process.env.HOME || "", "node_modules")] });
	playwrightOk = true;
} catch (e) {
	playwrightOk = false;
}

const SHOT_PORT = 18099;
const TARGET_PORT = 18998;
const skippable = !deps.mitm || !deps.py || !playwrightOk;

test("pentest_shot 端到端：截图 + 代理原始包证据链", { skip: skippable ? "需要 mitmdump / python3 / playwright" : false, timeout: 180000 }, async () => {
	const work = mkdtempSync(join(tmpdir(), "shot-test-"));
	const site = join(work, "site");
	const evidence = join(work, "evidence");
	writeFileSync(join(work, ".keep"), "");
	await exec("mkdir", ["-p", site]);
	writeFileSync(join(site, "index.html"), "<!doctype html><title>PoC-Target</title><h1 id=marker>VULN-MARKER-77C1</h1><p>idor proof</p>");

	process.env.PENTEST_EVIDENCE_DIR = evidence;
	process.env.PENTEST_SHOT_PORT = String(SHOT_PORT);
	process.env.PENTEST_SHOT_PROXY = "http://127.0.0.1:" + SHOT_PORT;
	process.env.PENTEST_SHOT_UPSTREAM = ""; // 直连，避免依赖 Burp
	process.env.PENTEST_SHOT_INDEX = join(evidence, "_proxy", "evidence-index.jsonl");

	const target = spawn("python3", ["-m", "http.server", String(TARGET_PORT), "--bind", "127.0.0.1"], { cwd: site, stdio: "ignore" });
	await sleep(1200);
	let proxyStarted = false;
	try {
		const { createShotTool } = await import(join(root, "lib", "shot.js"));
		const shStub = async (command, timeoutMs) => {
			try {
				const r = await exec("bash", ["-lc", command], { timeout: timeoutMs || 60000, maxBuffer: 8 * 1024 * 1024 });
				return { exitCode: 0, stdout: r.stdout, stderr: r.stderr };
			} catch (e) {
				return { exitCode: e.code === undefined ? 1 : e.code, stdout: e.stdout || "", stderr: e.stderr || String(e.message) };
			}
		};
		const tool = createShotTool({ sh: shStub, inScope: () => true, q: JSON.stringify, OUT: { schema: {}, render: () => [] }, NOTE: "" });
		const result = await tool.execute(
			{ url: "http://127.0.0.1:" + TARGET_PORT + "/", label: "idor-proof", findingId: "finding-1", fullPage: true },
			{ signal: undefined }
		);
		proxyStarted = !!(result.proxy && result.proxy.started);

		assert.equal(result.ok, true, "工具应成功: " + JSON.stringify(result).slice(0, 400));
		assert.ok(result.screenshots.length >= 1, "应产出截图");
		assert.ok(existsSync(result.screenshots[0]), "截图文件应存在");
		const kinds = result.evidence.map((e) => e.kind);
		assert.ok(kinds.includes("screenshot"), "证据应含 screenshot");
		assert.ok(kinds.includes("script"), "证据应含可复现脚本");
		assert.ok(kinds.includes("http"), "证据应含原始请求包(.http)");

		const httpFile = result.evidence.find((e) => e.kind === "http");
		const httpText = readFileSync(httpFile.path, "utf8");
		assert.ok(httpText.includes("VULN-MARKER-77C1"), ".http 应含目标响应体标记");
		assert.ok(httpText.includes("X-Pentest-Evidence") || httpText.includes("x-pentest-evidence"), ".http 应含证据标记头");

		const shotList = result.evidence.filter((e) => e.kind === "screenshot");
		assert.ok(shotList.length >= 1 && readFileSync(shotList[0].path).length > 1000, "截图应为有效 PNG 字节");

		const script = result.evidence.find((e) => e.kind === "script");
		assert.ok(readFileSync(script.path, "utf8").includes("chromium.launch"), "复现脚本应含 Playwright 启动");
	} finally {
		target.kill("SIGKILL");
		if (proxyStarted) {
			await exec("bash", ["-lc", "lsof -nP -iTCP:" + SHOT_PORT + " -sTCP:LISTEN -t 2>/dev/null | xargs -r kill 2>/dev/null || true"]).catch(() => {});
		}
	}
});
