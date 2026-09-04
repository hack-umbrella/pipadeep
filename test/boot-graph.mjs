/**
 * L5 冒烟测试：boot graph 必须含 @pipadeep/dsh-pentest。
 *
 * 背景（v1.0.0 事故）：loader 行名用了子路径，client-modules 扫描器静默跳过，
 * 客户端 bundle 从未进入 __DSH_BOOT__，「渗透」UI 完全不加载且无任何报错。
 *
 * 本测试起一个临时 `dsh web`（端口 0），用启动 URL 的 token 换 cookie，
 * 断言：
 *  1. 首页 __DSH_BOOT__ 图含 "id":"@pipadeep/dsh-pentest"；
 *  2. 下发的 client bundle 首个注册 id 与图行一致（裸包名）；
 *  3. engagements 数据路由可达（200 且含 engagements 数组）。
 *
 * 运行：node test/boot-graph.mjs   （需要 dsh 在 PATH；失败退出码 1）
 */
import { spawn } from "node:child_process";

const TIMEOUT_MS = 90_000;

function wait(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
	const child = spawn("dsh", ["web", "--port", "0", "--no-open"], {
		stdio: ["ignore", "pipe", "pipe"]
	});
	let output = "";
	child.stdout.on("data", (chunk) => {
		output += String(chunk);
	});
	child.stderr.on("data", (chunk) => {
		output += String(chunk);
	});
	const started = Date.now();
	let url = null;
	while (Date.now() - started < 30_000) {
		const match = output.match(/https?:\/\/\S+/);
		if (match) {
			url = match[0];
			break;
		}
		await wait(500);
	}
	if (!url) {
		child.kill("SIGTERM");
		console.error("FAIL: dsh web 未在 30s 内打印启动 URL");
		process.exit(1);
	}
	try {
		const tokenExchange = await fetch(url, { redirect: "manual" });
		const cookie = (tokenExchange.headers.get("set-cookie") || "").split(";")[0];
		if (!cookie) throw new Error("no auth cookie from token exchange");
		const page = await (await fetch(new URL("/", url), { headers: { cookie } })).text();

		const failures = [];
		if (!page.includes('"id":"@pipadeep/dsh-pentest"')) failures.push("boot graph 缺少 @pipadeep/dsh-pentest（v1.0.0 类回归）");
		const bundleMatch = page.match(/\/plugins\/\?\?@pipadeep\/dsh-pentest\/client\.js&rev=[0-9a-f-]+/);
		if (bundleMatch) {
			const bundle = await (await fetch(new URL(bundleMatch[0], url), { headers: { cookie } })).text();
			if (!/id: "@pipadeep\/dsh-pentest"/.test(bundle)) failures.push("client bundle 注册 id 不是裸包名（与图行不一致）");
		} else {
			failures.push("boot graph 未下发 @pipadeep/dsh-pentest 的 client bundle URL");
		}
		const engagements = await fetch(new URL("/api/pipadeep-pentest/engagements", url), { headers: { cookie } });
		const engagementsBody = await engagements.text();
		if (engagements.status !== 200 || !engagementsBody.includes('"engagements"')) {
			failures.push(`engagements 路由异常: HTTP ${engagements.status}`);
		}
		if (failures.length > 0) {
			console.error("FAIL:\n  - " + failures.join("\n  - "));
			process.exitCode = 1;
		} else {
			console.log("OK: boot graph 含 pentest 客户端、bundle id 一致、engagements 路由可达");
		}
	} catch (error) {
		console.error("FAIL:", error && error.message);
		process.exitCode = 1;
	} finally {
		child.kill("SIGTERM");
	}
}

const timer = setTimeout(() => {
	console.error("FAIL: 超时");
	process.exit(1);
}, TIMEOUT_MS);
main().finally(() => clearTimeout(timer));
