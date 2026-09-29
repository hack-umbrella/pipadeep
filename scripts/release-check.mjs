#!/usr/bin/env node
/**
 * 发版自检：把「发出去才发现」的几类错误在打包前拦掉。**与仓库无关，两个插件仓库共用同一份。**
 *
 * 每一项都对应一次真实事故：
 *   1. 客户端 bundle 的注册 id 与 loader 行包名不一致 → dsh 报
 *      `bundle … loaded without registering "<pkg>" via __ModuleLoader__.load` → 「Failed to load plugins」。
 *      **组装/改名时最容易漏改的一处。**
 *   2. peer 写精确版本 → dsh 0.1.7+ 的安装门禁按 includePrerelease 语义判定，直接拒装。
 *   3. 两份 workflow composition 漂移 → 某代 dsh 上整份预设 `never started`。
 *   4. composition 里出现文件路径（`./plugins/x.mjs` / `/abs/x.mjs`）→ 换机器或换代 dsh 就炸。
 *   5. patch 行的 row 名称映射不到本包 exports → 行加载失败。
 *   6. 机器绝对路径混进发布文件 → 泄漏本机目录结构。
 *   7. 打包漏文件（files 字段配错）→ 用户装上后缺预设/技能/脚本。
 *
 * 用法：
 *   node scripts/release-check.mjs            # 静态检查 + npm pack 内容核对
 *   node scripts/release-check.mjs --no-pack  # 只做静态检查
 *
 * 退出码非 0 表示不可发布。
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NO_PACK = process.argv.includes("--no-pack");

let failures = 0;
let checks = 0;
const ok = (label) => {
	checks += 1;
	console.log(`  ✓ ${label}`);
};
const bad = (label, detail = "") => {
	checks += 1;
	failures += 1;
	console.log(`  ✗ ${label}${detail === "" ? "" : `\n      ${detail}`}`);
};
const check = (label, condition, detail = "") => (condition ? ok(label) : bad(label, detail));

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const PATCH = pkg.dsh?.bundle?.patch ?? "cordis.patch.yml";
console.log(`\n包：${pkg.name}@${pkg.version}`);

// ── 1. package.json 基本形态 ────────────────────────────────────────────────
console.log("\n── 1. package.json ──");
check("有 name / version", typeof pkg.name === "string" && typeof pkg.version === "string");
const clientExport = pkg.exports?.["./client"];
check(
	"exports[./client] 指向存在文件",
	typeof clientExport === "string" && existsSync(join(ROOT, clientExport)),
	JSON.stringify(clientExport),
);
check("dsh.bundle.patch 指向存在文件", existsSync(join(ROOT, PATCH)), PATCH);
check("dsh.client.platform = web", pkg.dsh?.client?.platform === "web");

// ── 2. peer 范围必须可覆盖预发布版本（dsh 0.1.7+ 安装门禁）───────────────────
console.log("\n── 2. peer 范围（安装门禁按 includePrerelease 判定）──");
const exactPeers = Object.entries(pkg.peerDependencies ?? {}).filter(([, range]) => !/^[\^~]|^\*$|>/.test(range));
check("peer 没有精确钉死的版本（须用 ^/~/范围）", exactPeers.length === 0, exactPeers.map(([k, v]) => `${k}@${v}`).join(", "));

// ── 3. 客户端 bundle 注册 id === 包名（最容易漏改的一处）────────────────────
console.log("\n── 3. 客户端 bundle 注册 id ──");
const packagedFiles = [...new Set((pkg.files ?? []).flatMap((entry) => expand(entry)))];
// 客户端 bundle 以 `exports["./client"]` 为准：按 marker 全文扫描会把本脚本自己也算进来
// （脚本里含有该 marker 的正则字面量）。declare 的那一份才是 client-modules 会加载的。
const declaredClient = typeof clientExport === "string" ? join(ROOT, clientExport) : undefined;
check(
	"exports[./client] 的文件里有 __ModuleLoader__.load 注册",
	declaredClient !== undefined && /__ModuleLoader__\.load\(\{\s*id:/.test(safeRead(declaredClient)),
	clientExport ?? "(未声明)",
);
for (const file of declaredClient === undefined ? [] : [declaredClient]) {
	const rel = relative(ROOT, file);
	const ids = [...safeRead(file).matchAll(/__ModuleLoader__\.load\(\{\s*id:\s*"([^"]+)"/g)].map((m) => m[1]);
	const wrong = ids.filter((id) => id !== pkg.name);
	check(
		`${rel} 注册 id 等于包名（${ids.length} 处）`,
		ids.length > 0 && wrong.length === 0,
		wrong.length === 0 ? "未找到 __ModuleLoader__.load({id})" : `不符：${wrong.join(", ")}（应为 ${pkg.name}）`,
	);
}
// 顺带查一遍其它打包文件里有没有残留的旧注册 id（改名/搬运后最容易忘）
const stale = [];
for (const file of packagedFiles) {
	const rel = relative(ROOT, file);
	if (rel.startsWith("scripts/")) continue;
	if (!/\.(?:js|mjs)$/.test(rel)) continue;
	for (const m of safeRead(file).matchAll(/__ModuleLoader__\.load\(\{\s*id:\s*"([^"]+)"/g)) {
		if (m[1] !== pkg.name) stale.push(`${rel} → ${m[1]}`);
	}
}
check("没有残留的旧注册 id", stale.length === 0, stale.join("; "));

// ── 4. patch 行的 row 名称必须能映射到本包 exports ──────────────────────────
console.log("\n── 4. cordis.patch.yml 的 row ──");
const patchText = readFileSync(join(ROOT, PATCH), "utf8");
const rowNames = [...patchText.matchAll(/^\s*name:\s*['"]?([^'"\n]+)['"]?\s*$/gm)]
	.map((m) => m[1].trim())
	.filter((name) => name.startsWith(pkg.name));
check("patch 里有指向本包的 row", rowNames.length > 0, PATCH);
for (const name of rowNames) {
	const sub = name === pkg.name ? "." : `./${name.slice(pkg.name.length + 1)}`;
	const target = pkg.exports?.[sub];
	check(`row ${name} → exports["${sub}"]`, typeof target === "string" && existsSync(join(ROOT, target)), JSON.stringify(target));
}
check(
	"patch 里没有相对/绝对路径行",
	!/^\s*name:\s*['"](?:\.|\/)/m.test(patchText),
	"patch 行名出现了 './…' 或绝对路径",
);

// ── 5. preset composition：必须成对、只差 workflow 两行、不出现文件路径 ──────
console.log("\n── 5. preset composition ──");
const compositions = packagedFiles.filter((file) => /agent\.cordis[^/]*\.yml$/.test(file)).map((file) => relative(ROOT, file));
const base = compositions.find((rel) => !/\.next\.yml$/.test(rel));
const next = compositions.find((rel) => /\.next\.yml$/.test(rel));
check("发现成对的 workflow 变体（agent.cordis.yml + agent.cordis.next.yml）", base !== undefined && next !== undefined, JSON.stringify(compositions));
if (base !== undefined && next !== undefined) {
	const strip = (text) => text.split("\n").filter((line) => !/^\s*#/.test(line) && line.trim() !== "");
	const a = strip(readFileSync(join(ROOT, base), "utf8"));
	const b = strip(readFileSync(join(ROOT, next), "utf8"));
	const diffs = a.map((line, i) => (line === b[i] ? null : [i, line, b[i]])).filter(Boolean);
	check("两份变体行数一致", a.length === b.length, `${a.length} vs ${b.length}`);
	check(
		"差异恰为 workflow provider 两行",
		diffs.length === 2 && /worker-thread/.test(diffs[0][1]) && /ptc/.test(diffs[0][2]),
		JSON.stringify(diffs),
	);
	for (const rel of [base, next]) {
		const text = readFileSync(join(ROOT, rel), "utf8");
		check(`${rel} 没有相对/绝对文件路径行`, !/^\s*name:\s*['"](?:\.|\/)/m.test(text), "composition 里出现 './…' 或绝对路径");
	}
}
const presetYmls = packagedFiles.filter((file) => /\/preset\.yml$/.test(file));
check("预设目录带 preset.yml", presetYmls.length > 0, JSON.stringify(presetYmls.map((f) => relative(ROOT, f))));

// ── 6. 不泄漏本机路径 ───────────────────────────────────────────────────────
console.log("\n── 6. 机器路径泄漏 ──");
const leaked = [];
for (const file of packagedFiles) {
	const rel = relative(ROOT, file);
	if (!/\.(mjs|js|json|yml|yaml|md|txt|py)$/.test(rel)) continue;
	const text = safeRead(file);
	for (const pattern of [/\/Users\/[A-Za-z0-9._-]+/, /\/home\/[A-Za-z0-9._-]+/, /[A-Z]:\\\\Users\\\\/]) {
		if (pattern.test(text)) leaked.push(`${rel} 命中 ${pattern}`);
	}
}
check("打包文件里没有 /Users、/home 或 C:\\Users 绝对路径", leaked.length === 0, leaked.slice(0, 5).join("; "));

// ── 7. 打包内容完整 ─────────────────────────────────────────────────────────
if (!NO_PACK) {
	console.log("\n── 7. npm pack 内容 ──");
	try {
		const out = execFileSync("npm", ["pack", "--silent"], { cwd: ROOT, encoding: "utf8" }).trim().split("\n").pop();
		const list = execFileSync("tar", ["tzf", out], { cwd: ROOT, encoding: "utf8" }).split("\n").filter((line) => line !== "");
		const packed = (target) => `package/${String(target).replace(/^\.\//, "")}`;
		const required = [
			"package/package.json",
			packed(PATCH),
			...(typeof clientExport === "string" ? [packed(clientExport)] : []),
			...compositions.map((rel) => packed(rel)),
			...presetYmls.map((file) => packed(relative(ROOT, file))),
			...rowNames
				.map((name) => (name === pkg.name ? "." : `./${name.slice(pkg.name.length + 1)}`))
				.map((sub) => pkg.exports?.[sub])
				.filter((target) => typeof target === "string")
				.map((target) => packed(target)),
		];
		const missing = [...new Set(required)].filter((needle) => !list.includes(needle));
		check("tarball 含全部必需文件", missing.length === 0, `缺失：${missing.join(", ")}`);
		console.log(`      tarball: ${out}（${list.length - 1} 个文件）`);
	} catch (error) {
		bad("npm pack 失败", String((error && error.message) || error));
	}
}

console.log(`\n═══ ${checks - failures}/${checks} 通过${failures === 0 ? " —— 可以发布" : ` —— ${failures} 项失败，不可发布`} ═══\n`);
process.exit(failures === 0 ? 0 : 1);

/** 展开 package.json files 里的一条例（`dir/**` → 该目录下所有文件）。 */
function expand(entry) {
	const head = entry.replace(/\/\*\*.*$/, "").replace(/\*+$/, "");
	const full = join(ROOT, head);
	if (!existsSync(full)) return [];
	try {
		return statSync(full).isFile() ? [full] : walkAll(full);
	} catch {
		return [];
	}
}

function walkAll(dir) {
	const out = [];
	const stack = [dir];
	while (stack.length > 0) {
		const current = stack.pop();
		let entries = [];
		try {
			entries = readdirSync(current, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "__pycache__") continue;
			const full = join(current, entry.name);
			if (entry.isDirectory()) stack.push(full);
			else if (entry.isFile()) out.push(full);
		}
	}
	return out;
}

function safeRead(file) {
	try {
		return readFileSync(file, "utf8");
	} catch {
		return "";
	}
}
