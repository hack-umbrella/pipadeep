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
 *   8. 工具 schema 不合法（array 缺 items / output.schema 缺 type+additionalProperties）
 *      → 插件加载失败、整份预设建不了会话。
 *   7. 打包漏文件（files 字段配错）→ 用户装上后缺预设/技能/脚本；
 *      连带上游：相对 import 的目标没进包 → 插件加载失败（预设整份不可用）。
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

// ── 2b. peer 必须覆盖 dsh.support 声明的每条版本线 ────────────────────────────
// `^0.1.0-rc.6` = `>=0.1.0-rc.6 <0.2.0`，**天然不含 0.2.x** —— 升到 0.2 线时安装门禁
// 会直接拒装（实测 0.2.1-alpha.2 上 `installation rejected`）。这里按「次版本线」判断，
// 比解析完整 semver 范围更稳，也正好拦住这类漏改。
console.log("\n── 2b. peer 覆盖 dsh.support 声明的版本线 ──");
const supportLines = Array.isArray(pkg.dsh?.support) ? pkg.dsh.support.map(String) : [];
check("声明了 dsh.support（支持的 dsh 版本线）", supportLines.length > 0, JSON.stringify(supportLines));
for (const line of supportLines) {
	const covered = Object.values(pkg.peerDependencies ?? {}).some((range) =>
		String(range)
			.split("||")
			.some((alt) => {
				const m = /^\s*[\^~]?\s*(\d+)\.(\d+)/.exec(alt);
				return m !== null && `${m[1]}.${m[2]}` === line;
			}),
	);
	check(`peer 覆盖 dsh ${line}.x`, covered, "peer 里没有该次版本线 —— 安装门禁会按 includePrerelease 判定为不兼容");
}

// ── 2c. dsh 系 peer 必须声明为 optional ──────────────────────────────────────
// 事故：peer 非 optional 时 pnpm 会把 dsh 包装成**副本**进 profile 的 `.pnpm`。
// 预设 composition 里的行从插件目录向上解析，会落到 pnpm 的 `.pnpm/node_modules`
// 提升层拿到那些副本；换代 dsh 后副本版本与宿主不匹配 → dsh 判定「composition
// reaches an incompatible plugin」并**禁用整份预设**（症状：预设里的工具凭空消失，
// 日志有 `disabling profile plugin row "<name>-composition"`）。
// 声明 optional 后 pnpm 不装副本，解析落到 profile 的共享层（随 dsh 一起升级）。
console.log("\n── 2c. dsh 系 peer 应声明 optional（避免 pnpm 装出副本）──");
const dshPeers = Object.keys(pkg.peerDependencies ?? {}).filter((name) => name.startsWith("@deepseek-ai/"));
const notOptional = dshPeers.filter((name) => pkg.peerDependenciesMeta?.[name]?.optional !== true);
check(
	`dsh 系 peer 全部 optional（共 ${dshPeers.length} 个）`,
	dshPeers.length > 0 && notOptional.length === 0,
	notOptional.length === 0 ? "没有 @deepseek-ai/* peer" : `未声明 optional：${notOptional.join(", ")}`,
);

// ── 2d. 客户端快照字段必须覆盖 dsh 0.2（`current` 已被移除）──────────────────
// 事故：客户端用 `sessions.list.getSnapshot().current` 判断“当前会话”，dsh 0.2 的
// 快照改成 {ids, byId, phase, projectionsBySession}（**没有 current**）→ 判定恒为
// undefined → 按会话注册的视图（如渗透 tab）永远不挂载，且页面零报错、日志零报错，
// 只有肉眼看 UI 才能发现。凡引用 `snapshot.current` 的客户端必须同时带 0.2 回退。
console.log("\n── 2d. 客户端快照字段兼容 dsh 0.2 ──");
const clientFile = pkg.exports?.["./client"]?.default ?? pkg.exports?.["./client"] ?? pkg.client;
const clientPath = typeof clientFile === "string" ? join(ROOT, clientFile) : undefined;
if (clientPath === undefined || !existsSync(clientPath)) {
	console.log("  · 跳过（包未声明客户端 bundle）");
} else {
	const bundle = readFileSync(clientPath, "utf8");
	const usesCurrent = /snapshot\.current|\.current\b/.test(bundle) && /getSnapshot\(\)/.test(bundle);
	const hasFallback = bundle.includes("projectionsBySession");
	check(
		"用到 snapshot.current 时带 0.2 回退（projectionsBySession）",
		!usesCurrent || hasFallback,
		!usesCurrent ? "未使用 snapshot.current" : "缺 projectionsBySession 回退：dsh 0.2 上按会话挂载的视图会静默失效",
	);
}

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
	// ── 6c. 工具参数里的数组必须声明 items ───────────────────────────────────────
// 事故：新增工具的 `files: { type: "array" }` 没写 items → dsh 报
// `unsupported JSON schema: schema.type must be …`，**插件加载失败、整份预设建不了会话**，
// 而这种错误只有在用户建会话时才暴露。这里静态扫源码，打包前就拦下。
console.log("\n── 6c. 工具 schema：array 必须带 items ──");
const schemaSources = [];
for (const dir of ["lib", "preset"]) {
	const base = join(ROOT, dir);
	if (!existsSync(base)) continue;
	for (const entry of readdirSync(base, { recursive: true })) {
		const file = join(base, String(entry));
		if (!/\.(m?js|cjs|yml|yaml)$/.test(file)) continue;
		let stat;
		try { stat = statSync(file); } catch { continue; }
		if (stat.isFile()) schemaSources.push(file);
	}
}
const arrayWithoutItems = [];
/**
 * 找到 `type: "array"` 之后、**同一个对象字面量内**是否声明了 items。
 * 直接按窗口长度猜会误报（长 description 之后才有 items，本仓库里就有 4 处），
 * 所以先把字符串字面量等长屏蔽掉，再按大括号深度扫描。
 */
function arrayLacksItems(text) {
	const arrayAt = [];
	for (const match of text.matchAll(/type:\s*"array"/g)) arrayAt.push(match.index + match[0].length);
	if (arrayAt.length === 0) return [];
	const masked = text.replace(/"(?:[^"\\]|\\.)*"/g, (s) => "\u0000".repeat(s.length));
	const bad = [];
	for (const start of arrayAt) {
		let depth = 0;
		let found = false;
		for (let i = start; i < masked.length; i += 1) {
			const ch = masked[i];
			if (ch === "{") depth += 1;
			else if (ch === "}") {
				if (depth === 0) break;
				depth -= 1;
			} else if (depth === 0 && masked.startsWith("items", i)) { found = true; break; }
		}
		if (!found) bad.push(start);
	}
	return bad;
}
for (const file of schemaSources) {
	const text = readFileSync(file, "utf8");
	for (const index of arrayLacksItems(text)) {
		arrayWithoutItems.push(`${relative(ROOT, file)}: 第 ${text.slice(0, index).split("\n").length} 行`);
	}
}
check("array 参数都声明了 items", arrayWithoutItems.length === 0, arrayWithoutItems.slice(0, 5).join("; "));

// ── 6e. output.schema 必须声明 type 与 additionalProperties ───────────────────
// 事故：新工具的 output.schema 漏了 `type: "object"` 与 `additionalProperties`
// → dsh 报 `unsupported JSON schema: schema.type must be …`，插件加载失败、整份预设建不了会话。
// （用宿主 defineTool 逐变体压过：补上这两项才通过。）
console.log("\n── 6e. output.schema 需 type + additionalProperties ──");
const badOutput = [];
for (const file of schemaSources.filter((f) => /\.(m?js|cjs)$/.test(f))) {
	const text = readFileSync(file, "utf8");
	for (const match of text.matchAll(/output:\s*\{\s*schema:\s*\{/g)) {
		const window = text.slice(match.index, match.index + 400);
		if (!/type:\s*["']object["']/.test(window) || !/additionalProperties\s*:/.test(window)) {
			badOutput.push(`${relative(ROOT, file)}: 第 ${text.slice(0, match.index).split("\n").length} 行`);
		}
	}
}
check("output.schema 都声明了 type/additionalProperties", badOutput.length === 0, badOutput.slice(0, 4).join("; "));

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

		// 6b. 相对 import 的目标必须真的在包里。
		// 事故：files 写了 `lib/**/*.js` 却漏 `lib/**/*.mjs`，而插件 `import "./ingest.mjs"`
		// 在用户机器上直接加载失败（整个预设不可用）——固定清单式的检查发现不了这种漂移。
		const packedSet = new Set(list.map((entry) => entry.replace(/^package\//, "")));
		const missingImports = [];
		for (const file of [...packedSet].filter((entry) => /\.(m?js|cjs)$/.test(entry))) {
			const text = readFileSync(join(ROOT, file), "utf8");
			for (const match of text.matchAll(/(?:from\s*|import\s*\(\s*)["'](\.[^"']+)["']/g)) {
				const target = relative(ROOT, resolve(dirname(join(ROOT, file)), match[1])).split("\\").join("/");
				if (!packedSet.has(target)) missingImports.push(`${file} → ${match[1]}`);
			}
		}
		check("相对 import 的目标都随包分发", missingImports.length === 0, [...new Set(missingImports)].slice(0, 6).join("; "));
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
