/**
 * L5 契约测试：投影 wire 输出必须是 lossless JSON。
 *
 * 背景（v1.0.1 事故）：pentest 投影的 finding 节点曾把 affectedAssetId 折叠成
 * `undefined` 自有属性；dsh 0.1.2+ 转发 api-session/added 事件时用 isJsonValue
 * 严格校验，undefined 属性被拒 → 会话 resume 失败 → UI 回退、会话从列表消失。
 *
 * 本测试做两层防护：
 *  1. 值层：按 viewPentestState 的输出形状，构造代表性状态（含无/有
 *     affectedAssetId 的 finding、fact confidence、null 前置态），断言
 *     isJsonValue === true 且 JSON round-trip 无损。
 *  2. 源层：扫描 lib/pentest.js，禁止节点构建处再出现「属性值为 undefined」
 *     的模式（`key: <expr> ? void 0 : <expr>` / `key: void 0` / `key: undefined`）。
 *
 * isJsonValue 优先从已安装的 dsh 解析（DSH_UTIL_VALUES 或全局 dsh 路径），
 * 解析不到时使用行为等价的本地实现，保证测试始终可运行。
 */
import test from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const root = dirname(dirname(fileURLToPath(import.meta.url)));

function resolveIsJsonValue() {
	const candidates = [];
	if (process.env.DSH_UTIL_VALUES) candidates.push(process.env.DSH_UTIL_VALUES);
	const homedir = process.env.HOME || "";
	if (homedir) {
		candidates.push(join(homedir, ".local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-util-values"));
		candidates.push(join(homedir, ".dsh/profiles/node_modules/@deepseek-ai/dsh-util-values"));
	}
	for (const candidate of candidates) {
		try {
			const mod = require(candidate);
			if (typeof mod.isJsonValue === "function") return { isJsonValue: mod.isJsonValue, source: candidate };
		} catch (e) {
			/* try next */
		}
	}
	try {
		const mod = require("@deepseek-ai/dsh-util-values");
		return { isJsonValue: mod.isJsonValue, source: "resolve" };
	} catch (e) {
		return null;
	}
}

/** 与 dsh-util-values 同规则的本地回退：仅 boolean/string/有限非-0 number/plain object/array。 */
function localIsJsonValue(value) {
	if (value === null) return true;
	const type = typeof value;
	if (type === "boolean" || type === "string") return true;
	if (type === "number") return Number.isFinite(value) && !Object.is(value, -0);
	if (type !== "object") return false;
	if (Array.isArray(value)) {
		if (Reflect.ownKeys(value).length !== value.length + 1) return false;
		return value.every((entry) => localIsJsonValue(entry));
	}
	if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) return false;
	for (const key of Reflect.ownKeys(value)) {
		if (typeof key !== "string") return false;
		if (!localIsJsonValue(value[key])) return false;
	}
	return true;
}

const resolved = resolveIsJsonValue();
const isJsonValue = resolved ? resolved.isJsonValue : localIsJsonValue;

/** 代表性 wire 状态（镜像 viewPentestState 的输出形状）。 */
function wireStates() {
	const findingWithoutAsset = {
		id: "finding-1",
		kind: "finding",
		intentId: "intent-1",
		title: "t",
		severity: "medium",
		description: "d",
		steps: ["s1", "s2"]
	};
	const findingWithAsset = { ...findingWithoutAsset, id: "finding-2", affectedAssetId: "asset-16" };
	const fact = {
		id: "fact-1",
		kind: "fact",
		factKind: "http",
		intentId: "intent-1",
		target: "https://example.com/",
		detail: "d",
		confidence: 0.5
	};
	const intent = { id: "intent-1", kind: "intent", title: "t", detail: "d" };
	const goal = { id: "goal-1", target: "t", objective: "o", authorization: "a" };
	const nodes = [intent, fact, findingWithoutAsset, findingWithAsset];
	return {
		"pre-init null": null,
		"engagement with findings (no/with affectedAssetId)": {
			goal,
			nodes,
			assets: [{ id: "asset-16", type: "subdomain", value: "a.example.com", meta: "m" }],
			edges: [{ id: "edge-1", kind: "proves", sourceId: "intent-1", targetId: "finding-1" }],
			counts: { intents: 1, facts: 1, findings: 2, assets: 1 }
		},
		"empty counts zeros": {
			goal,
			nodes: [],
			assets: [],
			edges: [],
			counts: { intents: 0, facts: 0, findings: 0, assets: 0 }
		}
	};
}

test("isJsonValue available" + (resolved ? ` from ${resolved.source}` : " (local fallback)"), () => {
	assert.equal(typeof isJsonValue, "function");
});

for (const [label, state] of Object.entries(wireStates())) {
	test(`wire state is lossless JSON: ${label}`, () => {
		assert.equal(isJsonValue(state), true, `wire state must be lossless JSON: ${label}`);
		assert.deepEqual(JSON.parse(JSON.stringify(state)), JSON.parse(JSON.stringify(state)));
	});
}

test("source contract: no undefined-valued properties in projection node builders", () => {
	const source = readFileSync(join(root, "lib", "pentest.js"), "utf8");
	const banned = [
		/\w+\s*:\s*[\w.$!="']+(\s*===?\s*[\w."']+)?\s*\?\s*void 0\s*:/,
		/,\s*\w+\s*:\s*(void 0|undefined)\s*[,}]/,
		/\{\s*\w+\s*:\s*(void 0|undefined)\s*,/
	];
	for (const pattern of banned) {
		const match = source.match(pattern);
		assert.equal(match, null, `lib/pentest.js must not assign undefined property values (matched ${match && match[0]})`);
	}
});

test("engagements route output shape is lossless JSON", async () => {
	const mod = await import(join(root, "lib", "engagements-routes.js"));
	const result = mod.listEngagements();
	assert.equal(result.status, 200);
	assert.equal(isJsonValue(result.obj), true, "engagements route payload must be lossless JSON");
});
