import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { load } from "js-yaml";

export const inject = ["agentPresets"];

const require = createRequire(import.meta.url);

/** 宿主是否提供某个包（真实部署里宿主包在 profile 的 node_modules 链上，向上查找可达）。 */
function hostProvides(specifier) {
	try {
		require.resolve(specifier);
		return true;
	} catch {
		return false;
	}
}

/**
 * 选出与宿主匹配的 workflow provider 变体。
 *
 * `@deepseek-ai/dsh-workflow-worker-thread` 在 0.1.5-rc.3 之后被移除，0.1.6-alpha.1 起
 * 改为 `@deepseek-ai/dsh-workflow-ptc`。预设里引用一个不存在的包**不是降级可用**，
 * 而是整个预设激活失败（`agent-preset/invalid: ... never started`），所以必须选对。
 *
 * 判定顺序（前两步在真实机上命中，后一步是沙箱/非标准布局的兜底）：
 *   1. 显式环境变量 PIPADEEP_WORKFLOW_PROVIDER=ptc|worker-thread；
 *   2. 宿主包能否 resolve 到；
 *   3. 声明式 preset API（`register`）与 ptc 同期（0.1.7+）→ 用它推断。
 */
function workflowVariant(presets) {
	const forced = process.env.PIPADEEP_WORKFLOW_PROVIDER;
	if (forced === "ptc" || forced === "worker-thread") return forced;
	if (hostProvides("@deepseek-ai/dsh-workflow-ptc")) return "ptc";
	if (hostProvides("@deepseek-ai/dsh-workflow-worker-thread")) return "worker-thread";
	return typeof presets.register === "function" ? "ptc" : "worker-thread";
}

/**
 * 把本包自带的 `pentest` 预设挂上去，**兼容两代 dsh 的 agentPresets API**。
 *
 * - dsh 0.1.7+：agentPresets 是声明式的，调 `register(definition)`，定义里 `plugins`
 *   用 `cordis:include` 指回 composition —— 那份文件继续当**唯一事实源**（保留 `!!js`
 *   表达式与文件监听，是 `cordis:include` 相对内联的优势）。
 * - dsh 0.1.2：agentPresets 靠 `resolvedRoots` 目录扫描（预设目录的
 *   `<name>/agent.cordis.yml` 会被自动发现），把本包的 `preset/` 目录塞进 roots。
 *
 * 两代都不认的 API 直接抛错：静默失效会表现成「渗透预设凭空消失」，比报错难查得多。
 */
export async function* apply(ctx) {
	const root = new URL("../preset/", import.meta.url);
	const presets = ctx.get("agentPresets");
	const variant = workflowVariant(presets);
	const composition = new URL(
		variant === "ptc" ? "pentest/agent.cordis.next.yml" : "pentest/agent.cordis.yml",
		root,
	);

	if (typeof presets.register === "function") {
		const metadata = load(await readFile(new URL("pentest/preset.yml", root), "utf8")) ?? {};
		// dsh 0.2.1 起 `tool-subagent` 不再接受行内 `persona` / `toolFilter` / `n`
		// （见 dsh-tool-subagent 的 Config 白名单），要求把「执行子 agent 的人设与工具面」
		// 抽成一个独立预设，由父预设的 `agentPreset` 指过来。
		//
		// 这里**无条件**注册执行预设：`register` 存在就说明宿主支持声明式预设，
		// 而 `agentPreset` 是 0.2.x 委派的必需项——缺了它父预设的 tool-subagent 行会挂不上。
		// （曾有一个 `presets.supportsPresetSelection?.() !== false` 守卫，但 0.2.2 根本没有
		// 这个方法，可选链恒为 undefined，判断永远成立、等于死代码，故删掉。）
		//
		// 该预设会出现在模式选择器里（0.2.2 的 PresetDefinition 没有隐藏位），
		// 用 `order` 压到最后；它只含执行工具，无法记录或再委派，误选也无害。
		const executorComposition = new URL(
			variant === "ptc" ? "pentest/executor.cordis.next.yml" : "pentest/executor.cordis.yml",
			root,
		);
		yield await presets.register({
			id: "pentest-executor",
			name: "渗透执行子 agent（内部）",
			description: "内部使用：渗透测试的执行子 agent（只含执行工具，用于取代旧的 persona/toolFilter 行内配置）。",
			order: 999,
			plugins: [
				{
					id: "pentest-executor-composition",
					name: "cordis:include",
					config: { path: executorComposition.href },
				},
			],
		});
		yield await presets.register({
			id: "pentest",
			name: typeof metadata.name === "string" && metadata.name !== "" ? metadata.name : "渗透模式 Pro",
			description: typeof metadata.description === "string" ? metadata.description : "",
			// 排在官方内建预设（standard/ptc/minimal/cordis，order 1-4）之后，
			// 与 dsh-ir 等第三方预设的相对顺序由 id 决定，保持稳定即可。
			order: 100,
			plugins: [
				{
					id: "pentest-composition",
					name: "cordis:include",
					config: { path: composition.href },
				},
			],
		});
		return;
	}

	if (!Array.isArray(presets.resolvedRoots)) {
		throw new Error(
			"@pipadeep/dsh-pentest: unsupported agentPresets API (expected register or resolvedRoots); " +
				"this dsh revision cannot mount the bundled pentest preset",
		);
	}
	// 目录扫描模式下文件名是固定的 `agent.cordis.yml`（0.1.5-rc.3 及更早都提供
	// worker-thread，与该文件一致），所以这里只登记 root，不挑变体。
	const path = fileURLToPath(root);
	// 同一目录可能以不同拼写（尾斜杠 / 平台分隔符）到达这里；按 resolve 后的路径比较。
	if (
		presets.resolvedRoots.some(
			(entry) => typeof entry.path === "string" && resolve(entry.path) === resolve(path),
		)
	) {
		return;
	}
	const entry = { path, trust: "system" };
	presets.resolvedRoots.unshift(entry);
	yield () => {
		const index = presets.resolvedRoots.indexOf(entry);
		if (index !== -1) presets.resolvedRoots.splice(index, 1);
	};
}
