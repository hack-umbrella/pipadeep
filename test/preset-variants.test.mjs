import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'

/**
 * 两份 composition 只在 workflow provider 行上不同。
 *
 * `@deepseek-ai/dsh-workflow-worker-thread` 自 dsh 0.1.6-alpha.1 起被
 * `@deepseek-ai/dsh-workflow-ptc` 取代，而预设里引用一个不存在的包**不是降级可用**，
 * 而是整份预设激活失败（`agent-preset/invalid: … never started`）。所以维护两份变体，
 * 并把差异锁死在测试里，防止手改主文件后忘记同步。
 */
const main = new URL('../preset/pentest/agent.cordis.yml', import.meta.url)
const next = new URL('../preset/pentest/agent.cordis.next.yml', import.meta.url)
const lines = (url) =>
  readFileSync(url, 'utf8')
    .split('\n')
    .filter((line) => !/^\s*#/.test(line) && line.trim() !== '')

test('workflow 变体：差异仅限 workflow provider 与子 agent 配置方式', () => {
	const mainText = readFileSync(main, 'utf8')
	const nextText = readFileSync(next, 'utf8')
	// 只看配置本体（注释里会提到已移除的包名，那是说明文字，不算引用）
	const stripComments = (text) => text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n')
	const mainBody = stripComments(mainText)
	const nextBody = stripComments(nextText)

	// 1) workflow provider：旧变体 worker-thread、新变体 ptc（0.1.5 之后 worker-thread 被移除）
	assert.match(mainBody, /@deepseek-ai\/dsh-workflow-worker-thread/, '旧版变体使用 worker-thread')
	assert.match(nextBody, /@deepseek-ai\/dsh-workflow-ptc/, '新版变体使用 ptc')
	assert.doesNotMatch(nextBody, /@deepseek-ai\/dsh-workflow-worker-thread/, '新版变体不得引用已移除的 worker-thread')

	// 2) 子 agent 配置方式：新版必须用 agentPreset，且**不得**出现 persona / toolFilter
	//    （dsh 0.2.1 的 tool-subagent Config 白名单已移除它们，见到就拒绝整个预设）
	assert.match(nextBody, /agentPreset: pentest-executor/, '新版变体必须用 agentPreset 指向执行子预设')
	assert.doesNotMatch(nextBody, /^\s+persona:/m, 'next 变体不得保留 persona')
	assert.doesNotMatch(nextBody, /^\s+toolFilter:/m, 'next 变体不得保留 toolFilter')

	// 3) 旧版回退仍然保留行内写法（0.1.2~0.1.5 没有 agentPreset 概念）
	assert.match(mainBody, /^\s+persona:/m, '旧版变体需要保留 persona 供 0.1.x 使用')
	assert.match(mainBody, /^\s+toolFilter:/m, '旧版变体需要保留 toolFilter 供 0.1.x 使用')

	// 4) 两份变体除上述两类外，entry id 集合应当一致（防止手改主文件忘同步）
	const ids = (text) => new Set([...text.split('\n')].filter((line) => /^- id: /.test(line) && !/^\s*#/.test(line)).map((line) => line.replace(/^- id: /, '').trim()))
	const mainIds = ids(mainText)
	const nextIds = ids(nextText)
	assert.deepEqual([...nextIds].sort(), [...mainIds].sort(), '两份变体的顶层 entry 集合必须一致')
})

test('执行子预设：顶层是 entry 数组，且不含记录层与委派工具', () => {
	const executor = readFileSync(new URL('../preset/pentest/executor.cordis.next.yml', import.meta.url), 'utf8')
	assert.doesNotMatch(executor, /^plugins:/m, 'composition 顶层必须是 entry 数组，不能套 plugins:')
	assert.match(executor, /@pipadeep\/dsh-pentest\/pentest-tools/, '执行子 agent 需要执行层工具')
	assert.doesNotMatch(executor, /name: '@pipadeep\/dsh-pentest\/pentest'$/m, '执行子 agent 不得挂记录层（写入权限归指挥官）')
	assert.doesNotMatch(executor, /dsh-tool-subagent/, '执行子 agent 不得再委派')
})

test('主 composition 保持 0.1.5- 可用的 worker-thread', () => {
  assert.match(readFileSync(main, 'utf8'), /dsh-workflow-worker-thread/)
})

/**
 * v2.1.1 修的三处「静默失效」——都不是会报错的错误，只能靠断言锁住。
 */

test('执行子预设的人设必须挂在 dsh-persona，不能挂在 agent-instructions.text', () => {
	for (const name of ['executor.cordis.yml', 'executor.cordis.next.yml']) {
		const text = readFileSync(new URL(`../preset/pentest/${name}`, import.meta.url), 'utf8')
		// dsh-agent-instructions 的 Config 没有 text 字段（0.2.2 实测：值被保留但从不读取）
		assert.doesNotMatch(text, /name: '@deepseek-ai\/dsh-agent-instructions'\s*\n\s*config:\s*\n\s*text:/m,
			`${name}: 人设写在 agent-instructions.text 里不会生效`)
		assert.match(text, /name: '@deepseek-ai\/dsh-persona'/, `${name}: 人设必须由 dsh-persona 提供`)
		assert.match(text, /^\s+prefix: \*pentest_executor_persona/m, `${name}: 0.2.x 认 prefix，必须给`)
		assert.match(text, /^\s+text: &pentest_executor_persona/m, `${name}: 0.1.x 认 text，双写保留`)
	}
})

test('composition 不得残留 0.2.x 已移除的 subagent 配置键', () => {
	for (const name of ['agent.cordis.yml', 'agent.cordis.next.yml']) {
		const text = readFileSync(new URL(`../preset/pentest/${name}`, import.meta.url), 'utf8')
		// schemastery 会静默保留未知键 → 死键不会报错，只会误导后来人
		assert.doesNotMatch(text, /^\s+backgroundMode:/m, `${name}: backgroundMode 是 0.1.x 死键`)
		assert.doesNotMatch(text, /^\s+enableRunInBackground:/m, `${name}: enableRunInBackground 是 0.1.x 死键`)
	}
})

test('preset-root 不再依赖不存在的 supportsPresetSelection 守卫', async () => {
	const raw = readFileSync(new URL('../lib/preset-root.js', import.meta.url), 'utf8')
	// 注释里会解释这段历史，只断言**代码**不再引用它
	const code = raw.split('\n').filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line)).join('\n')
	assert.doesNotMatch(code, /supportsPresetSelection/, 'dsh 0.2.2 没有该方法，可选链恒为 undefined，判断等于死代码')
	// 执行预设必须无条件注册：0.2.x 委派依赖 agentPreset
	assert.match(raw, /id: "pentest-executor"/, '执行子预设必须始终注册')
	assert.match(raw, /order: 999/, '执行预设应排在选择器末尾')
	assert.match(raw, /order: 100/, '主预设应有稳定 order')
})

/**
 * v2.1.1 实机（dsh 0.2.2-rc.1）探针发现的三个会导致 `broken` 的硬错误。
 * 它们都不是静默失效——整份预设被判 broken 后，Web 选择器（只列 healthy 的）
 * 会直接**看不到预设**，这正是用户报的「4 行都在跑但预设不出现」。
 */

test('composition 不得再单独挂 list-agents 子路径（0.2.2 已并入主包）', () => {
	for (const name of ['agent.cordis.yml', 'agent.cordis.next.yml']) {
		const text = readFileSync(new URL(`../preset/pentest/${name}`, import.meta.url), 'utf8')
		// dsh-tool-subagent-control 的 exports 在 0.2.2 只剩 "."；子路径行会让预设 never started。
		// 主包的 apply 自己会 registerListAgents(ctx)，因此这行本来也冗余。
		assert.doesNotMatch(text, /dsh-tool-subagent-control\/list-agents/, `${name}: list-agents 子路径在 0.2.2 不存在`)
		// 但仍需要主包那一行，否则没有 send_message / interrupt_agent
		assert.match(text, /name: '@deepseek-ai\/dsh-tool-subagent-control'/, `${name}: 仍需挂主包`)
	}
})

test('fs-search 的 sampleOverCapGlobResults 在所有预设里都必须给（0.2.2 起 required）', () => {
	for (const name of ['agent.cordis.yml', 'agent.cordis.next.yml', 'executor.cordis.yml', 'executor.cordis.next.yml']) {
		const text = readFileSync(new URL(`../preset/pentest/${name}`, import.meta.url), 'utf8')
		const rows = text.split(/\n(?=- id: )/)
		for (const row of rows) {
			if (!row.includes('@deepseek-ai/dsh-tool-fs-search')) continue
			assert.match(row, /sampleOverCapGlobResults:/, `${name}: 缺 sampleOverCapGlobResults 会让整份预设 invalid config`)
		}
	}
})

test('每个 cordis:group 若挂 compaction/pruner 服务，必须声明 isolate realm', () => {
	for (const name of ['agent.cordis.yml', 'agent.cordis.next.yml', 'executor.cordis.yml', 'executor.cordis.next.yml']) {
		const text = readFileSync(new URL(`../preset/pentest/${name}`, import.meta.url), 'utf8')
		for (const row of text.split(/\n(?=- id: )/)) {
			const isCompactionGroup = /name: cordis:group/.test(row)
				&& /dsh-compaction-basic|dsh-compaction-tool-result-pruner/.test(row)
			if (!isCompactionGroup) continue
			// 0.2.2 mountPreset 会审计泄露到根 realm 的服务：
			// "Preset services require isolate realms: compaction, toolResultPruner"
			assert.match(row, /isolate:\s*\n\s+compaction: true/, `${name}: compaction group 必须 isolate`)
			assert.match(row, /toolResultPruner: true/, `${name}: toolResultPruner 必须 isolate`)
		}
	}
})
