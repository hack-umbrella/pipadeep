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
