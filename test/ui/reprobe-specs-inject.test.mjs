/**
 * 一键复测的「规格注入」契约（v2.2.1）。
 *
 * 背景：v2.2.0 的 reprobe 引擎只有 `options.specs` 一个注入通道，而 Web 路由是浏览器触发的，
 * 没有任何调用方会传 specs，`CHECK_SPECS` 又是空数组 —— 于是「一键复测」永远返回
 * 「需人工复测」且发 0 个请求，功能形同虚设。
 *
 * v2.2.1 增加：从基线同目录的 reprobe-specs.mjs 自动加载，并支持声明式 expect
 * （不必写 JS judge）。这里锁住加载、校验、判定、以及「不安全内容不发请求」。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadSpecs, reprobeOne, runReprobe, specsFileFor } from '../../lib/reprobe.mjs'

process.env.DSH_HOME = mkdtempSync(join(tmpdir(), 'dsh-spec-inject-'))

const work = mkdtempSync(join(tmpdir(), 'dsh-spec-dir-'))
const baselinePath = join(work, 'round1.json')
const baseline = {
	target: 'example.com',
	findings: [{ key: 'idor@https://example.com/api/users/1', title: 'IDOR 未授权读取用户', severity: 'high' }]
}
writeFileSync(baselinePath, JSON.stringify(baseline))

const writeSpecs = (body) => writeFileSync(specsFileFor(baselinePath), body)

test('specsFileFor 固定在基线同目录', () => {
	assert.equal(specsFileFor(baselinePath), join(work, 'reprobe-specs.mjs'))
})

test('没有规格文件：不发请求，且给出可操作的提示', async () => {
	let hits = 0
	const result = await reprobeOne(baseline, baseline.findings[0].key, {
		baselinePath,
		transport: async () => { hits += 1; return { ok: true, status: 200, body: '', headers: {} } }
	})
	assert.equal(hits, 0, '未配置规格时绝不能发请求')
	assert.equal(result.verdict, 'unclear')
	assert.match(result.detail, /reprobe-specs\.mjs/, '提示要指出该建哪个文件')
})

test('声明式 expect：命中 → open，不命中 → fixed', async () => {
	writeSpecs(`export const specs = [{
		id: 'idor', match: ['IDOR'], label: 'IDOR 复测',
		requests: [{ method: 'GET', url: 'https://example.com/api/users/1', headers: {} }],
		expect: { status: 200, bodyIncludes: ['phone'] }
	}]`)
	const loaded = await loadSpecs(baselinePath)
	assert.equal(loaded.specs.length, 1)
	assert.equal(loaded.error, '')
	assert.equal(typeof loaded.specs[0].judge, 'function', 'expect 应被编译成 judge')

	const open = await reprobeOne(baseline, baseline.findings[0].key, {
		baselinePath, transport: async () => ({ ok: true, status: 200, body: '{"phone":"13800000000"}', headers: {} })
	})
	assert.equal(open.verdict, 'open')
	assert.match(open.detail, /仍存在/)

	const fixed = await reprobeOne(baseline, baseline.findings[0].key, {
		baselinePath, transport: async () => ({ ok: true, status: 403, body: '{"error":"forbidden"}', headers: {} })
	})
	assert.equal(fixed.verdict, 'fixed')
	assert.match(fixed.detail, /已修复/)
})

test('judge 函数仍然被支持（复杂判定的逃生舱）', async () => {
	writeSpecs(`export const specs = [{
		id: 'idor', match: ['IDOR'], label: 'judge',
		requests: [{ method: 'GET', url: 'https://example.com/api/users/1' }],
		judge: ([r]) => ({ verdict: r.body.includes('OTHER_USER') ? 'open' : 'fixed', detail: '自定义判定' })
	}]`)
	const result = await reprobeOne(baseline, baseline.findings[0].key, {
		baselinePath, transport: async () => ({ ok: true, status: 200, body: 'OTHER_USER', headers: {} })
	})
	assert.equal(result.verdict, 'open')
	assert.equal(result.detail, '自定义判定')
})

test('形状不合法的规格被忽略并报原因，不会悄悄失效', async () => {
	writeSpecs(`export const specs = [
		{ id: 'no-requests', match: ['IDOR'], requests: [] },
		{ id: 'bad-url', match: ['IDOR'], requests: [{ method: 'GET', url: 'not-a-url' }] },
		{ id: 'ok', match: ['IDOR'], requests: [{ method: 'GET', url: 'https://example.com/x' }], expect: { status: 200 } }
	]`)
	const loaded = await loadSpecs(baselinePath)
	assert.equal(loaded.specs.length, 1, '只有合法的那条被采纳')
	assert.match(loaded.error, /no-requests|bad-url/)
})

test('规格请求域名与目标不符时不发请求（防 SSRF）', async () => {
	writeSpecs(`export const specs = [{
		id: 'ssrf', match: ['IDOR'], label: 'x',
		requests: [{ method: 'GET', url: 'https://evil.example.net/steal' }],
		expect: { status: 200 }
	}]`)
	let hits = 0
	const result = await reprobeOne(baseline, baseline.findings[0].key, {
		baselinePath, transport: async () => { hits += 1; return { ok: true, status: 200, body: '', headers: {} } }
	})
	assert.equal(hits, 0, '跨域规格必须被拦下')
	assert.equal(result.verdict, 'unclear')
	assert.match(result.detail, /域名与基线目标不一致/)
})

test('runReprobe 汇总里带上规格状态，便于页面解释原因', async () => {
	writeSpecs(`export const specs = [{
		id: 'idor', match: ['IDOR'], label: 'x',
		requests: [{ method: 'GET', url: 'https://example.com/api/users/1' }],
		expect: { status: 200 }
	}]`)
	const result = await runReprobe(baseline, {
		baselinePath, sessionId: 'spec-summary', force: true,
		transport: async () => ({ ok: true, status: 200, body: '', headers: {} })
	})
	assert.equal(result.specCount, 1)
	assert.equal(result.specError, '')
	assert.equal(result.total, 1)
	assert.equal(result.open, 1)
})
