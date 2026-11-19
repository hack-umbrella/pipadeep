/**
 * v2.1.0 复测工作流契约：基线快照（稳定对齐键、跨会话不依赖 asset id）、
 * 保存/读取/列举、两轮对比四类结论、详细 Markdown（复现步骤 + HTTP 证据）。
 */
import test from 'node:test'
import assert from 'node:assert'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
	buildSnapshot, stableFindingKey, diffAssessments, retestMarkdown,
	saveBaseline, readBaseline, listBaselines, baselineFile
} from '../lib/retest.mjs'

const dir = mkdtempSync(join(tmpdir(), 'retest-workflow-'))
const opts = { dir }

const session = {
	sessionId: 'session-abc',
	goal: { target: 'https://example.com', objective: 'test' },
	assets: [{ id: 'asset-1', type: 'endpoint', value: 'https://example.com/orders/1' }],
	findings: [{
		id: 'finding-1', title: 'IDOR in /orders', severity: 'high',
		description: 'read others orders', reproducibleSteps: ['GET /orders/1 with victim cookie', 'GET /orders/2'],
		evidence: [{ kind: 'http', path: '/ev/f1/idor.http', label: 'raw' }],
		affectedAssetId: 'asset-1'
	}]
}

test('buildSnapshot: 稳定对齐键用资产实际值而非会话内 asset id', () => {
	const snap = buildSnapshot(session, { now: '2026-01-01T00:00:00Z' })
	assert.equal(snap.kind, 'pentest-baseline')
	assert.equal(snap.version, 1)
	assert.equal(snap.count, 1)
	const row = snap.findings[0]
	assert.equal(row.location, 'https://example.com/orders/1')
	assert.deepEqual(row.steps, ['GET /orders/1 with victim cookie', 'GET /orders/2'])
	assert.equal(row.evidence[0].kind, 'http')
	// 新会话里 asset id 从 1 重新计数也一样对齐
	const other = { ...session, assets: [{ id: 'asset-99', type: 'endpoint', value: 'https://example.com/orders/1' }], findings: [{ ...session.findings[0], affectedAssetId: 'asset-99' }] }
	const snap2 = buildSnapshot(other, { now: '2026-01-02T00:00:00Z' })
	assert.equal(snap.findings[0].key, snap2.findings[0].key)
})

test('stableFindingKey: URL 尾斜杠/大小写归一', () => {
	assert.equal(stableFindingKey({ title: 'SQLI-1', url: 'https://A.com/x/' }), stableFindingKey({ title: 'sqli-1', target: 'https://a.com/x' }))
})

test('saveBaseline / readBaseline / listBaselines 往返', () => {
	const snap = buildSnapshot(session, { now: '2026-01-01T00:00:00Z' })
	const path = saveBaseline(snap, 'round1', { ...opts, targetDir: dir })
	assert.deepEqual(readBaseline(path), snap)
	const rows = listBaselines('', { dir, targetDir: dir })
	assert.ok(rows.some((row) => row.name === 'round1'))
	// 文件名清洗：路径穿越被拦
	assert.throws(() => baselineFile('../evil', '', { targetDir: dir }))
})

test('diffAssessments + retestMarkdown: 四类结论 + 复现步骤/证据内联', () => {
	const base = buildSnapshot(session)
	// 本轮：IDOR 修了；新增 RCE；XSS 回归（上轮标 fixed 又出现）
	const current = buildSnapshot({
		sessionId: 'session-xyz',
		goal: session.goal,
		assets: [],
		findings: [
			{ title: 'RCE in /exec', severity: 'critical', reproducibleSteps: ['POST cmd=id'], evidence: [] },
			{ title: 'XSS in /q', severity: 'medium', target: '/q', reproducibleSteps: ['GET /q=<script>alert(1)</script>'], evidence: [] }
		]
	})
	// 把 XSS 放进基线并标 fixed（与当前 key 对齐 → 回归）
	base.findings.push({ ruleId: 'XSS in /q', location: '/q', severity: 'medium', status: 'fixed', steps: ['old'], evidence: [] })
	const diff = diffAssessments(base, current)
	assert.equal(diff.summary.fixed, 1, 'IDOR 已修复')
	assert.equal(diff.summary.added, 1, 'RCE 新增')
	assert.equal(diff.summary.regressed, 1, '上轮标 fixed 的 XSS 本轮重现 → 回归')
	const md = retestMarkdown(diff)
	assert.match(md, /已修复 1/)
	assert.match(md, /GET \/orders\/1 with victim cookie/)
	assert.match(md, /idor\.http/)
})

test('源码契约：Web 面板注册复测 Tab、路由与文案', () => {
	const root = join(dirname(fileURLToPath(import.meta.url)), '..')
	const bundle = readFileSync(join(root, 'lib', 'ui-pentest.client.js'), 'utf8')
	assert.match(bundle, /"retest"/)
	assert.match(bundle, /view\.tab\.retest/)
	assert.match(bundle, /function RetestView/)
	assert.match(bundle, /tab === "retest"/)
	assert.match(bundle, /\/api\/pipadeep-pentest\/retest\?sessionId=/)
	const routes = readFileSync(join(root, 'lib', 'engagements-routes.js'), 'utf8')
	assert.match(routes, /POINT \+ "\/retest"/)
	assert.match(routes, /POINT \+ "\/retest\.md"/)
	const pentest = readFileSync(join(root, 'lib', 'pentest.js'), 'utf8')
	assert.match(pentest, /name: "pentest_retest"/)
})
