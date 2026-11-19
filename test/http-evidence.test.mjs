/**
 * HTTP 流量证据渲染契约：v2.0.4 起，每个 finding 绑定的 kind=http 原始请求/响应
 * 必须在报告里逐条内联（方法/URL/状态码/头/正文），且敏感头脱敏、正文截断可控。
 * 本测试直接打 lib/http-evidence.mjs（纯函数、零外部依赖）。
 */
import test from 'node:test'
import assert from 'node:assert'
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseHttpDump, renderHttpTraffic, evidenceHref, readFindingHttpEvidence } from '../lib/http-evidence.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const temp = mkdtempSync(join(tmpdir(), 'http-evidence-'))

const SHOT_DUMP = [
	'=== GET https://example.com/orders/1 -> 200 (42ms) ===',
	'--- request headers ---',
	'host: example.com',
	'cookie: session=secret-token',
	'authorization: Bearer supersecret',
	'--- request body ---',
	'',
	'--- response headers ---',
	'content-type: application/json',
	'set-cookie: sid=leak; HttpOnly',
	'--- response body ---',
	'{"id":1,"owner":"victim"}',
	''
].join('\n')

test('parseHttpDump: 解析 shot.js 的代理证据格式', () => {
	const rows = parseHttpDump(SHOT_DUMP)
	assert.equal(rows.length, 1)
	assert.equal(rows[0].method, 'GET')
	assert.equal(rows[0].url, 'https://example.com/orders/1')
	assert.equal(rows[0].status, '200')
	assert.equal(rows[0].durationMs, 42)
	assert.equal(rows[0].requestHeaders.host, 'example.com')
	assert.equal(rows[0].requestHeaders.cookie, 'session=secret-token')
	assert.equal(rows[0].responseBody, '{"id":1,"owner":"victim"}')
})

test('parseHttpDump: 兼容 curl -i 原始报文', () => {
	const raw = [
		'POST /login HTTP/1.1',
		'Host: example.com',
		'Content-Type: application/x-www-form-urlencoded',
		'',
		'user=admin&pass=test',
		'HTTP/1.1 302 Found',
		'Location: /dashboard',
		'',
		'redirecting'
	].join('\n')
	const rows = parseHttpDump(raw)
	assert.equal(rows.length, 1)
	assert.equal(rows[0].method, 'POST')
	assert.equal(rows[0].url, '/login')
	assert.equal(rows[0].status, '302')
	assert.equal(rows[0].requestBody, 'user=admin&pass=test')
	assert.equal(rows[0].responseHeaders.location, '/dashboard')
})

test('renderHttpTraffic: 内联请求/响应且脱敏敏感头', () => {
	const path = join(temp, 'idor.http')
	writeFileSync(path, SHOT_DUMP)
	const finding = { id: 'finding-1', evidence: [
		{ kind: 'http', path, label: 'IDOR 原始流量' },
		{ kind: 'screenshot', path: join(temp, 'idor.png'), label: 'IDOR 截图' }
	] }
	const lines = renderHttpTraffic(finding)
	const text = lines.join('\n')
	assert.match(text, /IDOR 原始流量/)
	assert.match(text, /GET https:\/\/example\.com\/orders\/1 → 200 \(42ms\)/)
	assert.match(text, /content-type: application\/json/)
	assert.match(text, /"owner":"victim"/)
	assert.match(text, /cookie: <已脱敏>/)
	assert.match(text, /authorization: <已脱敏>/)
	assert.match(text, /set-cookie: <已脱敏>/)
	assert.doesNotMatch(text, /session=secret-token|Bearer supersecret|sid=leak/)
	// screenshot 不是 http 项，不应出现在本节
	assert.doesNotMatch(text, /idor\.png/)
	// 原始文件链接走只读证据路由
	assert.match(text, /\/api\/pipadeep-pentest\/evidence\?path=/)
})

test('renderHttpTraffic: 无 http 证据或无 finding 时返回空', () => {
	assert.deepEqual(renderHttpTraffic({ id: 'f', evidence: [{ kind: 'screenshot', path: '/a.png' }] }), [])
	assert.deepEqual(renderHttpTraffic(undefined), [])
})

test('renderHttpTraffic: 原始文件不可读时给出可引用路径而非崩溃', () => {
	const lines = renderHttpTraffic({ id: 'f', evidence: [{ kind: 'http', path: join(temp, 'missing.http') }] })
	const text = lines.join('\n')
	assert.match(text, /原始文件当前不可读/)
})

test('evidenceHref: 绝对路径转只读路由，http(s) 原样', () => {
	assert.match(evidenceHref('/tmp/a.http'), /^\/api\/pipadeep-pentest\/evidence\?path=%2Ftmp%2Fa\.http$/)
	assert.equal(evidenceHref('https://x/y.http'), 'https://x/y.http')
	assert.equal(evidenceHref(''), '')
})

test('readFindingHttpEvidence: 仅挑 kind=http 项，保留顺序', () => {
	const a = join(temp, 'a.http'); writeFileSync(a, SHOT_DUMP)
	const b = join(temp, 'b.http'); writeFileSync(b, '')
	const out = readFindingHttpEvidence({ evidence: [
		{ kind: 'script', path: a },
		{ kind: 'http', path: a, label: 'A' },
		{ kind: 'http', path: b, label: 'B' },
		null,
		{ kind: 'http', path: '' }
	] })
	assert.equal(out.length, 2)
	assert.equal(out[0].label, 'A')
	assert.equal(out[0].exchanges.length, 1)
	assert.equal(out[1].exchanges.length, 0)
})

test('源码契约：buildReport 内联 HTTP 流量 + 步骤标题，截图走只读路由', () => {
	const source = readFileSync(join(root, 'lib', 'pentest.js'), 'utf8')
	assert.match(source, /import \{ renderHttpTraffic \} from "\.\/http-evidence\.mjs"/)
	assert.match(source, /const httpLines = renderHttpTraffic\(finding\)/)
	assert.match(source, /\.\.\.httpLines/)
	assert.match(source, /复现过程（按顺序执行，预期结果见 HTTP 流量）/)
	assert.match(source, /\/api\/pipadeep-pentest\/evidence\?path=\$\{encodeURIComponent\(item\.path\)\}/)
})

test('反证：超长正文被截断并指向原始文件，而不是灌满报告', () => {
	const path = join(temp, 'big.http')
	const body = 'A'.repeat(9000)
	writeFileSync(path, [
		'=== POST https://example.com/x -> 200 ===',
		'--- request headers ---',
		'content-type: text/plain',
		'--- request body ---',
		body,
		'--- response headers ---',
		'--- response body ---',
		body,
		''
	].join('\n'))
	const text = renderHttpTraffic({ evidence: [{ kind: 'http', path }] }).join('\n')
	assert.match(text, /截断，完整内容见原始证据文件/)
	assert.ok(text.length < 12000, `报告正文应被截断（实际 ${text.length} 字符）`)
})

test('反证：非法 evidence 项（非对象 / 缺 path / http 大小写混用）不崩溃', () => {
	const out = readFindingHttpEvidence({ evidence: [
		'garbage', 42, null, undefined,
		{ kind: 'HTTP', path: join(temp, 'idor.http') },
		{ kind: 'http', path: undefined },
		{ kind: 'http', path: 123 }
	] })
	assert.equal(out.length, 1, '只有 kind=http 且 path 非空的项被采纳')
	assert.equal(out[0].exchanges.length, 1)
})

test('反证：空文件 / 纯噪声文件不产生伪造的请求', () => {
	const path = join(temp, 'noise.http')
	writeFileSync(path, 'this is not an http dump\njust noise\n')
	assert.deepEqual(parseHttpDump(''), [])
	assert.deepEqual(parseHttpDump('noise only'), [])
	assert.match(renderHttpTraffic({ evidence: [{ kind: 'http', path }] }).join('\n'), /格式无法解析/)
})
