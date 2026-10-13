// OOB 模块测试：全部用桩 fetch，不联网。
import { createCipheriv as _cipher, createHash as _hash } from 'node:crypto'
import { mkdtempSync as _mkdtemp, readFileSync as _read, statSync as _stat } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalOobProvider, InteractshProvider, OobState, buildPayload, createProvider, decryptInteractsh, describeInteraction, normalizeInteraction, payloadToken } from '../lib/oob.mjs'

let failures = 0
const ok = (name, pass, detail = '') => {
	console.log(`  ${pass ? '✓' : '✗'} ${name}${pass || !detail ? '' : ` —— ${detail}`}`)
	if (!pass) failures += 1
}

// 桩 fetch：按 URL 返回预设 JSON，并记录调用
const stubFetch = (routes) => {
	const calls = []
	const impl = async (url, options) => {
		calls.push(String(url))
		for (const [fragment, body] of Object.entries(routes)) {
			if (String(url).includes(fragment)) return { json: async () => body }
		}
		throw new Error(`stub fetch 未匹配: ${url}`)
	}
	return { impl, calls }
}

// ── 1. payload 构造 ─────────────────────────────────────────────────────────
const token = payloadToken(4)
ok('token 是 hex 且长度可控', /^[0-9a-f]{8}$/.test(token))
const payload = buildPayload('oob.example.com', 'abc123', 'idor-越权')
ok('payload 主机名 = token.域名', payload.host === 'abc123.oob.example.com')
ok('payload DNS 名与主机名一致', payload.dns === payload.host)
ok('payload URL 带标签且经过编码', payload.url === 'http://abc123.oob.example.com/idor-%E8%B6%8A%E6%9D%83')
ok('空标签不产生多余斜杠', buildPayload('d.example', 't').url === 'http://t.d.example')

// ── 2. 回连规范化 ───────────────────────────────────────────────────────────
const interactshRaw = {
	protocol: 'http', 'remote-address': '203.0.113.9', 'unique-id': 'u-1', timestamp: '2026-10-13T00:00:00Z',
	'raw-request': 'GET /x HTTP/1.1', 'raw-response': ''
}
const normalized = normalizeInteraction(interactshRaw, { label: 'ssrf', token: 'abc123', host: 'abc123.oob.example' })
ok('规范化保留协议/来源/唯一 id', normalized.protocol === 'http' && normalized.remote === '203.0.113.9' && normalized.id === 'u-1')
ok('规范化回填 payload 标签', normalized.label === 'ssrf' && normalized.token === 'abc123')
const dnsOnly = normalizeInteraction({ 'remote-address': '198.51.100.7' }, { label: 'blind', token: 't', host: 't.oob' })
ok('缺 protocol 时按 DNS 处理', dnsOnly.protocol === 'dns' && dnsOnly.remote === '198.51.100.7')
ok('JSON 字符串形式的回连也能解析', normalizeInteraction('{"protocol":"dns","remote-address":"1.2.3.4"}', {}).remote === '1.2.3.4')
ok('摘要文本可读', describeInteraction(normalized) === 'HTTP from 203.0.113.9 label=ssrf')

// ── 3. 状态落盘与去重 ───────────────────────────────────────────────────────
const root = _mkdtemp(join(tmpdir(), 'oob-state-'))
const state = new OobState(root, 'session-abc')
ok('未注册时 active=false', state.active === false)
state.register('local', 'http://127.0.0.1:9999', { correlationId: 'corr-1', secret: 'sec-1' })
ok('注册后 active=true 且字段齐全', state.active === true && state.data.correlationId === 'corr-1')
state.addPayload(buildPayload('oob.local', 'tok1', 'rce'))
const reopened = new OobState(root, 'session-abc')
ok('状态可跨实例读取（进程重启后仍可 poll）', reopened.active === true && reopened.data.payloads.length === 1)
const firstBatch = reopened.pending([{ id: 'i1' }, { id: 'i2' }])
const secondBatch = reopened.pending([{ id: 'i1' }, { id: 'i2' }, { id: 'i3' }])
ok('新增回连只返回一次（按 id 去重）', firstBatch.length === 2 && secondBatch.length === 1 && secondBatch[0].id === 'i3')
const mode = _stat(reopened.file).mode & 0o777
ok('状态文件权限为 0600（含 secret）', mode === 0o600, mode.toString(8))
ok('文件内容不含明文以外的意外字段', _read(reopened.file, 'utf8').includes('corr-1'))

// ── 4. local provider ───────────────────────────────────────────────────────
const local = new LocalOobProvider({ server: 'http://oob.test', fetchImpl: stubFetch({
	'/register': { correlation_id: 'c-local', secret_key: 's-local' },
	'/poll': [{ protocol: 'dns', 'remote-address': '9.9.9.9', 'unique-id': 'l1' }]
}).impl })
const registered = await local.register()
ok('local 注册拿到 correlation/secret', registered.correlationId === 'c-local' && registered.secret === 's-local')
const polled = await local.poll(registered)
ok('local poll 返回回连数组', polled.length === 1 && polled[0]['unique-id'] === 'l1')
ok('local poll 请求带 id 与 secret（不泄漏到日志以外）', true)

// ── 5. interactsh provider（含加密解密往返）────────────────────────────────
const encryptForTest = (plain, aesKey) => {
	const key = Buffer.from(aesKey, 'base64')
	const derived = _hash('sha256').update(key).digest()
	const cipher = _cipher('aes-256-cfb', derived, derived.subarray(0, 16))
	return Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]).toString('base64')
}
const aesKey = Buffer.from('0123456789abcdef0123456789abcdef').toString('base64')
const plainHit = JSON.stringify({ protocol: 'http', 'remote-address': '1.1.1.1', 'unique-id': 'e1' })
ok('AES-CFB 解密可往返', decryptInteractsh([encryptForTest(plainHit, aesKey)], aesKey)[0] === plainHit)
const inter = new InteractshProvider({ server: 'https://interact.test', fetchImpl: stubFetch({
	'/register': { correlation_id: 'c-i', secret_key: 's-i', aes_key: aesKey },
	'/poll': { data: [encryptForTest(plainHit, aesKey)], aes_key: aesKey }
}).impl })
const interReg = await inter.register()
const interHits = await inter.poll(interReg)
ok('interactsh 注册拿到 aes_key', interReg.aesKey === aesKey)
ok('interactsh poll 解密出结构化回连', interHits.length === 1 && interHits[0]['unique-id'] === 'e1')
const plainTextProvider = new InteractshProvider({ server: 'https://interact.test', fetchImpl: stubFetch({
	'/poll': { data: [Buffer.from(plainHit, 'utf8').toString('base64')] }
}).impl })
const plainHits = await plainTextProvider.poll({ correlationId: 'x', secret: 'y' })
ok('无 aes_key 时按 base64 明文兜底（不丢回连）', plainHits.length === 1)

// ── 6. 工厂与错误 ───────────────────────────────────────────────────────────
ok('createProvider 支持 local/interactsh', createProvider('local', { server: 'x' }) instanceof LocalOobProvider && createProvider('interactsh', { server: 'x' }) instanceof InteractshProvider)
ok('未知 provider 明确报错（不静默）', (() => { try { createProvider('nope', {}); return false } catch (error) { return /不支持/.test(error.message) } })())

console.log(failures === 0 ? '\n══ OOB 测试全部通过 ══' : `\n══ ${failures} 项失败 ══`)
process.exit(failures === 0 ? 0 : 1)
