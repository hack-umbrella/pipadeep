/**
 * OOB（带外回连）客户端。
 *
 * 为什么必须有它：盲注、盲 SSRF、无回显 RCE、XXE 外带、以及 JNDI/反序列化注入的
 * 「**打没打中**」只能靠回连确认。没有回连就等于放弃这一整类漏洞，`poc` 纪律也无法闭环。
 *
 * 设计要点：
 * - **Provider 可插拔**：`local`（自建，明文 JSON 协议，便于自控与内网部署）与
 *   `interactsh`（公共/自建集群，数据用 AES 加密返回，按官方协议解密）。
 * - **纯逻辑与 I/O 分离**：HTTP 通过注入的 `fetchImpl`，测试里用桩，不联网。
 * - **状态落盘**：correlation id / secret 存 `$DSH_HOME/oob/<sessionId>.json`（0600），
 *   进程重启后还能继续 poll；同一 payload 的回连只入库一次（按 interaction id 去重）。
 */

import { createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

/** 支持的 OOB 后端。 */
export const OOB_PROVIDERS = ['local', 'interactsh']

const trim = (value) => String(value ?? '').trim()

/** 生成一个短、可读、可作为 DNS 标签的随机 id。 */
export function payloadToken(bytes = 8) {
	return randomBytes(bytes).toString('hex')
}

/** 由 token + 标签拼出回连用的主机名与 URL（DNS 与 HTTP 都指向同一个 token）。 */
export function buildPayload(domain, token, label = '') {
	const host = `${token}.${trim(domain)}`
	const suffix = trim(label) === '' ? '' : `/${encodeURIComponent(trim(label))}`
	return { token, host, url: `http://${host}${suffix}`, dns: `${token}.${trim(domain)}` }
}

/**
 * 解析 Interactsh 的 poll 响应。
 * 官方协议：`{ data: [base64(AES-CFB 密文)], aes_key: <base64/key> }`。
 * 解密失败不抛错（返回原始片段），避免因协议细节丢失整批回连。
 */
export function decryptInteractsh(data, aesKey) {
	if (!Array.isArray(data)) return []
	const key = Buffer.from(trim(aesKey), 'base64')
	return data.map((entry) => {
		const buffer = Buffer.from(trim(entry), 'base64')
		try {
			// interactsh 用 AES-256-CFB，密钥为 aes_key 的 sha256
			const derived = createHash('sha256').update(key).digest()
			const decipher = createDecipheriv('aes-256-cfb', derived, derived.subarray(0, 16))
			return Buffer.concat([decipher.update(buffer), decipher.final()]).toString('utf8')
		} catch {
			return buffer.toString('utf8')
		}
	})
}

/** 把一条回连规范化成入库用的形状（不同后端字段名不同，这里统一）。 */
export function normalizeInteraction(raw, payload) {
	const record = typeof raw === 'string' ? safeJson(raw) : (raw ?? {})
	const protocol = trim(record.protocol ?? record.type ?? (record['raw-request'] === undefined ? 'dns' : 'http')) || 'dns'
	const remote = trim(record['remote-address'] ?? record.remoteAddress ?? record.ip ?? record.client)
	const id = trim(record['unique-id'] ?? record.uniqueId ?? record.id ?? `${protocol}:${remote}:${record.timestamp ?? ''}:${trim(record['raw-request'] ?? record.rawRequest ?? '').length}`)
	return {
		id,
		protocol,
		remote,
		timestamp: trim(record.timestamp ?? record.time ?? ''),
		label: trim(payload?.label ?? ''),
		token: trim(payload?.token ?? ''),
		host: trim(payload?.host ?? ''),
		request: trim(record['raw-request'] ?? record.rawRequest ?? record.request ?? ''),
		response: trim(record['raw-response'] ?? record.rawResponse ?? record.response ?? ''),
		...(trim(record['smtp-from'] ?? '') === '' ? {} : { smtpFrom: trim(record['smtp-from']) })
	}
}

const safeJson = (text) => {
	try { return JSON.parse(text) } catch { return { raw: text } }
}

/**
 * 会话级的 OOB 状态：注册信息 + 已发出的 payload + 已入库的回连 id（去重）。
 * 落在 `$DSH_HOME/oob/<sessionId>.json`，权限 0600。
 */
export class OobState {
	constructor(root, sessionId) {
		this.file = join(root, 'oob', `${sessionId.replace(/[^A-Za-z0-9._-]/g, '_')}.json`)
		this.data = { provider: null, server: null, correlationId: null, secret: null, aesKey: null, payloads: [], seen: [] }
		if (existsSync(this.file)) {
			try { this.data = { ...this.data, ...JSON.parse(readFileSync(this.file, 'utf8')) } } catch { /* 损坏则重置 */ }
		}
	}
	get active() { return this.data.provider !== null && this.data.server !== null }
	save() {
		mkdirSync(dirname(this.file), { recursive: true })
		writeFileSync(this.file, JSON.stringify(this.data, null, 2), { mode: 0o600 })
		try { chmodSync(this.file, 0o600) } catch { /* 平台不支持则忽略 */ }
	}
	register(provider, server, options) {
		this.data = { provider, server: trim(server), correlationId: options.correlationId ?? payloadToken(8), secret: options.secret ?? payloadToken(16), aesKey: options.aesKey ?? null, payloads: [], seen: [] }
		this.save()
		return this.data
	}
	addPayload(payload) { this.data.payloads.push(payload); this.save(); return payload }
	pending(interactions) {
		const seen = new Set(this.data.seen)
		const fresh = interactions.filter((item) => !seen.has(item.id))
		for (const item of fresh) this.data.seen.push(item.id)
		if (fresh.length > 0) this.save()
		return fresh
	}
}

/** 自建后端（`local`）：一个极简 JSON 协议，便于内网自控与测试。 */
export class LocalOobProvider {
	constructor({ server, fetchImpl = fetch }) {
		this.server = trim(server)
		this.fetchImpl = fetchImpl
	}
	async register() {
		const response = await this.fetchImpl(`${this.server}/register`, { method: 'GET' })
		const body = await response.json()
		return { correlationId: trim(body.correlation_id ?? body.correlationId ?? payloadToken(8)), secret: trim(body.secret_key ?? body.secret ?? payloadToken(16)), aesKey: null }
	}
	async poll({ correlationId, secret }) {
		const url = `${this.server}/poll?id=${encodeURIComponent(correlationId)}&secret=${encodeURIComponent(secret)}`
		const response = await this.fetchImpl(url, { method: 'GET' })
		const body = await response.json()
		return Array.isArray(body) ? body : (Array.isArray(body.data) ? body.data : [])
	}
}

/** Interactsh 后端：register + poll（回连数据 AES 加密）。 */
export class InteractshProvider {
	constructor({ server, fetchImpl = fetch }) {
		this.server = trim(server).replace(/\/+$/, '')
		this.fetchImpl = fetchImpl
	}
	async register() {
		const response = await this.fetchImpl(`${this.server}/register`, { method: 'GET' })
		const body = await response.json()
		return { correlationId: trim(body.correlation_id), secret: trim(body.secret_key), aesKey: body.aes_key ?? null }
	}
	async poll({ correlationId, secret, aesKey }) {
		const url = `${this.server}/poll?id=${encodeURIComponent(correlationId)}&secret=${encodeURIComponent(secret)}`
		const response = await this.fetchImpl(url, { method: 'GET' })
		const body = await response.json()
		const raw = Array.isArray(body.data) ? body.data : []
		// 加密时的 aes_key 优先，其次用注册时返回的
		const key = trim(body.aes_key ?? aesKey ?? '')
		const lines = key === '' ? raw.map((entry) => Buffer.from(trim(entry), 'base64').toString('utf8')) : decryptInteractsh(raw, key)
		return lines.map((line) => safeJson(line))
	}
}

/** 按 provider 造客户端。 */
export function createProvider(provider, options) {
	if (provider === 'local') return new LocalOobProvider(options)
	if (provider === 'interactsh') return new InteractshProvider(options)
	throw new Error(`oob: 不支持的 provider ${provider}（可用：${OOB_PROVIDERS.join(' / ')}）`)
}

/** 回连 → 用于入库的摘要文本（给 fact 的 detail）。 */
export function describeInteraction(interaction) {
	const parts = [interaction.protocol.toUpperCase(), interaction.remote === '' ? '' : `from ${interaction.remote}`, interaction.label === '' ? '' : `label=${interaction.label}`]
	return parts.filter((x) => x !== '').join(' ')
}
