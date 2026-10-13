/**
 * 认证 / 授权自动化（路线图第 4 项）。
 *
 * 越权（IDOR/BOLA）是外网 Web 里最高频的高危，但它不能靠"看代码猜"：
 * 必须是**两个身份 × 同一资源**的实测差异。这里提供三件确定性工具：
 *   1. JWT 静态分析 + 弱密钥离线爆破（alg=none / 弱 HMAC / kid 注入 / 缺 exp）
 *   2. 访问矩阵：多身份 × 多请求的探测计划（让执行侧去发，别让模型即兴编）
 *   3. 响应差异归类：把"另一个身份也拿到了"判成越权候选，而不是"看到 200 就算漏洞"
 * 结论一律先当候选 —— 是否真越权必须人工看请求/响应（本插件纪律）。
 */

import { createHmac } from 'node:crypto'

const decode = (part) => {
	try { return JSON.parse(Buffer.from(String(part).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) } catch { return null }
}

/** 拆分并解析 JWT（不校验签名，仅解析）。 */
export function parseJwt(token) {
	const parts = String(token ?? '').trim().split('.')
	if (parts.length !== 3) throw new Error('parseJwt: 不是三段式 JWT')
	return { header: decode(parts[0]), payload: decode(parts[1]), signature: parts[2], parts }
}

/** 用候选密钥验证 HMAC 签名（HS256/384/512）。用于弱密钥检查，不联网、不爆破在线接口。 */
export function verifyHmac(token, secret) {
	const { header, parts } = parseJwt(token)
	const algorithm = String(header?.alg ?? '').toUpperCase()
	if (!algorithm.startsWith('HS')) return false
	const digest = algorithm === 'HS384' ? 'sha384' : algorithm === 'HS512' ? 'sha512' : 'sha256'
	const expected = createHmac(digest, String(secret)).update(`${parts[0]}.${parts[1]}`).digest('base64url')
	return expected === parts[2]
}

/** 用字典离线爆破 HMAC 密钥；命中返回密钥，否则返回 null。 */
export function crackHmac(token, wordlist) {
	for (const candidate of wordlist ?? []) if (verifyHmac(token, candidate)) return String(candidate)
	return null
}

/**
 * JWT 静态分析。
 * @param token - JWT 字符串
 * @param options - `{ wordlist?: string[], now?: number }`
 * @returns `{ issues: [{ code, severity, detail }], payload, header }`
 *   issue.code：`alg-none` / `alg-none-accepted-shape` / `weak-secret` / `kid-injection` /
 *   `no-expiry` / `expired` / `external-key-url` / `sensitive-claims`
 */
export function analyzeJwt(token, options = {}) {
	const { header, payload } = parseJwt(token)
	const issues = []
	const alg = String(header?.alg ?? '').toLowerCase()
	if (alg === 'none' || alg === '') issues.push({ code: 'alg-none', severity: 'critical', detail: 'alg 为 none —— 服务端若接受无签名令牌即为完全绕过' })
	if (/^hs/.test(alg)) {
		const cracked = crackHmac(token, options.wordlist ?? [])
		if (cracked !== null) issues.push({ code: 'weak-secret', severity: 'critical', detail: `HMAC 密钥可被离线字典命中（${cracked.length} 字符）—— 可伪造任意身份令牌` })
	}
	const kid = String(header?.kid ?? '')
	if (kid !== '' && /(\.\.|\/|\\|00|%2f)/i.test(kid)) issues.push({ code: 'kid-injection', severity: 'high', detail: `kid 含路径/空字节特征（${kid}）—— 可尝试路径穿越或 SQL 注入选择密钥` })
	if (header?.jku !== undefined || header?.x5u !== undefined) issues.push({ code: 'external-key-url', severity: 'high', detail: '存在 jku/x5u 外部密钥地址 —— 若未做白名单可劫持验签公钥' })
	const now = Math.floor((options.now ?? Date.now()) / 1000)
	if (payload?.exp === undefined) issues.push({ code: 'no-expiry', severity: 'medium', detail: '令牌没有 exp —— 失窃后长期有效' })
	else if (Number(payload.exp) < now) issues.push({ code: 'expired', severity: 'info', detail: '令牌已过期（作为基线时注意替换）' })
	const sensitive = ['password', 'passwd', 'pwd', 'secret', 'private_key', 'id_card', 'phone'].filter((key) => payload?.[key] !== undefined)
	if (sensitive.length !== 0) issues.push({ code: 'sensitive-claims', severity: 'medium', detail: `载荷含敏感字段：${sensitive.join(', ')}（客户端可读，注意信息泄露）` })
	return { header, payload, issues, worstSeverity: issues.reduce((worst, issue) => {
		const order = { critical: 4, high: 3, medium: 2, info: 1 }
		return (order[issue.severity] ?? 0) > (order[worst] ?? 0) ? issue.severity : worst
	}, 'none') }
}

/**
 * 访问矩阵：身份 × 请求 的探测计划。
 * @param identities - `[{ name, headers }]`（如 operator / tenant-b / anonymous）
 * @param requests - `[{ name, method, url, body? }]`
 * @returns 扁平化后的探测项（每项带唯一 id，便于执行侧回填结果）
 */
export function buildAccessMatrix(identities, requests) {
	const matrix = []
	for (const identity of identities ?? []) {
		for (const request of requests ?? []) {
			matrix.push({
				id: `${identity.name}::${request.name}`,
				identity: identity.name,
				name: request.name,
				method: request.method ?? 'GET',
				url: request.url,
				...(request.body === undefined ? {} : { body: request.body }),
				...(identity.headers === undefined ? {} : { headers: identity.headers })
			})
		}
	}
	return matrix
}

/**
 * 两个身份对同一资源的响应差异归类。
 * @param owner - 资源属主的响应 `{ status, bodyLength, body? }`
 * @param other - 另一身份的响应
 * @returns `{ verdict, severity, reason }`，verdict ∈
 *   `protected`（另一身份被拒，正常）/`bola-candidate`（另一身份也拿到且内容不同）/
 *   `idor-candidate`（另一身份拿到完全相同内容，通常是同一越权读取）/
 *   `indeterminate`（信息不足）
 */
export function classifyAccessPair(owner, other) {
	if (owner === undefined || other === undefined) return { verdict: 'indeterminate', severity: 'info', reason: '缺少一侧响应' }
	const ok = (response) => Number(response.status ?? 0) >= 200 && Number(response.status ?? 0) < 300
	if (!ok(other)) return { verdict: 'protected', severity: 'none', reason: `另一身份被拒（${other.status}）` }
	if (!ok(owner)) return { verdict: 'indeterminate', severity: 'info', reason: `属主侧不是 2xx（${owner.status}），基线不可信` }
	const sameLength = Number(owner.bodyLength ?? -1) === Number(other.bodyLength ?? -2)
	const sameBody = owner.body !== undefined && other.body !== undefined && String(owner.body) === String(other.body)
	if (sameBody || sameLength) return { verdict: 'idor-candidate', severity: 'high', reason: '另一身份拿到与属主相同/等长的内容 —— 越权读取候选，需人工确认资源归属' }
	return { verdict: 'bola-candidate', severity: 'high', reason: '另一身份返回 2xx 但内容不同 —— 可能是跨租户对象访问，需人工核对响应字段' }
}

/** 矩阵结果 → 越权候选列表（只保留有差异的项）。 */
export function authzCandidates(results) {
	const rows = Array.isArray(results) ? results : []
	const byResource = new Map()
	for (const row of rows) {
		const key = row.resource ?? row.url
		byResource.set(key, [...(byResource.get(key) ?? []), row])
	}
	const candidates = []
	for (const [resource, group] of byResource) {
		const owner = group.find((row) => row.isOwner === true) ?? group[0]
		for (const other of group) {
			if (other === owner || other.identity === owner.identity) continue
			const verdict = classifyAccessPair(owner, other)
			if (verdict.verdict === 'idor-candidate' || verdict.verdict === 'bola-candidate') candidates.push({ resource, owner: owner.identity, other: other.identity, ...verdict })
		}
	}
	return candidates
}
