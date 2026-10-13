/**
 * 前端情报与证书透明度（路线图第 3 项的代码部分）。
 *
 * 你们审的多是 Java 站点：真正的接口清单常在 JS 里，密钥/内网地址也常被前端硬编码。
 * 这里做确定性抽取（正则 + 熵判断），把结果当**端点线索**入库，而不是让模型"读 JS 猜接口"。
 * crt.sh 走公开接口，无武器依赖。
 */

const dedupe = (items) => [...new Set(items.filter((item) => item !== ''))]

/** 抽取接口路径：`"/api/x"`、`'/v2/user'`、模板串里的 `/api/${id}` 片段。 */
export function extractEndpoints(jsText, options = {}) {
	const text = String(jsText ?? '')
	const paths = []
	// 引号包裹的绝对路径
	for (const match of text.matchAll(/["'`](\/[A-Za-z0-9_\-./{}$:]{2,120})["'`]/g)) paths.push(match[1])
	// fetch/axios 里直接拼的路径
	for (const match of text.matchAll(/(?:fetch|axios(?:\.\w+)?|open)\(\s*["'`](\/[^"'`]{2,120})["'`]/g)) paths.push(match[1])
	const base = options.baseUrl === undefined ? '' : String(options.baseUrl).replace(/\/+$/, '')
	const endpoints = dedupe(paths
		.filter((path) => !/\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map)$/i.test(path))
		.map((path) => (base === '' ? path : `${base}${path}`)))
	return { endpoints, count: endpoints.length }
}

/** 抽取完整 URL（含内网地址）。 */
export function extractUrls(jsText) {
	const text = String(jsText ?? '')
	const urls = []
	for (const match of text.matchAll(/https?:\/\/[A-Za-z0-9_\-.:@/?=&%~#+]+/g)) urls.push(match[0])
	return { urls: dedupe(urls), internal: dedupe(urls.filter((url) => /\/\/(?:10\.|127\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|localhost|0\.0\.0\.0)/.test(url))) }
}

const ENTROPY_MIN = 3.2
const shannon = (value) => {
	const counts = new Map()
	for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
	let entropy = 0
	for (const count of counts.values()) { const p = count / value.length; entropy -= p * Math.log2(p) }
	return entropy
}

/**
 * 抽取硬编码密钥：云厂商 AK、常见 SDK key、私钥、Bearer/JWT，以及高熵赋值。
 * @returns `{ secrets: [{ kind, value, redacted }], count }`（value 原文保留，redacted 用于报告）
 */
export function extractSecrets(jsText) {
	const text = String(jsText ?? '')
	const found = []
	const push = (kind, value) => {
		if (value === undefined || value.length < 8) return
		found.push({ kind, value, redacted: `${value.slice(0, 4)}…${value.slice(-4)}(${value.length})` })
	}
	for (const match of text.matchAll(/\bAKIA[0-9A-Z]{16}\b/g)) push('aws-access-key-id', match[0])
	for (const match of text.matchAll(/\bAIza[0-9A-Za-z_\-]{33,36}\b/g)) push('google-api-key', match[0])
	for (const match of text.matchAll(/\bsk-[A-Za-z0-9]{20,}\b/g)) push('openai-style-key', match[0])
	for (const match of text.matchAll(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g)) push('private-key', match[0])
	for (const match of text.matchAll(/eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}/g)) push('jwt', match[0])
	// 赋值式：key/secret/token/password = "高熵值"
	for (const match of text.matchAll(/["']?(?:api[_-]?key|secret|access[_-]?token|password|passwd)["']?\s*[:=]\s*["']([^"']{8,120})["']/gi)) {
		if (shannon(match[1]) >= ENTROPY_MIN) push('assigned-secret', match[1])
	}
	const unique = new Map(found.map((item) => [`${item.kind}|${item.value}`, item]))
	return { secrets: [...unique.values()], count: unique.size }
}

/** 抽取查询参数名（找参数发现的方向）。 */
export function extractParams(jsText) {
	const text = String(jsText ?? '')
	const params = []
	for (const match of text.matchAll(/[?&]([A-Za-z_][A-Za-z0-9_]{1,30})=/g)) params.push(match[1])
	for (const match of text.matchAll(/(?:params|data|body)\s*:\s*\{([^}]{0,200})\}/g)) {
		for (const key of match[1].matchAll(/([A-Za-z_][A-Za-z0-9_]{1,30})\s*:/g)) params.push(key[1])
	}
	return dedupe(params).sort()
}

/** crt.sh 查询 URL（证书透明度 → 子域）。 */
export function crtShUrl(domain) {
	return `https://crt.sh/?q=${encodeURIComponent(`%.${String(domain).trim()}`)}&output=json`
}

/** 解析 crt.sh 响应，抽出唯一子域（含通配符去星号）。 */
export function parseCrtSh(json) {
	let rows
	try { rows = typeof json === 'string' ? JSON.parse(json) : json } catch { throw new Error('parseCrtSh: 响应不是合法 JSON（crt.sh 可能限流，稍后重试）') }
	const names = []
	for (const row of Array.isArray(rows) ? rows : []) {
		for (const name of String(row?.name_value ?? row?.common_name ?? '').split('\n')) {
			const clean = name.trim().toLowerCase().replace(/^\*\./, '')
			if (clean !== '' && /^[a-z0-9.-]+$/.test(clean)) names.push(clean)
		}
	}
	const unique = dedupe(names).sort()
	return { subdomains: unique, count: unique.length }
}
