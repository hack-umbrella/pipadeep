/**
 * 报告里的「HTTP 流量证据」渲染器。
 *
 * 背景：pentest_shot 经 mitmproxy 抓到的原始请求/响应落在 evidence/<finding>/*.http，
 * finding.evidence 里只记了 { kind:'http', path, label }。旧版报告只列一个本地路径，
 * 客户拿到报告既看不到流量、也无法核对漏洞到底是怎么触发的。
 *
 * 本模块做两件事：
 *   1. readHttpEvidence() — 从 finding.evidence 里挑出 http 项，读回 .http 原文并
 *      归一化为结构化的 { method, url, status, requestHeaders, requestBody,
 *      responseHeaders, responseBody, durationMs }（兼容 shot.js 的分段文本格式，
 *      也兼容原始 HTTP 报文 / curl -i 风格）。读不到文件时不抛错，返回 path 供引用。
 *   2. renderHttpTraffic() — 把归一化结果渲染成报告 Markdown：每个漏洞一节，
 *      请求/响应分块、保留关键头与 body（截断到可控长度），并附原始文件链接。
 *
 * 纯函数、零外部依赖，便于 test/http-evidence.test.mjs 直接测。
 */
import { readFileSync, existsSync } from 'node:fs'

const MAX_BODY = 4096
const MAX_HEADERS = 40

const trim = (value) => String(value ?? '').trim()

/** Read one file as UTF-8; returns null when missing/unreadable (evidence may have moved). */
export function readTextFile(path) {
	if (typeof path !== 'string' || path === '' || !existsSync(path)) return null
	try {
		return readFileSync(path, 'utf8')
	} catch {
		return null
	}
}

/**
 * Parse the .http text produced by shot.js renderHttp() (or a raw HTTP/curl -i dump)
 * into an array of exchange objects. Never throws: unrecognized lines go into the body.
 */
export function parseHttpDump(text) {
	const source = String(text ?? '')
	if (source === '') return []
	const exchanges = []
	let current = null
	let section = 'preamble'
	for (const rawLine of source.split(/\r?\n/)) {
		const line = rawLine.replace(/\s+$/, '')
		// shot.js 分隔头：=== GET http://... -> 200 (123ms) ===
		const marker = /^===\s+(?:(.+?)\s+)?(\S+)\s+->\s+(\S+?)(?:\s+\((\d+)ms\))?\s*===$/.exec(line)
		if (marker !== null) {
			current = {
				method: trim(marker[1]) || null,
				url: trim(marker[2]),
				status: trim(marker[3]) === '?' ? null : trim(marker[3]),
				durationMs: marker[4] === undefined ? null : Number(marker[4]),
				requestHeaders: {},
				requestBody: '',
				responseHeaders: {},
				responseBody: '',
				source: 'proxy'
			}
			exchanges.push(current)
			section = 'preamble'
			continue
		}
		if (line === '--- request headers ---') { section = 'requestHeaders'; continue }
		if (line === '--- request body ---') { section = 'requestBody'; continue }
		if (line === '--- response headers ---') { section = 'responseHeaders'; continue }
		if (line === '--- response body ---') { section = 'responseBody'; continue }
		if (current === null) continue
		if (section === 'requestHeaders' || section === 'responseHeaders') {
			const header = /^([^:\s][^:]*):\s*(.*)$/.exec(line)
			if (header !== null) current[section][header[1].trim().toLowerCase()] = header[2].trim()
			continue
		}
		if (section === 'requestBody' || section === 'responseBody') {
			const key = section === 'requestBody' ? 'requestBody' : 'responseBody'
			current[key] = current[key] === '' ? line : `${current[key]}\n${line}`
			continue
		}
		// 段外文本：若看起来像状态行，补进当前 exchange
		const statusLine = /^HTTP\/\S+\s+(\d{3})/.exec(line)
		if (statusLine !== null && current.status === null) current.status = statusLine[1]
	}
	// 没有 shot.js 标记时，尝试按原始报文解析（多个请求用空行+请求行切分过于脆弱，
	// 这里只处理单个完整请求/响应，足够覆盖 curl -i / 手工粘贴的报文）。
	if (exchanges.length === 0) return parseRawHttp(source)
	// shot.js 每段之间留一个空行；去掉正文尾部空行，保留内部换行
	for (const ex of exchanges) {
		ex.requestBody = ex.requestBody.replace(/\s+$/, '')
		ex.responseBody = ex.responseBody.replace(/\s+$/, '')
	}
	return exchanges
}

/** Parse a single raw HTTP request+response dump (curl -i style). */
function parseRawHttp(source) {
	const lines = source.split(/\r?\n/)
	let i = 0
	while (i < lines.length && trim(lines[i]) === '') i += 1
	const requestLine = /^([A-Z]+)\s+(\S+)\s+HTTP\//.exec(lines[i] ?? '')
	if (requestLine === null) return []
	const exchange = {
		method: requestLine[1], url: requestLine[2], status: null, durationMs: null,
		requestHeaders: {}, requestBody: '', responseHeaders: {}, responseBody: '', source: 'raw'
	}
	i += 1
	while (i < lines.length && trim(lines[i]) !== '') {
		const header = /^([^:\s][^:]*):\s*(.*)$/.exec(lines[i])
		if (header !== null) exchange.requestHeaders[header[1].trim().toLowerCase()] = header[2].trim()
		i += 1
	}
	i += 1 // blank line
	const bodyStart = i
	while (i < lines.length && !/^HTTP\/\S+\s+\d{3}/.test(lines[i])) i += 1
	exchange.requestBody = lines.slice(bodyStart, i).join('\n').trim()
	if (i < lines.length) {
		const statusLine = /^HTTP\/\S+\s+(\d{3})/.exec(lines[i])
		if (statusLine !== null) exchange.status = statusLine[1]
		i += 1
		while (i < lines.length && trim(lines[i]) !== '') {
			const header = /^([^:\s][^:]*):\s*(.*)$/.exec(lines[i])
			if (header !== null) exchange.responseHeaders[header[1].trim().toLowerCase()] = header[2].trim()
			i += 1
		}
		i += 1
		exchange.responseBody = lines.slice(i).join('\n').trim()
	}
	return [exchange]
}

/** Sensitive header values are redacted in the report (cookies/tokens stay in the evidence file). */
const REDACT = new Set(['cookie', 'set-cookie', 'authorization', 'x-api-key', 'x-csrf-token', 'proxy-authorization'])
function redactHeaders(headers) {
	const out = []
	for (const [name, value] of Object.entries(headers ?? {}).slice(0, MAX_HEADERS)) {
		out.push(`  ${name}: ${REDACT.has(name.toLowerCase()) ? '<已脱敏>' : value}`)
	}
	return out
}

function clip(text, max = MAX_BODY) {
	const value = String(text ?? '')
	return value.length <= max ? value : `${value.slice(0, max)}\n…（截断，完整内容见原始证据文件）`
}

/** Convert an evidence-href to the read-only Web route when the path is absolute. */
export function evidenceHref(path) {
	const value = String(path ?? '')
	if (value === '') return ''
	if (/^https?:\/\//i.test(value)) return value
	return `/api/pipadeep-pentest/evidence?path=${encodeURIComponent(value)}`
}

/**
 * Collect HTTP exchanges attached to a finding via evidence items of kind 'http'.
 * Each returned entry: { path, label, href, ok, exchanges }.
 */
export function readFindingHttpEvidence(finding) {
	const items = Array.isArray(finding?.evidence) ? finding.evidence : []
	const out = []
	for (const item of items) {
		if (item === null || typeof item !== 'object') continue
		const kind = trim(item.kind).toLowerCase()
		if (kind !== 'http') continue
		if (typeof item.path !== 'string') continue
		const path = trim(item.path)
		if (path === '') continue
		const text = readTextFile(path)
		out.push({
			path,
			label: trim(item.label) || '原始 HTTP 流量',
			href: evidenceHref(path),
			ok: text !== null,
			exchanges: text === null ? [] : parseHttpDump(text)
		})
	}
	return out
}

/**
 * Render the "HTTP 流量" section for one finding.
 * Returns Markdown lines (no trailing blank line) — empty array when no http evidence.
 */
export function renderHttpTraffic(finding) {
	const files = readFindingHttpEvidence(finding)
	if (files.length === 0) return []
	const lines = ['- HTTP 流量证据:']
	for (const file of files) {
		lines.push(`  - ${file.label} — [查看原始文件](${file.href})`)
		if (!file.ok) {
			lines.push('    - （原始文件当前不可读，内容可能已移走；请按上方路径取回核对。）')
			continue
		}
		if (file.exchanges.length === 0) {
			lines.push('    - （原始文件为空或格式无法解析，请直接查看原始文件。）')
			continue
		}
		for (const [index, ex] of file.exchanges.entries()) {
			lines.push(`  - 请求 ${index + 1}: ${ex.method ?? '?'} ${ex.url}${ex.status === null ? '' : ` → ${ex.status}`}${ex.durationMs === null ? '' : ` (${ex.durationMs}ms)`}`)
			lines.push(...redactHeaders(ex.requestHeaders).map((line) => `    ${line}`))
			if (trim(ex.requestBody) !== '') lines.push('    --- 请求体 ---', ...clip(ex.requestBody).split('\n').map((line) => `    ${line}`))
			if (ex.status !== null) lines.push(`  - 响应 ${index + 1}: HTTP ${ex.status}`)
			lines.push(...redactHeaders(ex.responseHeaders).map((line) => `    ${line}`))
			if (trim(ex.responseBody) !== '') lines.push('    --- 响应体 ---', ...clip(ex.responseBody).split('\n').map((line) => `    ${line}`))
		}
	}
	return lines
}
