/**
 * 一键复测引擎：对基线里的每条 finding 现场重放判定请求，抓新的原始请求/响应，
 * 给出「仍存在 / 已修复 / 需人工复核」结论，并把数据包一并返回（页面内联 + Markdown）。
 *
 * 设计要点：
 *   - 判定逻辑是声明式的 CHECK_SPECS：按 finding 标题（稳定对齐键的前半段）匹配，
 *     换会话、换 asset id 都不影响；匹配不到的 finding 标记 unclear（不猜）。
 *   - 每个请求用 curl 真打一次（只读 GET/POST 查询，写接口一律用空体，不产生业务数据），
 *     原始请求/响应同时落盘成 .http（复用 http-evidence.mjs 能解析的分段格式）。
 *   - 结果按（sessionId + baseline 文件指纹 + 目标）缓存 5 分钟，页面刷新不重复打靶。
 */

import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { randomUUID } from 'node:crypto'

const TIMEOUT_MS = 15000
const DELAY_MS = 220
const CACHE_TTL_MS = 5 * 60 * 1000

const norm = (value) => String(value ?? '').trim().toLowerCase().replace(/\/+$/, '')

function homeRoot() {
	return process.env.DSH_HOME || join(process.env.HOME || homedir(), '.dsh')
}

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

function parseHeaders(text) {
	const headers = {}
	for (const line of String(text ?? '').split(/\r?\n/)) {
		const m = /^([^:\s][^:]*):\s*(.*)$/.exec(line)
		if (m === null) continue
		const key = m[1].trim().toLowerCase()
		const value = m[2].trim()
		headers[key] = headers[key] === undefined ? value : `${headers[key]}\n${value}`
	}
	return headers
}

/** 用 curl 打一次，返回 { status, headers, body, rawRequest, rawResponse }。 */
function curlOnce(spec) {
	return new Promise((resolve) => {
		const started = Date.now()
		const args = ['-sS', '-k', '--max-time', String(Math.round(TIMEOUT_MS / 1000)), '--noproxy', '*', '-X', spec.method, '-D', '-']
		for (const [name, value] of Object.entries(spec.headers ?? {})) args.push('-H', `${name}: ${value}`)
		if (spec.body !== undefined && spec.body !== null) args.push('--data-binary', String(spec.body))
		if (spec.pathAsIs) args.push('--path-as-is')
		if (spec.http1) args.push('--http1.1')
		if (spec.maxRedirs !== undefined) args.push('--max-redirs', String(spec.maxRedirs))
		args.push('-w', '\n@@CURL_META@@%{http_code}', spec.url)
		execFile('curl', args, { timeout: TIMEOUT_MS + 3000, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) => {
			const text = String(stdout ?? '')
			const metaIndex = text.lastIndexOf('@@CURL_META@@')
			const head = metaIndex >= 0 ? text.slice(0, metaIndex).replace(/\n$/, '') : text
			const status = metaIndex >= 0 ? Number(text.slice(metaIndex + '@@CURL_META@@'.length).trim()) || 0 : 0
			const split = /\r?\n\r?\n/.exec(head)
			const headerText = split ? head.slice(0, split.index) : head
			const body = split ? head.slice(split.index + split[0].length) : ''
			const statusLine = /^HTTP\/\S+\s+(\d{3})/m.exec(headerText)
			const requestLines = [`${spec.method} ${spec.url} HTTP/1.1`]
			for (const [name, value] of Object.entries(spec.headers ?? {})) requestLines.push(`${name}: ${value}`)
			if (spec.body !== undefined && spec.body !== null) {
				requestLines.push('content-length: ' + String(spec.body).length)
			}
			const rawRequest = requestLines.join('\n')
			const rawResponse = headerText.trim() + (body ? '\n' + body : '')
			resolve({
				ok: !error && status !== 0,
				durationMs: Date.now() - started,
				status: status || Number(statusLine?.[1] ?? 0) || 0,
				statusText: (statusLine ? headerText.split('\n')[0] : '').trim(),
				headers: parseHeaders(headerText),
				body,
				rawRequest,
				rawResponse,
				error: error ? String(error.message ?? error) : ''
			})
		})
	})
}

// ── 判定规格 ────────────────────────────────────────────────────────────────
// match: 该 finding 标题必须包含的关键词（大小写不敏感）；judge(responses) 返回结论。
// Declarative retest specs. Each: { id, match: [title keywords], label, requests: [...], judge: (responses) => verdict }.
// Ships empty: per-target specs belong to the engagement, not the plugin. Inject via options.specs.
// Schema + worked examples: dev/reprobe-specs.example.mjs
const CHECK_SPECS = [];

function specFor(title, specs) {
	const pool = Array.isArray(specs) && specs.length ? specs : CHECK_SPECS
	const text = norm(title)
	return pool.find((spec) => spec.match.some((needle) => text.includes(norm(needle)))) ?? null
}

function judgeResponses(spec, responses) {
	if (responses.some((response) => !response.ok || response.status === 0 || response.status >= 500 || response.status === 429)) {
		return { verdict: 'unclear', detail: '请求失败、超时、限流或服务异常，无法确认修复；请检查本轮数据包后重试' }
	}
	return spec.judge(responses)
}

function specMatchesTarget(spec, baseline) {
	let target = String(baseline?.target ?? '').trim().toLowerCase()
	try { target = new URL(target.includes('://') ? target : 'https://' + target).hostname } catch { return false }
	return target !== '' && spec.requests.every((request) => {
		const host = new URL(request.url).hostname.toLowerCase()
		return host === target || host.endsWith('.' + target)
	})
}

function slugify(value) {
	return String(value ?? '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'check'
}

function renderHttpFile(packets) {
	const blocks = packets.map((packet) => [
		`=== ${packet.method} ${packet.url} -> ${packet.status} ===`,
		'--- request headers ---',
		`host: ${(() => { try { return new URL(packet.url).host } catch { return '' } })()}`,
		...Object.entries(packet.requestHeaders ?? {}).map(([k, v]) => `${k}: ${v}`),
		'--- request body ---',
		packet.requestBody ?? '',
		'--- response headers ---',
		String(packet.statusText ?? '').trim(),
		...Object.entries(packet.responseHeaders ?? {}).map(([k, v]) => `${k}: ${v}`),
		'--- response body ---',
		String(packet.responseBody ?? ''),
		''
	].join('\n'))
	return blocks.join('\n')
}

function cacheFile(sessionId) {
	return join(homeRoot(), 'storages', 'retest-cache', `${slugify(sessionId)}.json`)
}

function readCache(sessionId, stamp) {
	const file = cacheFile(sessionId)
	if (!existsSync(file)) return null
	try {
		const cached = JSON.parse(readFileSync(file, 'utf8'))
		if (cached.stamp !== stamp) return null
		if (Date.now() - Number(cached.ranAtMs ?? 0) > CACHE_TTL_MS) return null
		return cached.result
	} catch {
		return null
	}
}

function writeCache(sessionId, stamp, result) {
	const file = cacheFile(sessionId)
	mkdirSync(join(homeRoot(), 'storages', 'retest-cache'), { recursive: true })
	writeFileSync(file, JSON.stringify({ stamp, ranAtMs: Date.now(), result }, null, 2))
}

/**
 * 对单条 finding 现场重放（页面「复测这一条」按钮用）。
 * 每次点击都真打，不复用缓存，证据落到独立时间戳目录。
 */
export async function reprobeOne(baseline, key, options = {}) {
	const findings = Array.isArray(baseline?.findings) ? baseline.findings : []
	const needle = String(key ?? '')
	const finding = findings.find((row) => String(row?.key) === needle)
		?? findings.find((row) => String(row?.title ?? '') === needle)
		?? findings.find((row) => String(row?.key ?? '').startsWith(needle + '@'))
		?? findings.find((row) => {
			const rule = String(row?.key ?? '').split('@')[0]
			return rule !== '' && rule === needle
		})
	if (finding === undefined) return { error: '基线里找不到该条 finding（key 或标题不匹配）', key: String(key) }
	const spec = specFor(finding.title, options.specs)
	const runId = randomUUID()
	const startedAt = new Date().toISOString()
	const outDir = join(homeRoot(), 'storages', 'evidence', 'retest', new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID())
	mkdirSync(outDir, { recursive: true })
	if (spec === null || !specMatchesTarget(spec, baseline)) {
		return { key: finding.key, title: finding.title, severity: finding.severity, verdict: 'unclear', detail: '该条未配置自动判定规格，需人工复测', evidence: [], packets: [] }
	}
	const packets = []
	const responses = []
	for (const request of spec.requests) {
		await sleep(DELAY_MS)
		const response = await (options.transport ?? curlOnce)(request)
		responses.push(response)
		packets.push({
			method: request.method,
			url: request.url,
			status: response.status,
			statusText: response.statusText,
			durationMs: response.durationMs ?? null,
			error: response.error ?? '',
			requestHeaders: request.headers ?? {},
			requestBody: request.body ?? '',
			responseHeaders: response.headers,
			responseBody: String(response.body ?? '')
		})
	}
	let judged
	try {
		judged = judgeResponses(spec, responses)
	} catch (error) {
		judged = { verdict: 'unclear', detail: `判定异常：${String(error?.message ?? error)}` }
	}
	const file = join(outDir, `${slugify(spec.id)}.http`)
	try {
		writeFileSync(file, renderHttpFile(packets))
	} catch {
		/* 落盘失败不影响判定 */
	}
	return {
		key: finding.key,
		title: finding.title,
		severity: finding.severity,
		specId: spec.id,
		verdict: judged.verdict,
		detail: judged.detail,
		evidence: [{ kind: 'http', path: file, label: `${spec.label} — 本次点击实测原始包` }],
		packets,
		runId,
		startedAt,
		durationMs: Date.now() - Date.parse(startedAt),
		ranAt: new Date().toISOString()
	}
}

/**
 * 对基线逐条重放。返回 { ranAt, total, open, fixed, unclear, rows }。
 * rows：{ key, title, severity, verdict, detail, evidence:[{kind,path,label}], packets }。
 */
export async function runReprobe(baseline, options = {}) {
	const findings = Array.isArray(baseline?.findings) ? baseline.findings : []
	const sessionId = String(options.sessionId ?? '')
	const baselinePath = String(options.baselinePath ?? '')
	let stamp = ''
	try {
		stamp = baselinePath && existsSync(baselinePath) ? `${baselinePath}:${statSync(baselinePath).mtimeMs}` : ''
	} catch {
		stamp = ''
	}
	if (!options.force && sessionId !== '' && stamp !== '') {
		const cached = readCache(sessionId, stamp)
		if (cached) return cached
	}
	const outDir = join(homeRoot(), 'storages', 'evidence', 'retest', new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID())
	mkdirSync(outDir, { recursive: true })
	const rows = []
	for (const [index, finding] of findings.entries()) {
		const spec = specFor(finding.title, options.specs)
		if (spec === null || !specMatchesTarget(spec, baseline)) {
			rows.push({ key: finding.key, title: finding.title, severity: finding.severity, verdict: 'unclear', detail: '该条未配置自动判定规格，需人工复测', evidence: [], packets: [] })
			continue
		}
		const packets = []
		const responses = []
		for (const request of spec.requests) {
			await sleep(DELAY_MS)
			const response = await (options.transport ?? curlOnce)(request)
			responses.push(response)
			packets.push({
				method: request.method,
				url: request.url,
				status: response.status,
				statusText: response.statusText,
			durationMs: response.durationMs ?? null,
			error: response.error ?? '',
				requestHeaders: request.headers ?? {},
				requestBody: request.body ?? '',
				responseHeaders: response.headers,
				responseBody: String(response.body ?? '')
			})
		}
		let judged
		try {
			judged = judgeResponses(spec, responses)
		} catch (error) {
			judged = { verdict: 'unclear', detail: `判定异常：${String(error?.message ?? error)}` }
		}
		const file = join(outDir, `${String(index + 1).padStart(2, '0')}-${slugify(spec.id)}.http`)
		try {
			writeFileSync(file, renderHttpFile(packets))
		} catch {
			/* 落盘失败不影响判定 */
		}
		rows.push({
			key: finding.key,
			title: finding.title,
			severity: finding.severity,
			specId: spec.id,
			verdict: judged.verdict,
			detail: judged.detail,
			evidence: [{ kind: 'http', path: file, label: `${spec.label} — 本轮实测原始包` }],
			packets
		})
	}
	const result = {
		ranAt: new Date().toISOString(),
		total: rows.length,
		open: rows.filter((row) => row.verdict === 'open').length,
		fixed: rows.filter((row) => row.verdict === 'fixed').length,
		unclear: rows.filter((row) => row.verdict === 'unclear').length,
		rows
	}
	if (sessionId !== '' && stamp !== '') writeCache(sessionId, stamp, result)
	return result
}

/** 把重测结果写进 Markdown（含数据包）。 */
export function reprobeMarkdown(probe) {
	if (!probe || !Array.isArray(probe.rows)) return ''
	const lines = [
		'',
		'## 一键复测（现场重放判定）',
		'',
		`- 重测时间：${probe.ranAt}`,
		`- 共 ${probe.total} 条：**仍存在 ${probe.open}** ／ **已修复 ${probe.fixed}** ／ 需人工复核 ${probe.unclear}`,
		''
	]
	const groups = [
		{ verdict: 'open', label: '仍存在' },
		{ verdict: 'unclear', label: '需人工复核' },
		{ verdict: 'fixed', label: '已修复' }
	]
	for (const group of groups) {
		const rows = probe.rows.filter((row) => row.verdict === group.verdict)
		if (rows.length === 0) continue
		lines.push(`### ${group.label}（${rows.length}）`, '')
		for (const row of rows) {
			lines.push(`- **[${row.severity ?? 'unknown'}] ${row.title}** — ${row.detail}`)
			for (const packet of row.packets ?? []) {
				lines.push('', '```http', `${packet.method} ${packet.url}`, ...Object.entries(packet.requestHeaders ?? {}).map(([k, v]) => `${k}: ${v}`), '', packet.statusText ?? `HTTP ${packet.status}`, ...Object.entries(packet.responseHeaders ?? {}).map(([k, v]) => `${k}: ${v}`), '', String(packet.responseBody ?? '').slice(0, 1200), '```', '')
			}
		}
	}
	return lines.join('\n')
}