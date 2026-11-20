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
import { join, dirname } from 'node:path'
import { homedir } from 'node:os'
import { randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'

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

/**
 * 规格从「基线文件同目录的 reprobe-specs.mjs」按需加载。
 *
 * 为什么不内置：判定规格依赖具体目标的 URL/参数/成功特征，属于**该次 engagement 的资产**，
 * 不该硬编码进插件。但也绝不能只靠 `options.specs`——路由是 Web 触发的，没有调用方会传。
 * 所以约定一个固定位置：`<基线目录>/reprobe-specs.mjs`（与 round1.json 同级），
 * 由 `pentest_retest action=spec-scaffold` 生成起点文件，人工填好后一键复测即可用。
 *
 * 安全性：
 *   - 只从**基线所在目录**加载（不接受任意路径），文件名固定；
 *   - 模块内容由用户自己在本机编写、由本机 node 执行——与「写一个脚本」同信任级，
 *     但它不会从网络/其他会话被注入；
 *   - 加载失败/形状不合法 → 返回空规格并记原因，一键复测退化为「需人工复核」，不会误报。
 */
export function specsFileFor(baselinePath) {
	const dir = dirname(String(baselinePath ?? ''));
	return dir === '' ? '' : join(dir, 'reprobe-specs.mjs');
}

/** 校验一条规格的形状；返回 null 表示合法，否则返回原因。 */
function specProblem(spec) {
	if (spec === null || typeof spec !== 'object') return '规格必须是对象'
	if (typeof spec.id !== 'string' || spec.id === '') return 'spec.id 必须是非空字符串'
	if (!Array.isArray(spec.match) || spec.match.length === 0) return `${spec.id}: match 必须是非空数组`
	if (!Array.isArray(spec.requests) || spec.requests.length === 0) return `${spec.id}: requests 必须是非空数组`
	for (const request of spec.requests) {
		if (request === null || typeof request !== 'object') return `${spec.id}: 每个 request 必须是对象`
		if (typeof request.url !== 'string' || !/^https?:\/\//i.test(request.url)) return `${spec.id}: request.url 必须是 http(s) URL`
		if (typeof request.method !== 'string' || request.method === '') return `${spec.id}: request.method 必填`
	}
	if (typeof spec.judge !== 'function' && spec.expect === undefined) return `${spec.id}: 需要 judge 函数或声明式 expect`
	return null
}

/** 声明式 expect → judge 函数。够覆盖「未授权读到他⼈数据」这类常见判定，不必写 JS。 */
function judgeFromExpect(expect) {
	return (responses) => {
		const first = responses[0] ?? {}
		const body = String(first.body ?? '')
		const checks = []
		if (expect.status !== undefined) {
			const okStatus = Array.isArray(expect.status) ? expect.status.includes(first.status) : expect.status === first.status
			checks.push({ name: `状态码 ${first.status}`, ok: okStatus })
		}
		if (expect.bodyIncludes !== undefined) {
			const needles = Array.isArray(expect.bodyIncludes) ? expect.bodyIncludes : [expect.bodyIncludes]
			checks.push({ name: `响应体含 ${needles.join(' / ')}`, ok: needles.every((needle) => body.includes(String(needle))) })
		}
		if (expect.bodyExcludes !== undefined) {
			const needles = Array.isArray(expect.bodyExcludes) ? expect.bodyExcludes : [expect.bodyExcludes]
			checks.push({ name: `响应体不含 ${needles.join(' / ')}`, ok: needles.every((needle) => !body.includes(String(needle))) })
		}
		if (checks.length === 0) return { verdict: 'unclear', detail: '规格的 expect 为空，无法判定' }
		const failed = checks.filter((check) => !check.ok)
		const passed = checks.every((check) => check.ok)
		// 约定：expect 描述的是「漏洞存在」的特征 —— 命中即仍存在，未命中即已修复
		return passed
			? { verdict: 'open', detail: `仍存在：${checks.map((c) => c.name).join('；')}` }
			: { verdict: 'fixed', detail: `已修复：不满足 ${failed.map((c) => c.name).join('；')}` }
	}
}

/**
 * Load the spec list for one baseline.
 * @param baselinePath - path of the baseline JSON (specs live beside it).
 * @returns `{ specs, source, error }`; `specs` is always an array.
 */
export async function loadSpecs(baselinePath) {
	const file = specsFileFor(baselinePath)
	if (file === '' || !existsSync(file)) return { specs: [], source: file, error: 'no-specs-file' }
	let mod
	try {
		// cache-bust so an edited spec file takes effect without restarting dsh
		mod = await import(pathToFileURL(file).href + '?v=' + statSync(file).mtimeMs)
	} catch (error) {
		return { specs: [], source: file, error: `加载规格失败：${String(error?.message ?? error)}` }
	}
	const raw = Array.isArray(mod.specs) ? mod.specs : []
	if (raw.length === 0) return { specs: [], source: file, error: '规格文件里没有 specs 数组（或为空）' }
	const specs = []
	const problems = []
	for (const spec of raw) {
		const problem = specProblem(spec)
		if (problem !== null) { problems.push(problem); continue }
		specs.push(spec.judge === undefined ? { ...spec, judge: judgeFromExpect(spec.expect) } : spec)
	}
	return { specs, source: file, error: problems.length === 0 ? '' : `部分规格被忽略：${problems.join('；')}` }
}

function specFor(title, specs) {
	const pool = Array.isArray(specs) && specs.length ? specs : CHECK_SPECS
	const text = norm(title)
	return pool.find((spec) => Array.isArray(spec.match) && spec.match.some((needle) => text.includes(norm(needle)))) ?? null
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
	// 没有显式传 specs 时，从基线旁边的 reprobe-specs.mjs 自动加载（Web 路由就靠这条路径）
	const resolved = Array.isArray(options.specs) && options.specs.length > 0
		? { specs: options.specs, source: '', error: '' }
		: await loadSpecs(options.baselinePath)
	const spec = specFor(finding.title, resolved.specs)
	const runId = randomUUID()
	const startedAt = new Date().toISOString()
	const outDir = join(homeRoot(), 'storages', 'evidence', 'retest', new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID())
	mkdirSync(outDir, { recursive: true })
	if (spec === null || !specMatchesTarget(spec, baseline)) {
		const why = spec === null
			? (resolved.specs.length === 0
				? `该条未配置自动判定规格${resolved.error === 'no-specs-file' ? '（基线目录下没有 reprobe-specs.mjs）' : resolved.error === '' ? '' : `（${resolved.error}）`}，需人工复测`
				: '该条标题没有匹配到任何规格（检查 reprobe-specs.mjs 的 match 关键词），需人工复测')
			: '规格里的请求域名与基线目标不一致，为安全起见不发送请求，需人工复测'
		return { key: finding.key, title: finding.title, severity: finding.severity, verdict: 'unclear', detail: why, evidence: [], packets: [], specSource: resolved.source }
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
		// 规格文件改动也要让缓存失效，否则改完规格点复测还是旧结论
		const specFile = specsFileFor(baselinePath)
		if (specFile !== '' && existsSync(specFile)) stamp += `|${specFile}:${statSync(specFile).mtimeMs}`
	} catch {
		stamp = ''
	}
	if (!options.force && sessionId !== '' && stamp !== '') {
		const cached = readCache(sessionId, stamp)
		if (cached) return cached
	}
	const outDir = join(homeRoot(), 'storages', 'evidence', 'retest', new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID())
	mkdirSync(outDir, { recursive: true })
	// 显式 specs 优先；否则从基线旁边自动加载（Web 路由走这条）
	const resolved = Array.isArray(options.specs) && options.specs.length > 0
		? { specs: options.specs, source: '', error: '' }
		: await loadSpecs(baselinePath)
	const rows = []
	for (const [index, finding] of findings.entries()) {
		const spec = specFor(finding.title, resolved.specs)
		if (spec === null || !specMatchesTarget(spec, baseline)) {
			const why = spec === null
				? (resolved.specs.length === 0
					? `该条未配置自动判定规格${resolved.error === 'no-specs-file' ? '（基线目录下没有 reprobe-specs.mjs）' : resolved.error === '' ? '' : `（${resolved.error}）`}，需人工复测`
					: '该条标题没有匹配到任何规格（检查 reprobe-specs.mjs 的 match 关键词），需人工复测')
				: '规格里的请求域名与基线目标不一致，为安全起见不发送请求，需人工复测'
			rows.push({ key: finding.key, title: finding.title, severity: finding.severity, verdict: 'unclear', detail: why, evidence: [], packets: [] })
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
		// 让页面能解释「为什么全是需人工复核」：是没规格、规格没匹配上，还是加载失败
		specSource: resolved.source,
		specCount: resolved.specs.length,
		specError: resolved.error,
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