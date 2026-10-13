/**
 * 武器输出 → 结构化记录（**确定性**解析器）。
 *
 * 为什么要有这层：nmap 一次扫描动辄上千行，靠 agent 一条条 `pentest_add_asset` 必然
 * 漏项、重复、丢字段，而且无法度量覆盖率。这里把「工具输出的翻译」交给确定性代码，
 * agent 只负责判断（哪些是真漏洞、值不值得利用）。
 *
 * 设计约束：
 * - **纯函数、零依赖、零 I/O**：输入原始文本，输出 `{ assets, facts, notes }`，便于单测与复用。
 * - **不解析资源 id**：输出的是「逻辑父子关系」（`parent: {type, value}`），id 由调用方
 *   （持有 store 的工具）解析 —— 解析器不该知道存储层的编号规则。
 * - **稳定可复现**：输出按固定键排序、去重，同一份输入永远得到同一结果。
 * - 记录 field 名与 `pentest_add_asset` / `pentest_add_fact` 的参数一致（`type`/`value`、
 *   `kind`/`target`/`detail`），调用方可以直接转发。
 *
 * fact kind 必须是 store 认识的值：port / service / vuln / finding / http / info。
 */

/** 支持的输入类型。`auto` 按文件内容嗅探。 */
export const INGEST_KINDS = ['auto', 'nmap', 'nuclei', 'httpx', 'ffuf', 'masscan', 'naabu']

/** asset 类型（与 store 的 ASSET_TYPES 一致）。 */
const ASSET_TYPES = new Set(['root-domain', 'subdomain', 'ip', 'service', 'app', 'endpoint'])

const trim = (value) => String(value ?? '').trim()

const fact = (kind, target, detail, extra = {}) => ({ kind, target: trim(target), detail: trim(detail), ...extra })
const asset = (type, value, extra = {}) => {
	if (!ASSET_TYPES.has(type)) throw new Error(`ingest: 未知 asset 类型 ${type}`)
	return { type, value: trim(value), ...extra }
}

/** 按内容嗅探输入类型（文件名只作参考，内容优先）。 */
export function detectKind(name, text) {
	const lower = trim(name).toLowerCase()
	const head = String(text ?? '').slice(0, 4096)
	if (/<nmaprun[\s>]/.test(head)) return 'nmap'
	if (lower.endsWith('.xml') && /<host[\s>]/.test(head)) return 'nmap'
	if (lower.includes('ffuf') || /"results"\s*:\s*\[/.test(head)) return 'ffuf'
	if (/^\s*\[?\s*\{[^]*"ports"\s*:/.test(head) && /"status"\s*:\s*"open"/.test(head)) return 'masscan'
	// nuclei 与 httpx 都是 JSONL，用特征字段区分：nuclei 有 template-id，httpx 有 status_code
	const firstJson = head.split('\n').map((l) => l.trim()).find((l) => l.startsWith('{'))
	if (firstJson !== undefined) {
		if (/"template-id"|"templateID"/.test(firstJson)) return 'nuclei'
		if (/"status_code"|"status-code"/.test(firstJson)) return 'httpx'
		if (lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) return 'nuclei'
	}
	if (/"host"\s*:/.test(head) && /"port"\s*:/.test(head)) return 'naabu'
	if (lower.endsWith('.xml')) return 'nmap'
	return null
}

/** 极简 XML 取值助手：nmap 的 XML 结构固定，用正则足够，且避免引入依赖。 */
function xmlAttr(tag, name) {
	const match = new RegExp(`${name}\\s*=\\s*"([^"]*)"`).exec(tag)
	return match === null ? '' : match[1]
}

/**
 * 解析 nmap `-oX` 输出。
 * 产出：ip/subdomain 资产；端口与服务的 fact（`kind: port|service`）；脚本输出作为 info。
 */
export function parseNmapXml(xml) {
	const text = String(xml ?? '')
	if (!/<nmaprun[\s>]/.test(text)) throw new Error('ingest: 不是 nmap XML（缺少 <nmaprun>）')
	const assets = []
	const facts = []
	for (const hostBlock of text.match(/<host[\s>][^]*?<\/host>/g) ?? []) {
		const addrTag = /<address[\s][^>]*addrtype\s*=\s*"(?:ipv4|ipv6)"[^>]*>/.exec(hostBlock)
		const ip = addrTag === null ? '' : xmlAttr(addrTag[0], 'addr')
		const hostnameTag = /<hostname[\s>][^>]*>|<hostname\/>/.exec(hostBlock)
		const hostname = hostnameTag === null ? '' : xmlAttr(hostnameTag[0], 'name')
		if (ip !== '') assets.push(asset('ip', ip))
		if (hostname !== '') {
			assets.push(hostname.startsWith('*.')
				? asset('subdomain', hostname.slice(2))
				: asset('subdomain', hostname, ip === '' ? {} : { parent: { type: 'ip', value: ip } }))
		}
		const host = hostname === '' ? ip : hostname
		if (host === '') continue
		for (const portBlock of hostBlock.match(/<port[\s>][^]*?<\/port>/g) ?? []) {
			const portTag = /<port[^>]*>/.exec(portBlock)[0]
			const portId = xmlAttr(portTag, 'portid')
			const proto = xmlAttr(portTag, 'protocol') || 'tcp'
			const stateTag = /<state[\s][^>]*>/.exec(portBlock)
			const state = stateTag === null ? '' : xmlAttr(stateTag[0], 'state')
			if (portId === '' || state !== 'open') continue
			const target = `${host}:${portId}`
			facts.push(fact('port', target, `open/${proto}`, { port: Number(portId) }))
			const serviceTag = /<service[\s][^>]*>/.exec(portBlock)
			if (serviceTag !== null) {
				const name = xmlAttr(serviceTag[0], 'name')
				const product = xmlAttr(serviceTag[0], 'product')
				const version = xmlAttr(serviceTag[0], 'version')
				const banner = [name, product, version].filter((x) => x !== '').join(' ')
				if (banner !== '') {
					facts.push(fact('service', target, banner, { port: Number(portId) }))
					assets.push(asset('service', `${host}:${portId} ${name || 'unknown'}`, { parent: { type: 'ip', value: ip === '' ? host : ip }, meta: banner }))
				}
			}
			for (const scriptTag of portBlock.match(/<script[\s][^>]*>/g) ?? []) {
				const id = xmlAttr(scriptTag, 'id')
				const output = xmlAttr(scriptTag, 'output')
				if (id !== '' && output !== '') facts.push(fact('info', target, `[${id}] ${output.slice(0, 400)}`, { port: Number(portId) }))
			}
		}
	}
	return { assets, facts, notes: [] }
}

/** 解析 nuclei JSONL（`-jsonl` / `-json` 每行一个对象）。 */
export function parseNucleiJsonl(text) {
	const assets = []
	const facts = []
	const notes = []
	for (const line of String(text ?? '').split('\n')) {
		const trimmed = line.trim()
		if (trimmed === '') continue
		if (!trimmed.startsWith('{')) { notes.push(`nuclei: 跳过非 JSON 行: ${trimmed.slice(0, 60)}`); continue }
		let record
		try { record = JSON.parse(trimmed) } catch { notes.push(`nuclei: 跳过无法解析的行（前 60 字）: ${trimmed.slice(0, 60)}`); continue }
		const templateId = trim(record['template-id'] ?? record.templateID ?? record.template)
		const info = record.info ?? {}
		const severity = trim(info.severity) || 'unknown'
		const matched = trim(record['matched-at'] ?? record.matched ?? record.host ?? record.url)
		const name = trim(info.name) || templateId
		if (matched === '') { notes.push(`nuclei: 缺 matched-at，跳过 ${templateId}`); continue }
		assets.push(asset('endpoint', matched))
		const tags = Array.isArray(info.tags) ? info.tags.join(',') : trim(info.tags)
		facts.push(fact('vuln', matched, `[${severity}] ${name}${templateId === '' ? '' : ` (${templateId})`}${tags === '' ? '' : ` tags=${tags}`}`, {
			severity,
			ruleId: templateId,
			...(trim(record['matcher-name']) === '' ? {} : { matcher: trim(record['matcher-name']) }),
			...(trim(record['extracted-results']) === '' ? {} : { extracted: record['extracted-results'] }),
		}))
	}
	return { assets, facts, notes }
}

/** 解析 httpx JSONL（存活/指纹）。 */
export function parseHttpxJsonl(text) {
	const assets = []
	const facts = []
	const notes = []
	for (const line of String(text ?? '').split('\n')) {
		const trimmed = line.trim()
		if (trimmed === '') continue
		if (!trimmed.startsWith('{')) { notes.push(`nuclei: 跳过非 JSON 行: ${trimmed.slice(0, 60)}`); continue }
		let record
		try { record = JSON.parse(trimmed) } catch { notes.push(`httpx: 跳过无法解析的行: ${trimmed.slice(0, 60)}`); continue }
		const url = trim(record.url ?? (record.host === undefined ? '' : `${record.scheme ?? 'http'}://${record.host}${record.port === undefined ? '' : `:${record.port}`}`))
		if (url === '') { notes.push('httpx: 缺 url，跳过一行'); continue }
		const status = record.status_code ?? record['status-code']
		const title = trim(record.title)
		const tech = Array.isArray(record.tech) ? record.tech.join(',') : trim(record.tech)
		const webserver = trim(record.webserver)
		assets.push(asset('endpoint', url))
		if (trim(record.host) !== '') assets.push(asset('subdomain', trim(record.host)))
		const detail = [status === undefined ? '' : `HTTP ${status}`, title === '' ? '' : `title="${title}"`, webserver, tech].filter((x) => x !== '').join(' | ')
		facts.push(fact('http', url, detail, {
			...(status === undefined ? {} : { status: Number(status) }),
			...(title === '' ? {} : { title }),
			...(tech === '' ? {} : { tech: tech.split(',') }),
		}))
		if (webserver !== '' || tech !== '') assets.push(asset('app', tech === '' ? webserver : `${webserver} ${tech}`.trim(), { parent: { type: 'endpoint', value: url }, meta: detail }))
	}
	return { assets, facts, notes }
}

/** 解析 ffuf JSON（`-o out.json -of json`）。 */
export function parseFfufJson(text) {
	let parsed
	try { parsed = JSON.parse(String(text ?? '')) } catch (error) { throw new Error(`ingest: 不是合法 JSON（ffuf 需要 -of json）: ${error.message}`) }
	const results = Array.isArray(parsed?.results) ? parsed.results : []
	const assets = []
	const facts = []
	for (const row of results) {
		const url = trim(row.url)
		if (url === '') continue
		assets.push(asset('endpoint', url))
		const detail = [`HTTP ${row.status ?? '?'}`, `len=${row.length ?? '?'}`, trim(row.content_type), trim(row.redirectlocation)].filter((x) => x !== '').join(' | ')
		facts.push(fact('http', url, detail, { status: row.status === undefined ? undefined : Number(row.status), length: row.length === undefined ? undefined : Number(row.length) }))
	}
	return { assets, facts, notes: [] }
}

/** 解析 masscan `-oJ` / naabu `-json`（都是「主机 + 开放端口」）。 */
export function parsePortScanJson(text) {
	let parsed
	try { parsed = JSON.parse(String(text ?? '')) } catch (error) { throw new Error(`ingest: 不是合法 JSON（masscan 需 -oJ，naabu 需 -json）: ${error.message}`) }
	const rows = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.hosts) ? parsed.hosts : [])
	const assets = []
	const facts = []
	for (const row of rows) {
		const ip = trim(row.ip ?? row.host)
		if (ip !== '') assets.push(asset('ip', ip))
		const ports = Array.isArray(row.ports) ? row.ports : (row.port === undefined ? [] : [{ port: row.port, proto: row.protocol ?? 'tcp', status: row.status ?? 'open' }])
		for (const entry of ports) {
			const port = entry.port ?? entry.portid
			if (port === undefined) continue
			const status = trim(entry.status ?? 'open')
			if (status !== '' && status !== 'open') continue
			const target = ip === '' ? String(port) : `${ip}:${port}`
			facts.push(fact('port', target, `open/${trim(entry.proto ?? entry.protocol ?? 'tcp')}`, { port: Number(port) }))
		}
	}
	return { assets, facts, notes: [] }
}

/** 按类型分发。`auto` 先嗅探，嗅探不出就报错（不猜）。 */
export function parseOutput(kind, text, name = '') {
	const effective = kind === undefined || kind === 'auto' ? detectKind(name, text) : kind
	if (effective === null) throw new Error('ingest: 无法识别输出类型，请显式指定 kind（nmap/nuclei/httpx/ffuf/masscan/naabu）')
	switch (effective) {
		case 'nmap': return { kind: effective, ...parseNmapXml(text) }
		case 'nuclei': return { kind: effective, ...parseNucleiJsonl(text) }
		case 'httpx': return { kind: effective, ...parseHttpxJsonl(text) }
		case 'ffuf': return { kind: effective, ...parseFfufJson(text) }
		case 'masscan':
		case 'naabu': return { kind: effective, ...parsePortScanJson(text) }
		default: throw new Error(`ingest: 不支持的 kind ${effective}`)
	}
}

/**
 * 合并多份解析结果：按稳定键去重（资产 `type|value`、fact `kind|target|detail`），
 * 并返回每条记录的来源列表（同一记录被多个工具/文件命中时全部保留）。
 */
export function mergeIngest(results) {
	const assets = new Map()
	const facts = new Map()
	const notes = []
	for (const result of results ?? []) {
		if (result === null || result === undefined) continue
		const source = trim(result.source)
		for (const item of result.assets ?? []) {
			const key = `${item.type}|${item.value}`
			const found = assets.get(key)
			if (found === undefined) assets.set(key, { ...item, sources: source === '' ? [] : [source] })
			else if (source !== '' && !found.sources.includes(source)) found.sources.push(source)
		}
		for (const item of result.facts ?? []) {
			const key = `${item.kind}|${item.target}|${item.detail}`
			const found = facts.get(key)
			if (found === undefined) facts.set(key, { ...item, sources: source === '' ? [] : [source] })
			else {
				if (source !== '' && !found.sources.includes(source)) found.sources.push(source)
				// 同一 fact 被多个来源命中：合并更强的字段（有 severity 取更严重的）
				if (item.severity !== undefined && (found.severity === undefined || severityRank(item.severity) > severityRank(found.severity))) found.severity = item.severity
			}
		}
		for (const note of result.notes ?? []) notes.push(note)
	}
	return {
		assets: [...assets.values()].sort((a, b) => (a.type === b.type ? a.value.localeCompare(b.value) : a.type.localeCompare(b.type))),
		facts: [...facts.values()].sort((a, b) => (a.kind === b.kind ? a.target.localeCompare(b.target) : a.kind.localeCompare(b.kind))),
		notes,
	}
}

const SEVERITY_ORDER = ['info', 'unknown', 'low', 'medium', 'high', 'critical']
const severityRank = (value) => {
	const index = SEVERITY_ORDER.indexOf(trim(value).toLowerCase())
	return index < 0 ? 0 : index
}
