/**
 * 复测 / 回归（路线图第 6 项，v2.1.0 重写为完整工作流）。
 *
 * 客户修完要复测：结论不是「又扫了一遍」，而是「上轮 42 条里 30 条已修复、
 * 9 条仍存在、2 条无法复现、新增 1 条回归」。对齐键取 (规则族, 位置)——位置优先用
 * 资产的实际值（host/url），**不用会话内从 1 重新计数的 asset id**，否则跨会话必然错配。
 *
 * v2.1.0 提供：
 *   - buildSnapshot()：把当前会话 findings + assets 存成基线（含稳定对齐键与完整证据）
 *   - diffAssessments()：两轮对比 → fixed/open/added/regressed
 *   - retestMarkdown()：详细复测报告（逐条列出变化 + 复现步骤 + HTTP 证据引用）
 *   - baselineFile()/readBaseline()/saveBaseline()/listBaselines()：基线落盘/read（纯函数 + fs）
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs'
import { dirname, join, basename } from 'node:path'
import { severityRank } from './kpi.mjs'

const norm = (value) => String(value ?? '').trim().toLowerCase().replace(/\/+$/, '')

/** 一条结论的对齐键：规则 id（去掉结尾序号）+ 位置。兼容旧调用（filepath/url/target）。 */
export function findingKey(finding) {
	const location = norm(finding.location ?? finding.filepath ?? finding.url ?? finding.target ?? finding.assetValue ?? '')
	const rule = norm(finding.ruleId ?? finding.title ?? finding.name ?? '')
	return `${rule}@${location}`
}

/**
 * Stable key for a finding that survives a new session (asset ids restart at asset-1).
 * `asset` should be the resolved asset value from the store; `location` a URL/path fallback.
 */
export function stableFindingKey(finding, assetValue = '') {
	const value = norm(finding.location ?? finding.url ?? finding.target ?? assetValue ?? finding.assetValue ?? '')
	const rule = norm(finding.ruleId ?? finding.title ?? finding.name ?? '')
	return `${rule}@${value}`
}

/**
 * Build a baseline snapshot from a session's findings + assets.
 * @param session - `{ sessionId, goal?, findings: [...], assets: [...] }`
 * @returns snapshot object (JSON-serializable, lossless) with `findings[]` each carrying
 *          `{ ruleId, location, severity, status:'open', title, description, steps, evidence, affectedAsset, key }`.
 */
export function buildSnapshot(session, options = {}) {
	const assets = Array.isArray(session?.assets) ? session.assets : []
	const findings = Array.isArray(session?.findings) ? session.findings : []
	const at = options.now ?? new Date().toISOString()
	const rows = findings.map((finding) => {
		const asset = typeof finding.affectedAssetId === 'string'
			? assets.find((candidate) => candidate.id === finding.affectedAssetId)
			: undefined
		const location = String(finding.url ?? finding.target ?? asset?.value ?? finding.filepath ?? '')
		const steps = Array.isArray(finding.reproducibleSteps) ? finding.reproducibleSteps : (Array.isArray(finding.steps) ? finding.steps : [])
		return {
			ruleId: String(finding.title ?? finding.ruleId ?? finding.name ?? ''),
			location,
			severity: String(finding.severity ?? 'unknown'),
			status: 'open',
			title: String(finding.title ?? ''),
			description: String(finding.description ?? ''),
			steps: [...steps],
			evidence: Array.isArray(finding.evidence) ? finding.evidence.map((item) => ({
				kind: String(item?.kind ?? 'file'), path: String(item?.path ?? ''), label: String(item?.label ?? '')
			})) : [],
			affectedAsset: asset ? { id: asset.id, type: String(asset.type ?? ''), value: String(asset.value ?? '') } : undefined,
			key: stableFindingKey(finding, asset?.value ?? '')
		}
	})
	return {
		kind: 'pentest-baseline',
		version: 1,
		sessionId: String(session?.sessionId ?? ''),
		target: String(session?.goal?.target ?? ''),
		objective: String(session?.goal?.objective ?? ''),
		createdAt: at,
		count: rows.length,
		findings: rows
	}
}

/**
 * 两次评估的差异。
 * @param previous - 上一轮 `[{ ruleId, filepath|url|target, severity, status? }]` 或 snapshot 对象
 * @param current - 本轮同结构
 * @returns `{ fixed, open, added, regressed, summary, previous, current }`
 *   - fixed：上轮有、本轮无（视为已修复）
 *   - open：两轮都有（仍未修复）
 *   - added：上轮无、本轮有（新发现）
 *   - regressed：上轮标记为已修复（status=fixed），本轮又出现的
 */
export function diffAssessments(previous, current) {
	const beforeList = Array.isArray(previous) ? previous : (previous?.findings ?? [])
	const afterList = Array.isArray(current) ? current : (current?.findings ?? [])
	const before = new Map(beforeList.map((row) => [row.key ?? findingKey(row), row]))
	const after = new Map(afterList.map((row) => [row.key ?? findingKey(row), row]))
	const fixed = []
	const open = []
	const added = []
	const regressed = []
	// 兼容旧调用方：每个条目既带 {previous,current,key}，也把行字段摊平（旧版返回裸行）
	const flat = (row, key) => ({ ...row, key })
	for (const [key, row] of before) {
		const wasFixed = String(row.status ?? '').toLowerCase() === 'fixed'
		if (!after.has(key)) {
			// 上轮已标记修复且本轮仍未出现 → 修复成立；否则也只是"本轮没再报"
			fixed.push({ ...flat(row, key), previous: row, key })
			continue
		}
		// 上轮说已修复、本轮又出现 → 回归（这是复测报告里最该催客户的结论）
		if (wasFixed) regressed.push({ ...flat(after.get(key), key), previous: row, current: after.get(key), key })
		else open.push({ ...flat(after.get(key), key), previous: row, current: after.get(key), key })
	}
	for (const [key, row] of after) if (!before.has(key)) added.push({ ...flat(row, key), current: row, key })
	const bySeverity = (rows) => rows.reduce((acc, row) => {
		const severity = String(row.severity ?? row.current?.severity ?? row.previous?.severity ?? 'unknown').toLowerCase()
		acc[severity] = (acc[severity] ?? 0) + 1
		return acc
	}, {})
	// 仍存在里挑出最该催客户的（严重度高在前）
	const severityOf = (row) => row.current?.severity ?? row.severity
	open.sort((left, right) => severityRank(severityOf(right)) - severityRank(severityOf(left)))
	regressed.sort((left, right) => severityRank(severityOf(right)) - severityRank(severityOf(left)))
	return {
		fixed,
		open,
		added,
		regressed,
		summary: {
			previousTotal: before.size,
			currentTotal: after.size,
			fixed: fixed.length,
			open: open.length,
			added: added.length,
			regressed: regressed.length,
			openBySeverity: bySeverity(open),
			fixedBySeverity: bySeverity(fixed),
			regressedBySeverity: bySeverity(regressed)
		}
	}
}

/** One detail row → markdown lines (location, severity, repro steps, evidence). */
function detailLines(row, label) {
	const item = row.current ?? row.previous ?? row
	const title = item.title ?? item.ruleId ?? item.name ?? ''
	const location = item.location ?? item.filepath ?? item.url ?? item.target ?? ''
	const lines = [
		`### ${label} · [${item.severity ?? 'unknown'}] ${title}`,
		`- 位置: ${location === '' ? '（未记录）' : location}`,
		`- 规则/对齐键: ${item.ruleId ?? ''}${row.key ? ` (${row.key})` : ''}`
	]
	const steps = Array.isArray(item.steps) ? item.steps : (Array.isArray(item.reproducibleSteps) ? item.reproducibleSteps : [])
	if (steps.length > 0) {
		lines.push('- 复现步骤:')
		for (const [index, step] of steps.entries()) lines.push(`  ${index + 1}. ${step}`)
	}
	const evidence = Array.isArray(item.evidence) ? item.evidence : []
	if (evidence.length > 0) {
		lines.push(`- 证据: ${evidence.map((e) => `[${e.kind ?? 'file'}] ${e.path ?? ''}`).join('；')}`)
	}
	return lines
}

/** 复测结论 → Markdown 小节（详细版：逐条列出 + 复现步骤 + 证据）。 */
export function retestMarkdown(diff, options = {}) {
	const { summary } = diff
	const lines = [
		'## 复测结论',
		'',
		`- 上轮 ${summary.previousTotal} 条 → 本轮 ${summary.currentTotal} 条`,
		`- **已修复 ${summary.fixed}** ／ **仍存在 ${summary.open}** ／ 新发现 ${summary.added} ／ 回归 ${summary.regressed}`,
		''
	]
	const limit = options.limit ?? 50
	const section = (title, rows, label) => {
		if (rows.length === 0) return
		lines.push(`## ${title}（${rows.length}）`, '')
		for (const row of rows.slice(0, limit)) lines.push(...detailLines(row, label), '')
		if (rows.length > limit) lines.push(`…另有 ${rows.length - limit} 条，见基线 JSON。`, '')
	}
	section('回归（上轮已修复本轮重现）', diff.regressed, '回归')
	section('仍存在（按严重度排序）', diff.open, '仍存在')
	section('新发现', diff.added, '新增')
	section('已修复', diff.fixed, '已修复')
	return lines.join('\n')
}

// ── 基线落盘（确定性文件路径 + 只读/写入辅助） ──────────────────────────────

/** Baselines live under $DSH_HOME/storages/baselines/<target-slug>/<name>.json */
export function baselineRoot(options = {}) {
	if (options.dir) return options.dir
	const home = process.env.DSH_HOME || join((process.env.HOME || ''), '.dsh')
	return join(home, 'storages', 'baselines')
}

function slug(value) {
	return String(value ?? '').replace(/^https?:\/\//, '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'target'
}

/** Resolve a baseline file path by name and target; refuses path traversal in name. */
export function baselineFile(name, target = '', options = {}) {
	const safe = basename(String(name ?? '')).replace(/[^A-Za-z0-9._-]+/g, '-')
	if (safe === '' || safe === '.' || safe === '..') throw new Error('基线名非法')
	const dir = options.targetDir ? options.dir : join(baselineRoot(options), slug(target))
	return join(dir, `${safe}.json`)
}

/** Save a baseline snapshot to disk; returns the path. */
export function saveBaseline(snapshot, name, options = {}) {
	const path = baselineFile(name, snapshot?.target, options)
	mkdirSync(dirname(path), { recursive: true })
	writeFileSync(path, JSON.stringify(snapshot, null, 2))
	return path
}

/** Read one baseline; throws when missing. */
export function readBaseline(path) {
	return JSON.parse(readFileSync(path, 'utf8'))
}

/** List baseline files under a target directory (name + path + mtime). */
export function listBaselines(target = '', options = {}) {
	const dir = options.targetDir ? options.dir : join(baselineRoot(options), slug(target))
	if (!existsSync(dir)) return []
	return readdirSync(dir).filter((name) => name.endsWith('.json')).sort().map((name) => ({
		name: name.slice(0, -5),
		path: join(dir, name)
	}))
}
