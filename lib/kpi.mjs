/**
 * 降噪与质量度量（路线图第 7 项）。
 *
 * 没有 KPI 的审计结论是不可度量的：说「扫出 300 个漏洞」没有意义，
 * 有意义的是「候选 300 → 确认 42，确认率 14%，其中 critical 命中率 80%」。
 * 另外提供跨引擎合并：同一位置 + 同一规则族的命中应合并为一条并提升置信度。
 */

const SEVERITY_ORDER = ['none', 'info', 'unknown', 'low', 'medium', 'high', 'critical']

/** 严重度排序（用于取更严重者）。 */
export function severityRank(value) {
	const index = SEVERITY_ORDER.indexOf(String(value ?? '').trim().toLowerCase())
	return index < 0 ? 0 : index
}

const normalizeTarget = (value) => String(value ?? '').trim().toLowerCase().replace(/\/+$/, '')

/**
 * 计算降噪 KPI。
 * @param findings - `[{ severity, status?, ruleId?, target?, engine?, confirmed? }]`
 *   `confirmed` 或 `status === 'fixed'|'open'` 视为已确认；其余按候选计。
 * @returns 计数与比率（比率保留 4 位小数，除零返回 null）
 */
export function denoiseKpis(findings) {
	const rows = Array.isArray(findings) ? findings : []
	const isConfirmed = (row) => row.confirmed === true || ['fixed', 'open', 'wontfix', 'confirmed', 'regressed'].includes(String(row.status ?? '').toLowerCase())
	const bySeverity = {}
	const byEngine = {}
	const byRule = {}
	let confirmed = 0
	for (const row of rows) {
		const severity = String(row.severity ?? 'unknown').toLowerCase()
		bySeverity[severity] = bySeverity[severity] ?? { total: 0, confirmed: 0 }
		bySeverity[severity].total += 1
		if (row.engine !== undefined) byEngine[row.engine] = (byEngine[row.engine] ?? 0) + 1
		if (row.ruleId !== undefined) byRule[row.ruleId] = (byRule[row.ruleId] ?? 0) + 1
		if (isConfirmed(row)) {
			confirmed += 1
			bySeverity[severity].confirmed += 1
		}
	}
	const ratio = (a, b) => (b === 0 ? null : Number((a / b).toFixed(4)))
	const highPlus = ['critical', 'high'].reduce((sum, key) => sum + (bySeverity[key]?.total ?? 0), 0)
	const highPlusConfirmed = ['critical', 'high'].reduce((sum, key) => sum + (bySeverity[key]?.confirmed ?? 0), 0)
	return {
		total: rows.length,
		confirmed,
		candidates: rows.length - confirmed,
		confirmRate: ratio(confirmed, rows.length),
		falsePositiveRate: ratio(rows.length - confirmed, rows.length),
		highPlus,
		highPlusConfirmed,
		highPlusConfirmRate: ratio(highPlusConfirmed, highPlus),
		bySeverity,
		byEngine,
		byRule,
		// 按规则族的命中分布（找出「总在报但总不确认」的规则）
		noisyRules: Object.entries(byRule).filter(([rule]) => rows.filter((row) => row.ruleId === rule && !isConfirmed(row)).length > 0)
			.map(([rule]) => ({ ruleId: rule, total: byRule[rule], unconfirmed: rows.filter((row) => row.ruleId === rule && !isConfirmed(row)).length }))
			.sort((left, right) => right.unconfirmed - left.unconfirmed)
			.slice(0, 10)
	}
}

/** KPI → Markdown 表格（直接进报告）。 */
export function kpiMarkdown(kpi) {
	const percent = (value) => (value === null ? '—' : `${(value * 100).toFixed(1)}%`)
	const lines = [
		'| 指标 | 值 |',
		'| :-- | :-- |',
		`| 候选总数 | ${kpi.total} |`,
		`| 已确认 | ${kpi.confirmed} |`,
		`| 确认率 | ${percent(kpi.confirmRate)} |`,
		`| 未确认占比（≈误报率上界） | ${percent(kpi.falsePositiveRate)} |`,
		`| 高危及以上 | ${kpi.highPlus}（确认 ${kpi.highPlusConfirmed}，${percent(kpi.highPlusConfirmRate)}） |`
	]
	const severities = Object.entries(kpi.bySeverity).sort((left, right) => severityRank(right[0]) - severityRank(left[0]))
	if (severities.length > 0) {
		lines.push('', '| 严重度 | 数量 | 已确认 |', '| :-- | --: | --: |')
		for (const [severity, row] of severities) lines.push(`| ${severity} | ${row.total} | ${row.confirmed} |`)
	}
	return lines.join('\n')
}

const ruleFamily = (ruleId) => String(ruleId ?? '').trim().toLowerCase().replace(/[-_.]?\d+$/, '').replace(/(\d+)$/, '')

/**
 * 跨引擎合并：同一「位置 + 规则族」的多引擎命中合并为一条，置信度提升。
 * 位置键：ruleId 之外的 filepath/url + 可选 line。
 * @returns `{ merged, dropped }`：merged 为合并结果，每个含 `engines[]` 与 `confidence`。
 */
export function mergeEngines(findings) {
	const merged = new Map()
	let dropped = 0
	for (const row of Array.isArray(findings) ? findings : []) {
		const location = normalizeTarget(row.filepath ?? row.url ?? row.target ?? '')
		const key = `${location}|${row.line ?? ''}|${ruleFamily(row.ruleId)}`
		const found = merged.get(key)
		if (found === undefined) {
			merged.set(key, { ...row, engines: row.engine === undefined ? [] : [row.engine], confidence: 'low', mergedCount: 1 })
			continue
		}
		dropped += 1
		if (row.engine !== undefined && !found.engines.includes(row.engine)) found.engines.push(row.engine)
		found.mergedCount += 1
		if (severityRank(row.severity) > severityRank(found.severity)) found.severity = row.severity
		// 多引擎一致 → 置信度提升
		found.confidence = found.engines.length >= 2 ? 'high' : 'medium'
	}
	return { merged: [...merged.values()], dropped }
}
