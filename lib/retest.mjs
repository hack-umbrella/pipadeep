/**
 * 复测 / 回归（路线图第 6 项）。
 *
 * 客户修完要复测：结论不是「又扫了一遍」，而是「上轮 42 条里 30 条已修复、
 * 9 条仍存在、2 条无法复现、新增 1 条回归」。对齐键取 (规则族, 位置)。
 */

import { severityRank } from './kpi.mjs'

const norm = (value) => String(value ?? '').trim().toLowerCase().replace(/\/+$/, '')

/** 一条结论的对齐键：规则 id（去掉结尾序号）+ 位置。 */
export function findingKey(finding) {
	const location = norm(finding.filepath ?? finding.url ?? finding.target ?? '')
	const rule = norm(finding.ruleId ?? finding.title ?? finding.name ?? '')
	return `${rule}@${location}`
}

/**
 * 两次评估的差异。
 * @param previous - 上一轮 `[{ ruleId, filepath|url|target, severity, status? }]`
 * @param current - 本轮同结构
 * @returns `{ fixed, open, added, regressed, summary }`
 *   - fixed：上轮有、本轮无（视为已修复）
 *   - open：两轮都有（仍未修复）
 *   - added：上轮无、本轮有（新发现）
 *   - regressed：上轮标记为已修复（status=fixed），本轮又出现的
 */
export function diffAssessments(previous, current) {
	const before = new Map((previous ?? []).map((row) => [findingKey(row), row]))
	const after = new Map((current ?? []).map((row) => [findingKey(row), row]))
	const fixed = []
	const open = []
	const added = []
	const regressed = []
	for (const [key, row] of before) {
		const wasFixed = String(row.status ?? '').toLowerCase() === 'fixed'
		if (!after.has(key)) {
			// 上轮已标记修复且本轮仍未出现 → 修复成立；否则也只是"本轮没再报"
			if (!wasFixed) fixed.push(row)
			continue
		}
		// 上轮说已修复、本轮又出现 → 回归（这是复测报告里最该催客户的结论）
		if (wasFixed) regressed.push({ previous: row, current: after.get(key) })
		else open.push({ previous: row, current: after.get(key) })
	}
	for (const [key, row] of after) if (!before.has(key)) added.push(row)
	const bySeverity = (rows) => rows.reduce((acc, row) => {
		const severity = String(row.severity ?? 'unknown').toLowerCase()
		acc[severity] = (acc[severity] ?? 0) + 1
		return acc
	}, {})
	// 仍存在里挑出最该催客户的（严重度高在前）
	open.sort((left, right) => severityRank(right.current.severity) - severityRank(left.current.severity))
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
			openBySeverity: bySeverity(open.map((row) => row.current)),
			fixedBySeverity: bySeverity(fixed),
			regressedBySeverity: bySeverity(regressed.map((row) => row.current))
		}
	}
}

/** 复测结论 → Markdown 小节。 */
export function retestMarkdown(diff) {
	const { summary } = diff
	const lines = [
		'## 复测结论',
		'',
		`- 上轮 ${summary.previousTotal} 条 → 本轮 ${summary.currentTotal} 条`,
		`- **已修复 ${summary.fixed}** ／ **仍存在 ${summary.open}** ／ 新发现 ${summary.added} ／ 回归 ${summary.regressed}`
	]
	if (diff.open.length > 0) {
		lines.push('', '仍存在的条目（按严重度排序）：', '', '| 严重度 | 位置 | 规则 |', '| :-- | :-- | :-- |')
		for (const row of diff.open.slice(0, 30)) {
			lines.push(`| ${row.current.severity ?? 'unknown'} | ${row.current.filepath ?? row.current.url ?? row.current.target ?? ''} | ${row.current.ruleId ?? ''} |`)
		}
	}
	return lines.join('\n')
}
