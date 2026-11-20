/**
 * 探索链路 / 资产图的布局回归（v2.2.3）。
 *
 * 真实事故：一个含 6 intents / 37 facts / 11 findings 的会话，节点按「层 = 一列」
 * 排成单列长条，包围盒高达 4376px；ReactFlow 的默认 minZoom=0.5 又把 fitView
 * 的 0.14 强行放大到 0.5，结果节点挤成两根细竖条、左边大片空白。
 *
 * 修法：每列最多 8 行后折列（整体接近方阵）+ 把 minZoom 放宽到 0.15。
 * 这里用真实规模的合成数据锁住「不退化成长条」与「缩放不被 minZoom 卡住」。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const bundle = readFileSync(join(root, 'lib', 'ui-pentest.client.js'), 'utf8')

// bundle 里是打包后的实现，直接 eval 它依赖较多运行时；这里改为复刻同一算法，
// 并用「bundle 源码契约」断言两者没有漂移（下方 test('bundle 与测试实现一致')）。
function depthsOf(roots, edges) {
	const depth = new Map()
	const queue = []
	for (const root of roots) { depth.set(root, 0); queue.push({ id: root, level: 0 }) }
	for (const { id, level } of queue) for (const edge of edges) {
		if (edge.sourceId !== id || depth.has(edge.targetId)) continue
		depth.set(edge.targetId, level + 1)
		queue.push({ id: edge.targetId, level: level + 1 })
	}
	return depth
}
function stackByDepth(items, depth, columnGap, rowGap, maxRows = 8) {
	const maxDepth = Math.max(0, ...depth.values())
	const rows = new Map()
	for (const item of items) {
		const level = depth.get(item.id) ?? maxDepth + 1
		if (!rows.has(level)) rows.set(level, [])
		rows.get(level).push(item)
	}
	const placed = []
	let columnCursor = 0
	for (const [, row] of [...rows.entries()].sort((a, b) => a[0] - b[0])) {
		const slices = Math.max(1, Math.ceil(row.length / maxRows))
		for (let slice = 0; slice < slices; slice += 1) {
			const bucket = row.slice(slice * maxRows, (slice + 1) * maxRows)
			const x = (columnCursor + slice) * columnGap
			for (const [index, item] of bucket.entries()) placed.push({ ...item, x, y: index * rowGap })
		}
		columnCursor += slices
	}
	return placed
}

const NODE_W = 236, NODE_H = 120, COL_GAP = 320, ROW_GAP = 152
const VIEW = { w: 1894, h: 620 }

/** 真实规模：1 goal + 6 intents + 37 facts + 11 findings，分层成 6 级 */
function realistic() {
	const items = [{ id: 'goal-1' }, { id: 'intent-1' }]
	for (let i = 2; i <= 6; i += 1) items.push({ id: `intent-${i}` })
	for (let i = 1; i <= 37; i += 1) items.push({ id: `fact-${i}` })
	for (let i = 1; i <= 11; i += 1) items.push({ id: `finding-${i}` })
	const edges = [{ sourceId: 'goal-1', targetId: 'intent-1' }]
	for (let i = 2; i <= 6; i += 1) edges.push({ sourceId: 'intent-1', targetId: `intent-${i}` })
	for (let i = 1; i <= 37; i += 1) edges.push({ sourceId: `intent-${1 + (i % 5)}`, targetId: `fact-${i}` })
	for (let i = 1; i <= 11; i += 1) edges.push({ sourceId: `intent-${1 + (i % 5)}`, targetId: `finding-${i}` })
	return { items, edges }
}

const bounds = (placed) => ({
	w: Math.max(...placed.map((p) => p.x)) - Math.min(...placed.map((p) => p.x)) + NODE_W,
	h: Math.max(...placed.map((p) => p.y)) - Math.min(...placed.map((p) => p.y)) + NODE_H
})
const fitZoom = (b) => Math.min(VIEW.w / b.w, VIEW.h / b.h, 1)

test('真实规模下布局不退化成长条（宽高比合理）', () => {
	const { items, edges } = realistic()
	const depth = depthsOf(['goal-1'], edges)
	const placed = stackByDepth(items, depth, COL_GAP, ROW_GAP)
	const b = bounds(placed)
	assert.ok(placed.length === items.length, '所有节点都要被放置')
	assert.ok(b.h / b.w < 3, `包围盒不该是高瘦长条（实际 ${b.w}x${b.h}，比例 ${(b.h / b.w).toFixed(2)}）`)
})

test('每列不超过 8 行（折列生效）', () => {
	const { items, edges } = realistic()
	const depth = depthsOf(['goal-1'], edges)
	const placed = stackByDepth(items, depth, COL_GAP, ROW_GAP)
	const byX = new Map()
	for (const p of placed) byX.set(p.x, (byX.get(p.x) ?? 0) + 1)
	for (const [x, count] of byX) assert.ok(count <= 8, `x=${x} 这一列有 ${count} 个节点，超过 maxRows=8`)
})

test('fitView 的缩放不被 minZoom 卡住', () => {
	const { items, edges } = realistic()
	const depth = depthsOf(['goal-1'], edges)
	const b = bounds(stackByDepth(items, depth, COL_GAP, ROW_GAP))
	const need = fitZoom(b)
	// 抽出 ExploreView 实际声明的 minZoom
	const decl = /minZoom:\s*\.(\d+)/.exec(bundle)
	assert.ok(decl !== null, 'ExploreView 必须显式声明 minZoom')
	const minZoom = Number('0.' + decl[1])
	assert.ok(need >= minZoom, `需要的缩放 ${need.toFixed(2)} 低于 minZoom ${minZoom}，会被强行放大 → 留白`)
	assert.ok(need > 0.3, `缩放不应过小（实际 ${need.toFixed(2)}），否则文字不可读`)
})

test('横向利用率足够（不再出现大片空白）', () => {
	const { items, edges } = realistic()
	const depth = depthsOf(['goal-1'], edges)
	const placed = stackByDepth(items, depth, COL_GAP, ROW_GAP)
	const b = bounds(placed)
	const zoom = Math.max(fitZoom(b), 0.15)
	const usage = (zoom * b.w) / VIEW.w
	assert.ok(usage > 0.6, `横向利用率应 > 60%（实际 ${(usage * 100).toFixed(0)}%）`)
})

test('bundle 与测试实现一致（防漂移）', () => {
	// stackByDepth 必须支持 maxRows 折列，且默认 8
	assert.match(bundle, /function stackByDepth\(items, depth, columnGap, rowGap, maxRows = 8\)/, 'stackByDepth 签名应带 maxRows = 8')
	assert.match(bundle, /Math\.ceil\(row\.length \/ maxRows\)/, '折列逻辑应基于 maxRows')
	// 两个图都必须显式放宽 minZoom
	const minZooms = bundle.match(/minZoom:\s*\.15/g) ?? []
	assert.ok(minZooms.length >= 2, `探索链路与资产图都应声明 minZoom: .15（实际 ${minZooms.length} 处）`)
	assert.match(bundle, /fitViewOptions: \{ padding: \.2, maxZoom: 1 \}/, 'fitView 应限制初始 maxZoom，避免小图被放得过大')
})
