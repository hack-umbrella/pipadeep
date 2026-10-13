// 旧会话日志修复脚本的回归测试。
//
// 每个用例都对应一次真实事故（都是"看着像修好了、实际没修"的类型）：
//   1. dry-run 汇总行只在写路径累加 → 恒为 0 → 被误读成"无需修复"，修复从没执行过。
//   2. v0 的 `surfaceOp` 是**事件顶层**字段（{op:"replace",start,end}），只重映射 data.* 会漏
//      → dsh 报 `tool/result … surface start targets consumed assistant/chunk`。
//   3. 头部 `seedLength`（=v1 的 inheritedEventCount）删行后越界
//      → dsh 报 `Session inheritedEventCount exceeds its event count`。
//   4. 删行必须重编号，且所有 seq 引用字段一起改（漏一个就是 `targets consumed` /
//      `seq gap`），否则日志静默不可读。
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const SCRIPT = join(ROOT, 'scripts', 'repair-v0-logs.mjs')
const zstdDecode = (file) => execFileSync('zstd', ['-dc', file], { maxBuffer: 1 << 28 }).toString('utf8')
const zstdEncode = (text) => execFileSync('zstd', ['-q', '-c'], { input: Buffer.from(text, 'utf8'), maxBuffer: 1 << 28 })

let failures = 0
const ok = (name, pass, detail = '') => {
	console.log(`  ${pass ? '✓' : '✗'} ${name}${pass || !detail ? '' : ` —— ${detail}`}`)
	if (!pass) failures += 1
}

/** 造一份带合成事件、带顶层 surfaceOp、带越界 seedLength 的 v0 日志。 */
function fixture(dir) {
	const events = [
		{ type: 'turn/start', seq: 0, data: { turn: 1 } },
		{ type: 'step/start', seq: 1, data: { turn: 1, step: 1 } },
		{ type: 'reasoning-chunks', seq: 2, seq0: 2, data: { texts: ['分析一下', '这个接口'] } },
		{ type: 'assistant/chunk', seq: 4, data: { turn: 1, step: 1, chunk: { index: 0 } } },
		{ type: 'tool/call', seq: 5, data: { turn: 1, step: 1, callId: 'call_real', name: 'pentest_state', arguments: '{}' } },
		// 顶层 surfaceOp：v0 就长这样，只处理 data.* 会漏掉它
		{ type: 'tool/result', seq: 6, surfaceOp: { op: 'replace', start: 0, end: 4 }, data: { turn: 1, step: 1, callId: 'call_real', ok: true } },
		{ type: 'step/end', seq: 7, data: { turn: 1, step: 1 } },
		{ type: 'turn/end', seq: 8, data: { turn: 1, reason: { kind: 'completed' } } },
		// 旧版插件注入的合成事件（本次要清掉的东西）
		{ type: 'tool/call', seq: 9, data: { turn: 0, step: 1, callId: 'pentest-submit-1', name: 'pentest_add_fact', arguments: '{"a":1}' } },
		{ type: 'tool/call', seq: 10, data: { turn: 0, step: 2, callId: 'pentest-submit-2', name: 'pentest_add_asset', arguments: '{"b":2}' } },
		{ type: 'compaction/prune', seq: 11, data: { shadowedRange: { start: 2, end: 2 }, shadowedSeqs: [2, 10], shadowedTokenCount: 4046 } },
	]
	const header = { type: 'session', version: 0, id: 'session-fixture', createdAt: 1, cwd: dir, seedLength: 9999, agentPreset: 'pentest' }
	const file = join(dir, 'session.jsonl.zstd')
	writeFileSync(file, Buffer.concat([zstdEncode(JSON.stringify(header) + '\n'), zstdEncode(events.map((e) => JSON.stringify(e)).join('\n') + '\n')]))
	return { file, header, events }
}

const work = mkdtempSync(join(tmpdir(), 'repair-fixture-'))
const { file } = fixture(work)

// 1) dry-run 必须报出真实条数（回归：汇总恒为 0）
const dry = execFileSync('node', [SCRIPT, '--dry-run', file], { encoding: 'utf8' })
ok('dry-run 每文件列出条数', /将删除 2 个合成事件/.test(dry), dry.trim().split('\n').pop())
ok('dry-run 汇总不为 0（回归：曾经恒为 0 导致误判"无需修复"）', /共 2 个合成事件/.test(dry), dry.trim().split('\n').pop())
ok('dry-run 不写盘', zstdDecode(file).includes('pentest-submit-'))
ok('dry-run 不产生备份', !existsSync(file + '.bak'))

// 2) 实修
execFileSync('node', [SCRIPT, file], { encoding: 'utf8' })
const out = zstdDecode(file)
const lines = out.split('\n').filter((l) => l.trim() !== '')
const header = JSON.parse(lines[0])
const events = lines.slice(1).map((l) => JSON.parse(l))
ok('合成事件已清除', !out.includes('pentest-submit-'))
ok('原文件已备份', existsSync(file + '.bak') && zstdDecode(file + '.bak').includes('pentest-submit-'))
// 打包行（*chunks）在逻辑序号空间里占多格，所以连续性要按跨度算，不能按行号算。
const spanOfRow = (e) => (e.type === 'reasoning-chunks' || e.type === 'text-chunks'
	? Math.max(1, e.data?.texts?.length ?? 1)
	: e.type === 'tool-call-chunks' ? Math.max(1, (e.data?.dt?.length ?? 0) + 1) : 1)
let expected = 0
let contiguous = true
for (const e of events) {
	if (e.seq !== expected) { contiguous = false; break }
	expected += spanOfRow(e)
}
ok('逻辑序号连续重编号（按行跨度）', contiguous, events.map((e) => e.seq).join(','))

// 3) 结构规则
const bySeq = new Map(events.map((e) => [e.seq, e]))
const surface = events.find((e) => e.surfaceOp)
ok('顶层 surfaceOp 保留 op 语义', surface?.surfaceOp?.op === 'replace', JSON.stringify(surface?.surfaceOp))
ok(
	'顶层 surfaceOp 端点已重映射且指向更早的事件',
	typeof surface?.surfaceOp?.start === 'number' && surface.surfaceOp.start < surface.seq && surface.surfaceOp.end < surface.seq,
	JSON.stringify(surface?.surfaceOp),
)
const prune = events.find((e) => e.type === 'compaction/prune')
ok('shadowedRange 端点重映射', prune?.data?.shadowedRange?.start === 2 && prune.data.shadowedRange.end === 2, JSON.stringify(prune?.data?.shadowedRange))
ok('shadowedSeqs 已摘掉指向被删行的序号', Array.isArray(prune?.data?.shadowedSeqs) && !prune.data.shadowedSeqs.includes(10), JSON.stringify(prune?.data?.shadowedSeqs))
ok('shadowedTokenCount（token 数）未被误改', prune?.data?.shadowedTokenCount === 4046, String(prune?.data?.shadowedTokenCount))
ok('每个引用都能在重编号后的日志里找到目标', events.every((e) => {
	const refs = []
	if (Array.isArray(e.sourceEventSeqs)) for (const x of e.sourceEventSeqs.flat()) refs.push(x)
	if (e.surfaceOp) refs.push(e.surfaceOp.start, e.surfaceOp.end)
	if (Array.isArray(e.data?.shadowedSeqs)) refs.push(...e.data.shadowedSeqs)
	if (e.data?.shadowedRange) refs.push(e.data.shadowedRange.start, e.data.shadowedRange.end)
	return refs.every((r) => typeof r !== 'number' || bySeq.has(r))
}))

// 4) 头部自洽（回归：seedLength 越界 → dsh 报 inheritedEventCount exceeds）
ok('seedLength 超过行数时被置 0', header.seedLength === 0, String(header.seedLength))

// 5) 幂等
const again = execFileSync('node', [SCRIPT, file], { encoding: 'utf8' })
ok('再次执行是空操作（幂等）', /已修复 0 个文件/.test(again), again.trim().split('\n').pop())

console.log(failures === 0 ? '\n══ 修复脚本测试全部通过 ══' : `\n══ ${failures} 项失败 ══`)
process.exit(failures === 0 ? 0 : 1)
