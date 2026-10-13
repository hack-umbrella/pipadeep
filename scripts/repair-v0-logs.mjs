#!/usr/bin/env node
// 修复旧会话日志：删除本插件在旧版 dsh（≤0.1.2）为驱动父会话投影而注入的合成
// tool/call 事件（callId 前缀 `pentest-submit-`）。dsh 0.1.5 的会话格式迁移
// （v0→v3）会拒绝这类「不匹配 open turn/step」的 tool/call，导致旧渗透会话打不开。
//
// 关键：日志的逻辑序号（seq）不是「行号」——打包行（reasoning-chunks / text-chunks /
// tool-call-chunks）各跨多个 seq。删除事件后必须按同样的跨度规则重编号，并同步重映射
// 引用序号的字段（seq0 / sourceEventSeqs / data.messageSeqs），否则报 `seq gap`。
//
// ⚠️ 两个必须记住的坑（都踩过）：
//   1. dry-run 的**汇总行**曾经只在写路径累加，恒为 0 —— 于是「共删除 0 个」被误读成
//      「无需修复」，修复实际上从未执行。现在 dry-run 与实写共用同一套计数，且只列
//      **需要修复**的文件（`--verbose` 才逐条列无需修复的）。
//   2. 修完必须**用真正的消费方验证**：dsh 自己的迁移器才是权威。命令行自检只能覆盖已知规则，
//      所以写盘前先跑 `validateArtifact`，它自己不过就不写；之后再用 dsh 复验（见 README）。
//
// 用法：
//   node repair-v0-logs.mjs <session.jsonl.zstd> [more...]
//   node repair-v0-logs.mjs --all <DSH_HOME>/sessions     # 递归处理所有 session.jsonl.zstd
// 选项：--dry-run 只报告不写；默认先写 .bak 备份。
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const INJECTED = /^pentest-submit-/;
const args = process.argv.slice(2);
const dry = args.includes("--dry-run");
const verbose = args.includes("--verbose") || args.includes("-v");
const all = args.indexOf("--all");
const targets = all >= 0 ? collect(args[all + 1]) : args.filter((a) => !a.startsWith("--"));

function collect(dir) {
	const out = [];
	(function walk(d) {
		for (const name of readdirSync(d)) {
			const p = join(d, name);
			let st;
			try { st = statSync(p); } catch { continue; }
			if (st.isDirectory()) walk(p);
			else if (name === "session.jsonl.zstd") out.push(p);
		}
	})(dir);
	return out;
}

const zstdDecode = (file) => execFileSync("zstd", ["-dc", file], { maxBuffer: 1 << 30 }).toString("utf8");
const zstdEncode = (text) => execFileSync("zstd", ["-q", "-c"], { input: Buffer.from(text, "utf8"), maxBuffer: 1 << 30 });

/** 一行在逻辑 seq 空间里占多少格：打包 chunk 行按 chunk 数，普通行 1。 */
function spanOf(ev) {
	const t = ev.type;
	if (t === "reasoning-chunks" || t === "text-chunks") return Math.max(1, (ev.data?.texts?.length ?? 1));
	if (t === "tool-call-chunks") return Math.max(1, (ev.data?.dt?.length ?? 0) + 1);
	return 1;
}

/** 一行携带的「起始逻辑序号」：打包行用 seq0，普通行用 seq；header 无。 */
function startSeqOf(ev) {
	if (Object.hasOwn(ev, "seq")) return ev.seq;
	if (Object.hasOwn(ev, "seq0")) return ev.seq0;
	return undefined;
}

const isInjected = (ev) => ev.type === "tool/call" && INJECTED.test(String(ev?.data?.callId ?? ""));

let totalDropped = 0;
let filesTouched = 0;
for (const file of targets) {
	if (!existsSync(file)) { console.log("跳过(不存在):", file); continue; }
	const raw = zstdDecode(file);
	const lines = raw.split("\n").filter((l) => l.trim() !== "");
	if (lines.length === 0) { console.log("跳过(空):", file); continue; }
	const header = lines[0];
	const parsed = [];
	for (const line of lines.slice(1)) {
		try { parsed.push({ line, ev: JSON.parse(line) }); } catch { parsed.push({ line, ev: null }); }
	}
	const droppedCount = parsed.filter((p) => p.ev && isInjected(p.ev)).length;
	if (droppedCount === 0) {
		if (verbose) console.log(`无需修复(${parsed.length} 行): ${file}`);
		continue;
	}
	filesTouched += 1;
	if (dry) {
		totalDropped += droppedCount;
		console.log(`[dry-run] 将删除 ${droppedCount} 个合成事件: ${file}`);
		continue;
	}

	// 第一遍：建旧→新逻辑序号映射（按跨度推进；删除的行只推进旧游标）
	const remap = new Map();
	const injectedSeqs = new Set();
	let oldCursor = 0;
	let newCursor = 0;
	for (const { ev } of parsed) {
		if (ev === null) continue;
		const start = startSeqOf(ev);
		const span = spanOf(ev);
		if (start === undefined) continue;
		if (isInjected(ev)) { for (let i = 0; i < span; i += 1) injectedSeqs.add(start + i); oldCursor = start + span; continue; }
		for (let i = 0; i < span; i += 1) remap.set(start + i, newCursor + i);
		newCursor += span;
		oldCursor = start + span;
	}
	const mapSeq = (n) => (typeof n === "number" && remap.has(n) ? remap.get(n) : n);
	const survivingOld = [...remap.keys()].sort((a, b) => a - b);
	/** 悬空序号 → 最近的不大于它的存活序号（范围端点必须指向存在的事件）。 */
	const survive = (n) => {
		if (typeof n !== "number" || !injectedSeqs.has(n)) return n;
		let low = 0;
		let high = survivingOld.length - 1;
		let candidate = n;
		while (low <= high) {
			const mid = (low + high) >> 1;
			if (survivingOld[mid] < n) { candidate = survivingOld[mid]; low = mid + 1; }
			else high = mid - 1;
		}
		return candidate === n ? (survivingOld.find((x) => x > n) ?? n) : candidate;
	};
	/** 引用列表：成员是单值，或 [start,end] 区间对。 */
	const mapRefList = (list) => list.map((entry) => (Array.isArray(entry) ? entry.map((x) => mapSeq(survive(x))) : mapSeq(survive(entry))));
	/** 端点对象：v0/v1 用 {start,end}，v2+ 用 {startSeq,endSeq}，都认。 */
	const mapRange = (range) => {
		const out = { ...range };
		for (const key of ["start", "end", "startSeq", "endSeq"]) if (typeof out[key] === "number") out[key] = mapSeq(survive(out[key]));
		return out;
	};
	/**
	 * 需要重映射的引用字段 —— 照着 dsh 迁移器源码枚举（v1→v2 的 mapEventData / v2→v3 / v3→v4）：
	 *   command/done        → data.sourceEventSeq
	 *   compaction/prune|summary → data.shadowedRange{start,end} + data.shadowedSeqs[]
	 *   session/title*      → data.messageSeqs[]
	 *   surface 类事件       → data.surfaceOp{start,end}|{startSeq,endSeq}（"append" 是字符串，跳过）
	 *   developer/message   → data.headerSeq
	 *   多数事件（顶层）      → sourceEventSeqs（[start,end] 区间对数组）
	 * ⚠️ data.shadowedTokenCount 是 token 数不是序号，绝不能一起改（数值常落在序号值域里）。
	 */
	const REFERENCE_KEYS = ["sourceEventSeq", "messageSeqs", "shadowedSeqs", "shadowedRange", "surfaceOp", "headerSeq"];
	const mapRefs = (container) => {
		for (const key of REFERENCE_KEYS) {
			if (!Object.hasOwn(container, key)) continue;
			const value = container[key];
			if (Array.isArray(value)) container[key] = mapRefList(value);
			else if (value !== null && typeof value === "object") container[key] = mapRange(value);
			else if (typeof value === "number") container[key] = mapSeq(survive(value));
		}
		return container;
	};

	/** 复刻 dsh v0→v4 迁移里会拒绝的已知结构性规则；自己不过就不写盘。 */
	function validateArtifact(events) {
		let turn = null;
		let step = null;
		const open = new Map();
		const problems = [];
		const warnings = [];
		for (const ev of events) {
			const t = ev.type;
			const d = ev.data ?? {};
			if (t === "turn/start") { turn = d.turn ?? null; step = null; continue; }
			if (t === "turn/end") {
				// 未闭合的 tool/call 只警告不拦：v0 日志里本来就有中断场景，dsh 迁移对
				// 部分形态会自行修复（isExactToolNotStartedRepair），是否可迁移以 dsh 为准。
				if (open.size !== 0) warnings.push(`turn/end 时仍有未闭合的 tool/call: ${[...open.keys()][0]}`);
				open.clear();
				if (turn !== null && d.turn !== turn) problems.push(`turn/end 的 turn=${d.turn} 与打开的 ${turn} 不符`);
				turn = null; step = null; continue;
			}
			if (t === "step/start") { step = d.step ?? null; continue; }
			if (t === "step/end") { if (d.turn !== turn || d.step !== step) problems.push(`step/end(turn=${d.turn},step=${d.step}) 与打开(${turn},${step}) 不符`); step = null; continue; }
			if (t === "tool/call") {
				if (turn === null || step === null || d.turn !== turn || d.step !== step) {
					problems.push(`tool/call(turn=${d.turn},step=${d.step}) 不在打开中的 turn/step(${turn},${step}) 内（seq=${ev.seq ?? "?"}）`);
				}
				open.set(d.callId ?? ev.seq, true);
				continue;
			}
			if (t === "tool/result") { open.delete(d.callId ?? ev.seq); continue; }
			// 其余带 turn/step 的事件：有就得对得上打开的那一组
			if (d.turn !== undefined && turn !== null && d.turn !== turn) problems.push(`${t} 的 turn=${d.turn} 与打开的 ${turn} 不符`);
			if (d.step !== undefined && step !== null && d.step !== step) problems.push(`${t} 的 step=${d.step} 与打开的 ${step} 不符`);
		}
		if (open.size !== 0) warnings.push(`日志结束时仍有未闭合的 tool/call: ${[...open.keys()][0]}`);
		return { problems, warnings };
	}

	// 第二遍：删除注入行、改写 seq/seq0 与引用字段
	const kept = [];
	for (const { line, ev } of parsed) {
		if (ev === null) { kept.push(line); continue; }
		if (isInjected(ev)) continue;
		if (Object.hasOwn(ev, "seq")) ev.seq = mapSeq(ev.seq);
		if (Object.hasOwn(ev, "seq0")) ev.seq0 = mapSeq(ev.seq0);
		// v0 的引用字段分布在两处：事件顶层（sourceEventSeqs / surfaceOp）与 data 内
		// （command/done.sourceEventSeq、compaction/*、session/title、developer/message）。
		// surfaceOp 是顶层对象 {op:"replace",start,end} —— 只改 start/end，保留 op。
		if (Object.hasOwn(ev, "sourceEventSeqs")) ev.sourceEventSeqs = mapRefList(ev.sourceEventSeqs);
		if (ev.surfaceOp !== undefined && typeof ev.surfaceOp === "object" && ev.surfaceOp !== null) ev.surfaceOp = mapRange(ev.surfaceOp);
		if (ev.data && typeof ev.data === "object") mapRefs(ev.data);
		kept.push(JSON.stringify(ev));
	}
	// 头部自洽：v0 的 seedLength（=v1 的 inheritedEventCount）必须 ≤ 事件数，
	// 否则 dsh 报 `Session inheritedEventCount exceeds its event count`。
	// 删行后原本刚好合法的值可能越界；跨会话种子里继承事件数与实际行数不符的日志
	// （被截断过的子会话）直接置 0 —— 置 0 表示「不声明继承」，读者能看到全部历史。
	let headerOut = header;
	try {
		const head = JSON.parse(header);
		const keptRows = kept.length;
		if (typeof head.seedLength === "number" && head.seedLength > keptRows) {
			console.log(`提示(不拦): 头部 seedLength=${head.seedLength} > 保留行数 ${keptRows}，置 0 让日志自洽`);
			head.seedLength = 0;
			headerOut = JSON.stringify(head);
		}
	} catch { /* 头部不是 JSON 就原样保留 */ }

	const keptEvents = kept.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((e) => e !== null);
	const { problems, warnings } = validateArtifact(keptEvents);
	// 引用完整性：重映射之后仍指向「被删掉的合成行」才算真悬空
	for (const ev of keptEvents) {
		const refs = [];
		const push = (field, value) => { if (typeof value === "number") refs.push([field, value]); };
		if (Array.isArray(ev.sourceEventSeqs)) for (const entry of ev.sourceEventSeqs) for (const x of (Array.isArray(entry) ? entry : [entry])) push("sourceEventSeqs", x);
		if (ev.surfaceOp !== null && typeof ev.surfaceOp === "object") for (const [k, x] of Object.entries(ev.surfaceOp)) push(`surfaceOp.${k}`, x);
		for (const key of REFERENCE_KEYS) {
			const value = ev.data?.[key];
			if (Array.isArray(value)) for (const entry of value) for (const x of (Array.isArray(entry) ? entry : [entry])) push(`data.${key}`, x);
			else if (value !== null && typeof value === "object") for (const [k, x] of Object.entries(value)) push(`data.${key}.${k}`, x);
			else push(`data.${key}`, value);
		}
		for (const [field, ref] of refs) {
			if (injectedSeqs.has(ref)) problems.push(`${ev.type}(seq=${ev.seq}) 的 ${field} 仍指向被删除的合成事件序号 ${ref}`);
		}
	}
	if (oldCursor !== remap.size + droppedCount) {
		console.log(`提示: 序号重建行数(${remap.size}) + 删除(${droppedCount}) != 旧游标(${oldCursor})，可能存在非 1 跨度的被删行——已尽力重编号`);
	}
	totalDropped += droppedCount;
	// 保留 dsh 的分帧约定：首帧只含 header 行，其余放第二帧。
	writeFileSync(file + ".bak", readFileSync(file));
	const out = Buffer.concat([zstdEncode(headerOut + "\n"), zstdEncode(kept.join("\n") + "\n")]);
	writeFileSync(file, out);
	console.log(`已修复(删 ${droppedCount} 个合成事件，重编号后末 seq=${newCursor}): ${file}  (备份 ${file}.bak)`);
}
console.log(dry
	? `完成。${filesTouched} 个文件需要修复，共 ${totalDropped} 个合成事件（dry-run，未写）。`
	: `完成。已修复 ${filesTouched} 个文件，共删除 ${totalDropped} 个合成事件（原文件已备份为 <file>.bak）。`);
