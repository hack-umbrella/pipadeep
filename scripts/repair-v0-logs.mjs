#!/usr/bin/env node
// 修复旧会话日志：删除本插件在旧版 dsh（≤0.1.2）为驱动父会话投影而注入的合成
// tool/call 事件（callId 前缀 `pentest-submit-`）。dsh 0.1.5 的会话格式迁移
// （v0→v3）会拒绝这类「不匹配 open turn/step」的 tool/call，导致旧渗透会话打不开。
//
// 关键：日志的逻辑序号（seq）不是「行号」——打包行（reasoning-chunks / text-chunks /
// tool-call-chunks）各跨多个 seq。删除事件后必须按同样的跨度规则重编号，并同步重映射
// 引用序号的字段（seq0 / sourceEventSeqs / data.messageSeqs），否则报 `seq gap`。
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
	if (droppedCount === 0) { console.log(`无需修复(${parsed.length} 行): ${file}`); continue; }
	if (dry) { console.log(`[dry-run] 将删除 ${droppedCount} 个合成事件: ${file}`); continue; }

	// 第一遍：建旧→新逻辑序号映射（按跨度推进；删除的行只推进旧游标）
	const remap = new Map();
	let oldCursor = 0;
	let newCursor = 0;
	for (const { ev } of parsed) {
		if (ev === null) continue;
		const start = startSeqOf(ev);
		const span = spanOf(ev);
		if (start === undefined) continue;
		if (isInjected(ev)) { oldCursor = start + span; continue; }
		for (let i = 0; i < span; i += 1) remap.set(start + i, newCursor + i);
		newCursor += span;
		oldCursor = start + span;
	}
	const mapSeq = (n) => (typeof n === "number" && remap.has(n) ? remap.get(n) : n);
	const mapDeep = (v) => (Array.isArray(v) ? v.map(mapDeep) : mapSeq(v));

	// 第二遍：删除注入行、改写 seq/seq0 与引用字段
	const kept = [];
	for (const { line, ev } of parsed) {
		if (ev === null) { kept.push(line); continue; }
		if (isInjected(ev)) continue;
		if (Object.hasOwn(ev, "seq")) ev.seq = mapSeq(ev.seq);
		if (Object.hasOwn(ev, "seq0")) ev.seq0 = mapSeq(ev.seq0);
		if (Object.hasOwn(ev, "sourceEventSeqs")) ev.sourceEventSeqs = mapDeep(ev.sourceEventSeqs);
		if (ev.data && typeof ev.data === "object" && Object.hasOwn(ev.data, "messageSeqs")) ev.data.messageSeqs = mapDeep(ev.data.messageSeqs);
		kept.push(JSON.stringify(ev));
	}
	if (oldCursor !== remap.size + droppedCount) {
		console.log(`提示: 序号重建行数(${remap.size}) + 删除(${droppedCount}) != 旧游标(${oldCursor})，可能存在非 1 跨度的被删行——已尽力重编号`);
	}
	totalDropped += droppedCount;
	// 保留 dsh 的分帧约定：首帧只含 header 行，其余放第二帧。
	writeFileSync(file + ".bak", readFileSync(file));
	const out = Buffer.concat([zstdEncode(header + "\n"), zstdEncode(kept.join("\n") + "\n")]);
	writeFileSync(file, out);
	console.log(`已修复(删 ${droppedCount} 个合成事件，重编号后末 seq=${newCursor}): ${file}  (备份 ${file}.bak)`);
}
console.log(`完成。共删除合成事件 ${totalDropped} 个${dry ? "（dry-run，未写）" : ""}。`);
