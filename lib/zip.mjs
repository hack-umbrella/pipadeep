/**
 * 极简 ZIP 写入器（无依赖）。
 *
 * 为什么自己写：docx 与「证据包」本质都是 zip，而 Node 内置只有 zlib，没有 zip 容器；
 * 引第三方包会破坏本插件「零运行时依赖、随 dsh 宿主走」的约束。
 * 只实现发布需要的子集：deflate 存储 + 中央目录 + EOCD（不含 zip64/加密/流式）。
 */

import { deflateRawSync, inflateRawSync } from 'node:zlib'

/** CRC32（ZIP 规范要求的表驱动实现）。 */
const CRC_TABLE = (() => {
	const table = new Int32Array(256)
	for (let i = 0; i < 256; i += 1) {
		let value = i
		for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1)
		table[i] = value
	}
	return table
})()

export function crc32(buffer) {
	let crc = -1
	for (let i = 0; i < buffer.length; i += 1) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xff]
	return (crc ^ -1) >>> 0
}

const dosTime = (date) => ({
	time: ((date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() / 2)) & 0xffff,
	date: (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xffff
})

/**
 * 打包成 zip。
 * @param entries - `[{ name, data: Buffer|string, store?: boolean }]`
 * @param options - `{ date }` 便于测试固定时间戳
 * @returns zip 字节（Buffer）
 */
export function createZip(entries, options = {}) {
	const date = options.date ?? new Date()
	const { time, date: dosDate } = dosTime(date)
	const chunks = []
	const central = []
	let offset = 0
	for (const entry of entries) {
		const nameBuffer = Buffer.from(entry.name, 'utf8')
		const raw = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data ?? ''), 'utf8')
		// 已经很小的条目再压缩是负收益，直接存储
		const compressed = entry.store === true || raw.length < 64 ? raw : deflateRawSync(raw, { level: 9 })
		const method = compressed === raw ? 0 : 8
		const crc = crc32(raw)
		const local = Buffer.alloc(30)
		local.writeUInt32LE(0x04034b50, 0)
		local.writeUInt16LE(20, 4)
		local.writeUInt16LE(0, 6)
		local.writeUInt16LE(method, 8)
		local.writeUInt16LE(time, 10)
		local.writeUInt16LE(dosDate, 12)
		local.writeUInt32LE(crc, 14)
		local.writeUInt32LE(compressed.length, 18)
		local.writeUInt32LE(raw.length, 22)
		local.writeUInt16LE(nameBuffer.length, 26)
		local.writeUInt16LE(0, 28)
		chunks.push(local, nameBuffer, compressed)
		const header = Buffer.alloc(46)
		header.writeUInt32LE(0x02014b50, 0)
		header.writeUInt16LE(20, 4)
		header.writeUInt16LE(20, 6)
		header.writeUInt16LE(0, 8)
		header.writeUInt16LE(method, 10)
		header.writeUInt16LE(time, 12)
		header.writeUInt16LE(dosDate, 14)
		header.writeUInt32LE(crc, 16)
		header.writeUInt32LE(compressed.length, 20)
		header.writeUInt32LE(raw.length, 24)
		header.writeUInt16LE(nameBuffer.length, 28)
		header.writeUInt32LE(0, 38)
		header.writeUInt32LE(offset, 42)
		central.push(header, nameBuffer)
		offset += local.length + nameBuffer.length + compressed.length
	}
	const centralBuffer = Buffer.concat(central)
	const end = Buffer.alloc(22)
	end.writeUInt32LE(0x06054b50, 0)
	end.writeUInt16LE(entries.length, 8)
	end.writeUInt16LE(entries.length, 10)
	end.writeUInt32LE(centralBuffer.length, 12)
	end.writeUInt32LE(offset, 16)
	return Buffer.concat([...chunks, centralBuffer, end])
}

/**
 * 读取 zip（只支持本模块写出的子集：存储/deflate 单盘 zip）。
 * 用途：测试断言与「证据包自检」，不是通用解压器。
 */
export function readZip(buffer) {
	const entries = new Map()
	let cursor = 0
	while (cursor + 30 <= buffer.length && buffer.readUInt32LE(cursor) === 0x04034b50) {
		const method = buffer.readUInt16LE(cursor + 8)
		const compressedSize = buffer.readUInt32LE(cursor + 18)
		const nameLength = buffer.readUInt16LE(cursor + 26)
		const extraLength = buffer.readUInt16LE(cursor + 28)
		const name = buffer.subarray(cursor + 30, cursor + 30 + nameLength).toString('utf8')
		const start = cursor + 30 + nameLength + extraLength
		const data = buffer.subarray(start, start + compressedSize)
		entries.set(name, { method, data: method === 8 ? inflateRawSync(data) : data })
		cursor = start + compressedSize
	}
	return entries
}
