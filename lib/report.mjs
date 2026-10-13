/**
 * 交付物：CVSS 3.1 评分、docx 导出、证据包打包。
 *
 * 为什么放在插件里而不是让 agent 手写：客户交付物要**可复现、可核对**。
 * 评分公式、证据哈希、zip 结构都必须由确定性代码产出，模型只负责填内容。
 * 零运行时依赖：docx 与证据包都用 lib/zip.mjs 自己写的 ZIP 写入器。
 */

import { createHash } from 'node:crypto'
import { createZip } from './zip.mjs'

/** CVSS 3.1 各度量的取值权重（严格按规范）。 */
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC = { L: 0.77, H: 0.44 }
const PR_U = { N: 0.85, L: 0.62, H: 0.27 }
const PR_C = { N: 0.85, L: 0.68, H: 0.5 }
const UI = { N: 0.85, R: 0.62 }
const CIA = { H: 0.56, L: 0.22, N: 0 }

/** 规范里的 roundup：向上取到 1 位小数（避免浮点误差，例如 4.02 → 4.1）。 */
function roundUp(value) {
	const scaled = Math.round(value * 100000)
	return scaled % 10000 === 0 ? scaled / 100000 : (Math.floor(scaled / 10000) + 1) / 10
}

/**
 * 解析并计算 CVSS 3.1 **基础分**（Base）。
 * @param vector - 形如 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`（前缀可省）
 * @returns `{ score, severity, vector, metrics }`；向量非法时抛错（不猜）。
 */
export function cvss31(vector) {
	const text = String(vector ?? '').trim().replace(/^CVSS:3\.[01]\//i, '')
	const metrics = {}
	for (const part of text.split('/')) {
		const [key, value] = part.split(':')
		if (key !== undefined && value !== undefined) metrics[key.toUpperCase()] = value.toUpperCase()
	}
	const need = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
	const missing = need.filter((key) => metrics[key] === undefined)
	if (missing.length !== 0) throw new Error(`cvss31: 缺少度量 ${missing.join('/')}（需要 AV/AC/PR/UI/S/C/I/A）`)
	const scopeChanged = metrics.S === 'C'
	const table = (name, map) => {
		const value = map[metrics[name]]
		if (value === undefined) throw new Error(`cvss31: ${name} 取值非法（${metrics[name]}）`)
		return value
	}
	const iss = 1 - (1 - table('C', CIA)) * (1 - table('I', CIA)) * (1 - table('A', CIA))
	const impact = scopeChanged
		? 7.52 * (iss - 0.029) - 3.08 * Math.pow(iss - 0.02, 15)
		: 6.42 * iss
	const exploitability = 8.22 * table('AV', AV) * table('AC', AC) * table('PR', scopeChanged ? PR_C : PR_U) * table('UI', UI)
	const score = impact <= 0
		? 0
		: roundUp(Math.min(scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability, 10))
	return {
		score,
		severity: severityOf(score),
		// 规范化向量里 S 用规范的 U/C 表示
		vector: `CVSS:3.1/${need.map((key) => `${key}:${metrics[key]}`).join('/')}`,
		metrics
	}
}

/** 分值 → 等级（0 / low / medium / high / critical）。 */
export function severityOf(score) {
	if (score <= 0) return 'none'
	if (score < 4) return 'low'
	if (score < 7) return 'medium'
	if (score < 9) return 'high'
	return 'critical'
}

const xmlEscape = (text) => String(text ?? '')
	.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

/** Markdown → docx 段落（支持 #/##/### 标题、- 列表、表格行、`code`、**bold**，其余按正文）。 */
export function markdownToParagraphs(markdown) {
	const paragraphs = []
	for (const rawLine of String(markdown ?? '').split('\n')) {
		const line = rawLine.replace(/\s+$/, '')
		if (line.trim() === '') continue
		const heading = /^(#{1,3})\s+(.*)$/.exec(line)
		if (heading !== null) {
			paragraphs.push({ style: `Heading${heading[1].length}`, text: heading[2] })
			continue
		}
		const bullet = /^\s*[-*]\s+(.*)$/.exec(line)
		if (bullet !== null) {
			paragraphs.push({ style: 'ListParagraph', text: `• ${bullet[1]}`, bullet: true })
			continue
		}
		// 表格：`| a | b |` → 简化为制表符分隔的正文（docx 真表格超出这里的必要复杂度）
		if (/^\s*\|.*\|\s*$/.test(line)) {
			if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue
			paragraphs.push({ style: 'Normal', text: line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim()).join('\t') })
			continue
		}
		paragraphs.push({ style: 'Normal', text: line })
	}
	return paragraphs
}

/**
 * 生成 docx（最小 OOXML：固定样式，客户可直接打开/转 PDF）。
 * @returns Buffer
 */
export function buildDocx(markdown, options = {}) {
	const title = options.title ?? '渗透测试报告'
	const paragraphs = markdownToParagraphs(markdown)
	const body = paragraphs.map(({ style, text }) => {
		const runs = []
		// 行内 `code` 与 **bold** 简化处理：拆成多个 run
		const pieces = String(text).split(/(`[^`]*`|\*\*[^*]*\*\*)/g).filter((piece) => piece !== '')
		for (const piece of pieces) {
			if (/^`[^`]*`$/.test(piece)) runs.push(`<w:r><w:rPr><w:rFonts w:ascii="Menlo" w:hAnsi="Menlo"/></w:rPr><w:t xml:space="preserve">${xmlEscape(piece.slice(1, -1))}</w:t></w:r>`)
			else if (/^\*\*[^*]*\*\*$/.test(piece)) runs.push(`<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">${xmlEscape(piece.slice(2, -2))}</w:t></w:r>`)
			else runs.push(`<w:r><w:t xml:space="preserve">${xmlEscape(piece)}</w:t></w:r>`)
		}
		return `<w:p><w:pPr><w:pStyle w:val="${style}"/></w:pPr>${runs.join('')}</w:p>`
	}).join('')
	const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr></w:body></w:document>`
	const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="21"/></w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:pPr><w:ind w:left="420"/></w:pPr></w:style></w:styles>`
	const core = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${xmlEscape(title)}</dc:title></cp:coreProperties>`
	return createZip([
		{ name: '[Content_Types].xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>` },
		{ name: '_rels/.rels', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>` },
		{ name: 'word/_rels/document.xml.rels', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>` },
		{ name: 'word/document.xml', data: document },
		{ name: 'word/styles.xml', data: styles },
		{ name: 'docProps/core.xml', data: core }
	], options)
}

/**
 * 证据包：证据文件 + 清单（含 sha256 与大小）。
 * 清单放在 `manifest.json`，同时对每个文件写入哈希，便于事后核对未被篡改。
 */
export function buildEvidenceZip(files, options = {}) {
	const entries = []
	const manifest = { generatedAt: options.now ?? new Date().toISOString(), files: [] }
	for (const file of files ?? []) {
		const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(String(file.data ?? ''), 'utf8')
		const name = String(file.name ?? 'unnamed').replace(/^\/+/, '')
		manifest.files.push({ name, bytes: data.length, sha256: createHash('sha256').update(data).digest('hex'), ...(file.kind === undefined ? {} : { kind: file.kind }) })
		entries.push({ name: `evidence/${name}`, data })
	}
	entries.push({ name: 'manifest.json', data: JSON.stringify(manifest, null, 2) })
	return { zip: createZip(entries, options), manifest }
}
