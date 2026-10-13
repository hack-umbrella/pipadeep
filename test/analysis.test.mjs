// 第 3/4/5/6/7 项模块测试：交付物（zip/docx/CVSS/证据包）、KPI 与跨引擎合并、
// 复测差异、认证授权（JWT/矩阵/越权归类）、前端情报（端点/密钥/参数/crt.sh）。
import { createHmac, createHash } from 'node:crypto'
import { buildDocx, buildEvidenceZip, cvss31, markdownToParagraphs, severityOf } from '../lib/report.mjs'
import { createZip, crc32, readZip } from '../lib/zip.mjs'
import { denoiseKpis, kpiMarkdown, mergeEngines, severityRank } from '../lib/kpi.mjs'
import { diffAssessments, findingKey, retestMarkdown } from '../lib/retest.mjs'
import { analyzeJwt, authzCandidates, buildAccessMatrix, classifyAccessPair, crackHmac, parseJwt, verifyHmac } from '../lib/authz.mjs'
import { crtShUrl, extractEndpoints, extractParams, extractSecrets, extractUrls, parseCrtSh } from '../lib/jsintel.mjs'

let failures = 0
const ok = (name, pass, detail = '') => {
	console.log(`  ${pass ? '✓' : '✗'} ${name}${pass || !detail ? '' : ` —— ${detail}`}`)
	if (!pass) failures += 1
}

// ── zip ─────────────────────────────────────────────────────────────────────
const zip = createZip([{ name: 'a.txt', data: 'lorem ipsum '.repeat(40) }, { name: 'dir/b.bin', data: Buffer.from([1, 2, 3]) }, { name: 'small.txt', data: 'x' }], { date: new Date('2026-10-13T00:00:00Z') })
const unzip = readZip(zip)
ok('zip 往返：文本内容一致', unzip.get('a.txt').data.toString('utf8') === 'lorem ipsum '.repeat(40))
ok('zip 往返：二进制未损坏', Buffer.compare(unzip.get('dir/b.bin').data, Buffer.from([1, 2, 3])) === 0)
ok('zip 同时支持存储与 deflate（小条目存储、大条目压缩）', unzip.get('small.txt').method === 0 && unzip.get('a.txt').method === 8)
ok('zip 首尾签名正确', zip.readUInt32LE(0) === 0x04034b50 && zip.readUInt32LE(zip.length - 22) === 0x06054b50)
ok('crc32 是稳定数值', crc32(Buffer.from('hello zip')) === crc32(Buffer.from('hello zip')) && crc32(Buffer.from('a')) !== crc32(Buffer.from('b')))

// ── 交付物：CVSS / docx / 证据包 ────────────────────────────────────────────
ok('CVSS 3.1 参考向量 9.8', cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score === 9.8)
ok('CVSS 3.1 作用域变更 6.1', cvss31('AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N').score === 6.1)
ok('CVSS 缺度量时报错（不猜）', (() => { try { cvss31('AV:N/AC:L'); return false } catch { return true } })())
ok('严重度分档', ['none', 'low', 'medium', 'high', 'critical'].every((level, index) => severityOf([0, 3.9, 6.9, 8.9, 10][index]) === level))
const paragraphs = markdownToParagraphs('# 标题\n\n- 项目\n\n| a | b |\n| --- | --- |\n| 1 | 2 |\n\n正文 `code` 与 **加粗**')
ok('Markdown 解析出标题/列表/正文', paragraphs[0].style === 'Heading1' && paragraphs.some((p) => p.bullet === true) && paragraphs.some((p) => p.text.includes('code')))
const docx = readZip(buildDocx('# 报告\n\n**重点**：`CVSS:3.1` 与 <script>', { title: 'T' }))
ok('docx 含必需部件', ['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml'].every((name) => docx.has(name)))
const documentXml = docx.get('word/document.xml').data.toString('utf8')
ok('docx 正确转义 XML（不出注入）', documentXml.includes('&lt;script&gt;') && !documentXml.includes('<script>'))
ok('docx 加粗与代码用 run 表达', documentXml.includes('<w:b/>') && documentXml.includes('Menlo'))
const evidence = buildEvidenceZip([{ name: 'shot.png', data: Buffer.from('png-bytes'), kind: 'screenshot' }], { now: '2026-10-13T00:00:00.000Z' })
ok('证据包清单含 sha256 与大小', evidence.manifest.files[0].sha256 === createHash('sha256').update(Buffer.from('png-bytes')).digest('hex') && evidence.manifest.files[0].bytes === 9)
ok('证据包同时产出 zip', readZip(evidence.zip).get('manifest.json') !== undefined)

// ── KPI 与跨引擎合并 ────────────────────────────────────────────────────────
const findings = [
	{ severity: 'critical', status: 'open', ruleId: 'sqli-1', engine: 'semgrep', filepath: '/a.jsp', line: 10 },
	{ severity: 'high', status: 'fixed', ruleId: 'sqli-1', engine: 'bandit', filepath: '/a.jsp', line: 10 },
	{ severity: 'low', status: 'candidate', ruleId: 'info-leak', engine: 'builtin', filepath: '/b.jsp', line: 3 },
	{ severity: 'medium', ruleId: 'info-leak', engine: 'builtin', filepath: '/c.jsp', line: 9 }
]
const kpi = denoiseKpis(findings)
ok('KPI：总数/已确认/候选', kpi.total === 4 && kpi.confirmed === 2 && kpi.candidates === 2)
ok('KPI：确认率与误报率上界', kpi.confirmRate === 0.5 && kpi.falsePositiveRate === 0.5)
ok('KPI：高危及以上单独统计', kpi.highPlus === 2 && kpi.highPlusConfirmed === 2 && kpi.highPlusConfirmRate === 1)
ok('KPI：噪声规则排序（候选多者在前）', kpi.noisyRules[0].ruleId === 'info-leak' && kpi.noisyRules[0].unconfirmed === 2)
ok('KPI Markdown 可直接进报告', kpiMarkdown(kpi).includes('确认率') && kpiMarkdown(kpi).includes('| critical |'))
const merged = mergeEngines(findings)
ok('跨引擎合并：同位置同规则族合并为一条', merged.merged.length === 3 && merged.dropped === 1)
const mergedSqli = merged.merged.find((row) => row.ruleId === 'sqli-1')
ok('跨引擎合并：记录全部引擎并提升置信度', mergedSqli.engines.length === 2 && mergedSqli.confidence === 'high')
ok('跨引擎合并：严重度取更严重者', mergedSqli.severity === 'critical')
ok('严重度排序函数可用', severityRank('critical') > severityRank('low'))

// ── 复测差异 ────────────────────────────────────────────────────────────────
const before = [
	{ ruleId: 'sqli-1', filepath: '/a.jsp', severity: 'critical' },
	{ ruleId: 'xss-2', filepath: '/b.jsp', severity: 'high' },
	{ ruleId: 'csrf-3', filepath: '/c.jsp', severity: 'medium', status: 'fixed' }
]
const after = [
	{ ruleId: 'xss-2', filepath: '/b.jsp', severity: 'high' },
	{ ruleId: 'csrf-3', filepath: '/c.jsp', severity: 'medium' },
	{ ruleId: 'ssrf-9', filepath: '/d.jsp', severity: 'high' }
]
const diff = diffAssessments(before, after)
ok('复测：已修复 / 仍存在 / 新增 / 回归 分类正确', diff.summary.fixed === 1 && diff.summary.open === 1 && diff.summary.added === 1 && diff.summary.regressed === 1)
ok('复测：新增按对齐键判定（ssrf-9 不在上轮）', diff.added[0].ruleId === 'ssrf-9')
ok('复测：回归是"上轮已修复、本轮又出现"', diff.regressed[0].current.ruleId === 'csrf-3')
ok('复测：对齐键去掉大小写与尾斜杠差异', findingKey({ ruleId: 'SQLI-1', url: 'https://a/B/' }) === findingKey({ ruleId: 'sqli-1', filepath: 'https://a/b' }))
ok('复测 Markdown 给出结论行', retestMarkdown(diff).includes('已修复 1') && retestMarkdown(diff).includes('仍存在 1'))

// ── JWT / 授权 ──────────────────────────────────────────────────────────────
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
const weak = `eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.${b64({ sub: '1', role: 'admin', password: 'x' })}.x`
const signed = (() => {
	const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
	const body = Buffer.from(JSON.stringify({ sub: '42', exp: 4102444800 })).toString('base64url')
	const sig = createHmac('sha256', 'secret').update(`${head}.${body}`).digest('base64url')
	return `${head}.${body}.${sig}`
})()
ok('JWT 解析出 header/payload', parseJwt(signed).payload.sub === '42')
ok('HMAC 校验：正确密钥通过、错误密钥不通过', verifyHmac(signed, 'secret') === true && verifyHmac(signed, 'nope') === false)
ok('弱密钥可被字典命中', crackHmac(signed, ['123456', 'secret']) === 'secret')
const jwtReport = analyzeJwt(signed, { wordlist: ['secret'], now: 1_700_000_000_000 })
ok('JWT 分析报出弱密钥', jwtReport.issues.some((issue) => issue.code === 'weak-secret') && jwtReport.worstSeverity === 'critical')
const claimReport = analyzeJwt(`eyJhbGciOiJIUzI1NiJ9.${b64({ sub: '1', password: 'p@ss', phone: '13800000000' })}.x`)
ok('JWT 分析报出敏感字段', claimReport.issues.some((issue) => issue.code === 'sensitive-claims'))
const noneToken = `${b64({ alg: 'none' })}.${b64({ sub: '1' })}.`
ok('alg=none 报 critical', analyzeJwt(noneToken).issues.find((issue) => issue.code === 'alg-none').severity === 'critical')
ok('缺 exp 报 medium', analyzeJwt(parseJwt(noneToken) && `${b64({ alg: 'HS256' })}.${b64({ sub: '1' })}.x`).issues.some((issue) => issue.code === 'no-expiry'))
ok('kid 路径穿越被标出', analyzeJwt(`${b64({ alg: 'RS256', kid: '../../etc/passwd' })}.${b64({})}.x`).issues.some((issue) => issue.code === 'kid-injection'))
ok('弱密钥令牌（未命中字典）不误报 strong', analyzeJwt(weak, { wordlist: ['nope'] }).issues.every((issue) => issue.code !== 'weak-secret'))
const matrix = buildAccessMatrix([{ name: 'a', headers: { Cookie: 'A' } }, { name: 'b' }], [{ name: 'order', method: 'GET', url: '/api/orders/1' }])
ok('访问矩阵 = 身份 × 请求', matrix.length === 2 && matrix[0].id === 'a::order' && matrix[1].headers === undefined)
ok('越权归类：另一身份被拒 → protected', classifyAccessPair({ status: 200, bodyLength: 100 }, { status: 403 }).verdict === 'protected')
ok('越权归类：另一身份拿到等长内容 → idor 候选', classifyAccessPair({ status: 200, bodyLength: 100 }, { status: 200, bodyLength: 100 }).verdict === 'idor-candidate')
ok('越权归类：另一身份拿到不同内容 → bola 候选', classifyAccessPair({ status: 200, bodyLength: 100 }, { status: 200, bodyLength: 240 }).verdict === 'bola-candidate')
ok('越权归类：属主侧非 2xx → 不确定（不硬判）', classifyAccessPair({ status: 500 }, { status: 200, bodyLength: 10 }).verdict === 'indeterminate')
const candidates = authzCandidates([
	{ resource: '/api/orders/1', identity: 'a', isOwner: true, status: 200, bodyLength: 120 },
	{ resource: '/api/orders/1', identity: 'b', status: 200, bodyLength: 120 },
	{ resource: '/api/orders/2', identity: 'a', isOwner: true, status: 200, bodyLength: 90 },
	{ resource: '/api/orders/2', identity: 'b', status: 403 }
])
ok('越权候选只保留有差异的项', candidates.length === 1 && candidates[0].resource === '/api/orders/1' && candidates[0].other === 'b')

// ── 前端情报 ────────────────────────────────────────────────────────────────
const js = `fetch("/api/v1/users")\nconst u='/admin/panel';\naxios.post("/api/login", {username:1})\nconst img="/static/logo.png";\nconst k="AKIAIOSFODNN7EXAMPLE"; const g="AIzaSyA1234567890abcdefghijklmnopqrstuvw";\nconst s="https://10.0.0.9:8443/internal";\nconst t="secret=abcdEFGH1234xyz";\nfetch("/api/orders?id=1&tenant=2")`
const endpoints = extractEndpoints(js, { baseUrl: 'https://app.example' })
ok('抽取接口路径并去重、过滤静态资源', endpoints.endpoints.includes('https://app.example/api/v1/users') && !endpoints.endpoints.some((path) => path.endsWith('.png')))
ok('抽取完整 URL 与内网地址', extractUrls(js).internal.includes('https://10.0.0.9:8443/internal'))
const secrets = extractSecrets(js)
ok('抽取云密钥（AK/AIza）', secrets.secrets.some((item) => item.kind === 'aws-access-key-id') && secrets.secrets.some((item) => item.kind === 'google-api-key'))
ok('密钥带脱敏形式供报告使用', secrets.secrets[0].redacted.includes('…'))
ok('低熵"密钥"不误报', extractSecrets('const secret = "aaaaaaaaaaaa"').count === 0)
ok('抽取参数名', extractParams(js).includes('tenant') && extractParams(js).includes('id'))
ok('crt.sh URL 使用 % 通配查询', crtShUrl('example.com') === 'https://crt.sh/?q=%25.example.com&output=json')
const crt = parseCrtSh([{ name_value: 'a.example.com\n*.b.example.com' }, { common_name: 'A.EXAMPLE.COM' }])
ok('crt.sh 解析去通配符/去重/小写', crt.count === 2 && crt.subdomains.includes('a.example.com') && crt.subdomains.includes('b.example.com'))
ok('crt.sh 非 JSON 响应明确报错（限流场景）', (() => { try { parseCrtSh('<html>'); return false } catch (error) { return /限流/.test(error.message) } })())

console.log(failures === 0 ? '\n══ 5 个模块测试全部通过 ══' : `\n══ ${failures} 项失败 ══`)
process.exit(failures === 0 ? 0 : 1)
