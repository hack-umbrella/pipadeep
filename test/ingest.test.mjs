// 武器输出解析器测试：用真实工具的输出样例，断言「确定性、可复现、不丢字段」。
import { detectKind, mergeIngest, parseFfufJson, parseHttpxJsonl, parseNmapXml, parseNucleiJsonl, parseOutput, parsePortScanJson } from '../lib/ingest.mjs'

let failures = 0
const ok = (name, pass, detail = '') => {
	console.log(`  ${pass ? '✓' : '✗'} ${name}${pass || !detail ? '' : ` —— ${detail}`}`)
	if (!pass) failures += 1
}

const NMAP = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX out.xml 10.0.0.5">
<host starttime="1" endtime="2"><status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="app.corp.example" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0"/>
<script id="http-title" output="Admin Console"/></port>
<port protocol="tcp" portid="3306"><state state="closed" reason="reset"/></port>
</ports>
</host>
<host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="ssl" product="TLS" version="1.3"/></port>
</ports></host>
</nmaprun>`

const NUCLEI = `{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","tags":["cve","rce"]},"host":"https://vuln.example","matched-at":"https://vuln.example/api/login","matcher-name":"payload","type":"http"}
{"template-id":"tech-detect","info":{"name":"Nginx Detection","severity":"info"},"host":"https://vuln.example","matched-at":"https://vuln.example/"}
not-json-line
{"info":{"name":"缺模板 id"},"matched-at":"https://a.example/"}
{"template-id":"no-match","info":{"name":"缺命中地址","severity":"low"}}`

const HTTPX = `{"url":"https://app.example/login","host":"app.example","status_code":200,"title":"Login","webserver":"nginx/1.24.0","tech":["React","Nginx"],"port":443,"scheme":"https"}
{"input":"https://dead.example","status_code":0}
{"host":"no-url.example","status_code":200}`

const FFUF = JSON.stringify({ results: [
	{ url: 'https://app.example/admin', status: 403, length: 1200, content_type: 'text/html', redirectlocation: '' },
	{ url: 'https://app.example/backup.zip', status: 200, length: 918273, content_type: 'application/zip' },
] })

const MASSCAN = JSON.stringify({ hosts: [
	{ ip: '10.0.0.5', ports: [{ port: 80, proto: 'tcp', status: 'open' }, { port: 443, proto: 'tcp', status: 'open' }] },
	{ ip: '10.0.0.6', ports: [{ port: 22, proto: 'tcp', status: 'closed' }] },
] })

// ── 1. 类型嗅探 ──────────────────────────────────────────────────────────────
ok('嗅探 nmap', detectKind('scan.xml', NMAP) === 'nmap')
ok('嗅探 nuclei', detectKind('n.jsonl', NUCLEI) === 'nuclei')
ok('嗅探 httpx', detectKind('h.jsonl', HTTPX) === 'httpx')
ok('嗅探 ffuf', detectKind('f.json', FFUF) === 'ffuf')
ok('嗅探 masscan', detectKind('m.json', MASSCAN) === 'masscan')
ok('嗅探不出就返回 null（不猜）', detectKind('x.txt', 'hello world') === null)
ok('auto 嗅探不出时报错而不是静默产出空结果', (() => { try { parseOutput('auto', 'hello'); return false } catch { return true } })())

// ── 2. nmap ─────────────────────────────────────────────────────────────────
const nmap = parseNmapXml(NMAP)
const nmapFacts = (kind) => nmap.facts.filter((f) => f.kind === kind)
ok('nmap 解析出两台主机', nmap.assets.filter((a) => a.type === 'ip').length === 2)
ok('nmap 只收 open 端口（closed 的 3306 不收）', !nmap.facts.some((f) => f.target === 'app.corp.example:3306' && f.kind === 'port'))
ok('nmap 端口 fact 带协议与端口号', nmapFacts('port').some((f) => f.target === 'app.corp.example:22' && f.detail === 'open/tcp' && f.port === 22))
ok('nmap 服务 fact 合并 product/version', nmapFacts('service').some((f) => f.detail === 'ssh OpenSSH 9.6p1'))
ok('nmap 脚本输出进 info fact', nmapFacts('info').some((f) => f.detail.includes('http-title')))
ok('nmap 子域挂到 ip 之下（逻辑父子，不含具体 id）', nmap.assets.some((a) => a.type === 'subdomain' && a.value === 'app.corp.example' && a.parent?.type === 'ip'))
ok('nmap 服务资产挂在 ip 之下', nmap.assets.some((a) => a.type === 'service' && a.parent?.value === '10.0.0.5'))

// ── 3. nuclei ───────────────────────────────────────────────────────────────
const nuclei = parseNucleiJsonl(NUCLEI)
ok('nuclei critical 进 vuln fact', nuclei.facts.some((f) => f.kind === 'vuln' && f.severity === 'critical' && f.ruleId === 'CVE-2021-44228'))
ok('nuclei 坏行/缺命中地址都只记 note，不中断', nuclei.notes.length === 2 && nuclei.facts.length === 3, `notes=${nuclei.notes.length} facts=${nuclei.facts.length}`)
ok('nuclei 缺模板 id 但命中地址有效 → 仍产出 fact', nuclei.facts.some((f) => f.target === 'https://a.example/'))
ok('nuclei 命中地址进 endpoint 资产', nuclei.assets.some((a) => a.type === 'endpoint' && a.value === 'https://vuln.example/api/login'))

// ── 4. httpx ────────────────────────────────────────────────────────────────
const httpx = parseHttpxJsonl(HTTPX)
ok('httpx 存活端点进 endpoint', httpx.assets.some((a) => a.value === 'https://app.example/login'))
ok('httpx 指纹进 http fact（含 title/tech）', httpx.facts.some((f) => f.kind === 'http' && f.title === 'Login' && Array.isArray(f.tech) && f.tech.includes('React')))
ok('httpx 无 url 的行只记 note', httpx.notes.length === 1)

// ── 5. ffuf / masscan ───────────────────────────────────────────────────────
const ffuf = parseFfufJson(FFUF)
ok('ffuf 结果进端点 + http fact', ffuf.assets.length === 2 && ffuf.facts.some((f) => f.status === 403))
const masscan = parsePortScanJson(MASSCAN)
ok('masscan 只收 open 端口', masscan.facts.length === 2 && masscan.facts.every((f) => f.detail === 'open/tcp'))

// ── 6. 合并、去重与确定性 ────────────────────────────────────────────────────
const merged = mergeIngest([
	{ source: 'nmap-a.xml', ...nmap },
	{ source: 'nmap-b.xml', ...nmap },
	{ source: 'nuclei.jsonl', ...nuclei },
])
ok('同一资产被两个来源命中 → 合并为一条并记两个来源', merged.assets.find((a) => a.value === 'app.corp.example')?.sources.length === 2)
ok('资产按稳定键去重', merged.assets.length === new Set(merged.assets.map((a) => `${a.type}|${a.value}`)).size)
ok('fact 按稳定键去重', merged.facts.length === new Set(merged.facts.map((f) => `${f.kind}|${f.target}|${f.detail}`)).size)
const twice = mergeIngest([{ source: 'nmap-a.xml', ...parseNmapXml(NMAP) }, { source: 'nuclei.jsonl', ...nuclei }])
ok('同输入两次解析结果完全一致（可复现）', JSON.stringify(merged) === JSON.stringify(mergeIngest([{ source: 'nmap-a.xml', ...nmap }, { source: 'nmap-b.xml', ...nmap }, { source: 'nuclei.jsonl', ...nuclei }])) && JSON.stringify(twice.facts) === JSON.stringify(mergeIngest([{ source: 'nmap-a.xml', ...parseNmapXml(NMAP) }, { source: 'nuclei.jsonl', ...nuclei }]).facts))

// ── 7. 坏输入要报错，不能静默 ````````
ok('非 nmap XML 报错', (() => { try { parseNmapXml('<html/>'); return false } catch { return true } })())
ok('ffuf 传入非 JSON 报错（提示 -of json）', (() => { try { parseFfufJson('nope'); return false } catch (error) { return /-of json/.test(error.message) } })())
ok('masscan 传入非 JSON 报错', (() => { try { parsePortScanJson('nope'); return false } catch { return true } })())

console.log(failures === 0 ? '\n══ 解析器测试全部通过 ══' : `\n══ ${failures} 项失败 ══`)
process.exit(failures === 0 ? 0 : 1)
