import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { apply } from '../../lib/engagements-routes.js'
import { buildSnapshot, saveBaseline } from '../../lib/retest.mjs'

const home = mkdtempSync(join(tmpdir(), 'dsh-routes-ui-'))
process.env.DSH_HOME = home
mkdirSync(join(home, 'storages', 'evidence'), { recursive: true })
const sessionId = 'session-ui-fixture'
const packet = 'GET https://demo.example/test HTTP/1.1\nHost: demo.example\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\n' + 'x'.repeat(9000) + '\n```embedded-data```\nTAIL-MARKER'
const packetPath = join(home, 'storages', 'evidence', 'fixture.http')
writeFileSync(packetPath, packet)
const goal = { id: 'goal-1', sessionId, target: 'demo.example', objective: 'UI fixture' }
const assets = [{ id: 'asset-1', sessionId, type: 'endpoint', value: 'https://demo.example/test' }]
const findings = [{ id: 'finding-1', sessionId, title: 'Fixture finding', severity: 'low', affectedAssetId: 'asset-1', description: 'Fixture only', reproducibleSteps: ['curl https://demo.example/test'], evidence: [{ kind: 'http', path: packetPath, label: 'Fixture HTTP' }] }]
const db = new DatabaseSync(join(home, 'storages', 'pentest-sessions.db'))
for (const name of ['goals', 'intents', 'facts', 'findings', 'assets', 'edges']) db.exec('CREATE TABLE u_pentest_' + name + ' (key TEXT, value TEXT)')
for (const [name, values] of [['goals', [goal]], ['findings', findings], ['assets', assets]]) {
 const stmt = db.prepare('INSERT INTO u_pentest_' + name + ' VALUES (?, ?)')
 for (const value of values) stmt.run(name === 'goals' ? sessionId : sessionId + ':' + value.id, JSON.stringify(value))
}
db.close()
saveBaseline(buildSnapshot({ sessionId, goal, assets, findings }), 'latest')
const routes = new Map()
apply({ webServer: { register: (route) => { routes.set(route.path, route.handler); return () => {} } } })
async function call(path, query) {
 const headers = {}
 let body
 const res = { statusCode: 200, setHeader: (k, v) => { headers[k] = v }, end: (value) => { body = value } }
 await routes.get(path)({ url: path + query }, res)
 return { status: res.statusCode, headers, body }
}

test('opening the retest list never executes a probe or returns old packets', async () => {
 const result = await call('/api/pipadeep-pentest/retest', '?sessionId=' + sessionId)
 assert.equal(result.status, 200)
 const data = JSON.parse(result.body)
 assert.equal(data.probe, null)
 assert.equal(data.diff.open[0].probe, null)
 assert.equal(data.diff.open[0].packets, undefined)
 assert.equal(existsSync(join(home, 'storages', 'evidence', 'retest')), false)
})

test('report includes complete evidence bytes and safe Markdown fences', async () => {
 const result = await call('/api/pipadeep-pentest/report.md', '?sessionId=' + sessionId)
 assert.equal(result.status, 200)
 assert.ok(result.body.includes(packet))
 assert.ok(result.body.includes('````http\n'))
 assert.ok(result.body.includes('TAIL-MARKER\n````'))
 assert.equal(result.headers['cache-control'], 'no-store')
})
