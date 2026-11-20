import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { reprobeOne } from '../../lib/reprobe.mjs'

process.env.DSH_HOME = mkdtempSync(join(tmpdir(), 'dsh-retest-unit-'))
const baseline = { target: 'fixture.example', findings: [{ key: 'fixture-key', title: '债转公告接口未授权 fixture', severity: 'high' }] }
// 引擎本体不内置目标规格：测试通过 options.specs 显式注入
const fixtureSpecs = [{ id: 'fixture-debt', match: ['债转公告接口未授权'], label: 'fixture', requests: [{ method: 'POST', url: 'https://fixture.example/api/debt', headers: {}, body: 'id=1' }], judge: ([r]) => (r.status === 200 && String(r.body ?? '').includes('loan_number') ? { verdict: 'open', detail: 'fixture open' } : { verdict: 'fixed', detail: 'fixture fixed' }) }]
const response = (overrides = {}) => ({ ok: true, status: 200, statusText: 'HTTP/1.1 200 OK', headers: { 'content-type': 'application/json' }, body: '{}', error: '', durationMs: 8, ...overrides })

test('a single click returns a full body and independent run metadata', async () => {
 const full = JSON.stringify({ table_info: { loan_number: 'DEMO-MASKED', unpaid_total: 'MASKED' }, padding: 'x'.repeat(8000) })
 let count = 0
 const transport = async () => { count++; return response({ body: full }) }
 const first = await reprobeOne(baseline, 'fixture-key', { transport, specs: fixtureSpecs })
 assert.equal(count, 1)
 assert.equal(first.packets[0].responseBody, full)
 assert.equal(first.packets[0].durationMs, 8)
 assert.equal(first.verdict, 'open')
 assert.ok(readFileSync(first.evidence[0].path, 'utf8').includes(full))
 const second = await reprobeOne(baseline, 'fixture-key', { transport, specs: fixtureSpecs })
 assert.equal(count, 2)
 assert.notEqual(first.runId, second.runId)
 assert.notEqual(first.evidence[0].path, second.evidence[0].path)
})

test('network failures and server errors never count as fixed', async () => {
 for (const sample of [response({ ok: false, status: 0, error: 'timeout' }), response({ status: 503 }), response({ status: 429 })]) {
  const result = await reprobeOne(baseline, 'fixture-key', { transport: async () => sample, specs: fixtureSpecs })
  assert.equal(result.verdict, 'unclear')
 }
})

test('an unknown rule, key, or mismatched target never sends a request', async () => {
 let count = 0
 const transport = async () => { count++; return response() }
 const unknownKey = await reprobeOne(baseline, 'missing-key', { transport, specs: fixtureSpecs })
 assert.ok(unknownKey.error)
 const unknownRule = await reprobeOne({ ...baseline, findings: [{ key: 'new-rule', title: 'unconfigured fixture' }] }, 'new-rule', { transport, specs: fixtureSpecs })
 assert.equal(unknownRule.verdict, 'unclear')
 const foreignTarget = await reprobeOne({ ...baseline, target: 'demo.example' }, 'fixture-key', { transport, specs: fixtureSpecs })
 assert.equal(foreignTarget.verdict, 'unclear')
 assert.equal(count, 0)
})
