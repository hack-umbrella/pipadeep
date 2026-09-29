import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'

/**
 * 两份 composition 只在 workflow provider 行上不同。
 *
 * `@deepseek-ai/dsh-workflow-worker-thread` 自 dsh 0.1.6-alpha.1 起被
 * `@deepseek-ai/dsh-workflow-ptc` 取代，而预设里引用一个不存在的包**不是降级可用**，
 * 而是整份预设激活失败（`agent-preset/invalid: … never started`）。所以维护两份变体，
 * 并把差异锁死在测试里，防止手改主文件后忘记同步。
 */
const main = new URL('../preset/pentest/agent.cordis.yml', import.meta.url)
const next = new URL('../preset/pentest/agent.cordis.next.yml', import.meta.url)
const lines = (url) =>
  readFileSync(url, 'utf8')
    .split('\n')
    .filter((line) => !/^\s*#/.test(line) && line.trim() !== '')

test('workflow 变体之间只差 workflow provider 两行', () => {
  const a = lines(main)
  const b = lines(next)
  assert.equal(a.length, b.length, '两份文件的行数必须一致')
  const diffs = a.map((line, index) => (line === b[index] ? null : [index, line, b[index]])).filter(Boolean)
  assert.equal(diffs.length, 2, `只应有两行差异，实际 ${diffs.length}：${JSON.stringify(diffs)}`)
  assert.match(diffs[0][1], /workflow-worker-thread/)
  assert.match(diffs[0][2], /workflow-ptc/)
  assert.match(diffs[1][1], /dsh-workflow-worker-thread/)
  assert.match(diffs[1][2], /dsh-workflow-ptc/)
})

test('主 composition 保持 0.1.5- 可用的 worker-thread', () => {
  assert.match(readFileSync(main, 'utf8'), /dsh-workflow-worker-thread/)
})
