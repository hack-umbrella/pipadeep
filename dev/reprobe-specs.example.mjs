// reprobe 判定规格示例（Schema 说明 + 用例）
//
// 一键复测引擎 (lib/reprobe.mjs) 通过 `options.specs` 注入目标特定的判定规格；
// 插件本体不内置任何具体目标的规则。每条规格：
//
//   {
//     id:     'stable-id',              // 唯一标识（用于证据文件命名）
//     match:  ['标题关键词'],            // 与 finding 标题做「包含」匹配（大小写不敏感）
//     label:  '人类可读名',              // 展示与证据标签
//     requests: [                        // 要重放的请求（只读；写接口务必用空体）
//       { method: 'POST', url: 'https://target.example/api',
//         headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'id=1' }
//     ],
//     judge: (responses) => ({ verdict, detail })
//       // responses 与 requests 一一对应：{ ok, status, statusText, headers, body, durationMs, error }
//       // verdict ∈ 'open'（仍存在）| 'fixed'（已修复）| 'unclear'（需人工确认）
//   }
//
// 引擎自带的安全网（无需在 judge 里重复处理）：
//   - 请求失败 / 超时 / 5xx / 429  → 一律 unclear，绝不判 fixed
//   - 规格的请求域必须命中基线目标域（或其子域），否则不发请求、直接 unclear
//   - 目标不符 / 未匹配到规格 → unclear（需人工复测），不会瞎猜
//
// 使用：在调用 reprobeOne / runReprobe 时传入
//   import { specs } from './dev/reprobe-specs.example.mjs'
//   await reprobeOne(baseline, key, { sessionId, specs })

export const specs = [
	{
		id: 'example-unauth-api',
		match: ['未授权访问', 'Unauthorized API'],
		label: '未授权 API 访问（示例）',
		requests: [
			{ method: 'GET', url: 'https://target.example/api/profile', headers: { 'user-agent': 'dsh-retest/1.0' } }
		],
		judge: ([r]) => {
			if (r.status === 200 && String(r.body ?? '').includes('"email"')) return { verdict: 'open', detail: '未认证仍返回个人信息字段' }
			if (r.status === 401 || r.status === 403) return { verdict: 'fixed', detail: `已要求认证（HTTP ${r.status}）` }
			return { verdict: 'unclear', detail: `响应形态变化（HTTP ${r.status}），需人工确认` }
		}
	},
	{
		id: 'example-security-headers',
		match: ['安全响应头', 'Security Headers'],
		label: '安全响应头缺失（示例）',
		requests: [
			{ method: 'GET', url: 'https://target.example/', headers: { 'user-agent': 'dsh-retest/1.0' } }
		],
		judge: ([r]) => {
			const missing = ['strict-transport-security', 'content-security-policy', 'x-content-type-options'].filter((name) => !r.headers[name])
			if (missing.length > 0) return { verdict: 'open', detail: `仍缺 ${missing.join(' / ')}` }
			return { verdict: 'fixed', detail: '三项安全头均已下发' }
		}
	}
]
