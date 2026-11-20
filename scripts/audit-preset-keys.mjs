#!/usr/bin/env node
/**
 * 预设配置键审计：把 preset/ 目录里每个 composition 行，逐个对照**宿主插件的真实
 * Config schema**，找出「宿主根本不认识」的配置键。
 *
 * 为什么要有这个脚本：schemastery 对未知键是**静默保留、绝不报错**——
 * 写错键不会让预设挂掉，只会让那段配置悄悄不生效。本仓库真实踩过两次：
 *
 *   1. `dsh-agent-instructions` 的 `text`：它只负责加载 AGENTS.md 之类文件，
 *      Config 里没有 `text`。执行子 agent 的人设因此从未生效（应写 `dsh-persona.prefix`）。
 *   2. `dsh-tool-subagent` 的 `backgroundMode` / `enableRunInBackground`：0.2.x 早已移除，
 *      是 0.1.x 的遗留死键。
 *
 * 两处都不会报错，只能靠对照 schema 发现。允许的例外写在下面的 ALLOWLIST 里，
 * 每条都要说清为什么保留（通常是跨版本双写）。
 *
 * 用法：
 *   node scripts/audit-preset-keys.mjs                 # 用当前 profile 的 dsh 安装做对照
 *   node scripts/audit-preset-keys.mjs --dsh-dir <dir> # 指定 dsh 安装目录
 *   node scripts/audit-preset-keys.mjs --strict        # 例外也当失败（CI 用）
 *
 * 退出码非 0 表示发现未登记的多余键。
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * 允许存在的「schema 之外」键，必须写明原因。
 * key: `${pluginName}` → `{ keys: {[key]: reason} }`
 */
const ALLOWLIST = {
	'@deepseek-ai/dsh-persona': {
		text: 'dsh ≤0.1.2 的 dsh-persona 用 `text`；0.2.x 用 `prefix`。双写兼容两代。',
	},
	'@deepseek-ai/dsh-tool-subagent': {
		persona: 'dsh 0.1.x 的行内人设（0.2.x 已移除，但 agent.cordis.yml 是 0.1.x 专用变体）。',
		toolFilter: 'dsh 0.1.x 的行内工具过滤（0.2.x 已移除，同上）。',
	},
}

/** 0.1.x 专用变体：这些文件本来就要给老版本的键，不参与 0.2.x schema 对照。 */
const LEGACY_VARIANTS = new Set(['agent.cordis.yml', 'executor.cordis.yml'])

const args = process.argv.slice(2)
const strict = args.includes('--strict')
const dshDirArg = args.includes('--dsh-dir') ? args[args.indexOf('--dsh-dir') + 1] : undefined

/** Locate the running install's @deepseek-ai packages. */
function dshDir() {
	if (dshDirArg) return dshDirArg
	if (process.env.DSH_INSTALL_DIR) return process.env.DSH_INSTALL_DIR
	const home = process.env.HOME || ''
	const candidates = [
		join(home, '.local/lib/node_modules/@deepseek-ai/dsh'),
		'/usr/local/lib/node_modules/@deepseek-ai/dsh',
	]
	return candidates.find((dir) => existsSync(join(dir, 'package.json')))
}

/** Strip `!!js <expr>` tags so a plain YAML parse works (only keys matter here). */
function stripJs(text) {
	return text
		.split('\n')
		.map((line) => {
			if (!line.includes('!!js')) return line
			const match = /^(\s*[^:#]+:\s*)!!js\s+(.*)$/.exec(line)
			return match ? match[1] + JSON.stringify(match[2]) : line.replace(/!!js\s+/, '')
		})
		.join('\n')
}

/** Flatten nested `cordis:group` config arrays into one row list. */
function flatten(rows, out = []) {
	for (const row of rows ?? []) {
		if (row === null || typeof row !== 'object') continue
		if (typeof row.name === 'string' && !row.name.startsWith('cordis:')) out.push(row)
		if (Array.isArray(row.config)) flatten(row.config, out)
	}
	return out
}

async function loadConfigSchema(installDir, pluginName) {
	const spec = pluginName.replace('@deepseek-ai/', '')
	const base = join(installDir, 'node_modules/@deepseek-ai', spec)
	for (const entry of ['lib/index.js', 'index.js']) {
		const file = join(base, entry)
		if (!existsSync(file)) continue
		try {
			const mod = await import(pathToFileURL(file).href)
			const Config = mod.Config ?? mod.default?.Config
			if (Config && Config.dict) return new Map(Object.keys(Config.dict).map((key) => [key, true]))
		} catch {
			/* try the next entry */
		}
	}
	return null
}

/** Resolve js-yaml from this package first, then from the dsh install tree. */
async function loadYaml(installDir) {
	const candidates = []
	try {
		candidates.push(await import('js-yaml'))
	} catch {
		/* not installed in this checkout */
	}
	const fallbacks = [
		join(ROOT, 'node_modules/js-yaml/index.js'),
		installDir === undefined ? '' : join(installDir, 'node_modules/js-yaml/index.js'),
	]
	for (const file of fallbacks) {
		if (file === '' || !existsSync(file)) continue
		try {
			candidates.push(await import(pathToFileURL(file).href))
			break
		} catch {
			/* try the next location */
		}
	}
	const mod = candidates.find((entry) => typeof (entry.default ?? entry).load === 'function')
	if (mod === undefined) return null
	return mod.default ?? mod
}

async function main() {
	const installDir = dshDir()
	if (installDir === undefined || !existsSync(installDir)) {
		console.error('audit-preset-keys: 找不到 dsh 安装目录；用 --dsh-dir 指定，或设置 DSH_INSTALL_DIR。')
		process.exitCode = 2
		return
	}
	const yaml = await loadYaml(installDir)
	if (yaml === null) {
		console.error('audit-preset-keys: 找不到 js-yaml（先 npm install，或用 --dsh-dir 指向带 js-yaml 的 dsh 安装）。')
		process.exitCode = 2
		return
	}
	const load = yaml.load
	console.log(`dsh 安装：${installDir}`)

	const presetDir = join(ROOT, 'preset/pentest')
	const files = readdirSync(presetDir).filter((name) => name.endsWith('.yml') && name.includes('cordis'))
	const problems = []
	const checked = { rows: 0, schemas: 0 }

	for (const name of files) {
		const legacy = LEGACY_VARIANTS.has(name)
		const rows = flatten(load(stripJs(readFileSync(join(presetDir, name), 'utf8'))))
		console.log(`\n── ${name}${legacy ? '（0.1.x 变体，仅校验 schema 可见项）' : ''}：${rows.length} 行 ──`)
		for (const row of rows) {
			if (row.config === undefined || typeof row.config !== 'object' || Array.isArray(row.config)) continue
			checked.rows += 1
			const schema = await loadConfigSchema(installDir, row.name)
			if (schema === null) continue
			checked.schemas += 1
			const allowed = ALLOWLIST[row.name] ?? {}
			for (const key of Object.keys(row.config)) {
				if (schema.has(key)) continue
				const reason = allowed[key]
				if (reason !== undefined) {
					if (strict) problems.push(`${name} · ${row.name} · ${key}（已登记例外：${reason}）`)
					else console.log(`  ~ ${row.name} · ${key} — 已登记例外：${reason}`)
					continue
				}
				problems.push(`${name} · ${row.name} · ${key} 不在 Config schema（允许：${[...schema.keys()].join(', ')}）`)
			}
		}
	}

	console.log(`\n对照了 ${checked.rows} 个带 config 的行，其中 ${checked.schemas} 行拿到了宿主 schema。`)
	if (problems.length === 0) {
		console.log('✓ 没有未登记的多余配置键。')
		return
	}
	console.log(`\n✗ 发现 ${problems.length} 处未登记的多余键：`)
	for (const problem of problems) console.log(`  - ${problem}`)
	process.exitCode = 1
}

await main()
