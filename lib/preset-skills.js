import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const inject = ["skills"];

/** 本包自带的 skill（目录名即 skill 名）。 */
const BUNDLED_SKILLS = [
	"pentest-methodology",
	"pentest-recon",
	"pentest-exploit",
	"pentest-bypass",
	"pentest-report",
];

/**
 * 解析 SKILL.md 的 YAML frontmatter（只需 name/description，故不引 YAML 依赖）。
 * @param {string} text 文件全文
 * @returns {{ fields: Record<string, string>, body: string }}
 */
function parseFrontmatter(text) {
	const source = String(text ?? "");
	if (!source.startsWith("---")) return { fields: {}, body: source };
	const end = source.indexOf("\n---", 3);
	if (end === -1) return { fields: {}, body: source };
	const raw = source.slice(3, end);
	const fields = {};
	for (const line of raw.split("\n")) {
		const at = line.indexOf(":");
		if (at <= 0) continue;
		const key = line.slice(0, at).trim();
		let value = line.slice(at + 1).trim();
		if (
			(value.startsWith("'") && value.endsWith("'")) ||
			(value.startsWith('"') && value.endsWith('"'))
		) {
			value = value.slice(1, -1);
		}
		if (key !== "") fields[key] = value;
	}
	return { fields, body: source.slice(end + 4) };
}

/**
 * 把本包 `skills/` 下的 skill 注册进**当前预设作用域**。
 *
 * 为什么不能靠目录自动发现：dsh 0.1.7 起预设不再是「目录」，`$DSH_HOME/.agent-presets`
 * 那种扫描也没了 —— 预设自带的 `skills/` 不再有任何介质去发现。改为显式注册，
 * 两代（0.1.2 / 0.1.7）行为一致，也不依赖安装路径能被猜到。
 */
export function apply(ctx) {
	const skills = ctx.get("skills");
	if (!skills || typeof skills.register !== "function") return;
	for (const dir of BUNDLED_SKILLS) {
		let file;
		try {
			file = fileURLToPath(new URL(`../skills/${dir}/SKILL.md`, import.meta.url));
		} catch {
			continue;
		}
		if (!existsSync(file)) continue;
		const { fields, body } = parseFrontmatter(readFileSync(file, "utf8"));
		ctx.effect(
			() =>
				skills.register({
					name: fields.name || dir,
					description: fields.description || "",
					source: "runtime",
					provider: "pipadeep-pentest",
					path: file,
					resourceBase: { kind: "directory", path: dirname(file) },
					content: body,
				}),
			`pentest.skill.${dir}`,
		);
	}
}
