// 渗透-管理 数据路由（loopback-only）：供 Web 管理面板读写「绕过库」与「技能」。
// 完全对标 dsh-auto-memory 的 `/api/<plugin>/...` 模式：host 挂路由，浏览器 fetch 读写。
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { dirname, join as joinPath } from "node:path";

const name = "bypass-routes";
const inject = ["webServer"];

const POINT = "/api/pipadeep-pentest";
const BYPASS_TYPES = ["sqli","xss","lfi","cmdi","rce","upload","ssti","ssrf","xxe","jwt","generic"];

function bypassFile() { return (process.env.PENTEST_BYPASS_FILE || "./pentest-bypass.json"); }
function skillsDir() { return ((process.env.PENTEST_SKILLS_DIR || ".dsh/skills").replace(/\/+$/, "")) || ".dsh/skills"; }

function readJson(file) { try { return JSON.parse(readFileSync(file, "utf8")); } catch (e) { return {}; } }
function writeJsonFile(file, data) { const d = dirname(file); if (d) mkdirSync(d, { recursive: true }); writeFileSync(file, JSON.stringify(data, null, 2)); }
function send(res, status, obj) { try { res.statusCode = status; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(obj)); } catch (e) { /* noop */ } }
function bodyOf(req) {
  const b = req.body;
  if (b && typeof b === "object") return b;
  if (typeof b === "string") { try { return JSON.parse(b); } catch (e) { return {}; } }
  return {};
}

function addBypass(body) {
  const alias = { rce: "cmdi", cmd: "cmdi", command: "cmdi" };
  const vuln = String(alias[(body.vuln || "").toString().toLowerCase()] || body.vuln || "").toLowerCase();
  if (BYPASS_TYPES.indexOf(vuln) < 0) return { status: 400, obj: { error: "vuln 非法，应为 " + BYPASS_TYPES.join("|") } };
  const payloads = (Array.isArray(body.payloads) ? body.payloads : String(body.payloads || "").split(/[\n,]+/)).map((s) => s.toString().trim()).filter(Boolean);
  if (!payloads.length) return { status: 400, obj: { error: "payloads 为空" } };
  const file = bypassFile(); const data = readJson(file);
  const tier = Number(body.tier == null ? 1 : body.tier);
  const t = { tier: isNaN(tier) ? 1 : tier, name: String(body.name || ("T" + (isNaN(tier) ? 1 : tier))), note: String(body.note || ""), payloads };
  data[vuln] = Array.isArray(data[vuln]) ? data[vuln] : [];
  data[vuln].push(t);
  data[vuln].sort((a, b) => (Number(a.tier) || 0) - (Number(b.tier) || 0));
  writeJsonFile(file, data);
  return { status: 200, obj: { saved: true, file, vuln, count: data[vuln].length, added: t } };
}

function removeBypass(body) {
  const vuln = String(body.vuln || "").toLowerCase();
  const file = bypassFile(); const data = readJson(file);
  const list = Array.isArray(data[vuln]) ? data[vuln] : [];
  const before = list.length;
  data[vuln] = list.filter((t) => {
    if (body.name && String(body.name) === String(t.name)) return false;
    if (body.tier != null && Number(body.tier) === Number(t.tier)) return false;
    return true;
  });
  writeJsonFile(file, data);
  return { status: 200, obj: { saved: true, vuln, removed: before - data[vuln].length, remaining: data[vuln].length } };
}

function addSkill(body) {
  const name = String(body.name || "").trim();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) return { status: 400, obj: { error: "name 需为 kebab-case（小写字母/数字/连字符）" } };
  const desc = String(body.description || "").trim(); if (!desc) return { status: 400, obj: { error: "description 必填" } };
  const content = String(body.content || "").trim(); if (!content) return { status: 400, obj: { error: "content 为空" } };
  const dir = skillsDir();
  const rel = joinPath(dir, name, "SKILL.md");
  mkdirSync(dirname(rel), { recursive: true });
  writeFileSync(rel, "---\nname: " + name + "\ndescription: " + desc.replace(/\n+/g, " ") + "\n---\n\n" + content + "\n");
  return { status: 200, obj: { saved: true, file: rel, name } };
}

function listSkills() {
  const dir = skillsDir();
  let skills = [];
  try { if (existsSync(dir)) { for (const en of readdirSync(dir)) { if (existsSync(joinPath(dir, en, "SKILL.md"))) skills.push(en); } } } catch (e) { /* noop */ }
  return { status: 200, obj: { dir, skills } };
}

function listBypass() {
  const file = bypassFile(); const data = readJson(file);
  const types = {};
  for (const k of Object.keys(data)) if (Array.isArray(data[k])) types[k] = data[k];
  return { status: 200, obj: { file, types, waf_tips: data.waf_tips || {} } };
}

function apply(ctx) {
  const disposers = [];
  const routes = [
    { path: POINT + "/bypass", method: "GET", handler: async (req, res) => { const r = listBypass(); send(res, r.status, r.obj); } },
    { path: POINT + "/bypass", method: "POST", handler: async (req, res) => { const r = addBypass(bodyOf(req)); send(res, r.status, r.obj); } },
    { path: POINT + "/bypass/remove", method: "POST", handler: async (req, res) => { const r = removeBypass(bodyOf(req)); send(res, r.status, r.obj); } },
    { path: POINT + "/skills", method: "GET", handler: async (req, res) => { const r = listSkills(); send(res, r.status, r.obj); } },
    { path: POINT + "/skills", method: "POST", handler: async (req, res) => { const r = addSkill(bodyOf(req)); send(res, r.status, r.obj); } },
  ];
  for (const route of routes) {
    try { const d = ctx.webServer.register(route); if (d) disposers.push(d); }
    catch (e) { console.error("[pipadeep-routes] register " + route.path + ":", e && e.message); }
  }
  return () => { for (const d of disposers) try { d(); } catch (e) {} };
}

export { name, inject, apply, listBypass, addBypass, removeBypass, listSkills, addSkill };
