# Repository Guidelines

## 项目结构与模块划分

本仓库把渗透测试模式打包成一个 DSH bundle。`lib/` 是发布时的运行时面：`pentest.js`、
`storage-sqlite.js` 与 Web 客户端文件随 `npm pack` 一同分发。`cordis.patch.yml` 与这些
export 保持一致。

- `lib/pentest-tools.js`：**本项目的源码**（执行层）。纯 JS、零外部 import、无需构建，
  改完直接重新 `npm pack` 即可。
- `lib/pentest.js` / `lib/storage-sqlite.js` / `lib/ui-pentest.js` / `lib/ui-pentest.client.js` /
  `lib/preset-root.js` / `lib/index.js` / `lib/invariant.js`：**vendored** 自
  howmp/dsh-pentest 的构建产物（记录层 / Web 视图 / sqlite 后端 / 预设根）。除非要同步上游，
  否则不要手工编辑；上游改动后按其 AGENTS.md 的重建流程重新生成对应文件。
- `preset/pentest/`：只读系统预设（「渗透模式 Pro」），由 bundle 的 `preset-root` 注册。
- `README.md` 面向最终用户；本文件面向贡献者/agent。

## 安装、构建与验证命令

- `npm pack`：生成 npm `.tgz`（改名 `@pipadeep/dsh-pentest` 时文件名自动为
  `pipadeep-dsh-pentest-<version>.tgz`）。
- `dsh plugin --profile web add -w file:<path.tgz>`：安装进本地 Web profile（pnpm 10 需 `-w`）。
- `dsh --profile web --dump-config`：只组合并打印 profile 树、不启动服务，用于验证补丁层。
- 冒烟测试（无需重启 dsh）：
  ```bash
  node -e "import('<profile>/node_modules/@pipadeep/dsh-pentest/lib/pentest-tools.js').then(m=>console.log(Object.keys(m)))"
  ```
- `node --check lib/pentest-tools.js`：语法检查执行层源码。

## 改动后的验证清单

1. `node --check` 所有被改的 JS。
2. 用 js-yaml 校验 `preset/pentest/agent.cordis.yml` 与 `cordis.patch.yml`（注册 `!!js` 标量类型）。
3. `dsh --profile web --dump-config` 确认 `storage-domain` 路由 `pentest: sqlite` 及
   `ui-pentest` / `storage-sqlite` / `pentest-preset-root` 三行就位。
4. 重新 `npm pack`，并用 `dsh plugin remove -w` + `add -w` 重装（pnpm 会按 `file:` 路径
   解析依赖，删除旧 tarball 前必须先 remove）。

## 代码风格与命名

- `lib/pentest-tools.js` 用两空格缩进、单引号、无分号，函数/变量 `camelCase`。
- 工具名统一 `pentest_*` 小写蛇形；row id 与文件名 kebab-case。
- 每个执行工具必须：输入校验（`isHost`/`isUrl`/`isParam`）、返回 `OUT` 渲染、
  `exec.signal.aborted` 中断检查、请求统一走 `PROXY`（`127.0.0.1:8080`）。
- 记录层工具（`pentest_add_*` / `pentest_submit` / `pentest_state` / `pentest_graph` /
  `pentest_report`）只属于指挥官；执行子 agent 的 `toolFilter.deny` 必须继续禁掉它们。

## 授权边界（硬性）

- 只测有书面授权的目标。`pentest_add_goal` 的 `authorization` 是审计事实、不是门禁；
  扫描/利用仍受部署沙箱与审批约束。
- 绝不提交本地 profile、数据库、凭据、flag。

## 提交规范

Conventional Commit 风格，如 `feat: add xxx execution tool` / `fix: align sqlite path`。
涉及 UI 改动附 Web 截图；涉及 vendored 产物重生成时描述重建来源与版本。
