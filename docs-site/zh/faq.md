# FAQ

## 这是 Codex 的替代品吗？

不是。

Codex 仍然是总控。Claude Code 是外部 worker。

## 默认会改文件吗？

不会。

默认权限是计划模式。只有明确实现任务时，才使用 `allow_write=true` 或 `--allow-write`。

## 会修改我的全局 CCSwitch profile 吗？

不会。

orchestrator 只读取 CCSwitch profile，并把 provider 环境变量注入到单次 Claude Code 子进程。

## 为什么 CCSwitch 里需要多个模型？

因为一个模型很难适合所有角色。

快模型适合快速检查。强推理模型适合审查或架构。代码模型适合实现。

## 模型评分是真 benchmark 吗？

不是。

它是根据模型名称和能力信号做的本地启发式评分。用来辅助路由，不要当绝对真理。

## `healthcheck` 失败怎么办？

按这个顺序检查：

1. Python 3.10 或更新版本可用。
2. `claude` 在 PATH 里，或者设置了 `CLAUDE_CODE_BIN`。
3. CCSwitch 已安装。
4. CCSwitch 里有 Claude-compatible profiles。
5. `CC_ORCHESTRATOR_HOME` 指向 `scripts/cc-orchestrator`。

## 怎么看 worker 运行过程？

打开可视 worker：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-visible "Inspect this project" --role architecture
```

再查看最新 run：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" last-run
```

## 日志存在哪里？

在这里：

```text
.agent-workspace/claude-code-orchestrator/runs/<run_id>/
```

每次 run 可以包含 `metadata.json`、`stdout.txt`、`stderr.txt` 和总控产物。即时 prompt/context 通过 stdin 传输，不会再持久化成 `prompt.txt`。

## 怎么让 Agent 文件更整齐？

先跑：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" clean-workspace --cwd /path/to/project
```

`clean-workspace` 默认 dry-run，只管理 `.agent-workspace/claude-code-orchestrator` 里的 Agent 产物。

## GitHub Pages 怎么部署？

`.github/workflows/deploy-docs.yml` 会运行：

```bash
npm ci
npm run docs:build
```

然后上传：

```text
docs-site/.vitepress/dist
```

VitePress 的 `base` 会在 GitHub Actions 里根据 `GITHUB_REPOSITORY` 自动设置。
