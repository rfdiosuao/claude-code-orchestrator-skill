# 快速开始

这一页帮你安装 Skill、检查本机环境，并把 Codex 接到内置 MCP Server。

## 用一句话让 Codex 安装

先装好 Claude Code 和 CCSwitch，然后把这句话交给 Codex：

```text
Install the Codex Skill and MCP server from https://github.com/chu459/claude-code-orchestrator-skill. Put the Skill at ~/.codex/skills/claude-code-orchestrator, wire the bundled MCP server into Codex config.toml, run selftest, healthcheck, score-models, init-workspace, workspace-status, and show me the selected multi-agent routing plan. Do not print secrets.
```

## 从源码安装

Windows PowerShell：

```powershell
$tmp = Join-Path $env:TEMP "claude-code-orchestrator-skill.zip"; `
iwr -UseBasicParsing "https://github.com/rfdiosuao/claude-code-orchestrator-skill/archive/refs/tags/v0.8.0.zip" -OutFile $tmp; `
$dir = Join-Path $env:TEMP "claude-code-orchestrator-skill"; `
if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }; `
Expand-Archive $tmp -DestinationPath $dir -Force; `
& (Get-ChildItem $dir -Recurse -Filter install.ps1 | Select-Object -First 1).FullName
```

macOS 或 Linux：

```bash
tmp="$(mktemp -d)" && \
curl -L "https://github.com/rfdiosuao/claude-code-orchestrator-skill/archive/refs/tags/v0.8.0.zip" -o "$tmp/skill.zip" && \
unzip -q "$tmp/skill.zip" -d "$tmp" && \
bash "$tmp"/claude-code-orchestrator-skill-0.8.0/install/install.sh
```

只有在不可变的 `v0.8.0` tag 发布后才能用于生产安装。请把下载归档的 SHA-256 记入部署日志，回滚时复核；不得替换成分支归档。

默认安装到：

```text
~/.codex/skills/claude-code-orchestrator
```

> **平台边界：** v0.8.0 的生产级 guarded worker 执行仅支持 Windows。macOS 和 Linux 可以安装并运行管理检查，但在实现整棵进程树 containment 之前，启动命令会 fail closed。

## 设置工具路径

Windows PowerShell：

```powershell
$env:CC_ORCHESTRATOR_HOME = "$env:USERPROFILE\.codex\skills\claude-code-orchestrator\scripts\cc-orchestrator"
```

macOS 或 Linux：

```bash
export CC_ORCHESTRATOR_HOME="$HOME/.codex/skills/claude-code-orchestrator/scripts/cc-orchestrator"
```

## 运行检查

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" selftest
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" healthcheck
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" list-profiles
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" score-models
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd .
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd .
```

你应该看到：

- Windows 上 `selftest` 返回 `ok: true`；macOS/Linux 上会按设计返回非零，并报告 `runtime_security.process_tree_containment.supported: false`。
- `healthcheck` 能找到 Python 配置、Claude Code 和 CCSwitch 文件。
- `list-profiles` 能列出 Claude-compatible profiles。
- `score-models` 返回本机模型评分。
- `init-workspace` 创建 `.agent-workspace/claude-code-orchestrator`。
- `workspace-status` 显示 runs、reports、dashboard、archives、rollback、templates、policies 会写到哪里。

下一步：配置 [MCP](/zh/guide/mcp)，让 Codex 能直接调用工具。
