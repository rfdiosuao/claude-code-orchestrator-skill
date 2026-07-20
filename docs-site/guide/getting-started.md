# Get started

This page gets the Skill installed, checks the local setup, and points Codex at the bundled MCP server.

## Install with one Codex prompt

Paste this into Codex after Claude Code and CCSwitch are installed:

```text
Install the Codex Skill and MCP server from https://github.com/chu459/claude-code-orchestrator-skill. Put the Skill at ~/.codex/skills/claude-code-orchestrator, wire the bundled MCP server into Codex config.toml, run selftest, healthcheck, score-models, init-workspace, workspace-status, and show me the selected multi-agent routing plan. Do not print secrets.
```

## Install from source

Windows PowerShell:

```powershell
$tmp = Join-Path $env:TEMP "claude-code-orchestrator-skill.zip"; `
iwr -UseBasicParsing "https://github.com/chu459/claude-code-orchestrator-skill/archive/refs/heads/main.zip" -OutFile $tmp; `
$dir = Join-Path $env:TEMP "claude-code-orchestrator-skill"; `
if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }; `
Expand-Archive $tmp -DestinationPath $dir -Force; `
& (Get-ChildItem $dir -Recurse -Filter install.ps1 | Select-Object -First 1).FullName
```

macOS or Linux:

```bash
tmp="$(mktemp -d)" && \
curl -L "https://github.com/chu459/claude-code-orchestrator-skill/archive/refs/heads/main.zip" -o "$tmp/skill.zip" && \
unzip -q "$tmp/skill.zip" -d "$tmp" && \
bash "$tmp"/claude-code-orchestrator-skill-main/install/install.sh
```

The default install target is:

```text
~/.codex/skills/claude-code-orchestrator
```

> **Platform boundary:** Production guarded worker execution is Windows-only in v0.8.0. macOS and Linux can install and run administrative checks, but launch commands fail closed until whole-process-tree containment is implemented.

## Set the tool path

Windows PowerShell:

```powershell
$env:CC_ORCHESTRATOR_HOME = "$env:USERPROFILE\.codex\skills\claude-code-orchestrator\scripts\cc-orchestrator"
```

macOS or Linux:

```bash
export CC_ORCHESTRATOR_HOME="$HOME/.codex/skills/claude-code-orchestrator/scripts/cc-orchestrator"
```

## Run checks

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" selftest
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" healthcheck
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" list-profiles
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" score-models
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd .
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd .
```

Expected result:

- `selftest` returns `ok: true`.
- `healthcheck` can find Python config, Claude Code, and CCSwitch files.
- `list-profiles` shows Claude-compatible CCSwitch profiles.
- `score-models` returns local heuristic scores.
- `init-workspace` creates `.agent-workspace/claude-code-orchestrator`.
- `workspace-status` shows where runs, reports, dashboard, archives, rollback notes, templates, and policies will be written.

Next: configure [MCP](/guide/mcp) so Codex can call the tools directly.
