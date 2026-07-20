# CLI 命令

CLI 是 `cc_orchestrator.py`。

先设置 `CC_ORCHESTRATOR_HOME`：

```bash
export CC_ORCHESTRATOR_HOME="$HOME/.codex/skills/claude-code-orchestrator/scripts/cc-orchestrator"
```

Windows PowerShell：

```powershell
$env:CC_ORCHESTRATOR_HOME = "$env:USERPROFILE\.codex\skills\claude-code-orchestrator\scripts\cc-orchestrator"
```

## 健康检查和发现

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" selftest
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" healthcheck
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" list-profiles
```

启动 worker 前先跑这些。

## 工作区治理

初始化受管理的产物目录：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" folder-policy --cwd /path/to/project --apply
```

整理旧产物或噪声文件：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" migrate-data --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" clean-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" archive-runs --cwd /path/to/project --older-than-days 30
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" repair-mcp-paths --cwd /path/to/project --create
```

这些命令只管理 Agent 生成的产物。会改路径或删除东西的动作默认先预览，除非传 `--apply`。

## 路由

只看路由，不启动 Claude Code：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" pick --role implementation --task-type complex_code
```

生成完整工作流计划：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-plan "Refactor this project safely"
```

校验和预演可复用工作流 DAG：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-validate --file examples/workflows/safe-refactor.yaml --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-dry-run --file examples/workflows/safe-refactor.yaml --task "Refactor module X" --cwd /path/to/project
```

设置 `--cwd` 后，workflow 文件必须在这个项目目录或它托管的 `.agent-workspace` 里。

先用 mock 模式跑控制器，不花模型额度：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-run --file examples/workflows/safe-refactor.yaml --task "Refactor module X" --cwd /path/to/project --mock
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-status --workflow-id WF_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-report --workflow-id WF_ID
```

使用结构化 handoff 合约：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-template --role testing
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-validate --run-id RUN_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-read --run-id RUN_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-repair-prompt --run-id RUN_ID
```

## 模型评分和报告

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" score-models
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" write-auto-policy
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" write-reports
```

`write-auto-policy` 会更新角色别名，让本机模型按角色自动选择。

`write-reports` 会把模型评分和策略报告写到 `.agent-workspace/claude-code-orchestrator/reports`。

## 启动 worker

只读架构 worker：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run "Map this repository architecture" --role architecture
```

允许改文件的实现 worker：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run "Fix the failing test in src/foo.py" --role implementation --allow-write --cwd /path/to/project
```

打开可视 Claude Code 窗口：

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-visible "Inspect this project" --role architecture
```

## 查看运行结果

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" last-run
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" diff --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" verify-run --run-id <run_id> --test-command "npm test"
```

run 会存到：

```text
.agent-workspace/claude-code-orchestrator/runs/<run_id>/
  metadata.json
  stdout.txt
  stderr.txt
```

即时 prompt/context 通过受控 stdin 发送，不会持久化到 run 目录。

Windows 实时看 stdout：

```powershell
Get-Content ".agent-workspace\claude-code-orchestrator\runs\<run_id>\stdout.txt" -Wait
```

macOS 或 Linux：

```bash
tail -f ".agent-workspace/claude-code-orchestrator/runs/<run_id>/stdout.txt"
```

## 实时控制

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-streaming "Review this repo" --role review
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" poll-run --run-id <run_id>
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" summarize-run --run-id <run_id>
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" compact-events --run-id <run_id>
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-status
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" stop-run --run-id <run_id> --force
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" mock-stream-test
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-streaming "Noisy task" --role testing --max-output-bytes 200000 --kill-on-excessive-output
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" controller-report --limit 20
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" decision-review "accept worker result" --run-id <run_id> --evidence "verify-run passed"
```

`poll-run` 默认是 controller 模式，会返回压缩进度、风险、改动文件、时间线、工具调用摘要和 checkpoint 路径。

`mock-stream-test` 用假 Claude stream，不花模型额度也能测试 streaming。
