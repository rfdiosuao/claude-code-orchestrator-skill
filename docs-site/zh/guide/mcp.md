# MCP 设置

MCP 是工具层。

它让 Codex 不用手动复制命令，就能直接调用 orchestrator。

## Codex 配置

把这段加到 Codex `config.toml`：

```toml
[mcp_servers.claude-code-orchestrator]
command = "python"
args = [
  "-c",
  "import os,sys,runpy; home=os.environ.get('CODEX_HOME') or os.path.join(os.environ.get('USERPROFILE') or os.path.expanduser('~'), '.codex'); root=os.environ.get('CC_ORCHESTRATOR_HOME') or os.path.join(home, 'skills', 'claude-code-orchestrator', 'scripts', 'cc-orchestrator'); sys.path.insert(0, root); runpy.run_path(os.path.join(root, 'server.py'), run_name='__main__')"
]

[mcp_servers.claude-code-orchestrator.env]
PYTHONIOENCODING = "utf-8"
PYTHONUTF8 = "1"
CC_ORCHESTRATOR_WORKSPACE_ROOT = "."
CC_ORCHESTRATOR_ARTIFACT_ROOT = ".agent-workspace/claude-code-orchestrator"
```

Windows 上可以用安全安装脚本写入 Codex 和 Claude MCP 配置，脚本会先备份：

```powershell
powershell -ExecutionPolicy Bypass -File .\install\install-mcp.ps1
```

示例文件也在：

```text
docs/mcp.codex.example.toml
```

## 常用 MCP 工具

| 工具 | 作用 |
| --- | --- |
| `cc_healthcheck` | 检查 Claude Code、CCSwitch、Python 和配置 |
| `cc_list_profiles` | 列出 CCSwitch profiles，并脱敏密钥 |
| `cc_pick_profile` | 查看某个角色会用哪个 profile 和模型 |
| `cc_run_agent` | 启动一个 Claude Code worker |
| `cc_run_streaming_agent` | 后台启动 worker，并写入实时 `events.ndjson` |
| `cc_poll_run` | 默认返回压缩后的总控进度 |
| `cc_stop_run` | 停止一个 worker |
| `cc_spawn_role_team` | 一次启动多个角色 worker |
| `cc_verify_run` | 串起 diff、范围、密钥、测试和报告 |
| `cc_init_workspace` | 初始化 `.agent-workspace`、模板、策略、回滚和日志目录 |
| `cc_workspace_status` | 查看 Codex 和 Claude Code 的产物会写到哪里 |
| `cc_migrate_data` | 预览或迁移旧的 `runs`、`reports`、`dashboard` |
| `cc_clean_workspace` | 清理临时文件、空目录、过期 run，默认 dry-run |
| `cc_archive_runs` | 把旧 run 打包进 `archives/` |
| `cc_repair_mcp_paths` | 修复 `.mcp.json` 里的工作区和产物路径 |
| `cc_folder_policy` | 返回或写入“只管理 Agent 产物”的目录策略 |
| `cc_dashboard` | 生成本地 HTML 看板 |
| `cc_controller_report` | 导出总控验收和压测证据报告 |
| `cc_pressure_report` | `cc_controller_report` 的压测报告别名 |
| `cc_mock_stream_test` | 可选的本机诊断工具，默认不注册 |
| `cc_decision_review` | 审查 Codex 总控决策，返回 approve/revise/block |
| `cc_workflow_validate` | 校验 YAML/JSON 工作流 DAG |
| `cc_workflow_dry_run` | 不启动 worker，只看拓扑批次 |
| `cc_workflow_run` | 运行工作流；`mock=true` 不花模型额度 |
| `cc_workflow_status` | 查看节点状态、gate 细节和决策 |
| `cc_workflow_retry_node` | 让指定节点和下游节点失效并准备重试 |
| `cc_workflow_stop` | 取消工作流和正在跑的节点 |
| `cc_workflow_report` | 写出带 decision trail 的工作流报告 |
| `cc_handoff_template` | 返回角色 handoff schema 和示例 |
| `cc_handoff_validate` | 校验 run 的 `handoff.json` |
| `cc_handoff_read` | 读取 run 的 `handoff.json` |
| `cc_handoff_repair_prompt` | 生成补齐 handoff 缺字段的 prompt |

Workflow MCP 工具会把 workflow 文件限制在 `cwd` 或它托管的 `.agent-workspace` 内；不传 `cwd` 时，默认用 MCP server 当前项目目录。

## 默认安全策略

worker 默认使用计划模式。

只有 Codex 已经判断需要改文件，并且写入范围清楚时，才传 `allow_write=true`。

工具输出和保存日志会做密钥脱敏，但 prompt 里也不要主动要求打印原始密钥。

受支持的 MCP 部署仅限本机、同一用户的 `stdio`。`cc_mock_stream_test` 是使用内部 fake runtime 的诊断入口；不得通过 SSE/HTTP 或代理对外暴露，任何可远程访问的工具白名单都必须排除它。

MCP server 默认不会注册 `cc_mock_stream_test`。仅在临时本机诊断会话中，可为该 server 进程设置 `CC_ORCHESTRATOR_ENABLE_LOCAL_DIAGNOSTICS=1` 并重启；测试结束后应立即移除该变量。

## 冒烟测试

重启 Codex 后，调用：

```text
cc_healthcheck
cc_list_profiles
cc_score_models
cc_workspace_status
```

这些能跑通，就说明 Codex 已经能通过 MCP 调度 worker。
