# MCP setup

MCP is the tool layer. It lets Codex call the orchestrator without copying shell commands by hand.

## Codex config

Add this to Codex `config.toml`:

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

On Windows, the safe installer can write Codex and Claude MCP config after making backups:

```powershell
powershell -ExecutionPolicy Bypass -File .\install\install-mcp.ps1
```

The same example lives in:

```text
docs/mcp.codex.example.toml
```

## Tools

| Tool | What it does |
| --- | --- |
| `cc_healthcheck` | Checks Claude Code, CCSwitch, Python, and config |
| `cc_list_profiles` | Lists CCSwitch profiles with secrets redacted |
| `cc_pick_profile` | Shows which profile and model a role would use |
| `cc_run_agent` | Runs one Claude Code worker |
| `cc_run_streaming_agent` | Starts a background worker with live `events.ndjson` |
| `cc_poll_run` | Polls compact controller progress by default |
| `cc_summarize_run` | Writes and returns controller artifacts plus rolling checkpoints |
| `cc_compact_events` | Compacts raw events into a timeline and deduplicated tool summary |
| `cc_run_status` | Lists active workers or inspects one run |
| `cc_stop_run` | Stops one worker by run id |
| `cc_send_instruction` | Restarts a run with recovered context and a new instruction |
| `cc_spawn_role_team` | Starts several role workers |
| `cc_collect_team_results` | Summarizes team output |
| `cc_cross_review` | Starts second-round reviewer workers |
| `cc_preflight_write_scope` | Writes allowed/denied path rules |
| `cc_check_write_scope` | Blocks acceptance when writes cross the scope |
| `cc_diff_summary` | Summarizes changed files and risk |
| `cc_secret_scan_run` | Scans run logs and diff for secrets |
| `cc_verify_run` | Runs diff, scope, secret scan, tests, and report |
| `cc_rollback_run` | Conservatively rolls back a safe run diff |
| `cc_benchmark_model` | Plans or runs one benchmark task |
| `cc_benchmark_suite` | Plans or runs fixed benchmark tasks |
| `cc_calibrate_policy` | Saves local model preference notes |
| `cc_model_registry` | Builds the local model capability database |
| `cc_local_policy` | Reads or writes user-owned routing overrides |
| `cc_score_worker` | Grades a worker run and updates quality history |
| `cc_prompt_pack` | Lists or renders reusable worker prompts |
| `cc_cost_guard` | Sets concurrency and timeout guardrails |
| `cc_usage_summary` | Estimates daily usage from logs |
| `cc_queue_submit` | Submits a queued worker job |
| `cc_queue_tick` | Starts queued jobs up to a limit |
| `cc_queue_status` | Reads `queued`, `running`, `done`, `failed`, `timed_out`, and `cancelled` state |
| `cc_queue_cancel` | Cancels a queue job |
| `cc_queue_policy` | Reads or writes queue concurrency, retry, and timeout policy |
| `cc_upgrade_check` | Preserves local preferences across upgrades |
| `cc_mock_stream_test` | Optional local diagnostic; disabled unless explicitly enabled |
| `cc_init_workspace` | Initializes `.agent-workspace`, templates, policies, rollback/log dirs, and optional `CLAUDE.md` |
| `cc_workspace_status` | Shows where Codex and Claude Code artifacts will be written |
| `cc_migrate_data` | Previews or migrates old `runs`, `reports`, and `dashboard` |
| `cc_clean_workspace` | Cleans tmp files, non-scaffold empty dirs, and expired runs, dry-run by default |
| `cc_archive_runs` | Zips old run folders under `archives/` |
| `cc_repair_mcp_paths` | Repairs `.mcp.json` workspace and artifact env values |
| `cc_folder_policy` | Returns or writes the managed-artifacts-only folder policy |
| `cc_dashboard` | Generates a local HTML dashboard |
| `cc_open_run_folder` | Opens a run folder |
| `cc_export_report` | Exports a run or team report |
| `cc_controller_report` | Exports controller acceptance and pressure-report evidence |
| `cc_pressure_report` | Alias for pressure-test report export |
| `cc_decision_review` | Reviews a Codex controller decision and returns approve/revise/block |
| `cc_run_visible_agent` | Opens a visible Claude Code worker window |
| `cc_last_run` | Reads the latest run metadata and output tails |
| `cc_git_diff` | Returns a capped git diff for review |
| `cc_workflow_plan` | Builds the configured multi-agent workflow plan |
| `cc_workflow_validate` | Validates a YAML/JSON workflow DAG |
| `cc_workflow_dry_run` | Shows topological workflow batches without launching workers |
| `cc_workflow_run` | Runs a workflow; use `mock=true` to avoid model quota |
| `cc_workflow_status` | Reads workflow node state, gate details, and decisions |
| `cc_workflow_retry_node` | Invalidates one node and downstream nodes for retry |
| `cc_workflow_stop` | Cancels a workflow and active node runs |
| `cc_workflow_report` | Writes a workflow report with decision trail |
| `cc_handoff_template` | Returns a role-specific handoff schema and example |
| `cc_handoff_validate` | Validates a run `handoff.json` |
| `cc_handoff_read` | Reads a run `handoff.json` |
| `cc_handoff_repair_prompt` | Builds a prompt for missing handoff fields |
| `cc_write_claude_md` | Writes project instructions for Claude Code workers |
| `cc_score_models` | Scores models discovered from CCSwitch |
| `cc_write_strategy_reports` | Writes model score and strategy reports |

Workflow MCP tools scope workflow files to `cwd` or its managed `.agent-workspace`; when `cwd` is omitted, the MCP server's current project directory is used.

## Safe defaults

By default, worker runs use plan mode.

Pass `allow_write=true` only after Codex has decided that file edits are needed and the write scope is clear.

Secrets are redacted from tool output and persisted logs, but prompts should still avoid asking for raw secrets.

The supported MCP deployment is local, same-user `stdio` only. `cc_mock_stream_test` is a diagnostic surface backed by an internal fake runtime; never expose it through SSE/HTTP or a proxy, and exclude it from any remotely reachable tool allowlist.

The MCP server does not register `cc_mock_stream_test` by default. For a temporary local diagnostic session only, set `CC_ORCHESTRATOR_ENABLE_LOCAL_DIAGNOSTICS=1` in that server process and restart it; remove the variable after the test.

## Smoke test

After restarting Codex, call:

```text
cc_healthcheck
cc_list_profiles
cc_score_models
cc_workspace_status
```

If these work, Codex can route workers through MCP.
