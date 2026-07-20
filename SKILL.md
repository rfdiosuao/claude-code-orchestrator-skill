---
name: claude-code-orchestrator
description: Control Claude Code as an external sub-agent through the local cc-orchestrator MCP/CLI and CCSwitch profiles, with .agent-workspace governance for logs, reports, dashboards, archives, rollback notes, templates, policies, and MCP path repair. Use when the user asks Codex to use Claude Code, CCSwitch, external model routing, visible Claude Code windows, ClaudeCode as subagents, MCP control of Claude Code, configurable multi-agent workflows, workspace/status/cleanup/migration/archive of Claude Code run artifacts, repair .mcp.json paths, or folder policies where Codex is the controller and Claude Code agents are workers.
---

# Claude Code Orchestrator

Use this skill when Codex should control Claude Code through the bundled orchestrator. Prefer `$env:CC_ORCHESTRATOR_HOME` when set; otherwise use the installed skill's `scripts/cc-orchestrator` directory or the current workspace's `tools/cc-orchestrator`.

## Operating Model

Codex remains the controller. Claude Code is an external worker launched through the orchestrator. Do not treat Claude Code output as final until Codex has reviewed logs, diffs, and verification results.

Codex owns planning, write-scope decisions, final review, and final response. Claude Code agents only provide role-specific analysis or scoped edits when Codex explicitly enables write access.

Default routing:

- Discover CCSwitch from `$env:CCSWITCH_HOME`, `$env:USERPROFILE\.cc-switch`, or the current user home.
- Discover Claude Code only from recognized guarded installation layouts. Ambient `CLAUDE_CODE_BIN` and inherited `PATH` are not approvals; custom runtimes must be pinned in `runtime_security.override.json`.
- Score every Claude model found in CCSwitch, then choose the best local model for each agent role.

The orchestrator reads CCSwitch profiles in read-only mode and injects provider env vars only into the launched Claude Code process. It should not rewrite CCSwitch global state.

## Reference Files

When deciding how to supervise Claude Code workers, read `references/codex-controller-playbook.md`.

When assigning repeatable worker tasks, read `references/prompt-pack/README.md`, then open only the needed prompt template.

The runtime role configuration still lives in `scripts/cc-orchestrator/config/agents.json`. The prompt pack is controller guidance, not the only routing source.

## Worker Roles

Supported primary roles:

- `requirements`: clarify needs, gaps, plans, constraints, and acceptance criteria.
- `development`: implement scoped code changes when write access is granted.
- `testing`: design or run focused checks, edge cases, and failure-mode tests.
- `review`: review code quality, bugs, maintainability, and release blockers.
- `performance`: inspect slow paths, resource use, blocking IO, and measurable optimizations.
- `compatibility`: check OS, shell, dependency, version, and install portability.
- `documentation`: improve examples, onboarding, FAQ, and troubleshooting.
- `automation`: design CI/CD, tests, packaging, release, and repeatable scripts.
- `security`: audit secrets, permissions, injection, privacy, and destructive paths.
- `ops`: check deployment, logs, observability, release safety, and rollback.

Legacy/support roles still work: `architecture`, `implementation`, and `multimodal`.

## Preferred Commands

If `$env:CC_ORCHESTRATOR_HOME` is not set, set it to the workspace orchestrator path first:

```powershell
$workspaceTool = Join-Path (Get-Location) "tools\cc-orchestrator"
$installedSkillTool = Join-Path $env:USERPROFILE ".codex\skills\claude-code-orchestrator\scripts\cc-orchestrator"
$env:CC_ORCHESTRATOR_HOME = if (Test-Path $workspaceTool) { $workspaceTool } else { $installedSkillTool }
```

Healthcheck:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" healthcheck
```

Fast self-test for UTF-8 handling and required config files:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" selftest
```

Initialize and inspect the managed agent workspace:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" init-workspace --cwd "PROJECT_PATH"
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" workspace-status --cwd "PROJECT_PATH"
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" folder-policy --cwd "PROJECT_PATH" --apply
```

Move and maintain old agent artifacts safely:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" migrate-data --cwd "PROJECT_PATH"
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" migrate-data --cwd "PROJECT_PATH" --apply
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" clean-workspace --cwd "PROJECT_PATH"
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" archive-runs --cwd "PROJECT_PATH" --older-than-days 30
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" repair-mcp-paths --cwd "PROJECT_PATH" --create --apply
```

`clean-workspace`, `migrate-data`, `archive-runs`, and `repair-mcp-paths` are preview-first unless `--apply` is passed. They manage only agent-generated artifacts under `.agent-workspace/claude-code-orchestrator` plus explicitly requested `CLAUDE.md` or `.mcp.json` updates.

List profiles:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" list-profiles
```

Score local models:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" score-models
```

Write the portable auto-routing policy:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" write-auto-policy
```

Generate score and strategy reports:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" write-reports
```

Create or update a project `CLAUDE.md` for Claude Code sub-agents:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" write-claude-md --cwd "PROJECT_PATH" --role development
```

If a project already has `CLAUDE.md`, preserve it by default. Use `--append` to add the managed orchestrator section, or `--force` to replace after writing a timestamped backup.

Pick a route without running Claude Code:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" pick --role performance --task-type performance_review
```

Run Claude Code non-interactively:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" run "TASK" --role development
```

Run Claude Code as a streaming background worker:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" run-streaming "TASK" --role review
```

Poll a streaming run:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" poll-run --run-id RUN_ID --mode controller
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" summarize-run --run-id RUN_ID
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" compact-events --run-id RUN_ID
```

List active streaming workers:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" run-status
```

Stop a runaway worker:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" stop-run --run-id RUN_ID --force
```

Spawn a role team:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" spawn-role-team "TASK" --roles requirements,architecture,security,testing
```

Collect and cross-review team output:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" collect-team-results --team-id TEAM_ID
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" cross-review --run-id RUN_ID --run-id RUN_ID
```

Preflight writes and inspect risk:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" preflight-write-scope --cwd PROJECT_PATH --allow src --deny .env --max-diff-lines 800
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" check-write-scope --cwd PROJECT_PATH
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" diff-summary --cwd PROJECT_PATH
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" secret-scan-run --run-id RUN_ID
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" verify-run --run-id RUN_ID --test-command "pytest"
```

Benchmark, calibrate, and guard cost:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" benchmark-model --profile PROFILE --execute
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" benchmark-suite --profile PROFILE
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" calibrate-policy --preference coding=glm-5 --preference multimodal=qwen3.7-plus
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" cost-guard --max-concurrent 4 --max-timeout-seconds 1200 --apply
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" usage-summary --write-report
```

Generate operator artifacts:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" queue-submit "TASK" --role review --priority 100
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" queue-tick --max-concurrent 3
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" queue-status
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" model-registry --refresh
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" local-policy --show
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" score-worker --run-id RUN_ID
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" render-prompt --template bugfix --task "TASK"
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" upgrade-check --apply
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" mock-stream-test
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" dashboard
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" open-run-folder --run-id RUN_ID
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" export-report --run-id RUN_ID
```

For long multi-agent work, split prompts into short role-specific tasks and set a clear timeout. If a run times out, inspect the saved run folder instead of rerunning blindly:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" last-run
```

Open a visible Claude Code window:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" run-visible "TASK" --role review
```

Inspect last run:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" last-run
```

Inspect diff after write-enabled work:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" diff --cwd "PROJECT_PATH"
```

## Safety Rules

- Default to read-only/plan mode.
- Never add `--allow-unsafe-runtime` or MCP `allow_unsafe_runtime=true` on the user's behalf. A custom runtime requires both a matching local recursive identity pin and explicit approval for that one request.
- Treat `runtime_identity_changed`, `process_identity_mismatch`, and `process_identity_unverified` as controller stop conditions. Surface the structured error to the user; do not downgrade to PID-only signaling, and do not claim that `--force` bypasses identity verification.
- Immediate prompts travel through the guarded stdin channel and must not be reconstructed in argv, `prompt.txt`, metadata, logs, or audit events. Queued unsafe retries require a new single-use grant.
- Treat the installed `config/runtime_security.override.json` and each project's audit set as different ownership domains. Upgrades preserve the override; they must not copy, rotate, or recreate `<artifact_root>/config/runtime_security.audit.key`.
- Before accepting a custom-runtime run, require healthy security audit status. `local_unsafe` fails closed when audit is unavailable; trusted-default degraded operation must remain explicitly marked and reviewed.
- Treat production guarded worker execution as Windows-only in v0.8.0. On macOS or Linux, surface `runtime_containment_unavailable`; never reinterpret the test-only mock process group as production containment.
- Use `--allow-write` only for scoped implementation tasks after Codex has identified the write set.
- Never print or persist raw API keys. The orchestrator redacts secrets, but still avoid requesting secrets in prompts.
- After any write-enabled Claude Code run, inspect diffs and run verification before reporting success.
- After any write-enabled run, call `check-write-scope` or `verify-run`. If `write_scope.status=blocked`, do not accept the run; inspect the rollback recommendation.
- If the user wants to watch Claude Code work, use `run-visible`.
- Windows Chinese output is handled with UTF-8 stdio and child-process UTF-8 env. If a host still renders text strangely, rely on the UTF-8 files under `.agent-workspace/claude-code-orchestrator/runs/<run_id>/`.
- Timeout output is preserved when the subprocess exposes partial stdout/stderr; use `last-run` to recover the tails.
- For live control, prefer `run-streaming`: it uses Claude Code `stream-json`, writes `events.ndjson`, and enables `poll-run`, `run-status`, and `stop-run`.
- For noisy or uncertain workers, set output budgets with `--max-output-bytes`, `--max-events-bytes`, `--kill-on-excessive-output`, or `--final-only`.
- Treat `spawn-role-team` as transactional: if capacity is blocked or partial launch rollback occurs, inspect `runs`, `rollback`, and the team manifest before continuing.
- `send-instruction` preserves the previous profile/model by default. Reroute only when Codex intentionally wants a new route.
- For controller polling, prefer `poll-run --mode controller`. Raw `events.ndjson` stays on disk; Codex should usually read compact controller artifacts first.
- Use `controller-report` / `pressure-report` after multi-agent or pressure runs to export acceptance evidence.
- Use `decision-review` before high-impact accept, merge, or release decisions when evidence is thin or risk is nontrivial.
- When Claude Code needs a stable persona, project rules, or role-specific worker behavior, write `CLAUDE.md` first with `write-claude-md` or MCP tool `cc_write_claude_md`, then run the sub-agent from that project cwd.
- Before heavy multi-agent work in a project, run `init-workspace` or MCP `cc_init_workspace`. Keep agent logs, reports, dashboards, archives, rollback notes, templates, policies, and temp files under `.agent-workspace/claude-code-orchestrator`.
- Use `folder-policy` or MCP `cc_folder_policy` to make the boundary explicit: manage agent-generated artifacts only; do not clean, archive, or migrate project source files.

## Four-Phase Workflow

For the user's multi-agent workflow:

1. Codex plans the write scope and asks role workers for focused input.
2. Run or plan requirements, development, testing, review, performance, compatibility, documentation, automation, security, and ops roles as needed.
3. Cross-review conflicts before enabling any scoped write role.
4. Codex reviews logs, diffs, and verification, then gives the final answer.

Use:

```powershell
python "$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py" workflow-plan "TASK"
```

before launching a full workflow.

## MCP Parameter Notes

Use the same role names through MCP:

- `cc_pick_profile`, `cc_run_agent`, `cc_run_streaming_agent`, `cc_run_visible_agent`, and `cc_write_claude_md` accept `role`.
- `cc_run_streaming_agent` starts a background Claude Code worker and writes `events.ndjson`.
- `cc_run_streaming_agent` supports hard output/event budgets and final-only mode.
- `cc_poll_run` defaults to controller mode: status, compact progress, risk flags, changed files, timeline, and attention signals. Use raw mode only when debugging.
- `cc_compact_events` returns compact events plus deduplicated tool-call summaries.
- `cc_poll_run` and `cc_summarize_run` write `progress_summary.json`, `latest_decision.md`, `risk_flags.json`, `changed_files.json`, `tool_timeline.md`, and rolling `checkpoints/checkpoint-###.md`.
- `cc_summarize_run` returns the latest controller summary for one run.
- `cc_stop_run` terminates a specific run id.
- `cc_run_status` lists active workers or returns one run's status.
- `cc_send_instruction` stops and restarts a non-interactive run with recovered context and a new instruction.
- `cc_send_instruction` preserves route by default and reports route drift when rerouted.
- `cc_spawn_role_team` starts multiple role workers transactionally and writes a team manifest.
- `cc_collect_team_results` summarizes team outputs and marks repeated agreements plus explicit conflicts/risks.
- `cc_cross_review` launches second-round reviewer workers over previous outputs.
- `cc_preflight_write_scope` writes allowed/denied paths and max diff rules before write-enabled work.
- `cc_check_write_scope` checks whether run output crossed the write-scope boundaries and blocks acceptance on violations.
- `cc_diff_summary` summarizes changed files, line counts, risk markers, and test need.
- `cc_secret_scan_run` scans run logs/events/diff for leaked credentials.
- `cc_rollback_run` conservatively rolls back when a clean pre-run git snapshot proves it is safe.
- `cc_verify_run` runs diff summary, write-scope check, secret scan, optional tests, and writes a report.
- `cc_benchmark_model` can run a small real benchmark task when `execute=true`.
- `cc_benchmark_suite` can run or plan fixed code/review/security/context/multimodal benchmark tasks.
- `cc_model_registry` refreshes the local model capability database from CCSwitch, benchmark history, and worker quality history.
- `cc_calibrate_policy` persists local model preference notes.
- `cc_local_policy` reads or writes user-owned local routing overrides that upgrades must preserve.
- `cc_score_worker` grades one worker run and records model quality history.
- `cc_prompt_pack` lists or renders reusable worker prompt templates.
- `cc_cost_guard` stores max concurrency and timeout guardrails.
- `cc_usage_summary` estimates daily tokens, duration, failures, and per-model usage from logs.
- `cc_queue_submit`, `cc_queue_tick`, `cc_queue_status`, and `cc_queue_cancel` provide priority queue scheduling with `queued`, `running`, `done`, `failed`, `timed_out`, and `cancelled` states.
- `cc_upgrade_check` records version state while preserving local calibration/cost files.
- `cc_mock_stream_test` uses a fake Claude stream to validate `events.ndjson`, polling, status, and stop without spending model quota.
- `cc_init_workspace` initializes `.agent-workspace`, run/report/dashboard/archive/rollback/log/tmp/template/policy dirs, and optionally `CLAUDE.md`.
- `cc_workspace_status` shows the exact paths where Codex and Claude Code artifacts will be written.
- `cc_migrate_data` previews or moves legacy `runs`, `reports`, and `dashboard` into the managed workspace.
- `cc_clean_workspace` cleans tmp files, non-scaffold empty dirs, and expired run folders; it is dry-run by default.
- `cc_archive_runs` zips selected or old run folders into `archives/`.
- `cc_repair_mcp_paths` repairs `.mcp.json` so MCP uses the managed workspace paths.
- `cc_folder_policy` returns or writes the policy that limits folder management to agent-generated artifacts.
- `cc_dashboard` generates a local HTML worker dashboard.
- `cc_open_run_folder` opens or returns a run log directory.
- `cc_export_report` writes a Markdown report for a run or team.
- `cc_controller_report` and `cc_pressure_report` export controller acceptance and pressure-test reports.
- `cc_decision_review` returns supervisor-style approve/revise/block guidance for Codex controller decisions.
- `role` supports `requirements`, `development`, `testing`, `review`, `performance`, `compatibility`, `documentation`, `automation`, `security`, `supervisor`, `ops`, plus `architecture`, `implementation`, and `multimodal`.
- `task_type` supports `simple`, `normal`, `complex_code`, `development`, `review`, `security_review`, `supervisor`, `performance_review`, `compatibility_review`, `documentation`, `automation`, `architecture`, `multimodal`, and `ops`.
- `cc_workflow_plan` returns `controller: codex`, `worker_roles`, and one route per configured role.
- `cc_score_models` returns `role_scores` for all configured roles.
- `cc_write_claude_md` embeds the selected role prompt and states that Codex is the controller.

