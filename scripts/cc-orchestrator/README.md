# Claude Code Orchestrator MCP

Local MCP server that lets Codex control Claude Code through CCSwitch profiles.

The server discovers CCSwitch from environment variables and the current user home, reads the CCSwitch database as a model/profile registry, chooses a profile/model from configurable routing rules, injects the selected provider environment into a single `claude` subprocess, and stores runtime artifacts under `.agent-workspace/claude-code-orchestrator/`.

## Tools

- `cc_healthcheck` checks `claude.exe`, CCSwitch files, Python imports, and config.
- `cc_list_profiles` lists Claude profiles from CCSwitch with secrets redacted.
- `cc_pick_profile` explains which profile would be selected for a role/task.
- `cc_run_agent` runs Claude Code once with a selected role/profile and records logs.
- `cc_run_streaming_agent` starts Claude Code as a background worker with `stream-json` events.
- `cc_poll_run` polls compact controller progress by default; raw stdout/stderr/event deltas remain available with raw mode.
- `cc_summarize_run` writes controller artifacts such as progress summary, risk flags, changed files, and timeline.
- `cc_compact_events` compacts raw `events.ndjson` into a small timeline for Codex.
- `cc_stop_run` terminates a specific run id.
- `cc_run_status` lists active streaming workers or inspects one run.
- `cc_send_instruction` stops and restarts a run with recovered context and a new instruction.
- `cc_spawn_role_team` starts multiple role workers and writes a team manifest.
- `cc_collect_team_results` summarizes team output, repeated agreements, and conflicts/risks.
- `cc_cross_review` launches second-round reviewer workers over previous outputs.
- `cc_preflight_write_scope` writes allowed/denied path rules before write-enabled work.
- `cc_check_write_scope` blocks acceptance when a run changed files outside the preflight scope.
- `cc_diff_summary` summarizes changed files, line counts, risk markers, and test need.
- `cc_secret_scan_run` scans run output/events/diff for leaked credentials.
- `cc_rollback_run` conservatively rolls back only when a clean git snapshot proves it is safe.
- `cc_verify_run` runs diff summary, write-scope check, secret scan, optional tests, and a report.
- `cc_benchmark_model` plans or runs a small real benchmark task.
- `cc_benchmark_suite` plans or runs fixed code/review/security/context/multimodal benchmarks.
- `cc_model_registry` builds the local model capability database.
- `cc_calibrate_policy` records local model preference notes.
- `cc_local_policy` reads or writes user-owned model routing overrides that upgrades preserve.
- `cc_score_worker` grades one worker run and records model quality history.
- `cc_prompt_pack` lists or renders reusable worker prompt templates.
- `cc_cost_guard` configures max concurrency and timeout guardrails.
- `cc_usage_summary` estimates daily tokens, duration, failure rate, and model usage from logs.
- `cc_queue_submit`, `cc_queue_tick`, `cc_queue_status`, `cc_queue_cancel`, and `cc_queue_policy` provide priority queue scheduling.
- `cc_upgrade_check` records version state while preserving local calibration, overrides, model registry, quality history, queue policy, and cost settings.
- `cc_mock_stream_test` validates streaming/poll/stop/status with a fake Claude stream.
- `cc_init_workspace` initializes `.agent-workspace`, templates, policy files, rollback/log dirs, and optional `CLAUDE.md`.
- `cc_workspace_status` shows where Codex and Claude Code artifacts will be written.
- `cc_migrate_data` previews or moves legacy `runs`, `reports`, and `dashboard` into the managed workspace.
- `cc_clean_workspace` cleans tmp files, non-scaffold empty dirs, and expired run folders; dry-run by default.
- `cc_archive_runs` zips selected or old run folders under `archives/`.
- `cc_repair_mcp_paths` repairs `.mcp.json` workspace/artifact env values.
- `cc_folder_policy` returns or writes the rule that only agent-generated artifacts are managed.
- `cc_dashboard` generates a local HTML worker dashboard.
- `cc_open_run_folder` opens or returns a run log directory.
- `cc_export_report` writes a Markdown report for a run or team.
- `cc_run_visible_agent` opens Claude Code in a visible PowerShell window with the selected profile.
- `cc_last_run` returns the latest run metadata and tail output.
- `cc_git_diff` returns a capped `git diff` for post-run review.
- `cc_workflow_plan` returns the configured four-phase multi-agent role/model plan.
- `cc_workflow_validate`, `cc_workflow_dry_run`, `cc_workflow_run`, `cc_workflow_status`, `cc_workflow_retry_node`, `cc_workflow_stop`, and `cc_workflow_report` provide the first workflow DAG controller layer.
- `cc_handoff_template`, `cc_handoff_validate`, `cc_handoff_read`, and `cc_handoff_repair_prompt` provide machine-verifiable agent handoff contracts.
- `cc_write_claude_md` writes a project `CLAUDE.md` persona/instructions file for Claude Code workers.
- `cc_score_models` scores local CCSwitch models with local heuristics.
- `cc_write_strategy_reports` writes model score and routing reports.

Write access is disabled by default in `config/model_policy.json`. A caller must pass `allow_write=true` to `cc_run_agent`; otherwise the orchestrator uses `--permission-mode plan`.

## Reliability notes

- CLI and MCP JSON output force UTF-8 so Chinese text and symbols do not crash Windows GBK consoles.
- Child Claude Code runs receive UTF-8 Python environment variables, and visible PowerShell sessions set UTF-8 input/output encoding.
- Streaming runs write `events.ndjson` in real time from Claude Code `--output-format stream-json --verbose --include-partial-messages`.
- If a run times out, the orchestrator stores any partial stdout/stderr that Python exposes in `.agent-workspace/claude-code-orchestrator/runs/<run_id>/stdout.txt` and `stderr.txt`.
- Use `stop-run` / `cc_stop_run` for runaway workers. It requires an explicit run id.
- For large multi-agent work, prefer several short role-specific prompts over one broad prompt. Then use `last-run` or `cc_last_run` to inspect saved tails before retrying.

## Run

```powershell
python tools\cc-orchestrator\server.py
```

This workspace includes a root `.mcp.json` that starts the server with:

```json
{
  "claude-code-orchestrator": {
    "command": "python",
    "args": ["tools/cc-orchestrator/server.py"]
  }
}
```

For direct smoke tests:

```powershell
python tools\cc-orchestrator\cc_orchestrator.py healthcheck
python tools\cc-orchestrator\cc_orchestrator.py selftest
python tools\cc-orchestrator\cc_orchestrator.py list-profiles
python tools\cc-orchestrator\cc_orchestrator.py score-models
python tools\cc-orchestrator\cc_orchestrator.py write-auto-policy
python tools\cc-orchestrator\cc_orchestrator.py write-reports
python tools\cc-orchestrator\cc_orchestrator.py init-workspace --cwd .
python tools\cc-orchestrator\cc_orchestrator.py workspace-status --cwd .
python tools\cc-orchestrator\cc_orchestrator.py migrate-data --cwd .
python tools\cc-orchestrator\cc_orchestrator.py clean-workspace --cwd .
python tools\cc-orchestrator\cc_orchestrator.py archive-runs --cwd . --older-than-days 30
python tools\cc-orchestrator\cc_orchestrator.py repair-mcp-paths --cwd . --create
python tools\cc-orchestrator\cc_orchestrator.py folder-policy --cwd . --apply
python tools\cc-orchestrator\cc_orchestrator.py write-claude-md --cwd . --role implementation
python tools\cc-orchestrator\cc_orchestrator.py pick --role implementation --task-type complex_code
python tools\cc-orchestrator\cc_orchestrator.py workflow-plan "Fix the bug"
python tools\cc-orchestrator\cc_orchestrator.py workflow-validate --file examples\workflows\safe-refactor.yaml
python tools\cc-orchestrator\cc_orchestrator.py workflow-dry-run --file examples\workflows\safe-refactor.yaml --task "Fix the bug"
python tools\cc-orchestrator\cc_orchestrator.py workflow-run --file examples\workflows\safe-refactor.yaml --task "Fix the bug" --mock
python tools\cc-orchestrator\cc_orchestrator.py workflow-status --workflow-id WF_ID
python tools\cc-orchestrator\cc_orchestrator.py workflow-report --workflow-id WF_ID
python tools\cc-orchestrator\cc_orchestrator.py handoff-template --role testing
python tools\cc-orchestrator\cc_orchestrator.py handoff-validate --run-id RUN_ID
python tools\cc-orchestrator\cc_orchestrator.py run-streaming "Review this project" --role review
python tools\cc-orchestrator\cc_orchestrator.py run-status
python tools\cc-orchestrator\cc_orchestrator.py poll-run --run-id RUN_ID
python tools\cc-orchestrator\cc_orchestrator.py summarize-run --run-id RUN_ID
python tools\cc-orchestrator\cc_orchestrator.py compact-events --run-id RUN_ID
python tools\cc-orchestrator\cc_orchestrator.py stop-run --run-id RUN_ID --force
python tools\cc-orchestrator\cc_orchestrator.py spawn-role-team "Audit this project" --roles requirements,architecture,security,testing
python tools\cc-orchestrator\cc_orchestrator.py collect-team-results --team-id TEAM_ID
python tools\cc-orchestrator\cc_orchestrator.py mock-stream-test
python tools\cc-orchestrator\cc_orchestrator.py check-write-scope --cwd .
python tools\cc-orchestrator\cc_orchestrator.py verify-run --run-id RUN_ID --test-command "pytest"
python tools\cc-orchestrator\cc_orchestrator.py diff-summary --cwd .
python tools\cc-orchestrator\cc_orchestrator.py secret-scan-run --run-id RUN_ID
python tools\cc-orchestrator\cc_orchestrator.py benchmark-suite
python tools\cc-orchestrator\cc_orchestrator.py usage-summary --write-report
python tools\cc-orchestrator\cc_orchestrator.py queue-submit "Review this project" --role review --priority 100
python tools\cc-orchestrator\cc_orchestrator.py queue-tick --max-concurrent 3
python tools\cc-orchestrator\cc_orchestrator.py queue-policy --max-concurrent 3 --apply
python tools\cc-orchestrator\cc_orchestrator.py model-registry --refresh --apply
python tools\cc-orchestrator\cc_orchestrator.py prompt-pack --list
python tools\cc-orchestrator\cc_orchestrator.py upgrade-check --apply
python tools\cc-orchestrator\cc_orchestrator.py dashboard
python tools\cc-orchestrator\cc_orchestrator.py run-visible "Inspect this project" --role architecture
```

## Configuration

- `config/model_policy.json` controls aliases, task routes, role defaults, timeout limits, and write defaults. The default policy uses `auto:*` aliases so each machine routes to models present in its own CCSwitch database.
- `config/agents.json` controls role prompts.
- CCSwitch remains the source of provider URLs, tokens, and model names.

To add a stronger model later, add or update the provider in CCSwitch, then rerun `score-models`, `write-auto-policy`, and `write-reports`.

## Guarded runtime operations

### Platform support

Production guarded worker execution is currently Windows-only in v0.8.0 because Windows Job Objects provide the required kernel-enforced whole-process-tree containment. macOS and Linux remain supported for installation, configuration, reports, and contract checks, but every production worker launch fails closed with `runtime_containment_unavailable`. The process-group mechanism used by `mock-stream-test` is an explicit test fixture and must never be treated as production containment.

The MCP server is supported only as a local, same-user `stdio` process. `cc_mock_stream_test` must not be exposed through SSE/HTTP or a proxy; exclude it from any remotely reachable tool allowlist. It is not registered by default and requires `CC_ORCHESTRATOR_ENABLE_LOCAL_DIAGNOSTICS=1` in a temporary local MCP server process.

Recognized Claude Code installations use the `trusted_default` path and need no new configuration. Ambient `CLAUDE_CODE_BIN` and inherited `PATH` values are not runtime approvals. A custom executable must be an absolute path in `config/runtime_security.override.json`, have a complete recursive identity pin, and receive a separate approval on every request.

Generate a policy candidate locally, review it, and then place the reviewed JSON at `config/runtime_security.override.json`:

```powershell
$env:RUNTIME_EXE = "C:\absolute\path\to\claude.exe"
@'
import json, os
from runtime_security import ExecutableIdentity

def pin(identity):
    return {
        "canonical_path": identity.canonical_path,
        "sha256": identity.sha256,
        "size": identity.size,
        "file_id": None if identity.file_id is None else list(identity.file_id),
        "target_kind": identity.target_kind,
        "interpreter_identity": None if identity.interpreter_identity is None else pin(identity.interpreter_identity),
    }

identity = ExecutableIdentity.capture(os.environ["RUNTIME_EXE"])
print(json.dumps({
    "schema_version": 1,
    "runtime_executable": identity.canonical_path,
    "extra_provider_env_keys": [],
    "unsafe_runtimes": [{"runtime_id": "reviewed-local-runtime", "identity": pin(identity)}],
}, indent=2))
'@ | python -
```

Recreate and review the full pin after any executable, wrapper, or interpreter update. Do not copy only the digest: `canonical_path`, `sha256`, `size`, `file_id`, `target_kind`, and the recursive `interpreter_identity` are all part of the approval.

The policy alone is insufficient. For a reviewed request, add `--allow-unsafe-runtime` to the selected CLI command or set MCP `allow_unsafe_runtime=true`. This flag is request-scoped; controllers must never infer or add it automatically. Queue grants are protected, bound to the queued authorization, and consumed once. A retry or follow-up that needs the custom runtime requires a new grant.

### Security errors

| Code | Operator action |
| --- | --- |
| `provider_env_invalid` | Correct malformed or duplicate provider entries. |
| `provider_env_forbidden` | Remove process-control, loader, shell, Git-config, path, or orchestrator variables. They cannot be allowlisted. |
| `provider_env_unrecognized` | Remove the key or explicitly add a non-forbidden vendor key to `extra_provider_env_keys`. |
| `provider_env_too_large` | Reduce the value or total provider environment size. |
| `runtime_policy_invalid` | Correct the exact schema and absolute paths; never weaken the parser. |
| `runtime_candidate_unrecognized` | Install Claude Code in a recognized layout or pin the custom executable. |
| `unsafe_runtime_request_invalid` | Send a literal boolean approval through the supported CLI/MCP surface. |
| `runtime_not_trusted` | Review the candidate; do not retry with approval until a matching local pin exists. |
| `unsafe_runtime_policy_missing` | Add and review the local identity pin before requesting unsafe use. |
| `unsafe_runtime_request_missing` | Obtain user approval for this request, then resubmit it with the request flag. |
| `runtime_identity_changed` | Stop, recapture the complete identity chain, investigate the change, and update the pin only after review. |
| `runtime_containment_unavailable` | Use a platform/backend that can prove ownership and contain the process tree. |
| `process_identity_mismatch` | Do not signal the PID; inspect the recorded identity and clean up the owned process manually. |
| `process_identity_unverified` | Do not signal the PID; use supported identity capture or perform manual process cleanup. |
| `secure_payload_store_unavailable` | Restore the OS-protected payload store before retrying prompt or queue work. |
| `visible_runtime_unsupported` | Use `run-streaming` and `poll-run` instead of an unguarded visible launch. |
| `runtime_policy_drift` | Submit a new queue job under the current policy; do not reuse the stale authorization. |
| `security_audit_unavailable` | Restore the last known-good private audit set before another custom-runtime launch. |
| `trusted_runtime_authorized` | Informational; no operator action is required. |
| `unsafe_runtime_authorized` | Monitor the run and keep final acceptance pending controller review. |

Public `security_error` responses can also report bounded launch or operation failures. Follow their `next_step`, inspect the run metadata, and retry only after confirming cleanup. Never turn a timeout, identity failure, or audit failure into a raw PID kill.

### Stop, prompt, and audit rules

`stop-run --force` accelerates cleanup only after process identity has been verified; it does not bypass identity checks. Legacy PID-only metadata, missing launch nonces, mismatches, and unsupported capability states return `stopped=false`. Surface that result to the user and perform any necessary manual cleanup outside the orchestrator.

Immediate task/context text is delivered after spawn through an anonymous stdin pipe. It is not placed in argv, `prompt.txt`, runtime metadata, or the security audit. Queued text stays in the OS-protected payload store and is removed according to the queue transaction rather than copied into queue metadata.

The project audit set is separate from the installed Skill:

- `<artifact_root>/config/runtime_security.audit.key` is the 32-byte private HMAC key.
- `<artifact_root>/logs/security-events.ndjson` is the append-only local hash chain.
- `<artifact_root>/logs/security-events.checkpoint.json` authenticates event count, tail hash, and byte length.
- Lock and failure-marker material under `<artifact_root>/config` and the sibling bootstrap directory records cross-process failures.

Events are allowlisted and secret-free: schema/timestamp, code/severity, run/runtime/trust identifiers, provider pseudonym, policy decision and dedupe identifiers, safe field names, recommended action, predecessor hash, and record hash. Values from prompts, credentials, provider endpoints, and arbitrary details are not stored. The per-event limit is 16 KiB; the log limit is 32 MiB, and health becomes unhealthy before less than one maximum-size event remains.

There is no automatic rotation or repair. When capacity is low or verification fails, stop writers and preserve the key, log, checkpoint, lock, and applicable failure markers as one private evidence set. Restore only a matching known-good set, or switch the project to a fresh artifact root after archiving the old set. Never delete/rekey one component in place. Audit failure blocks `local_unsafe`; a trusted-default launch may continue only with explicit `audit_degraded` status. Code rollback must preserve the installed override and all project audit material.

For operations, alert externally at 70% audit capacity and pause new `local_unsafe` work at 85%; the built-in hard gate is reserved for the final 16 KiB. During upgrade, stop concurrent installer runs and record the timestamped backup path. If installation or verification fails, the previous tree remains in that backup even if the active target is incomplete.

Do not run a pre-0.8.0 installer to roll back: older installers do not know how to restore `runtime_security.override.json`. Either restore the complete pre-upgrade backup, or extract the old tag and replace versioned files while explicitly excluding the override. Preserve and hash the override before and after rollback. Do not roll back or clean the project artifact root; archive its key, log, checkpoint, lock, failure markers, and sibling bootstrap failure directory together with their permissions. If the old code lacks guarded custom-runtime support, disable custom/unsafe runtimes after rollback and use only a recognized trusted default.
