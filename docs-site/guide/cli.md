# CLI reference

The CLI is `cc_orchestrator.py`.

Set `CC_ORCHESTRATOR_HOME` first:

```bash
export CC_ORCHESTRATOR_HOME="$HOME/.codex/skills/claude-code-orchestrator/scripts/cc-orchestrator"
```

Windows PowerShell:

```powershell
$env:CC_ORCHESTRATOR_HOME = "$env:USERPROFILE\.codex\skills\claude-code-orchestrator\scripts\cc-orchestrator"
```

## Health and discovery

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" selftest
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" healthcheck
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" list-profiles
```

Use these before running workers.

## Workspace governance

Initialize the managed artifact workspace:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" folder-policy --cwd /path/to/project --apply
```

Maintain old or noisy artifacts:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" migrate-data --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" clean-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" archive-runs --cwd /path/to/project --older-than-days 30
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" repair-mcp-paths --cwd /path/to/project --create
```

These commands manage agent-generated artifacts only. Destructive or path-changing actions are preview-first unless `--apply` is passed.

## Routing

Pick a route without launching Claude Code:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" pick --role implementation --task-type complex_code
```

Build a full workflow plan:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-plan "Refactor this project safely"
```

Validate and dry-run a reusable workflow DAG:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-validate --file examples/workflows/safe-refactor.yaml --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-dry-run --file examples/workflows/safe-refactor.yaml --task "Refactor module X" --cwd /path/to/project
```

When `--cwd` is set, the workflow file must live inside that project or its managed `.agent-workspace`.

Run the workflow controller in mock mode before spending model quota:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-run --file examples/workflows/safe-refactor.yaml --task "Refactor module X" --cwd /path/to/project --mock
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-status --workflow-id WF_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workflow-report --workflow-id WF_ID
```

Use structured handoff contracts:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-template --role testing
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-validate --run-id RUN_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-read --run-id RUN_ID
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" handoff-repair-prompt --run-id RUN_ID
```

## Model scoring and reports

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" score-models
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" write-auto-policy
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" write-reports
```

`write-auto-policy` updates routing aliases so local models are selected by role.

`write-reports` writes model score and strategy reports under `.agent-workspace/claude-code-orchestrator/reports`.

## Run workers

Run a read-only architecture worker:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run "Map this repository architecture" --role architecture
```

Run a scoped write-capable implementation worker:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run "Fix the failing test in src/foo.py" --role implementation --allow-write --cwd /path/to/project
```

Open a visible Claude Code window:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-visible "Inspect this project" --role architecture
```

## Review runs

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" last-run
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" diff --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" verify-run --run-id <run_id> --test-command "npm test"
```

Runs are stored under:

```text
.agent-workspace/claude-code-orchestrator/runs/<run_id>/
  metadata.json
  stdout.txt
  stderr.txt
```

Immediate prompt/context text is sent over guarded stdin and is not persisted in the run directory.

On Windows, tail stdout:

```powershell
Get-Content ".agent-workspace\claude-code-orchestrator\runs\<run_id>\stdout.txt" -Wait
```

On macOS or Linux:

```bash
tail -f ".agent-workspace/claude-code-orchestrator/runs/<run_id>/stdout.txt"
```

## Live control

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

`poll-run` defaults to controller mode. It returns compact progress, risk flags, changed files, a timeline, deduplicated tool-call summary, and rolling checkpoint paths instead of dumping raw events.

`mock-stream-test` uses a fake Claude stream, so it checks `events.ndjson`, polling, status, and stop without spending model quota.

`run-streaming` can enforce output budgets. Use `--final-only` for noisy tasks and `--kill-on-excessive-output` when a runaway worker should be stopped.

## Write scope and acceptance

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" preflight-write-scope --cwd /path/to/project --allow src --deny .env --max-diff-lines 800
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" check-write-scope --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" verify-run --run-id <run_id> --test-command "pytest"
```

If write scope is blocked, Codex should not accept the worker result.

## Queue, usage, and upgrades

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" queue-submit "Review this repo" --role review --priority 100
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" queue-tick --max-concurrent 3
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" queue-status
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" queue-policy --max-concurrent 3 --default-timeout-seconds 900 --apply
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" model-registry --refresh --apply
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" local-policy --preference development=GLM5.2 --preference multimodal=qwen3.7-plus --apply
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" score-worker --run-id <run_id>
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" prompt-pack --list
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" render-prompt --template repo-audit --task "Audit install safety"
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" usage-summary --write-report
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" benchmark-suite
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" upgrade-check --apply
```

Queue jobs use `queued`, `running`, `done`, `failed`, `timed_out`, and `cancelled` states.
