# FAQ

## Is this a replacement for Codex?

No.

Codex remains the controller. Claude Code is an external worker.

## Does it edit files by default?

No.

The default permission mode is plan mode. Use `allow_write=true` or `--allow-write` only for scoped implementation work.

## Does it change my global CCSwitch profile?

No.

The orchestrator reads CCSwitch profiles and injects provider environment variables into a single Claude Code subprocess.

## Why do I need multiple models in CCSwitch?

Because one model is rarely best for every role.

A fast model may be good for quick checks. A stronger reasoning model may be better for review or architecture. A code-focused model may be better for implementation.

## Are model scores real benchmarks?

No.

They are local heuristics based on model names and public capability signals. Use them as routing hints, not truth.

## What should I do when `healthcheck` fails?

Check these in order:

1. Python 3.10 or newer is available.
2. `claude` is on PATH, or `CLAUDE_CODE_BIN` is set.
3. CCSwitch is installed.
4. CCSwitch has Claude-compatible profiles.
5. `CC_ORCHESTRATOR_HOME` points to `scripts/cc-orchestrator`.

## How do I watch a worker run?

Use a visible worker:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" run-visible "Inspect this project" --role architecture
```

Then inspect the latest run:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" last-run
```

## Where are logs stored?

Under:

```text
.agent-workspace/claude-code-orchestrator/runs/<run_id>/
```

Each run can include `metadata.json`, `stdout.txt`, `stderr.txt`, and guarded controller artifacts. Immediate prompt/context text is delivered over stdin and is not persisted as `prompt.txt`.

## How do I keep agent files tidy?

Start with:

```bash
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd /path/to/project
python "$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" clean-workspace --cwd /path/to/project
```

`clean-workspace` is dry-run by default. It only manages agent-generated artifacts under `.agent-workspace/claude-code-orchestrator`.

## Why does Windows output look strange sometimes?

The orchestrator forces UTF-8 for Python and child processes, but some host consoles still render text oddly.

When that happens, trust the UTF-8 files in the run folder.

## How does GitHub Pages deployment work?

The workflow at `.github/workflows/deploy-docs.yml` runs:

```bash
npm ci
npm run docs:build
```

Then it uploads:

```text
docs-site/.vitepress/dist
```

The VitePress `base` is set automatically from `GITHUB_REPOSITORY` during GitHub Actions. You can override it with `DOCS_BASE`.
