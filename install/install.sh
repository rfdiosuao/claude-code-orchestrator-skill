#!/usr/bin/env bash
set -euo pipefail

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="$CODEX_HOME/skills"
TARGET="$TARGET_ROOT/claude-code-orchestrator"
BACKUP="$TARGET.backup.$(date +%Y%m%d-%H%M%S)"

mkdir -p "$TARGET_ROOT"

if [ -e "$TARGET" ]; then
  mv "$TARGET" "$BACKUP"
  echo "Backed up existing skill to $BACKUP"
fi

mkdir -p "$TARGET"
rsync -a \
  --exclude '.git' \
  --exclude 'runs' \
  --exclude 'reports' \
  --exclude 'dashboard' \
  --exclude '.agent-workspace' \
  --exclude 'node_modules' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude 'model_calibration.json' \
  --exclude 'model_registry.json' \
  --exclude 'model_benchmark_history.json' \
  --exclude 'local_policy.override.json' \
  --exclude 'runtime_security.override.json' \
  --exclude 'runtime_security.audit.key' \
  --exclude 'worker_quality_history.json' \
  --exclude 'cost_guard.json' \
  --exclude 'queue_policy.json' \
  --exclude 'version_state.json' \
  --exclude 'queue.json' \
  "$REPO_ROOT/" "$TARGET/"

for relative in \
  "scripts/cc-orchestrator/config/model_calibration.json" \
  "scripts/cc-orchestrator/config/model_registry.json" \
  "scripts/cc-orchestrator/config/model_benchmark_history.json" \
  "scripts/cc-orchestrator/config/local_policy.override.json" \
  "scripts/cc-orchestrator/config/runtime_security.override.json" \
  "scripts/cc-orchestrator/config/worker_quality_history.json" \
  "scripts/cc-orchestrator/config/cost_guard.json" \
  "scripts/cc-orchestrator/config/queue_policy.json" \
  "scripts/cc-orchestrator/config/version_state.json"; do
  if [ -f "$BACKUP/$relative" ]; then
    mkdir -p "$(dirname "$TARGET/$relative")"
    cp "$BACKUP/$relative" "$TARGET/$relative"
    cmp -s "$BACKUP/$relative" "$TARGET/$relative" || {
      echo "Preserved local config failed verification: $relative" >&2
      exit 1
    }
    echo "Preserved local config: $relative"
  fi
done

TOOL_HOME="$TARGET/scripts/cc-orchestrator"

cat <<EOF

Claude Code Orchestrator Skill installed.
Skill path: $TARGET

Run:
  export CC_ORCHESTRATOR_HOME="$TOOL_HOME"
  python "\$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" selftest
  python "\$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" healthcheck
  python "\$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" init-workspace --cwd .
  python "\$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" workspace-status --cwd .
  python "\$CC_ORCHESTRATOR_HOME/cc_orchestrator.py" upgrade-check --apply

For MCP auto-registration on Windows, run install/install-mcp.ps1.
On macOS/Linux, add docs/mcp.codex.example.toml to your Codex config.toml.
EOF
