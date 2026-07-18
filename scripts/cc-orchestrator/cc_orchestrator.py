#!/usr/bin/env python3
"""Claude Code orchestration helpers backed by CCSwitch profiles."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import html as html_lib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def configure_stdio() -> None:
    """Keep JSON output readable on Windows consoles with non-ASCII text."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def force_utf8_env(env: dict[str, str]) -> dict[str, str]:
    """Make child Python/Node tools prefer UTF-8 without overwriting user choices."""
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    if os.name != "nt":
        env.setdefault("LANG", "C.UTF-8")
        env.setdefault("LC_ALL", "C.UTF-8")
    return env


def subprocess_text(value: Any) -> str:
    """Normalize subprocess output, including TimeoutExpired bytes payloads."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


configure_stdio()


ROOT = Path(__file__).resolve().parent


def _has_skill_assets(candidate: Path) -> bool:
    return (candidate / "version.json").exists() or (candidate / "references" / "prompt-pack").exists()


def resolve_skill_root(root: Path) -> Path:
    explicit = os.environ.get("CC_ORCHESTRATOR_SKILL_ROOT")
    if explicit:
        return Path(explicit).expanduser().resolve()

    candidates = [root.parent.parent, root, root.parent]
    seen: set[Path] = set()
    unique_candidates: list[Path] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_candidates.append(resolved)

    for candidate in unique_candidates:
        if (candidate / "version.json").exists() and (candidate / "references" / "prompt-pack").exists():
            return candidate
    for candidate in unique_candidates:
        if _has_skill_assets(candidate):
            return candidate
    return root.parent.parent.resolve()


SKILL_ROOT = resolve_skill_root(ROOT)
CONFIG_DIR = ROOT / "config"
AGENT_WORKSPACE_DIRNAME = ".agent-workspace"
ARTIFACT_NAMESPACE = "claude-code-orchestrator"


def resolve_workspace_root(cwd: str | Path | None = None) -> Path:
    explicit = os.environ.get("CC_ORCHESTRATOR_WORKSPACE_ROOT") or os.environ.get("CC_ORCHESTRATOR_WORKSPACE")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path(cwd or os.getcwd()).expanduser().resolve()


def resolve_artifact_root(cwd: str | Path | None = None) -> Path:
    explicit = os.environ.get("CC_ORCHESTRATOR_ARTIFACT_ROOT")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return resolve_workspace_root(cwd) / AGENT_WORKSPACE_DIRNAME / ARTIFACT_NAMESPACE


WORKSPACE_ROOT = resolve_workspace_root()
ARTIFACT_ROOT = resolve_artifact_root(WORKSPACE_ROOT)
RUNS_DIR = ARTIFACT_ROOT / "runs"
TEAMS_DIR = RUNS_DIR / "teams"
RUN_INDEX_DIR = RUNS_DIR / "index"
WORKFLOWS_DIR = ARTIFACT_ROOT / "workflows"
WORKFLOW_INDEX_DIR = WORKFLOWS_DIR / "index"
REPORTS_DIR = ARTIFACT_ROOT / "reports"
DASHBOARD_DIR = ARTIFACT_ROOT / "dashboard"
LEGACY_RUNS_DIR = ROOT / "runs"
LEGACY_REPORTS_DIR = ROOT / "reports"
LEGACY_DASHBOARD_DIR = ROOT / "dashboard"
REFERENCES_DIR = SKILL_ROOT / "references"
PROMPT_PACK_DIR = REFERENCES_DIR / "prompt-pack"
VERSION_PATH = SKILL_ROOT / "version.json"
POLICY_PATH = CONFIG_DIR / "model_policy.json"
AGENTS_PATH = CONFIG_DIR / "agents.json"
CALIBRATION_PATH = CONFIG_DIR / "model_calibration.json"
COST_GUARD_PATH = CONFIG_DIR / "cost_guard.json"
VERSION_STATE_PATH = CONFIG_DIR / "version_state.json"
MODEL_REGISTRY_PATH = CONFIG_DIR / "model_registry.json"
MODEL_BENCHMARK_HISTORY_PATH = CONFIG_DIR / "model_benchmark_history.json"
LOCAL_POLICY_OVERRIDE_PATH = CONFIG_DIR / "local_policy.override.json"
WORKER_QUALITY_HISTORY_PATH = CONFIG_DIR / "worker_quality_history.json"
QUEUE_POLICY_PATH = CONFIG_DIR / "queue_policy.json"
QUEUE_PATH = RUNS_DIR / "queue.json"
CLAUDE_MD_MARKER_BEGIN = "<!-- claude-code-orchestrator:begin -->"
CLAUDE_MD_MARKER_END = "<!-- claude-code-orchestrator:end -->"
SECRET_KEY_RE = re.compile(r"(key|token|secret|authorization|auth)", re.IGNORECASE)
TOKEN_USAGE_KEYS = {
    "inputtokens",
    "outputtokens",
    "totaltokens",
    "actualinputtokens",
    "actualoutputtokens",
    "actualtotaltokens",
    "inputtokensest",
    "outputtokensest",
    "totaltokensest",
    "thinkingtokens",
    "maxoutputtokens",
    "cachereadinputtokens",
    "cachecreationinputtokens",
}
MODEL_USAGE_ALLOWED_KEYS = TOKEN_USAGE_KEYS | {
    "costusd",
    "cost",
    "contextwindow",
    "websearchrequests",
}
SECRET_VALUE_RE = re.compile(
    r"("
    r"sk-[A-Za-z0-9_\-]{8,}|"
    r"ghp_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"npm_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_\-]{35}|"
    r"Bearer\s+[A-Za-z0-9._~+/=\-]{20,}|"
    r"[A-Za-z0-9]{20,}\.[A-Za-z0-9_\-]{8,}|"
    r"-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----"
    r")",
    re.IGNORECASE,
)
SECRET_ASSIGN_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|authorization|auth)\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=\-]{16,})"
)
SECRET_NAME_RE = re.compile(r"(?i)\b(?:[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|SECRET|PASSWORD)[A-Z0-9_]*|authorization)\b")
PLACEHOLDER_SECRET_RE = re.compile(
    r"(?i)(example|placeholder|dummy|fake|test|mock|sample|your[_-]?|replace[_-]?me|changeme|xxx|xxxx|<[^>]+>|\$\{[^}]+})"
)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
TEAM_ID_RE = re.compile(r"^team-\d{8}T\d{6}Z-[0-9a-f]{8}$")
QUEUE_JOB_ID_RE = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
WORKFLOW_ID_RE = re.compile(r"^wf-\d{8}T\d{6}Z-[0-9a-f]{8}$")
PASSTHROUGH_ENV_KEYS = {
    "PATH",
    "Path",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "CLAUDE_CODE_BIN",
    "CC_ORCHESTRATOR_WORKSPACE_ROOT",
    "CC_ORCHESTRATOR_ARTIFACT_ROOT",
    "CC_ORCHESTRATOR_FAKE_STEPS",
    "CC_ORCHESTRATOR_FAKE_DELAY",
    "CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SHELL",
    "TERM",
}
MODEL_ENV_KEYS = (
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)
ROLE_ORDER = [
    "requirements",
    "architecture",
    "development",
    "testing",
    "review",
    "performance",
    "compatibility",
    "documentation",
    "automation",
    "security",
    "supervisor",
    "implementation",
    "ops",
    "multimodal",
]
SCORE_KEYS = ("code", "long_context", "reasoning", "speed", "stability", "cost", "tool_use", "multimodal")
ROLE_SCORE_WEIGHTS: dict[str, dict[str, float]] = {
    "requirements": {"reasoning": 0.20, "long_context": 0.20, "tool_use": 0.15, "stability": 0.15, "speed": 0.15, "code": 0.10, "cost": 0.05},
    "architecture": {"reasoning": 0.30, "code": 0.25, "long_context": 0.20, "tool_use": 0.15, "stability": 0.10},
    "development": {"code": 0.35, "reasoning": 0.25, "tool_use": 0.20, "long_context": 0.10, "stability": 0.10},
    "security": {"reasoning": 0.35, "code": 0.20, "long_context": 0.20, "stability": 0.15, "tool_use": 0.10},
    "testing": {"code": 0.25, "tool_use": 0.25, "stability": 0.20, "speed": 0.15, "reasoning": 0.10, "cost": 0.05},
    "implementation": {"code": 0.35, "reasoning": 0.25, "tool_use": 0.20, "long_context": 0.10, "stability": 0.10},
    "review": {"reasoning": 0.30, "code": 0.25, "long_context": 0.20, "stability": 0.15, "tool_use": 0.10},
    "performance": {"speed": 0.25, "code": 0.25, "stability": 0.20, "tool_use": 0.15, "reasoning": 0.15},
    "compatibility": {"stability": 0.25, "tool_use": 0.20, "code": 0.20, "long_context": 0.15, "reasoning": 0.15, "cost": 0.05},
    "documentation": {"long_context": 0.25, "reasoning": 0.20, "speed": 0.15, "tool_use": 0.15, "stability": 0.10, "code": 0.10, "cost": 0.05},
    "automation": {"tool_use": 0.25, "code": 0.25, "stability": 0.20, "reasoning": 0.15, "speed": 0.10, "cost": 0.05},
    "supervisor": {"reasoning": 0.35, "long_context": 0.20, "stability": 0.20, "tool_use": 0.15, "code": 0.10},
    "ops": {"stability": 0.25, "tool_use": 0.20, "speed": 0.20, "reasoning": 0.15, "long_context": 0.10, "cost": 0.10},
    "multimodal": {"multimodal": 0.40, "tool_use": 0.20, "reasoning": 0.15, "code": 0.10, "long_context": 0.10, "stability": 0.05},
}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
BLOCKING_SEVERITIES = {"critical", "high"}
OUTPUT_BUDGET_DEFAULTS = {
    "max_output_bytes": 2_000_000,
    "max_events_bytes": 2_000_000,
    "soft_output_bytes": 1_000_000,
    "policy": "stop",
    "final_only": False,
    "final_max_chars": 20000,
}
CONTROLLER_ARTIFACTS = {
    "progress_summary": "progress_summary.json",
    "latest_decision": "latest_decision.md",
    "risk_flags": "risk_flags.json",
    "changed_files": "changed_files.json",
    "tool_timeline": "tool_timeline.md",
}
CHECKPOINT_EVENT_INTERVAL = 10
CHECKPOINT_SECONDS_INTERVAL = 30
FAILURE_PATTERNS = {
    "test_failed": re.compile(r"\b(test|pytest|npm test|pnpm test|vitest|jest).{0,80}\b(fail|failed|error|exit code [1-9])\b", re.IGNORECASE),
    "claimed_success": re.compile(r"\b(success|succeeded|done|completed|all tests pass|tests passed)\b", re.IGNORECASE),
    "permission_risk": re.compile(r"\b(rm -rf|Remove-Item|del /s|format |chmod 777|sudo |Set-ExecutionPolicy)\b", re.IGNORECASE),
    "repeated_search": re.compile(r"\b(rg|grep|findstr|Get-ChildItem|ls|dir)\b", re.IGNORECASE),
}


class OrchestratorError(RuntimeError):
    """Raised for expected orchestration failures with actionable messages."""


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    app_type: str
    settings: dict[str, Any]
    category: str | None
    provider_type: str | None
    is_current: bool
    endpoints: list[str]

    @property
    def model_entries(self) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        seen: set[str] = set()
        for key in MODEL_ENV_KEYS:
            model = self.env.get(key)
            if model and model not in seen:
                entries.append({"name": model, "source": key})
                seen.add(model)
        model = self.settings.get("model")
        if model and str(model) not in seen:
            entries.append({"name": str(model), "source": "settings.model"})
        return entries

    @property
    def models(self) -> list[str]:
        return [item["name"] for item in self.model_entries]

    @property
    def env(self) -> dict[str, str]:
        raw = self.settings.get("env") or {}
        return {str(k): str(v) for k, v in raw.items() if v is not None}

    @property
    def model(self) -> str | None:
        models = self.models
        return models[0] if models else None


def user_home() -> Path:
    return Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or str(Path.home()))


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or (user_home() / ".codex"))


def resolve_ccswitch_home(explicit: str | Path | None = None) -> Path:
    candidates: list[Path] = []
    for value in (explicit, os.environ.get("CCSWITCH_HOME")):
        if value:
            candidates.append(Path(value).expanduser())
    home = user_home()
    candidates.extend(
        [
            home / ".cc-switch",
            Path.home() / ".cc-switch",
            Path(os.environ.get("APPDATA", "")) / "cc-switch",
            Path(os.environ.get("LOCALAPPDATA", "")) / "cc-switch",
        ]
    )
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        if not str(candidate) or str(candidate) in seen:
            continue
        seen.add(str(candidate))
        unique.append(candidate)
        if (candidate / "cc-switch.db").exists():
            return candidate
    return unique[0] if unique else home / ".cc-switch"


def cc_db_path(ccswitch_home: str | Path | None = None) -> Path:
    return resolve_ccswitch_home(ccswitch_home) / "cc-switch.db"


def cc_settings_path(ccswitch_home: str | Path | None = None) -> Path:
    return resolve_ccswitch_home(ccswitch_home) / "settings.json"


def _claude_candidate_rank(path: str) -> tuple[int, str]:
    lower = path.lower()
    if lower.endswith(r"\node_modules\@anthropic-ai\claude-code\bin\claude.exe"):
        return (0, lower)
    suffix = Path(path).suffix.lower()
    ranks = {".exe": 1, ".cmd": 2, ".bat": 3, "": 4, ".ps1": 5}
    return (ranks.get(suffix, 6), lower)


def _existing_claude_candidates() -> list[str]:
    candidates: list[str] = []
    explicit = os.environ.get("CLAUDE_CODE_BIN")
    if explicit:
        resolved = shutil.which(explicit) if not Path(explicit).is_absolute() else explicit
        if resolved and (Path(resolved).exists() or shutil.which(resolved)):
            candidates.append(resolved)
    try:
        proc = subprocess.run(["where.exe", "claude"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        if proc.returncode == 0:
            candidates.extend(line.strip() for line in proc.stdout.splitlines() if line.strip())
    except Exception:
        found = shutil.which("claude")
        if found:
            candidates.append(found)
    home = user_home()
    program_data = Path(os.environ.get("PROGRAMDATA", "")) / "WorkBuddy"
    direct_candidates = [home / ".local" / "bin" / "claude.exe"]
    for path in direct_candidates:
        if path.exists():
            candidates.append(str(path))
    glob_roots = [
        (home, ".workbuddy/binaries/node/versions/*/node_modules/@anthropic-ai/claude-code/bin/claude.exe"),
        (program_data, "chromium-env/*/.workbuddy/binaries/node/versions/*/node_modules/@anthropic-ai/claude-code/bin/claude.exe"),
    ]
    for root, pattern in glob_roots:
        if not str(root) or not root.exists():
            continue
        try:
            candidates.extend(str(path) for path in root.glob(pattern) if path.exists())
        except Exception:
            continue
    seen: set[str] = set()
    existing: list[str] = []
    for candidate in candidates:
        resolved = shutil.which(candidate) if not Path(candidate).is_absolute() else candidate
        if not resolved or resolved in seen:
            continue
        if Path(resolved).exists() or shutil.which(resolved):
            seen.add(resolved)
            existing.append(resolved)
    if explicit and existing:
        return existing[:1] + sorted(existing[1:], key=_claude_candidate_rank)
    return sorted(existing, key=_claude_candidate_rank)


def claude_bin_path() -> str:
    candidates = _existing_claude_candidates()
    return candidates[0] if candidates else "claude"


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise OrchestratorError(f"Missing config file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise OrchestratorError(f"Invalid JSON in {path}: {exc}") from exc


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***REDACTED***" if should_redact_key(str(k), v) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return SECRET_VALUE_RE.sub(lambda match: match.group(0)[:6] + "..." + match.group(0)[-4:], value)
    return value


def is_number_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return re.fullmatch(r"\d+(?:\.\d+)?", value.strip()) is not None
    return False


def should_redact_key(key: str, value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if normalized in TOKEN_USAGE_KEYS and is_number_like(value):
        return False
    return bool(SECRET_KEY_RE.search(key))


def sanitize_model_usage(usage: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(usage, dict):
        return {}
    safe_usage: dict[str, dict[str, Any]] = {}
    for model_name, item in usage.items():
        if not isinstance(item, dict):
            continue
        safe_item: dict[str, Any] = {}
        for key, value in item.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized not in MODEL_USAGE_ALLOWED_KEYS:
                continue
            if is_number_like(value) or value == "***REDACTED***":
                safe_item[str(key)] = value
        if safe_item:
            safe_usage[str(redact(str(model_name)))[:200]] = safe_item
    return safe_usage


def validate_env_key(key: str) -> str:
    if not ENV_KEY_RE.match(key):
        raise OrchestratorError(f"Unsafe environment variable name from CCSwitch profile: {key!r}")
    return key


def build_worker_env(
    provider_env: dict[str, str],
    model_override: str | None = None,
    workspace_root: str | Path | None = None,
    artifact_root: str | Path | None = None,
) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in PASSTHROUGH_ENV_KEYS}
    for key, value in provider_env.items():
        env[validate_env_key(str(key))] = str(value)
    if model_override:
        env["ANTHROPIC_MODEL"] = str(model_override)
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    env["CC_ORCHESTRATOR_WORKSPACE_ROOT"] = str(Path(workspace_root).expanduser().resolve() if workspace_root else WORKSPACE_ROOT)
    env["CC_ORCHESTRATOR_ARTIFACT_ROOT"] = str(Path(artifact_root).expanduser().resolve() if artifact_root else ARTIFACT_ROOT)
    return force_utf8_env(env)


def workspace_paths(cwd: str | Path | None = None) -> dict[str, Path]:
    workspace_root = WORKSPACE_ROOT if cwd is None else Path(cwd).expanduser().resolve()
    artifact_root = ARTIFACT_ROOT if cwd is None else workspace_root / AGENT_WORKSPACE_DIRNAME / ARTIFACT_NAMESPACE
    return {
        "workspace_root": workspace_root,
        "agent_workspace": artifact_root.parent,
        "artifact_root": artifact_root,
        "runs": artifact_root / "runs",
        "teams": artifact_root / "runs" / "teams",
        "workflows": artifact_root / "workflows",
        "reports": artifact_root / "reports",
        "dashboard": artifact_root / "dashboard",
        "archives": artifact_root / "archives",
        "rollback": artifact_root / "rollback",
        "logs": artifact_root / "logs",
        "tmp": artifact_root / "tmp",
        "templates": artifact_root / "templates",
        "policies": artifact_root / "policies",
    }


def path_info(path: Path) -> dict[str, Any]:
    try:
        exists = path.exists()
        size = path_size(path) if exists else 0
        return {"path": str(path), "exists": exists, "bytes": size}
    except Exception as exc:
        return {"path": str(path), "exists": False, "error": str(exc)}


def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def ensure_under(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise OrchestratorError(f"Refusing path outside managed workspace: {resolved_path}") from exc
    return resolved_path


def managed_dirs(paths: dict[str, Path]) -> list[Path]:
    return [paths[name] for name in ("runs", "teams", "reports", "dashboard", "archives", "rollback", "logs", "tmp", "templates", "policies")]


def protected_scaffold_dirs(paths: dict[str, Path]) -> set[Path]:
    return {path.resolve() for path in managed_dirs(paths)}


def default_folder_policy(cwd: str | Path | None = None) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    artifact_root = paths["artifact_root"]
    return {
        "schema_version": 1,
        "generated_at": utc_now_iso(),
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(artifact_root),
        "principle": "Only manage agent-generated artifacts. Do not move, delete, or rewrite project source files.",
        "allowed_agent_artifact_dirs": [str(path) for path in managed_dirs(paths)],
        "allowed_project_files_when_explicitly_requested": [
            str(paths["workspace_root"] / "CLAUDE.md"),
            str(paths["workspace_root"] / ".mcp.json"),
            str(paths["workspace_root"] / ".gitignore"),
        ],
        "forbidden_project_paths": [
            ".git/",
            ".env",
            ".env.*",
            "src/",
            "app/",
            "lib/",
            "packages/",
            "docs/",
            "README.md",
        ],
        "commands": {
            "init_workspace": "May create .agent-workspace, templates, policy files, and an optional managed CLAUDE.md section.",
            "migrate_data": "May move legacy runs/reports/dashboard into artifact_root only when apply=true.",
            "clean_workspace": "Dry-run by default. May delete tmp contents, non-scaffold empty dirs, or expired run folders under artifact_root.",
            "archive_runs": "Archives run folders under artifact_root/archives. Removal requires apply=true and remove=true.",
            "repair_mcp_paths": "May update only .mcp.json MCP env path keys when apply=true.",
        },
    }


def folder_policy(cwd: str | Path | None = None, apply: bool = False) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    policy = default_folder_policy(cwd)
    policy_path = paths["policies"] / "folder-policy.json"
    if apply:
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "applied": apply, "path": str(policy_path), "policy": policy}


def write_workspace_templates(paths: dict[str, Path]) -> list[str]:
    templates_dir = paths["templates"]
    templates_dir.mkdir(parents=True, exist_ok=True)
    templates = {
        "worker-task.md": "\n".join(
            [
                "# Worker Task",
                "",
                "- Goal:",
                "- Role:",
                "- Allowed write scope:",
                "- Stop signals:",
                "- Required evidence:",
                "",
            ]
        ),
        "run-report.md": "\n".join(
            [
                "# Run Report",
                "",
                "- Run id:",
                "- Model/profile:",
                "- Files touched:",
                "- Checks run:",
                "- Risks:",
                "- Controller decision:",
                "",
            ]
        ),
        "rollback-note.md": "\n".join(
            [
                "# Rollback Note",
                "",
                "- Run id:",
                "- Snapshot:",
                "- Files restored:",
                "- Reason:",
                "",
            ]
        ),
    }
    written: list[str] = []
    for name, content in templates.items():
        path = templates_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            written.append(str(path))
    return written


def init_workspace(
    cwd: str | Path | None = None,
    role: str = "development",
    write_claude: bool = True,
    repair_mcp: bool = False,
) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    for path in managed_dirs(paths):
        path.mkdir(parents=True, exist_ok=True)
    workspace_readme = paths["artifact_root"] / "README.md"
    if not workspace_readme.exists():
        workspace_readme.write_text(
            "\n".join(
                [
                    "# Claude Code Orchestrator Workspace",
                    "",
                    "This directory stores agent-generated artifacts only.",
                    "",
                    "- runs/: Claude Code run logs and events",
                    "- reports/: exported reports and verification output",
                    "- dashboard/: local HTML dashboard",
                    "- archives/: zipped old runs",
                    "- rollback/: rollback notes and snapshots",
                    "- tmp/: temporary files",
                    "- templates/: reusable task/report templates",
                    "- policies/: folder policy and governance files",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    local_gitignore = paths["agent_workspace"] / ".gitignore"
    if not local_gitignore.exists():
        local_gitignore.write_text("*\n!.gitignore\n", encoding="utf-8")
    templates = write_workspace_templates(paths)
    policy_result = folder_policy(cwd, apply=True)
    claude_result: dict[str, Any] | None = None
    if write_claude:
        claude_result = write_claude_md(cwd=paths["workspace_root"], role=role, append=True)
    repair_result: dict[str, Any] | None = None
    if repair_mcp:
        repair_result = repair_mcp_paths(cwd=paths["workspace_root"], apply=True, create=True)
    return {
        "ok": True,
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "created_dirs": [str(path) for path in managed_dirs(paths)],
        "templates_written": templates,
        "folder_policy": policy_result,
        "claude_md": claude_result,
        "mcp_repair": repair_result,
    }


def workspace_status(cwd: str | Path | None = None) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    mcp_path = paths["workspace_root"] / ".mcp.json"
    policy_path = paths["policies"] / "folder-policy.json"
    policy_data = read_json_file(policy_path, {}) if policy_path.exists() else {}
    return {
        "ok": True,
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "env": {
            "CC_ORCHESTRATOR_WORKSPACE_ROOT": os.environ.get("CC_ORCHESTRATOR_WORKSPACE_ROOT"),
            "CC_ORCHESTRATOR_ARTIFACT_ROOT": os.environ.get("CC_ORCHESTRATOR_ARTIFACT_ROOT"),
        },
        "current_runtime_dirs": {
            "runs": str(RUNS_DIR),
            "reports": str(REPORTS_DIR),
            "dashboard": str(DASHBOARD_DIR),
        },
        "managed_dirs": {name: path_info(path) for name, path in paths.items() if name not in {"workspace_root", "agent_workspace", "artifact_root"}},
        "legacy_dirs": {
            "runs": path_info(LEGACY_RUNS_DIR),
            "reports": path_info(LEGACY_REPORTS_DIR),
            "dashboard": path_info(LEGACY_DASHBOARD_DIR),
        },
        "claude_md": path_info(paths["workspace_root"] / "CLAUDE.md"),
        "mcp_json": path_info(mcp_path),
        "folder_policy": {"path": str(policy_path), "exists": policy_path.exists(), "policy": policy_data},
    }


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = path.with_name(f"{path.name}.migrated-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.migrated-{stamp}-{counter}")
        counter += 1
    return candidate


def plan_move_contents(source: Path, destination: Path) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if not source.exists():
        return actions
    for item in sorted(source.iterdir(), key=lambda p: p.name):
        target = unique_destination(destination / item.name)
        actions.append({"source": str(item), "destination": str(target), "bytes": path_size(item)})
    return actions


def migrate_data(cwd: str | Path | None = None, apply: bool = False) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    mapping = [
        ("runs", LEGACY_RUNS_DIR, paths["runs"]),
        ("reports", LEGACY_REPORTS_DIR, paths["reports"]),
        ("dashboard", LEGACY_DASHBOARD_DIR, paths["dashboard"]),
    ]
    actions: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    artifact_root = paths["artifact_root"]
    if apply:
        artifact_root.mkdir(parents=True, exist_ok=True)
    for kind, source, destination in mapping:
        if source.resolve() == destination.resolve():
            skipped.append({"kind": kind, "source": str(source), "reason": "source_is_destination"})
            continue
        for action in plan_move_contents(source, destination):
            action["kind"] = kind
            if kind == "runs":
                source_path = Path(action["source"])
                if source_path.is_dir() and RUN_ID_RE.match(source_path.name) and run_dir_active(source_path):
                    skipped.append({"kind": kind, "source": str(source_path), "reason": "active_run"})
                    continue
            actions.append(action)
            if apply:
                destination.mkdir(parents=True, exist_ok=True)
                src = ensure_under(ROOT, Path(action["source"]))
                dst = ensure_under(artifact_root, Path(action["destination"]))
                shutil.move(str(src), str(dst))
    return {
        "ok": True,
        "applied": apply,
        "artifact_root": str(artifact_root),
        "action_count": len(actions),
        "actions": actions,
        "skipped": skipped,
    }


def run_dir_active(run_dir: Path) -> bool:
    try:
        metadata = read_json_file(run_dir / "metadata.json", {})
        return pid_alive(int(metadata.get("child_pid") or 0)) or pid_alive(int(metadata.get("worker_pid") or 0))
    except Exception:
        return False


def older_than(path: Path, days: int) -> bool:
    if days <= 0:
        return True
    try:
        return (time.time() - path.stat().st_mtime) >= days * 86400
    except OSError:
        return False


def clean_workspace(cwd: str | Path | None = None, older_than_days: int = 30, dry_run: bool = True) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    artifact_root = paths["artifact_root"]
    actions: list[dict[str, Any]] = []
    protected_dirs = protected_scaffold_dirs(paths)
    if not artifact_root.exists():
        return {"ok": True, "dry_run": dry_run, "artifact_root": str(artifact_root), "action_count": 0, "actions": []}
    for item in paths["tmp"].glob("*") if paths["tmp"].exists() else []:
        actions.append({"action": "delete_tmp", "path": str(item), "bytes": path_size(item)})
    if paths["runs"].exists():
        for run_dir in sorted(paths["runs"].iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0):
            if not run_dir.is_dir() or not RUN_ID_RE.match(run_dir.name):
                continue
            if run_dir_active(run_dir):
                continue
            if older_than(run_dir, older_than_days):
                actions.append({"action": "delete_expired_run", "path": str(run_dir), "bytes": path_size(run_dir)})
    for item in sorted(artifact_root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if item.is_dir():
            if item.resolve() in protected_dirs:
                continue
            try:
                if not any(item.iterdir()):
                    actions.append({"action": "delete_empty_dir", "path": str(item), "bytes": 0})
            except OSError:
                continue
    if not dry_run:
        for action in actions:
            target = ensure_under(artifact_root, Path(action["path"]))
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            elif target.exists():
                target.unlink()
    return {
        "ok": True,
        "dry_run": dry_run,
        "artifact_root": str(artifact_root),
        "older_than_days": older_than_days,
        "action_count": len(actions),
        "bytes": sum(int(action.get("bytes") or 0) for action in actions),
        "actions": actions,
    }


def archive_runs(
    cwd: str | Path | None = None,
    older_than_days: int = 30,
    run_ids: list[str] | None = None,
    apply: bool = False,
    remove: bool = False,
) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    runs_dir = paths["runs"]
    archives_dir = paths["archives"]
    selected: list[Path] = []
    requested = set(run_ids or [])
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir() or not RUN_ID_RE.match(run_dir.name):
                continue
            if requested and run_dir.name not in requested:
                continue
            if run_dir_active(run_dir):
                continue
            if requested or older_than(run_dir, older_than_days):
                selected.append(run_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_path = archives_dir / f"runs-{stamp}.zip"
    if apply and selected:
        archives_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for run_dir in selected:
                for item in run_dir.rglob("*"):
                    if item.is_file():
                        archive.write(item, arcname=str(Path("runs") / run_dir.name / item.relative_to(run_dir)))
        if remove:
            for run_dir in selected:
                shutil.rmtree(ensure_under(runs_dir, run_dir), ignore_errors=True)
    return {
        "ok": True,
        "applied": apply,
        "remove_after_archive": remove,
        "archive_path": str(archive_path),
        "selected_count": len(selected),
        "selected_runs": [path.name for path in selected],
    }


def default_mcp_server_block(paths: dict[str, Path]) -> dict[str, Any]:
    return {
        "command": "python",
        "args": [
            "-c",
            "import os,sys,runpy; root=os.environ.get('CC_ORCHESTRATOR_HOME') or os.path.join(os.getcwd(), 'scripts', 'cc-orchestrator'); sys.path.insert(0, root); runpy.run_path(os.path.join(root, 'server.py'), run_name='__main__')",
        ],
        "env": {
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "CC_ORCHESTRATOR_WORKSPACE_ROOT": str(paths["workspace_root"]),
            "CC_ORCHESTRATOR_ARTIFACT_ROOT": str(paths["artifact_root"]),
        },
    }


def repair_mcp_paths(
    cwd: str | Path | None = None,
    mcp_path: str | Path | None = None,
    apply: bool = False,
    create: bool = False,
) -> dict[str, Any]:
    paths = workspace_paths(cwd)
    if mcp_path:
        raw_path = Path(mcp_path).expanduser()
        path = raw_path.resolve() if raw_path.is_absolute() else (paths["workspace_root"] / raw_path).resolve()
    else:
        path = paths["workspace_root"] / ".mcp.json"
    before: dict[str, Any] | None = None
    if path.exists():
        before = json.loads(path.read_text(encoding="utf-8"))
        data = json.loads(json.dumps(before))
    elif create:
        data = {}
    else:
        return {"ok": True, "applied": False, "path": str(path), "changed": False, "reason": ".mcp.json not found; pass create=true to create it."}
    if "mcpServers" in data:
        servers = data.setdefault("mcpServers", {})
    else:
        servers = data
    block = servers.get("claude-code-orchestrator")
    if not isinstance(block, dict):
        block = default_mcp_server_block(paths)
        servers["claude-code-orchestrator"] = block
    env = block.setdefault("env", {})
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["CC_ORCHESTRATOR_WORKSPACE_ROOT"] = str(paths["workspace_root"])
    env["CC_ORCHESTRATOR_ARTIFACT_ROOT"] = str(paths["artifact_root"])
    after = data
    changed = before != after
    backup_path: Path | None = None
    if apply and changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup_path = path.with_name(f"{path.name}.backup.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
            backup_path.write_text(path.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        path.write_text(json.dumps(after, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "applied": apply and changed,
        "path": str(path),
        "changed": changed,
        "backup_path": str(backup_path) if backup_path else None,
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "mcp": after,
    }


def safe_run_dir(run_id: str) -> Path:
    if not RUN_ID_RE.match(run_id):
        raise OrchestratorError(f"Invalid run id: {run_id}")
    run_dir = (RUNS_DIR / run_id).resolve()
    root = RUNS_DIR.resolve()
    if run_dir.exists():
        try:
            run_dir.relative_to(root)
        except ValueError as exc:
            raise OrchestratorError(f"Run id resolves outside run directory: {run_id}") from exc
        return run_dir
    index_path = RUN_INDEX_DIR / f"{run_id}.json"
    if index_path.exists():
        index = read_json_file(index_path, {})
        return validate_indexed_run_dir(run_id, index, index_path)
    return run_dir


def validate_indexed_run_dir(run_id: str, index: dict[str, Any], index_path: Path) -> Path:
    if not isinstance(index, dict) or not index:
        raise OrchestratorError(f"Invalid run index: {index_path}")
    if str(index.get("run_id") or "") != run_id:
        raise OrchestratorError(f"Run index id mismatch: {index_path}")
    missing = [key for key in ("run_dir", "workspace_root", "artifact_root") if not index.get(key)]
    if missing:
        raise OrchestratorError(f"Run index missing {', '.join(missing)}: {index_path}")

    workspace_root = Path(str(index["workspace_root"])).expanduser().resolve()
    artifact_root = Path(str(index["artifact_root"])).expanduser().resolve()
    run_dir = Path(str(index["run_dir"])).expanduser().resolve()
    expected_artifact_root = (workspace_root / AGENT_WORKSPACE_DIRNAME / ARTIFACT_NAMESPACE).resolve()
    if artifact_root != expected_artifact_root:
        raise OrchestratorError(f"Run index artifact root does not match workspace root: {index_path}")
    runs_root = (artifact_root / "runs").resolve()
    try:
        run_dir.relative_to(runs_root)
    except ValueError as exc:
        raise OrchestratorError(f"Indexed run dir resolves outside artifact runs root: {index_path}") from exc
    if run_dir.name != run_id:
        raise OrchestratorError(f"Indexed run dir name does not match run id: {index_path}")
    if not run_dir.exists():
        raise OrchestratorError(f"Indexed run dir does not exist: {run_dir}")
    return run_dir


def register_run_dir(run_id: str, run_dir: Path, workspace_root: Path, artifact_root: Path) -> Path:
    if not RUN_ID_RE.match(run_id):
        raise OrchestratorError(f"Invalid run id: {run_id}")
    RUN_INDEX_DIR.mkdir(parents=True, exist_ok=True)
    return write_json_file(
        RUN_INDEX_DIR / f"{run_id}.json",
        {
            "run_id": run_id,
            "run_dir": str(run_dir.resolve()),
            "workspace_root": str(workspace_root.resolve()),
            "artifact_root": str(artifact_root.resolve()),
            "registered_at": utc_now_iso(),
        },
    )


def known_run_dirs() -> list[Path]:
    candidates: list[Path] = []
    if RUNS_DIR.exists():
        candidates.extend(path for path in RUNS_DIR.iterdir() if path.is_dir() and RUN_ID_RE.match(path.name))
    if RUN_INDEX_DIR.exists():
        for index_path in RUN_INDEX_DIR.glob("*.json"):
            index = read_json_file(index_path, {})
            run_id = str(index.get("run_id") or index_path.stem)
            if not RUN_ID_RE.match(run_id):
                continue
            try:
                candidates.append(validate_indexed_run_dir(run_id, index, index_path))
            except OrchestratorError:
                continue
    seen: set[str] = set()
    unique: list[Path] = []
    for path in candidates:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


def read_metadata(run_dir: Path) -> dict[str, Any]:
    metadata_path = run_dir / "metadata.json"
    if not metadata_path.exists():
        raise OrchestratorError(f"Run metadata not found: {run_dir.name}")
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def write_metadata(run_dir: Path, metadata: dict[str, Any]) -> None:
    (run_dir / "metadata.json").write_text(json.dumps(sanitize_for_json(metadata), ensure_ascii=False, indent=2), encoding="utf-8")


def update_metadata(run_dir: Path, **updates: Any) -> dict[str, Any]:
    metadata = read_metadata(run_dir)
    metadata.update(updates)
    write_metadata(run_dir, metadata)
    return metadata


def run_git_command(cwd: Path, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def parse_porcelain_status(raw: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    parts = raw.split("\0")
    idx = 0
    while idx < len(parts):
        entry = parts[idx]
        idx += 1
        if not entry:
            continue
        status = entry[:2]
        path = entry[3:] if len(entry) > 3 else ""
        old_path = ""
        if status.strip() and status[0] in {"R", "C"} and idx < len(parts):
            old_path = path
            path = parts[idx]
            idx += 1
        if path:
            item = {"status": status.strip() or "modified", "path": path.replace("\\", "/")}
            if old_path:
                item["old_path"] = old_path.replace("\\", "/")
            items.append(item)
    return items


def status_paths(items: list[dict[str, str]]) -> list[str]:
    paths: list[str] = []
    for item in items:
        for key in ("path", "old_path"):
            value = item.get(key)
            if value and value not in paths:
                paths.append(value)
    return paths


def safe_relative(root: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def file_sha256(path: Path, max_bytes: int = 20_000_000) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False}
    if path.is_dir():
        return {"exists": True, "type": "directory"}
    size = path.stat().st_size
    if size > max_bytes:
        return {"exists": True, "skipped": "too_large", "bytes": size}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"exists": True, "sha256": digest.hexdigest(), "bytes": size}


def workspace_hashes(cwd: Path, paths: list[str], limit: int = 1000) -> dict[str, Any]:
    important = [
        "README.md",
        "README.zh-CN.md",
        "SKILL.md",
        "CLAUDE.md",
        ".gitignore",
        "package.json",
        "package-lock.json",
        "pyproject.toml",
        "requirements.txt",
        ".claude-code-orchestrator/write-scope.json",
    ]
    selected: list[str] = []
    for item in [*paths, *important]:
        normalized = item.replace("\\", "/").strip("/")
        if normalized and normalized not in selected:
            selected.append(normalized)
        if len(selected) >= limit:
            break
    hashes: dict[str, Any] = {}
    for rel in selected:
        candidate = (cwd / rel).resolve()
        if safe_relative(cwd, candidate) is None:
            continue
        try:
            hashes[rel] = file_sha256(candidate)
        except Exception as exc:
            hashes[rel] = {"error": str(exc)}
    return hashes


def read_json_file(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    return default


def sanitize_for_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(sanitize_for_json(k)): sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_for_json(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_json(item) for item in value]
    if isinstance(value, str):
        return CONTROL_CHAR_RE.sub("\uFFFD", value)
    return value


def write_json_file(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sanitize_for_json(data), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


@contextlib.contextmanager
def launch_lock(timeout_seconds: int = 15, stale_seconds: int = 60) -> Any:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    lock_dir = RUNS_DIR / ".launch.lock"
    deadline = time.time() + timeout_seconds
    while True:
        try:
            lock_dir.mkdir()
            (lock_dir / "owner.json").write_text(
                json.dumps({"pid": os.getpid(), "created_at": utc_now_iso()}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            break
        except FileExistsError:
            try:
                age = time.time() - lock_dir.stat().st_mtime
                if age > stale_seconds:
                    shutil.rmtree(lock_dir, ignore_errors=True)
                    continue
            except OSError:
                pass
            if time.time() >= deadline:
                raise OrchestratorError("Timed out waiting for the launch lock.")
            time.sleep(0.1)
    try:
        yield
    finally:
        shutil.rmtree(lock_dir, ignore_errors=True)


def snapshot_hashes(snapshot: dict[str, Any]) -> dict[str, Any]:
    path = snapshot.get("hashes_path")
    if not path:
        return {}
    return read_json_file(Path(str(path)), {})


def changed_paths_between_snapshots(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_hashes = snapshot_hashes(before)
    after_hashes = snapshot_hashes(after)
    changed: set[str] = set()
    for path, after_value in after_hashes.items():
        if before_hashes.get(path) != after_value:
            changed.add(path)
    for path in before_hashes:
        if path not in after_hashes:
            changed.add(path)
    before_status = set(str(p).replace("\\", "/") for p in before.get("changed_paths", []) or [])
    after_status = set(str(p).replace("\\", "/") for p in after.get("changed_paths", []) or [])
    changed.update(after_status - before_status)
    before_untracked = set(str(p).replace("\\", "/") for p in before.get("untracked_paths", []) or [])
    after_untracked = set(str(p).replace("\\", "/") for p in after.get("untracked_paths", []) or [])
    changed.update(after_untracked - before_untracked)
    return sorted(path for path in changed if path)


def current_git_changed_paths(cwd: Path) -> list[str]:
    status_proc = run_git_command(cwd, ["status", "--porcelain=v1", "-z"], timeout=30)
    if status_proc.returncode != 0:
        return []
    return status_paths(parse_porcelain_status(status_proc.stdout or ""))


def pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            process_query_limited_information = 0x1000
            still_active = 259
            handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            try:
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return exit_code.value == still_active
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def terminate_process_tree(pid: int, force: bool = False, wait_seconds: int = 5) -> dict[str, Any]:
    """Terminate a process and its children where the platform supports it."""
    if pid <= 0:
        return {"pid": pid, "attempted": False, "alive": False, "method": "invalid-pid"}
    if not pid_alive(pid):
        return {"pid": pid, "attempted": False, "alive": False, "method": "already-exited"}
    method = "os.kill"
    if os.name == "nt":
        cmd = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            cmd.append("/F")
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=max(wait_seconds, 1) + 5)
        time.sleep(min(max(wait_seconds, 1), 5))
        alive = pid_alive(pid)
        return {
            "pid": pid,
            "attempted": True,
            "alive": alive,
            "method": "taskkill",
            "exit_code": proc.returncode,
            "stdout": str(redact(proc.stdout or ""))[-1000:],
            "stderr": str(redact(proc.stderr or ""))[-1000:],
        }
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        try:
            os.killpg(os.getpgid(pid), sig)
            method = "os.killpg"
        except Exception:
            os.kill(pid, sig)
        deadline = time.time() + max(wait_seconds, 1)
        while time.time() < deadline and pid_alive(pid):
            time.sleep(0.1)
        return {"pid": pid, "attempted": True, "alive": pid_alive(pid), "method": method, "signal": int(sig)}
    except OSError as exc:
        return {"pid": pid, "attempted": True, "alive": pid_alive(pid), "method": method, "error": str(exc)}


def read_file_delta(path: Path, offset: int = 0, max_bytes: int = 20000) -> dict[str, Any]:
    if offset < 0:
        raise OrchestratorError("Offset cannot be negative.")
    if max_bytes < 1:
        raise OrchestratorError("max_bytes must be positive.")
    if not path.exists():
        return {"path": str(path), "text": "", "offset": offset, "next_offset": offset, "size": 0, "truncated": False}
    size = path.stat().st_size
    if offset > size:
        offset = size
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(max_bytes)
    next_offset = offset + len(data)
    text = data.decode("utf-8", errors="replace")
    return {
        "path": str(path),
        "text": str(redact(text)),
        "offset": offset,
        "next_offset": next_offset,
        "size": size,
        "truncated": next_offset < size,
    }


def tail_file(path: Path, chars: int = 4000) -> str:
    if chars <= 0 or not path.exists():
        return ""
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - max(chars * 4, 4096)))
        data = handle.read()
    return str(redact(data.decode("utf-8", errors="replace")[-chars:]))


def last_nonempty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line[-1000:]
    return ""


def extract_event_phase(payload: Any, source: str) -> str | None:
    if source == "stderr":
        return "stderr"
    if not isinstance(payload, dict):
        return None
    event_type = str(payload.get("type") or payload.get("event") or payload.get("subtype") or "").lower()
    if "tool" in event_type:
        return "tool"
    if event_type in {"system", "init", "started", "start"}:
        return "started"
    if event_type in {"assistant", "message", "content_block_delta", "content_block_start"}:
        return "responding"
    if event_type in {"result", "complete", "completed", "done"}:
        return "finished"
    content = payload.get("message", {}).get("content") if isinstance(payload.get("message"), dict) else payload.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and str(item.get("type", "")).lower() == "tool_use":
                return "tool"
    return None


def extract_tool_calls_from_payload(payload: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            value_type = str(value.get("type", "")).lower()
            if value_type == "tool_use" or "tool" in value_type and ("name" in value or "tool_name" in value):
                calls.append(
                    {
                        "id": value.get("id"),
                        "name": value.get("name") or value.get("tool_name"),
                        "type": value.get("type"),
                    }
                )
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    return calls


def append_event(run_dir: Path, event: dict[str, Any]) -> None:
    seq_path = run_dir / "event_seq.txt"
    try:
        seq = int(seq_path.read_text(encoding="utf-8").strip() or "0") + 1
    except (FileNotFoundError, ValueError):
        seq = 1
    event.setdefault("seq", seq)
    event.setdefault("ts", utc_now_iso())
    event.setdefault("run_id", run_dir.name)
    path = run_dir / "events.ndjson"
    with path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(json.dumps(sanitize_for_json(redact(event)), ensure_ascii=False) + "\n")
    seq_path.write_text(str(seq), encoding="utf-8")


def parse_events_delta(path: Path, offset: int = 0, max_bytes: int = 20000) -> dict[str, Any]:
    delta = read_file_delta(path, offset=offset, max_bytes=max_bytes)
    events: list[dict[str, Any]] = []
    for line in delta["text"].splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "unparsed", "text": line})
    return {**delta, "events": events}


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    phase = None
    tool_calls: list[dict[str, Any]] = []
    for event in events:
        payload = event.get("payload") if isinstance(event, dict) else None
        event_phase = extract_event_phase(payload, str(event.get("source", ""))) if isinstance(event, dict) else None
        if event_phase:
            phase = event_phase
        tool_calls.extend(extract_tool_calls_from_payload(payload))
    return {"latest_phase": phase, "tool_calls": tool_calls[-20:]}


def read_events(path: Path, max_lines: int | None = None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if max_lines is not None and max_lines > 0:
        lines = lines[-max_lines:]
    events: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "unparsed", "text": str(redact(line))[:1000]})
    return events


def event_text(event: dict[str, Any], limit: int = 240) -> str:
    payload = event.get("payload")
    if isinstance(payload, dict):
        text = payload.get("text")
        if isinstance(text, str):
            return str(redact(text)).strip()[:limit]
        message = payload.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, list):
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        if isinstance(item.get("text"), str):
                            parts.append(str(item["text"]))
                        elif item.get("name"):
                            parts.append(f"tool:{item.get('name')}")
                if parts:
                    return str(redact(" ".join(parts))).strip()[:limit]
        if isinstance(payload.get("result"), str):
            return str(redact(payload["result"])).strip()[:limit]
    text = event.get("text")
    if isinstance(text, str):
        return str(redact(text)).strip()[:limit]
    return str(redact(event.get("type") or event.get("phase") or ""))[:limit]


def compact_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload") if isinstance(event, dict) else None
    tool_calls = extract_tool_calls_from_payload(payload)
    return {
        "seq": event.get("seq"),
        "ts": event.get("ts"),
        "type": event.get("type"),
        "source": event.get("source"),
        "phase": event.get("phase") or extract_event_phase(payload, str(event.get("source", ""))),
        "text": event_text(event),
        "tool_calls": tool_calls[:5],
    }


def compact_events(
    run_id: str,
    event_offset: int = 0,
    max_bytes: int = 20000,
    max_events: int = 20,
    write_artifacts: bool = False,
) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    events_path = run_dir / "events.ndjson"
    delta = parse_events_delta(events_path, offset=event_offset, max_bytes=max_bytes)
    recent = read_events(events_path, max_lines=max(max_events * 4, 80))
    compact_recent = [compact_event(event) for event in recent][-max_events:]
    summary = summarize_events(recent)
    tool_summary = summarize_tool_calls(compact_recent)
    timeline_md = build_tool_timeline_md(compact_recent)
    artifact_paths = {
        "tool_timeline": str(run_dir / CONTROLLER_ARTIFACTS["tool_timeline"]),
    }
    if write_artifacts:
        (run_dir / CONTROLLER_ARTIFACTS["tool_timeline"]).write_text(timeline_md, encoding="utf-8")
    return {
        "ok": True,
        "run_id": run_id,
        "events_path": str(events_path),
        "offset": delta["offset"],
        "next_offset": delta["next_offset"],
        "size": delta["size"],
        "truncated": delta["truncated"],
        "new_event_count": len(delta["events"]),
        "recent_event_count": len(recent),
        "items": compact_recent,
        "latest_phase": summary.get("latest_phase"),
        "tool_calls": summary.get("tool_calls", []),
        "tool_call_summary": tool_summary,
        "tool_timeline": timeline_md,
        "artifact_paths": artifact_paths,
    }


def build_tool_timeline_md(events: list[dict[str, Any]]) -> str:
    lines = ["# Run Timeline", "", f"Generated: {utc_now_iso()}", ""]
    if not events:
        lines.append("- No events found yet.")
        return "\n".join(lines).rstrip() + "\n"
    for event in events:
        ts = str(event.get("ts") or "")
        clock = ts[11:19] if len(ts) >= 19 else ts
        phase = event.get("phase") or event.get("type") or "event"
        text = str(event.get("text") or "").replace("\n", " ").strip()
        tools = ", ".join(str(call.get("name") or "tool") for call in event.get("tool_calls") or [])
        suffix = f" tools: {tools}" if tools else ""
        lines.append(f"- `{clock}` **{phase}** {text}{suffix}".rstrip())
    return "\n".join(lines).rstrip() + "\n"


def summarize_tool_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for event in events:
        for call in event.get("tool_calls") or []:
            name = str(call.get("name") or call.get("type") or "tool")
            bucket = buckets.setdefault(name, {"name": name, "count": 0, "first_seq": event.get("seq"), "last_seq": event.get("seq")})
            bucket["count"] += 1
            bucket["last_seq"] = event.get("seq")
    items = sorted(buckets.values(), key=lambda item: (-int(item.get("count") or 0), str(item.get("name") or "")))
    return items


def latest_meaningful_action(events: list[dict[str, Any]], status: dict[str, Any]) -> str:
    for event in reversed(events):
        text = str(event.get("text") or "").strip()
        phase = str(event.get("phase") or event.get("type") or "").strip()
        if text and text not in {"claude_stream", "process_exited", "process_started", "run_started", "stream_worker_started", "stream_worker_ready"}:
            return text[:500]
        if phase in {"tool", "responding", "finished", "stderr"}:
            return phase
    return str(status.get("last_stdout_line") or status.get("last_stderr_line") or status.get("status") or "no signal yet")[:500]


def new_findings_from_events(events: list[dict[str, Any]], limit: int = 5) -> list[str]:
    findings: list[str] = []
    markers = ("found", "risk", "error", "fail", "changed", "edited", "created", "updated", "fixed", "发现", "风险", "失败", "错误", "修改", "创建", "修复")
    for event in reversed(events):
        text = str(event.get("text") or "").replace("\n", " ").strip()
        if len(text) < 4:
            continue
        if any(marker in text.lower() for marker in markers):
            if text not in findings:
                findings.append(text[:300])
        if len(findings) >= limit:
            break
    return list(reversed(findings))


def should_write_checkpoint(run_dir: Path, event_count: int) -> tuple[bool, dict[str, Any]]:
    checkpoint_dir = run_dir / "checkpoints"
    manifest_path = checkpoint_dir / "manifest.json"
    manifest = read_json_file(manifest_path, {"next_index": 1, "last_event_count": 0, "last_written_at": None, "checkpoints": []})
    last_count = int(manifest.get("last_event_count") or 0)
    last_age = _iso_age_seconds(str(manifest.get("last_written_at") or ""))
    if not manifest.get("checkpoints"):
        return True, manifest
    if event_count - last_count >= CHECKPOINT_EVENT_INTERVAL:
        return True, manifest
    if last_age is not None and last_age >= CHECKPOINT_SECONDS_INTERVAL:
        return True, manifest
    return False, manifest


def write_run_checkpoint(
    run_dir: Path,
    progress: dict[str, Any],
    risks: dict[str, Any],
    changed_files: dict[str, Any],
    tool_summary: list[dict[str, Any]],
    event_count: int,
    force: bool = False,
) -> dict[str, Any]:
    should_write, manifest = should_write_checkpoint(run_dir, event_count)
    if not force and not should_write:
        latest = (manifest.get("checkpoints") or [])[-1] if manifest.get("checkpoints") else {}
        return {"written": False, "latest": latest, "manifest_path": str(run_dir / "checkpoints" / "manifest.json")}
    checkpoint_dir = run_dir / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    index = int(manifest.get("next_index") or 1)
    path = checkpoint_dir / f"checkpoint-{index:03d}.md"
    tool_lines = [f"- `{item.get('name')}` x{item.get('count')}" for item in tool_summary] or ["- No tool calls detected."]
    risk_lines = [f"- `{flag.get('severity')}` `{flag.get('code')}`: {flag.get('message')}" for flag in risks.get("flags", [])] or ["- No drift detected."]
    file_lines = [f"- `{path}`" for path in changed_files.get("files", [])[:30]] or ["- No changed files detected."]
    finding_lines = [f"- {item}" for item in (progress.get("new_findings") or [])] or ["- No new findings detected."]
    lines = [
        f"# Run Checkpoint {index:03d}",
        "",
        f"Run: `{progress.get('run_id')}`",
        f"Generated: {utc_now_iso()}",
        f"Status: `{progress.get('status')}`",
        f"Phase: `{progress.get('phase')}`",
        f"Recommended action: `{progress.get('recommended_action')}`",
        "",
        "## Done",
        f"- Last meaningful action: {progress.get('last_meaningful_action') or 'No meaningful action yet.'}",
        f"- Events observed: `{event_count}`",
        "",
        "## Findings",
        *finding_lines,
        "",
        "## Changed",
        *file_lines,
        "",
        "## Repeated Tools",
        *tool_lines,
        "",
        "## Remaining",
        f"- Controller recommendation: `{progress.get('recommended_action')}`",
        "",
        "## Drift",
        *risk_lines,
    ]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    checkpoints = manifest.setdefault("checkpoints", [])
    item = {"index": index, "path": str(path), "event_count": event_count, "written_at": utc_now_iso()}
    checkpoints.append(item)
    manifest["next_index"] = index + 1
    manifest["last_event_count"] = event_count
    manifest["last_written_at"] = item["written_at"]
    write_json_file(checkpoint_dir / "manifest.json", manifest)
    return {"written": True, "latest": item, "manifest_path": str(checkpoint_dir / "manifest.json")}


def classify_change_paths(cwd: Path, files: list[str]) -> dict[str, Any]:
    root = cwd.resolve()
    artifact_root = workspace_paths(root)["artifact_root"].resolve()
    project_paths: list[str] = []
    artifact_paths: list[str] = []
    other_paths: list[str] = []
    for raw in files:
        rel = str(raw).replace("\\", "/").strip("/")
        if not rel:
            continue
        candidate = (root / rel).resolve()
        if path_under(candidate, artifact_root):
            artifact_paths.append(rel)
        elif safe_relative(root, candidate) is not None:
            project_paths.append(rel)
        else:
            other_paths.append(rel)
    return {
        "project_source_changes": {
            "changed_count": len(project_paths),
            "paths": project_paths,
            "has_changes": bool(project_paths),
        },
        "agent_artifact_changes": {
            "changed_count": len(artifact_paths),
            "paths": artifact_paths,
            "has_changes": bool(artifact_paths),
            "artifact_root": str(artifact_root),
        },
        "outside_workspace_changes": {
            "changed_count": len(other_paths),
            "paths": other_paths,
            "has_changes": bool(other_paths),
        },
    }


def risk_summary(flags: list[dict[str, Any]]) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    max_severity = "none"
    blocking_count = 0
    warning_count = 0
    for flag in flags:
        item = dict(flag)
        severity = str(item.get("severity") or "low").lower()
        if severity not in SEVERITY_ORDER:
            severity = "low"
        item["severity"] = severity
        item.setdefault("category", "runtime")
        item.setdefault("confidence", "medium")
        item["blocking"] = bool(item.get("blocking", severity in BLOCKING_SEVERITIES))
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[max_severity]:
            max_severity = severity
        if item["blocking"]:
            blocking_count += 1
        elif severity != "none":
            warning_count += 1
        normalized.append(item)
    return {
        "ok": blocking_count == 0,
        "blocking_ok": blocking_count == 0,
        "has_warnings": warning_count > 0,
        "max_severity": max_severity,
        "warning_count": warning_count,
        "blocking_count": blocking_count,
        "flag_count": len(normalized),
        "flags": sorted(normalized, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 0), reverse=True),
        "needs_controller_attention": bool(normalized),
    }


def output_budget_from_metadata(metadata: dict[str, Any], run_dir: Path | None = None) -> dict[str, Any]:
    budget = dict(OUTPUT_BUDGET_DEFAULTS)
    budget.update(metadata.get("output_budget") or {})
    if run_dir:
        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        events_path = run_dir / "events.ndjson"
        stdout_bytes = stdout_path.stat().st_size if stdout_path.exists() else 0
        stderr_bytes = stderr_path.stat().st_size if stderr_path.exists() else 0
        events_bytes = events_path.stat().st_size if events_path.exists() else 0
        budget["stdout_bytes"] = stdout_bytes
        budget["stderr_bytes"] = stderr_bytes
        budget["observed_output_bytes"] = max(int(budget.get("observed_output_bytes") or 0), stdout_bytes + stderr_bytes)
        budget["written_output_bytes"] = stdout_bytes + stderr_bytes
        budget["events_bytes"] = events_bytes
        if budget.get("state") in {None, ""}:
            budget["state"] = "within_budget"
        soft = budget.get("soft_output_bytes")
        if soft and budget["observed_output_bytes"] > int(soft) and budget.get("state") == "within_budget":
            budget["state"] = "soft_exceeded"
    return budget


def route_drift_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    profile = metadata.get("profile") or {}
    drift = metadata.get("route_drift") or {}
    previous_profile = drift.get("previous_profile") or metadata.get("previous_profile")
    previous_model = drift.get("previous_model") or metadata.get("previous_model")
    current_profile = profile.get("name")
    current_model = profile.get("model")
    changed = bool(drift.get("route_changed"))
    if previous_profile or previous_model:
        changed = changed or previous_profile != current_profile or previous_model != current_model
    return {
        "previous_profile": previous_profile,
        "previous_model": previous_model,
        "current_profile": current_profile,
        "current_model": current_model,
        "route_changed": changed,
        "route_change_reason": drift.get("route_change_reason") or drift.get("reason") or "",
    }


def normalize_model_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9.]+", "", str(value or "").lower())


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _number_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_model_usage(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    candidates: list[Any] = [
        payload.get("modelUsage"),
        payload.get("model_usage"),
    ]
    usage = payload.get("usage")
    if isinstance(usage, dict):
        candidates.extend([usage.get("modelUsage"), usage.get("model_usage")])
    message = payload.get("message")
    if isinstance(message, dict):
        candidates.extend([message.get("modelUsage"), message.get("model_usage"), message.get("model")])
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate:
            return candidate
    return {}


def extract_payload_model(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("model", "actualModel", "actual_model"):
        if payload.get(key):
            return str(payload.get(key))
    message = payload.get("message")
    if isinstance(message, dict):
        for key in ("model", "actualModel", "actual_model"):
            if message.get(key):
                return str(message.get(key))
    usage = extract_model_usage(payload)
    if usage:
        ranked = sorted(
            usage.items(),
            key=lambda item: (
                _number((item[1] or {}).get("costUSD") if isinstance(item[1], dict) else 0),
                _number((item[1] or {}).get("inputTokens") if isinstance(item[1], dict) else 0)
                + _number((item[1] or {}).get("outputTokens") if isinstance(item[1], dict) else 0),
            ),
            reverse=True,
        )
        if ranked:
            return str(ranked[0][0])
    return None


def actual_route_from_payload(payload: Any, declared_model: Any = None) -> dict[str, Any]:
    usage = sanitize_model_usage(extract_model_usage(payload))
    actual_model = extract_payload_model(payload)
    input_tokens = 0
    output_tokens = 0
    total_cost = 0.0
    input_unknown = False
    output_unknown = False
    for item in usage.values():
        if not isinstance(item, dict):
            continue
        input_value = item.get("inputTokens") if item.get("inputTokens") is not None else item.get("input_tokens")
        output_value = item.get("outputTokens") if item.get("outputTokens") is not None else item.get("output_tokens")
        input_number = _number_or_none(input_value)
        output_number = _number_or_none(output_value)
        if input_value is not None and input_number is None:
            input_unknown = True
        elif input_number is not None:
            input_tokens += int(input_number)
        if output_value is not None and output_number is None:
            output_unknown = True
        elif output_number is not None:
            output_tokens += int(output_number)
        total_cost += _number(item.get("costUSD") or item.get("cost_usd"))
    actual_input_tokens = None if input_unknown and input_tokens == 0 else input_tokens
    actual_output_tokens = None if output_unknown and output_tokens == 0 else output_tokens
    actual_total_tokens = None
    if usage and actual_input_tokens is not None and actual_output_tokens is not None:
        actual_total_tokens = actual_input_tokens + actual_output_tokens
    declared = str(declared_model or "")
    mismatch = bool(actual_model and declared and normalize_model_name(actual_model) != normalize_model_name(declared))
    return {
        "actual_model": actual_model,
        "actual_model_usage": usage,
        "actual_input_tokens": actual_input_tokens,
        "actual_output_tokens": actual_output_tokens,
        "actual_total_tokens": actual_total_tokens,
        "actual_cost_usd": total_cost if usage else None,
        "declared_model": declared or None,
        "route_mismatch": mismatch,
    }


def actual_route_from_text(text: str, declared_model: Any = None) -> dict[str, Any]:
    candidates = [text]
    candidates.extend(reversed(text.splitlines()))
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        summary = actual_route_from_payload(payload, declared_model=declared_model)
        if summary.get("actual_model") or summary.get("actual_model_usage"):
            return summary
    return actual_route_from_payload({}, declared_model=declared_model)


def actual_route_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    profile = metadata.get("profile") or {}
    declared_model = profile.get("model")
    route = metadata.get("actual_route") or {}
    actual_model = metadata.get("actual_model") or route.get("actual_model")
    usage = metadata.get("actual_model_usage") or route.get("actual_model_usage") or {}
    summary = {
        "declared_profile": profile.get("name"),
        "declared_model": declared_model,
        "actual_model": actual_model,
        "actual_model_usage": usage,
        "actual_input_tokens": metadata.get("actual_input_tokens", route.get("actual_input_tokens")),
        "actual_output_tokens": metadata.get("actual_output_tokens", route.get("actual_output_tokens")),
        "actual_total_tokens": metadata.get("actual_total_tokens", route.get("actual_total_tokens")),
        "actual_cost_usd": metadata.get("actual_cost_usd", route.get("actual_cost_usd")),
    }
    if usage:
        recalculated = actual_route_from_payload({"modelUsage": usage, "model": actual_model}, declared_model=declared_model)
        for key in ("actual_input_tokens", "actual_output_tokens", "actual_total_tokens"):
            current = summary.get(key)
            replacement = recalculated.get(key)
            if current in (None, 0) and replacement is not None:
                summary[key] = replacement
            elif current == 0 and replacement is None and summary.get("actual_cost_usd"):
                summary[key] = None
        if summary.get("actual_cost_usd") is None:
            summary["actual_cost_usd"] = recalculated.get("actual_cost_usd")
    summary["route_mismatch"] = bool(
        metadata.get("route_mismatch")
        or route.get("route_mismatch")
        or (actual_model and declared_model and normalize_model_name(actual_model) != normalize_model_name(declared_model))
    )
    return summary


def changed_files_for_run(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    before = metadata.get("git_before") or {}
    after = metadata.get("git_after") or {}
    files = changed_paths_between_snapshots(before, after) if before or after else []
    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    classified = classify_change_paths(cwd, files)
    return {
        "ok": True,
        "run_id": run_id,
        "cwd": metadata.get("cwd"),
        "source": "run_snapshots" if before or after else "none",
        "file_count": len(files),
        "files": files,
        **classified,
    }


def _iso_age_seconds(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(str(ts))
        return max(0.0, (datetime.now(timezone.utc) - value).total_seconds())
    except Exception:
        return None


def detect_failure_modes(
    run_id: str,
    status: dict[str, Any] | None = None,
    compact: dict[str, Any] | None = None,
    changed_files: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    status = status or single_run_status(run_id, include_output_tail=True, tail_chars=4000)
    compact = compact or compact_events(run_id, max_events=30, write_artifacts=False)
    changed_files = changed_files or changed_files_for_run(run_id)
    stdout_tail = tail_file(run_dir / "stdout.txt", chars=12000)
    stderr_tail = tail_file(run_dir / "stderr.txt", chars=6000)
    merged_tail = f"{stdout_tail}\n{stderr_tail}"
    flags: list[dict[str, Any]] = []
    metadata = read_metadata(run_dir)

    events = compact.get("items") or []
    last_event = events[-1] if events else {}
    last_age = _iso_age_seconds(str(last_event.get("ts") or "")) if last_event else None
    if status.get("active") and last_age is not None and last_age > 180:
        flags.append({"code": "stalled", "severity": "medium", "category": "liveness", "confidence": "medium", "message": f"No compact event for {int(last_age)} seconds."})
    if status.get("timed_out") or status.get("status") == "timed_out":
        flags.append({"code": "timed_out", "severity": "high", "category": "liveness", "confidence": "high", "message": "Worker exceeded timeout."})
    output_budget = output_budget_from_metadata(metadata, run_dir)
    if str(output_budget.get("state")) in {"stopped", "truncated"}:
        flags.append({"code": "output_budget_exceeded", "severity": "high", "category": "output_budget", "confidence": "high", "message": f"Output budget policy triggered: {output_budget.get('stop_reason') or output_budget.get('state')}.", "output_budget": output_budget})
    elif int(output_budget.get("observed_output_bytes") or 0) > int(output_budget.get("soft_output_bytes") or 500_000):
        flags.append({"code": "excessive_output", "severity": "medium", "blocking": False, "category": "output_budget", "confidence": "high", "message": "Run produced more than the configured soft output budget.", "output_budget": output_budget})

    search_lines = [event for event in events if FAILURE_PATTERNS["repeated_search"].search(str(event.get("text") or ""))]
    if len(search_lines) >= 8:
        flags.append({"code": "repeated_search", "severity": "medium", "blocking": False, "category": "efficiency", "confidence": "medium", "message": "Many recent events look like repeated search/listing work."})

    if FAILURE_PATTERNS["permission_risk"].search(merged_tail):
        flags.append({"code": "destructive_command_risk", "severity": "high", "category": "safety", "confidence": "medium", "message": "Output mentions a potentially destructive shell command."})

    if FAILURE_PATTERNS["test_failed"].search(merged_tail) and FAILURE_PATTERNS["claimed_success"].search(merged_tail):
        flags.append({"code": "success_claim_after_test_failure", "severity": "high", "category": "quality", "confidence": "medium", "message": "Output appears to claim success while also containing test failure text."})

    actual_route = actual_route_summary(metadata)
    if actual_route.get("route_mismatch"):
        flags.append(
            {
                "code": "route_mismatch",
                "severity": "high",
                "category": "routing",
                "confidence": "high",
                "message": "Declared route model differs from Claude stream modelUsage.",
                "declared_model": actual_route.get("declared_model"),
                "actual_model": actual_route.get("actual_model"),
            }
        )

    try:
        scope = check_write_scope(run_id=run_id)
        if not scope.get("ok", True):
            flags.append({"code": "write_scope_violation", "severity": "high", "category": "scope", "confidence": "high", "message": "Changed files violate the preflight write scope.", "violations": scope.get("violations", [])})
    except Exception as exc:
        flags.append({"code": "write_scope_unknown", "severity": "low", "blocking": False, "category": "scope", "confidence": "low", "message": str(exc)})

    try:
        scan = secret_scan_run(run_id, include_diff=False)
        if scan.get("blocking_count"):
            flags.append({"code": "possible_secret_output", "severity": scan.get("max_severity") or "critical", "category": "secret", "confidence": "high", "message": "Run logs may contain credential-like values.", "finding_count": scan.get("finding_count"), "classification_counts": scan.get("classification_counts")})
        elif scan.get("finding_count"):
            flags.append({"code": "secret_scan_warnings", "severity": "low", "blocking": False, "category": "secret", "confidence": "medium", "message": "Secret scan found only placeholder or identifier-like warnings.", "finding_count": scan.get("finding_count"), "classification_counts": scan.get("classification_counts")})
    except Exception as exc:
        flags.append({"code": "secret_scan_unknown", "severity": "low", "blocking": False, "category": "secret", "confidence": "low", "message": str(exc)})

    watched = {".env", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock"}
    source_paths = (changed_files.get("project_source_changes") or {}).get("paths") or changed_files.get("files", [])
    unrelated = [path for path in source_paths if Path(path).name in watched]
    if unrelated:
        flags.append({"code": "sensitive_file_changed", "severity": "medium", "blocking": False, "category": "source_change", "confidence": "medium", "message": "Worker changed sensitive or lock/config files.", "files": unrelated})

    summary = risk_summary(flags)
    return {"run_id": run_id, **summary}


def controller_recommendation(status: dict[str, Any], risks: dict[str, Any]) -> str:
    flags = risks.get("flags", [])
    if any(flag.get("severity") in {"critical", "high"} for flag in flags):
        return "stop_or_review" if status.get("active") else "blocked_review"
    if status.get("active"):
        return "continue_polling"
    if status.get("status") == "succeeded":
        return "verify_run"
    if status.get("status") in {"failed", "timed_out", "lost"}:
        return "inspect_or_restart"
    return "controller_review"


def progress_summary_for_run(
    run_id: str,
    status: dict[str, Any],
    compact: dict[str, Any],
    changed_files: dict[str, Any],
    risks: dict[str, Any],
    max_summary_chars: int = 2000,
) -> dict[str, Any]:
    recent = compact.get("items") or []
    last = recent[-1] if recent else {}
    tool_names: list[str] = []
    for call in compact.get("tool_calls") or []:
        name = call.get("name")
        if name and name not in tool_names:
            tool_names.append(str(name))
    summary = {
        "ok": True,
        "run_id": run_id,
        "status": status.get("status"),
        "active": status.get("active"),
        "role": status.get("role"),
        "model": (status.get("profile") or {}).get("model"),
        "phase": compact.get("latest_phase") or status.get("latest_phase"),
        "elapsed_ms": status.get("elapsed_ms"),
        "last_event": {
            "ts": last.get("ts"),
            "phase": last.get("phase") or last.get("type"),
            "text": str(last.get("text") or "")[:max_summary_chars],
        },
        "last_meaningful_action": latest_meaningful_action(recent, status)[:max_summary_chars],
        "new_findings": new_findings_from_events(recent),
        "last_stdout_line": str(status.get("last_stdout_line") or "")[:max_summary_chars],
        "last_stderr_line": str(status.get("last_stderr_line") or "")[:max_summary_chars],
        "tool_call_count": len(compact.get("tool_calls") or []),
        "tool_call_summary": compact.get("tool_call_summary") or [],
        "recent_tools": tool_names[-10:],
        "changed_file_count": changed_files.get("file_count", 0),
        "changed_files": changed_files.get("files", [])[:50],
        "project_source_changes": changed_files.get("project_source_changes"),
        "agent_artifact_changes": changed_files.get("agent_artifact_changes"),
        "risk_flag_count": risks.get("flag_count", 0),
        "risk_blocking_ok": risks.get("blocking_ok", risks.get("ok")),
        "risk_has_warnings": risks.get("has_warnings", False),
        "risk_max_severity": risks.get("max_severity", "none"),
        "controller_attention_flags": risks.get("flags", []),
        "needs_controller_attention": risks.get("needs_controller_attention", False),
        "recommended_action": controller_recommendation(status, risks),
    }
    return summary


def write_latest_decision(run_dir: Path, summary: dict[str, Any], risks: dict[str, Any]) -> Path:
    lines = [
        "# Latest Controller Decision",
        "",
        f"Run: `{summary.get('run_id')}`",
        f"Status: `{summary.get('status')}`",
        f"Phase: `{summary.get('phase')}`",
        f"Recommended action: `{summary.get('recommended_action')}`",
        f"Needs attention: `{summary.get('needs_controller_attention')}`",
        "",
        "## Last Event",
        str((summary.get("last_event") or {}).get("text") or "-"),
        "",
        "## Risk Flags",
    ]
    flags = risks.get("flags") or []
    if flags:
        for flag in flags:
            lines.append(f"- `{flag.get('severity')}` `{flag.get('code')}`: {flag.get('message')}")
    else:
        lines.append("- None detected.")
    path = run_dir / CONTROLLER_ARTIFACTS["latest_decision"]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def summarize_run(
    run_id: str,
    event_offset: int = 0,
    max_bytes: int = 20000,
    max_events: int = 20,
    max_summary_chars: int = 2000,
    write_artifacts: bool = True,
) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    status = single_run_status(run_id, include_output_tail=False, tail_chars=0)
    compact = compact_events(run_id, event_offset=event_offset, max_bytes=max_bytes, max_events=max_events, write_artifacts=write_artifacts)
    changed_files = changed_files_for_run(run_id)
    risks = detect_failure_modes(run_id, status=status, compact=compact, changed_files=changed_files)
    progress = progress_summary_for_run(run_id, status, compact, changed_files, risks, max_summary_chars=max_summary_chars)
    artifact_paths = {
        "progress_summary": str(run_dir / CONTROLLER_ARTIFACTS["progress_summary"]),
        "latest_decision": str(run_dir / CONTROLLER_ARTIFACTS["latest_decision"]),
        "risk_flags": str(run_dir / CONTROLLER_ARTIFACTS["risk_flags"]),
        "changed_files": str(run_dir / CONTROLLER_ARTIFACTS["changed_files"]),
        "tool_timeline": str(run_dir / CONTROLLER_ARTIFACTS["tool_timeline"]),
    }
    if write_artifacts:
        write_json_file(run_dir / CONTROLLER_ARTIFACTS["progress_summary"], progress)
        write_json_file(run_dir / CONTROLLER_ARTIFACTS["risk_flags"], risks)
        write_json_file(run_dir / CONTROLLER_ARTIFACTS["changed_files"], changed_files)
        (run_dir / CONTROLLER_ARTIFACTS["tool_timeline"]).write_text(compact.get("tool_timeline") or "", encoding="utf-8")
        write_latest_decision(run_dir, progress, risks)
        checkpoint = write_run_checkpoint(
            run_dir,
            progress,
            risks,
            changed_files,
            compact.get("tool_call_summary") or [],
            int(compact.get("recent_event_count") or 0),
        )
    else:
        checkpoint = {"written": False, "latest": None, "manifest_path": str(run_dir / "checkpoints" / "manifest.json")}
    return {
        "ok": True,
        "run_id": run_id,
        "progress_summary": progress,
        "risk_flags": risks,
        "changed_files": changed_files,
        "tool_timeline": compact.get("tool_timeline"),
        "checkpoint": checkpoint,
        "offsets": {
            "event_offset": compact.get("offset"),
            "next_event_offset": compact.get("next_offset"),
            "events_size": compact.get("size"),
        },
        "artifact_paths": artifact_paths,
    }


def list_profiles(ccswitch_home: str | Path | None = None, include_secrets: bool = False) -> list[dict[str, Any]]:
    resolved_home = resolve_ccswitch_home(ccswitch_home)
    db_path = cc_db_path(resolved_home)
    if not db_path.exists():
        raise OrchestratorError(f"CCSwitch database not found: {db_path}")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            select id, app_type, name, settings_config, category, provider_type, is_current, sort_index
            from providers
            where app_type='claude'
            order by is_current desc, sort_index, lower(name)
            """
        ).fetchall()
        profiles: list[dict[str, Any]] = []
        for row in rows:
            endpoints = [
                r["url"]
                for r in con.execute(
                    "select url from provider_endpoints where provider_id=? and app_type='claude'",
                    (row["id"],),
                ).fetchall()
            ]
            settings = json.loads(row["settings_config"])
            provider = Provider(
                id=row["id"],
                name=row["name"],
                app_type=row["app_type"],
                settings=settings,
                category=row["category"],
                provider_type=row["provider_type"],
                is_current=bool(row["is_current"]),
                endpoints=endpoints,
            )
            payload = {
                "id": provider.id,
                "name": provider.name,
                "current": provider.is_current,
                "category": provider.category,
                "provider_type": provider.provider_type,
                "model": provider.model,
                "models": provider.models,
                "model_entries": provider.model_entries,
                "base_url": provider.env.get("ANTHROPIC_BASE_URL"),
                "endpoints": provider.endpoints,
                "settings": provider.settings if include_secrets else redact(provider.settings),
            }
            profiles.append(payload)
        return profiles
    finally:
        con.close()


def get_provider(profile: str | None = None, ccswitch_home: str | Path | None = None) -> Provider:
    profiles = list_profiles(ccswitch_home=ccswitch_home, include_secrets=True)
    if not profiles:
        raise OrchestratorError("No Claude providers found in CCSwitch.")
    selected: dict[str, Any] | None = None
    if profile:
        wanted = profile.strip().lower()
        for item in profiles:
            if item["id"].lower() == wanted or item["name"].lower() == wanted:
                selected = item
                break
        if not selected:
            names = ", ".join(p["name"] for p in profiles)
            raise OrchestratorError(f"Unknown profile '{profile}'. Available profiles: {names}")
    else:
        selected = next((p for p in profiles if p["current"]), profiles[0])
    return Provider(
        id=selected["id"],
        name=selected["name"],
        app_type="claude",
        settings=selected["settings"],
        category=selected.get("category"),
        provider_type=selected.get("provider_type"),
        is_current=bool(selected.get("current")),
        endpoints=selected.get("endpoints") or [],
    )


def _score_from_model_name(model: str) -> tuple[dict[str, int], list[str]]:
    name = model.lower()
    scores = {key: 6 for key in SCORE_KEYS}
    notes = ["local heuristic scoring; verify with real workloads before treating as benchmark data"]
    qwen_match = re.search(r"qwen[-_]?(\d+(?:\.\d+)?)", name)
    glm_match = re.search(r"glm[-_]?(\d+(?:\.\d+)?)", name)
    qwen_version = float(qwen_match.group(1)) if qwen_match else None
    glm_version = float(glm_match.group(1)) if glm_match else None
    if qwen_version is not None and qwen_version >= 3.7:
        scores.update(code=9, long_context=9, reasoning=8, speed=8, stability=7, cost=7, tool_use=9, multimodal=9)
        notes.append("Qwen docs describe Qwen as language plus multimodal models with tool use and agent capabilities.")
    elif qwen_version is not None and qwen_version >= 3.6:
        scores.update(code=8, long_context=8, reasoning=7, speed=8, stability=7, cost=7, tool_use=8, multimodal=7)
        notes.append("Qwen-family heuristic based on Qwen3 tool/agent and coding documentation.")
    elif "qwen" in name:
        scores.update(code=8, long_context=8, reasoning=7, speed=8, stability=7, cost=7, tool_use=8, multimodal=6)
        notes.append("Qwen-family heuristic based on Qwen3 tool/agent and coding documentation.")
    elif glm_version is not None and glm_version >= 5:
        scores.update(code=9, long_context=8, reasoning=9, speed=6, stability=7, cost=6, tool_use=8, multimodal=5)
        notes.append("Z.ai describes GLM-5 as focused on agentic engineering and coding workflows.")
    elif "claude" in name and "opus" in name:
        scores.update(code=9, long_context=8, reasoning=9, speed=6, stability=8, cost=5, tool_use=9, multimodal=7)
        notes.append("Claude Opus-family heuristic; exact proxy model quality depends on provider routing.")
    elif "claude" in name and "sonnet" in name:
        scores.update(code=8, long_context=8, reasoning=8, speed=8, stability=8, cost=7, tool_use=9, multimodal=7)
        notes.append("Claude Sonnet-family heuristic; exact proxy model quality depends on provider routing.")
    return scores, notes


def _weighted_score(scores: dict[str, int], weights: dict[str, float]) -> float:
    total_weight = sum(weights.values()) or 1.0
    return round(sum(scores.get(key, 0) * weight for key, weight in weights.items()) / total_weight, 2)


def score_models(ccswitch_home: str | Path | None = None) -> dict[str, Any]:
    profiles = list_profiles(ccswitch_home=ccswitch_home, include_secrets=True)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for profile in profiles:
        provider = get_provider(profile["id"], ccswitch_home=ccswitch_home)
        for entry in provider.model_entries:
            model = entry["name"]
            key = (provider.id, model)
            if key in seen:
                continue
            seen.add(key)
            scores, notes = _score_from_model_name(model)
            role_scores = {role: _weighted_score(scores, weights) for role, weights in ROLE_SCORE_WEIGHTS.items()}
            overall = round(sum(scores.values()) / len(scores), 2)
            rows.append(
                {
                    "profile_id": provider.id,
                    "profile_name": provider.name,
                    "current_profile": provider.is_current,
                    "model": model,
                    "source": entry["source"],
                    "scores": scores,
                    "overall": overall,
                    "role_scores": role_scores,
                    "basis": notes,
                }
            )
    rows.sort(key=lambda item: (not item["current_profile"], -item["overall"], item["profile_name"], item["model"]))
    return {
        "ok": True,
        "ccswitch_home": str(resolve_ccswitch_home(ccswitch_home)),
        "source_quality": "local heuristic plus public documentation signals; not a paid benchmark run",
        "score_keys": list(SCORE_KEYS),
        "models": rows,
    }


def load_local_policy_override() -> dict[str, Any]:
    return read_json_file(
        LOCAL_POLICY_OVERRIDE_PATH,
        {
            "updated_at": None,
            "preferred_models": {},
            "preferred_profiles": {},
            "notes": "User-owned local routing overrides. This file is ignored by git and preserved across upgrades.",
        },
    )


def local_policy_override(config: dict[str, Any] | None = None, apply: bool = False) -> dict[str, Any]:
    current = load_local_policy_override()
    if config:
        for key, value in config.items():
            if isinstance(value, dict) and isinstance(current.get(key), dict):
                current[key].update(value)
            else:
                current[key] = value
        current["updated_at"] = utc_now_iso()
    if apply:
        write_json_file(LOCAL_POLICY_OVERRIDE_PATH, current)
    return {"ok": True, "applied": apply, "path": str(LOCAL_POLICY_OVERRIDE_PATH), "policy": current}


def model_matches_preference(item: dict[str, Any], wanted: str) -> bool:
    needle = wanted.strip().lower()
    if not needle:
        return False
    compact_needle = re.sub(r"[^a-z0-9]+", "", needle)
    for key in ("model", "profile_name", "profile_id"):
        value = str(item.get(key) or "").lower()
        compact_value = re.sub(r"[^a-z0-9]+", "", value)
        if needle in value or value in needle or compact_needle in compact_value or compact_value in compact_needle:
            return True
    return False


def find_override_model(scored: list[dict[str, Any]], role: str, task_type: str | None = None) -> dict[str, Any] | None:
    override = load_local_policy_override()
    preferred_models = override.get("preferred_models") or {}
    preferred_profiles = override.get("preferred_profiles") or {}
    keys = [role, task_type or "", "default"]
    for key in keys:
        wanted_profile = str(preferred_profiles.get(key) or "").strip()
        if wanted_profile:
            for item in scored:
                if model_matches_preference(item, wanted_profile):
                    chosen = dict(item)
                    chosen["override_reason"] = f"Selected by local_policy.override.json preferred_profiles.{key}."
                    return chosen
        wanted_model = str(preferred_models.get(key) or "").strip()
        if wanted_model:
            for item in scored:
                if model_matches_preference(item, wanted_model):
                    chosen = dict(item)
                    chosen["override_reason"] = f"Selected by local_policy.override.json preferred_models.{key}."
                    return chosen
    return None


def load_model_benchmark_history() -> dict[str, Any]:
    return read_json_file(MODEL_BENCHMARK_HISTORY_PATH, {"updated_at": None, "records": []})


def append_model_benchmark_history(record: dict[str, Any]) -> None:
    history = load_model_benchmark_history()
    history.setdefault("records", []).append(record)
    history["updated_at"] = utc_now_iso()
    write_json_file(MODEL_BENCHMARK_HISTORY_PATH, history)


def load_worker_quality_history() -> dict[str, Any]:
    return read_json_file(WORKER_QUALITY_HISTORY_PATH, {"updated_at": None, "records": []})


def build_model_registry(refresh: bool = True, apply: bool = False) -> dict[str, Any]:
    scored = score_models()["models"] if refresh else []
    history = load_model_benchmark_history()
    quality = load_worker_quality_history()
    registry: dict[str, Any] = {
        "updated_at": utc_now_iso(),
        "source": "CCSwitch scan plus benchmark history plus worker quality history",
        "models": {},
    }
    for item in scored:
        model = str(item.get("model") or "unknown")
        entry = registry["models"].setdefault(
            model,
            {
                "model": model,
                "profiles": [],
                "heuristic_scores": item.get("scores", {}),
                "role_scores": item.get("role_scores", {}),
                "benchmark_runs": [],
                "worker_quality": {"runs": 0, "average_score": None, "by_role": {}},
            },
        )
        entry["profiles"].append({"profile_id": item.get("profile_id"), "profile_name": item.get("profile_name"), "current": item.get("current_profile")})
    for record in history.get("records", []):
        model = str(record.get("model") or "unknown")
        entry = registry["models"].setdefault(model, {"model": model, "profiles": [], "heuristic_scores": {}, "role_scores": {}, "benchmark_runs": [], "worker_quality": {"runs": 0, "average_score": None, "by_role": {}}})
        entry.setdefault("benchmark_runs", []).append(record)
    grouped_quality: dict[str, list[dict[str, Any]]] = {}
    for record in quality.get("records", []):
        grouped_quality.setdefault(str(record.get("model") or "unknown"), []).append(record)
    for model, records in grouped_quality.items():
        entry = registry["models"].setdefault(model, {"model": model, "profiles": [], "heuristic_scores": {}, "role_scores": {}, "benchmark_runs": [], "worker_quality": {"runs": 0, "average_score": None, "by_role": {}}})
        scores = [float(record.get("quality_score") or 0) for record in records]
        by_role: dict[str, dict[str, Any]] = {}
        for record in records:
            role = str(record.get("role") or "unknown")
            bucket = by_role.setdefault(role, {"runs": 0, "average_score": 0.0})
            bucket["runs"] += 1
            bucket["average_score"] += float(record.get("quality_score") or 0)
        for bucket in by_role.values():
            bucket["average_score"] = round(bucket["average_score"] / max(1, int(bucket["runs"])), 2)
        entry["worker_quality"] = {
            "runs": len(records),
            "average_score": round(sum(scores) / len(scores), 2) if scores else None,
            "by_role": by_role,
        }
    if apply:
        write_json_file(MODEL_REGISTRY_PATH, registry)
    return {"ok": True, "applied": apply, "path": str(MODEL_REGISTRY_PATH), "registry": registry}


def select_model_for_role(role: str = "implementation", task_type: str | None = None, ccswitch_home: str | Path | None = None) -> dict[str, Any]:
    target = role if role in ROLE_SCORE_WEIGHTS else "implementation"
    if task_type == "multimodal":
        target = "multimodal"
    elif role not in ROLE_SCORE_WEIGHTS:
        if task_type == "simple":
            target = "testing"
        elif task_type == "development":
            target = "development"
        elif task_type == "review":
            target = "review"
        elif task_type == "security_review":
            target = "security"
        elif task_type == "architecture":
            target = "architecture"
        elif task_type == "performance_review":
            target = "performance"
        elif task_type == "compatibility_review":
            target = "compatibility"
        elif task_type == "documentation":
            target = "documentation"
        elif task_type == "automation":
            target = "automation"
        elif task_type == "ops":
            target = "ops"
    scored = score_models(ccswitch_home=ccswitch_home)["models"]
    if not scored:
        provider = get_provider(ccswitch_home=ccswitch_home)
        return {
            "profile": provider.name,
            "model": provider.model,
            "score": None,
            "reason": "No explicit models found; using current CCSwitch Claude profile.",
        }
    override = find_override_model(scored, target, task_type=task_type)
    if override:
        return {
            "profile": override["profile_name"],
            "model": override["model"],
            "score": override["role_scores"].get(target, override["overall"]),
            "reason": override.get("override_reason") or f"Selected local override for {target}.",
            "scores": override["scores"],
        }
    best = max(
        scored,
        key=lambda item: (
            item["role_scores"].get(target, item["overall"]),
            item["current_profile"],
            item["overall"],
        ),
    )
    return {
        "profile": best["profile_name"],
        "model": best["model"],
        "score": best["role_scores"].get(target, best["overall"]),
        "reason": f"Selected highest local score for {target}.",
        "scores": best["scores"],
    }


def resolve_route(role: str = "implementation", task_type: str | None = None, profile: str | None = None) -> dict[str, Any]:
    policy = load_json(POLICY_PATH)
    routes = policy.get("task_routes", {})
    role_defaults = policy.get("role_defaults", {})
    aliases = policy.get("profile_aliases", {})
    effective_task_type = task_type or role_defaults.get(role, "normal")
    route = routes.get(effective_task_type) or routes.get("normal") or {}
    alias = route.get("profile_alias")
    resolved_profile = profile or aliases.get(alias, alias) or policy.get("default_profile")
    selected_model: dict[str, Any] | None = None
    selection_role = role
    if isinstance(resolved_profile, str) and resolved_profile.startswith("auto"):
        _, _, explicit_role = resolved_profile.partition(":")
        if explicit_role:
            selection_role = explicit_role
        selected_model = select_model_for_role(role=selection_role, task_type=effective_task_type)
        resolved_profile = selected_model["profile"]
    if not resolved_profile:
        raise OrchestratorError("No profile could be resolved from policy.")
    model_override = route.get("model_override")
    if selected_model and selected_model.get("model"):
        model_override = selected_model["model"]
    provider = get_provider(str(resolved_profile))
    if model_override and model_override not in provider.models:
        fallback = select_model_for_role(role=selection_role, task_type=effective_task_type)
        resolved_profile = fallback["profile"]
        model_override = fallback["model"]
        selected_model = fallback
    max_timeout = int(policy.get("safety", {}).get("max_timeout_seconds", 1800))
    timeout = min(int(route.get("timeout_seconds", 420)), max_timeout)
    return {
        "role": role,
        "task_type": effective_task_type,
        "profile": resolved_profile,
        "model_override": model_override,
        "permission_mode": route.get("permission_mode", "plan"),
        "timeout_seconds": timeout,
        "reason": selected_model.get("reason") if selected_model else route.get("reason", ""),
        "route": route,
        "auto_selection": selected_model,
        "selection_role": selection_role,
    }


def healthcheck() -> dict[str, Any]:
    ccswitch_home = resolve_ccswitch_home()
    db_path = cc_db_path(ccswitch_home)
    settings_path = cc_settings_path(ccswitch_home)
    result: dict[str, Any] = {
        "ok": True,
        "claude_bin": claude_bin_path(),
        "claude_candidates": _existing_claude_candidates(),
        "ccswitch_home": str(ccswitch_home),
        "ccswitch_db_exists": db_path.exists(),
        "ccswitch_settings_exists": settings_path.exists(),
        "policy_exists": POLICY_PATH.exists(),
        "agents_exists": AGENTS_PATH.exists(),
        "skill_root": str(SKILL_ROOT),
        "version_exists": VERSION_PATH.exists(),
        "version_path": str(VERSION_PATH),
        "prompt_pack_exists": PROMPT_PACK_DIR.exists(),
        "prompt_pack_path": str(PROMPT_PACK_DIR),
    }
    try:
        profiles = list_profiles()
        result["profile_count"] = len(profiles)
        current = next((p for p in profiles if p.get("current")), None)
        result["current_profile"] = current.get("name") if current else None
        result["current_profile_model"] = current.get("model") if current else None
        result["actual_model_usage_note"] = "Streaming runs record Claude result modelUsage as actual_model_usage and flag route_mismatch when it differs from the declared route."
    except Exception as exc:
        result["ok"] = False
        result["profiles_error"] = str(exc)
    try:
        proc = subprocess.run(
            [claude_bin_path(), "--version"],
            env=build_worker_env({}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        result["claude_version_exit_code"] = proc.returncode
        result["claude_version"] = (proc.stdout or proc.stderr).strip()
        if proc.returncode != 0:
            result["ok"] = False
    except Exception as exc:
        result["ok"] = False
        result["claude_error"] = str(exc)
    return result


def build_prompt(role: str, task: str, context: str | None = None, artifact_root: str | Path | None = None) -> str:
    agents = load_json(AGENTS_PATH)
    agent = agents.get(role) or agents.get("implementation") or {}
    scoped_artifact_root = Path(artifact_root).expanduser().resolve() if artifact_root else ARTIFACT_ROOT
    pieces = [
        "Codex is the controller, reviewer, and final decision maker. You are a Claude Code worker.",
        "",
        agent.get("prompt", f"You are the {role} Agent."),
        "",
        "Follow these operating rules:",
        "- Keep output concise and structured.",
        "- Do not reveal API keys, tokens, secrets, or hidden configuration values.",
        "- Do not revert unrelated work.",
        "- If you edit files, list every changed file and why.",
        f"- Put agent logs, reports, temporary files, and rollback notes only under: {scoped_artifact_root}",
        "",
        "Task:",
        task.strip(),
    ]
    if context and context.strip():
        pieces.extend(["", "Additional context:", context.strip()])
    return "\n".join(pieces)


def capture_git_snapshot(run_dir: Path, cwd: Path, label: str) -> dict[str, Any]:
    """Capture git diff/status, untracked files, and key file hashes."""
    result = {"ok": False, "label": label, "is_git_repo": False}
    if not (cwd / ".git").exists():
        return result
    try:
        diff_proc = run_git_command(cwd, ["diff", "--binary", "--", "."], timeout=60)
        status_proc = run_git_command(cwd, ["status", "--short"], timeout=30)
        porcelain_proc = run_git_command(cwd, ["status", "--porcelain=v1", "-z"], timeout=30)
        untracked_proc = run_git_command(cwd, ["ls-files", "--others", "--exclude-standard", "-z"], timeout=30)
        status_items = parse_porcelain_status(porcelain_proc.stdout or "") if porcelain_proc.returncode == 0 else []
        changed_paths = status_paths(status_items)
        untracked_paths = [part.replace("\\", "/") for part in (untracked_proc.stdout or "").split("\0") if part] if untracked_proc.returncode == 0 else []
        hashes = workspace_hashes(cwd, [*changed_paths, *untracked_paths])
        diff_path = run_dir / f"git_{label}.diff"
        status_path = run_dir / f"git_{label}_status.txt"
        porcelain_path = run_dir / f"git_{label}_porcelain.json"
        untracked_path = run_dir / f"git_{label}_untracked.txt"
        hashes_path = run_dir / f"git_{label}_hashes.json"
        diff_path.write_text(str(redact(diff_proc.stdout or diff_proc.stderr or "")), encoding="utf-8")
        status_path.write_text(str(redact(status_proc.stdout or status_proc.stderr or "")), encoding="utf-8")
        porcelain_path.write_text(json.dumps(status_items, ensure_ascii=False, indent=2), encoding="utf-8")
        untracked_path.write_text("\n".join(untracked_paths) + ("\n" if untracked_paths else ""), encoding="utf-8")
        hashes_path.write_text(json.dumps(hashes, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "ok": diff_proc.returncode == 0 and status_proc.returncode == 0 and porcelain_proc.returncode == 0,
            "label": label,
            "is_git_repo": True,
            "diff_path": str(diff_path),
            "status_path": str(status_path),
            "porcelain_path": str(porcelain_path),
            "untracked_path": str(untracked_path),
            "hashes_path": str(hashes_path),
            "diff_bytes": diff_path.stat().st_size,
            "status_bytes": status_path.stat().st_size,
            "changed_paths": changed_paths,
            "untracked_paths": untracked_paths,
            "changed_count": len(changed_paths),
            "untracked_count": len(untracked_paths),
            "hash_count": len(hashes),
        }
    except Exception as exc:
        return {"ok": False, "label": label, "is_git_repo": True, "error": str(exc)}


def run_agent(
    task: str,
    role: str = "implementation",
    task_type: str | None = None,
    profile: str | None = None,
    allow_write: bool = False,
    timeout_seconds: int | None = None,
    cwd: Path | None = None,
    context: str | None = None,
    output_format: str = "json",
) -> dict[str, Any]:
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    provider = get_provider(route["profile"])
    policy = load_json(POLICY_PATH)
    default_write = bool(policy.get("safety", {}).get("default_write_enabled", False))
    write_enabled = allow_write or default_write
    permission_mode = route["permission_mode"] if not write_enabled else "acceptEdits"
    timeout = timeout_seconds or int(route["timeout_seconds"])
    timeout = min(timeout, int(policy.get("safety", {}).get("max_timeout_seconds", 1800)))
    timeout = enforce_cost_guard(route.get("model_override") or provider.model, timeout)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    paths = workspace_paths(effective_cwd)
    run_dir = paths["runs"] / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    register_run_dir(run_id, run_dir, paths["workspace_root"], paths["artifact_root"])
    prompt = build_prompt(role, task, context, artifact_root=paths["artifact_root"])
    safe_prompt = str(redact(prompt))
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    env = build_worker_env(provider.env, route.get("model_override"), workspace_root=paths["workspace_root"], artifact_root=paths["artifact_root"])
    cmd = [
        claude_bin_path(),
        "-p",
        "--output-format",
        output_format,
        "--permission-mode",
        permission_mode,
        "--no-session-persistence",
        safe_prompt,
    ]
    started = time.time()
    metadata: dict[str, Any] = {
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "cwd": str(effective_cwd),
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "runs_root": str(paths["runs"]),
        "role": role,
        "task_type": route["task_type"],
        "profile": {
            "id": provider.id,
            "name": provider.name,
            "model": route.get("model_override") or provider.model,
            "provider_default_model": provider.model,
            "base_url": provider.env.get("ANTHROPIC_BASE_URL"),
            "endpoints": provider.endpoints,
        },
        "permission_mode": permission_mode,
        "allow_write": write_enabled,
        "timeout_seconds": timeout,
        "prompt_sha256": prompt_hash,
        "route_reason": route.get("reason", ""),
        "command": redact(cmd),
    }
    metadata["git_before"] = capture_git_snapshot(run_dir, effective_cwd, "before")
    write_metadata(run_dir, metadata)
    (run_dir / "prompt.txt").write_text(safe_prompt, encoding="utf-8")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(effective_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        timed_out = False
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = subprocess_text(exc.stdout)
        stderr = subprocess_text(exc.stderr)
        exit_code = 124
    duration_ms = int((time.time() - started) * 1000)
    safe_stdout = redact(stdout)
    safe_stderr = redact(stderr)
    (run_dir / "stdout.txt").write_text(str(safe_stdout), encoding="utf-8")
    (run_dir / "stderr.txt").write_text(str(safe_stderr), encoding="utf-8")
    actual_route = actual_route_from_text(str(stdout), declared_model=(metadata.get("profile") or {}).get("model"))
    metadata.update(
        {
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout_path": str(run_dir / "stdout.txt"),
            "stderr_path": str(run_dir / "stderr.txt"),
            "git_after": capture_git_snapshot(run_dir, effective_cwd, "after"),
        }
    )
    if actual_route.get("actual_model") or actual_route.get("actual_model_usage"):
        metadata.update(
            {
                "actual_route": actual_route,
                "actual_model": actual_route.get("actual_model"),
                "actual_model_usage": actual_route.get("actual_model_usage"),
                "actual_input_tokens": actual_route.get("actual_input_tokens"),
                "actual_output_tokens": actual_route.get("actual_output_tokens"),
                "actual_total_tokens": actual_route.get("actual_total_tokens"),
                "actual_cost_usd": actual_route.get("actual_cost_usd"),
                "route_mismatch": actual_route.get("route_mismatch"),
            }
        )
    write_metadata(run_dir, metadata)
    scope_check = check_write_scope(run_id=run_id)
    metadata["write_scope_check"] = scope_check
    metadata["acceptance_status"] = "blocked_write_scope" if not scope_check.get("ok", True) else "pending_controller_review"
    write_metadata(run_dir, metadata)
    paths["runs"].mkdir(parents=True, exist_ok=True)
    (paths["runs"] / "latest.txt").write_text(run_id, encoding="utf-8")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    (RUNS_DIR / "latest.txt").write_text(run_id, encoding="utf-8")
    return {
        **metadata,
        "stdout_tail": str(safe_stdout)[-4000:],
        "stderr_tail": str(safe_stderr)[-2000:],
    }


def run_streaming_agent(
    task: str,
    role: str = "implementation",
    task_type: str | None = None,
    profile: str | None = None,
    model_override: str | None = None,
    allow_write: bool = False,
    timeout_seconds: int | None = None,
    cwd: Path | None = None,
    context: str | None = None,
    output_format: str = "stream-json",
    include_partial_messages: bool = True,
    max_output_bytes: int | None = None,
    max_events_bytes: int | None = None,
    soft_output_bytes: int | None = None,
    output_budget_policy: str | None = None,
    kill_on_excessive_output: bool = False,
    final_only: bool = False,
    final_max_chars: int | None = None,
    skip_cost_guard: bool = False,
) -> dict[str, Any]:
    """Start Claude Code in the background and stream events to events.ndjson."""
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    provider = get_provider(route["profile"])
    policy = load_json(POLICY_PATH)
    default_write = bool(policy.get("safety", {}).get("default_write_enabled", False))
    write_enabled = allow_write or default_write
    permission_mode = route["permission_mode"] if not write_enabled else "acceptEdits"
    timeout = timeout_seconds or int(route["timeout_seconds"])
    timeout = min(timeout, int(policy.get("safety", {}).get("max_timeout_seconds", 1800)))
    selected_model = model_override or route.get("model_override") or provider.model
    timeout = clamp_timeout_for_model(selected_model, timeout) if skip_cost_guard else timeout
    if output_format != "stream-json":
        raise OrchestratorError("run_streaming_agent requires output_format='stream-json'.")
    budget = resolve_output_budget(
        max_output_bytes=max_output_bytes,
        max_events_bytes=max_events_bytes,
        soft_output_bytes=soft_output_bytes,
        output_budget_policy=output_budget_policy,
        kill_on_excessive_output=kill_on_excessive_output,
        final_only=final_only,
        final_max_chars=final_max_chars,
    )
    if budget.get("final_only"):
        include_partial_messages = False
        final_rules = "\n".join(
            [
                "Final-only output mode is enabled.",
                "Return only essential final findings, changed files, verification, and blockers.",
                "Do not stream exploratory narration or repeated progress logs.",
                f"Keep the final answer under {budget.get('final_max_chars')} characters.",
            ]
        )
        context = "\n\n".join(part for part in [context or "", final_rules] if part)

    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    paths = workspace_paths(effective_cwd)
    run_id = new_run_id()
    run_dir = paths["runs"] / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    register_run_dir(run_id, run_dir, paths["workspace_root"], paths["artifact_root"])
    prompt = build_prompt(role, task, context, artifact_root=paths["artifact_root"])
    safe_prompt = str(redact(prompt))
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    prompt_path = run_dir / "prompt.txt"
    prompt_path.write_text(safe_prompt, encoding="utf-8")
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    events_path = run_dir / "events.ndjson"
    stdout_path.write_text("", encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    events_path.write_text("", encoding="utf-8")

    metadata: dict[str, Any] = {
        "run_id": run_id,
        "mode": "streaming",
        "status": "starting",
        "started_at": utc_now_iso(),
        "cwd": str(effective_cwd),
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "runs_root": str(paths["runs"]),
        "role": role,
        "task_type": route["task_type"],
        "profile": {
            "id": provider.id,
            "name": provider.name,
            "model": selected_model,
            "provider_default_model": provider.model,
            "base_url": provider.env.get("ANTHROPIC_BASE_URL"),
            "endpoints": provider.endpoints,
        },
        "route": {
            "profile": provider.name,
            "model": selected_model,
            "profile_id": provider.id,
            "task_type": route["task_type"],
            "reason": route.get("reason", ""),
            "model_override": model_override or route.get("model_override"),
        },
        "permission_mode": permission_mode,
        "allow_write": write_enabled,
        "timeout_seconds": timeout,
        "output_format": output_format,
        "include_partial_messages": include_partial_messages,
        "output_budget": budget,
        "stop_reason": None,
        "prompt_sha256": prompt_hash,
        "route_reason": route.get("reason", ""),
        "prompt_path": str(prompt_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "events_path": str(events_path),
        "worker_pid": None,
        "child_pid": None,
    }
    metadata["git_before"] = capture_git_snapshot(run_dir, effective_cwd, "before")
    write_metadata(run_dir, metadata)
    append_event(run_dir, {"type": "run_started", "status": "starting", "role": role, "task_type": route["task_type"]})

    env = build_worker_env(
        provider.env,
        selected_model if selected_model != provider.model else route.get("model_override"),
        workspace_root=paths["workspace_root"],
        artifact_root=paths["artifact_root"],
    )
    worker_cmd = [sys.executable, "-B", str(Path(__file__).resolve()), "_stream-worker", "--run-id", run_id]
    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        popen_kwargs["start_new_session"] = True
    with (contextlib.nullcontext() if skip_cost_guard else launch_lock()):
        if not skip_cost_guard:
            timeout = enforce_cost_guard(selected_model, timeout)
            metadata["timeout_seconds"] = timeout
            write_metadata(run_dir, metadata)
        worker = subprocess.Popen(
            worker_cmd,
            cwd=str(ROOT),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            **popen_kwargs,
        )
    metadata.update({"worker_pid": worker.pid, "worker_command": redact(worker_cmd)})
    write_metadata(run_dir, metadata)
    append_event(run_dir, {"type": "stream_worker_started", "worker_pid": worker.pid})
    paths["runs"].mkdir(parents=True, exist_ok=True)
    (paths["runs"] / "latest.txt").write_text(run_id, encoding="utf-8")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    (RUNS_DIR / "latest.txt").write_text(run_id, encoding="utf-8")
    return {
        **metadata,
        "status": "starting",
        "worker_pid": worker.pid,
        "poll": {
            "tool": "cc_poll_run",
            "run_id": run_id,
            "event_offset": 0,
            "stdout_offset": 0,
            "stderr_offset": 0,
        },
    }


def stream_worker(run_id: str) -> dict[str, Any]:
    """Internal worker process. It owns Claude Code pipes for a streaming run."""
    run_dir = safe_run_dir(run_id)
    metadata = update_metadata(run_dir, worker_pid=os.getpid())
    prompt = (run_dir / "prompt.txt").read_text(encoding="utf-8", errors="replace")
    permission_mode = str(metadata.get("permission_mode", "plan"))
    output_format = str(metadata.get("output_format", "stream-json"))
    include_partial_messages = bool(metadata.get("include_partial_messages", True))
    timeout = int(metadata.get("timeout_seconds") or 1800)
    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    cmd = [
        claude_bin_path(),
        "-p",
        "--output-format",
        output_format,
    ]
    if output_format == "stream-json":
        cmd.append("--verbose")
    if include_partial_messages:
        cmd.append("--include-partial-messages")
    cmd.extend(
        [
            "--permission-mode",
            permission_mode,
            "--no-session-persistence",
            prompt,
        ]
    )
    append_event(run_dir, {"type": "stream_worker_ready", "worker_pid": os.getpid()})
    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True
    started = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=force_utf8_env(dict(os.environ)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        **popen_kwargs,
    )
    update_metadata(run_dir, status="running", child_pid=proc.pid, command=redact(cmd))
    (run_dir / "pid.txt").write_text(str(proc.pid), encoding="utf-8")
    append_event(run_dir, {"type": "process_started", "pid": proc.pid, "status": "running"})
    event_lock = threading.Lock()
    budget_lock = threading.Lock()
    budget = output_budget_from_metadata(metadata, run_dir)
    budget_stop = threading.Event()
    actual_route_recorded = threading.Event()
    route_mismatch_recorded = threading.Event()

    def persist_budget_unlocked(stop_reason: str | None = None) -> None:
        latest = read_metadata(run_dir)
        latest["output_budget"] = dict(budget)
        if stop_reason:
            latest["stop_reason"] = stop_reason
        write_metadata(run_dir, latest)

    def trigger_budget(reason: str, source: str) -> None:
        with budget_lock:
            if budget.get("state") in {"stopped", "truncated"}:
                return
            policy_name = str(budget.get("policy") or "stop")
            budget["state"] = "truncated" if policy_name == "truncate" else "stopped"
            budget["stop_reason"] = reason
            budget["triggered_at"] = utc_now_iso()
            budget["triggered_by"] = source
            try:
                budget["events_bytes"] = (run_dir / "events.ndjson").stat().st_size
            except OSError:
                pass
            persist_budget_unlocked(reason)
            if policy_name == "stop":
                budget_stop.set()
        try:
            append_event(run_dir, {"type": "output_budget_exceeded", "reason": reason, "source": source, "policy": budget.get("policy"), "output_budget": budget})
        except Exception:
            pass

    def event_is_final_or_control(event: dict[str, Any]) -> bool:
        if not budget.get("final_only"):
            return True
        payload = event.get("payload")
        if event.get("type") in {"run_started", "process_started", "process_exited", "output_budget_exceeded", "timeout", "stream_worker_ready", "actual_model_usage", "route_mismatch"}:
            return True
        if isinstance(payload, dict):
            event_type = str(payload.get("type") or "")
            subtype = str(payload.get("subtype") or "")
            if event_type == "result" or subtype in {"success", "error"}:
                return True
        return False

    def safe_append(event: dict[str, Any]) -> None:
        if not event_is_final_or_control(event):
            with budget_lock:
                budget["dropped_event_count"] = int(budget.get("dropped_event_count") or 0) + 1
            return
        encoded = (json.dumps(sanitize_for_json(redact(event)), ensure_ascii=False) + "\n").encode("utf-8", errors="replace")
        max_events = budget.get("max_events_bytes")
        events_path = run_dir / "events.ndjson"
        with event_lock:
            current_events = events_path.stat().st_size if events_path.exists() else 0
            if max_events and current_events + len(encoded) > int(max_events):
                with budget_lock:
                    budget["events_bytes"] = current_events
                    budget["dropped_event_count"] = int(budget.get("dropped_event_count") or 0) + 1
                    persist_budget_unlocked("events_budget_exceeded")
                trigger_budget("events_budget_exceeded", str(event.get("source") or event.get("type") or "events"))
                return
            append_event(run_dir, event)
            with budget_lock:
                budget["events_bytes"] = events_path.stat().st_size if events_path.exists() else current_events + len(encoded)

    def record_actual_route(payload: Any) -> None:
        declared_model = (metadata.get("profile") or {}).get("model")
        summary = actual_route_from_payload(payload, declared_model=declared_model)
        if not summary.get("actual_model") and not summary.get("actual_model_usage"):
            return
        update_metadata(
            run_dir,
            actual_route=summary,
            actual_model=summary.get("actual_model"),
            actual_model_usage=summary.get("actual_model_usage"),
            actual_input_tokens=summary.get("actual_input_tokens"),
            actual_output_tokens=summary.get("actual_output_tokens"),
            actual_total_tokens=summary.get("actual_total_tokens"),
            actual_cost_usd=summary.get("actual_cost_usd"),
            route_mismatch=summary.get("route_mismatch"),
        )
        if not actual_route_recorded.is_set():
            actual_route_recorded.set()
            safe_append(
                {
                    "type": "actual_model_usage",
                    "declared_model": summary.get("declared_model"),
                    "actual_model": summary.get("actual_model"),
                    "actual_total_tokens": summary.get("actual_total_tokens"),
                    "actual_cost_usd": summary.get("actual_cost_usd"),
                    "route_mismatch": summary.get("route_mismatch"),
                }
            )
        if summary.get("route_mismatch") and not route_mismatch_recorded.is_set():
            route_mismatch_recorded.set()
            safe_append(
                {
                    "type": "route_mismatch",
                    "severity": "high",
                    "declared_model": summary.get("declared_model"),
                    "actual_model": summary.get("actual_model"),
                    "message": "Claude stream modelUsage does not match the orchestrator-declared route model.",
                }
            )

    def pump(stream: Any, out_path: Path, source: str) -> None:
        try:
            with out_path.open("a", encoding="utf-8", errors="replace") as out:
                for line in iter(stream.readline, ""):
                    raw_bytes = len(line.encode("utf-8", errors="replace"))
                    safe_line = str(redact(line))
                    raw_payload: Any | None = None
                    if source == "stdout":
                        try:
                            raw_payload = json.loads(line)
                            parsed_payload: Any = redact(raw_payload)
                            parsed_event_type = "claude_stream"
                        except json.JSONDecodeError:
                            parsed_payload = {"text": safe_line.rstrip("\r\n")}
                            parsed_event_type = "stdout"
                    else:
                        parsed_payload = {"text": safe_line.rstrip("\r\n")}
                        parsed_event_type = "stderr"
                    if source == "stdout" and isinstance(raw_payload, dict):
                        record_actual_route(raw_payload)
                    event = {"type": parsed_event_type, "source": source, "payload": parsed_payload}
                    if budget.get("final_only") and not event_is_final_or_control(event):
                        with budget_lock:
                            budget["observed_output_bytes"] = int(budget.get("observed_output_bytes") or 0) + raw_bytes
                            budget["dropped_output_bytes"] = int(budget.get("dropped_output_bytes") or 0) + raw_bytes
                        continue
                    if budget.get("final_only") and isinstance(parsed_payload, dict) and parsed_payload.get("type") == "result" and parsed_payload.get("result") is not None:
                        safe_line = str(redact(str(parsed_payload.get("result")))).rstrip("\r\n") + "\n"
                    safe_line_bytes = len(safe_line.encode("utf-8", errors="replace"))
                    write_line = True
                    with budget_lock:
                        budget["observed_output_bytes"] = int(budget.get("observed_output_bytes") or 0) + raw_bytes
                        projected_written = int(budget.get("written_output_bytes") or 0) + safe_line_bytes
                        soft = budget.get("soft_output_bytes")
                        if soft and projected_written > int(soft) and budget.get("state") == "within_budget":
                            budget["state"] = "soft_exceeded"
                            budget["triggered_at"] = utc_now_iso()
                            budget["triggered_by"] = source
                            persist_budget_unlocked()
                        hard = budget.get("max_output_bytes")
                        if hard and projected_written > int(hard):
                            budget["dropped_output_bytes"] = int(budget.get("dropped_output_bytes") or 0) + safe_line_bytes
                            write_line = False
                    if not write_line:
                        trigger_budget("output_budget_exceeded", source)
                        continue
                    out.write(safe_line)
                    out.flush()
                    with budget_lock:
                        budget["written_output_bytes"] = int(budget.get("written_output_bytes") or 0) + safe_line_bytes
                    payload = parsed_payload
                    event_type = parsed_event_type
                    phase = extract_event_phase(payload, source)
                    event = {"type": event_type, "source": source, "payload": payload}
                    if phase:
                        event["phase"] = phase
                    safe_append(event)
                    if budget_stop.is_set():
                        break
        except Exception as exc:
            safe_append({"type": "stream_pump_error", "source": source, "error": str(exc)})

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, run_dir / "stdout.txt", "stdout"), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, run_dir / "stderr.txt", "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    stopped = False
    exit_code: int | None = None
    try:
        while True:
            exit_code = proc.poll()
            if exit_code is not None:
                break
            if (run_dir / "stop-requested.json").exists():
                stopped = True
                terminate_process_tree(proc.pid, force=False, wait_seconds=5)
            if budget_stop.is_set():
                stopped = True
                terminate_process_tree(proc.pid, force=False, wait_seconds=5)
                if pid_alive(proc.pid):
                    terminate_process_tree(proc.pid, force=True, wait_seconds=2)
            if time.time() - started > timeout:
                timed_out = True
                safe_append({"type": "timeout", "timeout_seconds": timeout})
                with budget_lock:
                    budget["stop_reason"] = "timeout"
                    persist_budget_unlocked("timeout")
                terminate_process_tree(proc.pid, force=False, wait_seconds=5)
                if pid_alive(proc.pid):
                    terminate_process_tree(proc.pid, force=True, wait_seconds=2)
            time.sleep(0.2)
        try:
            exit_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_process_tree(proc.pid, force=True, wait_seconds=2)
            exit_code = proc.poll()
    finally:
        for thread in threads:
            thread.join(timeout=2)

    duration_ms = int((time.time() - started) * 1000)
    latest_metadata = read_metadata(run_dir)
    stopped = stopped or bool(latest_metadata.get("stop_requested_at"))
    if timed_out:
        status = "timed_out"
        final_exit = 124 if exit_code is None else exit_code
    elif stopped:
        status = "stopped"
        final_exit = -15 if exit_code is None else exit_code
    else:
        final_exit = 0 if exit_code is None else exit_code
        status = "succeeded" if final_exit == 0 else "failed"
    with budget_lock:
        budget.update(output_budget_from_metadata({"output_budget": budget}, run_dir))
        if stopped and not budget.get("stop_reason"):
            budget["stop_reason"] = "user_requested"
        persist_budget_unlocked(str(budget.get("stop_reason") or "") or None)
    final_metadata = update_metadata(
        run_dir,
        status=status,
        finished_at=utc_now_iso(),
        duration_ms=duration_ms,
        exit_code=final_exit,
        timed_out=timed_out,
        stdout_path=str(run_dir / "stdout.txt"),
        stderr_path=str(run_dir / "stderr.txt"),
        events_path=str(run_dir / "events.ndjson"),
        output_budget=budget,
        stop_reason=budget.get("stop_reason") or ("timeout" if timed_out else "user_requested" if stopped else None),
        git_after=capture_git_snapshot(run_dir, cwd, "after"),
    )
    scope_check = check_write_scope(run_id=run_id)
    final_metadata = update_metadata(
        run_dir,
        write_scope_check=scope_check,
        acceptance_status="blocked_write_scope" if not scope_check.get("ok", True) else "pending_controller_review",
    )
    if not scope_check.get("ok", True):
        append_event(run_dir, {"type": "write_scope_blocked", "status": "blocked", "violations": scope_check.get("violations", [])})
    append_event(run_dir, {"type": "process_exited", "status": status, "exit_code": final_exit, "duration_ms": duration_ms})
    return final_metadata


def single_run_status(run_id: str, include_output_tail: bool = True, tail_chars: int = 4000) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    status = str(metadata.get("status") or "unknown")
    child_pid = metadata.get("child_pid")
    worker_pid = metadata.get("worker_pid")
    child_alive = pid_alive(int(child_pid)) if child_pid else False
    worker_alive = pid_alive(int(worker_pid)) if worker_pid else False
    active = status in {"starting", "running", "stop_requested"} and (child_alive or worker_alive)
    if status in {"starting", "running", "stop_requested"} and not active:
        if metadata.get("finished_at") or metadata.get("exit_code") is not None:
            exit_code = metadata.get("exit_code")
            if status == "stop_requested":
                status = "stopped"
            elif metadata.get("timed_out"):
                status = "timed_out"
            else:
                status = "succeeded" if exit_code == 0 else "failed"
        elif metadata.get("stop_reason") in {"output_budget_exceeded", "events_budget_exceeded", "user_requested"}:
            status = "stopped"
        else:
            status = "lost"
    started_at = metadata.get("started_at")
    finished_at = metadata.get("finished_at")
    elapsed_ms = metadata.get("duration_ms")
    if elapsed_ms is None and started_at:
        try:
            started_dt = datetime.fromisoformat(str(started_at))
            end_dt = datetime.fromisoformat(str(finished_at)) if finished_at else datetime.now(timezone.utc)
            elapsed_ms = int((end_dt - started_dt).total_seconds() * 1000)
        except Exception:
            elapsed_ms = None
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    events_path = run_dir / "events.ndjson"
    event_tail = tail_file(events_path, chars=20000)
    events: list[dict[str, Any]] = []
    for line in event_tail.splitlines()[-200:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    event_summary = summarize_events(events)
    stdout_tail = tail_file(stdout_path, chars=tail_chars)
    stderr_tail = tail_file(stderr_path, chars=min(tail_chars, 2000))
    stdout_bytes = stdout_path.stat().st_size if stdout_path.exists() else 0
    stderr_bytes = stderr_path.stat().st_size if stderr_path.exists() else 0
    events_bytes = events_path.stat().st_size if events_path.exists() else 0
    prompt_path = run_dir / "prompt.txt"
    prompt_text = prompt_path.read_text(encoding="utf-8", errors="replace") if prompt_path.exists() else ""
    input_tokens_est = max(0, int(len(prompt_text) / 4))
    output_tokens_est = max(0, int((stdout_bytes + stderr_bytes) / 4))
    output_budget = output_budget_from_metadata(metadata, run_dir)
    route_drift = route_drift_summary(metadata)
    actual_route = actual_route_summary(metadata)
    result = {
        "ok": True,
        "run_id": run_id,
        "status": status,
        "active": active,
        "worker_pid": worker_pid,
        "child_pid": child_pid,
        "worker_alive": worker_alive,
        "child_alive": child_alive,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "exit_code": metadata.get("exit_code"),
        "timed_out": bool(metadata.get("timed_out", False)),
        "stop_reason": metadata.get("stop_reason") or output_budget.get("stop_reason"),
        "role": metadata.get("role"),
        "task_type": metadata.get("task_type"),
        "profile": metadata.get("profile"),
        "route": metadata.get("route"),
        "route_drift": route_drift,
        "actual_route": actual_route,
        "actual_model": actual_route.get("actual_model"),
        "actual_model_usage": actual_route.get("actual_model_usage"),
        "route_mismatch": actual_route.get("route_mismatch"),
        "latest_phase": event_summary.get("latest_phase"),
        "tool_calls": event_summary.get("tool_calls", []),
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "events_bytes": events_bytes,
        "input_tokens_est": input_tokens_est,
        "output_tokens_est": output_tokens_est,
        "total_tokens_est": input_tokens_est + output_tokens_est,
        "output_budget": output_budget,
        "last_stdout_line": last_nonempty_line(stdout_tail),
        "last_stderr_line": last_nonempty_line(stderr_tail),
        "paths": {
            "run_dir": str(run_dir),
            "metadata": str(run_dir / "metadata.json"),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
            "events": str(events_path),
        },
    }
    if include_output_tail:
        result["stdout_tail"] = stdout_tail
        result["stderr_tail"] = stderr_tail
    return result


def run_status(
    run_id: str | None = None,
    include_output_tail: bool = False,
    tail_chars: int = 4000,
    include_finished: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if run_id:
        return single_run_status(run_id, include_output_tail=include_output_tail, tail_chars=tail_chars)
    runs: list[dict[str, Any]] = []
    candidates = known_run_dirs()
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            item = single_run_status(path.name, include_output_tail=include_output_tail, tail_chars=tail_chars)
        except Exception:
            continue
        if include_finished or item.get("active"):
            runs.append(item)
        if len(runs) >= limit:
            break
    return {
        "ok": True,
        "active_count": sum(1 for item in runs if item.get("active")),
        "count": len(runs),
        "runs": runs,
    }


def poll_run(
    run_id: str,
    stdout_offset: int = 0,
    stderr_offset: int = 0,
    event_offset: int = 0,
    max_bytes: int = 20000,
    include_output_tail: bool = True,
    tail_chars: int = 4000,
    mode: str = "raw",
    max_events: int = 20,
    max_summary_chars: int = 2000,
    write_artifacts: bool = True,
) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    status = single_run_status(run_id, include_output_tail=include_output_tail, tail_chars=tail_chars)
    if mode == "controller":
        summary = summarize_run(
            run_id,
            event_offset=event_offset,
            max_bytes=max_bytes,
            max_events=max_events,
            max_summary_chars=max_summary_chars,
            write_artifacts=write_artifacts,
        )
        return {
            "ok": True,
            "run_id": run_id,
            "mode": "controller",
            "status": status,
            "offsets": summary.get("offsets", {}),
            "progress_summary": summary.get("progress_summary"),
            "risk_flags": summary.get("risk_flags"),
            "changed_files": summary.get("changed_files"),
            "tool_timeline": summary.get("tool_timeline"),
            "checkpoint": summary.get("checkpoint"),
            "artifact_paths": summary.get("artifact_paths", {}),
        }
    if mode != "raw":
        raise OrchestratorError("poll_run mode must be 'raw' or 'controller'.")
    stdout_delta = read_file_delta(run_dir / "stdout.txt", offset=stdout_offset, max_bytes=max_bytes)
    stderr_delta = read_file_delta(run_dir / "stderr.txt", offset=stderr_offset, max_bytes=max_bytes)
    events_delta = parse_events_delta(run_dir / "events.ndjson", offset=event_offset, max_bytes=max_bytes)
    event_summary = summarize_events(events_delta["events"])
    return {
        "ok": True,
        "run_id": run_id,
        "status": status,
        "stdout": stdout_delta,
        "stderr": stderr_delta,
        "events": {
            "path": events_delta["path"],
            "offset": events_delta["offset"],
            "next_offset": events_delta["next_offset"],
            "size": events_delta["size"],
            "truncated": events_delta["truncated"],
            "items": events_delta["events"],
        },
        "latest_phase": event_summary.get("latest_phase") or status.get("latest_phase"),
        "tool_calls": event_summary.get("tool_calls") or status.get("tool_calls", []),
    }


def stop_run(run_id: str, force: bool = False, timeout_seconds: int = 5) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    status = single_run_status(run_id, include_output_tail=False)
    if not status.get("active"):
        final_status = status.get("status")
        return {
            "ok": True,
            "run_id": run_id,
            "previous_status": final_status,
            "status": "already_stopped" if final_status == "stopped" else "already_finished",
            "active": False,
            "exit_code": status.get("exit_code"),
        }
    requested_at = utc_now_iso()
    (run_dir / "stop-requested.json").write_text(json.dumps({"requested_at": requested_at, "force": force}, ensure_ascii=False), encoding="utf-8")
    update_metadata(run_dir, status="stop_requested", stop_requested_at=requested_at, stop_reason="user_requested")
    append_event(run_dir, {"type": "stop_requested", "force": force})
    results: list[dict[str, Any]] = []
    child_pid = status.get("child_pid")
    worker_pid = status.get("worker_pid")
    if child_pid:
        results.append(terminate_process_tree(int(child_pid), force=force, wait_seconds=timeout_seconds))
    refreshed = single_run_status(run_id, include_output_tail=False)
    if refreshed.get("active") and worker_pid:
        results.append(terminate_process_tree(int(worker_pid), force=True if force else False, wait_seconds=timeout_seconds))
    final = single_run_status(run_id, include_output_tail=False)
    stopped = not final.get("active")
    stopped_at = utc_now_iso()
    if stopped:
        update_metadata(run_dir, status="stopped", stopped_at=stopped_at, finished_at=stopped_at, exit_code=final.get("exit_code") if final.get("exit_code") is not None else -15, stop_reason="user_requested")
        append_event(run_dir, {"type": "stopped", "status": "stopped"})
        final = single_run_status(run_id, include_output_tail=False)
    return {
        "ok": True,
        "run_id": run_id,
        "previous_status": status.get("status"),
        "status": final.get("status"),
        "active": final.get("active"),
        "force": force,
        "stopped": stopped,
        "stop_results": results,
    }


def read_team_manifest(team_id: str) -> dict[str, Any]:
    if not TEAM_ID_RE.match(team_id):
        raise OrchestratorError(f"Invalid team id: {team_id}")
    path = TEAMS_DIR / f"{team_id}.json"
    if not path.exists():
        raise OrchestratorError(f"Team manifest not found: {team_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_team_manifest(team_id: str, data: dict[str, Any]) -> Path:
    TEAMS_DIR.mkdir(parents=True, exist_ok=True)
    path = TEAMS_DIR / f"{team_id}.json"
    return write_json_file(path, data)


def send_instruction(
    run_id: str,
    instruction: str,
    force: bool = False,
    role: str | None = None,
    task_type: str | None = None,
    timeout_seconds: int | None = None,
    preserve_route: bool = True,
    reroute: bool = False,
    route_profile: str | None = None,
    route_model: str | None = None,
) -> dict[str, Any]:
    """Append instruction by stopping the run and restarting with recovered context."""
    if not instruction.strip():
        raise OrchestratorError("Instruction cannot be empty.")
    previous = poll_run(run_id, max_bytes=50000, include_output_tail=True)
    status = previous["status"]
    if status.get("active"):
        stop = stop_run(run_id, force=force, timeout_seconds=5)
    else:
        stop = {"ok": True, "status": "already_finished"}
    metadata = read_metadata(safe_run_dir(run_id))
    run_dir = safe_run_dir(run_id)
    original_prompt = (run_dir / "prompt.txt").read_text(encoding="utf-8", errors="replace") if (run_dir / "prompt.txt").exists() else ""
    events_tail = tail_file(run_dir / "events.ndjson", chars=12000)
    context = "\n".join(
        [
            f"Previous run id: {run_id}",
            f"Previous status: {status.get('status')}",
            f"Previous role: {metadata.get('role')}",
            f"Previous task type: {metadata.get('task_type')}",
            f"Previous cwd: {metadata.get('cwd')}",
            f"Previous model: {(metadata.get('profile') or {}).get('model')}",
            "",
            "Original prompt:",
            original_prompt[-12000:],
            "",
            "Previous stdout tail:",
            str(status.get("stdout_tail", ""))[-10000:],
            "",
            "Previous stderr tail:",
            str(status.get("stderr_tail", ""))[-4000:],
            "",
            "Previous stream events tail:",
            events_tail[-12000:],
            "",
            "New instruction:",
            instruction.strip(),
            "",
            "Recovery rules:",
            "- Treat this as a resumed run, not a fresh unrelated task.",
            "- Do not repeat work that the previous run clearly completed.",
            "- If prior context is ambiguous, state the uncertainty before acting.",
            "- Preserve the previous write scope and safety rules.",
        ]
    )
    task = "Continue the previous Claude Code worker run using the new instruction. Preserve useful context, avoid repeating completed work, and report what changed."
    previous_profile = (metadata.get("profile") or {}).get("name")
    previous_model = (metadata.get("profile") or {}).get("model")
    selected_profile = route_profile or (previous_profile if preserve_route and not reroute else None)
    selected_model = route_model or (previous_model if preserve_route and not reroute else None)
    new_run = run_streaming_agent(
        task=task,
        role=role or str(metadata.get("role") or "implementation"),
        task_type=task_type or metadata.get("task_type"),
        profile=selected_profile,
        model_override=selected_model,
        allow_write=bool(metadata.get("allow_write", False)),
        timeout_seconds=timeout_seconds or metadata.get("timeout_seconds"),
        cwd=Path(str(metadata.get("cwd") or Path.cwd())),
        context=context,
        max_output_bytes=(metadata.get("output_budget") or {}).get("max_output_bytes"),
        max_events_bytes=(metadata.get("output_budget") or {}).get("max_events_bytes"),
        soft_output_bytes=(metadata.get("output_budget") or {}).get("soft_output_bytes"),
        output_budget_policy=(metadata.get("output_budget") or {}).get("policy"),
        final_only=bool((metadata.get("output_budget") or {}).get("final_only", False)),
        final_max_chars=(metadata.get("output_budget") or {}).get("final_max_chars"),
    )
    new_profile = (new_run.get("profile") or {}).get("name")
    new_model = (new_run.get("profile") or {}).get("model")
    route_drift = {
        "previous_profile": previous_profile,
        "previous_model": previous_model,
        "current_profile": new_profile,
        "current_model": new_model,
        "route_changed": previous_profile != new_profile or previous_model != new_model,
        "route_change_reason": "explicit_reroute" if reroute or route_profile or route_model else "preserve_route",
        "preserve_route": preserve_route,
    }
    update_metadata(safe_run_dir(str(new_run["run_id"])), parent_run_id=run_id, route_drift=route_drift)
    new_run["route_drift"] = route_drift
    return {"ok": True, "old_run_id": run_id, "stop": stop, "new_run": new_run, "route_drift": route_drift}


def spawn_role_team(
    task: str,
    roles: list[str] | None = None,
    cwd: Path | None = None,
    context: str | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    selected_roles = roles or ["requirements", "architecture", "security", "testing"]
    if not selected_roles:
        raise OrchestratorError("At least one role is required.")
    team_id = "team-" + new_run_id()
    runs: list[dict[str, Any]] = []
    rollback: dict[str, Any] | None = None
    active_before = 0
    max_concurrent = max_concurrent_limit()
    with launch_lock():
        active_before = int(run_status(include_finished=False).get("active_count") or 0)
        requested_count = len(selected_roles)
        if active_before + requested_count > max_concurrent:
            manifest = {
                "team_id": team_id,
                "created_at": utc_now_iso(),
                "status": "blocked_by_cost_guard",
                "task": task,
                "cwd": str(cwd or Path.cwd()),
                "roles": selected_roles,
                "runs": [],
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": requested_count,
                "rollback": {"attempted": False, "stops": []},
            }
            path = write_team_manifest(team_id, manifest)
            return {
                "ok": False,
                "status": "blocked_by_cost_guard",
                "error": f"Cost guard blocked team: active workers {active_before} + requested {requested_count} > max_concurrent {max_concurrent}.",
                "team_id": team_id,
                "manifest_path": str(path),
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": requested_count,
                "launched_count": 0,
                "runs": [],
                "rollback": manifest["rollback"],
            }
        try:
            for role in selected_roles:
                run = run_streaming_agent(
                    task=task,
                    role=role,
                    cwd=cwd,
                    context="\n".join(part for part in [f"Team id: {team_id}", context or ""] if part),
                    timeout_seconds=timeout_seconds,
                    skip_cost_guard=True,
                )
                update_metadata(safe_run_dir(str(run["run_id"])), team_id=team_id)
                runs.append({"role": role, "run_id": run["run_id"], "status": run["status"], "profile": run.get("profile")})
        except Exception as exc:
            stops = []
            for item in runs:
                try:
                    stop = stop_run(str(item["run_id"]), force=True, timeout_seconds=5)
                except Exception as stop_exc:
                    stop = {"ok": False, "error": str(stop_exc), "run_id": item.get("run_id")}
                stops.append(stop)
            failed_stop_count = sum(1 for item in stops if bool(item.get("active")) or not item.get("stopped", True) or not item.get("ok", True))
            rollback = {
                "attempted": True,
                "force": True,
                "stopped_count": len(stops) - failed_stop_count,
                "failed_stop_count": failed_stop_count,
                "stops": stops,
            }
            status_name = "rollback_incomplete" if failed_stop_count else "rolled_back_partial_launch"
            manifest = {
                "team_id": team_id,
                "created_at": utc_now_iso(),
                "status": status_name,
                "error": str(exc),
                "task": task,
                "cwd": str(cwd or Path.cwd()),
                "roles": selected_roles,
                "runs": runs,
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": len(selected_roles),
                "rollback": rollback,
            }
            path = write_team_manifest(team_id, manifest)
            return {
                "ok": False,
                "status": status_name,
                "team_id": team_id,
                "manifest_path": str(path),
                "error": str(exc),
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": len(selected_roles),
                "launched_count": len(runs),
                "runs": runs,
                "rollback": rollback,
            }
    manifest = {
        "team_id": team_id,
        "created_at": utc_now_iso(),
        "status": "launched",
        "task": task,
        "cwd": str(cwd or Path.cwd()),
        "roles": selected_roles,
        "runs": runs,
        "active_before": active_before,
        "max_concurrent": max_concurrent,
        "requested_count": len(selected_roles),
        "rollback": rollback,
    }
    path = write_team_manifest(team_id, manifest)
    return {
        "ok": True,
        "status": "launched",
        "team_id": team_id,
        "manifest_path": str(path),
        "active_before": active_before,
        "max_concurrent": max_concurrent,
        "requested_count": len(selected_roles),
        "launched_count": len(runs),
        "runs": runs,
        "rollback": rollback,
    }


def resolve_team_run_ids(team_id: str | None = None, run_ids: list[str] | None = None) -> list[str]:
    ids = list(run_ids or [])
    if team_id:
        manifest = read_team_manifest(team_id)
        ids.extend(str(item["run_id"]) for item in manifest.get("runs", []) if item.get("run_id"))
    if not ids:
        raise OrchestratorError("Provide team_id or run_ids.")
    seen: set[str] = set()
    unique: list[str] = []
    for run_id in ids:
        safe_run_dir(run_id)
        if run_id not in seen:
            seen.add(run_id)
            unique.append(run_id)
    return unique


def extract_signal_lines(text: str, limit: int = 60) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip(" -*\t")
        if len(line) < 8 or len(line) > 220:
            continue
        if any(token in line.lower() for token in ("error", "risk", "bug", "todo", "conflict", "agree", "recommend", "建议", "风险", "冲突", "一致", "结论")):
            lines.append(line)
        elif raw.lstrip().startswith(("-", "*", "1.", "2.", "3.")):
            lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def collect_team_results(team_id: str | None = None, run_ids: list[str] | None = None, tail_chars: int = 8000) -> dict[str, Any]:
    ids = resolve_team_run_ids(team_id, run_ids)
    items: list[dict[str, Any]] = []
    line_counts: dict[str, int] = {}
    conflict_lines: list[str] = []
    for run_id in ids:
        status = single_run_status(run_id, include_output_tail=True, tail_chars=tail_chars)
        text = str(status.get("stdout_tail", ""))
        signals = extract_signal_lines(text)
        for line in signals:
            key = re.sub(r"\s+", " ", line.lower())
            line_counts[key] = line_counts.get(key, 0) + 1
            if any(token in key for token in ("conflict", "risk", "blocked", "error", "冲突", "风险", "错误", "阻塞")):
                conflict_lines.append(line)
        items.append({"run_id": run_id, "role": status.get("role"), "status": status.get("status"), "active": status.get("active"), "signals": signals[:20]})
    agreements = [line for line, count in line_counts.items() if count > 1][:20]
    report_lines = ["# Team Results", ""]
    if team_id:
        report_lines.append(f"Team: `{team_id}`")
        report_lines.append("")
    report_lines.append("## Runs")
    for item in items:
        report_lines.append(f"- `{item['run_id']}` role `{item.get('role')}` status `{item.get('status')}` active `{item.get('active')}`")
    report_lines.extend(["", "## Agreements"])
    report_lines.extend(f"- {line}" for line in agreements) if agreements else report_lines.append("- No repeated agreement lines detected; controller review required.")
    report_lines.extend(["", "## Conflicts / Risks"])
    report_lines.extend(f"- {line}" for line in conflict_lines[:20]) if conflict_lines else report_lines.append("- No explicit conflict/risk markers detected.")
    return {"ok": True, "team_id": team_id, "run_ids": ids, "items": items, "agreements": agreements, "conflicts": conflict_lines[:20], "report": "\n".join(report_lines)}


def cross_review(
    run_ids: list[str],
    reviewer_roles: list[str] | None = None,
    cwd: Path | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ids = resolve_team_run_ids(run_ids=run_ids)
    roles = reviewer_roles or ["security", "testing", "review"]
    bundle_lines = ["Review these previous worker outputs. Focus on contradictions, missed risks, and acceptance blockers.", ""]
    for run_id in ids:
        status = single_run_status(run_id, include_output_tail=True, tail_chars=6000)
        bundle_lines.extend([f"## Run {run_id} / role {status.get('role')} / status {status.get('status')}", str(status.get("stdout_tail", ""))[-6000:], ""])
    task = "Cross-review prior Claude Code worker outputs and produce second-round findings ordered by severity."
    spawned: list[dict[str, Any]] = []
    for role in roles:
        run = run_streaming_agent(task=task, role=role, cwd=cwd, context="\n".join(bundle_lines), timeout_seconds=timeout_seconds)
        spawned.append({"reviewer_role": role, "run_id": run["run_id"], "status": run["status"], "profile": run.get("profile")})
    return {"ok": True, "source_run_ids": ids, "review_runs": spawned}


def preflight_write_scope(
    cwd: Path | None = None,
    allowed_paths: list[str] | None = None,
    denied_paths: list[str] | None = None,
    max_diff_lines: int = 800,
) -> dict[str, Any]:
    root = (cwd or Path.cwd()).resolve()
    if not root.exists():
        raise OrchestratorError(f"cwd does not exist: {root}")
    def normalize(items: list[str] | None) -> list[str]:
        result: list[str] = []
        for item in items or []:
            candidate = (root / item).resolve()
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise OrchestratorError(f"Path is outside cwd: {item}") from exc
            result.append(str(candidate))
        return result
    data = {
        "created_at": utc_now_iso(),
        "cwd": str(root),
        "allowed_paths": normalize(allowed_paths),
        "denied_paths": normalize(denied_paths),
        "max_diff_lines": max_diff_lines,
        "rules": [
            "Claude Code may only edit allowed_paths.",
            "Claude Code must never edit denied_paths.",
            "Codex must review git diff before accepting changes.",
        ],
    }
    scope_dir = root / ".claude-code-orchestrator"
    scope_dir.mkdir(parents=True, exist_ok=True)
    path = scope_dir / "write-scope.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(path), "scope": data}


def load_write_scope(cwd: Path) -> tuple[Path, dict[str, Any] | None]:
    path = cwd.resolve() / ".claude-code-orchestrator" / "write-scope.json"
    if not path.exists():
        return path, None
    return path, json.loads(path.read_text(encoding="utf-8"))


def path_under(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def count_diff_changed_lines(diff_text: str) -> int:
    count = 0
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            count += 1
        elif line.startswith("-") and not line.startswith("---"):
            count += 1
    return count


def check_write_scope(run_id: str | None = None, cwd: Path | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    run_dir: Path | None = None
    if run_id:
        run_dir = safe_run_dir(run_id)
        metadata = read_metadata(run_dir)
        root = Path(str(metadata.get("cwd") or cwd or Path.cwd())).resolve()
    else:
        root = (cwd or Path.cwd()).resolve()
    scope_path, scope = load_write_scope(root)
    if not scope:
        return {
            "ok": True,
            "status": "no_scope",
            "run_id": run_id,
            "cwd": str(root),
            "scope_path": str(scope_path),
            "message": "No write-scope file found; Codex must review diff manually.",
            "violations": [],
        }

    before = metadata.get("git_before") or {}
    after = metadata.get("git_after") or {}
    if run_id and before and after:
        changed_paths = changed_paths_between_snapshots(before, after)
    elif (root / ".git").exists():
        changed_paths = current_git_changed_paths(root)
    else:
        changed_paths = []

    allowed = [Path(item).resolve() for item in scope.get("allowed_paths", []) or []]
    denied = [Path(item).resolve() for item in scope.get("denied_paths", []) or []]
    violations: list[dict[str, Any]] = []
    checked: list[str] = []
    for rel in changed_paths:
        normalized = rel.replace("\\", "/").strip("/")
        if not normalized:
            continue
        if normalized == ".claude-code-orchestrator" or normalized.startswith(".claude-code-orchestrator/"):
            if run_id and normalized == ".claude-code-orchestrator/write-scope.json":
                violations.append({"path": normalized, "type": "internal_scope_modified", "message": "The run changed the write-scope file itself."})
            continue
        candidate = (root / normalized).resolve()
        if safe_relative(root, candidate) is None:
            violations.append({"path": normalized, "type": "outside_workspace", "message": "Changed path resolves outside cwd."})
            continue
        checked.append(normalized)
        if allowed and not any(path_under(candidate, base) or candidate == base for base in allowed):
            violations.append({"path": normalized, "type": "outside_allowed_paths", "message": "Changed path is not under allowed_paths."})
        if any(path_under(candidate, base) or candidate == base for base in denied):
            violations.append({"path": normalized, "type": "denied_path", "message": "Changed path is under denied_paths."})

    max_diff_lines = int(scope.get("max_diff_lines") or 0)
    diff_lines = 0
    diff_source = "current"
    if after.get("diff_path") and Path(str(after["diff_path"])).exists():
        diff_lines = count_diff_changed_lines(Path(str(after["diff_path"])).read_text(encoding="utf-8", errors="replace"))
        diff_source = "run_after_snapshot"
    elif (root / ".git").exists():
        diff_lines = count_diff_changed_lines(str(git_diff(cwd=root, limit_chars=1_000_000).get("diff", "")))
    if max_diff_lines and diff_lines > max_diff_lines:
        violations.append({"type": "max_diff_lines", "diff_lines": diff_lines, "limit": max_diff_lines, "message": "Diff is larger than the preflight max_diff_lines."})

    ok = not violations
    rollback_hint = None
    if not ok:
        rollback_hint = (
            f"Review diff first, then run: python {Path(__file__).name} rollback-run --run-id {run_id} --confirm"
            if run_id
            else "Review diff and revert only the violating files."
        )
    return {
        "ok": ok,
        "status": "passed" if ok else "blocked",
        "run_id": run_id,
        "cwd": str(root),
        "scope_path": str(scope_path),
        "checked_paths": checked,
        "changed_paths": changed_paths,
        "violation_count": len(violations),
        "violations": violations,
        "diff_lines": diff_lines,
        "diff_source": diff_source,
        "max_diff_lines": max_diff_lines,
        "rollback_recommendation": rollback_hint,
    }


def diff_summary(cwd: Path | None = None, limit_chars: int = 200000) -> dict[str, Any]:
    diff = git_diff(cwd=cwd, limit_chars=limit_chars)
    text = diff.get("diff", "")
    files: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            current = parts[-1][2:] if len(parts) >= 4 and parts[-1].startswith("b/") else parts[-1] if parts else None
            if current:
                files.setdefault(current, {"added": 0, "deleted": 0, "risk": []})
        elif current and line.startswith("+") and not line.startswith("+++"):
            files[current]["added"] += 1
        elif current and line.startswith("-") and not line.startswith("---"):
            files[current]["deleted"] += 1
    risk_keywords = {
        "package": "dependency/package metadata changed",
        "lock": "lockfile changed",
        "config": "configuration changed",
        "auth": "auth-sensitive path",
        "secret": "secret-sensitive path",
        "server": "runtime server path",
        "workflow": "CI workflow changed",
    }
    for file, info in files.items():
        lower = file.lower()
        for key, reason in risk_keywords.items():
            if key in lower:
                info["risk"].append(reason)
    total_added = sum(item["added"] for item in files.values())
    total_deleted = sum(item["deleted"] for item in files.values())
    needs_tests = bool(files) and (total_added + total_deleted > 20 or any(item["risk"] for item in files.values()))
    cwd_path = Path(str(diff.get("cwd") or cwd or Path.cwd()))
    change_split = classify_change_paths(cwd_path, list(files.keys()))
    return {
        "ok": diff.get("ok", False),
        "cwd": diff.get("cwd"),
        "file_count": len(files),
        "total_added": total_added,
        "total_deleted": total_deleted,
        "files": files,
        **change_split,
        "risks": [f"{file}: {', '.join(info['risk'])}" for file, info in files.items() if info["risk"]],
        "needs_tests": needs_tests,
        "truncated": diff.get("truncated", False),
    }


def classify_secret_line(line: str, source: str, lineno: int) -> dict[str, Any] | None:
    has_secret_value = bool(SECRET_VALUE_RE.search(line) or SECRET_ASSIGN_RE.search(line))
    has_secret_name = bool(SECRET_NAME_RE.search(line))
    lower_source = source.lower()
    placeholder = bool(PLACEHOLDER_SECRET_RE.search(line) or any(token in lower_source for token in (".env.example", "example", "fixture", "mock")))
    if has_secret_value:
        classification = "placeholder_or_example" if placeholder else "real_secret_candidate"
        severity = "low" if placeholder else "critical"
        confidence = "high"
    elif has_secret_name:
        stripped = line.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\s*[:=]\s*)?", stripped):
            classification = "config_key_name"
            severity = "low"
            confidence = "high"
        elif "process.env" in line or "os.environ" in line or "getenv" in line or re.search(r"(?i)\b(env|config|setting)s?\b", line):
            classification = "identifier_only"
            severity = "low"
            confidence = "medium"
        else:
            classification = "unknown_needs_review"
            severity = "medium"
            confidence = "medium"
    else:
        return None
    return {
        "source": source,
        "line": lineno,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "blocking": classification in {"real_secret_candidate", "unknown_needs_review"} and severity in BLOCKING_SEVERITIES,
        "snippet_redacted": str(redact(line))[:500],
    }


def secret_scan_text(text: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        finding = classify_secret_line(line, source, lineno)
        if finding:
            findings.append(finding)
    return findings


def secret_scan_run(run_id: str, include_diff: bool = True) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    findings: list[dict[str, Any]] = []
    for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
        path = run_dir / name
        if path.exists():
            findings.extend(secret_scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path)))
    if include_diff:
        cwd = Path(str(metadata.get("cwd") or Path.cwd()))
        if (cwd / ".git").exists():
            diff = git_diff(cwd=cwd, limit_chars=300000)
            findings.extend(secret_scan_text(str(diff.get("diff", "")), f"git-diff:{cwd}"))
    classification_counts: dict[str, int] = {}
    max_severity = "none"
    blocking_count = 0
    for item in findings:
        classification = str(item.get("classification") or "unknown_needs_review")
        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        severity = str(item.get("severity") or "low")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = severity
        if item.get("blocking"):
            blocking_count += 1
    return {
        "ok": blocking_count == 0,
        "run_id": run_id,
        "finding_count": len(findings),
        "blocking_count": blocking_count,
        "max_severity": max_severity,
        "classification_counts": classification_counts,
        "findings": findings[:100],
    }


def rollback_run(run_id: str, confirm: bool = False) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    before = metadata.get("git_before") or {}
    after = metadata.get("git_after") or {}
    before_diff = Path(before.get("diff_path", "")) if before.get("diff_path") else None
    after_diff = Path(after.get("diff_path", "")) if after.get("diff_path") else None
    if not before.get("is_git_repo") or not (cwd / ".git").exists():
        return {"ok": False, "run_id": run_id, "error": "Rollback requires a git repository snapshot."}
    if not before_diff or not before_diff.exists() or not after_diff or not after_diff.exists():
        return {"ok": False, "run_id": run_id, "error": "Missing before/after git snapshots for this run."}
    if before_diff.read_text(encoding="utf-8", errors="replace").strip():
        return {
            "ok": False,
            "run_id": run_id,
            "error": "Pre-run worktree was dirty. Automated rollback is refused to avoid reverting unrelated user changes.",
            "before_diff_path": str(before_diff),
            "after_diff_path": str(after_diff),
        }
    if not confirm:
        return {
            "ok": False,
            "run_id": run_id,
            "requires_confirm": True,
            "message": "Pre-run diff was empty. Pass confirm=true to apply reverse patch for the post-run diff.",
            "after_diff_path": str(after_diff),
        }
    backup_path = run_dir / f"rollback-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.diff"
    current = subprocess.run(["git", "diff", "--binary", "--", "."], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    backup_path.write_text(str(redact(current.stdout or current.stderr or "")), encoding="utf-8")
    proc = subprocess.run(["git", "apply", "-R", str(after_diff)], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    return {
        "ok": proc.returncode == 0,
        "run_id": run_id,
        "exit_code": proc.returncode,
        "backup_path": str(backup_path),
        "stdout": str(redact(proc.stdout or ""))[-2000:],
        "stderr": str(redact(proc.stderr or ""))[-2000:],
    }


def load_cost_guard() -> dict[str, Any]:
    if COST_GUARD_PATH.exists():
        return json.loads(COST_GUARD_PATH.read_text(encoding="utf-8"))
    return {"max_concurrent": 4, "max_timeout_seconds": 1800, "per_model": {}, "output_budget": OUTPUT_BUDGET_DEFAULTS, "updated_at": None}


def cost_guard(config: dict[str, Any] | None = None, apply: bool = False) -> dict[str, Any]:
    current = load_cost_guard()
    if config:
        current.update(config)
        if int(current.get("max_concurrent", 1)) < 1:
            raise OrchestratorError("cost guard max_concurrent must be >= 1.")
        if int(current.get("max_timeout_seconds", 10)) < 10:
            raise OrchestratorError("cost guard max_timeout_seconds must be >= 10.")
        current["updated_at"] = utc_now_iso()
        if apply:
            write_json_file(COST_GUARD_PATH, current)
    return {"ok": True, "path": str(COST_GUARD_PATH), "applied": apply, "guard": current}


def max_concurrent_limit() -> int:
    guard = load_cost_guard()
    return max(1, int(guard.get("max_concurrent", 4)))


def clamp_timeout_for_model(model: str | None, timeout_seconds: int) -> int:
    guard = load_cost_guard()
    timeout = min(timeout_seconds, int(guard.get("max_timeout_seconds", timeout_seconds)))
    if model:
        per_model = guard.get("per_model", {}).get(model, {})
        if per_model.get("max_timeout_seconds"):
            timeout = min(timeout, int(per_model["max_timeout_seconds"]))
    return timeout


def enforce_cost_guard(model: str | None, timeout_seconds: int) -> int:
    active = run_status(include_finished=False).get("active_count", 0)
    max_concurrent = max_concurrent_limit()
    if active >= max_concurrent:
        raise OrchestratorError(f"Cost guard blocked run: active workers {active} >= max_concurrent {max_concurrent}.")
    return clamp_timeout_for_model(model, timeout_seconds)


def resolve_output_budget(
    max_output_bytes: int | None = None,
    max_events_bytes: int | None = None,
    soft_output_bytes: int | None = None,
    output_budget_policy: str | None = None,
    kill_on_excessive_output: bool = False,
    final_only: bool = False,
    final_max_chars: int | None = None,
) -> dict[str, Any]:
    guard_budget = dict((load_cost_guard().get("output_budget") or {}))
    budget = dict(OUTPUT_BUDGET_DEFAULTS)
    budget.update({k: v for k, v in guard_budget.items() if v is not None})
    if max_output_bytes is not None:
        budget["max_output_bytes"] = max_output_bytes if max_output_bytes > 0 else None
    if max_events_bytes is not None:
        budget["max_events_bytes"] = max_events_bytes if max_events_bytes > 0 else None
    if soft_output_bytes is not None:
        budget["soft_output_bytes"] = soft_output_bytes if soft_output_bytes > 0 else None
    if output_budget_policy:
        if output_budget_policy not in {"stop", "truncate"}:
            raise OrchestratorError("output_budget_policy must be stop or truncate.")
        budget["policy"] = output_budget_policy
    if kill_on_excessive_output:
        budget["policy"] = "stop"
    if final_only:
        budget["final_only"] = True
    if final_max_chars is not None:
        budget["final_max_chars"] = max(1000, int(final_max_chars))
    budget.setdefault("state", "within_budget")
    budget.setdefault("stop_reason", None)
    budget.setdefault("observed_output_bytes", 0)
    budget.setdefault("written_output_bytes", 0)
    budget.setdefault("events_bytes", 0)
    budget.setdefault("dropped_output_bytes", 0)
    budget.setdefault("dropped_event_count", 0)
    return budget


def benchmark_model(
    profile: str | None = None,
    role: str = "testing",
    task: str = "Return a concise JSON object with keys ok and summary.",
    timeout_seconds: int = 120,
    execute: bool = False,
) -> dict[str, Any]:
    route = resolve_route(role=role, profile=profile)
    provider = get_provider(route["profile"])
    if not execute:
        return {
            "ok": True,
            "dry_run": True,
            "message": "Pass execute=true to run a real benchmark task through Claude Code.",
            "profile": provider.name,
            "model": route.get("model_override") or provider.model,
            "task": task,
        }
    started = time.time()
    run = run_agent(task=task, role=role, profile=profile, timeout_seconds=timeout_seconds, output_format="json")
    result = {
        "ok": run.get("exit_code") == 0,
        "dry_run": False,
        "profile": provider.name,
        "model": route.get("model_override") or provider.model,
        "duration_ms": int((time.time() - started) * 1000),
        "run_id": run.get("run_id"),
        "exit_code": run.get("exit_code"),
        "stdout_tail": run.get("stdout_tail", "")[-2000:],
    }
    append_model_benchmark_history({"recorded_at": utc_now_iso(), "type": "single", "role": role, **result})
    build_model_registry(refresh=True, apply=True)
    return result


def calibrate_policy(preferences: dict[str, Any], apply: bool = True) -> dict[str, Any]:
    data = {
        "updated_at": utc_now_iso(),
        "preferences": preferences,
        "notes": "Use this file to record local model preferences discovered from real workloads.",
    }
    if apply:
        CALIBRATION_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "applied": apply, "path": str(CALIBRATION_PATH), "calibration": data}


def _legacy_dashboard(include_finished: bool = True, limit: int = 12, open_browser: bool = False) -> dict[str, Any]:
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    data = run_status(include_finished=include_finished, include_output_tail=True, tail_chars=1000, limit=limit)
    route_cards: list[str] = []
    for role in ("development", "review", "security", "multimodal"):
        try:
            route = select_model_for_role(role=role, task_type="multimodal" if role == "multimodal" else None)
            route_cards.append(
                f"<div class='route'><b>{html_lib.escape(role)}</b><span>{html_lib.escape(str(route.get('model') or 'unknown'))}</span><small>{html_lib.escape(str(route.get('reason') or ''))}</small></div>"
            )
        except Exception as exc:
            route_cards.append(f"<div class='route'><b>{html_lib.escape(role)}</b><span>unavailable</span><small>{html_lib.escape(str(exc))}</small></div>")
    workers = []
    timelines = []
    risks = []
    for item in data.get("runs", []):
        try:
            summary = summarize_run(str(item.get("run_id")), max_events=12, write_artifacts=True)
            progress = summary.get("progress_summary") or {}
            risk = summary.get("risk_flags") or {}
            changed = summary.get("changed_files") or {}
            timeline_text = str(summary.get("tool_timeline") or "")
        except Exception as exc:
            progress = {"recommended_action": "inspect", "phase": item.get("latest_phase"), "last_event": {"text": str(exc)}}
            risk = {"flags": [{"severity": "low", "code": "dashboard_summary_failed", "message": str(exc)}]}
            changed = {"files": []}
            timeline_text = ""
        run_id = str(item.get("run_id"))
        workers.append(
            f"<button class='worker'><span><b>{item.get('role') or 'worker'}</b><code>{run_id}</code></span>"
            f"<small>{item.get('status')} · {(item.get('profile') or {}).get('model') or 'unknown model'}</small></button>"
        )
        timeline_lines = "".join(f"<li>{html_lib.escape(line[2:] if line.startswith('- ') else line)}</li>" for line in timeline_text.splitlines() if line.startswith("- "))
        timelines.append(
            f"<section class='panel'><h2>Timeline / Logs <code>{run_id}</code></h2>"
            f"<p><b>{progress.get('recommended_action')}</b> · phase {progress.get('phase') or 'unknown'} · changed {changed.get('file_count', 0)} files</p>"
            f"<ol>{timeline_lines or '<li>No timeline events yet.</li>'}</ol></section>"
        )
        risk_items = "".join(f"<li><b>{html_lib.escape(str(flag.get('severity')))}</b> {html_lib.escape(str(flag.get('code')))}: {html_lib.escape(str(flag.get('message')))}</li>" for flag in risk.get("flags", []))
        control_lines = [
            f"poll-run --run-id {run_id}",
            f"summarize-run --run-id {run_id}",
            f"verify-run --run-id {run_id}",
            f"stop-run --run-id {run_id} --force",
            f"open-run-folder --run-id {run_id}",
        ]
        controls = "".join(f"<li><code>{html_lib.escape(command)}</code></li>" for command in control_lines)
        risks.append(
            f"<section class='panel'><h2>Diff / Risk / Controls <code>{run_id}</code></h2>"
            f"<ul>{risk_items or '<li>No risk flags detected.</li>'}</ul>"
            f"<p>Files: {html_lib.escape(', '.join(changed.get('files', [])[:8]) or 'none')}</p>"
            f"<h3>Controls</h3><ul>{controls}</ul></section>"
        )
    html = "\n".join(
        [
            "<!doctype html><html><head><meta charset='utf-8'><title>Claude Code Workers</title>",
            "<style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0}header{padding:16px 20px;border-bottom:1px solid #30363d;background:#161b22}.routes{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:12px}.route{border:1px solid #30363d;border-radius:8px;padding:10px;background:#0d1117}.route b,.route span,.route small{display:block}.route span{color:#7ee787}.route small{color:#8b949e;margin-top:4px}.grid{display:grid;grid-template-columns:280px minmax(360px,1fr) 380px;gap:16px;padding:16px}.panel,.worker{border:1px solid #30363d;border-radius:8px;background:#161b22}.panel{padding:14px;margin-bottom:12px}.worker{width:100%;text-align:left;color:#e6edf3;padding:12px;margin-bottom:10px;display:block}.worker span{display:flex;justify-content:space-between;gap:8px}.worker small{display:block;color:#8b949e;margin-top:6px}code{color:#7ee787;overflow-wrap:anywhere}ol,ul{padding-left:22px}li{margin:8px 0;line-height:1.35}p{color:#c9d1d9}h3{margin-bottom:4px}</style>",
            "</head><body><header><h1>Claude Code Worker Dashboard</h1>",
            f"<p>Generated at {utc_now_iso()} · Runs {data.get('count', 0)} · Active {data.get('active_count', 0)}</p>",
            "<h2>Model Routing</h2><div class='routes'>",
            "".join(route_cards),
            "</div></header>",
            "<main class='grid'><aside>",
            "".join(workers) if workers else "<p>No runs found.</p>",
            "</aside><section>",
            "".join(timelines),
            "</section><aside>",
            "".join(risks),
            "</aside></main>",
            "</body></html>",
        ]
    )
    path = DASHBOARD_DIR / "index.html"
    path.write_text(html, encoding="utf-8")
    if open_browser:
        if os.name == "nt":
            subprocess.Popen(["cmd", "/c", "start", "", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "path": str(path), "run_count": data.get("count", 0), "opened": open_browser}


def dashboard(include_finished: bool = True, limit: int = 12, open_browser: bool = False) -> dict[str, Any]:
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    data = run_status(include_finished=include_finished, include_output_tail=True, tail_chars=1000, limit=limit)
    route_cards: list[str] = []
    for role in ("development", "review", "security", "supervisor", "multimodal"):
        try:
            route = select_model_for_role(role=role, task_type="multimodal" if role == "multimodal" else None)
            route_cards.append(
                f"<div class='route'><b>{html_lib.escape(role)}</b><span>{html_lib.escape(str(route.get('model') or 'unknown'))}</span><small>{html_lib.escape(str(route.get('reason') or ''))}</small></div>"
            )
        except Exception as exc:
            route_cards.append(f"<div class='route'><b>{html_lib.escape(role)}</b><span>unavailable</span><small>{html_lib.escape(str(exc))}</small></div>")
    workers: list[str] = []
    timelines: list[str] = []
    risks: list[str] = []
    for item in data.get("runs", []):
        run_id = str(item.get("run_id"))
        try:
            summary = summarize_run(run_id, max_events=12, write_artifacts=True)
            progress = summary.get("progress_summary") or {}
            risk = summary.get("risk_flags") or {}
            changed = summary.get("changed_files") or {}
            timeline_text = str(summary.get("tool_timeline") or "")
        except Exception as exc:
            progress = {"recommended_action": "inspect", "phase": item.get("latest_phase"), "last_event": {"text": str(exc)}}
            risk = risk_summary([{"severity": "low", "code": "dashboard_summary_failed", "message": str(exc), "blocking": False}])
            changed = {"files": [], "project_source_changes": {"paths": [], "changed_count": 0}, "agent_artifact_changes": {"paths": [], "changed_count": 0}}
            timeline_text = ""
        output_budget = item.get("output_budget") or {}
        route_drift = item.get("route_drift") or {}
        actual_route = item.get("actual_route") or {}
        source_changes = changed.get("project_source_changes") or {}
        artifact_changes = changed.get("agent_artifact_changes") or {}
        max_severity = str(risk.get("max_severity") or "none")
        blocking_count = int(risk.get("blocking_count") or 0)
        warning_count = int(risk.get("warning_count") or 0)
        budget_state = str(output_budget.get("state") or "unknown")
        stop_reason = str(item.get("stop_reason") or output_budget.get("stop_reason") or "none")
        active_text = "active" if item.get("active") else "inactive"
        role = str(item.get("role") or "worker")
        status_text = str(item.get("status") or "unknown")
        declared_model = str((item.get("profile") or {}).get("model") or "unknown")
        actual_model = str(actual_route.get("actual_model") or item.get("actual_model") or "")
        model = actual_model or declared_model
        route_changed = "yes" if route_drift.get("route_changed") else "no"
        route_mismatch = "yes" if actual_route.get("route_mismatch") or item.get("route_mismatch") else "no"
        workers.append(
            f"<button class='worker' data-role='{html_lib.escape(role)}' data-status='{html_lib.escape(status_text)}' data-risk='{html_lib.escape(max_severity)}' data-active='{html_lib.escape(active_text)}' data-model='{html_lib.escape(model)}'>"
            f"<span><b>{html_lib.escape(role)}</b><code>{run_id}</code></span>"
            f"<small>{html_lib.escape(status_text)} / {active_text} / actual {html_lib.escape(model)}</small>"
            f"<small>declared {html_lib.escape(declared_model)} / mismatch {route_mismatch}</small>"
            f"<small>risk {html_lib.escape(max_severity)} / budget {html_lib.escape(budget_state)} / route drift {route_changed}</small></button>"
        )
        timeline_lines = "".join(f"<li>{html_lib.escape(line[2:] if line.startswith('- ') else line)}</li>" for line in timeline_text.splitlines() if line.startswith("- "))
        timelines.append(
            f"<section class='panel'><h2>Timeline / Logs <code>{run_id}</code></h2>"
            f"<p><b>{html_lib.escape(str(progress.get('recommended_action')))}</b> / phase {html_lib.escape(str(progress.get('phase') or 'unknown'))} / heartbeat {html_lib.escape(str((progress.get('last_event') or {}).get('ts') or 'unknown'))}</p>"
            f"<p>source changes {source_changes.get('changed_count', 0)} / artifacts {artifact_changes.get('changed_count', 0)} / stop {html_lib.escape(stop_reason)}</p>"
            f"<ol>{timeline_lines or '<li>No timeline events yet.</li>'}</ol></section>"
        )
        risk_items = "".join(f"<li><b>{html_lib.escape(str(flag.get('severity')))}</b> {html_lib.escape(str(flag.get('code')))}: {html_lib.escape(str(flag.get('message')))}</li>" for flag in risk.get("flags", []))
        control_lines = [
            f"poll-run --run-id {run_id}",
            f"summarize-run --run-id {run_id}",
            f"verify-run --run-id {run_id}",
            f"secret-scan-run --run-id {run_id}",
            f"stop-run --run-id {run_id} --force",
            f"open-run-folder --run-id {run_id}",
            f"controller-report --run-id {run_id}",
        ]
        controls = "".join(f"<li><code>{html_lib.escape(command)}</code></li>" for command in control_lines)
        token_est = item.get("total_tokens_est")
        budget_lines = [
            f"state `{budget_state}`",
            f"tokens est `{token_est if token_est is not None else 'unknown'}`",
            f"actual cost usd `{actual_route.get('actual_cost_usd') if actual_route.get('actual_cost_usd') is not None else 'unknown'}`",
            f"stdout `{item.get('stdout_bytes', 0)}` bytes",
            f"stderr `{item.get('stderr_bytes', 0)}` bytes",
            f"events `{item.get('events_bytes', 0)}` bytes",
            f"stop reason `{stop_reason}`",
        ]
        budget_html = "".join(f"<li>{html_lib.escape(line)}</li>" for line in budget_lines)
        route_html = (
            f"<p>Route: declared {html_lib.escape(declared_model)} / actual {html_lib.escape(actual_model or 'unknown')} / mismatch {route_mismatch}; "
            f"follow-up drift {route_changed}</p>"
        )
        risks.append(
            f"<section class='panel'><h2>Diff / Risk / Controls <code>{run_id}</code></h2>"
            f"<p>Risk: max {html_lib.escape(max_severity)}, blocking {blocking_count}, warnings {warning_count}</p>"
            f"<ul>{risk_items or '<li>No risk flags detected.</li>'}</ul>"
            f"<p>Source: {html_lib.escape(', '.join(source_changes.get('paths', [])[:8]) or 'none')}</p>"
            f"<p>Artifacts: {html_lib.escape(', '.join(artifact_changes.get('paths', [])[:8]) or 'none')}</p>"
            f"{route_html}<h3>Output Budget</h3><ul>{budget_html}</ul>"
            f"<h3>Controls</h3><ul>{controls}</ul></section>"
        )
    html = "\n".join(
        [
            "<!doctype html><html><head><meta charset='utf-8'><title>Claude Code Workers</title>",
            "<style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0}header{padding:16px 20px;border-bottom:1px solid #30363d;background:#161b22}.routes,.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:12px}.route,.filter{border:1px solid #30363d;border-radius:8px;padding:10px;background:#0d1117}.route b,.route span,.route small{display:block}.route span{color:#7ee787}.route small,.filter label{color:#8b949e;margin-top:4px}.filter select,.filter input{width:100%;box-sizing:border-box;background:#010409;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:8px;margin-top:6px}.grid{display:grid;grid-template-columns:300px minmax(360px,1fr) 420px;gap:16px;padding:16px}.panel,.worker{border:1px solid #30363d;border-radius:8px;background:#161b22}.panel{padding:14px;margin-bottom:12px}.worker{width:100%;text-align:left;color:#e6edf3;padding:12px;margin-bottom:10px;display:block}.worker[hidden]{display:none}.worker span{display:flex;justify-content:space-between;gap:8px}.worker small{display:block;color:#8b949e;margin-top:6px}code{color:#7ee787;overflow-wrap:anywhere}ol,ul{padding-left:22px}li{margin:8px 0;line-height:1.35}p{color:#c9d1d9}h3{margin-bottom:4px}@media(max-width:980px){.grid{grid-template-columns:1fr}}</style>",
            "</head><body><header><h1>Claude Code Worker Dashboard</h1>",
            f"<p>Generated at {utc_now_iso()} / Runs {data.get('count', 0)} / Active {data.get('active_count', 0)}</p>",
            "<h2>Model Routing</h2><div class='routes'>",
            "".join(route_cards),
            "</div><h2>Filters</h2><div class='filters'><div class='filter'><label>Role<input id='roleFilter' placeholder='security'></label></div><div class='filter'><label>Status<input id='statusFilter' placeholder='running'></label></div><div class='filter'><label>Risk<select id='riskFilter'><option value=''>all</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>none</option></select></label></div><div class='filter'><label>Active<select id='activeFilter'><option value=''>all</option><option>active</option><option>inactive</option></select></label></div></div></header>",
            "<main class='grid'><aside>",
            "".join(workers) if workers else "<p>No runs found.</p>",
            "</aside><section>",
            "".join(timelines),
            "</section><aside>",
            "".join(risks),
            "</aside></main><script>const roleFilter=document.getElementById('roleFilter'),statusFilter=document.getElementById('statusFilter'),riskFilter=document.getElementById('riskFilter'),activeFilter=document.getElementById('activeFilter');function applyFilters(){const role=roleFilter.value.toLowerCase(),status=statusFilter.value.toLowerCase(),risk=riskFilter.value.toLowerCase(),active=activeFilter.value.toLowerCase();document.querySelectorAll('.worker').forEach(el=>{const ok=(!role||el.dataset.role.toLowerCase().includes(role))&&(!status||el.dataset.status.toLowerCase().includes(status))&&(!risk||el.dataset.risk.toLowerCase()===risk)&&(!active||el.dataset.active.toLowerCase()===active);el.hidden=!ok;});}[roleFilter,statusFilter,riskFilter,activeFilter].forEach(el=>el.addEventListener('input',applyFilters));</script>",
            "</body></html>",
        ]
    )
    path = DASHBOARD_DIR / "index.html"
    path.write_text(html, encoding="utf-8")
    if open_browser:
        if os.name == "nt":
            subprocess.Popen(["cmd", "/c", "start", "", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "path": str(path), "run_count": data.get("count", 0), "opened": open_browser}


def open_run_folder(run_id: str, open_folder: bool = True) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    if not run_dir.exists():
        raise OrchestratorError(f"Run not found: {run_id}")
    if open_folder:
        if os.name == "nt":
            subprocess.Popen(["explorer", str(run_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(run_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "run_id": run_id, "path": str(run_dir), "opened": open_folder}


def export_report(run_id: str | None = None, team_id: str | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    report_dir = output_dir or REPORTS_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Claude Code Orchestrator Report", "", f"Generated: {utc_now_iso()}", ""]
    if team_id:
        collected = collect_team_results(team_id=team_id)
        lines.extend([collected["report"], ""])
        name = f"{team_id}.md"
    elif run_id:
        status = single_run_status(run_id, include_output_tail=True, tail_chars=10000)
        scan = secret_scan_run(run_id, include_diff=False)
        lines.extend(
            [
                f"Run: `{run_id}`",
                "",
                f"- Status: `{status.get('status')}`",
                f"- Role: `{status.get('role')}`",
                f"- Model: `{(status.get('profile') or {}).get('model')}`",
                f"- Elapsed: `{status.get('elapsed_ms')}` ms",
                f"- Secret scan findings: `{scan.get('finding_count')}`",
                "",
                "## Stdout Tail",
                "```text",
                str(status.get("stdout_tail", ""))[-10000:],
                "```",
                "",
                "## Stderr Tail",
                "```text",
                str(status.get("stderr_tail", ""))[-4000:],
                "```",
            ]
        )
        name = f"run-{run_id}.md"
    else:
        raise OrchestratorError("Provide run_id or team_id.")
    path = report_dir / name
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"ok": True, "path": str(path), "run_id": run_id, "team_id": team_id}


def controller_report(
    run_id: str | None = None,
    team_id: str | None = None,
    date: str | None = None,
    include_finished: bool = True,
    limit: int = 50,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    report_dir = output_dir or REPORTS_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    dashboard_path = DASHBOARD_DIR / "index.html"
    if dashboard_path.exists():
        dashboard_result = {"ok": True, "path": str(dashboard_path), "run_count": None, "opened": False}
    else:
        dashboard_result = dashboard(include_finished=include_finished, limit=min(limit, 8), open_browser=False)
    usage_summary = daily_usage_summary(date=date, write_report=True)
    if run_id:
        run_ids = [run_id]
    elif team_id:
        run_ids = resolve_team_run_ids(team_id=team_id)
    else:
        run_ids = [str(item.get("run_id")) for item in run_status(include_finished=include_finished, limit=limit).get("runs", [])]
    run_rows: list[dict[str, Any]] = []
    source_paths: list[str] = []
    artifact_paths: list[str] = []
    max_severity = "none"
    blocking_runs = 0
    secret_summary: dict[str, int] = {}
    for rid in run_ids:
        try:
            status = single_run_status(rid, include_output_tail=False)
            usage = estimate_run_usage(rid)
            changed = changed_files_for_run(rid)
            risks = detect_failure_modes(rid, status=status, changed_files=changed)
            scan = secret_scan_run(rid, include_diff=False)
        except Exception as exc:
            run_rows.append({"run_id": rid, "status": "unreadable", "error": str(exc)})
            continue
        source = changed.get("project_source_changes") or {}
        artifacts = changed.get("agent_artifact_changes") or {}
        source_paths.extend(source.get("paths") or [])
        artifact_paths.extend(artifacts.get("paths") or [])
        severity = str(risks.get("max_severity") or "none")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = severity
        if not risks.get("blocking_ok", risks.get("ok", True)):
            blocking_runs += 1
        for key, count in (scan.get("classification_counts") or {}).items():
            secret_summary[str(key)] = secret_summary.get(str(key), 0) + int(count)
        budget = status.get("output_budget") or {}
        actual_route = status.get("actual_route") or {}
        run_rows.append(
            {
                "run_id": rid,
                "status": status.get("status"),
                "active": status.get("active"),
                "role": status.get("role"),
                "model": usage.get("model"),
                "declared_model": usage.get("declared_model") or (status.get("profile") or {}).get("model"),
                "actual_model": usage.get("actual_model") or actual_route.get("actual_model"),
                "route_mismatch": usage.get("route_mismatch") or actual_route.get("route_mismatch"),
                "duration_ms": usage.get("duration_ms") if usage.get("duration_ms") is not None else status.get("elapsed_ms"),
                "tokens_est": usage.get("total_tokens_est") if usage.get("total_tokens_est") is not None else status.get("total_tokens_est"),
                "actual_cost_usd": usage.get("actual_cost_usd") if usage.get("actual_cost_usd") is not None else actual_route.get("actual_cost_usd"),
                "stdout_bytes": status.get("stdout_bytes"),
                "stderr_bytes": status.get("stderr_bytes"),
                "events_bytes": status.get("events_bytes"),
                "budget_state": budget.get("state"),
                "stop_reason": status.get("stop_reason") or budget.get("stop_reason"),
                "risk_max_severity": risks.get("max_severity"),
                "risk_warning_count": risks.get("warning_count"),
                "risk_blocking_count": risks.get("blocking_count"),
                "source_change_count": source.get("changed_count", 0),
                "artifact_change_count": artifacts.get("changed_count", 0),
                "route_drift": status.get("route_drift"),
                "secret_scan": {
                    "finding_count": scan.get("finding_count"),
                    "blocking_count": scan.get("blocking_count"),
                    "classification_counts": scan.get("classification_counts"),
                },
            }
        )
    recommendations: list[str] = []
    if blocking_runs:
        recommendations.append("Review blocking risk runs before accepting worker output.")
    if usage_summary.get("budget_stop_count"):
        recommendations.append("Tune output budgets or switch noisy tasks to final-only mode.")
    if secret_summary.get("real_secret_candidate"):
        recommendations.append("Inspect redacted secret findings and rotate any exposed credentials.")
    if source_paths:
        recommendations.append("Review project source changes separately from agent artifacts.")
    if not recommendations:
        recommendations.append("No blocking controller issue detected in the selected run set.")
    lines = [
        "# Controller Pressure Report",
        "",
        f"Generated: {utc_now_iso()}",
        f"Scope: `{run_id or team_id or date or 'recent-runs'}`",
        "",
        "## Summary",
        f"- Runs: `{len(run_rows)}`",
        f"- Active now: `{run_status(include_finished=False).get('active_count', 0)}`",
        f"- Max risk severity: `{max_severity}`",
        f"- Blocking risk runs: `{blocking_runs}`",
        f"- Dashboard: `{dashboard_result.get('path')}`",
        f"- Usage summary: `{usage_summary.get('report_path')}`",
        f"- Estimated tokens: `{usage_summary.get('total_tokens_est')}`",
        f"- Total duration: `{usage_summary.get('total_duration_ms')}` ms",
        f"- Output bytes: `{usage_summary.get('total_output_bytes')}`",
        f"- Events bytes: `{usage_summary.get('total_events_bytes')}`",
        f"- Output budget stops: `{usage_summary.get('budget_stop_count')}`",
        "",
        "## By Model Usage",
    ]
    by_model = usage_summary.get("by_model") or {}
    if by_model:
        for model, bucket in sorted(by_model.items()):
            lines.append(
                f"- `{model}`: runs `{bucket.get('runs')}`, failures `{bucket.get('failures')}`, duration `{bucket.get('duration_ms')}` ms, "
                f"tokens `{bucket.get('tokens_est')}`, output `{bucket.get('output_bytes')}` bytes, events `{bucket.get('events_bytes')}` bytes, "
                f"budget stops `{bucket.get('budget_stops')}`, warnings `{bucket.get('warning_count')}`, blocking `{bucket.get('blocking_count')}`, "
                f"route mismatches `{bucket.get('route_mismatch_count')}`, max severity `{bucket.get('max_severity')}`"
            )
    else:
        lines.append("- No model usage recorded.")
    lines.extend(
        [
        "",
        "## Source vs Artifacts",
        f"- Project source changed paths: `{len(set(source_paths))}`",
        f"- Agent artifact changed paths: `{len(set(artifact_paths))}`",
        "",
        "## Secret Scan",
        ]
    )
    if secret_summary:
        lines.extend(f"- `{key}`: `{value}`" for key, value in sorted(secret_summary.items()))
    else:
        lines.append("- No secret findings in selected run logs.")
    lines.extend(["", "## Runs"])
    for row in run_rows:
        lines.append(
            f"- `{row.get('run_id')}` role `{row.get('role')}` model `{row.get('model')}` status `{row.get('status')}` "
            f"declared `{row.get('declared_model')}` actual `{row.get('actual_model') or 'unknown'}` mismatch `{row.get('route_mismatch')}` "
            f"duration `{row.get('duration_ms')}` ms tokens `{row.get('tokens_est')}` cost `{row.get('actual_cost_usd')}` stdout `{row.get('stdout_bytes')}` events `{row.get('events_bytes')}` "
            f"risk `{row.get('risk_max_severity')}` warnings `{row.get('risk_warning_count')}` blocking `{row.get('risk_blocking_count')}` "
            f"budget `{row.get('budget_state')}` source `{row.get('source_change_count')}` artifacts `{row.get('artifact_change_count')}`"
        )
    lines.extend(["", "## Recommendations"])
    lines.extend(f"- {item}" for item in recommendations)
    name = f"controller-report-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    path = report_dir / name
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {
        "ok": True,
        "path": str(path),
        "dashboard_path": dashboard_result.get("path"),
        "usage_summary_path": usage_summary.get("report_path"),
        "run_count": len(run_rows),
        "active_count": run_status(include_finished=False).get("active_count", 0),
        "max_severity": max_severity,
        "blocking_runs": blocking_runs,
        "by_model_usage": by_model,
        "secret_classification_counts": secret_summary,
        "source_change_count": len(set(source_paths)),
        "artifact_change_count": len(set(artifact_paths)),
        "recommendations": recommendations,
        "runs": run_rows,
    }


def decision_review(
    task: str,
    proposed_action: str,
    run_id: str | None = None,
    team_id: str | None = None,
    evidence: str | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    packet: dict[str, Any] = {
        "task": task,
        "proposed_action": proposed_action,
        "run_id": run_id,
        "team_id": team_id,
        "evidence": evidence or "",
        "created_at": utc_now_iso(),
        "runs": [],
    }
    run_ids: list[str] = []
    if run_id:
        run_ids.append(run_id)
    if team_id:
        run_ids.extend(resolve_team_run_ids(team_id=team_id))
    objections: list[str] = []
    missing_evidence: list[str] = []
    required_changes: list[str] = []
    max_severity = "none"
    for rid in dict.fromkeys(run_ids):
        status = single_run_status(rid, include_output_tail=False)
        changed = changed_files_for_run(rid)
        risks = detect_failure_modes(rid, status=status, changed_files=changed)
        packet["runs"].append({"status": status, "changed_files": changed, "risks": risks})
        severity = str(risks.get("max_severity") or "none")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = severity
        if status.get("active"):
            objections.append(f"Run {rid} is still active.")
        if not risks.get("blocking_ok", True):
            objections.append(f"Run {rid} has blocking risk flags.")
        if (changed.get("project_source_changes") or {}).get("changed_count") and "verify" not in proposed_action.lower():
            required_changes.append("Run verification should be completed before accepting source changes.")
    if not evidence and not run_ids:
        missing_evidence.append("No run/team evidence was provided.")
    if "merge" in proposed_action.lower() and (not evidence and not run_ids):
        objections.append("Merge-like action lacks evidence.")
    if objections:
        verdict = "block"
        confidence = "high"
    elif required_changes or missing_evidence or max_severity in {"medium", "low"}:
        verdict = "revise"
        confidence = "medium"
    else:
        verdict = "approve"
        confidence = "medium" if not run_ids else "high"
    report_dir = output_dir or REPORTS_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"decision-review-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    lines = [
        "# Supervisor Decision Review",
        "",
        f"Verdict: `{verdict}`",
        f"Confidence: `{confidence}`",
        f"Max severity: `{max_severity}`",
        "",
        "## Proposed Action",
        proposed_action,
        "",
        "## Objections",
        *(f"- {item}" for item in objections),
        *(["- None."] if not objections else []),
        "",
        "## Missing Evidence",
        *(f"- {item}" for item in missing_evidence),
        *(["- None."] if not missing_evidence else []),
        "",
        "## Required Changes",
        *(f"- {item}" for item in required_changes),
        *(["- None."] if not required_changes else []),
    ]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {
        "ok": True,
        "verdict": verdict,
        "confidence": confidence,
        "objections": objections,
        "missing_evidence": missing_evidence,
        "required_changes": required_changes,
        "judgment": "Supervisor allows the action only when blocking risks are cleared and evidence is enough.",
        "packet": packet,
        "report_path": str(path),
    }


def run_test_command(command: str, cwd: Path, timeout_seconds: int = 300) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
        return {
            "command": command,
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "duration_ms": int((time.time() - started) * 1000),
            "stdout_tail": str(redact(proc.stdout or ""))[-4000:],
            "stderr_tail": str(redact(proc.stderr or ""))[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "ok": False,
            "exit_code": 124,
            "timed_out": True,
            "duration_ms": int((time.time() - started) * 1000),
            "stdout_tail": str(redact(subprocess_text(exc.stdout)))[-4000:],
            "stderr_tail": str(redact(subprocess_text(exc.stderr)))[-4000:],
        }


def verify_run(
    run_id: str,
    test_commands: list[str] | None = None,
    test_timeout_seconds: int = 300,
    include_diff: bool = True,
) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    status = single_run_status(run_id, include_output_tail=True, tail_chars=6000)
    scope = check_write_scope(run_id=run_id)
    scan = secret_scan_run(run_id, include_diff=include_diff)
    diff = diff_summary(cwd=cwd)
    tests = [run_test_command(command, cwd=cwd, timeout_seconds=test_timeout_seconds) for command in (test_commands or [])]
    failures = detect_failure_modes(run_id, status=status)
    gates = {
        "run_finished_successfully": (not status.get("active")) and status.get("status") == "succeeded",
        "write_scope_ok": bool(scope.get("ok", True)),
        "secret_scan_ok": bool(scan.get("ok")),
        "failure_modes_ok": bool(failures.get("ok", True)),
        "tests_ok": all(item.get("ok") for item in tests) if tests else True,
    }
    ok = all(gates.values())
    report_dir = REPORTS_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"verify-{run_id}.md"
    lines = [
        "# Run Verification",
        "",
        f"Run: `{run_id}`",
        f"Generated: {utc_now_iso()}",
        "",
        "## Gates",
        *[f"- {name}: `{'pass' if value else 'fail'}`" for name, value in gates.items()],
        "",
        "## Diff",
        f"- Files: `{diff.get('file_count')}`",
        f"- Added: `{diff.get('total_added')}`",
        f"- Deleted: `{diff.get('total_deleted')}`",
        f"- Needs tests: `{diff.get('needs_tests')}`",
        "",
        "## Write Scope",
        f"- Status: `{scope.get('status')}`",
        f"- Violations: `{scope.get('violation_count', 0)}`",
        "",
        "## Secret Scan",
        f"- Findings: `{scan.get('finding_count')}`",
        "",
        "## Failure Modes",
        f"- Flags: `{failures.get('flag_count', 0)}`",
        "",
        "## Tests",
    ]
    if tests:
        for item in tests:
            lines.append(f"- `{item['command']}` -> `{'pass' if item.get('ok') else 'fail'}` exit `{item.get('exit_code')}`")
    else:
        lines.append("- No test commands provided.")
    if not ok:
        lines.extend(["", "## Blocking Notes"])
        if not scope.get("ok", True):
            lines.append(f"- Write scope blocked acceptance. {scope.get('rollback_recommendation') or ''}".strip())
        if not scan.get("ok", True):
            lines.append("- Secret scan found blocking credential-like values. Review redacted findings before sharing output.")
        if not failures.get("ok", True):
            lines.append("- Failure-mode detection found blocking run behavior.")
        if tests and not gates["tests_ok"]:
            lines.append("- One or more test commands failed.")
        if not gates["run_finished_successfully"]:
            lines.append("- Run did not finish successfully.")
    report_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    worker_quality = score_worker(run_id, solved=ok, apply=True, source="verify_run")
    result = {
        "ok": ok,
        "run_id": run_id,
        "status": status,
        "gates": gates,
        "diff_summary": diff,
        "write_scope": scope,
        "secret_scan": scan,
        "failure_modes": failures,
        "worker_quality": worker_quality,
        "tests": tests,
        "report_path": str(report_path),
    }
    update_metadata(run_dir, verification=result, acceptance_status="verified" if ok else "blocked_verification")
    return result


def estimate_tokens_from_text(text: str) -> int:
    return max(0, int(len(text) / 4))


def estimate_run_usage(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    prompt = (run_dir / "prompt.txt").read_text(encoding="utf-8", errors="replace") if (run_dir / "prompt.txt").exists() else ""
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    events_path = run_dir / "events.ndjson"
    stdout_bytes = stdout_path.stat().st_size if stdout_path.exists() else 0
    stderr_bytes = stderr_path.stat().st_size if stderr_path.exists() else 0
    events_bytes = events_path.stat().st_size if events_path.exists() else 0
    profile = metadata.get("profile") or {}
    actual_route = actual_route_summary(metadata)
    declared_model = profile.get("model")
    actual_model = actual_route.get("actual_model")
    input_tokens = estimate_tokens_from_text(prompt)
    output_tokens = max(0, int((stdout_bytes + stderr_bytes) / 4))
    if actual_route.get("actual_total_tokens") is not None:
        input_tokens = int(actual_route.get("actual_input_tokens") or 0)
        output_tokens = int(actual_route.get("actual_output_tokens") or 0)
    output_budget = output_budget_from_metadata(metadata, run_dir)
    return {
        "run_id": run_id,
        "started_at": metadata.get("started_at"),
        "finished_at": metadata.get("finished_at"),
        "status": metadata.get("status") or ("succeeded" if metadata.get("exit_code") == 0 else "failed" if metadata.get("exit_code") is not None else "unknown"),
        "role": metadata.get("role"),
        "profile": profile.get("name"),
        "model": actual_model or declared_model,
        "model_source": "actual_model_usage" if actual_model else "declared_route",
        "declared_model": declared_model,
        "actual_model": actual_model,
        "actual_model_usage": actual_route.get("actual_model_usage"),
        "route_mismatch": actual_route.get("route_mismatch"),
        "duration_ms": metadata.get("duration_ms"),
        "input_tokens_est": input_tokens,
        "output_tokens_est": output_tokens,
        "total_tokens_est": input_tokens + output_tokens,
        "actual_cost_usd": actual_route.get("actual_cost_usd"),
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "events_bytes": events_bytes,
        "output_budget": output_budget,
        "stop_reason": metadata.get("stop_reason") or output_budget.get("stop_reason"),
    }


def risk_snapshot_for_usage(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    cached = run_dir / CONTROLLER_ARTIFACTS["risk_flags"]
    if cached.exists():
        data = read_json_file(cached, {})
        if data:
            return data
    try:
        return detect_failure_modes(run_id)
    except Exception as exc:
        return risk_summary([{"code": "risk_snapshot_failed", "severity": "low", "blocking": False, "message": str(exc)}])


def score_worker(
    run_id: str,
    solved: bool | None = None,
    hallucination: bool | None = None,
    needs_rework: bool | None = None,
    notes: str | None = None,
    apply: bool = True,
    source: str = "manual",
) -> dict[str, Any]:
    status = single_run_status(run_id, include_output_tail=True, tail_chars=4000)
    metadata = read_metadata(safe_run_dir(run_id))
    usage = estimate_run_usage(run_id)
    scope = check_write_scope(run_id=run_id)
    scan = secret_scan_run(run_id, include_diff=False)
    failures = detect_failure_modes(run_id, status=status)
    finished_success = (not status.get("active")) and status.get("status") == "succeeded"
    solved_value = finished_success if solved is None else bool(solved)
    hallucination_value = False if hallucination is None else bool(hallucination)
    needs_rework_value = (not solved_value) if needs_rework is None else bool(needs_rework)
    score = 100
    if not solved_value:
        score -= 35
    if not finished_success:
        score -= 15
    if not scope.get("ok", True):
        score -= 25
    if scan.get("blocking_count"):
        score -= 30
    if failures.get("flag_count"):
        score -= min(25, int(failures.get("flag_count") or 0) * 8)
    if hallucination_value:
        score -= 25
    if needs_rework_value:
        score -= 15
    if int(usage.get("total_tokens_est") or 0) > 50000:
        score -= 10
    score = max(0, min(100, score))
    profile = metadata.get("profile") or {}
    record = {
        "recorded_at": utc_now_iso(),
        "source": source,
        "run_id": run_id,
        "role": metadata.get("role"),
        "profile": profile.get("name"),
        "model": profile.get("model"),
        "status": status.get("status"),
        "quality_score": score,
        "solved": solved_value,
        "scope_ok": bool(scope.get("ok", True)),
        "secret_ok": bool(scan.get("ok", True)),
        "failure_flags": failures.get("flags", []),
        "hallucination": hallucination_value,
        "needs_rework": needs_rework_value,
        "tokens_est": usage.get("total_tokens_est"),
        "notes": notes or "",
    }
    if apply:
        history = load_worker_quality_history()
        history.setdefault("records", []).append(record)
        history["updated_at"] = utc_now_iso()
        write_json_file(WORKER_QUALITY_HISTORY_PATH, history)
        try:
            build_model_registry(refresh=True, apply=True)
        except Exception as exc:
            record["registry_update_error"] = str(exc)
    return {"ok": True, "applied": apply, "path": str(WORKER_QUALITY_HISTORY_PATH), **record}


def daily_usage_summary(date: str | None = None, write_report: bool = False) -> dict[str, Any]:
    target_date = date or datetime.now(timezone.utc).date().isoformat()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, Any]] = []
    for path in known_run_dirs():
        try:
            usage = estimate_run_usage(path.name)
        except Exception:
            continue
        started = str(usage.get("started_at") or "")
        if started.startswith(target_date):
            risks = risk_snapshot_for_usage(path.name)
            usage["risk_max_severity"] = risks.get("max_severity", "none")
            usage["risk_warning_count"] = int(risks.get("warning_count") or 0)
            usage["risk_blocking_count"] = int(risks.get("blocking_count") or 0)
            usage["risk_flag_count"] = int(risks.get("flag_count") or 0)
            runs.append(usage)
    by_model: dict[str, dict[str, Any]] = {}
    for item in runs:
        model = str(item.get("model") or "unknown")
        bucket = by_model.setdefault(
            model,
            {
                "runs": 0,
                "failures": 0,
                "duration_ms": 0,
                "tokens_est": 0,
                "output_bytes": 0,
                "events_bytes": 0,
                "budget_stops": 0,
                "warning_count": 0,
                "blocking_count": 0,
                "route_mismatch_count": 0,
                "max_severity": "none",
            },
        )
        bucket["runs"] += 1
        if item.get("status") not in {"succeeded", "stopped"}:
            bucket["failures"] += 1
        bucket["duration_ms"] += int(item.get("duration_ms") or 0)
        bucket["tokens_est"] += int(item.get("total_tokens_est") or 0)
        bucket["output_bytes"] += int(item.get("stdout_bytes") or 0) + int(item.get("stderr_bytes") or 0)
        bucket["events_bytes"] += int(item.get("events_bytes") or 0)
        bucket["warning_count"] += int(item.get("risk_warning_count") or 0)
        bucket["blocking_count"] += int(item.get("risk_blocking_count") or 0)
        if item.get("route_mismatch"):
            bucket["route_mismatch_count"] += 1
        severity = str(item.get("risk_max_severity") or "none")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(str(bucket.get("max_severity") or "none"), 0):
            bucket["max_severity"] = severity
        if item.get("stop_reason") in {"output_budget_exceeded", "events_budget_exceeded"}:
            bucket["budget_stops"] += 1
    result = {
        "ok": True,
        "date": target_date,
        "run_count": len(runs),
        "total_tokens_est": sum(int(item.get("total_tokens_est") or 0) for item in runs),
        "total_output_bytes": sum(int(item.get("stdout_bytes") or 0) + int(item.get("stderr_bytes") or 0) for item in runs),
        "total_events_bytes": sum(int(item.get("events_bytes") or 0) for item in runs),
        "budget_stop_count": sum(1 for item in runs if item.get("stop_reason") in {"output_budget_exceeded", "events_budget_exceeded"}),
        "total_duration_ms": sum(int(item.get("duration_ms") or 0) for item in runs),
        "failure_count": sum(1 for item in runs if item.get("status") not in {"succeeded", "stopped"}),
        "by_model": by_model,
        "runs": runs,
        "note": "Token counts are estimates from prompt/log characters; providers may bill differently.",
    }
    if write_report:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / f"usage-{target_date}.md"
        lines = ["# Daily Usage Summary", "", f"Date: `{target_date}`", "", f"- Runs: `{result['run_count']}`", f"- Estimated tokens: `{result['total_tokens_est']}`", f"- Output bytes: `{result['total_output_bytes']}`", f"- Events bytes: `{result['total_events_bytes']}`", f"- Output budget stops: `{result['budget_stop_count']}`", f"- Failures: `{result['failure_count']}`", "", "## By Model"]
        for model, bucket in by_model.items():
            lines.append(f"- `{model}`: runs `{bucket['runs']}`, failures `{bucket['failures']}`, duration `{bucket['duration_ms']}` ms, output bytes `{bucket['output_bytes']}`, events bytes `{bucket['events_bytes']}`, budget stops `{bucket['budget_stops']}`, warnings `{bucket['warning_count']}`, blocking `{bucket['blocking_count']}`, route mismatches `{bucket['route_mismatch_count']}`, max severity `{bucket['max_severity']}`, estimated tokens `{bucket['tokens_est']}`")
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        result["report_path"] = str(path)
    return result


BENCHMARK_SUITE_TASKS = [
    {"id": "code_fix", "role": "development", "task": "Fix this Python bug mentally and return only a short patch plan: def add(a,b): return a-b"},
    {"id": "review", "role": "review", "task": "Review this change for risks: a CLI command now runs shell=True on user input. Return top 3 risks."},
    {"id": "security", "role": "security", "task": "Find the secret-leak risks in logging provider env vars. Return concise findings."},
    {"id": "long_context", "role": "architecture", "task": "Summarize a 5-module project architecture from noisy notes and name the highest-risk dependency boundary."},
    {"id": "multimodal", "role": "multimodal", "task": "Plan how to inspect an image-driven UI task when an image is available. Do not require actual image input."},
]


def benchmark_suite(profile: str | None = None, execute: bool = False, timeout_seconds: int = 120) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for task in BENCHMARK_SUITE_TASKS:
        result = benchmark_model(profile=profile, role=task["role"], task=task["task"], timeout_seconds=timeout_seconds, execute=execute)
        items.append({"id": task["id"], "role": task["role"], **result})
    score = 0
    if execute and items:
        passed = sum(1 for item in items if item.get("ok"))
        avg_speed_bonus = sum(max(0, 120000 - int(item.get("duration_ms") or 120000)) for item in items) / len(items) / 120000
        score = round((passed / len(items)) * 85 + avg_speed_bonus * 15, 2)
    result = {
        "ok": all(item.get("ok", False) for item in items) if execute else True,
        "dry_run": not execute,
        "profile": profile,
        "score": score if execute else None,
        "tasks": items,
        "note": "Dry run avoids spending model quota. Pass execute=true for real CCSwitch benchmark data.",
    }
    if execute:
        append_model_benchmark_history({"recorded_at": utc_now_iso(), "type": "suite", **result})
        build_model_registry(refresh=True, apply=True)
    return result


def load_queue() -> dict[str, Any]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if QUEUE_PATH.exists():
        queue = json.loads(QUEUE_PATH.read_text(encoding="utf-8"))
        for job in queue.get("jobs", []):
            if job.get("status") == "pending":
                job["status"] = "queued"
            elif job.get("status") == "succeeded":
                job["status"] = "done"
        return queue
    return {"created_at": utc_now_iso(), "updated_at": None, "jobs": []}


def save_queue(queue: dict[str, Any]) -> None:
    queue["updated_at"] = utc_now_iso()
    QUEUE_PATH.write_text(json.dumps(queue, ensure_ascii=False, indent=2), encoding="utf-8")


def load_queue_policy() -> dict[str, Any]:
    policy = read_json_file(QUEUE_POLICY_PATH, {})
    defaults = {
        "max_concurrent": 3,
        "default_priority": 100,
        "default_timeout_seconds": 900,
        "retry_failed_read_only": 1,
        "retry_write_enabled": 0,
        "stop_timed_out": True,
    }
    defaults.update(policy if isinstance(policy, dict) else {})
    return defaults


def queue_policy(config: dict[str, Any] | None = None, apply: bool = False) -> dict[str, Any]:
    current = load_queue_policy()
    if config:
        current.update(config)
        current["updated_at"] = utc_now_iso()
    if apply:
        write_json_file(QUEUE_POLICY_PATH, current)
    return {"ok": True, "applied": apply, "path": str(QUEUE_POLICY_PATH), "policy": current}


def queue_submit(
    task: str,
    role: str = "implementation",
    priority: int = 100,
    cwd: Path | None = None,
    context: str | None = None,
    timeout_seconds: int | None = None,
    max_retries: int = 0,
    allow_write: bool = False,
) -> dict[str, Any]:
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    queue = load_queue()
    policy = load_queue_policy()
    job_id = "job-" + new_run_id()
    effective_timeout = timeout_seconds or int(policy.get("default_timeout_seconds", 900))
    effective_retries = max_retries
    if max_retries == 0:
        effective_retries = int(policy.get("retry_write_enabled" if allow_write else "retry_failed_read_only", 0))
    job = {
        "job_id": job_id,
        "status": "queued",
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "priority": priority if priority is not None else int(policy.get("default_priority", 100)),
        "task": task,
        "role": role,
        "cwd": str(cwd or Path.cwd()),
        "context": context,
        "timeout_seconds": effective_timeout,
        "max_retries": effective_retries,
        "attempts": 0,
        "allow_write": allow_write,
        "timeout_policy": "stop",
        "retry_policy": "read_only_default" if not allow_write else "write_disabled_by_default",
        "runs": [],
    }
    queue.setdefault("jobs", []).append(job)
    save_queue(queue)
    return {"ok": True, "job": job, "queue_path": str(QUEUE_PATH)}


def refresh_queue_job(job: dict[str, Any]) -> dict[str, Any]:
    if job.get("status") != "running" or not job.get("run_id"):
        return job
    status = single_run_status(str(job["run_id"]), include_output_tail=False)
    started_age = _iso_age_seconds(str(job.get("started_at") or ""))
    timeout = int(job.get("timeout_seconds") or 0)
    if status.get("active") and timeout and started_age is not None and started_age > timeout:
        stopped = stop_run(str(job["run_id"]), force=True)
        job["status"] = "timed_out"
        job["last_error"] = f"Queue timeout after {timeout}s; stop result: {stopped.get('status')}"
        job["updated_at"] = utc_now_iso()
        return job
    if status.get("active"):
        return job
    if status.get("status") == "succeeded":
        job["status"] = "done"
    elif status.get("status") == "timed_out":
        job["status"] = "timed_out"
        job["last_error"] = f"Run {job['run_id']} timed out."
    elif int(job.get("attempts") or 0) <= int(job.get("max_retries") or 0) and not bool(job.get("allow_write", False)):
        job["status"] = "queued"
        job["last_error"] = f"Run {job['run_id']} ended as {status.get('status')}; retry queued."
    else:
        job["status"] = "failed"
        job["last_error"] = f"Run {job['run_id']} ended as {status.get('status')}."
    job["updated_at"] = utc_now_iso()
    return job


def queue_tick(max_concurrent: int | None = None) -> dict[str, Any]:
    queue = load_queue()
    jobs = [refresh_queue_job(job) for job in queue.get("jobs", [])]
    active = run_status(include_finished=False).get("active_count", 0)
    guard = load_cost_guard()
    policy = load_queue_policy()
    limit = max_concurrent if max_concurrent is not None else min(int(policy.get("max_concurrent", 3)), int(guard.get("max_concurrent", 4)))
    slots = max(0, limit - int(active))
    started: list[dict[str, Any]] = []
    pending = sorted(
        [job for job in jobs if job.get("status") == "queued"],
        key=lambda item: (-int(item.get("priority") or 0), str(item.get("created_at") or "")),
    )
    for job in pending[:slots]:
        run = run_streaming_agent(
            task=str(job["task"]),
            role=str(job.get("role") or "implementation"),
            cwd=Path(str(job.get("cwd") or Path.cwd())),
            context=job.get("context"),
            timeout_seconds=job.get("timeout_seconds"),
            allow_write=bool(job.get("allow_write", False)),
        )
        job["status"] = "running"
        job["run_id"] = run["run_id"]
        job["started_at"] = utc_now_iso()
        job["attempts"] = int(job.get("attempts") or 0) + 1
        job["updated_at"] = utc_now_iso()
        job.setdefault("runs", []).append(run["run_id"])
        started.append({"job_id": job["job_id"], "run_id": run["run_id"], "role": job.get("role")})
    queue["jobs"] = jobs
    save_queue(queue)
    return {"ok": True, "queue_path": str(QUEUE_PATH), "max_concurrent": limit, "slots_used": len(started), "started": started, "jobs": jobs}


def queue_status(include_finished: bool = True) -> dict[str, Any]:
    queue = load_queue()
    all_jobs = [refresh_queue_job(job) for job in queue.get("jobs", [])]
    queue["jobs"] = all_jobs
    save_queue(queue)
    jobs = all_jobs
    if not include_finished:
        jobs = [job for job in all_jobs if job.get("status") in {"queued", "running"}]
    counts: dict[str, int] = {}
    for job in all_jobs:
        counts[str(job.get("status") or "unknown")] = counts.get(str(job.get("status") or "unknown"), 0) + 1
    return {"ok": True, "queue_path": str(QUEUE_PATH), "policy": load_queue_policy(), "count": len(jobs), "state_counts": counts, "jobs": jobs}


def queue_cancel(job_id: str) -> dict[str, Any]:
    if not QUEUE_JOB_ID_RE.match(job_id):
        raise OrchestratorError(f"Invalid queue job id: {job_id}")
    queue = load_queue()
    for job in queue.get("jobs", []):
        if job.get("job_id") != job_id:
            continue
        if job.get("status") == "running" and job.get("run_id"):
            stop_run(str(job["run_id"]), force=True)
        job["status"] = "cancelled"
        job["updated_at"] = utc_now_iso()
        save_queue(queue)
        return {"ok": True, "job": job}
    raise OrchestratorError(f"Queue job not found: {job_id}")


def read_version() -> dict[str, Any]:
    data = read_json_file(VERSION_PATH, {})
    if not data:
        data = {"version": "0.0.0", "schema_version": 1}
    return data


def upgrade_check(apply: bool = False) -> dict[str, Any]:
    version = read_version()
    state = read_json_file(VERSION_STATE_PATH, {})
    preserve_files = [
        CALIBRATION_PATH,
        COST_GUARD_PATH,
        LOCAL_POLICY_OVERRIDE_PATH,
        MODEL_REGISTRY_PATH,
        MODEL_BENCHMARK_HISTORY_PATH,
        WORKER_QUALITY_HISTORY_PATH,
        QUEUE_POLICY_PATH,
        VERSION_STATE_PATH,
    ]
    preserved: list[dict[str, Any]] = []
    for path in preserve_files:
        item = {"path": str(path), "exists": path.exists()}
        if path.exists():
            item.update(file_sha256(path))
        preserved.append(item)
    actions = []
    if state.get("current_version") != version.get("version"):
        actions.append({"type": "version_state_update", "from": state.get("current_version"), "to": version.get("version")})
    if CALIBRATION_PATH.exists():
        actions.append({"type": "preserve_local_model_calibration", "path": str(CALIBRATION_PATH)})
    if COST_GUARD_PATH.exists():
        actions.append({"type": "preserve_cost_guard", "path": str(COST_GUARD_PATH)})
    if LOCAL_POLICY_OVERRIDE_PATH.exists():
        actions.append({"type": "preserve_local_policy_override", "path": str(LOCAL_POLICY_OVERRIDE_PATH)})
    if MODEL_REGISTRY_PATH.exists():
        actions.append({"type": "preserve_model_registry", "path": str(MODEL_REGISTRY_PATH)})
    if WORKER_QUALITY_HISTORY_PATH.exists():
        actions.append({"type": "preserve_worker_quality_history", "path": str(WORKER_QUALITY_HISTORY_PATH)})
    if apply:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        new_state = {
            "updated_at": utc_now_iso(),
            "current_version": version.get("version"),
            "schema_version": version.get("schema_version", 1),
            "previous_state": state or None,
            "preserved_files": preserved,
        }
        VERSION_STATE_PATH.write_text(json.dumps(new_state, ensure_ascii=False, indent=2), encoding="utf-8")
        preserved = []
        for path in preserve_files:
            item = {"path": str(path), "exists": path.exists()}
            if path.exists():
                item.update(file_sha256(path))
            preserved.append(item)
    return {
        "ok": True,
        "applied": apply,
        "version": version,
        "state_path": str(VERSION_STATE_PATH),
        "previous_state": state,
        "actions": actions,
        "preserved_files": preserved,
        "note": "Local calibration, overrides, model registry, quality history, queue policy, and cost guard files are user-owned and should survive upgrades.",
    }


def write_fake_claude_launcher(directory: Path) -> Path:
    script = directory / "fake_claude.py"
    script.write_text(
        "\n".join(
            [
                "import json, os, sys, time",
                "steps = int(os.environ.get('CC_ORCHESTRATOR_FAKE_STEPS', '4'))",
                "delay = float(os.environ.get('CC_ORCHESTRATOR_FAKE_DELAY', '0.05'))",
                "payload_bytes = int(os.environ.get('CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES', '0'))",
                "payload = 'x' * payload_bytes",
                "model_usage = {'fake-model': {'inputTokens': 123, 'outputTokens': 45, 'costUSD': 0.99, 'contextWindow': 200000, 'maxOutputTokens': 4096}}",
                "print(json.dumps({'type':'system','subtype':'init','cwd':os.getcwd()}), flush=True)",
                "for i in range(steps):",
                "    print(json.dumps({'type':'assistant','phase':f'mock-step-{i}','thinking_tokens':i,'message':{'content':[{'type':'text','text':f'mock step {i} {payload}'}]}}), flush=True)",
                "    time.sleep(delay)",
                "print(json.dumps({'type':'result','subtype':'success','result':'mock complete','modelUsage':model_usage}), flush=True)",
            ]
        ),
        encoding="utf-8",
    )
    if os.name == "nt":
        launcher = directory / "fake-claude.cmd"
        launcher.write_text(f"@echo off\r\n\"{sys.executable}\" \"{script}\"\r\n", encoding="utf-8")
    else:
        launcher = directory / "fake-claude"
        launcher.write_text(f"#!/usr/bin/env sh\nexec \"{sys.executable}\" \"{script}\"\n", encoding="utf-8")
        launcher.chmod(0o755)
    return launcher


def mock_stream_test(timeout_seconds: int = 20) -> dict[str, Any]:
    gates: dict[str, bool] = {}
    details: dict[str, Any] = {}
    old_bin = os.environ.get("CLAUDE_CODE_BIN")
    old_steps = os.environ.get("CC_ORCHESTRATOR_FAKE_STEPS")
    old_delay = os.environ.get("CC_ORCHESTRATOR_FAKE_DELAY")
    old_payload = os.environ.get("CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES")
    mock_parent = Path(os.environ.get("PROGRAMDATA") or "C:/ProgramData") / "cc-orchestrator-mock"
    mock_dir = mock_parent / uuid.uuid4().hex[:12]
    mock_dir.mkdir(parents=True, exist_ok=False)
    launcher = write_fake_claude_launcher(mock_dir)
    os.environ["CLAUDE_CODE_BIN"] = str(launcher)
    cleanup_mock_dir = os.environ.get("CC_ORCHESTRATOR_CLEAN_MOCK_DIR") == "1"
    try:
            os.environ["CC_ORCHESTRATOR_FAKE_STEPS"] = "4"
            os.environ["CC_ORCHESTRATOR_FAKE_DELAY"] = "0.05"
            finish_run = run_streaming_agent("mock finish test", role="testing", timeout_seconds=timeout_seconds)
            deadline = time.time() + timeout_seconds
            finish_poll: dict[str, Any] = {}
            while time.time() < deadline:
                finish_poll = poll_run(finish_run["run_id"], include_output_tail=True)
                status_name = finish_poll["status"].get("status")
                if (not finish_poll["status"].get("active")) and status_name in {"succeeded", "failed", "timed_out", "stopped"}:
                    break
                time.sleep(0.1)
            gates["finish_run_succeeded"] = finish_poll.get("status", {}).get("status") == "succeeded"
            gates["events_ndjson_written"] = int(finish_poll.get("events", {}).get("size") or 0) > 0
            gates["poll_returned_events"] = bool(finish_poll.get("events", {}).get("items"))

            os.environ["CC_ORCHESTRATOR_FAKE_STEPS"] = "200"
            os.environ["CC_ORCHESTRATOR_FAKE_DELAY"] = "0.1"
            stop_run_data = run_streaming_agent("mock stop test", role="testing", timeout_seconds=60)
            before_stop = {}
            deadline = time.time() + 5
            while time.time() < deadline:
                before_stop = run_status(run_id=stop_run_data["run_id"])
                if before_stop.get("active"):
                    break
                time.sleep(0.1)
            stopped = stop_run(stop_run_data["run_id"], force=True)
            after_stop = run_status(run_id=stop_run_data["run_id"])
            gates["status_saw_active_worker"] = bool(before_stop.get("active"))
            gates["stop_run_stopped_worker"] = bool(stopped.get("stopped")) or not bool(after_stop.get("active"))
            gates["status_after_stop_inactive"] = not bool(after_stop.get("active"))

            os.environ["CC_ORCHESTRATOR_FAKE_STEPS"] = "20"
            os.environ["CC_ORCHESTRATOR_FAKE_DELAY"] = "0.01"
            os.environ["CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES"] = "4096"
            budget_run = run_streaming_agent(
                "mock output budget test",
                role="testing",
                timeout_seconds=timeout_seconds,
                max_output_bytes=3000,
                max_events_bytes=200000,
                output_budget_policy="truncate",
            )
            deadline = time.time() + timeout_seconds
            budget_status: dict[str, Any] = {}
            while time.time() < deadline:
                budget_status = run_status(run_id=budget_run["run_id"])
                if not budget_status.get("active"):
                    break
                time.sleep(0.1)
            budget_meta = read_metadata(safe_run_dir(budget_run["run_id"]))
            budget_state = budget_meta.get("output_budget") or {}
            gates["output_budget_truncated_without_hang"] = budget_status.get("status") in {"succeeded", "stopped"} and budget_state.get("state") == "truncated"
            gates["output_budget_reason_recorded"] = budget_meta.get("stop_reason") == "output_budget_exceeded" or budget_state.get("stop_reason") == "output_budget_exceeded"

            os.environ["CC_ORCHESTRATOR_FAKE_STEPS"] = "12"
            os.environ["CC_ORCHESTRATOR_FAKE_DELAY"] = "0"
            os.environ["CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES"] = "4096"
            final_only_run = run_streaming_agent(
                "mock final-only budget test",
                role="testing",
                timeout_seconds=timeout_seconds,
                max_output_bytes=20000,
                max_events_bytes=200000,
                final_only=True,
                final_max_chars=1200,
            )
            deadline = time.time() + timeout_seconds
            final_only_status: dict[str, Any] = {}
            while time.time() < deadline:
                final_only_status = run_status(run_id=final_only_run["run_id"], include_output_tail=True)
                if not final_only_status.get("active"):
                    break
                time.sleep(0.1)
            final_only_dir = safe_run_dir(final_only_run["run_id"])
            final_only_meta = read_metadata(final_only_dir)
            final_only_stdout = (final_only_dir / "stdout.txt").read_text(encoding="utf-8", errors="replace")
            final_only_budget = final_only_meta.get("output_budget") or {}
            gates["final_only_completed_under_low_budget"] = final_only_status.get("status") == "succeeded" and final_only_meta.get("stop_reason") not in {"output_budget_exceeded", "events_budget_exceeded"}
            gates["final_only_stdout_is_compact"] = "mock complete" in final_only_stdout and "thinking_tokens" not in final_only_stdout and '"type": "assistant"' not in final_only_stdout and len(final_only_stdout.encode("utf-8")) < 20000
            gates["actual_model_usage_tokens_preserved"] = final_only_meta.get("actual_input_tokens") == 123 and final_only_meta.get("actual_output_tokens") == 45 and final_only_meta.get("actual_total_tokens") == 168
            gates["actual_model_usage_cost_preserved"] = abs(float(final_only_meta.get("actual_cost_usd") or 0) - 0.99) < 0.000001

            cwd_target = mock_dir / "target-中文路径"
            cwd_target.mkdir(parents=True, exist_ok=True)
            init_workspace(cwd=cwd_target, write_claude=False, repair_mcp=False)
            cwd_paths = workspace_paths(cwd_target)
            cwd_run_id = new_run_id()
            cwd_run_dir = cwd_paths["runs"] / cwd_run_id
            cwd_run_dir.mkdir(parents=True, exist_ok=False)
            register_run_dir(cwd_run_id, cwd_run_dir, cwd_paths["workspace_root"], cwd_paths["artifact_root"])
            cwd_prompt = build_prompt("testing", "mock cwd artifact root test", artifact_root=cwd_paths["artifact_root"])
            write_metadata(
                cwd_run_dir,
                {
                    "run_id": cwd_run_id,
                    "status": "succeeded",
                    "cwd": str(cwd_target.resolve()),
                    "artifact_root": str(cwd_paths["artifact_root"].resolve()),
                    "runs_root": str(cwd_paths["runs"].resolve()),
                },
            )
            gates["cwd_run_uses_cwd_artifact_root"] = cwd_run_dir.parent.resolve() == cwd_paths["runs"].resolve()
            gates["cwd_prompt_uses_cwd_artifact_root"] = str(cwd_paths["artifact_root"].resolve()) in cwd_prompt
            gates["cwd_metadata_records_artifact_root"] = Path(str(read_metadata(cwd_run_dir).get("artifact_root"))).resolve() == cwd_paths["artifact_root"].resolve()
            gates["cwd_safe_run_dir_finds_indexed_run"] = safe_run_dir(cwd_run_id).resolve() == cwd_run_dir.resolve()
            tampered_dir = mock_dir / "outside-index" / cwd_run_id
            tampered_dir.mkdir(parents=True, exist_ok=True)
            write_json_file(
                RUN_INDEX_DIR / f"{cwd_run_id}.json",
                {
                    "run_id": cwd_run_id,
                    "run_dir": str(tampered_dir.resolve()),
                    "workspace_root": str(cwd_paths["workspace_root"].resolve()),
                    "artifact_root": str(cwd_paths["artifact_root"].resolve()),
                    "registered_at": utc_now_iso(),
                },
            )
            try:
                safe_run_dir(cwd_run_id)
                gates["cwd_tampered_run_index_rejected"] = False
            except OrchestratorError:
                gates["cwd_tampered_run_index_rejected"] = True
            register_run_dir(cwd_run_id, cwd_run_dir, cwd_paths["workspace_root"], cwd_paths["artifact_root"])
            gates["cwd_global_run_dir_not_created"] = not (RUNS_DIR / cwd_run_id).exists()
            details = {
                "finish_run_id": finish_run["run_id"],
                "finish_poll": finish_poll,
                "stop_run_id": stop_run_data["run_id"],
                "before_stop": before_stop,
                "stop_result": stopped,
                "after_stop": after_stop,
                "budget_run_id": budget_run["run_id"],
                "budget_status": budget_status,
                "budget_state": budget_state,
                "final_only_run_id": final_only_run["run_id"],
                "final_only_status": final_only_status,
                "final_only_stdout_bytes": len(final_only_stdout.encode("utf-8")),
                "final_only_budget": final_only_budget,
                "cwd_run_id": cwd_run_id,
                "cwd_run_dir": str(cwd_run_dir),
                "cwd_expected_runs": str(cwd_paths["runs"]),
            }
    finally:
        if old_bin is None:
            os.environ.pop("CLAUDE_CODE_BIN", None)
        else:
            os.environ["CLAUDE_CODE_BIN"] = old_bin
        if old_steps is None:
            os.environ.pop("CC_ORCHESTRATOR_FAKE_STEPS", None)
        else:
            os.environ["CC_ORCHESTRATOR_FAKE_STEPS"] = old_steps
        if old_delay is None:
            os.environ.pop("CC_ORCHESTRATOR_FAKE_DELAY", None)
        else:
            os.environ["CC_ORCHESTRATOR_FAKE_DELAY"] = old_delay
        if old_payload is None:
            os.environ.pop("CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES", None)
        else:
            os.environ["CC_ORCHESTRATOR_FAKE_PAYLOAD_BYTES"] = old_payload
        if cleanup_mock_dir:
            shutil.rmtree(mock_dir, ignore_errors=True)
        else:
            details["mock_dir"] = str(mock_dir)
    return {"ok": all(gates.values()), "gates": gates, "details": details}


def run_visible_agent(
    task: str,
    role: str = "implementation",
    task_type: str | None = None,
    profile: str | None = None,
    allow_write: bool = False,
    cwd: Path | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    """Open Claude Code in a visible PowerShell window with selected provider env."""
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    provider = get_provider(route["profile"])
    permission_mode = route["permission_mode"] if not allow_write else "acceptEdits"
    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    paths = workspace_paths(effective_cwd)
    prompt = build_prompt(role, task, context, artifact_root=paths["artifact_root"])
    safe_prompt = str(redact(prompt))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = paths["runs"] / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    register_run_dir(run_id, run_dir, paths["workspace_root"], paths["artifact_root"])
    prompt_path = run_dir / "prompt.txt"
    bootstrap_path = run_dir / "start-visible.ps1"
    prompt_path.write_text(safe_prompt, encoding="utf-8")
    env = build_worker_env(provider.env, route.get("model_override"), workspace_root=paths["workspace_root"], artifact_root=paths["artifact_root"])
    env_for_log: dict[str, str] = {}
    for key, value in provider.env.items():
        env_for_log[key] = value
    if route.get("model_override"):
        env_for_log["ANTHROPIC_MODEL"] = str(route["model_override"])
    env_for_log["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    console_lines = [
        "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()",
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()",
        "$OutputEncoding = [System.Text.UTF8Encoding]::new()",
    ]
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"Set-Location -LiteralPath {json.dumps(str(effective_cwd))}",
            *console_lines,
            f"$prompt = Get-Content -Raw -LiteralPath {json.dumps(str(prompt_path))}",
            f"& {json.dumps(claude_bin_path())} --permission-mode {permission_mode} $prompt",
            "Write-Host ''",
            "Write-Host 'Claude Code session ended. Press Enter to close this window.'",
            "[void][Console]::ReadLine()",
        ]
    )
    bootstrap_path.write_text(script, encoding="utf-8")
    metadata = {
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mode": "visible_window",
        "cwd": str(effective_cwd),
        "workspace_root": str(paths["workspace_root"]),
        "artifact_root": str(paths["artifact_root"]),
        "runs_root": str(paths["runs"]),
        "role": role,
        "task_type": route["task_type"],
        "profile": {
            "id": provider.id,
            "name": provider.name,
            "model": route.get("model_override") or provider.model,
            "provider_default_model": provider.model,
            "base_url": provider.env.get("ANTHROPIC_BASE_URL"),
            "endpoints": provider.endpoints,
        },
        "permission_mode": permission_mode,
        "allow_write": allow_write,
        "prompt_path": str(prompt_path),
        "bootstrap_path": str(bootstrap_path),
        "env": redact(env_for_log),
    }
    write_metadata(run_dir, metadata)
    subprocess.Popen(
        [
            "powershell",
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(bootstrap_path),
        ],
        cwd=str(effective_cwd),
        env=env,
        creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
    )
    paths["runs"].mkdir(parents=True, exist_ok=True)
    (paths["runs"] / "latest.txt").write_text(run_id, encoding="utf-8")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    (RUNS_DIR / "latest.txt").write_text(run_id, encoding="utf-8")
    return metadata


def git_diff(cwd: Path | None = None, limit_chars: int = 12000) -> dict[str, Any]:
    effective_cwd = cwd or Path.cwd()
    if not (effective_cwd / ".git").exists():
        return {"ok": False, "error": f"Not a git repository: {effective_cwd}"}
    proc = subprocess.run(
        ["git", "diff", "--", "."],
        cwd=str(effective_cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    text = proc.stdout or proc.stderr or ""
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "cwd": str(effective_cwd),
        "truncated": len(text) > limit_chars,
        "diff": text[:limit_chars],
    }


def run_workflow_plan(task: str, cwd: Path | None = None) -> dict[str, Any]:
    """Return a deterministic multi-agent run plan without launching every agent."""
    steps = []
    for role in ROLE_ORDER:
        route = resolve_route(role=role)
        provider = get_provider(route["profile"])
        steps.append(
            {
                "role": role,
                "task_type": route["task_type"],
                "profile": provider.name,
                "model": route.get("model_override") or provider.model,
                "permission_mode": route["permission_mode"],
                "timeout_seconds": route["timeout_seconds"],
                "selection_score": (route.get("auto_selection") or {}).get("score"),
                "selection_role": route.get("selection_role", role),
                "reason": route.get("reason", ""),
            }
        )
    return {
        "task": task,
        "cwd": str(cwd or Path.cwd()),
        "controller": "codex",
        "worker_roles": ROLE_ORDER,
        "phases": [
            "parallel_analysis",
            "cross_review",
            "execution",
            "controller_summary",
        ],
        "steps": steps,
    }


HANDOFF_REQUIRED_FIELDS: dict[str, list[str]] = {
    "base": ["schema_version", "run_id", "role", "status", "summary"],
    "requirements": ["requirements", "boundaries", "acceptance_criteria"],
    "architecture": ["touched_files", "dependencies", "plan", "risks"],
    "development": ["changed_files", "write_scope", "commands_run"],
    "implementation": ["changed_files", "write_scope", "commands_run"],
    "testing": ["tests_run", "failures", "coverage_gaps"],
    "review": ["findings", "blocking_issues", "residual_risk"],
    "security": ["findings", "secret_exposure", "permissions", "blocking_status"],
    "ops": ["deploy_impact", "rollback", "observability", "release_risk"],
    "supervisor": ["verdict", "confidence", "objections", "missing_evidence"],
}


def handoff_required_fields(role: str) -> list[str]:
    return HANDOFF_REQUIRED_FIELDS["base"] + HANDOFF_REQUIRED_FIELDS.get(role, [])


def handoff_template(role: str = "testing") -> dict[str, Any]:
    if role not in ROLE_ORDER and role not in HANDOFF_REQUIRED_FIELDS:
        raise OrchestratorError(f"Unknown handoff role: {role}")
    example: dict[str, Any] = {
        "schema_version": 1,
        "run_id": "20260615T000000Z-example",
        "node_id": role,
        "role": role,
        "status": "pass",
        "summary": f"Example {role} handoff.",
        "inputs_consumed": [],
        "changed_files": [],
        "commands_run": [],
        "risks": [],
        "blocking_issues": [],
        "next_inputs": {},
    }
    for field in HANDOFF_REQUIRED_FIELDS.get(role, []):
        example.setdefault(field, [] if field not in {"write_scope", "blocking_status", "confidence", "verdict"} else {})
    if role == "supervisor":
        example["verdict"] = "approve"
        example["confidence"] = "medium"
    schema = {
        "schema_version": 1,
        "role": role,
        "required": handoff_required_fields(role),
        "status_values": ["pass", "fail", "blocked", "needs_repair"],
        "note": "This compact contract is intentionally controller-validated and backwards-compatible with ad-hoc runs.",
    }
    return {"ok": True, "role": role, "schema": schema, "example": example}


def validate_handoff_data(handoff: Any, role: str | None = None, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(handoff, dict):
        return {"ok": False, "missing_fields": handoff_required_fields(role or "testing"), "errors": ["handoff_not_object"], "blocking_count": 1}
    effective_role = role or str(handoff.get("role") or "testing")
    required = list((schema or {}).get("required") or handoff_required_fields(effective_role))
    missing = [field for field in required if field not in handoff or handoff.get(field) in (None, "")]
    errors: list[str] = []
    status = str(handoff.get("status") or "")
    if status and status not in {"pass", "fail", "blocked", "needs_repair"}:
        errors.append("invalid_status")
    blocking_count = len(handoff.get("blocking_issues") or []) if isinstance(handoff.get("blocking_issues"), list) else 0
    if missing:
        errors.append("missing_required_fields")
    return {
        "ok": not missing and not errors,
        "role": effective_role,
        "status": status or None,
        "missing_fields": missing,
        "errors": errors,
        "blocking_count": blocking_count,
    }


def handoff_path_for_run(run_id: str) -> Path:
    return safe_run_dir(run_id) / "handoff.json"


def handoff_read(run_id: str) -> dict[str, Any]:
    path = handoff_path_for_run(run_id)
    if not path.exists():
        return {"ok": False, "run_id": run_id, "path": str(path), "error": "handoff.json not found"}
    return {"ok": True, "run_id": run_id, "path": str(path), "handoff": read_json_file(path, {})}


def handoff_validate(run_id: str, schema_path: str | Path | None = None) -> dict[str, Any]:
    if schema_path:
        raise OrchestratorError("External handoff schema files are disabled in v0.7.0; use the built-in role schema.")
    read = handoff_read(run_id)
    if not read.get("ok"):
        result = {"ok": False, "run_id": run_id, "missing_fields": ["handoff.json"], "errors": [read.get("error")]}
    else:
        result = validate_handoff_data(read.get("handoff"))
        result.update({"run_id": run_id, "path": read.get("path")})
    validation_path = safe_run_dir(run_id) / "handoff.validation.json"
    write_json_file(validation_path, result)
    result["validation_path"] = str(validation_path)
    return result


def handoff_repair_prompt(run_id: str) -> dict[str, Any]:
    validation = handoff_validate(run_id)
    missing = validation.get("missing_fields") or []
    prompt = (
        "Return only a JSON handoff object. "
        f"Run id: {run_id}. "
        f"Missing required fields: {', '.join(missing) if missing else 'none'}. "
        "Do not include markdown fences or prose."
    )
    return {"ok": True, "run_id": run_id, "validation": validation, "prompt": prompt}


def resolve_workflow_spec_path(file: str | Path, cwd: str | Path | None = None) -> Path:
    raw_path = Path(file).expanduser()
    if cwd is None:
        return raw_path.resolve()
    root = Path(cwd).expanduser().resolve()
    path = raw_path if raw_path.is_absolute() else root / raw_path
    resolved = path.resolve()
    artifact_root = workspace_paths(root)["artifact_root"].resolve()
    if not path_under(resolved, root) and not path_under(resolved, artifact_root):
        raise OrchestratorError(f"Workflow file is outside cwd and managed artifact workspace: {resolved}")
    return resolved


def load_workflow_spec(file: str | Path, cwd: str | Path | None = None) -> dict[str, Any]:
    path = resolve_workflow_spec_path(file, cwd=cwd)
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
        except Exception as exc:
            try:
                data = parse_simple_workflow_yaml(text)
            except Exception as fallback_exc:
                raise OrchestratorError(f"Cannot parse workflow YAML: {exc}; fallback parser also failed: {fallback_exc}") from fallback_exc
    if not isinstance(data, dict):
        raise OrchestratorError(f"Workflow file must contain an object: {path}")
    data["_source_file"] = str(path)
    data["_source_text"] = text
    return data


def workflow_error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}


def parse_simple_yaml_scalar(value: str) -> Any:
    raw = value.strip()
    if raw == "":
        return ""
    if raw in {"true", "True"}:
        return True
    if raw in {"false", "False"}:
        return False
    if raw in {"null", "Null", "~"}:
        return None
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [parse_simple_yaml_scalar(part.strip()) for part in inner.split(",")]
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if re.fullmatch(r"-?\d+\.\d+", raw):
        return float(raw)
    return raw


def parse_simple_workflow_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by workflow specs when PyYAML is absent."""
    rows: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        rows.append((indent, raw_line.strip()))
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for index, (indent, content) in enumerate(rows):
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise OrchestratorError("Invalid workflow YAML indentation.")
        parent = stack[-1][1]
        if content.startswith("- "):
            if not isinstance(parent, list):
                raise OrchestratorError("YAML list item appeared under a non-list parent.")
            parent.append(parse_simple_yaml_scalar(content[2:].strip()))
            continue
        if ":" not in content:
            raise OrchestratorError(f"Invalid workflow YAML line: {content}")
        key, value = content.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not isinstance(parent, dict):
            raise OrchestratorError("YAML mapping item appeared under a non-map parent.")
        if value:
            parent[key] = parse_simple_yaml_scalar(value)
            continue
        next_is_list = False
        for next_indent, next_content in rows[index + 1 :]:
            if next_indent <= indent:
                break
            next_is_list = next_content.startswith("- ")
            break
        container: Any = [] if next_is_list else {}
        parent[key] = container
        stack.append((indent, container))

    return root


def normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def workflow_nodes(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = spec.get("nodes")
    if not isinstance(raw, dict) or not raw:
        raise OrchestratorError("Workflow must define a non-empty nodes map.")
    return {str(node_id): (node if isinstance(node, dict) else {}) for node_id, node in raw.items()}


def workflow_graph(nodes: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    return {node_id: [str(item) for item in normalize_list(node.get("needs"))] for node_id, node in nodes.items()}


def workflow_descendants(nodes: dict[str, dict[str, Any]], node_id: str) -> set[str]:
    graph = workflow_graph(nodes)
    result: set[str] = set()
    changed = True
    while changed:
        changed = False
        for candidate, needs in graph.items():
            if candidate in result:
                continue
            if node_id in needs or any(item in needs for item in result):
                result.add(candidate)
                changed = True
    return result


def workflow_topological_batches(nodes: dict[str, dict[str, Any]]) -> list[list[str]]:
    graph = workflow_graph(nodes)
    remaining = set(nodes)
    batches: list[list[str]] = []
    while remaining:
        ready = sorted(node_id for node_id in remaining if all(dep not in remaining for dep in graph[node_id]))
        if not ready:
            raise OrchestratorError("cycle_detected")
        batches.append(ready)
        remaining.difference_update(ready)
    return batches


def validate_workflow_spec(spec: dict[str, Any]) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    nodes = workflow_nodes(spec)
    for node_id, node in nodes.items():
        node_type = str(node.get("type") or "worker")
        needs = [str(item) for item in normalize_list(node.get("needs"))]
        for dep in needs:
            if dep not in nodes:
                errors.append({"code": "missing_dependency", "node_id": node_id, "dependency": dep})
        if node_type != "gate":
            role = str(node.get("role") or "")
            if role not in ROLE_ORDER:
                errors.append({"code": "unknown_role", "node_id": node_id, "role": role})
            if not node.get("outputs"):
                errors.append({"code": "missing_outputs", "node_id": node_id})
            if bool(node.get("allow_write")) and not isinstance(node.get("write_scope"), dict):
                errors.append({"code": "missing_write_scope", "node_id": node_id})
            write_scope = node.get("write_scope") or {}
            if write_scope and not isinstance(write_scope.get("allow"), list):
                errors.append({"code": "invalid_write_scope", "node_id": node_id, "field": "allow"})
        else:
            on_fail = node.get("on_fail") or {}
            if on_fail and (not isinstance(on_fail, dict) or ("retry" in on_fail and "max_retries" not in on_fail)):
                errors.append({"code": "missing_max_retries", "node_id": node_id})
            if isinstance(on_fail, dict) and on_fail.get("retry") and str(on_fail["retry"]) not in nodes:
                errors.append({"code": "missing_retry_target", "node_id": node_id, "target": on_fail.get("retry")})
    if not errors:
        try:
            workflow_topological_batches(nodes)
        except OrchestratorError:
            errors.append({"code": "cycle_detected"})
    batches: list[list[str]] = []
    if not errors:
        batches = workflow_topological_batches(nodes)
    return {
        "ok": not errors,
        "workflow": {"id": spec.get("id"), "description": spec.get("description")},
        "node_count": len(nodes),
        "edge_count": sum(len(normalize_list(node.get("needs"))) for node in nodes.values()),
        "batches": batches,
        "errors": errors,
    }


def workflow_validate(file: str | Path, cwd: Path | None = None) -> dict[str, Any]:
    spec = load_workflow_spec(file, cwd=cwd)
    result = validate_workflow_spec(spec)
    result["source_file"] = spec.get("_source_file")
    return result


def workflow_dry_run(file: str | Path, task: str | None = None, cwd: Path | None = None) -> dict[str, Any]:
    spec = load_workflow_spec(file, cwd=cwd)
    validation = validate_workflow_spec(spec)
    if not validation.get("ok"):
        return {**validation, "source_file": spec.get("_source_file"), "launched_workers": 0}
    nodes = workflow_nodes(spec)
    batches = validation["batches"]
    fan_out = {node_id: sorted(workflow_descendants(nodes, node_id)) for node_id in nodes}
    return {
        "ok": True,
        "source_file": spec.get("_source_file"),
        "task": task,
        "cwd": str(cwd or Path.cwd()),
        "workflow_id": spec.get("id"),
        "batches": batches,
        "execution_order": [node_id for batch in batches for node_id in batch],
        "fan_out": fan_out,
        "fan_in": {node_id: [str(item) for item in normalize_list(node.get("needs"))] for node_id, node in nodes.items()},
        "launched_workers": 0,
    }


def new_workflow_id() -> str:
    return "wf-" + new_run_id()


def register_workflow_dir(workflow_id: str, workflow_dir: Path, workspace_root: Path, artifact_root: Path) -> None:
    WORKFLOW_INDEX_DIR.mkdir(parents=True, exist_ok=True)
    write_json_file(
        WORKFLOW_INDEX_DIR / f"{workflow_id}.json",
        {
            "workflow_id": workflow_id,
            "workflow_dir": str(workflow_dir.resolve()),
            "workspace_root": str(workspace_root.resolve()),
            "artifact_root": str(artifact_root.resolve()),
            "registered_at": utc_now_iso(),
        },
    )


def safe_workflow_dir(workflow_id: str, cwd: Path | None = None) -> Path:
    if not WORKFLOW_ID_RE.match(workflow_id):
        raise OrchestratorError(f"Invalid workflow id: {workflow_id}")
    paths = workspace_paths(cwd) if cwd else None
    candidates: list[Path] = []
    if paths:
        candidates.append((paths["workflows"] / workflow_id).resolve())
    candidates.append((WORKFLOWS_DIR / workflow_id).resolve())
    index_path = WORKFLOW_INDEX_DIR / f"{workflow_id}.json"
    if index_path.exists():
        index = read_json_file(index_path, {})
        return validate_indexed_workflow_dir(workflow_id, index, index_path)
    for candidate in candidates:
        if candidate.exists() and candidate.name == workflow_id:
            return candidate
    return candidates[0]


def validate_indexed_workflow_dir(workflow_id: str, index: dict[str, Any], index_path: Path) -> Path:
    if not isinstance(index, dict) or not index:
        raise OrchestratorError(f"Invalid workflow index: {index_path}")
    if str(index.get("workflow_id") or "") != workflow_id:
        raise OrchestratorError(f"Workflow index id mismatch: {index_path}")
    missing = [key for key in ("workflow_dir", "workspace_root", "artifact_root") if not index.get(key)]
    if missing:
        raise OrchestratorError(f"Workflow index missing {', '.join(missing)}: {index_path}")
    workspace_root = Path(str(index["workspace_root"])).expanduser().resolve()
    artifact_root = Path(str(index["artifact_root"])).expanduser().resolve()
    workflow_dir = Path(str(index["workflow_dir"])).expanduser().resolve()
    expected_artifact_root = (workspace_root / AGENT_WORKSPACE_DIRNAME / ARTIFACT_NAMESPACE).resolve()
    if artifact_root != expected_artifact_root:
        raise OrchestratorError(f"Workflow index artifact root does not match workspace root: {index_path}")
    workflows_root = (artifact_root / "workflows").resolve()
    try:
        workflow_dir.relative_to(workflows_root)
    except ValueError as exc:
        raise OrchestratorError(f"Indexed workflow dir resolves outside artifact workflows root: {index_path}") from exc
    if workflow_dir.name != workflow_id:
        raise OrchestratorError(f"Indexed workflow dir name does not match workflow id: {index_path}")
    if not workflow_dir.exists():
        raise OrchestratorError(f"Indexed workflow dir does not exist: {workflow_dir}")
    return workflow_dir


def write_workflow_status(workflow_dir: Path, status: dict[str, Any]) -> Path:
    status["updated_at"] = utc_now_iso()
    return write_json_file(workflow_dir / "status.json", status)


def read_workflow_status(workflow_id: str, cwd: Path | None = None) -> dict[str, Any]:
    workflow_dir = safe_workflow_dir(workflow_id, cwd=cwd)
    status = read_json_file(workflow_dir / "status.json", {})
    if not status:
        raise OrchestratorError(f"Workflow status not found: {workflow_id}")
    return status


def workflow_mock_handoff(node_id: str, node: dict[str, Any], run_id: str, status_value: str) -> dict[str, Any]:
    role = str(node.get("role") or "testing")
    handoff = handoff_template(role)["example"]
    handoff.update(
        {
            "run_id": run_id,
            "node_id": node_id,
            "role": role,
            "status": status_value,
            "summary": f"Mock {node_id} completed with status {status_value}.",
            "blocking_issues": [] if status_value == "pass" else [{"severity": "high", "description": "Mock failure"}],
        }
    )
    return handoff


def create_mock_workflow_run_node(paths: dict[str, Path], workflow_dir: Path, workflow_id: str, node_id: str, node: dict[str, Any], attempt: int) -> dict[str, Any]:
    sequence = normalize_list(node.get("mock_status_sequence")) or [node.get("mock_status") or "pass"]
    status_value = str(sequence[min(attempt, len(sequence) - 1)] or "pass")
    run_id = new_run_id()
    run_dir = paths["runs"] / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    register_run_dir(run_id, run_dir, paths["workspace_root"], paths["artifact_root"])
    handoff = workflow_mock_handoff(node_id, node, run_id, status_value)
    if node.get("mock_missing_handoff"):
        for field in normalize_list(node.get("mock_missing_handoff")):
            handoff.pop(str(field), None)
    validation = validate_handoff_data(handoff, role=str(node.get("role") or "testing"))
    metadata = {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "workflow_node_id": node_id,
        "started_at": utc_now_iso(),
        "finished_at": utc_now_iso(),
        "status": "succeeded" if validation.get("ok") and status_value == "pass" else "failed",
        "role": node.get("role"),
        "actual_model": "mock-workflow-model",
        "actual_input_tokens": 123,
        "actual_output_tokens": 45,
        "actual_total_tokens": 168,
        "actual_cost_usd": 0.99,
    }
    write_metadata(run_dir, metadata)
    (run_dir / "stdout.txt").write_text(f"mock workflow node {node_id}: {status_value}\n", encoding="utf-8")
    (run_dir / "stderr.txt").write_text("", encoding="utf-8")
    write_json_file(run_dir / "handoff.json", handoff)
    write_json_file(run_dir / "handoff.validation.json", validation)
    node_dir = workflow_dir / "nodes" / node_id
    node_dir.mkdir(parents=True, exist_ok=True)
    (node_dir / "run_id.txt").write_text(run_id, encoding="utf-8")
    write_json_file(node_dir / "handoff.json", handoff)
    write_json_file(node_dir / "validation.json", validation)
    return {"run_id": run_id, "handoff": handoff, "validation": validation, "status_value": status_value}


def workflow_condition_value(status: dict[str, Any], node_id: str, field: str) -> Any:
    node = (status.get("nodes") or {}).get(node_id) or {}
    handoff = node.get("handoff") or {}
    if field == "status":
        return handoff.get("status") or node.get("handoff_status") or node.get("state")
    if field == "blocking_count":
        validation = node.get("handoff_validation") or {}
        return validation.get("blocking_count", len(handoff.get("blocking_issues") or []))
    return handoff.get(field)


def evaluate_workflow_gate(node_id: str, node: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    conditions = [str(item) for item in normalize_list(node.get("pass_when"))]
    if not conditions:
        conditions = [f"{dep}.status == \"pass\"" for dep in normalize_list(node.get("needs"))]
    results: list[dict[str, Any]] = []
    ok = True
    for condition in conditions:
        match = re.match(r"^([A-Za-z0-9_.-]+)\.([A-Za-z0-9_]+)\s*==\s*(?:\"([^\"]*)\"|'([^']*)'|([0-9]+))$", condition.strip())
        if not match:
            results.append({"condition": condition, "ok": False, "error": "unsupported_condition"})
            ok = False
            continue
        source_node, field, expected_text, expected_single, expected_number = match.groups()
        actual = workflow_condition_value(status, source_node, field)
        expected: Any = int(expected_number) if expected_number is not None else (expected_text if expected_text is not None else expected_single)
        passed = actual == expected
        results.append({"condition": condition, "source_node": source_node, "field": field, "expected": expected, "actual": actual, "ok": passed})
        ok = ok and passed
    return {"ok": ok, "node_id": node_id, "checks": results}


STALE_WORKFLOW_EVIDENCE_KEYS = (
    "run_id",
    "handoff",
    "handoff_validation",
    "handoff_status",
    "actual_total_tokens",
    "actual_cost_usd",
    "gate",
)


def invalidate_workflow_node_evidence(node_state: dict[str, Any], *, reason: str) -> None:
    stale: dict[str, Any] = {
        "reason": reason,
        "invalidated_at": utc_now_iso(),
    }
    if node_state.get("run_id"):
        stale["run_id"] = node_state.get("run_id")
    if isinstance(node_state.get("handoff"), dict):
        stale["handoff_status"] = node_state["handoff"].get("status")
    if isinstance(node_state.get("handoff_validation"), dict):
        stale["handoff_validation_ok"] = node_state["handoff_validation"].get("ok")
    if isinstance(node_state.get("gate"), dict):
        stale["gate_ok"] = node_state["gate"].get("ok")
    if node_state.get("actual_total_tokens") is not None:
        stale["actual_total_tokens"] = node_state.get("actual_total_tokens")
    if node_state.get("actual_cost_usd") is not None:
        stale["actual_cost_usd"] = node_state.get("actual_cost_usd")
    for key in STALE_WORKFLOW_EVIDENCE_KEYS:
        node_state.pop(key, None)
    node_state["state"] = "pending"
    node_state["stale_evidence"] = stale


def workflow_write_report(workflow_id: str, cwd: Path | None = None) -> dict[str, Any]:
    workflow_dir = safe_workflow_dir(workflow_id, cwd=cwd)
    status = read_json_file(workflow_dir / "status.json", {})
    if not status:
        raise OrchestratorError(f"Workflow status not found: {workflow_id}")
    report_dir = workflow_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / "workflow-report.md"
    lines = [
        "# Workflow Report",
        "",
        f"- Workflow id: `{workflow_id}`",
        f"- Status: `{status.get('status')}`",
        f"- Task: `{status.get('task')}`",
    ]
    if status.get("status") == "needs_rerun" or status.get("requires_rerun"):
        lines.extend(
            [
                f"- Requires rerun: `{bool(status.get('requires_rerun'))}`",
                f"- Invalidated nodes: `{', '.join(status.get('invalidated_nodes') or [])}`",
                "",
                "> This workflow has been manually invalidated. Pending nodes must run again before the controller accepts it.",
            ]
        )
    lines.extend(["", "## Nodes"])
    for node_id, node in (status.get("nodes") or {}).items():
        lines.extend(
            [
                f"- `{node_id}`: state `{node.get('state')}`, run `{node.get('run_id')}`, handoff `{bool((node.get('handoff_validation') or {}).get('ok'))}`",
                f"  - tokens `{node.get('actual_total_tokens')}`, cost `{node.get('actual_cost_usd')}`",
            ]
        )
        if node.get("gate"):
            lines.append(f"  - gate: `{json.dumps(node['gate'], ensure_ascii=False)}`")
        if node.get("stale_evidence"):
            lines.append(f"  - stale evidence: `{json.dumps(node['stale_evidence'], ensure_ascii=False)}`")
    lines.extend(["", "## Decision Trail"])
    for decision in status.get("decisions") or []:
        lines.append(f"- `{decision.get('ts')}` `{decision.get('node_id')}` -> `{decision.get('decision')}`: {decision.get('reason')}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"ok": True, "workflow_id": workflow_id, "status": status.get("status"), "report_path": str(path)}


def workflow_decision(
    node_id: str | None,
    decision: str,
    reason: str,
    *,
    requires_controller_takeover: bool | None = None,
    requires_codex_takeover: bool | None = None,
    **details: Any,
) -> dict[str, Any]:
    """Build the agent-neutral workflow decision contract with its legacy alias."""
    if requires_controller_takeover is not None and type(requires_controller_takeover) is not bool:
        raise OrchestratorError("requires_controller_takeover must be a boolean.")
    if requires_codex_takeover is not None and type(requires_codex_takeover) is not bool:
        raise OrchestratorError("requires_codex_takeover must be a boolean.")
    if (
        requires_controller_takeover is not None
        and requires_codex_takeover is not None
        and requires_codex_takeover != requires_controller_takeover
    ):
        raise OrchestratorError("Conflicting controller takeover aliases.")
    takeover = (
        requires_controller_takeover
        if requires_controller_takeover is not None
        else requires_codex_takeover if requires_codex_takeover is not None else False
    )
    payload = {
        "ts": utc_now_iso(),
        "node_id": node_id,
        "decision": decision,
        "reason": reason,
        **details,
    }
    payload["requires_controller_takeover"] = takeover
    payload["requires_codex_takeover"] = takeover
    return payload


def workflow_run(file: str | Path, task: str, cwd: Path | None = None, mock: bool = False, loop_guard: int = 50) -> dict[str, Any]:
    if not mock:
        raise OrchestratorError("Real workflow-run is not enabled in v0.7.0. Use --mock to validate the controller without spending model quota.")
    spec = load_workflow_spec(file, cwd=cwd)
    validation = validate_workflow_spec(spec)
    if not validation.get("ok"):
        return {**validation, "source_file": spec.get("_source_file")}
    paths = workspace_paths(cwd or Path.cwd())
    workflow_id = new_workflow_id()
    workflow_dir = paths["workflows"] / workflow_id
    workflow_dir.mkdir(parents=True, exist_ok=False)
    register_workflow_dir(workflow_id, workflow_dir, paths["workspace_root"], paths["artifact_root"])
    nodes = workflow_nodes(spec)
    source_text = str(spec.get("_source_text") or json.dumps({k: v for k, v in spec.items() if not str(k).startswith("_")}, ensure_ascii=False, indent=2))
    (workflow_dir / "workflow.yaml").write_text(source_text, encoding="utf-8")
    manifest = {
        "workflow_id": workflow_id,
        "source_file": spec.get("_source_file"),
        "task": task,
        "cwd": str((cwd or Path.cwd()).resolve()),
        "mock": mock,
        "created_at": utc_now_iso(),
    }
    write_json_file(workflow_dir / "manifest.json", manifest)
    status: dict[str, Any] = {
        "workflow_id": workflow_id,
        "status": "running",
        "task": task,
        "cwd": manifest["cwd"],
        "mock": mock,
        "created_at": utc_now_iso(),
        "nodes": {
            node_id: {
                "state": "pending",
                "type": str(node.get("type") or "worker"),
                "role": node.get("role"),
                "needs": [str(item) for item in normalize_list(node.get("needs"))],
                "attempts": 0,
                "retry_count": 0,
            }
            for node_id, node in nodes.items()
        },
        "decisions": [],
    }
    batches = workflow_topological_batches(nodes)
    order = [node_id for batch in batches for node_id in batch]
    transitions = 0
    while transitions < loop_guard:
        progress = False
        transitions += 1
        for node_id in order:
            node = nodes[node_id]
            node_state = status["nodes"][node_id]
            node_type = str(node.get("type") or "worker")
            if node_state.get("state") in {"done", "failed", "blocked", "cancelled", "skipped"}:
                continue
            needs = [str(item) for item in normalize_list(node.get("needs"))]
            dep_states = {dep: status["nodes"][dep].get("state") for dep in needs}
            if node_type == "gate":
                if not all(state in {"done", "failed", "skipped"} for state in dep_states.values()):
                    continue
            else:
                failed_deps = [dep for dep, state in dep_states.items() if state in {"failed", "blocked", "cancelled"}]
                if failed_deps:
                    node_state["state"] = "blocked"
                    status["decisions"].append(
                        workflow_decision(
                            node_id,
                            "block",
                            "dependency failed or blocked",
                            failed_dependencies=failed_deps,
                            requires_controller_takeover=True,
                        )
                    )
                    progress = True
                    continue
                if not all(state in {"done", "skipped"} for state in dep_states.values()):
                    continue
            if node_type == "gate":
                node_state["state"] = "validating"
                gate = evaluate_workflow_gate(node_id, node, status)
                node_state.pop("stale_evidence", None)
                node_state["gate"] = gate
                if gate.get("ok"):
                    node_state["state"] = "done"
                    decision = workflow_decision(node_id, "advance", "gate passed", next_nodes=[])
                    status["decisions"].append(decision)
                    progress = True
                    continue
                on_fail = node.get("on_fail") or {}
                retry_target = str(on_fail.get("retry") or "") if isinstance(on_fail, dict) else ""
                max_retries = int(on_fail.get("max_retries") or 0) if isinstance(on_fail, dict) else 0
                if retry_target and node_state.get("retry_count", 0) < max_retries:
                    node_state["retry_count"] = int(node_state.get("retry_count") or 0) + 1
                    invalidated = {retry_target, *workflow_descendants(nodes, retry_target)}
                    for item in invalidated:
                        invalidate_workflow_node_evidence(status["nodes"][item], reason="gate retry")
                    decision = workflow_decision(
                        node_id,
                        "retry",
                        "gate failed",
                        next_nodes=[retry_target],
                        retry_count=node_state["retry_count"],
                    )
                    status["decisions"].append(decision)
                    progress = True
                    break
                node_state["state"] = "blocked"
                decision = workflow_decision(
                    node_id,
                    "block",
                    "gate failed and retries exhausted",
                    next_nodes=[],
                    retry_count=node_state.get("retry_count", 0),
                    requires_controller_takeover=True,
                )
                status["decisions"].append(decision)
                progress = True
                continue
            if not mock:
                node_state["state"] = "queued"
                run = run_streaming_agent(
                    task=f"{task}\n\nWorkflow node {node_id}: {node.get('task') or ''}",
                    role=str(node.get("role") or "implementation"),
                    cwd=cwd or Path.cwd(),
                    timeout_seconds=int(node.get("timeout_seconds") or (spec.get("defaults") or {}).get("timeout_seconds") or 900),
                    allow_write=bool(node.get("allow_write", False)),
                    final_only=bool((spec.get("defaults") or {}).get("final_only", True)),
                    max_output_bytes=int((spec.get("defaults") or {}).get("max_output_bytes") or OUTPUT_BUDGET_DEFAULTS["max_output_bytes"]),
                    max_events_bytes=int((spec.get("defaults") or {}).get("max_events_bytes") or OUTPUT_BUDGET_DEFAULTS["max_events_bytes"]),
                )
                node_state.update({"state": "running", "run_id": run["run_id"]})
                status["decisions"].append(workflow_decision(node_id, "advance", "worker launched", next_nodes=[]))
                progress = True
                continue
            attempt = int(node_state.get("attempts") or 0)
            node_state["state"] = "running"
            result = create_mock_workflow_run_node(paths, workflow_dir, workflow_id, node_id, node, attempt)
            node_state.pop("stale_evidence", None)
            node_state["attempts"] = attempt + 1
            node_state["run_id"] = result["run_id"]
            node_state["handoff"] = result["handoff"]
            node_state["handoff_validation"] = result["validation"]
            node_state["handoff_status"] = result["handoff"].get("status")
            node_state["actual_total_tokens"] = 168
            node_state["actual_cost_usd"] = 0.99
            if not result["validation"].get("ok"):
                node_state["state"] = "blocked"
                status["decisions"].append(
                    workflow_decision(
                        node_id,
                        "block",
                        "handoff validation failed",
                        missing_fields=result["validation"].get("missing_fields"),
                        requires_controller_takeover=True,
                    )
                )
            elif result["handoff"].get("status") == "pass":
                node_state["state"] = "done"
                status["decisions"].append(workflow_decision(node_id, "advance", "handoff valid", next_nodes=[]))
            else:
                node_state["state"] = "failed"
                status["decisions"].append(workflow_decision(node_id, "advance", "handoff status failed; gate may retry", next_nodes=[]))
            progress = True
        write_workflow_status(workflow_dir, status)
        if not progress:
            break
        if all(item.get("state") in {"done", "blocked", "cancelled", "skipped"} for item in status["nodes"].values()):
            break
    if transitions >= loop_guard:
        status["status"] = "blocked"
        status["block_reason"] = "loop_guard_exceeded"
        status["decisions"].append(
            workflow_decision(None, "block", "loop_guard_exceeded", requires_controller_takeover=True)
        )
    elif any(item.get("state") == "blocked" for item in status["nodes"].values()):
        status["status"] = "blocked"
    elif any(item.get("state") in {"running", "queued", "pending", "failed"} for item in status["nodes"].values()):
        status["status"] = "waiting_for_controller"
    else:
        status["status"] = "succeeded"
    write_workflow_status(workflow_dir, status)
    report = workflow_write_report(workflow_id, cwd=cwd)
    return {"ok": status["status"] == "succeeded", "workflow_id": workflow_id, "status": status, "workflow_dir": str(workflow_dir), "report_path": report.get("report_path")}


def workflow_status(workflow_id: str, cwd: Path | None = None) -> dict[str, Any]:
    status = read_workflow_status(workflow_id, cwd=cwd)
    return {"ok": True, "workflow_id": workflow_id, "status": status.get("status"), "nodes": status.get("nodes"), "decisions": status.get("decisions"), "path": str(safe_workflow_dir(workflow_id, cwd=cwd) / "status.json")}


def workflow_retry_node(workflow_id: str, node_id: str, cwd: Path | None = None) -> dict[str, Any]:
    workflow_dir = safe_workflow_dir(workflow_id, cwd=cwd)
    status = read_json_file(workflow_dir / "status.json", {})
    spec = load_workflow_spec(workflow_dir / "workflow.yaml")
    nodes = workflow_nodes(spec)
    if node_id not in nodes:
        raise OrchestratorError(f"Unknown workflow node: {node_id}")
    invalidated = {node_id, *workflow_descendants(nodes, node_id)}
    for item in invalidated:
        if item in status.get("nodes", {}):
            invalidate_workflow_node_evidence(status["nodes"][item], reason="manual retry requested")
    status["status"] = "needs_rerun"
    status["block_reason"] = None
    status["requires_rerun"] = True
    status["invalidated_nodes"] = sorted(invalidated)
    status["invalidated_at"] = utc_now_iso()
    status.setdefault("decisions", []).append(
        workflow_decision(
            node_id,
            "retry",
            "manual retry requested",
            next_nodes=[node_id],
            invalidated=sorted(invalidated),
            requires_controller_takeover=True,
        )
    )
    write_workflow_status(workflow_dir, status)
    return {"ok": True, "workflow_id": workflow_id, "node_id": node_id, "invalidated": sorted(invalidated), "status_path": str(workflow_dir / "status.json")}


def workflow_stop(workflow_id: str, force: bool = False, cwd: Path | None = None) -> dict[str, Any]:
    workflow_dir = safe_workflow_dir(workflow_id, cwd=cwd)
    status = read_json_file(workflow_dir / "status.json", {})
    stopped: list[dict[str, Any]] = []
    for node_id, node in (status.get("nodes") or {}).items():
        if node.get("state") == "running" and node.get("run_id"):
            stopped.append({"node_id": node_id, "stop": stop_run(str(node["run_id"]), force=force)})
            node["state"] = "cancelled"
    status["status"] = "cancelled"
    status.setdefault("decisions", []).append(
        workflow_decision(None, "cancel", "workflow-stop requested", requires_controller_takeover=True)
    )
    write_workflow_status(workflow_dir, status)
    return {"ok": True, "workflow_id": workflow_id, "stopped": stopped, "status": "cancelled"}


def default_auto_policy() -> dict[str, Any]:
    return {
        "default_profile": "auto",
        "profile_aliases": {
            "strong_text": "auto:architecture",
            "code_strong": "auto:implementation",
            "development_strong": "auto:development",
            "review_strong": "auto:review",
            "security_strong": "auto:security",
            "performance_strong": "auto:performance",
            "compatibility_stable": "auto:compatibility",
            "documentation_balanced": "auto:documentation",
            "automation_strong": "auto:automation",
            "multimodal": "auto:multimodal",
            "general": "auto:requirements",
            "fast": "auto:testing",
            "ops": "auto:ops",
        },
        "task_routes": {
            "simple": {"profile_alias": "fast", "permission_mode": "plan", "timeout_seconds": 180, "reason": "Fast low-risk planning or summarization."},
            "normal": {"profile_alias": "general", "permission_mode": "plan", "timeout_seconds": 420, "reason": "Balanced local model for routine project analysis."},
            "complex_code": {"profile_alias": "code_strong", "permission_mode": "plan", "timeout_seconds": 900, "reason": "Highest local score for code implementation."},
            "development": {"profile_alias": "development_strong", "permission_mode": "plan", "timeout_seconds": 900, "reason": "Highest local score for main code development."},
            "review": {"profile_alias": "review_strong", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Highest local score for code review."},
            "security_review": {"profile_alias": "security_strong", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Highest local score for security review."},
            "performance_review": {"profile_alias": "performance_strong", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Best local fit for runtime, IO, and resource optimization review."},
            "compatibility_review": {"profile_alias": "compatibility_stable", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Best local fit for multi-environment compatibility checks."},
            "documentation": {"profile_alias": "documentation_balanced", "permission_mode": "plan", "timeout_seconds": 420, "reason": "Balanced local model for documentation and examples."},
            "automation": {"profile_alias": "automation_strong", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Best local fit for CI/CD and repeatable automation work."},
            "architecture": {"profile_alias": "strong_text", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Highest local score for architecture reasoning."},
            "multimodal": {"profile_alias": "multimodal", "permission_mode": "plan", "timeout_seconds": 600, "reason": "Highest local score for multimodal tasks."},
            "ops": {"profile_alias": "ops", "permission_mode": "plan", "timeout_seconds": 420, "reason": "Stable local model for operational checks."},
        },
        "role_defaults": {
            "requirements": "normal",
            "architecture": "architecture",
            "development": "development",
            "security": "security_review",
            "testing": "simple",
            "implementation": "complex_code",
            "review": "review",
            "performance": "performance_review",
            "compatibility": "compatibility_review",
            "documentation": "documentation",
            "automation": "automation",
            "ops": "ops",
            "multimodal": "multimodal",
        },
        "safety": {
            "default_write_enabled": False,
            "visible_window_default": False,
            "max_timeout_seconds": 1800,
            "redact_secret_values": True,
        },
    }


def write_auto_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    policy = default_auto_policy()
    path.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "policy_path": str(path), "policy": policy}


def write_reports(output_dir: Path | None = None) -> dict[str, Any]:
    report_dir = output_dir or REPORTS_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    scores = score_models()
    plan = run_workflow_plan("local multi-agent routing calibration")
    scores_path = report_dir / "model_scores.json"
    strategy_path = report_dir / "multi_agent_strategy.md"
    scores_path.write_text(json.dumps(scores, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Claude Code Orchestrator Strategy",
        "",
        "Scoring source: local CCSwitch configuration plus heuristic public documentation signals. This is not a paid benchmark run.",
        "",
        "## Models",
        "",
    ]
    for item in scores["models"]:
        lines.append(f"- `{item['model']}` via `{item['profile_name']}`: overall {item['overall']}/10; role scores {json.dumps(item['role_scores'], ensure_ascii=False)}")
    lines.extend(["", "## Multi-Agent Routing", ""])
    for step in plan["steps"]:
        lines.append(
            f"- `{step['role']}` -> profile `{step['profile']}`, model `{step['model']}`, permission `{step['permission_mode']}`, score `{step['selection_score']}`"
        )
    lines.extend(
        [
            "",
            "## Research References",
            "",
            "- Qwen documentation: https://qwen.readthedocs.io/en/latest/",
            "- Qwen concepts and tool-calling notes: https://qwen.readthedocs.io/en/latest/getting_started/concepts.html",
            "- GLM-5 official blog: https://z.ai/blog/glm-5",
            "",
            "## Notes",
            "",
            "- Write access remains disabled by default; pass allow_write only for scoped implementation tasks.",
            "- If a configured model disappears from CCSwitch, routing falls back to the highest-scored available local model.",
            "- Secrets are redacted from tool output and persisted logs.",
        ]
    )
    strategy_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"ok": True, "scores_path": str(scores_path), "strategy_path": str(strategy_path), "workflow_plan": plan}


def build_claude_md(role: str = "implementation", project_name: str | None = None) -> str:
    agents = load_json(AGENTS_PATH)
    agent = agents.get(role) or agents.get("implementation", {})
    role_prompt = agent.get("prompt", "")
    role_description = agent.get("description", "Claude Code worker controlled by Codex.")
    title = project_name or "this repository"
    return "\n".join(
        [
            CLAUDE_MD_MARKER_BEGIN,
            "# CLAUDE.md",
            "",
            "You are a Claude Code worker inside a Codex-controlled multi-agent workflow.",
            "",
            f"Project: {title}",
            f"Assigned role: {role}",
            f"Role purpose: {role_description}",
            "",
            "## Control Model",
            "",
            "- Codex is the controller, planner, reviewer, and final decision maker.",
            "- Claude Code is an external worker process launched by Claude Code Orchestrator.",
            "- Do not treat your own output as final until Codex reviews it.",
            "- Keep work scoped to the user request and the current repository.",
            "",
            "## Role Instruction",
            "",
            role_prompt or "Follow the assigned role and keep output concise, safe, and verifiable.",
            "",
            "## Safety Rules",
            "",
            "- Do not print secrets, API keys, cookies, tokens, or hidden config values.",
            "- Do not run destructive commands unless the user explicitly requested them.",
            "- Do not revert unrelated user changes.",
            "- Prefer read-only analysis unless write access is explicitly granted.",
            "- When editing, list changed files and verification results.",
            f"- Store agent-generated logs, reports, temporary files, and rollback notes under `{ARTIFACT_ROOT}`.",
            "- Do not scatter agent runtime artifacts into the project source tree.",
            "- If blocked, report the blocker, the evidence, and the smallest next action.",
            "",
            "## Progress Reporting",
            "",
            "- State the current phase before long work.",
            "- Prefer short, structured summaries.",
            "- Mention tests or checks actually run.",
            "- Save important reasoning in the final response, not in hidden state.",
            CLAUDE_MD_MARKER_END,
            "",
        ]
    )


def write_claude_md(
    cwd: Path | None = None,
    role: str = "implementation",
    project_name: str | None = None,
    append: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    effective_cwd = (cwd or Path.cwd()).resolve()
    effective_cwd.mkdir(parents=True, exist_ok=True)
    path = effective_cwd / "CLAUDE.md"
    content = build_claude_md(role=role, project_name=project_name or effective_cwd.name)
    backup_path: Path | None = None

    if path.exists():
        current = path.read_text(encoding="utf-8", errors="replace")
        if CLAUDE_MD_MARKER_BEGIN in current and CLAUDE_MD_MARKER_END in current:
            updated = re.sub(
                re.escape(CLAUDE_MD_MARKER_BEGIN) + r".*?" + re.escape(CLAUDE_MD_MARKER_END) + r"\n?",
                content,
                current,
                flags=re.DOTALL,
            )
            path.write_text(updated, encoding="utf-8")
            return {
                "ok": True,
                "path": str(path),
                "mode": "updated-managed-section",
                "backup_path": None,
                "role": role,
            }
        if append:
            path.write_text(current.rstrip() + "\n\n" + content, encoding="utf-8")
            return {
                "ok": True,
                "path": str(path),
                "mode": "appended-managed-section",
                "backup_path": None,
                "role": role,
            }
        if force:
            backup_path = path.with_name(f"CLAUDE.md.backup.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
            backup_path.write_text(current, encoding="utf-8")
            path.write_text(content, encoding="utf-8")
            return {
                "ok": True,
                "path": str(path),
                "mode": "replaced-with-backup",
                "backup_path": str(backup_path),
                "role": role,
            }
        return {
            "ok": False,
            "path": str(path),
            "error": "CLAUDE.md already exists. Use append=true to add a managed section or force=true to replace with a backup.",
            "role": role,
        }

    path.write_text(content, encoding="utf-8")
    return {
        "ok": True,
        "path": str(path),
        "mode": "created",
        "backup_path": None,
        "role": role,
    }


def selftest() -> dict[str, Any]:
    env = force_utf8_env({})
    decoded = subprocess_text("中文✅".encode("utf-8"))
    claude_md = build_claude_md("review", "selftest")
    sample_github_token = "ghp_" + ("1" * 36)
    sample_api_key = "sk-" + "testSecretValue"
    redacted = str(redact(f"token {sample_github_token} {sample_api_key}"))
    usage_redacted = redact(
        {
            "actual_total_tokens": 168,
            "inputTokens": 123,
            "outputTokens": "45",
            "github_token": sample_github_token,
        }
    )
    try:
        safe_run_dir("../bad")
        run_id_rejected = False
    except OrchestratorError:
        run_id_rejected = True
    worker_env = build_worker_env({"ANTHROPIC_API_KEY": sample_api_key})
    try:
        workflow_decision(
            None,
            "block",
            "selftest",
            requires_controller_takeover=True,
            requires_codex_takeover=False,
        )
        conflicting_takeover_alias_rejected = False
    except OrchestratorError:
        conflicting_takeover_alias_rejected = True
    legacy_only_takeover_decision = workflow_decision(
        None,
        "block",
        "selftest legacy alias",
        requires_codex_takeover=True,
    )
    secret_findings = secret_scan_text("OPENAI_API_KEY=sk-" + ("1" * 32), "selftest")
    placeholder_findings = secret_scan_text("OPENAI_API_KEY=" + "sk-" + "your-placeholder-token", ".env.example")
    false_findings = secret_scan_text("input_tokens = estimate_tokens_from_text(prompt)", "selftest")
    warning_risks = risk_summary([{"code": "soft_output", "severity": "medium", "blocking": False, "message": "warning only"}])
    actual_route = actual_route_from_payload(
        {"modelUsage": {"glm-5.2": {"inputTokens": 100, "outputTokens": 25, "costUSD": 0.12, "apiKey": sample_github_token}}},
        declared_model="qwen3.7-plus",
    )
    status = workspace_status()
    policy = folder_policy(apply=False)
    prompt_pack = list_prompt_pack()
    with tempfile.TemporaryDirectory(prefix="cc-orchestrator-selftest-") as tmp:
        init_workspace(cwd=tmp, write_claude=False)
        clean_after_init = clean_workspace(cwd=tmp, dry_run=True)
        chinese_root = Path(tmp) / "中文项目"
        chinese_root.mkdir()
        json_path = write_json_file(chinese_root / "metadata.json", {"prompt": "中文✅\x01", "path": str(chinese_root)})
        json_roundtrip = json.loads(json_path.read_text(encoding="utf-8"))
        change_split = classify_change_paths(
            chinese_root,
            [
                ".agent-workspace/claude-code-orchestrator/runs/mock/stdout.txt",
                "src/app.py",
            ],
        )
        valid_workflow = {
            "schema_version": 1,
            "id": "mock-safe-refactor",
            "defaults": {"final_only": True, "timeout_seconds": 30, "allow_write": False},
            "nodes": {
                "requirements": {"role": "requirements", "task": "mock requirements", "outputs": "requirements_handoff"},
                "implementation": {
                    "role": "development",
                    "needs": ["requirements"],
                    "allow_write": True,
                    "write_scope": {"allow": ["src/", "tests/"], "deny": [".env", ".env.*"], "max_diff_lines": 800},
                    "outputs": "implementation_handoff",
                },
                "testing": {"role": "testing", "needs": ["implementation"], "outputs": "testing_handoff", "mock_status_sequence": ["fail", "pass"]},
                "review": {"role": "review", "needs": ["implementation"], "outputs": "review_handoff"},
                "quality_gate": {
                    "type": "gate",
                    "needs": ["testing", "review"],
                    "pass_when": ['testing.status == "pass"', "review.blocking_count == 0"],
                    "on_fail": {"retry": "implementation", "max_retries": 2},
                },
                "supervisor": {"role": "supervisor", "needs": ["quality_gate"], "outputs": "supervisor_handoff"},
            },
        }
        workflow_path = Path(tmp) / "workflow.json"
        write_json_file(workflow_path, valid_workflow)
        workflow_project_cwd = Path(tmp) / "workflow-project"
        workflow_project_cwd.mkdir()
        outside_workflow_path = Path(tmp) / "outside-workflow.json"
        write_json_file(outside_workflow_path, valid_workflow)
        try:
            workflow_validate(outside_workflow_path, cwd=workflow_project_cwd)
            workflow_cwd_scope_rejected = False
        except OrchestratorError:
            workflow_cwd_scope_rejected = True
        simple_yaml_parsed = parse_simple_workflow_yaml(
            """
schema_version: 1
id: fallback
nodes:
  requirements:
    role: requirements
    outputs: requirements_handoff
  testing:
    role: testing
    needs: [requirements]
    outputs: testing_handoff
  quality_gate:
    type: gate
    needs: [testing]
    pass_when:
      - testing.status == "pass"
"""
        )
        simple_yaml_validation = validate_workflow_spec(simple_yaml_parsed)
        source_dir = Path(tmp) / "src"
        source_dir.mkdir()
        source_file = source_dir / "app.py"
        source_file.write_text("print('stable')\n", encoding="utf-8")
        source_before = source_file.read_text(encoding="utf-8")
        workflow_valid = validate_workflow_spec(valid_workflow)
        workflow_dry = workflow_dry_run(workflow_path, task="mock task", cwd=Path(tmp))
        workflow_mock = workflow_run(workflow_path, task="mock task", cwd=Path(tmp), mock=True)
        workflow_mock_status = workflow_status(str(workflow_mock.get("workflow_id")), cwd=Path(tmp))
        workflow_report_text = Path(str(workflow_mock.get("report_path"))).read_text(encoding="utf-8")
        workflow_id = str(workflow_mock.get("workflow_id"))
        workflow_dir = safe_workflow_dir(workflow_id, cwd=Path(tmp))
        tampered_workflow_dir = Path(tmp) / "outside-workflow-index" / workflow_id
        tampered_workflow_dir.mkdir(parents=True, exist_ok=True)
        write_json_file(
            WORKFLOW_INDEX_DIR / f"{workflow_id}.json",
            {
                "workflow_id": workflow_id,
                "workflow_dir": str(tampered_workflow_dir.resolve()),
                "workspace_root": str(Path(tmp).resolve()),
                "artifact_root": str(workspace_paths(Path(tmp))["artifact_root"].resolve()),
                "registered_at": utc_now_iso(),
            },
        )
        try:
            safe_workflow_dir(workflow_id, cwd=Path(tmp))
            tampered_workflow_index_rejected = False
        except OrchestratorError:
            tampered_workflow_index_rejected = True
        register_workflow_dir(workflow_id, workflow_dir, workspace_paths(Path(tmp))["workspace_root"], workspace_paths(Path(tmp))["artifact_root"])
        try:
            workflow_run(workflow_path, task="real workflow should be disabled", cwd=Path(tmp), mock=False)
            real_workflow_run_rejected = False
        except OrchestratorError:
            real_workflow_run_rejected = True
        manual_retry_workflow = workflow_run(workflow_path, task="mock manual retry", cwd=Path(tmp), mock=True)
        manual_retry_id = str(manual_retry_workflow.get("workflow_id"))
        manual_retry_result = workflow_retry_node(manual_retry_id, "implementation", cwd=Path(tmp))
        manual_retry_status = read_workflow_status(manual_retry_id, cwd=Path(tmp))
        manual_retry_nodes = manual_retry_status.get("nodes") or {}
        manual_retry_report_result = workflow_write_report(manual_retry_id, cwd=Path(tmp))
        manual_retry_report_text = Path(str(manual_retry_report_result.get("report_path"))).read_text(encoding="utf-8")
        workflow_stop(manual_retry_id, cwd=Path(tmp))
        stopped_workflow_status = read_workflow_status(manual_retry_id, cwd=Path(tmp))
        source_after = source_file.read_text(encoding="utf-8")

        cycle_spec = json.loads(json.dumps(valid_workflow))
        cycle_spec["nodes"]["requirements"]["needs"] = ["supervisor"]
        cycle_validation = validate_workflow_spec(cycle_spec)
        unknown_role_spec = json.loads(json.dumps(valid_workflow))
        unknown_role_spec["nodes"]["testing"]["role"] = "unknown"
        unknown_role_validation = validate_workflow_spec(unknown_role_spec)
        missing_dep_spec = json.loads(json.dumps(valid_workflow))
        missing_dep_spec["nodes"]["testing"]["needs"] = ["missing"]
        missing_dep_validation = validate_workflow_spec(missing_dep_spec)
        missing_outputs_spec = json.loads(json.dumps(valid_workflow))
        missing_outputs_spec["nodes"]["testing"].pop("outputs", None)
        missing_outputs_validation = validate_workflow_spec(missing_outputs_spec)
        missing_write_scope_spec = json.loads(json.dumps(valid_workflow))
        missing_write_scope_spec["nodes"]["implementation"].pop("write_scope", None)
        missing_write_scope_validation = validate_workflow_spec(missing_write_scope_spec)

        handoff_test_template = handoff_template("testing")
        valid_handoff = handoff_test_template["example"]
        valid_handoff_result = validate_handoff_data(valid_handoff, role="testing")
        invalid_handoff = json.loads(json.dumps(valid_handoff))
        invalid_handoff.pop("status", None)
        invalid_handoff_result = validate_handoff_data(invalid_handoff, role="testing")

        missing_handoff_spec = json.loads(json.dumps(valid_workflow))
        missing_handoff_spec["nodes"]["requirements"]["mock_missing_handoff"] = ["status"]
        missing_handoff_path = Path(tmp) / "missing-handoff-workflow.json"
        write_json_file(missing_handoff_path, missing_handoff_spec)
        missing_handoff_run = workflow_run(missing_handoff_path, task="mock missing handoff", cwd=Path(tmp), mock=True)
        missing_handoff_nodes = (missing_handoff_run.get("status") or {}).get("nodes") or {}

        max_retry_spec = json.loads(json.dumps(valid_workflow))
        max_retry_spec["nodes"]["testing"]["mock_status_sequence"] = ["fail", "fail", "fail"]
        max_retry_spec["nodes"]["quality_gate"]["on_fail"]["max_retries"] = 1
        max_retry_path = Path(tmp) / "max-retry-workflow.json"
        write_json_file(max_retry_path, max_retry_spec)
        max_retry_run = workflow_run(max_retry_path, task="mock max retry", cwd=Path(tmp), mock=True)
        max_retry_status = max_retry_run.get("status") or {}
        max_retry_nodes = max_retry_status.get("nodes") or {}
        max_retry_decisions = max_retry_status.get("decisions") or []
        loop_guard_run = workflow_run(workflow_path, task="mock loop guard", cwd=Path(tmp), mock=True, loop_guard=1)
        loop_guard_status = loop_guard_run.get("status") or {}
        decision_sets = [
            workflow_mock_status.get("decisions") or [],
            missing_handoff_run.get("status", {}).get("decisions") or [],
            max_retry_decisions,
            manual_retry_status.get("decisions") or [],
            stopped_workflow_status.get("decisions") or [],
            loop_guard_status.get("decisions") or [],
        ]
        workflow_decisions = [decision for decisions in decision_sets for decision in decisions]
        takeover_reasons = {
            "dependency failed or blocked",
            "gate failed and retries exhausted",
            "handoff validation failed",
            "loop_guard_exceeded",
            "manual retry requested",
            "workflow-stop requested",
        }
    checks = {
        "utf8_env": env.get("PYTHONIOENCODING") == "utf-8" and env.get("PYTHONUTF8") == "1",
        "timeout_bytes_decode": decoded == "中文✅",
        "policy_exists": POLICY_PATH.exists(),
        "agents_exists": AGENTS_PATH.exists(),
        "skill_root_assets": VERSION_PATH.exists() and PROMPT_PACK_DIR.exists(),
        "prompt_pack_available": bool(prompt_pack.get("ok")) and bool(prompt_pack.get("templates")),
        "claude_md_template": "Assigned role: review" in claude_md and CLAUDE_MD_MARKER_BEGIN in claude_md,
        "secret_redaction": sample_github_token not in redacted and sample_api_key not in redacted,
        "numeric_token_usage_not_redacted": usage_redacted.get("actual_total_tokens") == 168 and usage_redacted.get("inputTokens") == 123 and usage_redacted.get("outputTokens") == "45" and usage_redacted.get("github_token") == "***REDACTED***",
        "secret_scan_detects_assignment": bool(secret_findings) and secret_findings[0].get("classification") == "real_secret_candidate",
        "secret_scan_downgrades_placeholder": bool(placeholder_findings) and placeholder_findings[0].get("classification") == "placeholder_or_example" and not placeholder_findings[0].get("blocking"),
        "secret_scan_ignores_token_words": not false_findings,
        "risk_warning_not_blocking": warning_risks.get("ok") and warning_risks.get("has_warnings") and warning_risks.get("blocking_count") == 0,
        "actual_model_usage_detects_mismatch": actual_route.get("actual_model") == "glm-5.2" and actual_route.get("actual_total_tokens") == 125 and actual_route.get("route_mismatch"),
        "actual_model_usage_allowlist": "apiKey" not in actual_route.get("actual_model_usage", {}).get("glm-5.2", {}),
        "utf8_json_roundtrip": json_roundtrip.get("prompt") == "中文✅�" and "中文项目" in str(json_roundtrip.get("path")),
        "change_split_source_vs_artifact": change_split["project_source_changes"]["changed_count"] == 1 and change_split["agent_artifact_changes"]["changed_count"] == 1,
        "run_id_validation": run_id_rejected,
        "worker_env_allowlist": "ANTHROPIC_API_KEY" in worker_env and "GITHUB_TOKEN" not in worker_env and "NPM_TOKEN" not in worker_env,
        "mock_env_allowlist": "CC_ORCHESTRATOR_FAKE_STEPS" in PASSTHROUGH_ENV_KEYS,
        "workspace_root_configured": AGENT_WORKSPACE_DIRNAME in str(status.get("artifact_root")),
        "worker_env_artifact_root": worker_env.get("CC_ORCHESTRATOR_ARTIFACT_ROOT") == str(ARTIFACT_ROOT),
        "folder_policy_generated_only": "Only manage agent-generated artifacts" in str(policy.get("policy", {}).get("principle", "")),
        "clean_workspace_preserves_scaffold": clean_after_init.get("action_count") == 0,
        "workflow_validate_accepts_valid_dag": workflow_valid.get("ok") and workflow_valid.get("node_count") == 6 and workflow_valid.get("edge_count", 0) >= 5,
        "workflow_validate_rejects_outside_cwd": workflow_cwd_scope_rejected,
        "workflow_simple_yaml_fallback_parser": simple_yaml_validation.get("ok") and simple_yaml_validation.get("node_count") == 3,
        "workflow_validate_rejects_cycle": any(item.get("code") == "cycle_detected" for item in cycle_validation.get("errors", [])),
        "workflow_validate_rejects_unknown_role": any(item.get("code") == "unknown_role" for item in unknown_role_validation.get("errors", [])),
        "workflow_validate_rejects_missing_needs": any(item.get("code") == "missing_dependency" for item in missing_dep_validation.get("errors", [])),
        "workflow_validate_requires_outputs": any(item.get("code") == "missing_outputs" for item in missing_outputs_validation.get("errors", [])),
        "workflow_validate_requires_write_scope_for_write_node": any(item.get("code") == "missing_write_scope" for item in missing_write_scope_validation.get("errors", [])),
        "workflow_dry_run_has_topological_batches": workflow_dry.get("batches") == [["requirements"], ["implementation"], ["review", "testing"], ["quality_gate"], ["supervisor"]],
        "workflow_dry_run_launches_no_workers": workflow_dry.get("launched_workers") == 0,
        "handoff_template_testing_is_valid": "tests_run" in handoff_test_template.get("schema", {}).get("required", []),
        "handoff_validate_accepts_valid_handoff": bool(valid_handoff_result.get("ok")),
        "handoff_validate_reports_missing_fields": not invalid_handoff_result.get("ok") and "status" in invalid_handoff_result.get("missing_fields", []),
        "workflow_mock_run_succeeds": workflow_mock.get("ok") and workflow_mock.get("status", {}).get("status") == "succeeded",
        "workflow_tampered_index_rejected": tampered_workflow_index_rejected,
        "workflow_real_run_requires_mock": real_workflow_run_rejected,
        "manual_retry_marks_needs_rerun": manual_retry_result.get("ok")
        and manual_retry_status.get("status") == "needs_rerun"
        and manual_retry_status.get("requires_rerun") is True
        and "implementation" in (manual_retry_status.get("invalidated_nodes") or []),
        "manual_retry_clears_stale_acceptance_evidence": manual_retry_nodes.get("implementation", {}).get("state") == "pending"
        and "run_id" not in manual_retry_nodes.get("implementation", {})
        and "handoff_validation" not in manual_retry_nodes.get("implementation", {})
        and manual_retry_nodes.get("implementation", {}).get("stale_evidence", {}).get("handoff_status") == "pass"
        and "gate" not in manual_retry_nodes.get("quality_gate", {})
        and manual_retry_nodes.get("quality_gate", {}).get("stale_evidence", {}).get("gate_ok") is True,
        "manual_retry_report_warns_needs_rerun": "manually invalidated" in manual_retry_report_text and "stale evidence" in manual_retry_report_text,
        "mock_5_node_fanout_join_ok": (workflow_mock_status.get("nodes") or {}).get("quality_gate", {}).get("state") == "done" and (workflow_mock_status.get("nodes") or {}).get("testing", {}).get("attempts") == 2,
        "retry_once_then_pass": any(decision.get("decision") == "retry" and decision.get("retry_count") == 1 for decision in workflow_mock_status.get("decisions") or []) and workflow_mock_status.get("status") == "succeeded",
        "max_retries_blocks": max_retry_status.get("status") == "blocked"
        and max_retry_nodes.get("testing", {}).get("attempts") == 2
        and max_retry_nodes.get("quality_gate", {}).get("retry_count") == 1
        and max_retry_status.get("block_reason") != "loop_guard_exceeded"
        and any(decision.get("decision") == "block" and "retries exhausted" in str(decision.get("reason")) for decision in max_retry_decisions),
        "missing_handoff_blocks_downstream": missing_handoff_run.get("status", {}).get("status") == "blocked" and missing_handoff_nodes.get("requirements", {}).get("state") == "blocked" and not missing_handoff_nodes.get("implementation", {}).get("run_id"),
        "workflow_status_has_gate_details": bool((workflow_mock_status.get("nodes") or {}).get("quality_gate", {}).get("gate")),
        "workflow_report_has_decision_trail": "## Decision Trail" in workflow_report_text and "`retry`" in workflow_report_text,
        "workflow_decisions_use_neutral_takeover_contract": bool(workflow_decisions)
        and all(
            "requires_controller_takeover" in decision
            and "requires_codex_takeover" in decision
            and type(decision["requires_controller_takeover"]) is bool
            and type(decision["requires_codex_takeover"]) is bool
            and decision["requires_controller_takeover"] == decision["requires_codex_takeover"]
            for decision in workflow_decisions
        ),
        "workflow_takeover_alias_cannot_diverge": conflicting_takeover_alias_rejected,
        "workflow_legacy_takeover_alias_supported": legacy_only_takeover_decision["requires_controller_takeover"] is True
        and legacy_only_takeover_decision["requires_codex_takeover"] is True,
        "workflow_takeover_semantics": all(
            decision["requires_controller_takeover"] is False
            for decision in workflow_decisions
            if decision.get("decision") == "advance" or (decision.get("decision") == "retry" and decision.get("reason") == "gate failed")
        )
        and takeover_reasons.issubset({str(decision.get("reason")) for decision in workflow_decisions})
        and all(
            decision["requires_controller_takeover"] is True
            for decision in workflow_decisions
            if decision.get("reason") in takeover_reasons
        ),
        "workflow_controller_only_no_source_changes": source_before == source_after,
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "decoded_sample": decoded,
    }


def last_run(run_id: str | None = None, include_output: bool = True) -> dict[str, Any]:
    if run_id is None:
        latest_path = RUNS_DIR / "latest.txt"
        if not latest_path.exists():
            raise OrchestratorError("No runs found yet.")
        run_id = latest_path.read_text(encoding="utf-8").strip()
    run_dir = safe_run_dir(run_id)
    metadata_path = run_dir / "metadata.json"
    if not metadata_path.exists():
        raise OrchestratorError(f"Run metadata not found: {run_id}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if include_output:
        for name in ("stdout", "stderr"):
            path = run_dir / f"{name}.txt"
            metadata[f"{name}_tail"] = path.read_text(encoding="utf-8", errors="replace")[-4000:] if path.exists() else ""
    return metadata


def print_json(data: Any) -> None:
    text = json.dumps(sanitize_for_json(data), ensure_ascii=False, indent=2)
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_json_arg(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise OrchestratorError(f"Invalid JSON argument: {exc}") from exc


def parse_key_values(items: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise OrchestratorError(f"Expected key=value, got: {item}")
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def list_prompt_pack() -> dict[str, Any]:
    if not PROMPT_PACK_DIR.exists():
        return {"ok": False, "path": str(PROMPT_PACK_DIR), "templates": [], "error": "Prompt pack directory not found."}
    templates = []
    for path in sorted(PROMPT_PACK_DIR.glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        first_line = path.read_text(encoding="utf-8", errors="replace").splitlines()[0:1]
        templates.append({"name": path.stem, "path": str(path), "title": first_line[0].lstrip("# ").strip() if first_line else path.stem})
    return {"ok": True, "path": str(PROMPT_PACK_DIR), "templates": templates}


def render_prompt_template(template: str, task: str = "", variables: dict[str, Any] | None = None) -> dict[str, Any]:
    if not re.match(r"^[A-Za-z0-9_\-]+$", template):
        raise OrchestratorError(f"Invalid prompt template name: {template}")
    path = PROMPT_PACK_DIR / f"{template}.md"
    if not path.exists():
        available = ", ".join(item["name"] for item in list_prompt_pack().get("templates", []))
        raise OrchestratorError(f"Prompt template not found: {template}. Available: {available}")
    values = {str(k): str(v) for k, v in (variables or {}).items()}
    values.setdefault("task", task)
    values.setdefault("write_scope", "No write scope provided. Default to read-only.")
    text = path.read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    return {"ok": True, "template": template, "path": str(path), "prompt": text}


def main() -> int:
    parser = argparse.ArgumentParser(description="Claude Code orchestrator backed by CCSwitch.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("healthcheck")
    init_ws = sub.add_parser("init-workspace")
    init_ws.add_argument("--cwd")
    init_ws.add_argument("--role", default="development")
    init_ws.add_argument("--no-claude-md", action="store_true")
    init_ws.add_argument("--repair-mcp", action="store_true")
    ws_status = sub.add_parser("workspace-status")
    ws_status.add_argument("--cwd")
    migrate_cmd = sub.add_parser("migrate-data")
    migrate_cmd.add_argument("--cwd")
    migrate_cmd.add_argument("--apply", action="store_true")
    clean_cmd = sub.add_parser("clean-workspace")
    clean_cmd.add_argument("--cwd")
    clean_cmd.add_argument("--older-than-days", type=int, default=30)
    clean_cmd.add_argument("--apply", action="store_true")
    archive_cmd = sub.add_parser("archive-runs")
    archive_cmd.add_argument("--cwd")
    archive_cmd.add_argument("--older-than-days", type=int, default=30)
    archive_cmd.add_argument("--run-id", action="append", dest="run_ids")
    archive_cmd.add_argument("--apply", action="store_true")
    archive_cmd.add_argument("--remove", action="store_true")
    repair_cmd = sub.add_parser("repair-mcp-paths")
    repair_cmd.add_argument("--cwd")
    repair_cmd.add_argument("--mcp-path")
    repair_cmd.add_argument("--create", action="store_true")
    repair_cmd.add_argument("--apply", action="store_true")
    policy_cmd = sub.add_parser("folder-policy")
    policy_cmd.add_argument("--cwd")
    policy_cmd.add_argument("--apply", action="store_true")
    lp = sub.add_parser("list-profiles")
    lp.add_argument("--include-secrets", action="store_true")
    pick = sub.add_parser("pick")
    pick.add_argument("--role", default="implementation")
    pick.add_argument("--task-type")
    pick.add_argument("--profile")
    run = sub.add_parser("run")
    run.add_argument("task")
    run.add_argument("--role", default="implementation")
    run.add_argument("--task-type")
    run.add_argument("--profile")
    run.add_argument("--allow-write", action="store_true")
    run.add_argument("--timeout-seconds", type=int)
    run.add_argument("--cwd")
    stream = sub.add_parser("run-streaming")
    stream.add_argument("task")
    stream.add_argument("--role", default="implementation")
    stream.add_argument("--task-type")
    stream.add_argument("--profile")
    stream.add_argument("--allow-write", action="store_true")
    stream.add_argument("--timeout-seconds", type=int)
    stream.add_argument("--cwd")
    stream.add_argument("--context")
    stream.add_argument("--no-include-partial-messages", action="store_true")
    stream.add_argument("--max-output-bytes", type=int)
    stream.add_argument("--max-events-bytes", type=int)
    stream.add_argument("--soft-output-bytes", type=int)
    stream.add_argument("--output-budget-policy", choices=["stop", "truncate"])
    stream.add_argument("--kill-on-excessive-output", action="store_true")
    stream.add_argument("--final-only", action="store_true")
    stream.add_argument("--final-max-chars", type=int)
    poll = sub.add_parser("poll-run")
    poll.add_argument("--run-id", required=True)
    poll.add_argument("--stdout-offset", type=int, default=0)
    poll.add_argument("--stderr-offset", type=int, default=0)
    poll.add_argument("--event-offset", type=int, default=0)
    poll.add_argument("--max-bytes", type=int, default=20000)
    poll.add_argument("--tail-chars", type=int, default=4000)
    poll.add_argument("--no-output-tail", action="store_true")
    poll.add_argument("--mode", choices=["raw", "controller"], default="controller")
    poll.add_argument("--max-events", type=int, default=20)
    poll.add_argument("--max-summary-chars", type=int, default=2000)
    poll.add_argument("--no-write-artifacts", action="store_true")
    summarize_cmd = sub.add_parser("summarize-run")
    summarize_cmd.add_argument("--run-id", required=True)
    summarize_cmd.add_argument("--event-offset", type=int, default=0)
    summarize_cmd.add_argument("--max-bytes", type=int, default=20000)
    summarize_cmd.add_argument("--max-events", type=int, default=20)
    summarize_cmd.add_argument("--max-summary-chars", type=int, default=2000)
    summarize_cmd.add_argument("--no-write-artifacts", action="store_true")
    compact_cmd = sub.add_parser("compact-events")
    compact_cmd.add_argument("--run-id", required=True)
    compact_cmd.add_argument("--event-offset", type=int, default=0)
    compact_cmd.add_argument("--max-bytes", type=int, default=20000)
    compact_cmd.add_argument("--max-events", type=int, default=20)
    compact_cmd.add_argument("--write-artifacts", action="store_true")
    stop = sub.add_parser("stop-run")
    stop.add_argument("--run-id", required=True)
    stop.add_argument("--force", action="store_true")
    stop.add_argument("--timeout-seconds", type=int, default=5)
    status = sub.add_parser("run-status")
    status.add_argument("--run-id")
    status.add_argument("--include-output", action="store_true")
    status.add_argument("--include-finished", action="store_true")
    status.add_argument("--tail-chars", type=int, default=4000)
    status.add_argument("--limit", type=int, default=50)
    send = sub.add_parser("send-instruction")
    send.add_argument("--run-id", required=True)
    send.add_argument("instruction")
    send.add_argument("--force", action="store_true")
    send.add_argument("--role")
    send.add_argument("--task-type")
    send.add_argument("--timeout-seconds", type=int)
    send.add_argument("--no-preserve-route", action="store_true")
    send.add_argument("--reroute", action="store_true")
    send.add_argument("--route-profile")
    send.add_argument("--route-model")
    team = sub.add_parser("spawn-role-team")
    team.add_argument("task")
    team.add_argument("--roles", default="requirements,architecture,security,testing")
    team.add_argument("--cwd")
    team.add_argument("--context")
    team.add_argument("--timeout-seconds", type=int)
    collect = sub.add_parser("collect-team-results")
    collect.add_argument("--team-id")
    collect.add_argument("--run-id", action="append", dest="run_ids")
    collect.add_argument("--tail-chars", type=int, default=8000)
    cross = sub.add_parser("cross-review")
    cross.add_argument("--run-id", action="append", dest="run_ids", required=True)
    cross.add_argument("--reviewer-roles", default="security,testing,review")
    cross.add_argument("--cwd")
    cross.add_argument("--timeout-seconds", type=int)
    scope = sub.add_parser("preflight-write-scope")
    scope.add_argument("--cwd")
    scope.add_argument("--allow", action="append", dest="allowed_paths")
    scope.add_argument("--deny", action="append", dest="denied_paths")
    scope.add_argument("--max-diff-lines", type=int, default=800)
    check_scope = sub.add_parser("check-write-scope")
    check_scope.add_argument("--run-id")
    check_scope.add_argument("--cwd")
    diff_summary_cmd = sub.add_parser("diff-summary")
    diff_summary_cmd.add_argument("--cwd")
    secret_scan = sub.add_parser("secret-scan-run")
    secret_scan.add_argument("--run-id", required=True)
    secret_scan.add_argument("--no-diff", action="store_true")
    rollback = sub.add_parser("rollback-run")
    rollback.add_argument("--run-id", required=True)
    rollback.add_argument("--confirm", action="store_true")
    verify = sub.add_parser("verify-run")
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--test-command", action="append", dest="test_commands")
    verify.add_argument("--test-timeout-seconds", type=int, default=300)
    verify.add_argument("--no-diff", action="store_true")
    bench = sub.add_parser("benchmark-model")
    bench.add_argument("--profile")
    bench.add_argument("--role", default="testing")
    bench.add_argument("--task", default="Return a concise JSON object with keys ok and summary.")
    bench.add_argument("--timeout-seconds", type=int, default=120)
    bench.add_argument("--execute", action="store_true")
    bench_suite = sub.add_parser("benchmark-suite")
    bench_suite.add_argument("--profile")
    bench_suite.add_argument("--timeout-seconds", type=int, default=120)
    bench_suite.add_argument("--execute", action="store_true")
    calibrate = sub.add_parser("calibrate-policy")
    calibrate.add_argument("--preferences-json", default="{}")
    calibrate.add_argument("--preference", action="append", dest="preferences")
    calibrate.add_argument("--no-apply", action="store_true")
    guard = sub.add_parser("cost-guard")
    guard.add_argument("--config-json", default="{}")
    guard.add_argument("--max-concurrent", type=int)
    guard.add_argument("--max-timeout-seconds", type=int)
    guard.add_argument("--apply", action="store_true")
    usage = sub.add_parser("usage-summary")
    usage.add_argument("--date")
    usage.add_argument("--write-report", action="store_true")
    queue_submit_cmd = sub.add_parser("queue-submit")
    queue_submit_cmd.add_argument("task")
    queue_submit_cmd.add_argument("--role", default="implementation")
    queue_submit_cmd.add_argument("--priority", type=int, default=100)
    queue_submit_cmd.add_argument("--cwd")
    queue_submit_cmd.add_argument("--context")
    queue_submit_cmd.add_argument("--timeout-seconds", type=int)
    queue_submit_cmd.add_argument("--max-retries", type=int, default=0)
    queue_submit_cmd.add_argument("--allow-write", action="store_true")
    queue_tick_cmd = sub.add_parser("queue-tick")
    queue_tick_cmd.add_argument("--max-concurrent", type=int)
    queue_status_cmd = sub.add_parser("queue-status")
    queue_status_cmd.add_argument("--active-only", action="store_true")
    queue_cancel_cmd = sub.add_parser("queue-cancel")
    queue_cancel_cmd.add_argument("--job-id", required=True)
    queue_policy_cmd = sub.add_parser("queue-policy")
    queue_policy_cmd.add_argument("--config-json", default="{}")
    queue_policy_cmd.add_argument("--max-concurrent", type=int)
    queue_policy_cmd.add_argument("--default-timeout-seconds", type=int)
    queue_policy_cmd.add_argument("--apply", action="store_true")
    registry_cmd = sub.add_parser("model-registry")
    registry_cmd.add_argument("--refresh", action="store_true")
    registry_cmd.add_argument("--apply", action="store_true")
    local_policy_cmd = sub.add_parser("local-policy")
    local_policy_cmd.add_argument("--config-json", default="{}")
    local_policy_cmd.add_argument("--preference", action="append", dest="preferences")
    local_policy_cmd.add_argument("--show", action="store_true")
    local_policy_cmd.add_argument("--apply", action="store_true")
    score_worker_cmd = sub.add_parser("score-worker")
    score_worker_cmd.add_argument("--run-id", required=True)
    score_worker_cmd.add_argument("--solved", choices=["true", "false"])
    score_worker_cmd.add_argument("--hallucination", choices=["true", "false"])
    score_worker_cmd.add_argument("--needs-rework", choices=["true", "false"])
    score_worker_cmd.add_argument("--notes")
    score_worker_cmd.add_argument("--no-apply", action="store_true")
    prompt_pack_cmd = sub.add_parser("prompt-pack")
    prompt_pack_cmd.add_argument("--list", action="store_true")
    render_prompt_cmd = sub.add_parser("render-prompt")
    render_prompt_cmd.add_argument("--template", required=True)
    render_prompt_cmd.add_argument("--task", default="")
    render_prompt_cmd.add_argument("--var", action="append", dest="variables")
    upgrade = sub.add_parser("upgrade-check")
    upgrade.add_argument("--apply", action="store_true")
    mock = sub.add_parser("mock-stream-test")
    mock.add_argument("--timeout-seconds", type=int, default=20)
    dash = sub.add_parser("dashboard")
    dash.add_argument("--include-finished", action="store_true")
    dash.add_argument("--active-only", action="store_true")
    dash.add_argument("--limit", type=int, default=12)
    dash.add_argument("--open", action="store_true")
    open_folder = sub.add_parser("open-run-folder")
    open_folder.add_argument("--run-id", required=True)
    open_folder.add_argument("--no-open", action="store_true")
    export = sub.add_parser("export-report")
    export.add_argument("--run-id")
    export.add_argument("--team-id")
    export.add_argument("--output-dir")
    controller = sub.add_parser("controller-report")
    controller.add_argument("--run-id")
    controller.add_argument("--team-id")
    controller.add_argument("--date")
    controller.add_argument("--active-only", action="store_true")
    controller.add_argument("--limit", type=int, default=50)
    controller.add_argument("--output-dir")
    pressure = sub.add_parser("pressure-report")
    pressure.add_argument("--run-id")
    pressure.add_argument("--team-id")
    pressure.add_argument("--date")
    pressure.add_argument("--active-only", action="store_true")
    pressure.add_argument("--limit", type=int, default=50)
    pressure.add_argument("--output-dir")
    decision = sub.add_parser("decision-review")
    decision.add_argument("proposed_action")
    decision.add_argument("--task", default="")
    decision.add_argument("--run-id")
    decision.add_argument("--team-id")
    decision.add_argument("--evidence")
    decision.add_argument("--output-dir")
    supervise = sub.add_parser("supervise-decision")
    supervise.add_argument("proposed_action")
    supervise.add_argument("--task", default="")
    supervise.add_argument("--run-id")
    supervise.add_argument("--team-id")
    supervise.add_argument("--evidence")
    supervise.add_argument("--output-dir")
    visible = sub.add_parser("run-visible")
    visible.add_argument("task")
    visible.add_argument("--role", default="implementation")
    visible.add_argument("--task-type")
    visible.add_argument("--profile")
    visible.add_argument("--allow-write", action="store_true")
    visible.add_argument("--cwd")
    diff = sub.add_parser("diff")
    diff.add_argument("--cwd")
    workflow = sub.add_parser("workflow-plan")
    workflow.add_argument("task")
    workflow.add_argument("--cwd")
    workflow_validate_cmd = sub.add_parser("workflow-validate")
    workflow_validate_cmd.add_argument("--file", required=True)
    workflow_validate_cmd.add_argument("--cwd")
    workflow_dry_cmd = sub.add_parser("workflow-dry-run")
    workflow_dry_cmd.add_argument("--file", required=True)
    workflow_dry_cmd.add_argument("--task")
    workflow_dry_cmd.add_argument("--cwd")
    workflow_run_cmd = sub.add_parser("workflow-run")
    workflow_run_cmd.add_argument("--file", required=True)
    workflow_run_cmd.add_argument("--task", required=True)
    workflow_run_cmd.add_argument("--cwd")
    workflow_run_cmd.add_argument("--mock", action="store_true")
    workflow_run_cmd.add_argument("--loop-guard", type=int, default=50)
    workflow_status_cmd = sub.add_parser("workflow-status")
    workflow_status_cmd.add_argument("--workflow-id", required=True)
    workflow_status_cmd.add_argument("--cwd")
    workflow_retry_cmd = sub.add_parser("workflow-retry-node")
    workflow_retry_cmd.add_argument("--workflow-id", required=True)
    workflow_retry_cmd.add_argument("--node-id", required=True)
    workflow_retry_cmd.add_argument("--cwd")
    workflow_stop_cmd = sub.add_parser("workflow-stop")
    workflow_stop_cmd.add_argument("--workflow-id", required=True)
    workflow_stop_cmd.add_argument("--cwd")
    workflow_stop_cmd.add_argument("--force", action="store_true")
    workflow_report_cmd = sub.add_parser("workflow-report")
    workflow_report_cmd.add_argument("--workflow-id", required=True)
    workflow_report_cmd.add_argument("--cwd")
    handoff_template_cmd = sub.add_parser("handoff-template")
    handoff_template_cmd.add_argument("--role", default="testing")
    handoff_validate_cmd = sub.add_parser("handoff-validate")
    handoff_validate_cmd.add_argument("--run-id", required=True)
    handoff_validate_cmd.add_argument("--schema")
    handoff_read_cmd = sub.add_parser("handoff-read")
    handoff_read_cmd.add_argument("--run-id", required=True)
    handoff_repair_cmd = sub.add_parser("handoff-repair-prompt")
    handoff_repair_cmd.add_argument("--run-id", required=True)
    sub.add_parser("score-models")
    sub.add_parser("write-auto-policy")
    reports = sub.add_parser("write-reports")
    reports.add_argument("--output-dir")
    claude_md = sub.add_parser("write-claude-md")
    claude_md.add_argument("--cwd")
    claude_md.add_argument("--role", default="implementation")
    claude_md.add_argument("--project-name")
    claude_md.add_argument("--append", action="store_true")
    claude_md.add_argument("--force", action="store_true")
    sub.add_parser("selftest")
    last = sub.add_parser("last-run")
    last.add_argument("--run-id")
    worker = sub.add_parser("_stream-worker")
    worker.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        if args.command == "healthcheck":
            print_json(healthcheck())
        elif args.command == "init-workspace":
            print_json(init_workspace(cwd=args.cwd, role=args.role, write_claude=not args.no_claude_md, repair_mcp=args.repair_mcp))
        elif args.command == "workspace-status":
            print_json(workspace_status(cwd=args.cwd))
        elif args.command == "migrate-data":
            print_json(migrate_data(cwd=args.cwd, apply=args.apply))
        elif args.command == "clean-workspace":
            print_json(clean_workspace(cwd=args.cwd, older_than_days=args.older_than_days, dry_run=not args.apply))
        elif args.command == "archive-runs":
            print_json(archive_runs(cwd=args.cwd, older_than_days=args.older_than_days, run_ids=args.run_ids, apply=args.apply, remove=args.remove))
        elif args.command == "repair-mcp-paths":
            print_json(repair_mcp_paths(cwd=args.cwd, mcp_path=args.mcp_path, apply=args.apply, create=args.create))
        elif args.command == "folder-policy":
            print_json(folder_policy(cwd=args.cwd, apply=args.apply))
        elif args.command == "list-profiles":
            print_json(list_profiles(include_secrets=args.include_secrets))
        elif args.command == "pick":
            route = resolve_route(args.role, args.task_type, args.profile)
            provider = get_provider(route["profile"])
            print_json({**route, "selected_provider": redact(provider.settings), "model": route.get("model_override") or provider.model})
        elif args.command == "run":
            print_json(
                run_agent(
                    task=args.task,
                    role=args.role,
                    task_type=args.task_type,
                    profile=args.profile,
                    allow_write=args.allow_write,
                    timeout_seconds=args.timeout_seconds,
                    cwd=Path(args.cwd) if args.cwd else None,
                )
            )
        elif args.command == "run-streaming":
            print_json(
                run_streaming_agent(
                    task=args.task,
                    role=args.role,
                    task_type=args.task_type,
                    profile=args.profile,
                    allow_write=args.allow_write,
                    timeout_seconds=args.timeout_seconds,
                    cwd=Path(args.cwd) if args.cwd else None,
                    context=args.context,
                    include_partial_messages=not args.no_include_partial_messages,
                    max_output_bytes=args.max_output_bytes,
                    max_events_bytes=args.max_events_bytes,
                    soft_output_bytes=args.soft_output_bytes,
                    output_budget_policy=args.output_budget_policy,
                    kill_on_excessive_output=args.kill_on_excessive_output,
                    final_only=args.final_only,
                    final_max_chars=args.final_max_chars,
                )
            )
        elif args.command == "poll-run":
            print_json(
                poll_run(
                    run_id=args.run_id,
                    stdout_offset=args.stdout_offset,
                    stderr_offset=args.stderr_offset,
                    event_offset=args.event_offset,
                    max_bytes=args.max_bytes,
                    include_output_tail=not args.no_output_tail,
                    tail_chars=args.tail_chars,
                    mode=args.mode,
                    max_events=args.max_events,
                    max_summary_chars=args.max_summary_chars,
                    write_artifacts=not args.no_write_artifacts,
                )
            )
        elif args.command == "summarize-run":
            print_json(
                summarize_run(
                    run_id=args.run_id,
                    event_offset=args.event_offset,
                    max_bytes=args.max_bytes,
                    max_events=args.max_events,
                    max_summary_chars=args.max_summary_chars,
                    write_artifacts=not args.no_write_artifacts,
                )
            )
        elif args.command == "compact-events":
            print_json(compact_events(run_id=args.run_id, event_offset=args.event_offset, max_bytes=args.max_bytes, max_events=args.max_events, write_artifacts=args.write_artifacts))
        elif args.command == "stop-run":
            print_json(stop_run(run_id=args.run_id, force=args.force, timeout_seconds=args.timeout_seconds))
        elif args.command == "run-status":
            print_json(
                run_status(
                    run_id=args.run_id,
                    include_output_tail=args.include_output,
                    tail_chars=args.tail_chars,
                    include_finished=args.include_finished,
                    limit=args.limit,
                )
            )
        elif args.command == "send-instruction":
            print_json(
                send_instruction(
                    run_id=args.run_id,
                    instruction=args.instruction,
                    force=args.force,
                    role=args.role,
                    task_type=args.task_type,
                    timeout_seconds=args.timeout_seconds,
                    preserve_route=not args.no_preserve_route,
                    reroute=args.reroute,
                    route_profile=args.route_profile,
                    route_model=args.route_model,
                )
            )
        elif args.command == "spawn-role-team":
            print_json(
                spawn_role_team(
                    task=args.task,
                    roles=split_csv(args.roles),
                    cwd=Path(args.cwd) if args.cwd else None,
                    context=args.context,
                    timeout_seconds=args.timeout_seconds,
                )
            )
        elif args.command == "collect-team-results":
            print_json(collect_team_results(team_id=args.team_id, run_ids=args.run_ids, tail_chars=args.tail_chars))
        elif args.command == "cross-review":
            print_json(
                cross_review(
                    run_ids=args.run_ids,
                    reviewer_roles=split_csv(args.reviewer_roles),
                    cwd=Path(args.cwd) if args.cwd else None,
                    timeout_seconds=args.timeout_seconds,
                )
            )
        elif args.command == "preflight-write-scope":
            print_json(
                preflight_write_scope(
                    cwd=Path(args.cwd) if args.cwd else None,
                    allowed_paths=args.allowed_paths,
                    denied_paths=args.denied_paths,
                    max_diff_lines=args.max_diff_lines,
                )
            )
        elif args.command == "check-write-scope":
            print_json(check_write_scope(run_id=args.run_id, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "diff-summary":
            print_json(diff_summary(cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "secret-scan-run":
            print_json(secret_scan_run(args.run_id, include_diff=not args.no_diff))
        elif args.command == "rollback-run":
            print_json(rollback_run(args.run_id, confirm=args.confirm))
        elif args.command == "verify-run":
            print_json(
                verify_run(
                    run_id=args.run_id,
                    test_commands=args.test_commands,
                    test_timeout_seconds=args.test_timeout_seconds,
                    include_diff=not args.no_diff,
                )
            )
        elif args.command == "benchmark-model":
            print_json(
                benchmark_model(
                    profile=args.profile,
                    role=args.role,
                    task=args.task,
                    timeout_seconds=args.timeout_seconds,
                    execute=args.execute,
                )
            )
        elif args.command == "benchmark-suite":
            print_json(benchmark_suite(profile=args.profile, execute=args.execute, timeout_seconds=args.timeout_seconds))
        elif args.command == "calibrate-policy":
            preferences = parse_json_arg(args.preferences_json)
            preferences.update(parse_key_values(args.preferences))
            print_json(calibrate_policy(preferences, apply=not args.no_apply))
        elif args.command == "cost-guard":
            guard_config = parse_json_arg(args.config_json)
            if args.max_concurrent is not None:
                guard_config["max_concurrent"] = args.max_concurrent
            if args.max_timeout_seconds is not None:
                guard_config["max_timeout_seconds"] = args.max_timeout_seconds
            print_json(cost_guard(guard_config, apply=args.apply))
        elif args.command == "usage-summary":
            print_json(daily_usage_summary(date=args.date, write_report=args.write_report))
        elif args.command == "queue-submit":
            print_json(
                queue_submit(
                    task=args.task,
                    role=args.role,
                    priority=args.priority,
                    cwd=Path(args.cwd) if args.cwd else None,
                    context=args.context,
                    timeout_seconds=args.timeout_seconds,
                    max_retries=args.max_retries,
                    allow_write=args.allow_write,
                )
            )
        elif args.command == "queue-tick":
            print_json(queue_tick(max_concurrent=args.max_concurrent))
        elif args.command == "queue-status":
            print_json(queue_status(include_finished=not args.active_only))
        elif args.command == "queue-cancel":
            print_json(queue_cancel(args.job_id))
        elif args.command == "queue-policy":
            policy_config = parse_json_arg(args.config_json)
            if args.max_concurrent is not None:
                policy_config["max_concurrent"] = args.max_concurrent
            if args.default_timeout_seconds is not None:
                policy_config["default_timeout_seconds"] = args.default_timeout_seconds
            print_json(queue_policy(policy_config, apply=args.apply))
        elif args.command == "model-registry":
            print_json(build_model_registry(refresh=args.refresh or True, apply=args.apply))
        elif args.command == "local-policy":
            local_config = parse_json_arg(args.config_json)
            prefs = parse_key_values(args.preferences)
            if prefs:
                local_config.setdefault("preferred_models", {}).update(prefs)
            print_json(local_policy_override(local_config, apply=args.apply))
        elif args.command == "score-worker":
            to_bool = lambda value: None if value is None else value == "true"
            print_json(score_worker(args.run_id, solved=to_bool(args.solved), hallucination=to_bool(args.hallucination), needs_rework=to_bool(args.needs_rework), notes=args.notes, apply=not args.no_apply))
        elif args.command == "prompt-pack":
            print_json(list_prompt_pack())
        elif args.command == "render-prompt":
            print_json(render_prompt_template(args.template, task=args.task, variables=parse_key_values(args.variables)))
        elif args.command == "upgrade-check":
            print_json(upgrade_check(apply=args.apply))
        elif args.command == "mock-stream-test":
            print_json(mock_stream_test(timeout_seconds=args.timeout_seconds))
        elif args.command == "dashboard":
            print_json(dashboard(include_finished=(args.include_finished or not args.active_only), limit=args.limit, open_browser=args.open))
        elif args.command == "open-run-folder":
            print_json(open_run_folder(args.run_id, open_folder=not args.no_open))
        elif args.command == "export-report":
            print_json(export_report(run_id=args.run_id, team_id=args.team_id, output_dir=Path(args.output_dir) if args.output_dir else None))
        elif args.command in {"controller-report", "pressure-report"}:
            print_json(
                controller_report(
                    run_id=args.run_id,
                    team_id=args.team_id,
                    date=args.date,
                    include_finished=not args.active_only,
                    limit=args.limit,
                    output_dir=Path(args.output_dir) if args.output_dir else None,
                )
            )
        elif args.command in {"decision-review", "supervise-decision"}:
            print_json(
                decision_review(
                    task=args.task,
                    proposed_action=args.proposed_action,
                    run_id=args.run_id,
                    team_id=args.team_id,
                    evidence=args.evidence,
                    output_dir=Path(args.output_dir) if args.output_dir else None,
                )
            )
        elif args.command == "run-visible":
            print_json(
                run_visible_agent(
                    task=args.task,
                    role=args.role,
                    task_type=args.task_type,
                    profile=args.profile,
                    allow_write=args.allow_write,
                    cwd=Path(args.cwd) if args.cwd else None,
                )
            )
        elif args.command == "diff":
            print_json(git_diff(cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-plan":
            print_json(run_workflow_plan(args.task, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-validate":
            print_json(workflow_validate(args.file, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-dry-run":
            print_json(workflow_dry_run(args.file, task=args.task, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-run":
            print_json(workflow_run(args.file, task=args.task, cwd=Path(args.cwd) if args.cwd else None, mock=args.mock, loop_guard=args.loop_guard))
        elif args.command == "workflow-status":
            print_json(workflow_status(args.workflow_id, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-retry-node":
            print_json(workflow_retry_node(args.workflow_id, args.node_id, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-stop":
            print_json(workflow_stop(args.workflow_id, force=args.force, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "workflow-report":
            print_json(workflow_write_report(args.workflow_id, cwd=Path(args.cwd) if args.cwd else None))
        elif args.command == "handoff-template":
            print_json(handoff_template(args.role))
        elif args.command == "handoff-validate":
            print_json(handoff_validate(args.run_id, schema_path=args.schema))
        elif args.command == "handoff-read":
            print_json(handoff_read(args.run_id))
        elif args.command == "handoff-repair-prompt":
            print_json(handoff_repair_prompt(args.run_id))
        elif args.command == "score-models":
            print_json(score_models())
        elif args.command == "write-auto-policy":
            print_json(write_auto_policy())
        elif args.command == "write-reports":
            print_json(write_reports(output_dir=Path(args.output_dir) if args.output_dir else None))
        elif args.command == "write-claude-md":
            print_json(
                write_claude_md(
                    cwd=Path(args.cwd) if args.cwd else None,
                    role=args.role,
                    project_name=args.project_name,
                    append=args.append,
                    force=args.force,
                )
            )
        elif args.command == "selftest":
            result = selftest()
            print_json(result)
            if not result.get("ok"):
                return 1
        elif args.command == "last-run":
            print_json(last_run(args.run_id))
        elif args.command == "_stream-worker":
            print_json(stream_worker(args.run_id))
        return 0
    except OrchestratorError as exc:
        print_json({"ok": False, "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
