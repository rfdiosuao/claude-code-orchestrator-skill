#!/usr/bin/env python3
"""Claude Code orchestration helpers backed by CCSwitch profiles."""

from __future__ import annotations

import argparse
import ctypes
import contextlib
import contextvars
import errno
import functools
import hashlib
import hmac
import html as html_lib
import json
import math
import os
import queue
import re
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from process_identity import (
    ProcessIdentity,
    capture_process_identity,
    compare_process_identity,
    open_stable_process_capability,
)
from runtime_security import (
    ExecutableIdentity,
    RuntimeExecutableCandidate,
    RuntimeLaunchSpec,
    RuntimeSecurityError,
    RuntimeSecurityPolicy,
    build_runtime_launch_spec,
    canonical_path,
)
from secure_payload_store import (
    SecurePayloadStore,
    SecurePayloadStoreError,
    SecurePayloadStoreUnavailable,
    create_secure_payload_store,
)


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


_OPERATION_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "cc_orchestrator_operation_deadline", default=None
)
_TEST_ONLY_RUNTIME_CANDIDATE: contextvars.ContextVar[
    RuntimeExecutableCandidate | None
] = contextvars.ContextVar("cc_orchestrator_test_runtime_candidate", default=None)
_HELD_ARTIFACT_LOCKS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "cc_orchestrator_held_artifact_locks", default=frozenset()
)
_TERMINAL_EVENT_APPEND: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cc_orchestrator_terminal_event_append", default=False
)
_ATOMIC_PRECOMMIT: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "cc_orchestrator_atomic_precommit", default=None
)
_PROCESS_ARTIFACT_LOCK_TOKENS: dict[str, str] = {}
_PROCESS_ARTIFACT_LOCK_TOKENS_LOCK = threading.Lock()
_LEGACY_RECLAIM_LOCKS: dict[str, threading.Lock] = {}
_LEGACY_RECLAIM_LOCKS_GUARD = threading.Lock()
_PROCESS_LAUNCH_LOCK_TOKENS: dict[str, str] = {}
_PROCESS_LAUNCH_LOCK_TOKENS_LOCK = threading.Lock()
_ACTIVE_CLEANUP_OWNERS: dict[str, threading.Thread] = {}
_ACTIVE_CLEANUP_OWNERS_LOCK = threading.Lock()
TERMINALIZATION_TIMEOUT_SECONDS = 1.0
WORKER_FINALIZATION_GRACE_SECONDS = TERMINALIZATION_TIMEOUT_SECONDS + 0.25

_LINUX_PR_SET_PDEATHSIG = 1
_LINUX_PRCTL = None
if sys.platform.startswith("linux"):
    try:
        _LINUX_PRCTL = ctypes.CDLL(None, use_errno=True).prctl
        _LINUX_PRCTL.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        _LINUX_PRCTL.restype = ctypes.c_int
    except (AttributeError, OSError):
        _LINUX_PRCTL = None


def _effective_deadline(deadline: float | None = None) -> float | None:
    return deadline if deadline is not None else _OPERATION_DEADLINE.get()


def _check_deadline(deadline: float | None = None, message: str = "Operation exceeded the launch deadline.") -> None:
    effective = _effective_deadline(deadline)
    if effective is not None and time.monotonic() >= effective:
        raise TimeoutError(message)


@contextlib.contextmanager
def _terminal_artifact_scope() -> Any:
    """Give best-effort terminal persistence a short, independent deadline."""
    token = _OPERATION_DEADLINE.set(
        time.monotonic() + TERMINALIZATION_TIMEOUT_SECONDS
    )
    try:
        yield
    finally:
        _OPERATION_DEADLINE.reset(token)


def _guard_public_launch_transaction(timeout_position: int) -> Any:
    """Establish the launch deadline before any route or policy preparation."""
    def decorate(function: Any) -> Any:
        @functools.wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            requested = kwargs.get("timeout_seconds")
            if requested is None and len(args) > timeout_position:
                requested = args[timeout_position]
            try:
                timeout_seconds = max(1, int(requested or 1800))
            except (TypeError, ValueError):
                timeout_seconds = 1800
            inherited = _effective_deadline()
            deadline = inherited or (
                time.monotonic()
                + timeout_seconds
                + TRANSACTION_CLOSURE_RESERVE_SECONDS
            )
            token = _OPERATION_DEADLINE.set(deadline)
            try:
                _check_deadline(deadline)
                return function(*args, **kwargs)
            except TimeoutError:
                return {
                    "ok": False,
                    "status": "timed_out",
                    "timed_out": True,
                    "stop_reason": "timeout",
                    "exit_code": 124,
                    "terminal_state_count": 1,
                    "persisted": False,
                    "persistence_state": "not_created",
                    "security_error": {
                        "code": "launch_deadline_exceeded",
                        "message": "Runtime preparation exceeded the launch deadline.",
                        "safe_details": {},
                        "suggested_action": "Retry with a longer explicitly approved timeout.",
                    },
                }
            finally:
                _OPERATION_DEADLINE.reset(token)

        return guarded

    return decorate


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
RUNTIME_SECURITY_POLICY_PATH = CONFIG_DIR / "runtime_security.override.json"
WORKER_QUALITY_HISTORY_PATH = CONFIG_DIR / "worker_quality_history.json"
QUEUE_POLICY_PATH = CONFIG_DIR / "queue_policy.json"
QUEUE_PATH = RUNS_DIR / "queue.json"
INTERNAL_WORKER_NONCE_ENV = "CC_ORCHESTRATOR_INTERNAL_WORKER_NONCE"
INTERNAL_GIT_BIN_ENV = "CC_ORCHESTRATOR_INTERNAL_GIT_BIN"
_DISCOVERED_GIT_COMMAND = shutil.which("git")
_PINNED_SUBPROCESS_POPEN = subprocess.Popen
PRIVATE_LAUNCH_FRAME_LIMIT = 64 * 1024
PROMPT_BYTES_LIMIT = 1024 * 1024
INTERNAL_WORKER_NONCE_TTL_SECONDS = 60
WORKER_START_GATE_TIMEOUT_SECONDS = 5.0
TRANSACTION_CLOSURE_RESERVE_SECONDS = 0.05
WORKER_START_GATE_FILENAME = "worker-start-gate.json"
SCRUBBED_VALUE = "[REDACTED]"
CONTROLLER_OS_BASELINE_KEYS = (
    (
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    )
    if os.name == "nt"
    else ("HOME", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR")
)
_ACTIVE_WORKER_HANDLES: dict[str, subprocess.Popen[Any]] = {}
_ACTIVE_WORKER_HANDLES_LOCK = threading.Lock()


@dataclass
class _OwnedProcessTree:
    generation: str
    process: subprocess.Popen[Any]
    kind: str
    handle: int
    deadline: float
    owner_token: str = "caller"
    state: str = "caller_owned"
    termination_requested: threading.Event = field(default_factory=threading.Event)
    completed: threading.Event = field(default_factory=threading.Event)
    owner: threading.Thread | None = None
    member_handles: dict[int, int] = field(default_factory=dict)
    member_wait_confirmed: set[int] = field(default_factory=set)
    member_close_attempted: set[int] = field(default_factory=set)
    streams_close_attempted: set[str] = field(default_factory=set)
    members_captured: bool = False
    assignment_verified: bool = False
    job_termination_attempted: bool = False
    job_active_zero: bool = False
    job_closed: bool = False
    root_reaped: bool = False
    readers_closed: bool = False
    cleanup_result: str = "owned"
    api_failures: list[str] = field(default_factory=list)
    proof_failures: list[str] = field(default_factory=list)
    lock: Any = field(default_factory=threading.RLock, repr=False)

    def request_termination(self) -> None:
        self.termination_requested.set()


_OWNED_PROCESS_TREES: dict[str, _OwnedProcessTree] = {}
_OWNED_PROCESS_TREES_LOCK = threading.Lock()
_PENDING_DESCENDANT_CLEANUPS: dict[int, _OwnedProcessTree] = {}
_PENDING_DESCENDANT_CLEANUPS_LOCK = threading.Lock()
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
_SECRET_PREFIX_SPECS = (
    ("sk-", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"), 8, None),
    ("ghp_", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"), 20, None),
    ("github_pat_", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"), 20, None),
    ("npm_", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 20, None),
    ("akia", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 16, 16),
    ("aiza", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"), 35, 35),
)
_BEARER_VALUE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+/=-"
)
_PRIVATE_KEY_MARKERS = (
    "-----begin rsa key-----",
    "-----begin openssh key-----",
    "-----begin private key-----",
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


class _OwnedCleanupPending(OrchestratorError):
    def __init__(
        self,
        process: subprocess.Popen[Any],
        threads: tuple[threading.Thread, ...] | list[threading.Thread] = (),
        response_updates: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(f"Owned process {process.pid} is awaiting confirmed reaping.")
        self.process = process
        self.threads = tuple(threads)
        self.response_updates = dict(response_updates or {})


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


def load_runtime_security_policy() -> RuntimeSecurityPolicy:
    if not RUNTIME_SECURITY_POLICY_PATH.exists():
        return RuntimeSecurityPolicy.default()
    return RuntimeSecurityPolicy.load(RUNTIME_SECURITY_POLICY_PATH)


def local_configured_candidate(path: str | Path) -> RuntimeExecutableCandidate:
    return RuntimeExecutableCandidate(
        canonical_path=str(canonical_path(path)),
        source="runtime_security.override.json",
        trust_class="local_configured",
    )


def _trusted_candidate_source(
    path: Path, *, discovered_path: Path | None = None
) -> str | None:
    normalized = path.as_posix().casefold()
    local_names = {"claude", "claude.exe"}
    origin = discovered_path or path
    official_local = user_home() / ".local" / "bin" / origin.name
    origin_key = os.path.normcase(os.path.abspath(str(origin)))
    official_key = os.path.normcase(os.path.abspath(str(official_local)))
    canonical_key = os.path.normcase(os.path.abspath(str(path)))
    versions_root = os.path.normcase(
        os.path.abspath(str(user_home() / ".local" / "share" / "claude" / "versions"))
    )
    if origin.name.casefold() in local_names and origin_key == official_key:
        try:
            within_versions = (
                os.path.commonpath((canonical_key, versions_root))
                == versions_root
            )
        except ValueError:
            within_versions = False
        if canonical_key == official_key or within_versions:
            return "official_user_local"
    package_suffixes = (
        "/node_modules/@anthropic-ai/claude-code/bin/claude",
        "/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
    )
    origin_normalized = Path(origin_key).as_posix().casefold()
    if (
        normalized.endswith(package_suffixes)
        and origin_normalized.endswith(package_suffixes)
        and canonical_key == origin_key
        and "/.workbuddy/binaries/node/versions/" in normalized
    ):
        return "workbuddy_package"
    return None


def discover_claude_candidate(
    *, ignore_environment_override: bool = True
) -> RuntimeExecutableCandidate:
    candidates: list[tuple[Path, str]] = []
    home = user_home()
    direct_names = ("claude.exe", "claude") if os.name == "nt" else ("claude",)
    for name in direct_names:
        candidate = home / ".local" / "bin" / name
        if candidate.is_file():
            candidates.append((candidate, "enumerated_root"))
    glob_roots = (
        (
            home,
            ".workbuddy/binaries/node/versions/*/node_modules/@anthropic-ai/claude-code/bin/claude*",
        ),
        (
            Path(os.environ.get("PROGRAMDATA", "")) / "WorkBuddy",
            "chromium-env/*/.workbuddy/binaries/node/versions/*/node_modules/@anthropic-ai/claude-code/bin/claude*",
        ),
    )
    for root, pattern in glob_roots:
        if not str(root) or not root.exists():
            continue
        try:
            candidates.extend(
                (path, "enumerated_root")
                for path in root.glob(pattern)
                if path.is_file()
            )
        except OSError:
            continue
    path_hit = shutil.which("claude")
    if path_hit:
        candidates.append((Path(path_hit), "path_discovery"))
    if not ignore_environment_override:
        explicit = os.environ.get("CLAUDE_CODE_BIN")
        if explicit:
            explicit_path = Path(explicit).expanduser()
            resolved = (
                str(explicit_path)
                if explicit_path.is_absolute()
                else shutil.which(explicit) or ""
            )
            if resolved and Path(resolved).is_file():
                candidates.insert(0, (Path(resolved), "environment_override"))

    resolved_candidates: dict[str, tuple[Path, str, Path]] = {}
    for candidate, provenance in candidates:
        try:
            resolved = canonical_path(candidate)
        except (OSError, ValueError):
            continue
        key = os.path.normcase(str(resolved))
        previous = resolved_candidates.get(key)
        if previous is None or (
            provenance == "enumerated_root" and previous[1] != "enumerated_root"
        ):
            origin = Path(os.path.abspath(str(candidate.expanduser())))
            resolved_candidates[key] = (resolved, provenance, origin)
    if not resolved_candidates:
        ambient = os.environ.get("CLAUDE_CODE_BIN")
        action = (
            "Pin the absolute executable and identity in "
            "runtime_security.override.json; CLAUDE_CODE_BIN is ignored."
            if ambient
            else "Install Claude Code in a recognized layout or pin it in runtime_security.override.json."
        )
        raise RuntimeSecurityError(
            code="runtime_not_trusted",
            message="No approved Claude Code runtime candidate was found.",
            safe_details={"ambient_override_ignored": bool(ambient)},
            suggested_action=action,
        )

    selected, provenance, discovered_path = sorted(
        resolved_candidates.values(),
        key=lambda item: (
            0
            if item[1] == "enumerated_root"
            and _trusted_candidate_source(
                item[0], discovered_path=item[2]
            )
            is not None
            else 1,
            _claude_candidate_rank(str(item[0])),
        ),
    )[0]
    trusted_source = (
        _trusted_candidate_source(
            selected, discovered_path=discovered_path
        )
        if provenance == "enumerated_root"
        else None
    )
    return RuntimeExecutableCandidate(
        canonical_path=str(selected),
        source=trusted_source or provenance,
        trust_class="trusted_default" if trusted_source else "discovered_unpinned",
    )


def resolve_runtime_candidate(
    policy: RuntimeSecurityPolicy,
) -> RuntimeExecutableCandidate:
    test_fixture = _TEST_ONLY_RUNTIME_CANDIDATE.get()
    if test_fixture is not None:
        return test_fixture
    configured = policy.configured_runtime_path()
    if configured is not None:
        return local_configured_candidate(configured)
    return discover_claude_candidate(ignore_environment_override=True)


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise OrchestratorError(f"Missing config file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise OrchestratorError(f"Invalid JSON in {path}: {exc}") from exc


def _secret_value_spans(value: str) -> list[tuple[int, int]]:
    """Find known token shapes with bounded, forward-only scans."""
    lowered = value.casefold()
    spans: list[tuple[int, int]] = []
    for prefix, allowed, minimum, exact in _SECRET_PREFIX_SPECS:
        offset = 0
        while True:
            start = lowered.find(prefix, offset)
            if start < 0:
                break
            body_start = start + len(prefix)
            end = body_start
            limit = len(value) if exact is None else min(len(value), body_start + exact)
            while end < limit and value[end] in allowed:
                end += 1
            if end - body_start >= minimum:
                spans.append((start, end))
                offset = end
            else:
                offset = max(body_start, start + 1)

    offset = 0
    while True:
        start = lowered.find("bearer", offset)
        if start < 0:
            break
        body_start = start + len("bearer")
        while body_start < len(value) and value[body_start].isspace():
            body_start += 1
        end = body_start
        while end < len(value) and value[end] in _BEARER_VALUE_CHARS:
            end += 1
        if body_start > start + len("bearer") and end - body_start >= 20:
            spans.append((start, end))
            offset = end
        else:
            offset = max(body_start, start + 1)

    for marker in _PRIVATE_KEY_MARKERS:
        offset = 0
        while True:
            start = lowered.find(marker, offset)
            if start < 0:
                break
            spans.append((start, start + len(marker)))
            offset = start + len(marker)

    index = 0
    while index < len(value):
        if not value[index].isalnum() or not value[index].isascii():
            index += 1
            continue
        left_start = index
        while (
            index < len(value)
            and value[index].isascii()
            and value[index].isalnum()
        ):
            index += 1
        if index - left_start < 20 or index >= len(value) or value[index] != ".":
            continue
        right_start = index + 1
        end = right_start
        while (
            end < len(value)
            and value[end].isascii()
            and (value[end].isalnum() or value[end] in "_-")
        ):
            end += 1
        if end - right_start >= 8:
            spans.append((left_start, end))
        index = max(index + 1, end)

    if not spans:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _contains_secret_value(value: str) -> bool:
    return bool(_secret_value_spans(value))


def _redact_secret_values(value: str) -> str:
    spans = _secret_value_spans(value)
    if not spans:
        return value
    parts: list[str] = []
    offset = 0
    for start, end in spans:
        token = value[start:end]
        parts.extend((value[offset:start], token[:6], "...", token[-4:]))
        offset = end
    parts.append(value[offset:])
    return "".join(parts)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***REDACTED***" if should_redact_key(str(k), v) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _redact_secret_values(value)
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


def _controller_os_environment_baseline() -> dict[str, str]:
    baseline: dict[str, str] = {}
    for key in CONTROLLER_OS_BASELINE_KEYS:
        value = os.environ.get(key)
        if isinstance(value, str) and value and "\x00" not in value:
            baseline[key] = value
    return baseline


def _reject_provider_baseline_overrides(provider_env: Mapping[str, str]) -> None:
    baseline_names = {key.casefold() for key in CONTROLLER_OS_BASELINE_KEYS}
    forbidden = sorted(
        str(key)
        for key in provider_env
        if isinstance(key, str) and key.casefold() in baseline_names
    )
    if forbidden:
        raise RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a controller-owned OS key.",
            safe_details={"keys": forbidden},
            suggested_action="Remove controller-owned OS keys from the provider profile.",
        )


def build_worker_env(
    provider_env: dict[str, str],
    model_override: str | None = None,
    workspace_root: str | Path | None = None,
    artifact_root: str | Path | None = None,
) -> dict[str, str]:
    policy = load_runtime_security_policy()
    _reject_provider_baseline_overrides(provider_env)
    env = dict(policy.validate_provider_env(provider_env))
    if model_override is not None:
        if not isinstance(model_override, str) or not model_override or "\x00" in model_override:
            raise OrchestratorError("model_override must be a non-empty string.")
        env["ANTHROPIC_MODEL"] = model_override
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    env["CC_ORCHESTRATOR_WORKSPACE_ROOT"] = str(Path(workspace_root).expanduser().resolve() if workspace_root else WORKSPACE_ROOT)
    env["CC_ORCHESTRATOR_ARTIFACT_ROOT"] = str(Path(artifact_root).expanduser().resolve() if artifact_root else ARTIFACT_ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if os.name != "nt":
        env["LANG"] = "C.UTF-8"
        env["LC_ALL"] = "C.UTF-8"
    env.update(_controller_os_environment_baseline())
    return env


def workspace_paths(cwd: str | Path | None = None) -> dict[str, Path]:
    workspace_root = (
        Path(WORKSPACE_ROOT).expanduser().resolve()
        if cwd is None
        else Path(cwd).expanduser().resolve()
    )
    artifact_root = (
        Path(ARTIFACT_ROOT).expanduser().resolve()
        if cwd is None
        else workspace_root / AGENT_WORKSPACE_DIRNAME / ARTIFACT_NAMESPACE
    )
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


def _guarded_launch_paths(cwd: str | Path) -> dict[str, Path]:
    workspace_root = Path(WORKSPACE_ROOT).expanduser().resolve()
    launch_cwd = Path(cwd).expanduser().resolve()
    try:
        launch_cwd.relative_to(workspace_root)
    except ValueError as exc:
        raise OrchestratorError(
            f"Launch cwd is outside the configured workspace root: {launch_cwd}"
        ) from exc
    artifact_root = Path(ARTIFACT_ROOT).expanduser().resolve()
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
        if (
            metadata.get("status") in {"cleanup_pending", "cleanup_incomplete"}
            or metadata.get("cleanup_state") == "cleanup_incomplete"
        ):
            return True
        worker = _process_identity_observation(
            metadata,
            pid_field="worker_pid",
            identity_field="worker_process_identity",
        )
        child = _process_identity_observation(
            metadata,
            pid_field="child_pid",
            identity_field="child_process_identity",
        )
        return (
            bool(worker["alive"])
            or bool(child["alive"])
            or pid_alive(int(metadata.get("owned_process_pid") or 0))
        )
    except Exception:
        return True


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


def _artifact_lock_owner(payload: bytes) -> tuple[int, str | None]:
    owner_text = payload.decode("ascii").strip()
    try:
        owner = json.loads(owner_text)
    except json.JSONDecodeError:
        return int(owner_text), None
    if not isinstance(owner, dict):
        return int(owner), None
    return int(owner["pid"]), str(owner["token"])


def _artifact_lock_file_identity(details: Any) -> tuple[int, int]:
    if isinstance(details, Mapping):
        file_id = details.get("file_id")
        if (
            isinstance(file_id, (list, tuple))
            and len(file_id) == 2
        ):
            return int(file_id[0]), int(file_id[1])
    return int(details.st_dev), int(details.st_ino)


@contextlib.contextmanager
def _locked_artifact_lock_generation(
    lock_path: Path, *, deadline: float | None = None
) -> Any:
    """Lock and expose one exact artifact-lock file generation."""
    effective = _effective_deadline(deadline)
    with _open_managed_file(
        lock_path, writable=True, verify_private=False
    ) as (handle, details):
        acquired = False
        while not acquired:
            _check_deadline(
                effective,
                "Artifact lock generation inspection exceeded its deadline.",
            )
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(
                        handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                acquired = True
            except OSError:
                time.sleep(0.005)
        try:
            handle.seek(0)
            payload = handle.read(257)
            if len(payload) > 256:
                raise OrchestratorError("Artifact lock owner exceeds its size limit.")
            yield handle, details, payload
        finally:
            if acquired:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass


def _artifact_lock_path_matches_generation(
    lock_path: Path, expected_identity: tuple[int, int]
) -> bool:
    try:
        with _open_managed_file(
            lock_path, verify_private=False
        ) as (_handle, details):
            return _artifact_lock_file_identity(details) == expected_identity
    except FileNotFoundError:
        return False


def _artifact_lock_directory_identity(details: Any) -> tuple[int, int]:
    return _artifact_lock_file_identity(details)


def _artifact_lock_directory_path_matches_generation(
    lock_dir: Path, expected_identity: tuple[int, int]
) -> bool:
    try:
        with _open_managed_directory(
            lock_dir, verify_private=False
        ) as (_handle, details):
            return _artifact_lock_directory_identity(details) == expected_identity
    except FileNotFoundError:
        return False


@contextlib.contextmanager
def _locked_legacy_artifact_lock_generation(
    lock_dir: Path, *, deadline: float | None = None
) -> Any:
    """Serialize retirement while retaining the inspected legacy directory."""
    effective = _effective_deadline(deadline)
    lock_key = os.path.normcase(str(lock_dir.resolve(strict=False)))
    with _LEGACY_RECLAIM_LOCKS_GUARD:
        local_lock = _LEGACY_RECLAIM_LOCKS.setdefault(
            lock_key, threading.Lock()
        )
    while not local_lock.acquire(blocking=False):
        _check_deadline(
            effective,
            "Legacy artifact lock inspection exceeded its deadline.",
        )
        time.sleep(0.005)
    try:
        directory_context = _open_managed_directory(
            lock_dir, writable=True, verify_private=False
        )
        directory_handle, directory_details = directory_context.__enter__()
    except Exception:
        local_lock.release()
        raise
    owner_context: Any | None = None
    owner_handle: Any | None = None
    acquired = False
    try:
        if os.name == "nt":
            owner_context = _open_windows_relative_managed_file(
                directory_handle,
                "owner.pid",
                writable=True,
                verify_private=False,
            )
            owner_handle, _owner_details = owner_context.__enter__()
        else:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            owner_fd = os.open("owner.pid", flags, dir_fd=directory_handle)
            owner_handle = os.fdopen(owner_fd, "r+b")
        while not acquired:
            _check_deadline(
                effective,
                "Legacy artifact lock inspection exceeded its deadline.",
            )
            try:
                owner_handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(owner_handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(
                        owner_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                acquired = True
            except OSError:
                time.sleep(0.005)
        owner_handle.seek(0)
        payload = owner_handle.read(257)
        if len(payload) > 256:
            raise OrchestratorError("Artifact lock owner exceeds its size limit.")
        # POSIX retirement keeps the interprocess owner-file claim through the
        # rename. A waiter that opened this generation cannot pass its own
        # generation comparison until the retiring claimant has finished.
        if os.name == "nt":
            owner_handle.seek(0)
            import msvcrt

            msvcrt.locking(owner_handle.fileno(), msvcrt.LK_UNLCK, 1)
            acquired = False
            if owner_context is not None:
                owner_context.__exit__(None, None, None)
                owner_context = None
            owner_handle = None
        yield directory_handle, directory_details, payload
    finally:
        if acquired and owner_handle is not None:
            try:
                owner_handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(owner_handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(owner_handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        if owner_context is not None:
            owner_context.__exit__(None, None, None)
        elif owner_handle is not None:
            owner_handle.close()
        directory_context.__exit__(None, None, None)
        local_lock.release()


def _claim_ownerless_legacy_artifact_lock(
    lock_dir: Path, *, deadline: float | None = None
) -> tuple[int, int] | None:
    """Atomically claim one stale ownerless legacy directory generation."""
    with _open_managed_directory(
        lock_dir, verify_private=False
    ) as (directory_handle, directory_details):
        generation = _artifact_lock_directory_identity(directory_details)
        try:
            path_details = lock_dir.stat()
        except OSError:
            return None
        if time.time() - path_details.st_mtime <= 60:
            return None
        if not _artifact_lock_directory_path_matches_generation(
            lock_dir, generation
        ):
            return None
        owner_payload = json.dumps(
            {"pid": os.getpid(), "token": uuid.uuid4().hex},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        try:
            if os.name == "nt":
                with _create_windows_private_file(
                    lock_dir / "owner.pid", parent_handle=directory_handle
                ) as owner_handle:
                    owner_handle.write(owner_payload)
                    owner_handle.flush()
                    os.fsync(owner_handle.fileno())
            else:
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                    os, "O_NOFOLLOW", 0
                )
                fd = os.open(
                    "owner.pid", flags, 0o600, dir_fd=directory_handle
                )
                with os.fdopen(fd, "wb") as owner_handle:
                    owner_handle.write(owner_payload)
                    owner_handle.flush()
                    os.fsync(owner_handle.fileno())
        except FileExistsError:
            return None
        _check_deadline(deadline)
        return generation


def _retire_artifact_lock_directory(
    lock_dir: Path,
    suffix: str,
    expected_identity: tuple[int, int] | None = None,
    retained_handle: Any | None = None,
) -> bool:
    if (
        expected_identity is not None
        and not _artifact_lock_directory_path_matches_generation(
            lock_dir, expected_identity
        )
    ):
        return False
    retired = lock_dir.with_name(f"{lock_dir.name}.released-{suffix}")
    try:
        if os.name == "nt" and retained_handle is not None:
            _windows_rename_retained_directory(retained_handle, retired)
        else:
            os.replace(lock_dir, retired)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        (retired / "owner.pid").unlink(missing_ok=True)
        retired.rmdir()
    except OSError:
        pass
    return True


def _windows_rename_retained_directory(
    directory_handle: Any, destination: Path
) -> None:
    import ctypes
    from ctypes import wintypes

    filename = str(destination.resolve(strict=False))

    class FileRenameInfoEx(ctypes.Structure):
        _fields_ = (
            ("Flags", wintypes.DWORD),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * (len(filename) + 1)),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    information = FileRenameInfoEx()
    information.Flags = 0x00000002
    information.RootDirectory = None
    information.FileNameLength = len(filename.encode("utf-16-le"))
    information.FileName = filename
    if not kernel32.SetFileInformationByHandle(
        directory_handle,
        22,
        ctypes.byref(information),
        FileRenameInfoEx.FileName.offset + information.FileNameLength + 2,
    ):
        error = ctypes.get_last_error()
        if error in {2, 3}:
            raise FileNotFoundError(
                error, "Artifact lock generation disappeared"
            )
        raise ctypes.WinError(error)


def _retire_artifact_lock_file(lock_path: Path, suffix: str) -> bool:
    return _retire_artifact_lock_file_generation(lock_path, suffix)


def _retire_artifact_lock_file_generation(
    lock_path: Path,
    suffix: str,
    expected_identity: tuple[int, int] | None = None,
) -> bool:
    if (
        expected_identity is not None
        and not _artifact_lock_path_matches_generation(
            lock_path, expected_identity
        )
    ):
        return False
    retired = lock_path.with_name(f"{lock_path.name}.released-{suffix}")
    try:
        os.replace(lock_path, retired)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        retired.unlink(missing_ok=True)
    except OSError:
        pass
    return True


def _publish_artifact_lock_candidate(candidate: Path, lock_path: Path) -> None:
    with _PREPARED_ATOMIC_PARENTS_LOCK:
        anchor = _PREPARED_ATOMIC_PARENTS.get(str(candidate))
    if anchor is None:
        raise OrchestratorError("Artifact lock candidate capability is unavailable.")
    if anchor[0] == "posix":
        published_fd = _publish_posix_retained_source(
            anchor, lock_path.name
        )
        os.close(published_fd)
        return

    import ctypes
    import msvcrt
    from ctypes import wintypes

    filename = lock_path.name

    class FileLinkInformation(ctypes.Structure):
        _fields_ = (
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * len(filename)),
        )

    class IoStatusBlock(ctypes.Structure):
        _fields_ = (("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t))

    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtSetInformationFile.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    )
    ntdll.NtSetInformationFile.restype = ctypes.c_long
    ntdll.RtlNtStatusToDosError.argtypes = (ctypes.c_long,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    source_handle = anchor[5]
    current = os.fstat(source_handle.fileno())
    if (int(current.st_dev), int(current.st_ino)) != anchor[6]:
        raise OrchestratorError("Artifact lock candidate identity changed.")
    information = FileLinkInformation()
    information.ReplaceIfExists = 0
    information.RootDirectory = anchor[3]
    information.FileNameLength = len(filename.encode("utf-16-le"))
    information.FileName = filename
    io_status = IoStatusBlock()
    status = ntdll.NtSetInformationFile(
        msvcrt.get_osfhandle(source_handle.fileno()),
        ctypes.byref(io_status),
        ctypes.byref(information),
        ctypes.sizeof(information),
        11,
    )
    if status < 0:
        error = int(ntdll.RtlNtStatusToDosError(status))
        if error in {80, 183}:
            raise FileExistsError(error, "Artifact lock already exists", lock_path)
        raise OSError(error, "Artifact lock publication failed", lock_path)


def _reclaim_artifact_lock_for_dead_process(
    run_dir: Path, process_pid: int, *, deadline: float | None = None
) -> bool:
    lock_dir = run_dir.parent / f".{run_dir.name}.artifact.lock"
    for _attempt in range(100):
        if not lock_dir.exists():
            return True
        if deadline is not None and time.monotonic() >= deadline:
            return False
        if not lock_dir.is_dir():
            try:
                with _locked_artifact_lock_generation(
                    lock_dir, deadline=deadline
                ) as (_handle, details, owner_payload):
                    owner_pid, _owner_token = _artifact_lock_owner(owner_payload)
                    if owner_pid != process_pid:
                        return False
                    generation = _artifact_lock_file_identity(details)
                    if not _artifact_lock_path_matches_generation(
                        lock_dir, generation
                    ):
                        continue
                    if _retire_artifact_lock_file(
                        lock_dir, uuid.uuid4().hex
                    ):
                        return True
            except FileNotFoundError:
                return True
            except (OSError, OrchestratorError, KeyError, TypeError, ValueError):
                time.sleep(0.005)
                continue
            time.sleep(0.005)
            continue
        try:
            with _locked_legacy_artifact_lock_generation(
                lock_dir, deadline=deadline
            ) as (directory_handle, directory_details, owner_payload):
                owner_pid, _owner_token = _artifact_lock_owner(owner_payload)
                if owner_pid != process_pid:
                    return False
                generation = _artifact_lock_directory_identity(
                    directory_details
                )
                if not _artifact_lock_directory_path_matches_generation(
                    lock_dir, generation
                ):
                    continue
                if _retire_artifact_lock_directory(
                    lock_dir,
                    uuid.uuid4().hex,
                    generation,
                    directory_handle,
                ):
                    return True
        except FileNotFoundError:
            time.sleep(0.005)
            continue
        except (OSError, KeyError, TypeError, ValueError):
            time.sleep(0.005)
            continue
        time.sleep(0.005)
    return not lock_dir.exists()


class _ArtifactLock:
    def __init__(
        self,
        run_dir: Path,
        timeout_seconds: float,
        deadline: float | None = None,
    ) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.timeout_seconds = timeout_seconds
        self.deadline = _effective_deadline(deadline)
        self.lock_dir = self.run_dir.parent / f".{self.run_dir.name}.artifact.lock"
        self.owner_token = uuid.uuid4().hex
        self.reentrant = False

    def __enter__(self) -> None:
        if not RUN_ID_RE.match(self.run_dir.name):
            raise OrchestratorError(
                f"Invalid run directory for artifact lock: {self.run_dir}"
            )
        key = str(self.run_dir)
        held = _HELD_ARTIFACT_LOCKS.get()
        if key in held:
            self.reentrant = True
            return
        self.run_dir.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout_seconds
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        while True:
            candidate: Path | None = None
            try:
                owner_payload = json.dumps(
                    {"pid": os.getpid(), "token": self.owner_token},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                candidate = _prepare_private_atomic_write(
                    self.lock_dir, owner_payload, deadline=deadline
                )
                try:
                    with _PROCESS_ARTIFACT_LOCK_TOKENS_LOCK:
                        _publish_artifact_lock_candidate(candidate, self.lock_dir)
                        _PROCESS_ARTIFACT_LOCK_TOKENS[key] = self.owner_token
                except Exception:
                    raise
                finally:
                    _discard_prepared_atomic_write(candidate)
                    candidate = None
                _HELD_ARTIFACT_LOCKS.set(held | {key})
                return
            except FileExistsError:
                _discard_prepared_atomic_write(candidate)
                legacy_directory = self.lock_dir.is_dir()
                retired = False
                if not legacy_directory:
                    try:
                        with _locked_artifact_lock_generation(
                            self.lock_dir, deadline=deadline
                        ) as (owner_handle, owner_details, owner_payload):
                            try:
                                owner_pid, owner_token = _artifact_lock_owner(
                                    owner_payload
                                )
                            except (KeyError, TypeError, ValueError):
                                owner_pid, owner_token = None, None
                            with _PROCESS_ARTIFACT_LOCK_TOKENS_LOCK:
                                active_local_token = (
                                    _PROCESS_ARTIFACT_LOCK_TOKENS.get(key)
                                )
                            abandoned = (
                                owner_pid is not None and not pid_alive(owner_pid)
                            )
                            if owner_pid == os.getpid():
                                abandoned = (
                                    not owner_token
                                    or active_local_token != owner_token
                                )
                            if owner_pid is None:
                                abandoned = (
                                    time.time()
                                    - os.fstat(owner_handle.fileno()).st_mtime
                                    > 60
                                )
                            generation = _artifact_lock_file_identity(
                                owner_details
                            )
                            if abandoned and _artifact_lock_path_matches_generation(
                                self.lock_dir, generation
                            ):
                                retired = _retire_artifact_lock_file_generation(
                                    self.lock_dir, uuid.uuid4().hex, generation
                                )
                    except (FileNotFoundError, OSError, OrchestratorError):
                        retired = False
                else:
                    owner_token = None
                    try:
                        with _locked_legacy_artifact_lock_generation(
                            self.lock_dir, deadline=deadline
                        ) as (
                            directory_handle,
                            directory_details,
                            owner_payload,
                        ):
                            owner_pid, owner_token = _artifact_lock_owner(
                                owner_payload
                            )
                            with _PROCESS_ARTIFACT_LOCK_TOKENS_LOCK:
                                active_local_token = (
                                    _PROCESS_ARTIFACT_LOCK_TOKENS.get(key)
                                )
                            abandoned = (
                                owner_pid is not None and not pid_alive(owner_pid)
                            )
                            if owner_pid == os.getpid():
                                abandoned = (
                                    not owner_token
                                    or active_local_token != owner_token
                                )
                            generation = _artifact_lock_directory_identity(
                                directory_details
                            )
                            if (
                                abandoned
                                and _artifact_lock_directory_path_matches_generation(
                                    self.lock_dir, generation
                                )
                            ):
                                retired = _retire_artifact_lock_directory(
                                    self.lock_dir,
                                    uuid.uuid4().hex,
                                    generation,
                                    directory_handle,
                                )
                    except (
                        FileNotFoundError,
                        OSError,
                        OrchestratorError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ):
                        owner_pid = None
                        try:
                            generation = _claim_ownerless_legacy_artifact_lock(
                                self.lock_dir, deadline=deadline
                            )
                            if generation is not None:
                                # Re-enter through the owner-file claim so the
                                # exact claimed generation stays locked until
                                # retirement on POSIX.
                                retired = True
                        except (OSError, OrchestratorError):
                            retired = False
                if retired:
                    continue
                if time.monotonic() >= deadline:
                    raise OrchestratorError(
                        f"Timed out acquiring artifact lock for run: {self.run_dir.name}"
                    )
                time.sleep(0.005)
            except OSError as exc:
                if (
                    os.name == "nt"
                    and getattr(exc, "winerror", None) in {5, 32, 183}
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.005)
                    continue
                raise OrchestratorError(
                    f"Could not acquire artifact lock for run: {self.run_dir.name}"
                ) from exc

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if self.reentrant:
            return False
        try:
            released = False
            release_error: OSError | None = None
            for _attempt in range(100):
                try:
                    owner_pid, owner_token = _artifact_lock_owner(
                        _read_bounded_regular_file(
                            self.lock_dir, 256, deadline=self.deadline
                        )
                    )
                    if owner_pid != os.getpid() or owner_token != self.owner_token:
                        raise OrchestratorError(
                            f"Artifact lock ownership changed for run: {self.run_dir.name}"
                        )
                    self.lock_dir.unlink(missing_ok=True)
                    released = True
                    break
                except FileNotFoundError:
                    released = not self.lock_dir.exists()
                    if released:
                        break
                except OSError as exc:
                    release_error = exc
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    break
                time.sleep(0.005)
            if not released:
                raise OrchestratorError(
                    f"Could not release artifact lock for run: {self.run_dir.name}"
                ) from release_error
        finally:
            key = str(self.run_dir)
            with _PROCESS_ARTIFACT_LOCK_TOKENS_LOCK:
                if _PROCESS_ARTIFACT_LOCK_TOKENS.get(key) == self.owner_token:
                    _PROCESS_ARTIFACT_LOCK_TOKENS.pop(key, None)
            held = _HELD_ARTIFACT_LOCKS.get()
            _HELD_ARTIFACT_LOCKS.set(held - {key})
        return False


def artifact_lock(
    run_dir: Path,
    timeout_seconds: float = 10.0,
    *,
    deadline: float | None = None,
) -> _ArtifactLock:
    """Serialize controller/worker writes for one run across processes."""
    return _ArtifactLock(run_dir, timeout_seconds, deadline)


MAX_MANAGED_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_MANAGED_ARTIFACT_FILES = 10_000
EVENT_RECOVERY_TAIL_BYTES = 4 * 1024 * 1024
_WINDOWS_REPARSE_POINT = 0x400
_PREPARED_ATOMIC_PARENTS: dict[str, tuple[str, Any, Any]] = {}
_PREPARED_ATOMIC_PARENTS_LOCK = threading.Lock()


def _posix_fd_digest(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise OrchestratorError(
                "Retained artifact source ended before its recorded size."
            )
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _publish_posix_retained_source(
    anchor: tuple[Any, ...], destination_name: str
) -> int:
    """Publish an absent POSIX name from the retained source FD, never its path."""
    import ctypes

    directory_fd = int(anchor[1])
    source_fd = int(anchor[4].fileno())
    expected_identity = anchor[5]
    source = os.fstat(source_fd)
    if (
        not stat.S_ISREG(source.st_mode)
        or (int(source.st_dev), int(source.st_ino)) != expected_identity
        or int(source.st_size) > MAX_MANAGED_ARTIFACT_BYTES
    ):
        raise OrchestratorError("Retained artifact source capability changed.")

    libc = ctypes.CDLL(None, use_errno=True)
    published = False
    if sys.platform.startswith("linux"):
        linkat = getattr(libc, "linkat", None)
        if linkat is None:
            raise OrchestratorError(
                "FD-bound Linux artifact publication is unavailable."
            )
        try:
            linkat.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
            )
            linkat.restype = ctypes.c_int
        except AttributeError:
            pass
        destination = ctypes.c_char_p(os.fsencode(destination_name))
        ctypes.set_errno(0)
        result = linkat(
            source_fd,
            ctypes.c_char_p(b""),
            directory_fd,
            destination,
            0x1000,
        )
        if result != 0:
            error = ctypes.get_errno()
            fallback_errors = {
                errno.EPERM,
                errno.ENOENT,
                errno.EINVAL,
                errno.ENOSYS,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }
            if error not in fallback_errors:
                if error == errno.EEXIST:
                    raise FileExistsError(
                        error, os.strerror(error), destination_name
                    )
                raise OSError(error, os.strerror(error), destination_name)
            ctypes.set_errno(0)
            result = linkat(
                -100,
                ctypes.c_char_p(
                    os.fsencode(f"/proc/self/fd/{source_fd}")
                ),
                directory_fd,
                destination,
                0x400,
            )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError(
                    error, os.strerror(error), destination_name
                )
            raise OrchestratorError(
                "FD-bound Linux artifact publication failed."
            ) from OSError(error, os.strerror(error), destination_name)
        published = True
    elif sys.platform == "darwin":
        clone = getattr(libc, "fclonefileat", None)
        if clone is None:
            raise OrchestratorError(
                "FD-bound macOS artifact publication is unavailable."
            )
        try:
            clone.argtypes = (
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
            )
            clone.restype = ctypes.c_int
        except AttributeError:
            pass
        ctypes.set_errno(0)
        if clone(
            source_fd,
            directory_fd,
            ctypes.c_char_p(os.fsencode(destination_name)),
            0,
        ) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError(
                    error, os.strerror(error), destination_name
                )
            raise OrchestratorError(
                "FD-bound macOS artifact publication failed."
            ) from OSError(error, os.strerror(error), destination_name)
        published = True
    else:
        raise OrchestratorError(
            "FD-bound artifact publication is unsupported on this POSIX platform."
        )

    if not published:
        raise OrchestratorError("POSIX artifact publication failed closed.")
    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    open_flags |= getattr(os, "O_CLOEXEC", 0)
    published_fd = os.open(
        destination_name, open_flags, dir_fd=directory_fd
    )
    published_details = os.fstat(published_fd)
    published_key = (
        int(published_details.st_dev),
        int(published_details.st_ino),
    )
    try:
        if (
            not stat.S_ISREG(published_details.st_mode)
            or int(published_details.st_size) != int(source.st_size)
            or _posix_fd_digest(published_fd, int(published_details.st_size))
            != _posix_fd_digest(source_fd, int(source.st_size))
        ):
            raise OrchestratorError(
                "Published artifact does not match its retained source."
            )
        os.fsync(directory_fd)
        return published_fd
    except Exception:
        os.close(published_fd)
        try:
            current = os.stat(
                destination_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (int(current.st_dev), int(current.st_ino)) == published_key:
                os.unlink(destination_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except (FileNotFoundError, OSError):
            pass
        raise


def _exchange_posix_names(
    directory_fd: int, first_name: str, second_name: str
) -> None:
    """Atomically swap two existing names within one retained directory."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    first = ctypes.c_char_p(os.fsencode(first_name))
    second = ctypes.c_char_p(os.fsencode(second_name))
    if sys.platform.startswith("linux"):
        exchange = getattr(libc, "renameat2", None)
        if exchange is None:
            raise OrchestratorError(
                "Atomic Linux generation exchange is unavailable."
            )
        try:
            exchange.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            exchange.restype = ctypes.c_int
        except AttributeError:
            pass
        ctypes.set_errno(0)
        result = exchange(
            directory_fd, first, directory_fd, second, 0x2
        )
    elif sys.platform == "darwin":
        exchange = getattr(libc, "renameatx_np", None)
        if exchange is None:
            raise OrchestratorError(
                "Atomic macOS generation exchange is unavailable."
            )
        try:
            exchange.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            exchange.restype = ctypes.c_int
        except AttributeError:
            pass
        ctypes.set_errno(0)
        result = exchange(
            directory_fd, first, directory_fd, second, 0x2
        )
    else:
        raise OrchestratorError(
            "Atomic generation exchange is unsupported on this POSIX platform."
        )
    if result != 0:
        error = ctypes.get_errno()
        raise OrchestratorError(
            "Atomic artifact generation exchange failed."
        ) from OSError(error, os.strerror(error))


def _lstat_managed_path(path: Path, *, is_dir: bool) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as exc:
        raise OrchestratorError(f"Managed artifact is unavailable: {path.name}") from exc
    attributes = int(getattr(details, "st_file_attributes", 0) or 0)
    if stat.S_ISLNK(details.st_mode) or attributes & _WINDOWS_REPARSE_POINT:
        raise OrchestratorError(
            f"Managed artifact links and reparse points are forbidden: {path.name}"
        )
    expected = stat.S_ISDIR(details.st_mode) if is_dir else stat.S_ISREG(details.st_mode)
    if not expected:
        kind = "directory" if is_dir else "regular file"
        raise OrchestratorError(f"Managed artifact is not a {kind}: {path.name}")
    if not is_dir and details.st_size > MAX_MANAGED_ARTIFACT_BYTES:
        raise OrchestratorError(f"Managed artifact exceeds its size limit: {path.name}")
    return details


def _windows_security_apis() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    advapi32.GetSecurityInfo.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    return ctypes, advapi32, kernel32


def _windows_sid_text(ctypes: Any, advapi32: Any, kernel32: Any, sid: Any) -> str:
    from ctypes import wintypes

    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise OSError(ctypes.get_last_error(), "Could not render a Windows SID")
    try:
        return str(text.value)
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _windows_current_user_sid(
    ctypes: Any, advapi32: Any, kernel32: Any
) -> str:
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise OSError(ctypes.get_last_error(), "Could not open the process token")
    try:
        required = ctypes.c_uint32()
        advapi32.GetTokenInformation(
            token, 1, None, 0, ctypes.byref(required)
        )
        if required.value == 0:
            raise OSError(
                ctypes.get_last_error(), "Could not size the process token user"
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(
                ctypes.get_last_error(), "Could not read the process token user"
            )
        sid = ctypes.c_void_p.from_buffer(buffer).value
        if not sid:
            raise OrchestratorError("The process token has no user SID.")
        return _windows_sid_text(
            ctypes, advapi32, kernel32, ctypes.c_void_p(sid)
        )
    finally:
        kernel32.CloseHandle(token)


def _inspect_windows_private_acl(path: Path, *, is_dir: bool) -> dict[str, Any]:
    if os.name != "nt":
        raise OrchestratorError("Windows ACL inspection is unavailable on this platform.")
    _lstat_managed_path(path, is_dir=is_dir)
    ctypes, advapi32, kernel32 = _windows_security_apis()
    from ctypes import wintypes

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise OSError(result, f"Could not inspect the Windows ACL for {path.name}")
    try:
        owner_sid = _windows_sid_text(
            ctypes, advapi32, kernel32, owner
        )
        current_user_sid = _windows_current_user_sid(
            ctypes, advapi32, kernel32
        )
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise OSError(ctypes.get_last_error(), "Could not inspect DACL control")

        class AclSizeInformation(ctypes.Structure):
            _fields_ = (
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            )

        info = AclSizeInformation()
        if not dacl or not advapi32.GetAclInformation(
            dacl, ctypes.byref(info), ctypes.sizeof(info), 2
        ):
            raise OSError(ctypes.get_last_error(), "Could not inspect DACL entries")
        entries: list[dict[str, Any]] = []
        for index in range(int(info.AceCount)):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "Could not inspect a DACL entry")
            address = int(ace.value)
            ace_type = ctypes.c_ubyte.from_address(address).value
            ace_flags = ctypes.c_ubyte.from_address(address + 1).value
            mask = ctypes.c_uint32.from_address(address + 4).value
            sid = ctypes.c_void_p(address + 8)
            entries.append(
                {
                    "type": ace_type,
                    "flags": ace_flags,
                    "mask": mask,
                    "sid": _windows_sid_text(
                        ctypes, advapi32, kernel32, sid
                    ),
                }
            )
        expected_flags = 0x03 if is_dir else 0
        exact = bool(control.value & 0x1000) and entries == [
            {
                "type": 0,
                "flags": expected_flags,
                "mask": 0x001F01FF,
                "sid": current_user_sid,
            }
        ]
        return {
            "protected": bool(control.value & 0x1000),
            "owner_sid": owner_sid,
            "current_user_sid": current_user_sid,
            "ace_sids": [str(entry["sid"]) for entry in entries],
            "has_inherited_aces": any(
                int(entry["flags"]) & 0x10 for entry in entries
            ),
            "entries": entries,
            "exact": exact,
        }
    finally:
        kernel32.LocalFree(descriptor)


def _inspect_windows_private_acl_handle(
    native_handle: Any, *, is_dir: bool
) -> dict[str, Any]:
    ctypes, advapi32, kernel32 = _windows_security_apis()
    from ctypes import wintypes

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        native_handle,
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise OSError(result, "Could not inspect the Windows artifact ACL")
    try:
        owner_sid = _windows_sid_text(ctypes, advapi32, kernel32, owner)
        current_user_sid = _windows_current_user_sid(ctypes, advapi32, kernel32)
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise OSError(ctypes.get_last_error(), "Could not inspect DACL control")

        class AclSizeInformation(ctypes.Structure):
            _fields_ = (
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            )

        info = AclSizeInformation()
        if not dacl or not advapi32.GetAclInformation(
            dacl, ctypes.byref(info), ctypes.sizeof(info), 2
        ):
            raise OSError(ctypes.get_last_error(), "Could not inspect DACL entries")
        entries: list[dict[str, Any]] = []
        for index in range(int(info.AceCount)):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "Could not inspect a DACL entry")
            address = int(ace.value)
            entries.append(
                {
                    "type": ctypes.c_ubyte.from_address(address).value,
                    "flags": ctypes.c_ubyte.from_address(address + 1).value,
                    "mask": ctypes.c_uint32.from_address(address + 4).value,
                    "sid": _windows_sid_text(
                        ctypes,
                        advapi32,
                        kernel32,
                        ctypes.c_void_p(address + 8),
                    ),
                }
            )
        expected_flags = 0x03 if is_dir else 0
        exact = bool(control.value & 0x1000) and entries == [
            {
                "type": 0,
                "flags": expected_flags,
                "mask": 0x001F01FF,
                "sid": current_user_sid,
            }
        ]
        return {
            "protected": bool(control.value & 0x1000),
            "owner_sid": owner_sid,
            "current_user_sid": current_user_sid,
            "ace_sids": [str(entry["sid"]) for entry in entries],
            "has_inherited_aces": any(
                int(entry["flags"]) & 0x10 for entry in entries
            ),
            "entries": entries,
            "exact": exact,
        }
    finally:
        kernel32.LocalFree(descriptor)


def _enforce_windows_private_acl_handle(
    native_handle: Any, *, is_dir: bool
) -> None:
    ctypes, advapi32, kernel32 = _windows_security_apis()
    current_user_sid = _windows_current_user_sid(ctypes, advapi32, kernel32)
    flags = "OICI" if is_dir else ""
    descriptor = ctypes.c_void_p()
    size = ctypes.c_uint32()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:P(A;{flags};FA;;;{current_user_sid})",
        1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    ):
        raise OrchestratorError("Could not construct a private Windows ACL.")
    try:
        present = ctypes.c_int()
        defaulted = ctypes.c_int()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ) or not present.value:
            raise OrchestratorError("Could not read the private Windows DACL.")
        result = advapi32.SetSecurityInfo(
            native_handle,
            1,
            0x00000004 | 0x80000000,
            None,
            None,
            dacl,
            None,
        )
        if result != 0:
            raise OSError(result, "Could not enforce the private Windows ACL")
    finally:
        kernel32.LocalFree(descriptor)
    if not _inspect_windows_private_acl_handle(
        native_handle, is_dir=is_dir
    )["exact"]:
        raise OrchestratorError("Private Windows ACL verification failed.")


def _enforce_windows_private_acl(path: Path, *, is_dir: bool) -> None:
    _lstat_managed_path(path, is_dir=is_dir)
    ctypes, advapi32, kernel32 = _windows_security_apis()
    current_user_sid = _windows_current_user_sid(
        ctypes, advapi32, kernel32
    )
    flags = "OICI" if is_dir else ""
    sddl = f"D:P(A;{flags};FA;;;{current_user_sid})"
    descriptor = ctypes.c_void_p()
    size = ctypes.c_uint32()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise OrchestratorError(
            f"Could not construct a private Windows ACL for {path.name}."
        )
    try:
        if not advapi32.SetFileSecurityW(str(path), 0x00000004, descriptor):
            raise OrchestratorError(
                f"Could not enforce a private Windows ACL for {path.name}."
            )
    finally:
        kernel32.LocalFree(descriptor)
    if not _inspect_windows_private_acl(path, is_dir=is_dir)["exact"]:
        raise OrchestratorError(
            f"Private Windows ACL verification failed for {path.name}."
        )


def _open_windows_relative_native_handle(
    parent_handle: Any,
    name: str,
    *,
    writable: bool,
    is_dir: bool,
    create: bool = False,
) -> Any:
    if os.name != "nt":
        raise OrchestratorError("Windows relative handles are unavailable.")
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        )

    class ObjectAttributes(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p),
            ("SecurityQualityOfService", ctypes.c_void_p),
        )

    class IoStatusBlock(ctypes.Structure):
        _fields_ = (("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t))

    encoded_name = name.encode("utf-16-le")
    name_buffer = ctypes.create_unicode_buffer(name)
    unicode_name = UnicodeString(
        len(encoded_name),
        len(encoded_name) + 2,
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes),
        parent_handle,
        ctypes.pointer(unicode_name),
        0x40,
        None,
        None,
    )
    desired_access = 0x80000000 | 0x00020000 | 0x00100000
    if writable:
        desired_access |= 0x40000000 | 0x00040000 | 0x00010000
    options = 0x00000020 | 0x00200000
    options |= 0x00000001 if is_dir else 0x00000040
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtCreateFile.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    ntdll.NtCreateFile.restype = ctypes.c_long
    ntdll.RtlNtStatusToDosError.argtypes = (ctypes.c_long,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    opened = wintypes.HANDLE()
    io_status = IoStatusBlock()
    status = ntdll.NtCreateFile(
        ctypes.byref(opened),
        desired_access,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0x80 if create else 0,
        0x00000001 | 0x00000002 | 0x00000004,
        2 if create else 1,
        options,
        None,
        0,
    )
    if status < 0:
        error = int(ntdll.RtlNtStatusToDosError(status))
        if error in {2, 3}:
            raise FileNotFoundError(error, "Managed artifact is unavailable", name)
        if error in {80, 183}:
            raise FileExistsError(error, "Managed artifact already exists", name)
        raise ctypes.WinError(error)
    return opened.value


def _windows_list_directory_handle(native_handle: Any) -> list[str]:
    if os.name != "nt":
        raise OrchestratorError("Windows handle enumeration is unavailable.")
    import ctypes
    from ctypes import wintypes

    class FileIdBothDirectoryInfo(ctypes.Structure):
        _fields_ = (
            ("NextEntryOffset", wintypes.DWORD),
            ("FileIndex", wintypes.DWORD),
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("AllocationSize", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
            ("FileNameLength", wintypes.DWORD),
            ("EaSize", wintypes.DWORD),
            ("ShortNameLength", ctypes.c_ubyte),
            ("ShortName", wintypes.WCHAR * 12),
            ("FileId", ctypes.c_longlong),
            ("FileName", wintypes.WCHAR * 1),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    names: list[str] = []
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        if not kernel32.GetFileInformationByHandleEx(
            native_handle, 10, buffer, len(buffer)
        ):
            error = ctypes.get_last_error()
            if error == 18:
                break
            raise ctypes.WinError(error)
        offset = 0
        while True:
            address = ctypes.addressof(buffer) + offset
            entry = FileIdBothDirectoryInfo.from_address(address)
            name = ctypes.wstring_at(
                address + FileIdBothDirectoryInfo.FileName.offset,
                int(entry.FileNameLength) // 2,
            )
            if name not in {".", ".."}:
                names.append(name)
            if entry.NextEntryOffset == 0:
                break
            offset += int(entry.NextEntryOffset)
    return names


@contextlib.contextmanager
def _open_windows_managed_file(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    if os.name != "nt":
        raise OrchestratorError("Windows managed-file handles are unavailable.")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ByHandleFileInformation),
    )
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = (
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    desired_access = 0x80000000 | 0x00020000
    if writable:
        desired_access |= 0x40000000 | 0x00040000 | 0x00010000
    parent_context = _open_windows_managed_directory(
        path.parent, verify_private=False
    )
    _parent_handle, parent_details = parent_context.__enter__()
    native_handle = None
    invalid_handle = ctypes.c_void_p(-1).value
    file_handle: Any | None = None
    try:
        native_handle = _open_windows_relative_native_handle(
            _parent_handle,
            path.name,
            writable=writable,
            is_dir=False,
        )
        if native_handle in {None, invalid_handle}:
            raise ctypes.WinError(ctypes.get_last_error())
        information = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            native_handle, ctypes.byref(information)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = int(information.dwFileAttributes)
        size = (int(information.nFileSizeHigh) << 32) | int(
            information.nFileSizeLow
        )
        if attributes & _WINDOWS_REPARSE_POINT:
            raise OrchestratorError(
                f"Managed artifact links and reparse points are forbidden: {path.name}"
            )
        if attributes & 0x10:
            raise OrchestratorError(
                f"Managed artifact is not a regular file: {path.name}"
            )
        if size > MAX_MANAGED_ARTIFACT_BYTES:
            raise OrchestratorError(
                f"Managed artifact exceeds its size limit: {path.name}"
            )
        if writable:
            _enforce_windows_private_acl_handle(native_handle, is_dir=False)
        elif verify_private and not _inspect_windows_private_acl_handle(
            native_handle, is_dir=False
        )["exact"]:
            raise OrchestratorError(
                f"Private Windows ACL verification failed for {path.name}."
            )
        final_buffer = ctypes.create_unicode_buffer(32768)
        final_length = kernel32.GetFinalPathNameByHandleW(
            native_handle, final_buffer, len(final_buffer), 0
        )
        if not final_length or final_length >= len(final_buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        final_path = final_buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        with _open_windows_managed_directory(
            path.parent, verify_private=False
        ) as (_current_parent, current_parent_details):
            if current_parent_details["file_id"] != parent_details["file_id"]:
                raise OrchestratorError(
                    f"Managed artifact ancestor changed after file open: {path.name}"
                )
        flags = os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY)
        fd = msvcrt.open_osfhandle(int(native_handle), flags)
        native_handle = None
        file_handle = os.fdopen(fd, "r+b" if writable else "rb")
        yield file_handle, {
            "size": size,
            "attributes": attributes,
            "final_path": final_path,
            "file_id": (
                int(information.dwVolumeSerialNumber),
                (int(information.nFileIndexHigh) << 32)
                | int(information.nFileIndexLow),
            ),
        }
    finally:
        if file_handle is not None:
            file_handle.close()
        elif native_handle not in {None, invalid_handle}:
            kernel32.CloseHandle(native_handle)
        parent_context.__exit__(None, None, None)


@contextlib.contextmanager
def _open_windows_managed_directory(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    if os.name != "nt":
        raise OrchestratorError("Windows managed-directory handles are unavailable.")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ByHandleFileInformation),
    )
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = (
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    desired_access = 0x80000000 | 0x00020000
    if writable:
        desired_access |= 0x00040000 | 0x00010000
    native_handle = kernel32.CreateFileW(
        str(path),
        desired_access,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if native_handle in {None, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            native_handle, ctypes.byref(information)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = int(information.dwFileAttributes)
        if attributes & _WINDOWS_REPARSE_POINT:
            raise OrchestratorError(
                f"Managed artifact links and reparse points are forbidden: {path.name}"
            )
        if not attributes & 0x10:
            raise OrchestratorError(
                f"Managed artifact is not a directory: {path.name}"
            )
        if writable:
            _enforce_windows_private_acl_handle(native_handle, is_dir=True)
        elif verify_private and not _inspect_windows_private_acl_handle(
            native_handle, is_dir=True
        )["exact"]:
            raise OrchestratorError(
                f"Private Windows ACL verification failed for {path.name}."
            )
        final_buffer = ctypes.create_unicode_buffer(32768)
        final_length = kernel32.GetFinalPathNameByHandleW(
            native_handle, final_buffer, len(final_buffer), 0
        )
        if not final_length or final_length >= len(final_buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        final_path = final_buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        if os.path.normcase(os.path.abspath(final_path)) != os.path.normcase(
            os.path.abspath(path)
        ):
            raise OrchestratorError(
                f"Managed artifact ancestor changed after directory open: {path.name}"
            )
        yield native_handle, {
            "attributes": attributes,
            "final_path": final_path,
            "file_id": (
                int(information.dwVolumeSerialNumber),
                (int(information.nFileIndexHigh) << 32)
                | int(information.nFileIndexLow),
            ),
        }
    finally:
        kernel32.CloseHandle(native_handle)


def _open_posix_directory_fd(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    anchor = Path(absolute.anchor)
    fd = os.open(str(anchor), flags)
    try:
        for part in absolute.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            details = os.fstat(next_fd)
            if not stat.S_ISDIR(details.st_mode):
                os.close(next_fd)
                raise OrchestratorError(
                    f"Managed artifact is not a directory: {part}"
                )
            os.close(fd)
            fd = next_fd
        return fd
    except OSError as exc:
        os.close(fd)
        if exc.errno == errno.ELOOP:
            raise OrchestratorError(
                f"Managed artifact links are forbidden: {path.name}"
            ) from exc
        raise
    except Exception:
        os.close(fd)
        raise


@contextlib.contextmanager
def _open_posix_managed_directory(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    fd: int | None = None
    try:
        fd = _open_posix_directory_fd(path)
        if writable:
            os.fchmod(fd, 0o700)
        details = os.fstat(fd)
        if not stat.S_ISDIR(details.st_mode):
            raise OrchestratorError(
                f"Managed artifact is not a directory: {path.name}"
            )
        if verify_private and stat.S_IMODE(details.st_mode) != 0o700:
            raise OrchestratorError(
                f"Private artifact mode is invalid: {path.name}"
            )
        yield fd, details
    finally:
        if fd is not None:
            os.close(fd)


@contextlib.contextmanager
def _open_posix_managed_file(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    directory_fd = _open_posix_directory_fd(path.parent)
    fd: int | None = None
    file_handle: Any | None = None
    try:
        flags = os.O_RDWR if writable else os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path.name, flags, dir_fd=directory_fd)
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise OrchestratorError(
                f"Managed artifact is not a regular file: {path.name}"
            )
        if details.st_size > MAX_MANAGED_ARTIFACT_BYTES:
            raise OrchestratorError(
                f"Managed artifact exceeds its size limit: {path.name}"
            )
        if writable:
            os.fchmod(fd, 0o600)
            details = os.fstat(fd)
        if verify_private and stat.S_IMODE(details.st_mode) != 0o600:
            raise OrchestratorError(f"Private artifact mode is invalid: {path.name}")
        file_handle = os.fdopen(fd, "r+b" if writable else "rb")
        fd = None
        yield file_handle, details
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise OrchestratorError(
                f"Managed artifact links are forbidden: {path.name}"
            ) from exc
        raise
    finally:
        if file_handle is not None:
            file_handle.close()
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)


def _open_managed_file(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    opener = _open_windows_managed_file if os.name == "nt" else _open_posix_managed_file
    return opener(path, writable=writable, verify_private=verify_private)


def _open_managed_directory(
    path: Path, *, writable: bool = False, verify_private: bool = True
) -> Any:
    opener = (
        _open_windows_managed_directory
        if os.name == "nt"
        else _open_posix_managed_directory
    )
    return opener(path, writable=writable, verify_private=verify_private)


def _read_bounded_regular_file(
    path: Path,
    limit: int,
    *,
    deadline: float | None = None,
) -> bytes:
    _check_deadline(deadline)
    with _open_managed_file(path, verify_private=False) as (handle, _details):
        payload = handle.read(limit + 1)
        _check_deadline(deadline)
    if len(payload) > limit:
        raise OrchestratorError(f"Managed file exceeds its size limit: {path.name}")
    return payload


def _verify_private_path(path: Path, *, is_dir: bool = False) -> None:
    if not is_dir:
        with _open_managed_file(path, verify_private=True):
            return
    with _open_managed_directory(path, verify_private=True):
        return


def _set_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _open_managed_directory(
        path, writable=True, verify_private=False
    ):
        pass
    _verify_private_path(path, is_dir=True)


def _set_private_file(path: Path) -> None:
    with _open_managed_file(path, writable=True, verify_private=False):
        return


def _unlink_managed_file(path: Path) -> None:
    try:
        if os.name == "nt":
            with _open_windows_managed_directory(
                path.parent, verify_private=False
            ) as (parent_handle, _details):
                with _open_windows_relative_managed_file(
                    parent_handle,
                    path.name,
                    writable=True,
                    verify_private=False,
                ) as (file_handle, _file_details):
                    _windows_delete_retained_file(file_handle)
        else:
            directory_fd = _open_posix_directory_fd(path.parent)
            try:
                details = os.stat(
                    path.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if not stat.S_ISREG(details.st_mode):
                    raise OrchestratorError(
                        f"Managed artifact is not a regular file: {path.name}"
                    )
                os.unlink(path.name, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
    except FileNotFoundError:
        return


def _secure_private_writable_handle(handle: Any, path: Path) -> None:
    if os.name == "nt":
        import msvcrt

        native_handle = msvcrt.get_osfhandle(handle.fileno())
        _enforce_windows_private_acl_handle(native_handle, is_dir=False)
        if not _inspect_windows_private_acl_handle(
            native_handle, is_dir=False
        )["exact"]:
            raise OrchestratorError(
                f"Private Windows ACL verification failed for {path.name}."
            )
    else:
        os.fchmod(handle.fileno(), 0o600)
        if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600:
            raise OrchestratorError(
                f"Private artifact mode is invalid: {path.name}"
            )


@contextlib.contextmanager
def _create_windows_private_file(
    path: Path, *, parent_handle: Any | None = None
) -> Any:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    native_handle = (
        _open_windows_relative_native_handle(
            parent_handle,
            path.name,
            writable=True,
            is_dir=False,
            create=True,
        )
        if parent_handle is not None
        else kernel32.CreateFileW(
            str(path),
            0x80000000 | 0x40000000 | 0x00020000 | 0x00040000,
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            1,
            0x00200000,
            None,
        )
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if native_handle in {None, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())
    file_handle: Any | None = None
    try:
        _enforce_windows_private_acl_handle(native_handle, is_dir=False)
        fd = msvcrt.open_osfhandle(int(native_handle), os.O_RDWR | os.O_BINARY)
        native_handle = None
        file_handle = os.fdopen(fd, "w+b")
        yield file_handle
    finally:
        if file_handle is not None:
            file_handle.close()
        elif native_handle not in {None, invalid_handle}:
            kernel32.CloseHandle(native_handle)


def _windows_relative_handle_details(native_handle: Any, name: str) -> dict[str, Any]:
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(
        native_handle, ctypes.byref(information)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = int(information.dwFileAttributes)
    if attributes & _WINDOWS_REPARSE_POINT:
        raise OrchestratorError(
            f"Managed artifact links and reparse points are forbidden: {name}"
        )
    return {
        "attributes": attributes,
        "size": (int(information.nFileSizeHigh) << 32)
        | int(information.nFileSizeLow),
        "file_id": (
            int(information.dwVolumeSerialNumber),
            (int(information.nFileIndexHigh) << 32)
            | int(information.nFileIndexLow),
        ),
    }


@contextlib.contextmanager
def _open_windows_relative_managed_directory(
    parent_handle: Any,
    name: str,
    *,
    writable: bool = False,
    verify_private: bool = False,
) -> Any:
    import ctypes
    from ctypes import wintypes

    native_handle = _open_windows_relative_native_handle(
        parent_handle, name, writable=writable, is_dir=True
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        details = _windows_relative_handle_details(native_handle, name)
        if not details["attributes"] & 0x10:
            raise OrchestratorError(
                f"Managed artifact is not a directory: {name}"
            )
        if writable:
            _enforce_windows_private_acl_handle(native_handle, is_dir=True)
        elif verify_private and not _inspect_windows_private_acl_handle(
            native_handle, is_dir=True
        )["exact"]:
            raise OrchestratorError(
                f"Private Windows ACL verification failed for {name}."
            )
        yield native_handle, details
    finally:
        kernel32.CloseHandle(native_handle)


@contextlib.contextmanager
def _open_windows_relative_managed_file(
    parent_handle: Any,
    name: str,
    *,
    writable: bool = False,
    verify_private: bool = False,
) -> Any:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    native_handle = _open_windows_relative_native_handle(
        parent_handle, name, writable=writable, is_dir=False
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    file_handle: Any | None = None
    try:
        details = _windows_relative_handle_details(native_handle, name)
        if details["attributes"] & 0x10:
            raise OrchestratorError(
                f"Managed artifact is not a regular file: {name}"
            )
        if details["size"] > MAX_MANAGED_ARTIFACT_BYTES:
            raise OrchestratorError(
                f"Managed artifact exceeds its size limit: {name}"
            )
        if writable:
            _enforce_windows_private_acl_handle(native_handle, is_dir=False)
        elif verify_private and not _inspect_windows_private_acl_handle(
            native_handle, is_dir=False
        )["exact"]:
            raise OrchestratorError(
                f"Private Windows ACL verification failed for {name}."
            )
        flags = os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY)
        fd = msvcrt.open_osfhandle(int(native_handle), flags)
        native_handle = None
        file_handle = os.fdopen(fd, "r+b" if writable else "rb")
        yield file_handle, details
    finally:
        if file_handle is not None:
            file_handle.close()
        elif native_handle is not None:
            kernel32.CloseHandle(native_handle)


def _walk_windows_managed_artifacts(
    run_dir: Path,
    *,
    writable: bool = False,
    file_action: Any | None = None,
) -> list[tuple[Path, bool]]:
    entries: list[tuple[Path, bool]] = []
    count = 0

    # Keep the prior post-validation swap regression active, then retain the
    # second capability for the complete traversal.
    with _open_windows_managed_directory(run_dir, verify_private=False):
        pass

    def visit(directory_handle: Any, display_dir: Path) -> None:
        nonlocal count
        for name in _windows_list_directory_handle(directory_handle):
            display_path = display_dir / name
            try:
                directory_context = _open_windows_relative_managed_directory(
                    directory_handle,
                    name,
                    writable=writable,
                    verify_private=not writable,
                )
                child_handle, _details = directory_context.__enter__()
            except OSError:
                directory_context = None
            if directory_context is not None:
                try:
                    entries.append((display_path, True))
                    visit(child_handle, display_path)
                finally:
                    directory_context.__exit__(None, None, None)
                continue
            count += 1
            if count > MAX_MANAGED_ARTIFACT_FILES:
                raise OrchestratorError(
                    "Managed artifact file-count limit exceeded."
                )
            with _open_windows_relative_managed_file(
                directory_handle,
                name,
                writable=writable,
                verify_private=not writable,
            ) as (file_handle, details):
                entries.append((display_path, False))
                if file_action is not None:
                    file_action(display_path, file_handle, details)

    with _open_windows_managed_directory(
        run_dir, writable=writable, verify_private=not writable
    ) as (root_handle, root_details):
        visit(root_handle, Path(str(root_details["final_path"])))
    return entries


def _iter_managed_artifacts(run_dir: Path) -> list[tuple[Path, bool]]:
    if os.name == "nt":
        return _walk_windows_managed_artifacts(run_dir)
    entries: list[tuple[Path, bool]] = []
    count = 0

    def visit(directory: Path) -> None:
        nonlocal count
        with _open_managed_directory(directory, verify_private=False) as (
            handle,
            directory_details,
        ):
            bound_directory = directory
            names = os.listdir(handle)
            for name in names:
                path = bound_directory / name
                details = os.stat(
                    name, dir_fd=handle, follow_symlinks=False
                )
                attributes = int(
                    getattr(details, "st_file_attributes", 0) or 0
                )
                if stat.S_ISLNK(details.st_mode) or attributes & _WINDOWS_REPARSE_POINT:
                    raise OrchestratorError(
                        f"Managed artifact links and reparse points are forbidden: {name}"
                    )
                is_dir = stat.S_ISDIR(details.st_mode)
                is_file = stat.S_ISREG(details.st_mode)
                if is_dir:
                    with _open_managed_directory(path, verify_private=False):
                        pass
                    entries.append((path, True))
                    visit(path)
                elif is_file:
                    count += 1
                    if count > MAX_MANAGED_ARTIFACT_FILES:
                        raise OrchestratorError(
                            "Managed artifact file-count limit exceeded."
                        )
                    with _open_managed_file(path, verify_private=False):
                        pass
                    entries.append((path, False))
                else:
                    raise OrchestratorError(
                        f"Managed artifact has an unsupported type: {name}"
                    )

    visit(run_dir)
    return entries


def _secure_run_artifacts(run_dir: Path) -> None:
    if os.name == "nt":
        _walk_windows_managed_artifacts(run_dir, writable=True)
        return
    entries = _iter_managed_artifacts(run_dir)
    _set_private_directory(run_dir)
    for path, is_dir in entries:
        if is_dir:
            _set_private_directory(path)
        else:
            _set_private_file(path)


def _scrub_run_artifacts(
    run_dir: Path, sensitive_values: tuple[str, ...]
) -> None:
    replacements: set[bytes] = set()
    for value in sensitive_values:
        replacements.add(value.encode("utf-8"))
        escaped = json.dumps(value, ensure_ascii=False)[1:-1]
        replacements.add(escaped.encode("utf-8"))
    replacements.discard(b"")
    marker = SCRUBBED_VALUE.encode("utf-8")
    with artifact_lock(run_dir):
        if os.name == "nt":
            def scrub_handle(
                path: Path, handle: Any, _details: Mapping[str, Any]
            ) -> None:
                handle.seek(0)
                payload = handle.read(MAX_MANAGED_ARTIFACT_BYTES + 1)
                if len(payload) > MAX_MANAGED_ARTIFACT_BYTES:
                    raise OrchestratorError(
                        f"Managed artifact exceeds its size limit: {path.name}"
                    )
                scrubbed = payload
                for value in sorted(replacements, key=len, reverse=True):
                    scrubbed = scrubbed.replace(value, marker)
                if scrubbed != payload:
                    handle.seek(0)
                    handle.write(scrubbed)
                    handle.truncate()
                    handle.flush()
                    os.fsync(handle.fileno())

            _walk_windows_managed_artifacts(
                run_dir, writable=True, file_action=scrub_handle
            )
            return
        for path, is_dir in _iter_managed_artifacts(run_dir):
            if is_dir:
                continue
            with _open_managed_file(path) as (handle, _details):
                payload = handle.read(MAX_MANAGED_ARTIFACT_BYTES + 1)
            if len(payload) > MAX_MANAGED_ARTIFACT_BYTES:
                raise OrchestratorError(
                    f"Managed artifact exceeds its size limit: {path.name}"
                )
            scrubbed = payload
            for value in sorted(replacements, key=len, reverse=True):
                scrubbed = scrubbed.replace(value, marker)
            if scrubbed != payload:
                _atomic_write_bytes(path, scrubbed)


def _prepare_private_atomic_write(
    path: Path, payload: bytes, *, deadline: float | None = None
) -> Path:
    deadline = _effective_deadline(deadline)
    _check_deadline(deadline)
    if len(payload) > MAX_MANAGED_ARTIFACT_BYTES:
        raise OrchestratorError(f"Atomic artifact exceeds its size limit: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    parent_anchor: tuple[str, Any, Any] | None = None
    try:
        if os.name == "nt":
            temporary_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
            parent_context = _open_windows_managed_directory(path.parent)
            try:
                _parent_handle, parent_details = parent_context.__enter__()
            except OrchestratorError:
                with _open_windows_managed_directory(
                    path.parent, writable=True, verify_private=False
                ):
                    pass
                parent_context = _open_windows_managed_directory(path.parent)
                _parent_handle, parent_details = parent_context.__enter__()
            handle_context = _create_windows_private_file(
                temporary_path, parent_handle=_parent_handle
            )
            handle = handle_context.__enter__()
            import msvcrt

            native_source = msvcrt.get_osfhandle(handle.fileno())
            source_identity = _windows_relative_handle_details(
                native_source, temporary_path.name
            )["file_id"]
            parent_anchor = (
                "windows",
                parent_context,
                parent_details["file_id"],
                _parent_handle,
                handle_context,
                handle,
                (int(source_identity[0]), int(source_identity[1])),
            )
            source_details = os.fstat(handle.fileno())
            if (
                int(source_details.st_dev),
                int(source_details.st_ino),
            ) != parent_anchor[6]:
                raise OrchestratorError("Managed artifact source handle changed.")
        else:
            directory_fd = _open_posix_directory_fd(path.parent)
            temporary_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(
                temporary_path.name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
            handle_context = contextlib.closing(os.fdopen(fd, "w+b"))
            handle = handle_context.__enter__()
            source_details = os.fstat(handle.fileno())
            parent_anchor = (
                "posix",
                directory_fd,
                os.fstat(directory_fd),
                handle_context,
                handle,
                (int(source_details.st_dev), int(source_details.st_ino)),
            )
        _secure_private_writable_handle(handle, temporary_path)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        _check_deadline(deadline)
        source_details = os.fstat(handle.fileno())
        expected_source = parent_anchor[5 if parent_anchor[0] == "posix" else 6]
        if (int(source_details.st_dev), int(source_details.st_ino)) != expected_source:
            raise OrchestratorError("Managed artifact source handle changed.")
        if parent_anchor[0] == "posix":
            _verify_private_path(temporary_path, is_dir=False)
            current_source = os.stat(
                temporary_path.name,
                dir_fd=parent_anchor[1],
                follow_symlinks=False,
            )
            if (int(current_source.st_dev), int(current_source.st_ino)) != expected_source:
                raise OrchestratorError(
                    "Managed artifact source changed during atomic creation."
                )
        else:
            import msvcrt

            native_source = msvcrt.get_osfhandle(handle.fileno())
            if not _inspect_windows_private_acl_handle(
                native_source, is_dir=False
            )["exact"]:
                raise OrchestratorError(
                    "Managed artifact source ACL changed during atomic creation."
                )
        prepared = temporary_path
        assert parent_anchor is not None
        with _PREPARED_ATOMIC_PARENTS_LOCK:
            _PREPARED_ATOMIC_PARENTS[str(prepared)] = parent_anchor
        parent_anchor = None
        temporary_path = None
        return prepared
    finally:
        if temporary_path is not None:
            if parent_anchor is not None and parent_anchor[0] == "windows":
                try:
                    retained = parent_anchor[5]
                    current = os.fstat(retained.fileno())
                    if (
                        int(current.st_dev),
                        int(current.st_ino),
                    ) == parent_anchor[6]:
                        _windows_delete_retained_file(retained)
                except FileNotFoundError:
                    pass
            elif parent_anchor is not None:
                try:
                    current = os.stat(
                        temporary_path.name,
                        dir_fd=parent_anchor[1],
                        follow_symlinks=False,
                    )
                    if (
                        int(current.st_dev),
                        int(current.st_ino),
                    ) == parent_anchor[5]:
                        os.unlink(
                            temporary_path.name, dir_fd=parent_anchor[1]
                        )
                except FileNotFoundError:
                    pass
            else:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
        if parent_anchor is not None:
            if parent_anchor[0] == "posix":
                parent_anchor[3].__exit__(None, None, None)
                os.close(parent_anchor[1])
            else:
                parent_anchor[4].__exit__(None, None, None)
                parent_anchor[1].__exit__(None, None, None)


def _windows_replace_relative(
    temporary_path: Path, path: Path, parent_handle: Any
) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    filename = path.name

    class FileRenameInformation(ctypes.Structure):
        _fields_ = (
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * len(filename)),
        )

    class IoStatusBlock(ctypes.Structure):
        _fields_ = (
            ("Status", ctypes.c_void_p),
            ("Information", ctypes.c_size_t),
        )

    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtSetInformationFile.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    )
    ntdll.NtSetInformationFile.restype = ctypes.c_long
    ntdll.RtlNtStatusToDosError.argtypes = (ctypes.c_long,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
    with _PREPARED_ATOMIC_PARENTS_LOCK:
        anchor = _PREPARED_ATOMIC_PARENTS.get(str(temporary_path))
    if anchor is None or anchor[0] != "windows":
        raise OrchestratorError("Atomic artifact source handle is unavailable.")
    retained_handle = anchor[5]
    retained_details = os.fstat(retained_handle.fileno())
    if (int(retained_details.st_dev), int(retained_details.st_ino)) != anchor[6]:
        raise OrchestratorError("Atomic artifact source identity changed.")
    native_handle = msvcrt.get_osfhandle(retained_handle.fileno())
    if not _inspect_windows_private_acl_handle(
        native_handle, is_dir=False
    )["exact"]:
        raise OrchestratorError("Atomic artifact source ACL changed.")
    information = FileRenameInformation()
    information.ReplaceIfExists = 1
    information.RootDirectory = parent_handle
    information.FileNameLength = len(filename.encode("utf-16-le"))
    information.FileName = filename
    io_status = IoStatusBlock()
    precommit = _ATOMIC_PRECOMMIT.get()
    if precommit is not None:
        precommit()
    status = ntdll.NtSetInformationFile(
        native_handle,
        ctypes.byref(io_status),
        ctypes.byref(information),
        ctypes.sizeof(information),
        10,
    )
    if status < 0:
        error = int(ntdll.RtlNtStatusToDosError(status))
        if error in {5, 32, 33}:
            raise PermissionError(error, "Atomic artifact replacement failed")
        raise OSError(error, "Atomic artifact replacement failed")


def _windows_delete_retained_file(handle: Any) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = (("DeleteFile", wintypes.BOOLEAN),)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    disposition = FileDispositionInfo(1)
    if not kernel32.SetFileInformationByHandle(
        msvcrt.get_osfhandle(handle.fileno()),
        4,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        error = ctypes.get_last_error()
        if error not in {2, 3}:
            raise ctypes.WinError(error)


def _posix_replace_relative(
    temporary_path: Path, path: Path, directory_fd: int
) -> None:
    with _PREPARED_ATOMIC_PARENTS_LOCK:
        anchor = _PREPARED_ATOMIC_PARENTS.get(str(temporary_path))
    if anchor is None or anchor[0] != "posix":
        raise OrchestratorError("Atomic artifact source handle is unavailable.")
    previous_fd: int | None = None
    previous_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    previous_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        previous_fd = os.open(
            path.name, previous_flags, dir_fd=directory_fd
        )
    except FileNotFoundError:
        previous_fd = None

    def unlink_known_generation(
        name: str, expected_key: tuple[int, int]
    ) -> bool:
        try:
            current = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (int(current.st_dev), int(current.st_ino)) != expected_key:
                return False
            os.unlink(name, dir_fd=directory_fd)
            return True
        except OSError:
            return False

    def remove_original_source_name() -> None:
        unlink_known_generation(temporary_path.name, anchor[5])

    precommit = _ATOMIC_PRECOMMIT.get()
    try:
        if precommit is not None:
            precommit()
        if previous_fd is None:
            published_fd = _publish_posix_retained_source(anchor, path.name)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(published_fd)
            remove_original_source_name()
            return

        previous = os.fstat(previous_fd)
        if not stat.S_ISREG(previous.st_mode):
            raise OrchestratorError(
                "Atomic artifact target is not a regular file."
            )
        previous_key = (int(previous.st_dev), int(previous.st_ino))
        bound_name = f".{path.name}.{uuid.uuid4().hex}.bound"
        bound_fd = _publish_posix_retained_source(anchor, bound_name)
        bound = os.fstat(bound_fd)
        bound_key = (int(bound.st_dev), int(bound.st_ino))
        bound_cleanup_key: tuple[int, int] | None = bound_key
        try:
            current_target = os.stat(
                path.name, dir_fd=directory_fd, follow_symlinks=False
            )
            current_bound = os.stat(
                bound_name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                (int(current_target.st_dev), int(current_target.st_ino))
                != previous_key
                or (int(current_bound.st_dev), int(current_bound.st_ino))
                != bound_key
            ):
                raise OrchestratorError(
                    "Atomic artifact generation changed before exchange."
                )
            _exchange_posix_names(directory_fd, bound_name, path.name)
            bound_cleanup_key = None
            published = os.stat(
                path.name, dir_fd=directory_fd, follow_symlinks=False
            )
            displaced = os.stat(
                bound_name, dir_fd=directory_fd, follow_symlinks=False
            )
            published_key = (int(published.st_dev), int(published.st_ino))
            displaced_key = (int(displaced.st_dev), int(displaced.st_ino))
            if published_key != bound_key or displaced_key != previous_key:
                _exchange_posix_names(
                    directory_fd, bound_name, path.name
                )
                restored = os.stat(
                    path.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                restored_bound = os.stat(
                    bound_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (
                    int(restored.st_dev),
                    int(restored.st_ino),
                ) != displaced_key or (
                    int(restored_bound.st_dev),
                    int(restored_bound.st_ino),
                ) != published_key:
                    raise OrchestratorError(
                        "Atomic artifact commit is indeterminate after rollback."
                    )
                os.fsync(directory_fd)
                bound_cleanup_key = published_key
                raise OrchestratorError(
                    "Atomic artifact exchange published an unexpected generation."
                )
            os.fsync(directory_fd)
            bound_cleanup_key = previous_key
            remove_original_source_name()
        finally:
            os.close(bound_fd)
            if bound_cleanup_key is not None and unlink_known_generation(
                bound_name, bound_cleanup_key
            ):
                os.fsync(directory_fd)
    finally:
        if previous_fd is not None:
            os.close(previous_fd)


def _replace_prepared_atomic_write(
    temporary_path: Path,
    path: Path,
    *,
    deadline: float | None = None,
    precommit: Any | None = None,
) -> None:
    effective = _effective_deadline(deadline)
    replace_deadline = time.monotonic() + 2.0
    if effective is not None:
        replace_deadline = min(replace_deadline, effective)
    with _PREPARED_ATOMIC_PARENTS_LOCK:
        parent_anchor = _PREPARED_ATOMIC_PARENTS.get(str(temporary_path))
    if parent_anchor is None:
        raise OrchestratorError("Atomic artifact parent handle is unavailable.")
    replaced = False
    try:
        while True:
            try:
                _check_deadline(effective)
                if precommit is not None:
                    precommit()
                precommit_token = _ATOMIC_PRECOMMIT.set(precommit)
                try:
                    if parent_anchor[0] == "posix":
                        directory_fd = parent_anchor[1]
                        os.fsync(directory_fd)
                        _posix_replace_relative(temporary_path, path, directory_fd)
                    else:
                        _windows_replace_relative(
                            temporary_path, path, parent_anchor[3]
                        )
                finally:
                    _ATOMIC_PRECOMMIT.reset(precommit_token)
                replaced = True
                return
            except PermissionError:
                if time.monotonic() >= replace_deadline:
                    raise
                time.sleep(0.005)
    finally:
        if replaced:
            with _PREPARED_ATOMIC_PARENTS_LOCK:
                _PREPARED_ATOMIC_PARENTS.pop(str(temporary_path), None)
            try:
                if parent_anchor[0] == "posix":
                    parent_anchor[3].__exit__(None, None, None)
                    os.close(parent_anchor[1])
                else:
                    parent_anchor[4].__exit__(None, None, None)
                    parent_anchor[1].__exit__(None, None, None)
            except Exception:
                pass


def _discard_prepared_atomic_write(temporary_path: Path | None) -> None:
    if temporary_path is None:
        return
    with _PREPARED_ATOMIC_PARENTS_LOCK:
        parent_anchor = _PREPARED_ATOMIC_PARENTS.pop(str(temporary_path), None)
    try:
        if parent_anchor is not None and parent_anchor[0] == "posix":
            try:
                current = os.stat(
                    temporary_path.name,
                    dir_fd=parent_anchor[1],
                    follow_symlinks=False,
                )
                if (int(current.st_dev), int(current.st_ino)) == parent_anchor[5]:
                    os.unlink(temporary_path.name, dir_fd=parent_anchor[1])
            except FileNotFoundError:
                pass
        elif parent_anchor is not None:
            try:
                retained = parent_anchor[5]
                current = os.fstat(retained.fileno())
                if (int(current.st_dev), int(current.st_ino)) == parent_anchor[6]:
                    _windows_delete_retained_file(retained)
            except FileNotFoundError:
                pass
        else:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    finally:
        if parent_anchor is not None:
            if parent_anchor[0] == "posix":
                parent_anchor[3].__exit__(None, None, None)
                os.close(parent_anchor[1])
            else:
                parent_anchor[4].__exit__(None, None, None)
                parent_anchor[1].__exit__(None, None, None)


def _atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    deadline: float | None = None,
    precommit: Any | None = None,
) -> None:
    deadline = _effective_deadline(deadline)
    if deadline is None:
        temporary_path = _prepare_private_atomic_write(path, payload)
    else:
        temporary_path = _prepare_private_atomic_write(
            path, payload, deadline=deadline
        )
    try:
        if deadline is None:
            _replace_prepared_atomic_write(
                temporary_path, path, precommit=precommit
            )
        else:
            _replace_prepared_atomic_write(
                temporary_path,
                path,
                deadline=deadline,
                precommit=precommit,
            )
    except Exception:
        _discard_prepared_atomic_write(temporary_path)
        raise


def _atomic_write_text(
    path: Path, text: str, *, deadline: float | None = None
) -> None:
    effective = _effective_deadline(deadline)
    if effective is None:
        _atomic_write_bytes(path, text.encode("utf-8"))
    else:
        _atomic_write_bytes(
            path, text.encode("utf-8"), deadline=effective
        )


def _metadata_bytes(metadata: Mapping[str, Any]) -> bytes:
    return json.dumps(
        sanitize_for_json(dict(metadata)), ensure_ascii=False, indent=2
    ).encode("utf-8")


def _read_metadata_unlocked(
    run_dir: Path, *, deadline: float | None = None
) -> dict[str, Any]:
    metadata_path = run_dir / "metadata.json"
    effective = _effective_deadline(deadline)
    retry_deadline = time.monotonic() + 2.0
    if effective is not None:
        retry_deadline = min(retry_deadline, effective)
    while True:
        try:
            payload = _read_bounded_regular_file(
                metadata_path,
                MAX_MANAGED_ARTIFACT_BYTES,
                deadline=effective,
            )
            return json.loads(payload.decode("utf-8"))
        except FileNotFoundError as exc:
            raise OrchestratorError(
                f"Run metadata not found: {run_dir.name}"
            ) from exc
        except PermissionError:
            if time.monotonic() >= retry_deadline:
                raise
            time.sleep(0.005)


def read_metadata(
    run_dir: Path, *, deadline: float | None = None
) -> dict[str, Any]:
    with artifact_lock(run_dir, deadline=deadline):
        return _read_metadata_unlocked(run_dir, deadline=deadline)


def write_metadata(run_dir: Path, metadata: dict[str, Any]) -> None:
    with artifact_lock(run_dir):
        _atomic_write_bytes(run_dir / "metadata.json", _metadata_bytes(metadata))


def update_metadata(run_dir: Path, **updates: Any) -> dict[str, Any]:
    with artifact_lock(run_dir):
        metadata = read_metadata(run_dir)
        metadata.update(updates)
        _atomic_write_bytes(run_dir / "metadata.json", _metadata_bytes(metadata))
        return metadata


def run_git_command(
    cwd: Path, args: list[str], timeout: float = 30
) -> subprocess.CompletedProcess:
    configured = os.environ.get(INTERNAL_GIT_BIN_ENV)
    if configured:
        git_path = Path(configured)
        if not git_path.is_absolute():
            raise OrchestratorError("The internal Git executable must be absolute.")
        git_command = str(git_path.resolve())
    else:
        discovered = _DISCOVERED_GIT_COMMAND or shutil.which("git")
        if not discovered:
            raise OrchestratorError("Git executable is unavailable.")
        git_command = str(Path(discovered).resolve())
    effective = _effective_deadline()
    if effective is not None:
        remaining = effective - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Git evidence capture exceeded the launch deadline.")
        timeout = max(0.001, min(timeout, remaining))
    git_environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    git_environment.update(
        {"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"}
    )
    process = _PINNED_SUBPROCESS_POPEN(
        [git_command, *args],
        cwd=str(cwd),
        env=git_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        remaining = _remaining_deadline(_effective_deadline(), 1.0)
        if remaining <= 0:
            _retain_worker_handle(
                f"git-cleanup-{process.pid}-{uuid.uuid4().hex}",
                process,
                request_cleanup=True,
            )
            raise
        try:
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            _retain_worker_handle(
                f"git-cleanup-{process.pid}-{uuid.uuid4().hex}",
                process,
                request_cleanup=True,
            )
            raise
    if len((stdout or "").encode("utf-8", errors="replace")) + len(
        (stderr or "").encode("utf-8", errors="replace")
    ) > MAX_MANAGED_ARTIFACT_BYTES:
        raise OrchestratorError("Git evidence command exceeded its output bound.")
    return subprocess.CompletedProcess(
        [git_command, *args], process.returncode, stdout, stderr
    )


def _canonical_git_path(value: Any) -> str:
    path = str(value)
    return path.replace("\\", "/") if os.name == "nt" else path


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
            old_path = parts[idx]
            idx += 1
        if path:
            item = {
                "status": status.strip() or "modified",
                "path": _canonical_git_path(path),
            }
            if old_path:
                item["old_path"] = _canonical_git_path(old_path)
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


def file_sha256(
    path: Path,
    max_bytes: int | None = None,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256()
    try:
        with _open_managed_file(path, verify_private=False) as (handle, _details):
            details = os.fstat(handle.fileno())
            size = int(details.st_size)
            while True:
                _check_deadline(
                    deadline,
                    "Git evidence hashing exceeded the launch deadline.",
                )
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except FileNotFoundError:
        return {"exists": False}
    except OSError as exc:
        if os.name != "nt" or getattr(exc, "winerror", None) != 5:
            raise
        with _open_managed_directory(path, verify_private=False):
            return {"exists": True, "type": "directory"}
    except OrchestratorError as exc:
        if "not a regular file" not in str(exc):
            raise
        with _open_managed_directory(path, verify_private=False):
            return {"exists": True, "type": "directory"}
    return {"exists": True, "sha256": digest.hexdigest(), "bytes": size}


def workspace_hashes(
    cwd: Path,
    paths: list[str],
    limit: int = 10_000,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
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
        normalized = _canonical_git_path(item).strip("/")
        if normalized and normalized not in selected:
            selected.append(normalized)
        if len(selected) > limit:
            raise OrchestratorError(
                "Git evidence path-count limit exceeded; launch cannot proceed safely."
            )
    hashes: dict[str, Any] = {}
    for rel in selected:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Git evidence capture exceeded the launch deadline.")
        candidate = (cwd / rel).resolve()
        if safe_relative(cwd, candidate) is None:
            continue
        try:
            hashes[rel] = file_sha256(candidate, deadline=deadline)
        except Exception as exc:
            hashes[rel] = {"error": str(exc)}
    return hashes


def read_json_file(path: Path, default: Any) -> Any:
    try:
        return json.loads(
            _read_bounded_regular_file(
                path, MAX_MANAGED_ARTIFACT_BYTES
            ).decode("utf-8")
        )
    except FileNotFoundError:
        return default
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


def write_json_file(
    path: Path, data: Any, *, precommit: Any | None = None
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(
        path,
        json.dumps(
            sanitize_for_json(data), ensure_ascii=False, indent=2
        ).encode("utf-8"),
        precommit=precommit,
    )
    return path


class _LaunchLock:
    def __init__(
        self, timeout_seconds: float = 15, stale_seconds: float = 60
    ) -> None:
        self.timeout_seconds = float(timeout_seconds)
        self.stale_seconds = float(stale_seconds)
        self.path = RUNS_DIR / ".launch.lock"
        self.token = uuid.uuid4().hex
        self.generation = uuid.uuid4().hex
        self.identity: tuple[int, int] | None = None

    def _rollback_published_generation(self, key: str, deadline: float) -> None:
        """Retire only the generation published by this acquisition attempt."""
        try:
            with _locked_artifact_lock_generation(
                self.path, deadline=deadline
            ) as (_handle, details, owner_payload):
                owner = json.loads(owner_payload.decode("utf-8"))
                generation = _artifact_lock_file_identity(details)
                if (
                    isinstance(owner, Mapping)
                    and owner.get("pid") == os.getpid()
                    and owner.get("token") == self.token
                    and owner.get("generation") == self.generation
                    and _artifact_lock_path_matches_generation(
                        self.path, generation
                    )
                ):
                    _retire_artifact_lock_file_generation(
                        self.path, self.generation, generation
                    )
        except (
            FileNotFoundError,
            OSError,
            OrchestratorError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            pass
        finally:
            with _PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                if _PROCESS_LAUNCH_LOCK_TOKENS.get(key) == self.token:
                    _PROCESS_LAUNCH_LOCK_TOKENS.pop(key, None)
            self.identity = None

    def _legacy_directory_abandoned(self) -> bool:
        owner_path = self.path / "owner.json"
        try:
            owner = json.loads(
                _read_bounded_regular_file(
                    owner_path, 4096, deadline=_effective_deadline()
                ).decode("utf-8")
            )
            owner_pid = owner.get("pid")
            if (
                isinstance(owner_pid, int)
                and not isinstance(owner_pid, bool)
                and owner_pid > 0
                and pid_alive(owner_pid)
            ):
                return False
        except Exception:
            pass
        try:
            return time.time() - self.path.stat().st_mtime > self.stale_seconds
        except OSError:
            return False

    def _retire_legacy_directory(self) -> bool:
        if not self._legacy_directory_abandoned():
            return False
        claim_path = self.path / ".reclaim"
        try:
            with _open_managed_directory(
                self.path, writable=True, verify_private=False
            ) as (directory_handle, details):
                generation = _artifact_lock_directory_identity(details)
                if os.name == "nt":
                    with _create_windows_private_file(
                        claim_path, parent_handle=directory_handle
                    ) as claim:
                        claim.write(self.token.encode("ascii"))
                        claim.flush()
                        os.fsync(claim.fileno())
                else:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                        os, "O_NOFOLLOW", 0
                    )
                    fd = os.open(
                        claim_path.name,
                        flags,
                        0o600,
                        dir_fd=directory_handle,
                    )
                    with os.fdopen(fd, "wb") as claim:
                        claim.write(self.token.encode("ascii"))
                        claim.flush()
                        os.fsync(claim.fileno())
                if not _artifact_lock_directory_path_matches_generation(
                    self.path, generation
                ):
                    return False
                retired = self.path.with_name(
                    f"{self.path.name}.released-{self.generation}"
                )
                if os.name == "nt":
                    _windows_rename_retained_directory(
                        directory_handle, retired
                    )
                else:
                    os.replace(self.path, retired)
        except (FileExistsError, FileNotFoundError, OSError, OrchestratorError):
            return False
        try:
            for child in retired.iterdir():
                child.unlink(missing_ok=True)
            retired.rmdir()
        except OSError:
            pass
        return True

    def __enter__(self) -> None:
        _set_private_directory(RUNS_DIR)
        deadline = time.monotonic() + self.timeout_seconds
        operation_deadline = _effective_deadline()
        if operation_deadline is not None:
            deadline = min(deadline, operation_deadline)
        key = os.path.normcase(str(self.path.resolve(strict=False)))
        payload = json.dumps(
            {
                "pid": os.getpid(),
                "token": self.token,
                "generation": self.generation,
                "created_at": utc_now_iso(),
                "created_unix": time.time(),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        while True:
            candidate: Path | None = None
            try:
                candidate = _prepare_private_atomic_write(
                    self.path, payload, deadline=deadline
                )
                try:
                    with _PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                        _publish_artifact_lock_candidate(candidate, self.path)
                        _PROCESS_LAUNCH_LOCK_TOKENS[key] = self.token
                finally:
                    _discard_prepared_atomic_write(candidate)
                    candidate = None
                with _open_managed_file(
                    self.path, verify_private=False
                ) as (_handle, details):
                    self.identity = _artifact_lock_file_identity(details)
                return
            except FileExistsError:
                _discard_prepared_atomic_write(candidate)
                if self.path.is_dir():
                    if self._retire_legacy_directory():
                        continue
                else:
                    try:
                        with _locked_artifact_lock_generation(
                            self.path, deadline=deadline
                        ) as (handle, details, owner_payload):
                            generation = _artifact_lock_file_identity(details)
                            try:
                                owner = json.loads(
                                    owner_payload.decode("utf-8")
                                )
                            except (
                                UnicodeDecodeError,
                                json.JSONDecodeError,
                            ):
                                owner = {}
                            if not isinstance(owner, Mapping):
                                owner = {}
                            owner_pid = owner.get("pid")
                            owner_token = owner.get("token")
                            with _PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                                local_token = _PROCESS_LAUNCH_LOCK_TOKENS.get(
                                    key
                                )
                            invalid_owner = (
                                not isinstance(owner_pid, int)
                                or isinstance(owner_pid, bool)
                                or owner_pid <= 0
                            )
                            abandoned = (
                                invalid_owner
                                or not pid_alive(owner_pid)
                            )
                            if owner_pid == os.getpid():
                                abandoned = (
                                    not owner_token
                                    or local_token != owner_token
                                )
                            if invalid_owner or not owner_token:
                                abandoned = abandoned and (
                                    time.time()
                                    - os.fstat(handle.fileno()).st_mtime
                                    > self.stale_seconds
                                )
                            if (
                                abandoned
                                and _artifact_lock_path_matches_generation(
                                    self.path, generation
                                )
                                and _retire_artifact_lock_file_generation(
                                    self.path,
                                    self.generation,
                                    generation,
                                )
                            ):
                                continue
                    except (
                        FileNotFoundError,
                        OSError,
                        OrchestratorError,
                        UnicodeDecodeError,
                        json.JSONDecodeError,
                    ):
                        pass
                if time.monotonic() >= deadline:
                    raise OrchestratorError(
                        "Timed out waiting for the launch lock."
                    )
                time.sleep(0.01)
            except OSError as exc:
                self._rollback_published_generation(key, deadline)
                raise OrchestratorError(
                    "Could not acquire the launch lock."
                ) from exc
            except Exception:
                self._rollback_published_generation(key, deadline)
                raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        key = os.path.normcase(str(self.path.resolve(strict=False)))
        release_deadline = _effective_deadline()
        try:
            try:
                with _locked_artifact_lock_generation(
                    self.path, deadline=release_deadline
                ) as (_handle, details, owner_payload):
                    owner = json.loads(owner_payload.decode("utf-8"))
                    if not isinstance(owner, Mapping):
                        owner = {}
                    generation = _artifact_lock_file_identity(details)
                    if (
                        owner.get("pid") == os.getpid()
                        and owner.get("token") == self.token
                        and owner.get("generation") == self.generation
                        and self.identity == generation
                        and _artifact_lock_path_matches_generation(
                            self.path, generation
                        )
                    ):
                        self.path.unlink(missing_ok=True)
            except (
                FileNotFoundError,
                OSError,
                OrchestratorError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                pass
        finally:
            with _PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                if _PROCESS_LAUNCH_LOCK_TOKENS.get(key) == self.token:
                    _PROCESS_LAUNCH_LOCK_TOKENS.pop(key, None)
        return False


def launch_lock(
    timeout_seconds: float = 15, stale_seconds: float = 60
) -> _LaunchLock:
    return _LaunchLock(timeout_seconds, stale_seconds)


def snapshot_hashes(snapshot: dict[str, Any]) -> dict[str, Any]:
    raw_hashes = snapshot.get("_raw_hashes")
    if isinstance(raw_hashes, dict):
        return raw_hashes
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
    before_status = set(
        _canonical_git_path(p)
        for p in before.get("_raw_changed_paths", before.get("changed_paths", [])) or []
    )
    after_status = set(
        _canonical_git_path(p)
        for p in after.get("_raw_changed_paths", after.get("changed_paths", [])) or []
    )
    changed.update(after_status ^ before_status)
    before_items = {
        _canonical_git_path(item.get("path") or ""): str(
            item.get("status") or ""
        )
        for item in before.get("_raw_status_items", []) or []
        if item.get("path")
    }
    after_items = {
        _canonical_git_path(item.get("path") or ""): str(
            item.get("status") or ""
        )
        for item in after.get("_raw_status_items", []) or []
        if item.get("path")
    }
    for path in set(before_items) | set(after_items):
        if before_items.get(path) != after_items.get(path):
            changed.add(path)
    before_staged = {
        _canonical_git_path(path)
        for path in before.get("_raw_staged_paths", before.get("staged_paths", [])) or []
    }
    after_staged = {
        _canonical_git_path(path)
        for path in after.get("_raw_staged_paths", after.get("staged_paths", [])) or []
    }
    changed.update(before_staged ^ after_staged)
    before_index_entries = before.get("_raw_index_entries") or {}
    after_index_entries = after.get("_raw_index_entries") or {}
    if isinstance(before_index_entries, Mapping) and isinstance(
        after_index_entries, Mapping
    ):
        for path in set(before_index_entries) | set(after_index_entries):
            if before_index_entries.get(path) != after_index_entries.get(path):
                changed.add(_canonical_git_path(path))
    before_untracked = set(
        _canonical_git_path(p)
        for p in before.get("_raw_untracked_paths", before.get("untracked_paths", [])) or []
    )
    after_untracked = set(
        _canonical_git_path(p)
        for p in after.get("_raw_untracked_paths", after.get("untracked_paths", [])) or []
    )
    changed.update(after_untracked ^ before_untracked)
    return sorted(path for path in changed if path)


def _parse_index_entries(raw: str) -> dict[str, list[str]]:
    entries: dict[str, list[str]] = {}
    for record in raw.split("\0"):
        if not record or "\t" not in record:
            continue
        evidence, path = record.split("\t", 1)
        entries.setdefault(_canonical_git_path(path), []).append(evidence)
    return entries


def _parse_nul_name_status(raw: str) -> list[dict[str, str]]:
    parts = raw.split("\0")
    items: list[dict[str, str]] = []
    index = 0
    while index < len(parts):
        status = parts[index]
        index += 1
        if not status:
            continue
        if index >= len(parts):
            raise OrchestratorError("Git name-status evidence is incomplete.")
        path = parts[index]
        index += 1
        item = {
            "status": status,
            "path": _canonical_git_path(path),
        }
        if status[:1] in {"R", "C"}:
            if index >= len(parts):
                raise OrchestratorError(
                    "Git rename name-status evidence is incomplete."
                )
            item["old_path"] = _canonical_git_path(path)
            item["path"] = _canonical_git_path(parts[index])
            index += 1
        items.append(item)
    return items


def _parse_nul_numstat_paths(raw: str) -> list[str]:
    parts = raw.split("\0")
    paths: list[str] = []
    index = 0
    while index < len(parts):
        record = parts[index]
        index += 1
        if not record:
            continue
        fields = record.split("\t", 2)
        if len(fields) != 3:
            raise OrchestratorError("Git numstat evidence is malformed.")
        path = fields[2]
        if path:
            paths.append(_canonical_git_path(path))
            continue
        if index + 1 >= len(parts):
            raise OrchestratorError("Git rename numstat evidence is incomplete.")
        _old_path = parts[index]
        new_path = parts[index + 1]
        index += 2
        paths.append(_canonical_git_path(new_path))
    return paths


def _diff_change_records(
    diff_text: str, structured_paths: list[str] | tuple[str, ...] = ()
) -> set[tuple[str, str, str, int]]:
    records: set[tuple[str, str, str, int]] = set()
    occurrences: dict[tuple[str, str, str], int] = {}
    current_path = ""
    path_index = 0
    path_is_structured = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if path_index < len(structured_paths):
                current_path = _canonical_git_path(
                    structured_paths[path_index]
                )
                path_index += 1
                path_is_structured = True
            else:
                current_path = ""
                path_is_structured = False
            continue
        if not path_is_structured and line.startswith("+++ b/"):
            current_path = _canonical_git_path(line[6:])
            continue
        if not path_is_structured and line.startswith("--- a/"):
            current_path = _canonical_git_path(line[6:])
            continue
        if line.startswith("+") and not line.startswith("+++"):
            base = (current_path, "+", line[1:])
            occurrences[base] = occurrences.get(base, 0) + 1
            records.add((*base, occurrences[base]))
        elif line.startswith("-") and not line.startswith("---"):
            base = (current_path, "-", line[1:])
            occurrences[base] = occurrences.get(base, 0) + 1
            records.add((*base, occurrences[base]))
    return records


def _git_transition_evidence(
    root: Path,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> tuple[set[str], set[tuple[str, str, str, int]], list[str]]:
    paths: set[str] = set()
    changes: set[tuple[str, str, str, int]] = set()
    head_changes: set[tuple[str, str, str, int]] = set()
    errors: list[str] = []

    def compare_objects(
        label: str,
        old: Any,
        new: Any,
        target: set[tuple[str, str, str, int]] | None = None,
    ) -> None:
        if old == new:
            return
        if not isinstance(old, str) or not old or not isinstance(new, str) or not new:
            errors.append(f"{label}_continuity")
            return
        try:
            diff = run_git_command(root, ["diff", "--binary", old, new, "--", "."])
            names = run_git_command(root, ["diff", "--name-only", "-z", old, new, "--", "."])
        except Exception:
            errors.append(f"{label}_transition")
            return
        if diff.returncode != 0 or names.returncode != 0:
            errors.append(f"{label}_transition")
            return
        output = diff.stdout or ""
        named_list = [
            _canonical_git_path(item)
            for item in (names.stdout or "").split("\0")
            if item
        ]
        named = set(named_list)
        if not named and old != new:
            errors.append(f"{label}_transition_unattributed")
            return
        paths.update(named)
        (changes if target is None else target).update(
            _diff_change_records(output, named_list)
        )

    before_head = before.get("_raw_head", before.get("head"))
    after_head = after.get("_raw_head", after.get("head"))
    if before_head != after_head:
        before_head_tree = before.get(
            "_raw_head_tree", before.get("head_tree")
        )
        after_head_tree = after.get("_raw_head_tree", after.get("head_tree"))
        if before_head_tree == after_head_tree:
            errors.append("head_transition_unattributed")
        else:
            compare_objects(
                "head", before_head_tree, after_head_tree, head_changes
            )
    compare_objects(
        "index",
        before.get("_raw_index_tree", before.get("index_tree")),
        after.get("_raw_index_tree", after.get("index_tree")),
    )
    before_entries = before.get("_raw_index_entries") or {}
    after_entries = after.get("_raw_index_entries") or {}
    if isinstance(before_entries, Mapping) and isinstance(after_entries, Mapping):
        for path in set(before_entries) | set(after_entries):
            if before_entries.get(path) != after_entries.get(path):
                paths.add(_canonical_git_path(path))
    else:
        errors.append("index_entries")
    before_worktree = _diff_change_records(
        str(before.get("_raw_diff_text") or ""),
        list(before.get("_raw_diff_paths") or []),
    )
    after_worktree = _diff_change_records(
        str(after.get("_raw_diff_text") or ""),
        list(after.get("_raw_diff_paths") or []),
    )
    before_staged = _diff_change_records(
        str(before.get("_raw_staged_diff_text") or ""),
        list(before.get("_raw_staged_diff_paths") or []),
    )
    after_staged = _diff_change_records(
        str(after.get("_raw_staged_diff_text") or ""),
        list(after.get("_raw_staged_diff_paths") or []),
    )
    # Compare logical workspace content with multiplicity. Identical lines may
    # move between the staged and worktree layers; set union would collapse
    # those occurrences and misclassify a layer move as a new edit.
    def record_counter(
        records: set[tuple[str, str, str, int]],
    ) -> Counter[tuple[str, str, str]]:
        return Counter((path, kind, line) for path, kind, line, _ in records)

    before_logical = record_counter(before_staged) + record_counter(before_worktree)
    after_logical = (
        record_counter(head_changes)
        + record_counter(after_staged)
        + record_counter(after_worktree)
    )
    logical_delta = (after_logical - before_logical) + (
        before_logical - after_logical
    )
    changes = {
        (*record, occurrence)
        for record, count in logical_delta.items()
        for occurrence in range(1, count + 1)
    }
    before_hashes = before.get("_raw_hashes") or {}
    after_hashes = after.get("_raw_hashes") or {}
    if isinstance(before_hashes, Mapping) and isinstance(after_hashes, Mapping):
        unchanged_content: set[str] = set()
        for path in set(before_hashes) & set(after_hashes):
            old_evidence = before_hashes.get(path)
            new_evidence = after_hashes.get(path)
            if (
                isinstance(old_evidence, Mapping)
                and isinstance(new_evidence, Mapping)
                and old_evidence.get("exists") is True
                and new_evidence.get("exists") is True
                and isinstance(old_evidence.get("sha256"), str)
                and old_evidence.get("sha256") == new_evidence.get("sha256")
            ):
                unchanged_content.add(_canonical_git_path(path))
        changes = {
            record for record in changes if record[0] not in unchanged_content
        }
    return paths, changes, errors


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


def terminate_process_tree(
    expected_identity: ProcessIdentity,
    *,
    force: bool = False,
    wait_seconds: int = 5,
) -> dict[str, Any]:
    """Terminate only through an identity-bound stable process capability."""
    if not isinstance(expected_identity, ProcessIdentity):
        raise TypeError("expected_identity must be a ProcessIdentity")
    if sys.platform != "win32":
        return {
            "pid": expected_identity.pid,
            "attempted": False,
            "alive": True,
            "identity_state": "unverified",
            "differing_fields": ["process_tree_containment"],
            "method": None,
        }
    with open_stable_process_capability(expected_identity) as capability:
        return capability.terminate(force=force, wait_seconds=wait_seconds)


def read_file_delta(path: Path, offset: int = 0, max_bytes: int = 20000) -> dict[str, Any]:
    if offset < 0:
        raise OrchestratorError("Offset cannot be negative.")
    if max_bytes < 1:
        raise OrchestratorError("max_bytes must be positive.")
    try:
        with _open_managed_file(path, verify_private=False) as (handle, _details):
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if offset > size:
                offset = size
            handle.seek(offset)
            data = handle.read(max_bytes)
    except FileNotFoundError:
        return {"path": str(path), "text": "", "offset": offset, "next_offset": offset, "size": 0, "truncated": False}
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
    if chars <= 0:
        return ""
    try:
        with _open_managed_file(path, verify_private=False) as (handle, _details):
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max(chars * 4, 4096)))
            data = handle.read()
    except FileNotFoundError:
        return ""
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


def _read_event_seq_sidecar(path: Path) -> tuple[int, int | None]:
    try:
        with _open_managed_file(path, verify_private=False) as (handle, _details):
            raw = handle.read(256)
            if handle.read(1):
                return 0, None
    except FileNotFoundError:
        return 0, None
    text = raw.decode("utf-8", errors="replace").strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        seq = payload.get("seq")
        events_bytes = payload.get("events_bytes")
        if (
            isinstance(seq, int)
            and not isinstance(seq, bool)
            and seq >= 0
            and isinstance(events_bytes, int)
            and not isinstance(events_bytes, bool)
            and events_bytes >= 0
        ):
            return seq, events_bytes
    try:
        value = int(text)
    except ValueError:
        return 0, None
    return (value, None) if value >= 0 else (0, None)


def _last_complete_event_handle(handle: Any) -> tuple[int, int | None]:
    """Return the last complete sequence and a partial-tail truncation offset."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return 0, None
    start = max(0, size - EVENT_RECOVERY_TAIL_BYTES)
    handle.seek(start)
    tail = handle.read()
    if tail.endswith(b"\n"):
        complete_end = len(tail) - 1
        truncate_at = None
    else:
        final_newline = tail.rfind(b"\n")
        if final_newline < 0:
            if start:
                raise OrchestratorError("Last event exceeds the recovery bound.")
            return 0, 0
        complete_end = final_newline
        truncate_at = start + final_newline + 1
    previous_newline = tail.rfind(b"\n", 0, complete_end)
    line_start = previous_newline + 1
    if start and previous_newline < 0:
        raise OrchestratorError("Last event exceeds the recovery bound.")
    line = tail[line_start:complete_end]
    if not line.strip():
        return 0, truncate_at
    try:
        candidate = json.loads(line.decode("utf-8")).get("seq")
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("Last complete event is invalid.") from exc
    if not isinstance(candidate, int) or isinstance(candidate, bool) or candidate < 0:
        raise OrchestratorError("Last complete event sequence is invalid.")
    return candidate, truncate_at


def _last_complete_event(path: Path) -> tuple[int, int | None]:
    try:
        with _open_managed_file(path, verify_private=False) as (handle, _details):
            return _last_complete_event_handle(handle)
    except FileNotFoundError:
        return 0, None


def append_event(run_dir: Path, event: dict[str, Any]) -> None:
    with artifact_lock(run_dir):
        seq_path = run_dir / "event_seq.txt"
        path = run_dir / "events.ndjson"
        sidecar_seq, sidecar_size = _read_event_seq_sidecar(seq_path)
        if not path.exists():
            _atomic_write_bytes(path, b"")
        with _open_managed_file(
            path, writable=True, verify_private=False
        ) as (handle, _details):
            handle.seek(0, os.SEEK_END)
            current_size = handle.tell()
            if sidecar_size is not None and sidecar_size == current_size:
                event_seq, truncate_at = sidecar_seq, None
            else:
                event_seq, truncate_at = _last_complete_event_handle(handle)
            if truncate_at is not None:
                handle.truncate(truncate_at)
                handle.flush()
                os.fsync(handle.fileno())
            last_seq = sidecar_seq if sidecar_size == current_size else event_seq
            seq = last_seq + 1
            persisted_event = dict(event)
            persisted_event["seq"] = seq
            persisted_event.setdefault("ts", utc_now_iso())
            persisted_event.setdefault("run_id", run_dir.name)
            encoded = (
                json.dumps(
                    sanitize_for_json(redact(persisted_event)), ensure_ascii=False
                )
                + "\n"
            ).encode("utf-8", errors="replace")
            handle.seek(0, os.SEEK_END)
            if handle.tell() + len(encoded) > MAX_MANAGED_ARTIFACT_BYTES:
                raise OrchestratorError("Event log exceeds its size limit.")
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            events_bytes = handle.tell()
        if not _TERMINAL_EVENT_APPEND.get():
            _atomic_write_text(
                seq_path,
                json.dumps(
                    {"seq": seq, "events_bytes": events_bytes},
                    separators=(",", ":"),
                ),
            )


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
    try:
        payload = _read_bounded_regular_file(
            path, MAX_MANAGED_ARTIFACT_BYTES
        )
    except FileNotFoundError:
        return []
    lines = payload.decode("utf-8", errors="replace").splitlines()
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
        rel = _canonical_git_path(raw).strip("/")
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


def _freeze_route_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_route_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_route_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("safe route metadata must contain only JSON-compatible values")


def _thaw_route_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_route_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_route_value(item) for item in value]
    return value


def _endpoint_sensitive_values(value: str) -> tuple[str, ...]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        if value.casefold().startswith(("http:", "https:")):
            return _normalize_sensitive_values(
                (value, unquote(value), unquote_plus(value))
            )
        return ()
    if parsed.scheme.casefold() in {"http", "https"} and not parsed.netloc:
        return _normalize_sensitive_values(
            (value, unquote(value), unquote_plus(value))
        )
    if parsed.scheme.casefold() not in {"http", "https"}:
        return ()
    sensitive: list[str] = []
    sensitive.extend((value, unquote(value), unquote_plus(value)))
    for component in (parsed.username, parsed.password):
        if not component:
            continue
        sensitive.extend((component, unquote(component), unquote_plus(component)))
    for field in parsed.query.split("&"):
        raw_key, separator, raw_value = field.partition("=")
        if not separator or not raw_value:
            continue
        decoded_key = unquote_plus(raw_key)
        decoded_value = unquote_plus(raw_value)
        sensitive.extend((raw_value, unquote(raw_value), decoded_value))
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        query = []
    sensitive.extend(query_value for _query_key, query_value in query if query_value)
    if parsed.fragment:
        sensitive.extend(
            (
                parsed.fragment,
                unquote(parsed.fragment),
                unquote_plus(parsed.fragment),
            )
        )
    return _normalize_sensitive_values(sensitive)


def _sanitize_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return (
            SCRUBBED_VALUE
            if value.casefold().startswith(("http:", "https:"))
            else value
        )
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        return (
            SCRUBBED_VALUE
            if parsed.scheme.casefold() in {"http", "https"}
            else value
        )
    hostname = parsed.hostname
    if not hostname:
        return SCRUBBED_VALUE
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme.casefold(), netloc, "", "", ""))


def _collect_route_sensitive_values(value: Any) -> tuple[str, ...]:
    collected: list[str] = []
    if isinstance(value, Mapping):
        for item in value.values():
            collected.extend(_collect_route_sensitive_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            collected.extend(_collect_route_sensitive_values(item))
    elif isinstance(value, str):
        collected.extend(_endpoint_sensitive_values(value))
    return tuple(collected)


def _prompt_sensitive_values(prompt: bytes | str) -> tuple[str, ...]:
    text = (
        prompt.decode("utf-8", errors="strict")
        if isinstance(prompt, bytes)
        else prompt
    )
    values = [text] if text else []
    task_marker = "\nTask:\n"
    context_marker = "\n\nAdditional context:\n"
    if task_marker in text:
        task_and_context = text.rsplit(task_marker, 1)[1]
        if context_marker in task_and_context:
            task, context = task_and_context.split(context_marker, 1)
            values.extend([task.strip(), context.strip()])
        else:
            values.append(task_and_context.strip())
    return tuple(value for value in values if value)


def _normalize_sensitive_values(values: Any) -> tuple[str, ...]:
    unique = {
        str(value)
        for value in values
        if isinstance(value, str) and value
    }
    return tuple(sorted(unique, key=lambda item: (-len(item), item)))


def _scrub_exact_text(text: str, sensitive_values: tuple[str, ...]) -> str:
    safe = _sanitize_endpoint(text)
    for value in sensitive_values:
        safe = safe.replace(value, SCRUBBED_VALUE)
    return str(redact(safe))


def _scrub_output_text(text: str, sensitive_values: tuple[str, ...]) -> str:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _scrub_exact_text(text, sensitive_values)
    scrubbed = _scrub_guarded_value(parsed, sensitive_values)
    ending = "\n" if text.endswith(("\n", "\r")) else ""
    return json.dumps(scrubbed, ensure_ascii=False) + ending


def _scrub_guarded_value(value: Any, sensitive_values: tuple[str, ...]) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _scrub_guarded_value(item, sensitive_values)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub_guarded_value(item, sensitive_values) for item in value]
    if isinstance(value, str):
        return _scrub_exact_text(value, sensitive_values)
    return value


def _scrub_data_keyed_mapping(
    value: Mapping[str, Any], sensitive_values: tuple[str, ...]
) -> dict[str, Any]:
    """Scrub mappings whose keys are user data, such as Git path indexes."""
    return {
        _scrub_exact_text(str(key), sensitive_values): _scrub_guarded_value(
            item, sensitive_values
        )
        for key, item in value.items()
    }


@dataclass
class _LaunchAdmissionReservation:
    team_id: str
    owner_pid: int
    deadline: float | None = None
    active: bool = True
    registered_run_ids: list[str] | None = None

    def __post_init__(self) -> None:
        if self.registered_run_ids is None:
            self.registered_run_ids = []

    def require_active(self) -> None:
        if not self.active or self.owner_pid != os.getpid():
            raise OrchestratorError("Team launch admission reservation is inactive.")

    def register(self, run_id: str) -> None:
        self.require_active()
        assert self.registered_run_ids is not None
        if run_id in self.registered_run_ids:
            raise OrchestratorError("Team child registration was duplicated.")
        self.registered_run_ids.append(run_id)


@dataclass(frozen=True)
class PreparedWorkerLaunch:
    mode: str
    launch_spec: RuntimeLaunchSpec
    prompt_bytes: bytes
    safe_route_metadata: Mapping[str, Any]
    expected_child_launches: int
    transaction_deadline_monotonic: float
    selected_model: str | None = None
    skip_cost_guard: bool = False
    sensitive_values: tuple[str, ...] = ()
    admission_reservation: _LaunchAdmissionReservation | None = None
    _preflight_git_before: dict[str, Any] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.mode not in {"one_shot", "streaming", "visible"}:
            raise ValueError("prepared launch mode is unsupported")
        if not isinstance(self.launch_spec, RuntimeLaunchSpec):
            raise TypeError("launch_spec must be a RuntimeLaunchSpec")
        if not isinstance(self.prompt_bytes, bytes):
            raise TypeError("prompt_bytes must be bytes")
        object.__setattr__(self, "prompt_bytes", bytes(self.prompt_bytes))
        if len(self.prompt_bytes) > PROMPT_BYTES_LIMIT:
            raise OrchestratorError("Prompt exceeds the 1 MiB launch limit.")
        if len(self.launch_spec.private_frame()) > PRIVATE_LAUNCH_FRAME_LIMIT:
            raise OrchestratorError("Private launch frame exceeds the 64 KiB limit.")
        if not isinstance(self.safe_route_metadata, Mapping):
            raise TypeError("safe_route_metadata must be a mapping")
        object.__setattr__(
            self,
            "safe_route_metadata",
            _freeze_route_value(self.safe_route_metadata),
        )
        if (
            not isinstance(self.expected_child_launches, int)
            or isinstance(self.expected_child_launches, bool)
            or self.expected_child_launches < 1
        ):
            raise TypeError("expected_child_launches must be a positive integer")
        if (
            not isinstance(self.transaction_deadline_monotonic, (int, float))
            or isinstance(self.transaction_deadline_monotonic, bool)
            or not math.isfinite(float(self.transaction_deadline_monotonic))
        ):
            raise TypeError(
                "transaction_deadline_monotonic must be finite deadline evidence"
            )
        object.__setattr__(
            self,
            "transaction_deadline_monotonic",
            float(self.transaction_deadline_monotonic),
        )
        if self.selected_model is not None and not isinstance(
            self.selected_model, str
        ):
            raise TypeError("selected_model must be a string or null")
        if not isinstance(self.skip_cost_guard, bool):
            raise TypeError("skip_cost_guard must be a boolean")
        if self.admission_reservation is not None:
            self.admission_reservation.require_active()
        object.__setattr__(
            self,
            "sensitive_values",
            _normalize_sensitive_values(self.sensitive_values),
        )

    def metadata(self) -> dict[str, Any]:
        return _thaw_route_value(self.safe_route_metadata)


def _with_controller_environment_baseline(
    launch_spec: RuntimeLaunchSpec,
) -> RuntimeLaunchSpec:
    environment = dict(launch_spec.environment)
    environment.update(_controller_os_environment_baseline())
    return RuntimeLaunchSpec.create(
        runtime_id=launch_spec.runtime_id,
        protocol_version=launch_spec.protocol_version,
        executable_identity=launch_spec.executable_identity,
        arguments=launch_spec.arguments,
        cwd=launch_spec.cwd,
        permission_mode=launch_spec.permission_mode,
        timeout_seconds=launch_spec.timeout_seconds,
        environment=environment,
        trust_level=launch_spec.trust_level,
        policy_decision_id=launch_spec.policy_decision_id,
    )


def _prepare_worker_launch_inner(
    *,
    mode: str,
    prompt: str | bytes,
    provider_env: Mapping[str, str],
    model_override: str | None,
    cwd: str | Path,
    workspace_root: str | Path,
    artifact_root: str | Path,
    permission_mode: str,
    timeout_seconds: int,
    arguments: tuple[str, ...],
    safe_route_metadata: Mapping[str, Any],
    expected_child_launches: int = 1,
    allow_unsafe_runtime: bool = False,
    selected_model: str | None = None,
    skip_cost_guard: bool = False,
    sensitive_values: tuple[str, ...] = (),
    admission_reservation: _LaunchAdmissionReservation | None = None,
) -> PreparedWorkerLaunch:
    _check_deadline(
        message="Runtime launch preparation exceeded the transaction deadline."
    )
    if mode not in {"one_shot", "streaming", "visible"}:
        raise OrchestratorError("Launch mode must be one_shot, streaming, or visible.")
    if isinstance(prompt, str):
        prompt_bytes = prompt.encode("utf-8")
    elif isinstance(prompt, bytes):
        prompt_bytes = bytes(prompt)
        try:
            prompt_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OrchestratorError("Prompt bytes must be valid UTF-8.") from exc
    else:
        raise TypeError("prompt must be text or bytes")
    if len(prompt_bytes) > PROMPT_BYTES_LIMIT:
        raise OrchestratorError("Prompt exceeds the 1 MiB launch limit.")
    effective_cwd = Path(cwd).expanduser().resolve()
    if not effective_cwd.is_dir():
        raise OrchestratorError(f"Launch cwd is not a directory: {effective_cwd}")
    workspace = Path(workspace_root).expanduser().resolve()
    if not workspace.is_dir():
        raise OrchestratorError(
            f"Configured workspace root is not a directory: {workspace}"
        )
    try:
        effective_cwd.relative_to(workspace)
    except ValueError as exc:
        raise OrchestratorError(
            f"Launch cwd is outside the configured workspace root: {effective_cwd}"
        ) from exc
    artifacts = Path(artifact_root).expanduser().resolve()
    policy = load_runtime_security_policy()
    _check_deadline(
        message="Runtime policy resolution exceeded the transaction deadline."
    )
    _reject_provider_baseline_overrides(provider_env)
    candidate = resolve_runtime_candidate(policy)
    _check_deadline(
        message="Runtime executable resolution exceeded the transaction deadline."
    )
    launch_spec = build_runtime_launch_spec(
        runtime_candidate=candidate,
        provider_env=provider_env,
        model_override=model_override,
        cwd=effective_cwd,
        workspace_root=workspace,
        artifact_root=artifacts,
        permission_mode=permission_mode,
        timeout_seconds=timeout_seconds,
        arguments=arguments,
        policy=policy,
        allow_unsafe_runtime=allow_unsafe_runtime,
    )
    _check_deadline(
        message="Runtime executable hashing exceeded the transaction deadline."
    )
    launch_spec = _with_controller_environment_baseline(launch_spec)
    frame = launch_spec.private_frame()
    if len(frame) > PRIVATE_LAUNCH_FRAME_LIMIT:
        raise OrchestratorError("Private launch frame exceeds the 64 KiB limit.")
    provider_secrets = tuple(
        str(value)
        for key, value in provider_env.items()
        if value and should_redact_key(str(key), value)
    )
    provider_endpoint_secrets = tuple(
        secret
        for value in provider_env.values()
        if value
        for secret in _endpoint_sensitive_values(str(value))
    )
    exact_values = _normalize_sensitive_values(
        (
            *_prompt_sensitive_values(prompt_bytes),
            *provider_secrets,
            *provider_endpoint_secrets,
            *_collect_route_sensitive_values(safe_route_metadata),
            *sensitive_values,
        )
    )
    metadata = _scrub_guarded_value(dict(safe_route_metadata), exact_values)
    metadata.update(
        {
            "run_id": new_run_id(),
            "mode": (
                "visible_window"
                if mode == "visible"
                else "streaming" if mode == "streaming" else "one_shot"
            ),
            "started_at": utc_now_iso(),
            "cwd": str(effective_cwd),
            "workspace_root": str(workspace),
            "artifact_root": str(artifacts),
            "runs_root": str(artifacts / "runs"),
            "timeout_seconds": timeout_seconds,
            "permission_mode": permission_mode,
            "prompt_bytes": len(prompt_bytes),
            "prompt_tokens_est": max(0, (len(prompt_bytes) + 3) // 4),
        }
    )
    if launch_spec.trust_level == "local_unsafe":
        metadata["acceptance_status"] = "pending_controller_review"
    return PreparedWorkerLaunch(
        mode=mode,
        launch_spec=launch_spec,
        prompt_bytes=prompt_bytes,
        safe_route_metadata=metadata,
        expected_child_launches=expected_child_launches,
        transaction_deadline_monotonic=float(_effective_deadline()),
        selected_model=selected_model,
        skip_cost_guard=skip_cost_guard,
        sensitive_values=exact_values,
        admission_reservation=admission_reservation,
    )


def prepare_worker_launch(
    *,
    mode: str,
    prompt: str | bytes,
    provider_env: Mapping[str, str],
    model_override: str | None,
    cwd: str | Path,
    workspace_root: str | Path,
    artifact_root: str | Path,
    permission_mode: str,
    timeout_seconds: int,
    arguments: tuple[str, ...],
    safe_route_metadata: Mapping[str, Any],
    expected_child_launches: int = 1,
    allow_unsafe_runtime: bool = False,
    selected_model: str | None = None,
    skip_cost_guard: bool = False,
    sensitive_values: tuple[str, ...] = (),
    admission_reservation: _LaunchAdmissionReservation | None = None,
) -> PreparedWorkerLaunch:
    inherited = _effective_deadline()
    deadline = inherited or (
        time.monotonic()
        + max(1, int(timeout_seconds))
        + TRANSACTION_CLOSURE_RESERVE_SECONDS
    )
    if (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
    ):
        raise OrchestratorError(
            "Runtime launch preparation deadline evidence is invalid."
        )
    if (
        admission_reservation is not None
        and float(admission_reservation.deadline) != float(deadline)
    ):
        raise OrchestratorError(
            "Team launch preparation deadline does not match its reservation."
        )
    token = _OPERATION_DEADLINE.set(float(deadline))
    try:
        return _prepare_worker_launch_inner(
            mode=mode,
            prompt=prompt,
            provider_env=provider_env,
            model_override=model_override,
            cwd=cwd,
            workspace_root=workspace_root,
            artifact_root=artifact_root,
            permission_mode=permission_mode,
            timeout_seconds=timeout_seconds,
            arguments=arguments,
            safe_route_metadata=safe_route_metadata,
            expected_child_launches=expected_child_launches,
            allow_unsafe_runtime=allow_unsafe_runtime,
            selected_model=selected_model,
            skip_cost_guard=skip_cost_guard,
            sensitive_values=sensitive_values,
            admission_reservation=admission_reservation,
        )
    finally:
        _OPERATION_DEADLINE.reset(token)


def _runtime_command(
    identity: ExecutableIdentity, arguments: tuple[str, ...]
) -> list[str]:
    executable = identity.canonical_path
    interpreter = identity.interpreter_identity
    if interpreter is None:
        return [executable, *arguments]
    host = interpreter.canonical_path
    if identity.target_kind == "cmd":
        return [host, "/d", "/s", "/c", executable, *arguments]
    if identity.target_kind == "powershell":
        return [
            host,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            executable,
            *arguments,
        ]
    return [host, executable, *arguments]


def _expected_process_image(identity: ExecutableIdentity) -> str:
    current = identity
    while current.interpreter_identity is not None:
        current = current.interpreter_identity
    return current.canonical_path


def _paths_match(left: str, right: str) -> bool:
    return os.path.normcase(str(Path(left).resolve(strict=False))) == os.path.normcase(
        str(Path(right).resolve(strict=False))
    )


def _security_error(
    code: str,
    message: str,
    *,
    safe_details: Mapping[str, Any] | None = None,
    suggested_action: str,
) -> RuntimeSecurityError:
    return RuntimeSecurityError(
        code=code,
        message=message,
        safe_details=dict(safe_details or {}),
        suggested_action=suggested_action,
    )


def _runtime_identity_changed(path: str) -> RuntimeSecurityError:
    return _security_error(
        "runtime_identity_changed",
        "Runtime executable identity changed after launch approval.",
        safe_details={"canonical_path": path},
        suggested_action="Re-run preflight and review the executable identity.",
    )


def _process_identity_unverified(pid: int, kind: str) -> RuntimeSecurityError:
    return _security_error(
        "process_identity_unverified",
        f"The {kind} process identity could not be verified.",
        safe_details={"pid": pid, "process_kind": kind},
        suggested_action="Use a platform with supported process identity capture.",
    )


def _validate_started_identity(
    process_identity: ProcessIdentity,
    executable_identity: ExecutableIdentity,
    *,
    process_kind: str,
) -> None:
    if (
        not process_identity.supported
        or process_identity.executable_path is None
        or not _paths_match(
            process_identity.executable_path,
            _expected_process_image(executable_identity),
        )
    ):
        raise _process_identity_unverified(process_identity.pid, process_kind)


def _git_snapshot_projection(
    snapshot: Mapping[str, Any], sensitive_values: tuple[str, ...]
) -> dict[str, Any]:
    public = {
        key: value
        for key, value in snapshot.items()
        if not str(key).startswith("_raw_")
    }
    return _scrub_guarded_value(public, sensitive_values)


def _failed_git_snapshot(
    label: str,
    error: BaseException,
    sensitive_values: tuple[str, ...] = (),
    *,
    is_git_repo: bool = False,
) -> dict[str, Any]:
    error_code = (
        "git_evidence_timeout"
        if isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        else "git_evidence_capture_failed"
    )
    return {
        "ok": False,
        "label": label,
        "is_git_repo": is_git_repo,
        "error": _scrub_exact_text(str(error), sensitive_values),
        "evidence_complete": False,
        "evidence_errors": [error_code],
        "_raw_error": str(error),
        "_raw_evidence_complete": False,
        "_raw_evidence_errors": [error_code],
    }


def capture_git_snapshot(
    run_dir: Path,
    cwd: Path,
    label: str,
    sensitive_values: tuple[str, ...] = (),
    deadline: float | None = None,
) -> dict[str, Any]:
    """Capture a complete, root-bound view of repository and file state."""
    deadline = _effective_deadline(deadline)
    cwd = cwd.resolve()
    is_git_repo = False
    try:
        def command_timeout(limit: float) -> float:
            effective = _effective_deadline(deadline)
            if effective is None:
                return limit
            remaining = effective - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Git evidence capture exceeded the launch deadline.")
            return max(0.001, min(limit, remaining))

        root_proc = run_git_command(
            cwd, ["rev-parse", "--show-toplevel"], timeout=command_timeout(30)
        )
        if root_proc.returncode != 0:
            diagnostic = f"{root_proc.stdout}\n{root_proc.stderr}".lower()
            if "not a git repository" in diagnostic:
                return {
                    "ok": True,
                    "label": label,
                    "is_git_repo": False,
                    "evidence_complete": True,
                    "evidence_errors": [],
                    "_raw_evidence_complete": True,
                    "_raw_evidence_errors": [],
                }
            raise OrchestratorError("Git repository discovery was inconclusive.")
        root_text = root_proc.stdout.strip()
        if not root_text:
            raise OrchestratorError("Git repository discovery returned no top-level path.")
        repo_root = Path(root_text).resolve()
        is_git_repo = True
        if repo_root != cwd:
            return {
                "ok": False,
                "label": label,
                "is_git_repo": True,
                "repository_identity": {
                    "workspace_root": str(cwd),
                    "repository_root": str(repo_root),
                },
                "evidence_complete": False,
                "evidence_errors": ["repository_root_mismatch"],
                "_raw_evidence_complete": False,
                "_raw_evidence_errors": ["repository_root_mismatch"],
            }

        git_marker = repo_root / ".git"
        if git_marker.exists():
            marker_details = git_marker.lstat()
            marker_attributes = int(
                getattr(marker_details, "st_file_attributes", 0) or 0
            )
            if (
                stat.S_ISLNK(marker_details.st_mode)
                or marker_attributes & _WINDOWS_REPARSE_POINT
            ):
                raise OrchestratorError(
                    "Git repository marker cannot be a link or reparse point."
                )

        commands = {
            "git_dir": ["rev-parse", "--absolute-git-dir"],
            "head": ["rev-parse", "--verify", "HEAD"],
            "head_tree": ["rev-parse", "--verify", "HEAD^{tree}"],
            "head_symbolic": ["symbolic-ref", "-q", "HEAD"],
            "index_tree": ["write-tree"],
            "index_entries": ["ls-files", "--stage", "-v", "-z"],
            "diff": ["diff", "--binary", "--", "."],
            "diff_numstat": ["diff", "--numstat", "-z", "--", "."],
            "staged_diff": ["diff", "--cached", "--binary", "--", "."],
            "staged_diff_numstat": [
                "diff", "--cached", "--numstat", "-z", "--", "."
            ],
            "status": ["status", "--short"],
            "porcelain": ["status", "--porcelain=v1", "-z"],
            "staged_status": ["diff", "--cached", "--name-status", "-z", "--", "."],
            "untracked": ["ls-files", "--others", "--exclude-standard", "-z"],
            "tracked": ["ls-files", "-z"],
        }
        processes = {
            name: run_git_command(
                cwd, args, timeout=command_timeout(60 if "diff" in name else 30)
            )
            for name, args in commands.items()
        }
        processes["root"] = root_proc
        required = tuple(
            name
            for name in commands
            if name not in {"head", "head_tree", "head_symbolic"}
        )
        command_errors = sorted(
            name for name in required if processes[name].returncode != 0
        )
        for name, process in processes.items():
            output_bytes = len((process.stdout or "").encode("utf-8", errors="replace"))
            error_bytes = len((process.stderr or "").encode("utf-8", errors="replace"))
            if output_bytes + error_bytes > MAX_MANAGED_ARTIFACT_BYTES:
                command_errors.append(f"{name}_size_limit")
        head_proc = processes["head"]
        head = head_proc.stdout.strip() if head_proc.returncode == 0 else None
        head_tree_proc = processes["head_tree"]
        head_tree = (
            head_tree_proc.stdout.strip()
            if head_tree_proc.returncode == 0
            else None
        )
        symbolic_proc = processes["head_symbolic"]
        symbolic_head = (
            symbolic_proc.stdout.strip()
            if symbolic_proc.returncode == 0
            else None
        )
        if head is None:
            if symbolic_head:
                raw_head_identity = f"unborn:{symbolic_head}"
                head_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
            else:
                raw_head_identity = None
                command_errors.extend(["head", "head_tree"])
        else:
            raw_head_identity = head
            if head_tree is None:
                command_errors.append("head_tree")
        git_dir_proc = processes["git_dir"]
        git_dir = Path(git_dir_proc.stdout.strip()).resolve() if git_dir_proc.returncode == 0 and git_dir_proc.stdout.strip() else None
        repository_identity: dict[str, Any] | None = None
        if git_dir is not None:
            git_details = git_dir.stat()
            repository_identity = {
                "workspace_root": str(cwd),
                "repository_root": str(repo_root),
                "git_dir": str(git_dir),
                "file_id": [int(git_details.st_dev), int(git_details.st_ino)],
            }

        porcelain_proc = processes["porcelain"]
        status_items = (
            parse_porcelain_status(porcelain_proc.stdout or "")
            if porcelain_proc.returncode == 0
            else []
        )
        changed_paths = status_paths(status_items)
        staged_items = _parse_nul_name_status(
            processes["staged_status"].stdout or ""
        )
        staged_paths = status_paths(staged_items)
        diff_paths = _parse_nul_numstat_paths(
            processes["diff_numstat"].stdout or ""
        )
        staged_diff_paths = _parse_nul_numstat_paths(
            processes["staged_diff_numstat"].stdout or ""
        )
        untracked_paths = [
            _canonical_git_path(part)
            for part in (processes["untracked"].stdout or "").split("\0")
            if part
        ]
        tracked_paths = [
            _canonical_git_path(part)
            for part in (processes["tracked"].stdout or "").split("\0")
            if part
        ]
        index_entries = _parse_index_entries(processes["index_entries"].stdout or "")
        hashes = workspace_hashes(
            cwd,
            [*tracked_paths, *changed_paths, *staged_paths, *untracked_paths],
            deadline=deadline,
        )
        evidence_errors = sorted(
            rel
            for rel, evidence in hashes.items()
            if isinstance(evidence, Mapping)
            and (evidence.get("error") or evidence.get("skipped"))
        )
        evidence_complete = not evidence_errors and not command_errors
        diff_path = run_dir / f"git_{label}.diff"
        staged_diff_path = run_dir / f"git_{label}_staged.diff"
        status_path = run_dir / f"git_{label}_status.txt"
        porcelain_path = run_dir / f"git_{label}_porcelain.json"
        state_path = run_dir / f"git_{label}_state.json"
        untracked_path = run_dir / f"git_{label}_untracked.txt"
        hashes_path = run_dir / f"git_{label}_hashes.json"
        raw_diff = processes["diff"].stdout or processes["diff"].stderr or ""
        raw_staged_diff = processes["staged_diff"].stdout or processes["staged_diff"].stderr or ""
        raw_status = processes["status"].stdout or processes["status"].stderr or ""
        safe_diff = _scrub_exact_text(str(redact(raw_diff)), sensitive_values)
        safe_staged_diff = _scrub_exact_text(
            str(redact(raw_staged_diff)), sensitive_values
        )
        safe_status = _scrub_exact_text(str(redact(raw_status)), sensitive_values)
        safe_items = _scrub_guarded_value(status_items, sensitive_values)
        safe_untracked = _scrub_guarded_value(untracked_paths, sensitive_values)
        safe_hashes = _scrub_data_keyed_mapping(hashes, sensitive_values)
        raw_state = {
            "head": head,
            "head_identity": raw_head_identity,
            "head_tree": head_tree,
            "index_tree": (processes["index_tree"].stdout or "").strip() or None,
            "index_entries": index_entries,
            "repository_identity": repository_identity,
            "status_items": status_items,
            "staged_paths": staged_paths,
            "tracked_paths": tracked_paths,
            "command_errors": command_errors,
        }
        safe_state = _scrub_guarded_value(raw_state, sensitive_values)
        safe_state["index_entries"] = _scrub_data_keyed_mapping(
            index_entries, sensitive_values
        )
        artifact_payloads = (
            (diff_path, safe_diff),
            (staged_diff_path, safe_staged_diff),
            (status_path, safe_status),
            (
                porcelain_path,
                json.dumps(safe_items, ensure_ascii=False, indent=2),
            ),
            (
                untracked_path,
                "\n".join(safe_untracked) + ("\n" if safe_untracked else ""),
            ),
            (
                hashes_path,
                json.dumps(safe_hashes, ensure_ascii=False, indent=2),
            ),
            (
                state_path,
                json.dumps(safe_state, ensure_ascii=False, indent=2),
            ),
        )
        for artifact_path, safe_payload in artifact_payloads:
            _check_deadline(
                deadline,
                "Git evidence artifact writes exceeded the launch deadline.",
            )
            _atomic_write_text(artifact_path, safe_payload)
        return {
            "ok": evidence_complete,
            "label": label,
            "is_git_repo": True,
            "repository_identity": _scrub_guarded_value(
                repository_identity, sensitive_values
            ),
            "head": head,
            "head_tree": raw_state["head_tree"],
            "index_tree": raw_state["index_tree"],
            "diff_path": str(diff_path),
            "staged_diff_path": str(staged_diff_path),
            "status_path": str(status_path),
            "porcelain_path": str(porcelain_path),
            "state_path": str(state_path),
            "untracked_path": str(untracked_path),
            "hashes_path": str(hashes_path),
            "diff_bytes": len(safe_diff.encode("utf-8")),
            "status_bytes": len(safe_status.encode("utf-8")),
            "changed_paths": safe_items and status_paths(safe_items) or [],
            "staged_paths": _scrub_guarded_value(staged_paths, sensitive_values),
            "untracked_paths": safe_untracked,
            "changed_count": len(changed_paths),
            "untracked_count": len(untracked_paths),
            "hash_count": len(hashes),
            "evidence_complete": evidence_complete,
            "evidence_errors": _scrub_guarded_value(
                [*evidence_errors, *command_errors], sensitive_values
            ),
            "_raw_diff_text": raw_diff,
            "_raw_diff_paths": diff_paths,
            "_raw_staged_diff_text": raw_staged_diff,
            "_raw_staged_diff_paths": staged_diff_paths,
            "_raw_changed_paths": changed_paths,
            "_raw_status_items": status_items,
            "_raw_staged_paths": staged_paths,
            "_raw_tracked_paths": tracked_paths,
            "_raw_head": raw_head_identity,
            "_raw_head_tree": raw_state["head_tree"],
            "_raw_index_tree": raw_state["index_tree"],
            "_raw_index_entries": index_entries,
            "_raw_repository_identity": repository_identity,
            "_raw_untracked_paths": untracked_paths,
            "_raw_hashes": hashes,
            "_raw_evidence_complete": evidence_complete,
            "_raw_evidence_errors": [*evidence_errors, *command_errors],
        }
    except Exception as exc:
        return _failed_git_snapshot(
            label,
            exc,
            sensitive_values,
            is_git_repo=is_git_repo,
        )


def _launch_failure_error(code: str, message: str) -> RuntimeSecurityError:
    return _security_error(
        code,
        message,
        suggested_action="Review the blocked launch details and retry preflight.",
    )


def _record_blocked_launch(
    run_dir: Path,
    metadata: Mapping[str, Any],
    *,
    status: str,
    error: RuntimeSecurityError,
    sensitive_values: tuple[str, ...] = (),
    **updates: Any,
) -> dict[str, Any]:
    effective_deadline = _effective_deadline()
    deadline_expired = (
        effective_deadline is not None
        and time.monotonic() >= effective_deadline
    )
    proposed = _scrub_guarded_value(dict(metadata), sensitive_values)
    proposed.update(_scrub_guarded_value(updates, sensitive_values))
    timeout_primary = (
        status == "timed_out"
        or deadline_expired
        or _has_timeout_evidence(proposed)
    )
    terminal_status = "timed_out" if timeout_primary else status
    terminal_exit_code = 124 if timeout_primary else None
    if timeout_primary:
        proposed.update({"timed_out": True, "stop_reason": "timeout"})
    proposed.update(
        {
            "status": terminal_status,
            "finished_at": utc_now_iso(),
            "exit_code": terminal_exit_code,
            "security_error": _scrub_guarded_value(
                error.to_dict(), sensitive_values
            ),
            "terminal_state_count": 1,
        }
    )
    try:
        with artifact_lock(run_dir):
            try:
                current = read_metadata(run_dir)
            except (FileNotFoundError, OrchestratorError):
                current = {}
            if int(current.get("terminal_state_count") or 0) >= 1:
                return {
                    **current,
                    "persisted": True,
                    "persistence_state": "persisted",
                }
            blocked = _scrub_guarded_value(dict(metadata), sensitive_values)
            blocked.update(_scrub_guarded_value(current, sensitive_values))
            blocked.update(_scrub_guarded_value(updates, sensitive_values))
            blocked_timeout = (
                status == "timed_out"
                or deadline_expired
                or _has_timeout_evidence(blocked)
            )
            blocked_status = "timed_out" if blocked_timeout else status
            blocked_exit_code = 124 if blocked_timeout else None
            if blocked_timeout:
                blocked.update(
                    {"timed_out": True, "stop_reason": "timeout"}
                )
            blocked.update(
                {
                    "status": blocked_status,
                    "finished_at": utc_now_iso(),
                    "exit_code": blocked_exit_code,
                    "security_error": _scrub_guarded_value(
                        error.to_dict(), sensitive_values
                    ),
                    "terminal_state_count": 1,
                    "persisted": True,
                    "persistence_state": "persisted",
                }
            )
            _atomic_write_bytes(
                run_dir / "metadata.json", _metadata_bytes(blocked)
            )
            return blocked
    except Exception:
        return {
            **proposed,
            "persisted": False,
            "persistence_state": "degraded",
        }


def _has_timeout_evidence(*states: Mapping[str, Any]) -> bool:
    for state in states:
        if state.get("timed_out") is True or state.get("stop_reason") == "timeout":
            return True
        output_budget = state.get("output_budget")
        if (
            isinstance(output_budget, Mapping)
            and output_budget.get("stop_reason") == "timeout"
        ):
            return True
    return False


def _transaction_deadline_expired(
    *states: Mapping[str, Any], fallback: float | None = None
) -> bool:
    deadlines: list[float] = []
    for state in states:
        value = state.get("transaction_deadline_monotonic")
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            deadlines.append(float(value))
    if not deadlines and fallback is not None and math.isfinite(float(fallback)):
        deadlines.append(float(fallback))
    return bool(deadlines) and time.monotonic() >= min(deadlines)


def _terminal_cleanup_confirmed(metadata: Mapping[str, Any]) -> bool:
    return metadata.get("cleanup_state") == "cleanup_confirmed"


def _degraded_terminal_result(
    proposed: Mapping[str, Any], sensitive_values: tuple[str, ...] = ()
) -> dict[str, Any]:
    degraded = _scrub_guarded_value(dict(proposed), sensitive_values)
    degraded.update(
        {
            "terminal_state_count": 0,
            "persisted": False,
            "persistence_state": "degraded",
        }
    )
    if degraded.get("status") in {None, "succeeded"}:
        degraded.update(
            {
                "status": "failed",
                "exit_code": 1,
                "acceptance_status": "blocked_artifact_finalization",
                "finalization_state": "failed",
                "finalization_error": {
                    "code": "artifact_finalization_failed",
                    "message": "Execution artifacts could not be finalized safely.",
                },
            }
        )
    return degraded


def _persist_terminal_state(
    run_dir: Path,
    metadata: Mapping[str, Any],
    *,
    updates: Mapping[str, Any],
    event: Mapping[str, Any] | None = None,
    sensitive_values: tuple[str, ...] = (),
    remove_pid: bool = False,
    launch_deadline: float | None = None,
) -> dict[str, Any]:
    """Persist one terminal transition after process cleanup has concluded."""
    _ = remove_pid
    launch_deadline = _validated_finite_deadline(
        launch_deadline, label="Terminal launch deadline"
    )
    safe_updates = _scrub_guarded_value(dict(updates), sensitive_values)
    timeout_evidence = _has_timeout_evidence(metadata, safe_updates)
    deadline_exempt = safe_updates.get("status") == "stopped" or (
        not timeout_evidence
        and (
            safe_updates.get("status") == "cleanup_incomplete"
            or safe_updates.get("cleanup_state") == "cleanup_incomplete"
        )
    )

    def apply_launch_timeout(
        candidate: dict[str, Any], *, force: bool = False
    ) -> None:
        if (
            launch_deadline is not None
            and (force or time.monotonic() >= launch_deadline)
            and not deadline_exempt
        ):
            candidate.update(
                {
                    "status": "timed_out",
                    "timed_out": True,
                    "exit_code": 124,
                    "stop_reason": "timeout",
                }
            )

    apply_launch_timeout(safe_updates)
    proposed = _scrub_guarded_value(dict(metadata), sensitive_values)
    proposed.update(safe_updates)
    try:
        with _terminal_artifact_scope():
            terminal_deadline = _validated_finite_deadline(
                _effective_deadline(), label="Terminal persistence deadline"
            )
            with artifact_lock(run_dir, deadline=terminal_deadline):
                try:
                    current = _read_metadata_unlocked(
                        run_dir, deadline=terminal_deadline
                    )
                except FileNotFoundError:
                    current = {}
                if int(current.get("terminal_state_count") or 0) >= 1:
                    return _scrub_guarded_value(
                        {
                            **current,
                            "persisted": True,
                            "persistence_state": "persisted",
                        },
                        sensitive_values,
                    )
                terminal = _scrub_guarded_value(
                    {**dict(metadata), **current}, sensitive_values
                )
                terminal.update(safe_updates)
                terminal.update(
                    {
                        "terminal_state_count": 1,
                        "persisted": True,
                        "persistence_state": "persisted",
                    }
                )
                apply_launch_timeout(terminal)

                def launch_deadline_precommit() -> None:
                    if (
                        launch_deadline is not None
                        and time.monotonic() >= launch_deadline
                        and terminal.get("status") != "timed_out"
                        and not deadline_exempt
                    ):
                        raise TimeoutError(
                            "Terminal commit crossed the launch deadline."
                        )

                try:
                    _atomic_write_bytes(
                        run_dir / "metadata.json",
                        _metadata_bytes(terminal),
                        deadline=terminal_deadline,
                        precommit=launch_deadline_precommit,
                    )
                except TimeoutError:
                    apply_launch_timeout(terminal, force=True)
                    _atomic_write_bytes(
                        run_dir / "metadata.json",
                        _metadata_bytes(terminal),
                        deadline=terminal_deadline,
                    )
            if _terminal_cleanup_confirmed(terminal):
                try:
                    _unlink_managed_file(run_dir / "pid.txt")
                except Exception:
                    pass
            if event is not None:
                event_token = _TERMINAL_EVENT_APPEND.set(True)
                try:
                    persisted_event = dict(event)
                    if persisted_event.get("type") == "process_exited":
                        persisted_event.update(
                            {
                                "status": terminal.get("status"),
                                "exit_code": terminal.get("exit_code"),
                            }
                        )
                    append_event(
                        run_dir,
                        _scrub_guarded_value(
                            persisted_event, sensitive_values
                        ),
                    )
                except Exception:
                    pass
                finally:
                    _TERMINAL_EVENT_APPEND.reset(event_token)
            return terminal
    except Exception:
        return _degraded_terminal_result(proposed, sensitive_values)


def _persist_streaming_terminal_state(
    run_dir: Path,
    metadata: Mapping[str, Any],
    *,
    updates: Mapping[str, Any],
    events: tuple[Mapping[str, Any], ...] = (),
    sensitive_values: tuple[str, ...] = (),
    remove_pid: bool = False,
    launch_deadline: float | None = None,
) -> dict[str, Any]:
    """Scrub, secure, and publish one complete streaming terminal state."""
    _ = remove_pid
    launch_deadline = _validated_finite_deadline(
        launch_deadline, label="Streaming launch deadline"
    )
    safe_updates = _scrub_guarded_value(dict(updates), sensitive_values)
    lifecycle_stopped = safe_updates.get("status") == "stopped"
    lifecycle_timed_out = _has_timeout_evidence(metadata, safe_updates)
    lifecycle_cleanup_incomplete = (
        not lifecycle_timed_out
        and (
            safe_updates.get("status") == "cleanup_incomplete"
            or safe_updates.get("cleanup_state") == "cleanup_incomplete"
        )
    )

    def failed_updates() -> dict[str, Any]:
        failed = dict(safe_updates)
        timed_out = _has_timeout_evidence(metadata, failed)
        cleanup_incomplete = (
            failed.get("status") == "cleanup_incomplete"
            or failed.get("cleanup_state") == "cleanup_incomplete"
        )
        status = (
            "timed_out"
            if timed_out
            else "cleanup_incomplete"
            if cleanup_incomplete
            else "failed"
        )
        exit_code = failed.get("exit_code")
        if status == "timed_out":
            exit_code = 124
        elif status == "failed" and exit_code in {None, 0}:
            exit_code = 1
        failed.update(
            {
                "status": status,
                "finished_at": utc_now_iso(),
                "exit_code": exit_code,
                "acceptance_status": "blocked_artifact_finalization",
                "finalization_state": "failed",
                "finalization_error": {
                    "code": "artifact_finalization_failed",
                    "message": "Streaming execution artifacts could not be finalized safely.",
                },
            }
        )
        if timed_out:
            failed.update({"timed_out": True, "stop_reason": "timeout"})
        return failed

    def terminal_candidate(
        current: Mapping[str, Any], candidate_updates: Mapping[str, Any]
    ) -> dict[str, Any]:
        terminal = _scrub_guarded_value(
            {**dict(metadata), **dict(current)}, sensitive_values
        )
        terminal.update(
            _scrub_guarded_value(dict(candidate_updates), sensitive_values)
        )
        terminal.update(
            {
                "terminal_state_count": 1,
                "persisted": True,
                "persistence_state": "persisted",
            }
        )
        return terminal

    def apply_launch_deadline(
        terminal: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        if (
            launch_deadline is not None
            and (force or time.monotonic() >= launch_deadline)
            and not lifecycle_stopped
            and not lifecycle_cleanup_incomplete
        ):
            terminal.update(
                {
                    "status": "timed_out",
                    "timed_out": True,
                    "exit_code": 124,
                    "stop_reason": "timeout",
                }
            )
        return terminal

    def launch_deadline_precommit() -> None:
        if (
            launch_deadline is not None
            and time.monotonic() >= launch_deadline
            and not lifecycle_stopped
            and not lifecycle_cleanup_incomplete
        ):
            raise TimeoutError(
                "Streaming terminal commit crossed the launch deadline."
            )

    def append_terminal_events(
        terminal: Mapping[str, Any], candidate_events: tuple[Mapping[str, Any], ...]
    ) -> None:
        event_token = _TERMINAL_EVENT_APPEND.set(True)
        try:
            for event in candidate_events:
                persisted_event = dict(event)
                if persisted_event.get("type") == "process_exited":
                    persisted_event.update(
                        {
                            "status": terminal.get("status"),
                            "exit_code": terminal.get("exit_code"),
                        }
                    )
                try:
                    append_event(
                        run_dir,
                        _scrub_guarded_value(
                            persisted_event, sensitive_values
                        ),
                    )
                except Exception:
                    pass
        finally:
            _TERMINAL_EVENT_APPEND.reset(event_token)

    proposed = apply_launch_deadline(
        terminal_candidate({}, failed_updates())
    )
    with _terminal_artifact_scope():
        terminal_deadline = _validated_finite_deadline(
            _effective_deadline(), label="Streaming terminal deadline"
        )
        if terminal_deadline is None:
            return _degraded_terminal_result(proposed, sensitive_values)
        remaining = max(0.0, terminal_deadline - time.monotonic())
        normal_deadline = terminal_deadline - min(0.075, remaining / 3)
        prepared_paths: list[Path] = []
        terminal: dict[str, Any] | None = None
        won_transition = False
        try:
            with artifact_lock(run_dir, deadline=terminal_deadline):
                try:
                    current = _read_metadata_unlocked(
                        run_dir, deadline=terminal_deadline
                    )
                except FileNotFoundError:
                    current = {}
                if int(current.get("terminal_state_count") or 0) >= 1:
                    return _scrub_guarded_value(
                        {
                            **current,
                            "persisted": True,
                            "persistence_state": "persisted",
                        },
                        sensitive_values,
                    )

                failure_terminal = terminal_candidate(
                    current, failed_updates()
                )
                failure_path = _prepare_private_atomic_write(
                    run_dir / "metadata.json",
                    _metadata_bytes(failure_terminal),
                    deadline=terminal_deadline,
                )
                prepared_paths.append(failure_path)
                timeout_terminal: dict[str, Any] | None = None
                timeout_path: Path | None = None
                if (
                    launch_deadline is not None
                    and not lifecycle_stopped
                    and not lifecycle_cleanup_incomplete
                ):
                    timeout_terminal = apply_launch_deadline(
                        terminal_candidate(current, safe_updates), force=True
                    )
                    timeout_path = _prepare_private_atomic_write(
                        run_dir / "metadata.json",
                        _metadata_bytes(timeout_terminal),
                        deadline=terminal_deadline,
                    )
                    prepared_paths.append(timeout_path)

                normal_ready = False
                normal_token = _OPERATION_DEADLINE.set(normal_deadline)
                try:
                    _scrub_run_artifacts(run_dir, sensitive_values)
                    _secure_run_artifacts(run_dir)
                    _check_deadline(
                        normal_deadline,
                        "Streaming artifact preparation exceeded its terminal deadline.",
                    )
                    normal_ready = True
                except Exception:
                    normal_ready = False
                finally:
                    _OPERATION_DEADLINE.reset(normal_token)

                if normal_ready:
                    normal_terminal = terminal_candidate(
                        current, safe_updates
                    )
                    try:
                        _atomic_write_bytes(
                            run_dir / "metadata.json",
                            _metadata_bytes(normal_terminal),
                            deadline=terminal_deadline,
                            precommit=launch_deadline_precommit,
                        )
                        terminal = normal_terminal
                    except Exception:
                        terminal = None

                if terminal is None:
                    use_timeout = (
                        timeout_path is not None
                        and timeout_terminal is not None
                        and launch_deadline is not None
                        and time.monotonic() >= launch_deadline
                    )
                    if not use_timeout and timeout_path is not None:
                        try:
                            _replace_prepared_atomic_write(
                                failure_path,
                                run_dir / "metadata.json",
                                deadline=terminal_deadline,
                                precommit=launch_deadline_precommit,
                            )
                            prepared_paths.remove(failure_path)
                            terminal = failure_terminal
                        except TimeoutError:
                            use_timeout = True
                    if use_timeout:
                        assert timeout_path is not None
                        assert timeout_terminal is not None
                        _replace_prepared_atomic_write(
                            timeout_path,
                            run_dir / "metadata.json",
                            deadline=terminal_deadline,
                        )
                        prepared_paths.remove(timeout_path)
                        terminal = timeout_terminal
                    elif terminal is None:
                        _replace_prepared_atomic_write(
                            failure_path,
                            run_dir / "metadata.json",
                            deadline=terminal_deadline,
                        )
                        prepared_paths.remove(failure_path)
                        terminal = failure_terminal
                won_transition = True
        except Exception:
            return _degraded_terminal_result(proposed, sensitive_values)
        finally:
            for prepared_path in tuple(prepared_paths):
                try:
                    _discard_prepared_atomic_write(prepared_path)
                except Exception:
                    pass

        if not won_transition or terminal is None:
            return _degraded_terminal_result(proposed, sensitive_values)
        if _terminal_cleanup_confirmed(terminal):
            try:
                _unlink_managed_file(run_dir / "pid.txt")
            except Exception:
                pass
        terminal_events = events
        if terminal.get("finalization_state") == "failed":
            terminal_events = (
                {
                    "type": "process_exited",
                    "status": terminal.get("status"),
                    "exit_code": terminal.get("exit_code"),
                    "duration_ms": terminal.get("duration_ms"),
                    "finalization_state": "failed",
                },
            )
        append_terminal_events(terminal, terminal_events)
        return terminal


def _remaining_deadline(deadline: float | None, ceiling: float) -> float:
    if deadline is None:
        return ceiling
    return max(0.0, min(ceiling, deadline - time.monotonic()))


def _validated_finite_deadline(
    deadline: float | None, *, label: str
) -> float | None:
    if deadline is None:
        return None
    if (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
    ):
        raise OrchestratorError(f"{label} must be finite.")
    return float(deadline)


def _cleanup_attempt_deadline(
    record: _OwnedProcessTree, deadline: float | None
) -> float:
    requested = _validated_finite_deadline(
        _effective_deadline(deadline), label="Owned process cleanup deadline"
    )
    durable = _validated_finite_deadline(
        record.deadline, label="Owned process durable deadline"
    )
    assert durable is not None
    return min(durable, requested) if requested is not None else durable


def _owned_process_cleanup_deadline(
    process: subprocess.Popen[Any],
    deadline: float | None,
    *,
    timeout_evidence: bool,
) -> float | None:
    requested = _validated_finite_deadline(
        _effective_deadline(deadline), label="Owned process cleanup deadline"
    )
    record = _owned_process_record(process)
    if record is None:
        return requested
    if timeout_evidence:
        return float(record.deadline)
    return _cleanup_attempt_deadline(record, requested)


def _live_thread_names(
    threads: tuple[threading.Thread, ...] | list[threading.Thread],
) -> list[str]:
    return sorted(
        {
            thread.name
            for thread in threads
            if thread is not threading.current_thread() and thread.is_alive()
        }
    )


_OWNED_PROCESS_GENERATION_ATTRIBUTE = "_cc_owned_process_generation"
_OWNED_PROCESS_RESULT_ATTRIBUTE = "_cc_owned_process_cleanup_result"


def _owned_process_record(
    process: subprocess.Popen[Any],
) -> _OwnedProcessTree | None:
    generation = getattr(process, _OWNED_PROCESS_GENERATION_ATTRIBUTE, None)
    if not isinstance(generation, str):
        return None
    with _OWNED_PROCESS_TREES_LOCK:
        record = _OWNED_PROCESS_TREES.get(generation)
    if record is None or record.process is not process:
        return None
    return record


def _ensure_owned_process_record(
    process: subprocess.Popen[Any], *, deadline: float | None = None
) -> _OwnedProcessTree:
    existing = _owned_process_record(process)
    if existing is not None:
        return existing
    generation = uuid.uuid4().hex
    effective = _validated_finite_deadline(
        _effective_deadline(deadline), label="Owned process deadline"
    )
    record = _OwnedProcessTree(
        generation=generation,
        process=process,
        kind="uncontained",
        handle=0,
        deadline=float(
            effective if effective is not None else time.monotonic()
        ),
        owner_token=f"caller:{generation}",
        job_active_zero=True,
    )
    _publish_owned_process_record(record)
    return record


def _record_owner_matches(
    record: _OwnedProcessTree, owner_token: str | None
) -> bool:
    if owner_token is None:
        return record.state == "caller_owned"
    return (
        record.state == "cleanup_owned"
        and record.owner_token == owner_token
    )


def _publish_owned_process_record(record: _OwnedProcessTree) -> None:
    with _OWNED_PROCESS_TREES_LOCK:
        if record.generation in _OWNED_PROCESS_TREES:
            raise OrchestratorError("Owned process generation is already published.")
        setattr(
            record.process,
            _OWNED_PROCESS_GENERATION_ATTRIBUTE,
            record.generation,
        )
        _OWNED_PROCESS_TREES[record.generation] = record


def _remove_owned_process_record(record: _OwnedProcessTree) -> bool:
    removed = False
    with _OWNED_PROCESS_TREES_LOCK:
        if _OWNED_PROCESS_TREES.get(record.generation) is record:
            _OWNED_PROCESS_TREES.pop(record.generation, None)
            removed = True
    if (
        removed
        and getattr(
            record.process, _OWNED_PROCESS_GENERATION_ATTRIBUTE, None
        )
        == record.generation
    ):
        try:
            delattr(record.process, _OWNED_PROCESS_GENERATION_ATTRIBUTE)
        except AttributeError:
            pass
    if removed:
        try:
            setattr(
                record.process,
                _OWNED_PROCESS_RESULT_ATTRIBUTE,
                record.cleanup_result,
            )
        except (AttributeError, TypeError):
            pass
    return removed


def _detach_owned_process_record(process: subprocess.Popen[Any]) -> bool:
    """Release provisional launch ownership after a verified handoff."""
    record = _owned_process_record(process)
    if record is None:
        return False
    with record.lock:
        if record.state != "caller_owned" or record.termination_requested.is_set():
            return False
    removed = _remove_owned_process_record(record)
    if removed:
        try:
            delattr(process, _OWNED_PROCESS_RESULT_ATTRIBUTE)
        except AttributeError:
            pass
    return removed


def _create_windows_kill_job() -> int:
    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = (
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        )

    class IoCounters(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        ))

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = (
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(information), ctypes.sizeof(information)
    ):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise ctypes.WinError(error)
    return int(job)


def _close_windows_handle(handle: int) -> None:
    if not handle:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _assign_windows_job(process: subprocess.Popen[Any], job: int) -> None:
    import ctypes
    from ctypes import wintypes

    native_process = getattr(process, "_handle", None)
    if native_process is None:
        raise OrchestratorError("Owned Windows process handle is unavailable.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    if not kernel32.AssignProcessToJobObject(job, int(native_process)):
        raise ctypes.WinError(ctypes.get_last_error())


def _verify_windows_job_assignment(
    process: subprocess.Popen[Any], job: int
) -> None:
    import ctypes
    from ctypes import wintypes

    native_process = getattr(process, "_handle", None)
    if native_process is None:
        raise OrchestratorError("Owned Windows process handle is unavailable.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.IsProcessInJob.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    assigned = wintypes.BOOL()
    if not kernel32.IsProcessInJob(
        int(native_process), job, ctypes.byref(assigned)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not assigned.value:
        raise OrchestratorError(
            "Owned Windows process was not assigned to its exact Job Object."
        )


def _resume_windows_process(process: subprocess.Popen[Any]) -> None:
    import ctypes
    from ctypes import wintypes

    native_process = getattr(process, "_handle", None)
    if native_process is None:
        return
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = ctypes.c_long
    status = int(ntdll.NtResumeProcess(int(native_process)))
    if status < 0:
        raise OSError(status, "Owned Windows process could not be resumed.")


def _linux_parent_death_preexec(*, expected_parent_pid: int | None = None) -> None:
    parent_pid = (
        int(expected_parent_pid)
        if expected_parent_pid is not None
        else os.getppid()
    )
    if os.getppid() != parent_pid:
        os._exit(127)
        return
    if _LINUX_PRCTL is None or _LINUX_PRCTL(
        _LINUX_PR_SET_PDEATHSIG,
        int(signal.SIGKILL),
        0,
        0,
        0,
    ) != 0:
        os._exit(127)
        return
    if os.getppid() != parent_pid:
        os._exit(127)


def runtime_tree_containment_support() -> dict[str, Any]:
    if sys.platform == "win32":
        return {
            "supported": True,
            "mechanism": "windows_job_object_kill_on_close",
            "reason": None,
            "test_only": False,
        }
    fixture = _TEST_ONLY_RUNTIME_CANDIDATE.get()
    if (
        fixture is not None
        and fixture.source == "explicit_mock_stream_test_fixture"
    ):
        return {
            "supported": True,
            "mechanism": "test_fixture_process_group",
            "reason": None,
            "test_only": True,
        }
    return {
        "supported": False,
        "mechanism": None,
        "reason": (
            "Kernel-enforced whole-tree containment is unavailable; parent-death "
            "signals and process groups do not cover escaped descendants."
        ),
        "test_only": False,
    }


def _owned_process_popen(
    command: list[str],
    *,
    final_identity: ExecutableIdentity | None = None,
    ownership_deadline: float | None = None,
    **kwargs: Any,
) -> subprocess.Popen[Any]:
    """Create a process inside containment, with identity validation adjacent."""
    job: int | None = None
    record: _OwnedProcessTree | None = None
    process: subprocess.Popen[Any] | None = None
    launch_deadline = _validated_finite_deadline(
        _effective_deadline(), label="Owned process launch deadline"
    )
    owned_deadline = _validated_finite_deadline(
        ownership_deadline, label="Owned process deadline"
    )
    if owned_deadline is None:
        owned_deadline = (
            launch_deadline + WORKER_FINALIZATION_GRACE_SECONDS
            if launch_deadline is not None
            else None
        )
    if owned_deadline is None:
        owned_deadline = time.monotonic()
    if os.name == "nt":
        creationflags = int(kwargs.get("creationflags") or 0) | int(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )
        job = _create_windows_kill_job()
        creationflags |= int(
            getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        )
        kwargs["creationflags"] = creationflags
    else:
        kwargs["start_new_session"] = True
        if sys.platform.startswith("linux"):
            if _LINUX_PRCTL is None:
                raise OrchestratorError(
                    "Linux parent-death process containment is unavailable."
                )
            kwargs["preexec_fn"] = functools.partial(
                _linux_parent_death_preexec,
                expected_parent_pid=os.getpid(),
            )
    if final_identity is not None and not final_identity.matches_current_file():
        if job is not None:
            _close_windows_handle(job)
        raise _runtime_identity_changed(final_identity.canonical_path)
    try:
        process = subprocess.Popen(command, **kwargs)
        generation = uuid.uuid4().hex
        if os.name == "nt":
            assert job is not None
            _assign_windows_job(process, job)
            _verify_windows_job_assignment(process, job)
            record = _OwnedProcessTree(
                generation=generation,
                process=process,
                kind="windows",
                handle=job,
                deadline=float(owned_deadline),
                owner_token=f"caller:{generation}",
                assignment_verified=True,
            )
            _publish_owned_process_record(record)
            job = None
            _resume_windows_process(process)
        else:
            record = _OwnedProcessTree(
                generation=generation,
                process=process,
                kind="posix",
                handle=int(process.pid),
                deadline=float(owned_deadline),
                owner_token=f"caller:{generation}",
            )
            _publish_owned_process_record(record)
        return process
    except Exception as launch_error:
        if process is not None:
            cleanup_deadline = launch_deadline
            if record is not None:
                cleanup_deadline = _cleanup_attempt_deadline(
                    record, launch_deadline
                )
            elif cleanup_deadline is None:
                cleanup_deadline = float(owned_deadline)
            if not _bounded_process_cleanup(
                process, deadline=cleanup_deadline
            ):
                raise _OwnedCleanupPending(process) from launch_error
        raise
    finally:
        if job is not None:
            _close_windows_handle(job)


def _capture_windows_job_members(
    record: _OwnedProcessTree, *, attempt_deadline: float | None = None
) -> None:
    if record.kind != "windows" or record.members_captured:
        return
    try:
        member_pids = _windows_job_process_ids(
            record.handle, deadline=attempt_deadline
        )
    except Exception as exc:
        record.api_failures.append(f"job_membership_query: {exc}")
        record.members_captured = True
        return
    for pid in member_pids:
        if pid == int(record.process.pid):
            continue
        handle = _open_windows_process_sync_handle(pid)
        if handle is None:
            record.proof_failures.append(
                f"member_handle_unavailable:{pid}"
            )
            continue
        try:
            if not _windows_process_handle_in_job(handle, record.handle):
                record.proof_failures.append(
                    f"member_not_in_exact_job:{pid}"
                )
                _close_windows_handle(handle)
                continue
        except Exception as exc:
            record.api_failures.append(
                f"member_job_validation:{pid}: {exc}"
            )
            try:
                _close_windows_handle(handle)
            except Exception as close_exc:
                record.api_failures.append(
                    f"member_validation_close:{pid}: {close_exc}"
                )
            continue
        record.member_handles[pid] = handle
        with _PENDING_DESCENDANT_CLEANUPS_LOCK:
            _PENDING_DESCENDANT_CLEANUPS[pid] = record
    record.members_captured = True


def _terminate_owned_containment(
    process: subprocess.Popen[Any],
    *,
    force: bool,
    deadline: float | None = None,
    _owner_token: str | None = None,
) -> None:
    record = _owned_process_record(process)
    if record is None:
        return
    with record.lock:
        if not _record_owner_matches(record, _owner_token):
            return
        if record.kind == "windows":
            if not force or record.job_termination_attempted:
                return
            _capture_windows_job_members(
                record,
                attempt_deadline=_cleanup_attempt_deadline(record, deadline),
            )
            record.job_termination_attempted = True
            try:
                _terminate_windows_job(record.handle)
            except Exception as exc:
                record.api_failures.append(f"terminate_job: {exc}")
                raise
            return
        if record.root_reaped or record.process.poll() is not None:
            return
        try:
            live_group = os.getpgid(int(record.process.pid))
        except (ProcessLookupError, PermissionError, OSError):
            record.proof_failures.append("process_group_identity_unverified")
            return
        if live_group != int(record.handle):
            record.proof_failures.append("process_group_identity_mismatch")
            return
        if not force:
            try:
                os.killpg(record.handle, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            return
        try:
            os.killpg(record.handle, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _release_owned_containment(
    process: subprocess.Popen[Any], *, terminate_descendants: bool = False,
    deadline: float | None = None,
    threads: tuple[threading.Thread, ...] = (),
    _owner_token: str | None = None,
) -> bool:
    record = _owned_process_record(process)
    if record is None:
        return getattr(
            process, _OWNED_PROCESS_RESULT_ATTRIBUTE, None
        ) == "cleanup_confirmed"
    attempt_deadline = _cleanup_attempt_deadline(record, deadline)
    with record.lock:
        if not _record_owner_matches(record, _owner_token):
            return False
        record.root_reaped = process.poll() is not None
    try:
        return _finalize_owned_process_record(
            record,
            threads,
            terminate_descendants=terminate_descendants,
            owner_token=_owner_token,
            attempt_deadline=attempt_deadline,
        )
    except Exception as exc:
        with record.lock:
            record.api_failures.append(f"containment_release: {exc}")
            record.cleanup_result = "cleanup_failed"
            record.state = "cleanup_incomplete"
            record.completed.set()
        return False


def _mark_owned_cleanup_incomplete(
    process: subprocess.Popen[Any], reason: str
) -> None:
    record = _owned_process_record(process)
    if record is None:
        return
    with record.lock:
        if record.cleanup_result == "cleanup_confirmed":
            return
        if reason not in record.proof_failures:
            record.proof_failures.append(reason)
        record.cleanup_result = "cleanup_incomplete"
        record.state = "cleanup_incomplete"
        record.completed.set()


def _windows_job_process_ids(
    job: int, *, deadline: float | None = None
) -> list[int]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    capacity = 16
    deadline = _validated_finite_deadline(
        _effective_deadline(deadline), label="Windows Job membership deadline"
    )
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Windows Job membership query exceeded its deadline.")

        class ProcessIdList(ctypes.Structure):
            _fields_ = (
                ("NumberOfAssignedProcesses", wintypes.DWORD),
                ("NumberOfProcessIdsInList", wintypes.DWORD),
                ("ProcessIdList", ctypes.c_size_t * capacity),
            )

        members = ProcessIdList()
        returned = wintypes.DWORD()
        queried = kernel32.QueryInformationJobObject(
            job,
            3,
            ctypes.byref(members),
            ctypes.sizeof(members),
            ctypes.byref(returned),
        )
        assigned = int(members.NumberOfAssignedProcesses)
        listed = int(members.NumberOfProcessIdsInList)
        if queried and assigned <= listed <= capacity:
            return [
                int(members.ProcessIdList[index]) for index in range(listed)
            ]
        error = ctypes.get_last_error()
        if not queried and error != 234:
            raise ctypes.WinError(error)
        capacity = max(capacity * 2, assigned, listed, capacity + 1)


def _windows_job_active_processes(job: int) -> int:
    import ctypes
    from ctypes import wintypes

    class BasicAccountingInformation(ctypes.Structure):
        _fields_ = (
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    information = BasicAccountingInformation()
    if not kernel32.QueryInformationJobObject(
        job,
        1,
        ctypes.byref(information),
        ctypes.sizeof(information),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(information.ActiveProcesses)


def _open_windows_process_sync_handle(pid: int) -> int | None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(0x00101000, False, pid)
    if not handle:
        return None
    return int(handle)


def _windows_process_handle_in_job(handle: int, job: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.IsProcessInJob.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    assigned = wintypes.BOOL()
    if not kernel32.IsProcessInJob(handle, job, ctypes.byref(assigned)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(assigned.value)


def _wait_windows_handle_exit(handle: int, timeout_ms: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    result = int(
        kernel32.WaitForSingleObject(handle, max(0, int(timeout_ms)))
    )
    if result == 0x00000000:
        return True
    if result == 0x00000102:
        return False
    if result == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    raise OSError(result, "Unexpected Windows process wait result.")


def _terminate_windows_job(job: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    if not kernel32.TerminateJobObject(job, 1):
        raise ctypes.WinError(ctypes.get_last_error())


def _close_process_streams(
    process: subprocess.Popen[Any], *, _owner_token: str | None = None
) -> bool:
    record = _owned_process_record(process)
    if record is None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        return True
    with record.lock:
        if not _record_owner_matches(record, _owner_token):
            return False
        closed = True
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, name, None)
            if stream is None or name in record.streams_close_attempted:
                continue
            record.streams_close_attempted.add(name)
            try:
                stream.close()
            except (OSError, ValueError) as exc:
                record.api_failures.append(f"{name}_close: {exc}")
                closed = False
        return closed


def _wait_owned_root(
    record: _OwnedProcessTree,
    *,
    owner_token: str | None,
    attempt_deadline: float,
) -> bool:
    with record.lock:
        if not _record_owner_matches(record, owner_token):
            return False
        if record.root_reaped:
            return True
        process = record.process
    reaped = False
    wait_error: OSError | None = None
    try:
        process.wait(timeout=max(0.0, attempt_deadline - time.monotonic()))
        reaped = process.poll() is not None
    except subprocess.TimeoutExpired:
        pass
    except OSError as exc:
        wait_error = exc
    with record.lock:
        if not _record_owner_matches(record, owner_token):
            return False
        record.root_reaped = record.root_reaped or reaped
        if not record.root_reaped and wait_error is None:
            record.proof_failures.append("root_wait_deadline")
        if wait_error is not None:
            record.api_failures.append(f"root_wait: {wait_error}")
        return record.root_reaped


def _close_owned_readers(
    record: _OwnedProcessTree,
    threads: tuple[threading.Thread, ...],
    *,
    owner_token: str | None,
    attempt_deadline: float,
) -> bool:
    streams_closed = _close_process_streams(
        record.process, _owner_token=owner_token
    )
    for thread in threads:
        if thread is threading.current_thread() or not thread.is_alive():
            continue
        thread.join(timeout=max(0.0, attempt_deadline - time.monotonic()))
    with record.lock:
        if not _record_owner_matches(record, owner_token):
            return False
        threads_closed = all(
            thread is threading.current_thread() or not thread.is_alive()
            for thread in threads
        )
        if not threads_closed:
            record.proof_failures.append("reader_join_deadline")
        record.readers_closed = streams_closed and threads_closed
        return record.readers_closed


def _finish_windows_job_proof(
    record: _OwnedProcessTree, *, attempt_deadline: float
) -> None:
    for pid, handle in tuple(record.member_handles.items()):
        if pid not in record.member_wait_confirmed:
            try:
                confirmed = _wait_windows_handle_exit(
                    handle,
                    int(
                        max(0.0, attempt_deadline - time.monotonic())
                        * 1000
                    ),
                )
                if confirmed:
                    record.member_wait_confirmed.add(pid)
                else:
                    record.proof_failures.append(
                        f"member_wait_deadline:{pid}"
                    )
            except Exception as exc:
                record.api_failures.append(f"member_wait:{pid}: {exc}")
    try:
        record.job_active_zero = (
            _windows_job_active_processes(record.handle) == 0
        )
        if not record.job_active_zero:
            record.proof_failures.append("job_active_processes_nonzero")
    except Exception as exc:
        record.api_failures.append(f"job_active_process_query: {exc}")
        record.job_active_zero = False


def _close_windows_containment_handles(record: _OwnedProcessTree) -> None:
    for pid, handle in tuple(record.member_handles.items()):
        if pid in record.member_close_attempted:
            continue
        record.member_close_attempted.add(pid)
        try:
            _close_windows_handle(handle)
        except Exception as exc:
            record.api_failures.append(f"member_close:{pid}: {exc}")
    if not record.job_closed:
        try:
            _close_windows_handle(record.handle)
            record.job_closed = True
        except Exception as exc:
            record.api_failures.append(f"job_close: {exc}")
    if record.job_closed:
        with _PENDING_DESCENDANT_CLEANUPS_LOCK:
            for pid in tuple(record.member_handles):
                if _PENDING_DESCENDANT_CLEANUPS.get(pid) is record:
                    _PENDING_DESCENDANT_CLEANUPS.pop(pid, None)


def _finalize_owned_process_record(
    record: _OwnedProcessTree,
    threads: tuple[threading.Thread, ...],
    *,
    terminate_descendants: bool,
    owner_token: str | None,
    attempt_deadline: float,
) -> bool:
    attempt_deadline = float(
        _validated_finite_deadline(
            attempt_deadline, label="Owned process cleanup attempt deadline"
        )
    )
    with record.lock:
        if not _record_owner_matches(record, owner_token):
            return False
        if record.kind == "windows":
            if terminate_descendants and not record.job_termination_attempted:
                _capture_windows_job_members(
                    record, attempt_deadline=attempt_deadline
                )
                record.job_termination_attempted = True
                try:
                    _terminate_windows_job(record.handle)
                except Exception as exc:
                    record.api_failures.append(f"terminate_job: {exc}")
        kind = record.kind
    if kind == "windows":
        _finish_windows_job_proof(
            record, attempt_deadline=attempt_deadline
        )
    elif kind == "posix":
        with record.lock:
            if not _record_owner_matches(record, owner_token):
                return False
            try:
                os.killpg(record.handle, 0)
            except ProcessLookupError:
                record.job_active_zero = True
            except (PermissionError, OSError) as exc:
                record.api_failures.append(f"process_group_query: {exc}")
            else:
                record.job_active_zero = False
                if terminate_descendants and record.root_reaped:
                    record.proof_failures.append(
                        "process_group_alive_after_root_exit"
                    )
    else:
        with record.lock:
            if not _record_owner_matches(record, owner_token):
                return False
            record.job_active_zero = True
    _close_owned_readers(
        record,
        threads,
        owner_token=owner_token,
        attempt_deadline=attempt_deadline,
    )
    with record.lock:
        members_confirmed = (
            record.kind != "windows"
            or len(record.member_wait_confirmed) == len(record.member_handles)
        )
        proof_complete = (
            record.root_reaped
            and record.readers_closed
            and record.job_active_zero
            and members_confirmed
            and not record.api_failures
            and not record.proof_failures
        )
        if record.kind == "windows" and proof_complete:
            _close_windows_containment_handles(record)
        handles_closed = record.kind != "windows" or (
            record.job_closed
            and len(record.member_close_attempted)
            == len(record.member_handles)
        )
        confirmed = (
            proof_complete and handles_closed and not record.api_failures
        )
        if confirmed:
            record.cleanup_result = "cleanup_confirmed"
            record.state = "completed"
            _remove_owned_process_record(record)
        else:
            record.cleanup_result = (
                "cleanup_failed"
                if record.api_failures
                else "cleanup_incomplete"
            )
            record.state = "cleanup_incomplete"
        record.completed.set()
        return confirmed


def _bounded_process_cleanup(
    process: subprocess.Popen[Any],
    threads: tuple[threading.Thread, ...] = (),
    *,
    deadline: float | None = None,
    _owner_token: str | None = None,
) -> bool:
    requested_deadline = _validated_finite_deadline(
        _effective_deadline(deadline), label="Owned process cleanup deadline"
    )
    prior_result = getattr(process, _OWNED_PROCESS_RESULT_ATTRIBUTE, None)
    if prior_result is not None and _owned_process_record(process) is None:
        return prior_result == "cleanup_confirmed"
    record = _ensure_owned_process_record(process, deadline=requested_deadline)
    attempt_deadline = _cleanup_attempt_deadline(record, requested_deadline)
    with record.lock:
        if not _record_owner_matches(record, _owner_token):
            record.request_termination()
            completed = record.completed
            wait_deadline = attempt_deadline
        else:
            completed = None
            wait_deadline = attempt_deadline
            try:
                if process.poll() is None:
                    process.terminate()
            except OSError as exc:
                record.api_failures.append(f"root_terminate: {exc}")
    if completed is not None:
        completed.wait(max(0.0, wait_deadline - time.monotonic()))
        return record.cleanup_result == "cleanup_confirmed"
    try:
        _terminate_owned_containment(
            process,
            force=False,
            deadline=attempt_deadline,
            _owner_token=_owner_token,
        )
        _terminate_owned_containment(
            process,
            force=True,
            deadline=attempt_deadline,
            _owner_token=_owner_token,
        )
    except Exception:
        pass
    with record.lock:
        if _record_owner_matches(record, _owner_token):
            try:
                if process.poll() is None and record.kind != "windows":
                    process.kill()
            except OSError as exc:
                record.api_failures.append(f"root_kill: {exc}")
    _wait_owned_root(
        record,
        owner_token=_owner_token,
        attempt_deadline=attempt_deadline,
    )
    return _finalize_owned_process_record(
        record,
        threads,
        terminate_descendants=True,
        owner_token=_owner_token,
        attempt_deadline=attempt_deadline,
    )


def _runtime_execution_deadline(
    launch_deadline: float, started_monotonic: float
) -> float:
    remaining = max(0.0, launch_deadline - started_monotonic)
    finalization_reserve = min(
        remaining, 0.2, max(0.05, remaining * 0.2)
    )
    return launch_deadline - finalization_reserve


def _sleep_stream_worker_iteration(
    deadline: float, *, termination_requested: bool
) -> bool:
    remaining = _remaining_deadline(deadline, 0.05)
    if termination_requested and remaining <= 0:
        return False
    time.sleep(
        min(0.01 if termination_requested else 0.05, max(0.001, remaining))
    )
    return True


def _worker_cleanup_response_updates(
    *, timed_out: bool, stopped: bool
) -> dict[str, Any]:
    if timed_out:
        return {
            "timed_out": True,
            "stop_reason": "timeout",
            "exit_code": 124,
        }
    if stopped:
        return {"stop_reason": "user_requested"}
    return {}


def _owned_process_owner_main(
    record: _OwnedProcessTree,
    owner_token: str,
    attempt_deadline: float,
    ready: threading.Event,
    commit: threading.Event,
    cancel: threading.Event,
    accepted: threading.Event,
    threads: tuple[threading.Thread, ...],
    on_complete: Any,
) -> None:
    operation_token: contextvars.Token[float | None] | None = None
    try:
        deadline = float(
            _validated_finite_deadline(
                attempt_deadline, label="Cleanup owner deadline"
            )
        )
        operation_token = _OPERATION_DEADLINE.set(deadline)
        ready.set()
        while not commit.is_set() and not cancel.is_set():
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                cancel.set()
                return
            commit.wait(min(remaining, 0.05))
        if cancel.is_set():
            return
        with record.lock:
            if not _record_owner_matches(record, owner_token):
                return
        accepted.set()
        while not record.termination_requested.is_set():
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                break
            try:
                record.process.wait(timeout=min(remaining, 0.05))
                with record.lock:
                    if not _record_owner_matches(record, owner_token):
                        return
                    record.root_reaped = True
                break
            except subprocess.TimeoutExpired:
                continue
            except OSError as exc:
                with record.lock:
                    record.api_failures.append(f"owner_root_wait: {exc}")
                break
        if record.root_reaped:
            _finalize_owned_process_record(
                record,
                threads,
                terminate_descendants=True,
                owner_token=owner_token,
                attempt_deadline=deadline,
            )
        else:
            _bounded_process_cleanup(
                record.process,
                threads,
                deadline=deadline,
                _owner_token=owner_token,
            )
    except Exception as exc:
        with record.lock:
            record.api_failures.append(f"cleanup_owner: {exc}")
            record.cleanup_result = "cleanup_failed"
            record.state = "cleanup_incomplete"
            record.completed.set()
    finally:
        with record.lock:
            if (
                record.state == "cleanup_owned"
                and record.owner_token == owner_token
                and not record.completed.is_set()
            ):
                record.proof_failures.append("cleanup_owner_exited")
                record.cleanup_result = "cleanup_incomplete"
                record.state = "cleanup_incomplete"
                record.completed.set()
        try:
            on_complete(record)
        except Exception:
            pass
        if operation_token is not None:
            _OPERATION_DEADLINE.reset(operation_token)


def _start_owned_process_owner(
    record: _OwnedProcessTree,
    *,
    owner_name: str,
    threads: tuple[threading.Thread, ...] = (),
    active_run_id: str | None = None,
    request_cleanup: bool,
    attempt_deadline: float | None = None,
    on_complete: Any = lambda _record: None,
) -> bool:
    owner_token = f"cleanup:{record.generation}:{uuid.uuid4().hex}"
    ready = threading.Event()
    commit = threading.Event()
    cancel = threading.Event()
    accepted = threading.Event()
    owner: threading.Thread | None = None
    owner_started = False
    callback_lock = threading.Lock()
    callback_called = False
    transfer_deadline = _cleanup_attempt_deadline(
        record,
        record.deadline if attempt_deadline is None else attempt_deadline,
    )

    def complete_once(completed_record: _OwnedProcessTree) -> None:
        nonlocal callback_called
        with callback_lock:
            if callback_called:
                return
            callback_called = True
        with _ACTIVE_CLEANUP_OWNERS_LOCK:
            registered_owner = _ACTIVE_CLEANUP_OWNERS.get(owner_name)
            if registered_owner is owner or registered_owner is threading.current_thread():
                _ACTIVE_CLEANUP_OWNERS.pop(owner_name, None)
        try:
            on_complete(completed_record)
        except Exception:
            pass

    try:
        owner = threading.Thread(
            target=_owned_process_owner_main,
            args=(
                record,
                owner_token,
                transfer_deadline,
                ready,
                commit,
                cancel,
                accepted,
                threads,
                complete_once,
            ),
            name=owner_name,
            daemon=False,
        )
        with _ACTIVE_CLEANUP_OWNERS_LOCK:
            _ACTIVE_CLEANUP_OWNERS[owner_name] = owner
        owner.start()
        owner_started = True
        if not ready.wait(max(0.0, transfer_deadline - time.monotonic())):
            raise OrchestratorError("Cleanup owner did not become ready.")
        if active_run_id is not None:
            with _ACTIVE_WORKER_HANDLES_LOCK:
                existing = _ACTIVE_WORKER_HANDLES.get(active_run_id)
                if existing is not None and existing is not record.process:
                    raise OrchestratorError(
                        "A different worker already owns this active run id."
                    )
                _ACTIVE_WORKER_HANDLES[active_run_id] = record.process
        with record.lock:
            if record.state != "caller_owned":
                raise OrchestratorError(
                    "Owned process is no longer caller-owned for transfer."
                )
            record.owner_token = owner_token
            record.owner = owner
            record.state = "cleanup_owned"
            if request_cleanup:
                record.request_termination()
        commit.set()
        if not accepted.wait(
            max(0.0, transfer_deadline - time.monotonic())
        ):
            raise OrchestratorError("Cleanup owner did not accept ownership.")
        with record.lock:
            valid_owner = (
                record.owner is owner
                and owner.is_alive()
                and not record.completed.is_set()
            )
        if not valid_owner:
            raise OrchestratorError("Cleanup ownership was not retained.")
        return True
    except Exception:
        cancel.set()
        commit.set()
        if accepted.is_set():
            record.request_termination()
            if owner is not None and (
                owner.is_alive() and not record.completed.is_set()
            ):
                return True
        if active_run_id is not None:
            with _ACTIVE_WORKER_HANDLES_LOCK:
                if _ACTIVE_WORKER_HANDLES.get(active_run_id) is record.process:
                    _ACTIVE_WORKER_HANDLES.pop(active_run_id, None)
        with record.lock:
            if record.state == "cleanup_owned" and record.owner is owner:
                record.owner_token = f"caller:{record.generation}"
                record.owner = None
                record.state = "caller_owned"
        if (
            owner_started
            and owner is not None
            and owner is not threading.current_thread()
        ):
            owner.join(
                timeout=max(0.0, transfer_deadline - time.monotonic())
            )
        _bounded_process_cleanup(
            record.process, threads, deadline=transfer_deadline
        )
        if not owner_started:
            complete_once(record)
        elif owner is not None and not owner.is_alive():
            complete_once(record)
        return False


def _cleanup_pending_response(
    metadata: Mapping[str, Any],
    process: subprocess.Popen[Any],
    sensitive_values: tuple[str, ...] = (),
    threads: tuple[threading.Thread, ...] | list[threading.Thread] = (),
    *,
    response_updates: Mapping[str, Any] | None = None,
    attempt_deadline: float | None = None,
) -> dict[str, Any]:
    owned_threads = tuple(
        thread
        for thread in threads
        if thread is not threading.current_thread()
    )
    run_id = str(metadata.get("run_id") or "")
    artifact_root = metadata.get("artifact_root")
    run_dir = (
        Path(str(artifact_root)) / "runs" / run_id
        if artifact_root and RUN_ID_RE.match(run_id)
        else None
    )
    record = _owned_process_record(process)
    transaction_deadline = _validated_finite_deadline(
        _effective_deadline(), label="Cleanup transaction deadline"
    )
    inherited_deadline = _validated_finite_deadline(
        _effective_deadline(attempt_deadline), label="Cleanup response deadline"
    )
    safe_response_updates = _scrub_guarded_value(
        dict(response_updates or {}), sensitive_values
    )
    if record is None:
        record = _ensure_owned_process_record(
            process, deadline=inherited_deadline
        )
    timed_out_cleanup = _has_timeout_evidence(
        metadata, safe_response_updates
    ) or _transaction_deadline_expired(
        metadata, fallback=transaction_deadline
    )
    if timed_out_cleanup:
        safe_response_updates.update(
            _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
        )
    cleanup_deadline = _owned_process_cleanup_deadline(
        process,
        inherited_deadline,
        timeout_evidence=timed_out_cleanup,
    )
    assert cleanup_deadline is not None
    owner_name = f"cc-cleanup-owner-{run_id or process.pid}-{uuid.uuid4().hex[:8]}"
    pending_state = {
        **safe_response_updates,
        "status": "cleanup_pending",
        "cleanup_state": "durable_owner_pending",
        "cleanup_owner": owner_name,
        "owned_process_pid": process.pid,
        "live_cleanup_threads": _live_thread_names(owned_threads),
        "terminal_state_count": 0,
        "persisted": True,
        "persistence_state": "persisted",
    }
    current = {**dict(metadata), **pending_state}
    if run_dir is not None:
        token = _OPERATION_DEADLINE.set(cleanup_deadline)
        try:
            _atomic_write_text(
                run_dir / "pid.txt",
                str(process.pid),
                deadline=cleanup_deadline,
            )
            current = update_metadata(run_dir, **pending_state)
            append_event(
                run_dir,
                {
                    "type": "cleanup_pending",
                    "status": "cleanup_pending",
                    "cleanup_owner": owner_name,
                    "owned_process_pid": process.pid,
                    "live_cleanup_threads": pending_state[
                        "live_cleanup_threads"
                    ],
                },
            )
        except Exception:
            current.update(
                {"persisted": False, "persistence_state": "degraded"}
            )
        finally:
            _OPERATION_DEADLINE.reset(token)

    def terminal_cleanup_state(complete: bool) -> dict[str, Any]:
        timed_out = _has_timeout_evidence(current, safe_response_updates)
        terminal_status = (
            "timed_out"
            if timed_out
            else "cleanup_incomplete"
            if not complete
            else "blocked_runtime_launch"
        )
        terminal = {
            **safe_response_updates,
            "status": terminal_status,
            "cleanup_state": (
                "cleanup_confirmed" if complete else "cleanup_incomplete"
            ),
            "cleanup_owner": owner_name,
            "owned_process_pid": process.pid,
            "live_cleanup_threads": (
                [] if complete else _live_thread_names(owned_threads)
            ),
            "finished_at": utc_now_iso(),
            "exit_code": 124 if timed_out else None,
            "terminal_state_count": 1,
            "persisted": True,
            "persistence_state": "persisted",
        }
        if timed_out:
            terminal.update(
                {"timed_out": True, "stop_reason": "timeout"}
            )
        reconciled = {**current, **terminal}
        if run_dir is None:
            return reconciled
        return _persist_terminal_state(
            run_dir,
            current,
            updates=terminal,
            event={
                "type": (
                    "cleanup_confirmed"
                    if complete
                    else "cleanup_incomplete"
                ),
                "status": terminal_status,
                "owned_process_pid": process.pid,
            },
            sensitive_values=sensitive_values,
            remove_pid=complete,
        )

    terminal_result: list[dict[str, Any]] = []

    def owner_complete(completed_record: _OwnedProcessTree) -> None:
        terminal_result.append(
            terminal_cleanup_state(
                completed_record.cleanup_result == "cleanup_confirmed"
            )
        )

    if record is not None and record.completed.is_set():
        return _scrub_guarded_value(
            terminal_cleanup_state(
                record.cleanup_result == "cleanup_confirmed"
            ),
            sensitive_values,
        )
    if cleanup_deadline is not None and time.monotonic() >= cleanup_deadline:
        complete = _bounded_process_cleanup(
            process, owned_threads, deadline=cleanup_deadline
        )
        return _scrub_guarded_value(
            terminal_cleanup_state(complete), sensitive_values
        )

    _start_owned_process_owner(
        record,
        owner_name=owner_name,
        threads=owned_threads,
        request_cleanup=True,
        attempt_deadline=cleanup_deadline,
        on_complete=owner_complete,
    )
    return _scrub_guarded_value(
        terminal_result[-1] if terminal_result else current,
        sensitive_values,
    )


def _complete_isolated_worker_cleanup(
    run_dir: Path,
    metadata: Mapping[str, Any],
    pending: _OwnedCleanupPending,
) -> dict[str, Any]:
    """Keep the isolated worker responsible until process and threads are gone."""
    metadata = {**dict(metadata), **pending.response_updates}
    process = pending.process
    threads = tuple(
        thread
        for thread in pending.threads
        if thread is not threading.current_thread()
    )
    inherited_deadline = _effective_deadline()
    record = _owned_process_record(process)
    timed_out_cleanup = _has_timeout_evidence(
        metadata
    ) or _transaction_deadline_expired(
        metadata, fallback=_effective_deadline()
    )
    if timed_out_cleanup:
        metadata.update(
            _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
        )
    cleanup_deadline = _owned_process_cleanup_deadline(
        process,
        inherited_deadline,
        timeout_evidence=timed_out_cleanup,
    )
    if cleanup_deadline is None:
        cleanup_deadline = time.monotonic()
    live_names = _live_thread_names(threads)
    durable_token = _OPERATION_DEADLINE.set(cleanup_deadline)
    try:
        pending_state = {
            "status": "cleanup_pending",
            "cleanup_state": "owned_worker_cleanup",
            "owned_process_pid": process.pid,
            "live_cleanup_threads": live_names,
            "terminal_state_count": 0,
            "persisted": True,
            "persistence_state": "persisted",
        }
        try:
            _atomic_write_text(
                run_dir / "pid.txt",
                str(process.pid),
                deadline=cleanup_deadline,
            )
            current = update_metadata(run_dir, **pending_state)
            append_event(
                run_dir,
                {
                    "type": "cleanup_pending",
                    "status": "cleanup_pending",
                    "owned_process_pid": process.pid,
                    "live_cleanup_threads": live_names,
                },
            )
        except Exception:
            current = {**dict(metadata), **pending_state}
            current.update(
                {"persisted": False, "persistence_state": "degraded"}
            )
    finally:
        _OPERATION_DEADLINE.reset(durable_token)

    complete = _bounded_process_cleanup(
        process, threads, deadline=cleanup_deadline
    )
    timed_out = _has_timeout_evidence(metadata, current)
    terminal_status = (
        "timed_out"
        if timed_out
        else "cleanup_incomplete"
        if not complete
        else "failed"
    )
    confirmed_updates = {
        "status": terminal_status,
        "cleanup_state": (
            "cleanup_confirmed" if complete else "cleanup_incomplete"
        ),
        "owned_process_pid": process.pid,
        "live_cleanup_threads": (
            [] if complete else _live_thread_names(threads)
        ),
        "finished_at": utc_now_iso(),
        "exit_code": 124 if timed_out else None if not complete else 1,
        "terminal_state_count": 1,
        "persisted": True,
        "persistence_state": "persisted",
    }
    if timed_out:
        confirmed_updates.update(
            {"timed_out": True, "stop_reason": "timeout"}
        )
    elif complete:
        confirmed_updates.update(
            {
                "acceptance_status": "blocked_artifact_finalization",
                "finalization_state": "failed",
                "finalization_error": {
                    "code": "artifact_finalization_failed",
                    "message": "Streaming execution artifacts could not be finalized safely.",
                },
            }
        )
    return _persist_terminal_state(
        run_dir,
        current,
        updates=confirmed_updates,
        event={
            "type": (
                "cleanup_confirmed" if complete else "cleanup_incomplete"
            ),
            "status": terminal_status,
            "owned_process_pid": process.pid,
        },
        remove_pid=complete,
    )


def _terminate_owned_process(
    process: subprocess.Popen[Any], *, deadline: float | None = None
) -> bool:
    effective_deadline = _validated_finite_deadline(
        _effective_deadline(deadline), label="Owned process termination deadline"
    )
    record = _owned_process_record(process)
    cleanup_deadline = (
        _cleanup_attempt_deadline(record, effective_deadline)
        if record is not None
        else effective_deadline
    )
    return _bounded_process_cleanup(process, deadline=cleanup_deadline)


def _output_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", errors="replace")


def _prefer_complete_output(partial: Any, drained: Any) -> bytes:
    partial_bytes = _output_bytes(partial)
    drained_bytes = _output_bytes(drained)
    if not partial_bytes:
        return drained_bytes
    if not drained_bytes:
        return partial_bytes
    if partial_bytes in drained_bytes:
        return drained_bytes
    if drained_bytes in partial_bytes:
        return partial_bytes
    return partial_bytes + drained_bytes


def _terminate_and_drain_owned_process(
    process: subprocess.Popen[Any],
    *,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    record = _owned_process_record(process)
    if record is not None:
        deadline = _cleanup_attempt_deadline(record, deadline)
    else:
        deadline = _validated_finite_deadline(
            _effective_deadline(deadline),
            label="Owned process drain deadline",
        )
    _terminate_owned_containment(process, force=False, deadline=deadline)
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
    _terminate_owned_containment(process, force=True, deadline=deadline)
    try:
        remaining = _remaining_deadline(deadline, 5.0)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 0)
        stdout, stderr = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired as timeout_error:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        remaining = _remaining_deadline(deadline, 5.0)
        if remaining > 0:
            try:
                stdout, stderr = process.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
        else:
            stdout, stderr = b"", b""
        stdout = _prefer_complete_output(timeout_error.output, stdout)
        stderr = _prefer_complete_output(timeout_error.stderr, stderr)
    if process.poll() is None:
        _retain_worker_handle(
            f"cleanup-{process.pid}-{uuid.uuid4().hex}",
            process,
            request_cleanup=True,
        )
    else:
        _close_process_streams(process)
        _release_owned_containment(
            process,
            terminate_descendants=True,
            deadline=deadline,
        )
    return _output_bytes(stdout), _output_bytes(stderr)


def _retain_worker_handle(
    run_id: str,
    worker: subprocess.Popen[Any],
    *,
    request_cleanup: bool = False,
) -> bool:
    with _ACTIVE_WORKER_HANDLES_LOCK:
        if any(handle is worker for handle in _ACTIVE_WORKER_HANDLES.values()):
            return True

    record = _owned_process_record(worker)
    if record is None:
        record = _ensure_owned_process_record(
            worker, deadline=_effective_deadline()
        )
    owner_name = f"cc-worker-reaper-{run_id}"

    def release_registries(_record: _OwnedProcessTree) -> None:
        if _record.cleanup_result == "cleanup_confirmed":
            with _ACTIVE_WORKER_HANDLES_LOCK:
                if _ACTIVE_WORKER_HANDLES.get(run_id) is worker:
                    _ACTIVE_WORKER_HANDLES.pop(run_id, None)
        with _ACTIVE_CLEANUP_OWNERS_LOCK:
            if _ACTIVE_CLEANUP_OWNERS.get(owner_name) is threading.current_thread():
                _ACTIVE_CLEANUP_OWNERS.pop(owner_name, None)

    return _start_owned_process_owner(
        record,
        owner_name=owner_name,
        active_run_id=run_id,
        request_cleanup=request_cleanup,
        on_complete=release_registries,
    )


def _spawn_detached_internal_worker(
    command: list[str], *, ownership_deadline: float, **kwargs: Any
) -> subprocess.Popen[bytes]:
    if not command or not Path(command[0]).is_absolute():
        raise OrchestratorError(
            "The detached internal worker executable must be absolute."
        )
    expected_python = os.path.normcase(str(Path(sys.executable).resolve()))
    actual_python = os.path.normcase(str(Path(command[0]).resolve()))
    if actual_python != expected_python or kwargs.get("shell"):
        raise OrchestratorError(
            "The detached internal worker command is not approved."
        )
    worker = subprocess.Popen(command, **kwargs)
    try:
        _ensure_owned_process_record(worker, deadline=ownership_deadline)
    except Exception:
        try:
            worker.terminate()
            worker.wait(
                timeout=max(0.001, ownership_deadline - time.monotonic())
            )
        except (OSError, subprocess.SubprocessError):
            try:
                worker.kill()
            except OSError:
                pass
        raise
    return worker


def _register_background_worker_watcher(
    run_id: str, worker: subprocess.Popen[Any]
) -> bool:
    if worker.poll() is not None:
        return False

    def reap_worker() -> None:
        try:
            worker.wait()
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            _close_process_streams(worker)
            with _ACTIVE_WORKER_HANDLES_LOCK:
                if _ACTIVE_WORKER_HANDLES.get(run_id) is worker:
                    _ACTIVE_WORKER_HANDLES.pop(run_id, None)

    try:
        watcher = threading.Thread(
            target=reap_worker,
            name=f"cc-worker-watcher-{run_id}",
            daemon=True,
        )
    except Exception:
        return False
    with _ACTIVE_WORKER_HANDLES_LOCK:
        existing = _ACTIVE_WORKER_HANDLES.get(run_id)
        if existing is not None and existing is not worker:
            return False
        _ACTIVE_WORKER_HANDLES[run_id] = worker
    try:
        watcher.start()
    except Exception:
        with _ACTIVE_WORKER_HANDLES_LOCK:
            if _ACTIVE_WORKER_HANDLES.get(run_id) is worker:
                _ACTIVE_WORKER_HANDLES.pop(run_id, None)
        return False
    return True


def _wait_for_worker_handoff_ready(
    run_dir: Path,
    worker: subprocess.Popen[Any],
    *,
    deadline: float,
) -> dict[str, Any]:
    while time.monotonic() < deadline:
        if worker.poll() is not None:
            raise OrchestratorError(
                "The isolated worker exited before handoff readiness."
            )
        latest = read_metadata(run_dir)
        launch = latest.get("worker_launch")
        if (
            latest.get("worker_pid") == worker.pid
            and str(latest.get("status") or "") in {"starting", "running"}
            and isinstance(launch, Mapping)
            and launch.get("nonce_consumed") is True
            and launch.get("controller_handoff") == "ready"
        ):
            return latest
        time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    raise TimeoutError("The isolated worker handoff did not become ready.")


def _accept_worker_handoff(
    run_dir: Path,
    worker: subprocess.Popen[Any],
    *,
    launch_nonce: str,
) -> dict[str, Any]:
    with artifact_lock(run_dir):
        metadata = read_metadata(run_dir)
        launch = metadata.get("worker_launch")
        if (
            worker.poll() is not None
            or metadata.get("worker_pid") != worker.pid
            or str(metadata.get("status") or "") not in {"starting", "running"}
            or not isinstance(launch, Mapping)
            or launch.get("nonce_consumed") is not True
            or launch.get("controller_handoff") != "ready"
        ):
            raise OrchestratorError(
                "The isolated worker handoff is no longer valid."
            )
        try:
            expected_identity = ProcessIdentity.from_dict(
                metadata.get("worker_process_identity")
            )
        except (TypeError, ValueError) as exc:
            raise OrchestratorError(
                "The isolated worker handoff identity is invalid."
            ) from exc
        if expected_identity.pid != worker.pid:
            raise OrchestratorError(
                "The isolated worker handoff identity does not match its owned handle."
            )
        identity_check = compare_process_identity(
            expected_identity, expected_launch_nonce=launch_nonce
        )
        if identity_check.state != "match":
            raise OrchestratorError(
                "The isolated worker changed during handoff."
            )
        accepted_launch = dict(launch)
        accepted_launch.update(
            {
                "controller_handoff": "accepted",
                "controller_handoff_accepted_at": utc_now_iso(),
            }
        )
        metadata["worker_launch"] = accepted_launch

        def handoff_precommit() -> None:
            if worker.poll() is not None or expected_identity.pid != worker.pid:
                raise OrchestratorError(
                    "The isolated worker exited during handoff acceptance."
                )
            final_check = compare_process_identity(
                expected_identity, expected_launch_nonce=launch_nonce
            )
            if final_check.state != "match":
                raise OrchestratorError(
                    "The isolated worker changed during handoff acceptance."
                )

        _atomic_write_bytes(
            run_dir / "metadata.json",
            _metadata_bytes(metadata),
            precommit=handoff_precommit,
        )
        return metadata


def _initialize_prepared_run(
    prepared: PreparedWorkerLaunch,
) -> tuple[Path, dict[str, Any]]:
    metadata = prepared.metadata()
    transaction_deadline = _effective_deadline()
    if transaction_deadline is not None:
        metadata["transaction_deadline_monotonic"] = transaction_deadline
    run_id = str(metadata["run_id"])
    artifact_root = Path(str(metadata["artifact_root"]))
    run_dir = artifact_root / "runs" / run_id
    if run_dir.exists():
        raise FileExistsError(run_dir)
    _set_private_directory(run_dir)
    metadata.update(
        {
            "status": "starting" if prepared.mode == "streaming" else metadata.get("status"),
            "runtime_launch": prepared.launch_spec.public_metadata(),
            "stdout_path": str(run_dir / "stdout.txt"),
            "stderr_path": str(run_dir / "stderr.txt"),
            "events_path": str(run_dir / "events.ndjson"),
            "worker_pid": None,
            "child_pid": None,
        }
    )
    if metadata["status"] is None:
        metadata.pop("status")
    if prepared.mode == "streaming":
        metadata["worker_launch"] = {
            "nonce_consumed": False,
            "nonce_expires_at": (
                datetime.now(timezone.utc)
                + timedelta(seconds=INTERNAL_WORKER_NONCE_TTL_SECONDS)
            ).isoformat(),
            "start_gate": "closed",
            "controller_handoff": (
                "team_managed"
                if prepared.admission_reservation is not None
                else "pending"
            ),
        }
        metadata["controller_pid"] = os.getpid()
        if prepared.admission_reservation is not None:
            metadata["team_id"] = prepared.admission_reservation.team_id
            metadata["team_manifest_path"] = str(
                TEAMS_DIR / f"{prepared.admission_reservation.team_id}.json"
            )
    for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
        _atomic_write_text(run_dir / name, "")
    register_run_dir(
        run_id,
        run_dir,
        Path(str(metadata["workspace_root"])),
        artifact_root,
    )
    if prepared.mode == "one_shot":
        git_before_raw = capture_git_snapshot(
            run_dir,
            Path(str(metadata["workspace_root"])),
            "before",
            prepared.sensitive_values,
        )
        object.__setattr__(prepared, "_preflight_git_before", git_before_raw)
        metadata["git_before"] = _git_snapshot_projection(
            git_before_raw, prepared.sensitive_values
        )
    else:
        metadata["git_before"] = {
            "ok": False,
            "label": "before",
            "evidence_complete": False,
            "state": "pending_worker_capture",
        }
    _scrub_run_artifacts(run_dir, prepared.sensitive_values)
    _secure_run_artifacts(run_dir)
    write_metadata(run_dir, metadata)
    if prepared.mode == "streaming":
        append_event(
            run_dir,
            {
                "type": "run_started",
                "status": "starting",
                "role": metadata.get("role"),
                "task_type": metadata.get("task_type"),
            },
        )
    return run_dir, metadata


def _publish_latest_run(metadata: Mapping[str, Any]) -> None:
    run_id = str(metadata["run_id"])
    runs_root = Path(str(metadata["runs_root"]))
    runs_root.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(runs_root / "latest.txt", run_id)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(RUNS_DIR / "latest.txt", run_id)


def _append_unsafe_runtime_event(
    prepared: PreparedWorkerLaunch, run_dir: Path
) -> None:
    if prepared.launch_spec.trust_level != "local_unsafe":
        return
    append_event(
        run_dir,
        _scrub_guarded_value(
            {
                "type": "unsafe_runtime_approved",
                "severity": "high",
                "trust_level": "local_unsafe",
                "acceptance_status": "pending_controller_review",
                "message": "A locally approved unsafe runtime is about to start.",
            },
            prepared.sensitive_values,
        ),
    )


def _start_one_shot_launch_inner(
    prepared: PreparedWorkerLaunch,
    run_dir: Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    spec = prepared.launch_spec
    identity = spec.executable_identity
    if not identity.matches_current_file():
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_identity",
            error=_runtime_identity_changed(identity.canonical_path),
        )
    command = _runtime_command(identity, spec.arguments)
    process: subprocess.Popen[bytes] | None = None
    timed_out = False
    if not identity.matches_current_file():
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_identity",
            error=_runtime_identity_changed(identity.canonical_path),
        )
    try:
        _append_unsafe_runtime_event(prepared, run_dir)
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed",
                "Unsafe-runtime security event could not be persisted.",
            ),
        )
    try:
        git_before_raw = prepared._preflight_git_before
        object.__setattr__(prepared, "_preflight_git_before", None)
        if git_before_raw is None:
            git_before_raw = capture_git_snapshot(
                run_dir,
                Path(str(metadata["workspace_root"])),
                "before",
                prepared.sensitive_values,
            )
        if (
            git_before_raw.get("ok") is not True
            or git_before_raw.get("evidence_complete") is not True
            or git_before_raw.get("_raw_evidence_complete") is not True
        ):
            raise OrchestratorError("Pre-launch Git evidence is unavailable.")
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed",
                "Pre-launch Git evidence could not be persisted safely.",
            ),
        )
    try:
        pinned_scope = _pin_write_scope_policy(
            Path(str(metadata["workspace_root"]))
        )
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "write_scope_invalid",
                "The write-scope policy could not be pinned before runtime launch.",
            ),
        )
    launch_deadline = _effective_deadline()
    if launch_deadline is None:
        raise OrchestratorError("One-shot launch deadline is unavailable.")
    try:
        process = _owned_process_popen(
            command,
            final_identity=identity,
            cwd=spec.cwd,
            env=dict(spec.environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except RuntimeSecurityError as error:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_identity",
            error=error,
        )
    except TimeoutError:
        timeout_updates = _worker_cleanup_response_updates(
            timed_out=True, stopped=False
        )
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="timed_out",
            error=_launch_failure_error(
                "runtime_launch_timeout",
                "Runtime process creation exceeded the launch deadline.",
            ),
            **timeout_updates,
        )
    except OSError:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "runtime_launch_failed", "The approved runtime process could not be started."
            ),
        )
    try:
        started_monotonic = time.monotonic()
        runtime_deadline = _runtime_execution_deadline(
            launch_deadline, started_monotonic
        )
        timeout_cleanup_deadline = _owned_process_cleanup_deadline(
            process,
            launch_deadline,
            timeout_evidence=True,
        )
        if timeout_cleanup_deadline is None:
            timeout_cleanup_deadline = launch_deadline
        try:
            child_identity = capture_process_identity(
                process.pid, launch_nonce=spec.launch_nonce
            )
            _validate_started_identity(
                child_identity, identity, process_kind="runtime child"
            )
            _check_deadline(
                launch_deadline,
                "Runtime identity validation exceeded the launch deadline.",
            )
        except TimeoutError:
            timed_out = True
            timeout_updates = _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
            if not _terminate_owned_process(
                process, deadline=timeout_cleanup_deadline
            ):
                raise _OwnedCleanupPending(
                    process,
                    response_updates=timeout_updates,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="timed_out",
                error=_launch_failure_error(
                    "runtime_launch_timeout",
                    "Runtime identity validation exceeded the launch deadline.",
                ),
                child_pid=process.pid,
                **timeout_updates,
            )
        except (OSError, TypeError, ValueError, RuntimeSecurityError) as exc:
            if not _terminate_owned_process(process, deadline=launch_deadline):
                return _cleanup_pending_response(
                    metadata, process, prepared.sensitive_values
                )
            error = (
                exc
                if isinstance(exc, RuntimeSecurityError)
                else _process_identity_unverified(process.pid, "runtime child")
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_identity",
                error=error,
                child_pid=process.pid,
            )
        try:
            artifact_token = _OPERATION_DEADLINE.set(runtime_deadline)
            try:
                metadata = update_metadata(
                    run_dir,
                    child_pid=process.pid,
                    child_process_identity=child_identity.to_dict(),
                )
            finally:
                _OPERATION_DEADLINE.reset(artifact_token)
        except Exception:
            deadline_expired = time.monotonic() >= launch_deadline
            failure_updates: dict[str, Any] = {
                "child_pid": process.pid,
                "child_process_identity": child_identity.to_dict(),
            }
            if deadline_expired:
                timed_out = True
                failure_updates.update(
                    {"timed_out": True, "stop_reason": "timeout"}
                )
            if not _terminate_owned_process(
                process,
                deadline=(
                    timeout_cleanup_deadline
                    if deadline_expired
                    else launch_deadline
                ),
            ):
                return _cleanup_pending_response(
                    metadata,
                    process,
                    prepared.sensitive_values,
                    response_updates=failure_updates,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "artifact_write_failed",
                    "Child process identity metadata could not be persisted.",
                ),
                **failure_updates,
            )
        if not identity.matches_current_file():
            if not _terminate_owned_process(process, deadline=launch_deadline):
                return _cleanup_pending_response(
                    metadata, process, prepared.sensitive_values
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_identity",
                error=_runtime_identity_changed(identity.canonical_path),
                child_pid=process.pid,
                child_process_identity=child_identity.to_dict(),
            )
        try:
            remaining = _remaining_deadline(
                runtime_deadline, float(spec.timeout_seconds)
            )
            if remaining <= 0:
                timed_out = True
                cleanup_deadline = _owned_process_cleanup_deadline(
                    process,
                    launch_deadline,
                    timeout_evidence=True,
                )
                stdout_bytes, stderr_bytes = _terminate_and_drain_owned_process(
                    process, deadline=cleanup_deadline
                )
                if process.poll() is None:
                    return _cleanup_pending_response(
                        metadata,
                        process,
                        prepared.sensitive_values,
                        response_updates={
                            "timed_out": True,
                            "stop_reason": "timeout",
                            "exit_code": 124,
                        },
                    )
                exit_code = 124
            else:
                stdout_bytes, stderr_bytes = process.communicate(
                    input=prepared.prompt_bytes, timeout=remaining
                )
                timed_out = False
                exit_code = process.returncode
        except subprocess.TimeoutExpired as timeout_error:
            timed_out = True
            cleanup_deadline = _owned_process_cleanup_deadline(
                process,
                launch_deadline,
                timeout_evidence=True,
            )
            drained_stdout, drained_stderr = _terminate_and_drain_owned_process(
                process, deadline=cleanup_deadline
            )
            if process.poll() is None:
                return _cleanup_pending_response(
                    metadata,
                    process,
                    prepared.sensitive_values,
                    response_updates={
                        "timed_out": True,
                        "stop_reason": "timeout",
                        "exit_code": 124,
                    },
                )
            stdout_bytes = _prefer_complete_output(
                timeout_error.output, drained_stdout
            )
            stderr_bytes = _prefer_complete_output(
                timeout_error.stderr, drained_stderr
            )
            exit_code = 124
    finally:
        cleanup_deadline = _owned_process_cleanup_deadline(
            process,
            launch_deadline,
            timeout_evidence=timed_out,
        )
        if process.poll() is None:
            cleanup_confirmed = _terminate_owned_process(
                process, deadline=cleanup_deadline
            )
        else:
            _close_process_streams(process)
            cleanup_confirmed = _release_owned_containment(
                process,
                terminate_descendants=True,
                deadline=cleanup_deadline,
            )
        if not cleanup_confirmed:
            _mark_owned_cleanup_incomplete(
                process, "normal_completion_containment_unconfirmed"
            )
            response_updates: dict[str, Any] = {}
            if timed_out:
                response_updates.update(
                    {
                        "timed_out": True,
                        "stop_reason": "timeout",
                        "exit_code": 124,
                    }
                )
            raise _OwnedCleanupPending(
                process, response_updates=response_updates
            )
        metadata = update_metadata(
            run_dir,
            cleanup_state="cleanup_confirmed",
            owned_process_pid=process.pid,
            live_cleanup_threads=[],
        )
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    safe_stdout = _scrub_output_text(stdout, prepared.sensitive_values)
    safe_stderr = _scrub_output_text(stderr, prepared.sensitive_values)
    _atomic_write_text(run_dir / "stdout.txt", safe_stdout)
    _atomic_write_text(run_dir / "stderr.txt", safe_stderr)
    if time.monotonic() >= launch_deadline:
        timed_out = True
        exit_code = 124
    workspace_root = Path(str(metadata["workspace_root"]))
    if timed_out:
        actual_route: dict[str, Any] = {}
        git_after_raw = _failed_git_snapshot(
            "after",
            TimeoutError(
                "Post-run Git evidence was not captured after timeout."
            ),
            prepared.sensitive_values,
            is_git_repo=bool(git_before_raw.get("is_git_repo")),
        )
    else:
        actual_route = _scrub_guarded_value(
            actual_route_from_text(
                stdout,
                declared_model=(metadata.get("profile") or {}).get("model"),
            ),
            prepared.sensitive_values,
        )
        git_after_raw = capture_git_snapshot(
            run_dir,
            workspace_root,
            "after",
            prepared.sensitive_values,
            deadline=launch_deadline,
        )
        if time.monotonic() >= launch_deadline:
            timed_out = True
            exit_code = 124
    (
        scope_check_raw,
        _scope_finalization_failed,
        scope_deadline_crossed,
    ) = _terminal_write_scope_evidence(
        str(metadata["run_id"]),
        workspace_root,
        git_before_raw,
        git_after_raw,
        pinned_scope,
        timed_out=timed_out,
    )
    if scope_deadline_crossed:
        timed_out = True
        exit_code = 124
    git_after = _git_snapshot_projection(
        git_after_raw, prepared.sensitive_values
    )
    scope_check = _scrub_guarded_value(
        scope_check_raw, prepared.sensitive_values
    )
    updates: dict[str, Any] = _scrub_guarded_value(
        {
            "status": (
                "timed_out"
                if timed_out
                else "succeeded"
                if exit_code == 0
                else "failed"
            ),
            "finished_at": utc_now_iso(),
            "duration_ms": int((time.monotonic() - started_monotonic) * 1000),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "cleanup_state": "cleanup_confirmed",
            "owned_process_pid": process.pid,
            "live_cleanup_threads": [],
            "git_after": git_after,
            "write_scope_check": scope_check,
            "acceptance_status": (
                "blocked_write_scope"
                if not scope_check.get("ok", True)
                else "pending_controller_review"
            ),
        },
        prepared.sensitive_values,
    )
    if actual_route.get("actual_model") or actual_route.get("actual_model_usage"):
        updates.update(
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
    try:
        _scrub_run_artifacts(run_dir, prepared.sensitive_values)
        _secure_run_artifacts(run_dir)
        _publish_latest_run({**metadata, **updates})
    except Exception:
        finalization_timed_out = _has_timeout_evidence(updates)
        failure_status = "timed_out" if finalization_timed_out else "failed"
        failed = _persist_terminal_state(
            run_dir,
            metadata,
            updates={
                "status": failure_status,
                "finished_at": utc_now_iso(),
                "exit_code": 124 if finalization_timed_out else 1,
                **(
                    {"timed_out": True, "stop_reason": "timeout"}
                    if finalization_timed_out
                    else {}
                ),
                "acceptance_status": "blocked_artifact_finalization",
                "finalization_state": "failed",
                "finalization_error": {
                    "code": "artifact_finalization_failed",
                    "message": "One-shot execution artifacts could not be finalized safely.",
                },
            },
            event={
                "type": "process_exited",
                "status": failure_status,
                "exit_code": 124 if finalization_timed_out else 1,
                "finalization_state": "failed",
            },
            sensitive_values=prepared.sensitive_values,
            remove_pid=True,
            launch_deadline=launch_deadline,
        )
        try:
            _scrub_run_artifacts(run_dir, prepared.sensitive_values)
            _secure_run_artifacts(run_dir)
        except Exception:
            pass
        return _scrub_guarded_value(failed, prepared.sensitive_values)
    metadata = _persist_terminal_state(
        run_dir,
        metadata,
        updates=updates,
        event={
            "type": "process_exited",
            "status": updates["status"],
            "exit_code": exit_code,
            "duration_ms": updates["duration_ms"],
        },
        sensitive_values=prepared.sensitive_values,
        remove_pid=True,
        launch_deadline=launch_deadline,
    )
    return _scrub_guarded_value({
        **metadata,
        "stdout_tail": safe_stdout[-4000:],
        "stderr_tail": safe_stderr[-2000:],
    }, prepared.sensitive_values)


def _start_one_shot_launch(
    prepared: PreparedWorkerLaunch,
    run_dir: Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    deadline = _effective_deadline()
    if deadline is None:
        raise OrchestratorError("One-shot transaction deadline is unavailable.")
    token = _OPERATION_DEADLINE.set(deadline)
    try:
        try:
            return _start_one_shot_launch_inner(prepared, run_dir, metadata)
        except _OwnedCleanupPending as pending:
            return _cleanup_pending_response(
                metadata,
                pending.process,
                prepared.sensitive_values,
                pending.threads,
                response_updates=pending.response_updates,
            )
        except Exception:
            try:
                latest = read_metadata(run_dir)
            except Exception:
                latest = dict(metadata)
            if latest.get("child_pid") is not None:
                fallback_timed_out = _has_timeout_evidence(latest) or (
                    time.monotonic() >= deadline
                )
                fallback_status = (
                    "timed_out" if fallback_timed_out else "failed"
                )
                return _persist_terminal_state(
                    run_dir,
                    latest,
                    updates={
                        "status": fallback_status,
                        "finished_at": utc_now_iso(),
                        "exit_code": 124 if fallback_timed_out else 1,
                        **(
                            {"timed_out": True, "stop_reason": "timeout"}
                            if fallback_timed_out
                            else {}
                        ),
                        "acceptance_status": "blocked_artifact_finalization",
                        "finalization_state": "failed",
                        "finalization_error": {
                            "code": "artifact_finalization_failed",
                            "message": "One-shot execution artifacts could not be finalized safely.",
                        },
                    },
                    event={
                        "type": "process_exited",
                        "status": fallback_status,
                        "exit_code": 124 if fallback_timed_out else 1,
                        "finalization_state": "failed",
                    },
                    sensitive_values=prepared.sensitive_values,
                    remove_pid=True,
                    launch_deadline=deadline,
                )
            return _record_blocked_launch(
                run_dir,
                latest,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "artifact_write_failed",
                    "Pre-launch execution artifacts could not be finalized safely.",
                ),
            )
    finally:
        _OPERATION_DEADLINE.reset(token)


def _start_prepared_worker_launch_inner(
    prepared: PreparedWorkerLaunch,
) -> dict[str, Any]:
    if not isinstance(prepared, PreparedWorkerLaunch):
        raise TypeError("prepared must be a PreparedWorkerLaunch")
    metadata = prepared.metadata()
    run_dir = (
        Path(str(metadata["artifact_root"]))
        / "runs"
        / str(metadata["run_id"])
    )
    try:
        run_dir, metadata = _initialize_prepared_run(prepared)
    except Exception:
        try:
            _set_private_directory(run_dir)
        except Exception:
            pass
        metadata.update(
            {
                "runtime_launch": prepared.launch_spec.public_metadata(),
                "stdout_path": str(run_dir / "stdout.txt"),
                "stderr_path": str(run_dir / "stderr.txt"),
                "events_path": str(run_dir / "events.ndjson"),
            }
        )
        for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
            if not (run_dir / name).exists():
                try:
                    _atomic_write_text(run_dir / name, "")
                except Exception:
                    pass
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed", "Run artifacts could not be initialized atomically."
            ),
        )
    containment = runtime_tree_containment_support()
    if not containment["supported"]:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=prepared.sensitive_values,
            status="blocked_runtime_launch",
            error=_security_error(
                "runtime_containment_unavailable",
                "The runtime was not started because whole-process-tree containment is unavailable.",
                safe_details={
                    "platform": sys.platform,
                    "required_mechanism": "kernel_enforced_process_tree",
                },
                suggested_action=(
                    "Run on Windows with Job Object support or install a future "
                    "guarded cgroup-v2 runtime backend before retrying."
                ),
            ),
        )
    if prepared.mode == "one_shot":
        return _start_one_shot_launch(prepared, run_dir, metadata)
    if prepared.mode == "visible":
        return _start_streaming_controller(
            prepared,
            run_dir,
            metadata,
            worker_subcommand="_visible-worker",
            visible_console=True,
        )
    return _start_streaming_controller(prepared, run_dir, metadata)


def start_prepared_worker_launch(
    prepared: PreparedWorkerLaunch,
) -> dict[str, Any]:
    if not isinstance(prepared, PreparedWorkerLaunch):
        raise TypeError("prepared must be a PreparedWorkerLaunch")
    deadline = prepared.transaction_deadline_monotonic
    if (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
    ):
        raise OrchestratorError(
            "Prepared launch deadline evidence is missing or invalid."
        )
    inherited_deadline = _effective_deadline()
    reservation = prepared.admission_reservation
    if (
        inherited_deadline is not None
        and float(inherited_deadline) != float(deadline)
    ):
        raise OrchestratorError(
            "Prepared launch deadline differs from the active transaction."
        )
    if (
        reservation is not None
        and float(reservation.deadline) != float(deadline)
    ):
        raise OrchestratorError(
            "Prepared team deadline differs from its reservation."
        )
    _check_deadline(
        float(deadline),
        "Prepared launch deadline expired before start.",
    )
    token = _OPERATION_DEADLINE.set(float(deadline))
    try:
        return _start_prepared_worker_launch_inner(prepared)
    finally:
        _OPERATION_DEADLINE.reset(token)


@_guard_public_launch_transaction(timeout_position=5)
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
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    if not isinstance(task, str) or not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    _check_deadline(
        message="Route resolution exceeded the launch transaction deadline."
    )
    provider = get_provider(route["profile"])
    _check_deadline(
        message="Provider resolution exceeded the launch transaction deadline."
    )
    model_policy = load_json(POLICY_PATH)
    default_write = bool(
        model_policy.get("safety", {}).get("default_write_enabled", False)
    )
    write_enabled = allow_write or default_write
    permission_mode = route["permission_mode"] if not write_enabled else "acceptEdits"
    timeout = timeout_seconds or int(route["timeout_seconds"])
    timeout = min(
        timeout,
        int(model_policy.get("safety", {}).get("max_timeout_seconds", 1800)),
    )
    selected_model = route.get("model_override") or provider.model
    timeout = enforce_cost_guard(selected_model, timeout)
    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    paths = _guarded_launch_paths(effective_cwd)
    prompt = build_prompt(
        role, task, context, artifact_root=paths["artifact_root"]
    )
    _check_deadline(
        message="Prompt construction exceeded the launch transaction deadline."
    )
    prepared = prepare_worker_launch(
        mode="one_shot",
        prompt=prompt,
        provider_env=provider.env,
        model_override=route.get("model_override"),
        cwd=effective_cwd,
        workspace_root=paths["workspace_root"],
        artifact_root=paths["artifact_root"],
        permission_mode=permission_mode,
        timeout_seconds=timeout,
        arguments=(
            "-p",
            "--output-format",
            output_format,
            "--permission-mode",
            permission_mode,
            "--no-session-persistence",
        ),
        safe_route_metadata={
            "role": role,
            "task_type": route["task_type"],
            "profile": {
                "id": provider.id,
                "name": provider.name,
                "model": selected_model,
                "provider_default_model": provider.model,
                "endpoints": provider.endpoints,
            },
            "permission_mode": permission_mode,
            "allow_write": write_enabled,
            "route_reason": route.get("reason", ""),
            "output_format": output_format,
        },
        allow_unsafe_runtime=allow_unsafe_runtime,
        selected_model=selected_model,
        sensitive_values=(task, context or ""),
    )
    _check_deadline(
        message="Runtime preparation exceeded the launch transaction deadline."
    )
    return start_prepared_worker_launch(prepared)


def _validate_worker_process_identity(identity: ProcessIdentity) -> None:
    expected = str(Path(sys.executable).resolve())
    if (
        not identity.supported
        or identity.executable_path is None
        or not _paths_match(identity.executable_path, expected)
    ):
        raise _process_identity_unverified(identity.pid, "internal worker")


def _write_pipe_chunk(pipe: Any, payload: bytes) -> None:
    deadline = _effective_deadline()
    _check_deadline(deadline, "The private worker protocol exceeded the launch deadline.")
    result: list[int] = []
    errors: list[BaseException] = []
    completed = threading.Event()

    def write() -> None:
        try:
            result.append(int(pipe.write(payload)))
        except BaseException as exc:
            errors.append(exc)
        finally:
            completed.set()

    writer = threading.Thread(
        target=write,
        name=f"cc-deadline-writer-{uuid.uuid4().hex[:8]}",
        daemon=True,
    )
    writer.start()
    while not completed.wait(_remaining_deadline(deadline, 0.01)):
        if deadline is not None and time.monotonic() >= deadline:
            if os.name == "nt" and writer.native_id is not None:
                try:
                    import ctypes
                    from ctypes import wintypes

                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    thread_handle = kernel32.OpenThread(
                        0x0001, False, int(writer.native_id)
                    )
                    if thread_handle:
                        try:
                            kernel32.CancelSynchronousIo(thread_handle)
                        finally:
                            kernel32.CloseHandle(thread_handle)
                except Exception:
                    pass
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
            completed.wait(0.05)
            raise TimeoutError(
                "The private worker protocol exceeded the launch deadline."
            )
    if errors:
        raise errors[0]
    written = result[0] if result else 0
    if written != len(payload):
        raise BrokenPipeError("short write to internal worker protocol")
    _check_deadline(deadline, "The private worker protocol exceeded the launch deadline.")


def _worker_start_gate_payload(metadata: Mapping[str, Any]) -> dict[str, Any]:
    public = metadata.get("runtime_launch")
    worker_identity = metadata.get("worker_process_identity")
    if not isinstance(public, Mapping) or not isinstance(worker_identity, Mapping):
        raise OrchestratorError("Worker start gate identity is unavailable.")
    launch_nonce = public.get("launch_nonce")
    worker_pid = metadata.get("worker_pid")
    creation_token = worker_identity.get("creation_token")
    if (
        not isinstance(launch_nonce, str)
        or not launch_nonce
        or not isinstance(worker_pid, int)
        or isinstance(worker_pid, bool)
        or worker_pid <= 0
        or not isinstance(creation_token, str)
        or not creation_token
    ):
        raise OrchestratorError("Worker start gate identity is invalid.")
    return {
        "state": "open",
        "run_id": str(metadata.get("run_id") or ""),
        "launch_nonce": launch_nonce,
        "worker_pid": worker_pid,
        "worker_creation_token": creation_token,
        "opened_at": utc_now_iso(),
    }


def _read_worker_start_gate(run_dir: Path) -> dict[str, Any]:
    gate_path = run_dir / WORKER_START_GATE_FILENAME
    with _open_managed_file(gate_path) as (handle, _details):
        payload = handle.read(MAX_MANAGED_ARTIFACT_BYTES + 1)
    if len(payload) > MAX_MANAGED_ARTIFACT_BYTES:
        raise OrchestratorError("Worker start gate exceeds its size limit.")
    try:
        gate = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("Worker start gate is invalid.") from exc
    if not isinstance(gate, dict):
        raise OrchestratorError("Worker start gate is invalid.")
    return gate


def _open_worker_start_gate(run_dir: Path) -> dict[str, Any]:
    temporary_path: Path | None = None
    target = run_dir / WORKER_START_GATE_FILENAME
    try:
        with artifact_lock(run_dir):
            metadata = read_metadata(run_dir)
            worker_launch = metadata.get("worker_launch")
            if not isinstance(worker_launch, dict):
                raise OrchestratorError("Worker start gate metadata is unavailable.")
            if worker_launch.get("start_gate") != "closed":
                raise OrchestratorError("Worker start gate is not closed.")
            if target.exists():
                raise OrchestratorError("Worker start gate is already published.")
            gate = _worker_start_gate_payload(metadata)
            temporary_path = _prepare_private_atomic_write(
                target,
                json.dumps(gate, ensure_ascii=False, indent=2).encode("utf-8"),
            )
            opened_metadata = dict(metadata)
            opened_worker_launch = dict(worker_launch)
            opened_worker_launch.update(
                {"start_gate": "open", "gate_opened_at": gate["opened_at"]}
            )
            opened_metadata["worker_launch"] = opened_worker_launch
    except Exception:
        _discard_prepared_atomic_write(temporary_path)
        raise
    try:
        _replace_prepared_atomic_write(temporary_path, target)
    except Exception:
        _discard_prepared_atomic_write(temporary_path)
        raise
    return opened_metadata


def _start_streaming_controller(
    prepared: PreparedWorkerLaunch,
    run_dir: Path,
    metadata: dict[str, Any],
    *,
    worker_subcommand: str = "_stream-worker",
    visible_console: bool = False,
) -> dict[str, Any]:
    spec = prepared.launch_spec
    worker_env = dict(spec.environment)
    worker_env[INTERNAL_WORKER_NONCE_ENV] = spec.launch_nonce
    git_command = shutil.which("git")
    if git_command:
        worker_env[INTERNAL_GIT_BIN_ENV] = str(Path(git_command).resolve())
    worker_command = [
        str(Path(sys.executable).resolve()),
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        worker_subcommand,
        "--run-id",
        str(metadata["run_id"]),
    ]
    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(
            subprocess,
            "CREATE_NEW_CONSOLE" if visible_console else "CREATE_NO_WINDOW",
            0,
        )
    else:
        popen_kwargs["start_new_session"] = True
    reservation = prepared.admission_reservation
    admission: Any | None = None
    if reservation is not None:
        try:
            reservation.require_active()
        except Exception:
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "cost_guard_blocked",
                    "Team launch admission reservation is unavailable.",
                ),
            )
        admission_active = False
    else:
        try:
            admission = launch_lock()
            admission.__enter__()
        except Exception:
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "cost_guard_blocked", "Streaming launch admission could not be acquired."
                ),
            )
        admission_active = True
    worker: subprocess.Popen[bytes] | None = None
    worker_deadline = _effective_deadline()
    if worker_deadline is None:
        raise OrchestratorError("Streaming transaction deadline is unavailable.")
    worker_cleanup_deadline = (
        worker_deadline + WORKER_FINALIZATION_GRACE_SECONDS
    )
    try:
        try:
            if not prepared.skip_cost_guard:
                enforce_cost_guard(
                    prepared.selected_model, spec.timeout_seconds
                )
        except Exception:
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "cost_guard_blocked", "Streaming launch admission was denied."
                ),
            )
        try:
            worker = _spawn_detached_internal_worker(
                worker_command,
                ownership_deadline=worker_cleanup_deadline,
                cwd=str(ROOT),
                env=worker_env,
                stdin=subprocess.PIPE,
            stdout=None if visible_console else subprocess.DEVNULL,
            stderr=None if visible_console else subprocess.DEVNULL,
            creationflags=creationflags,
            **popen_kwargs,
        )
        except TimeoutError:
            timeout_updates = _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="timed_out",
                error=_launch_failure_error(
                    "worker_launch_timeout",
                    "Internal worker process creation exceeded the launch deadline.",
                ),
                **timeout_updates,
            )
        except OSError:
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "runtime_launch_failed",
                    "The isolated internal worker could not be started.",
                ),
            )

        try:
            frame = spec.private_frame()
            if len(frame) > PRIVATE_LAUNCH_FRAME_LIMIT:
                raise BrokenPipeError("private launch frame exceeds limit")
            if len(prepared.prompt_bytes) > PROMPT_BYTES_LIMIT:
                raise BrokenPipeError("prompt exceeds limit")
            if worker.stdin is None:
                raise BrokenPipeError("internal worker stdin is unavailable")
            _write_pipe_chunk(worker.stdin, struct.pack("!Q", len(frame)))
            _write_pipe_chunk(worker.stdin, frame)
            _write_pipe_chunk(
                worker.stdin, struct.pack("!Q", len(prepared.prompt_bytes))
            )
            _write_pipe_chunk(worker.stdin, prepared.prompt_bytes)
            worker.stdin.flush()
            worker.stdin.close()
            worker.stdin = None
        except TimeoutError:
            timeout_updates = _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
            if not _terminate_owned_process(
                worker, deadline=worker_cleanup_deadline
            ):
                return _cleanup_pending_response(
                    metadata,
                    worker,
                    prepared.sensitive_values,
                    response_updates=timeout_updates,
                    attempt_deadline=worker_cleanup_deadline,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="timed_out",
                error=_launch_failure_error(
                    "worker_protocol_timeout",
                    "The private worker launch pipe exceeded its deadline.",
                ),
                worker_pid=worker.pid,
                **timeout_updates,
            )
        except (BrokenPipeError, OSError):
            if not _terminate_owned_process(
                worker, deadline=worker_cleanup_deadline
            ):
                return _cleanup_pending_response(
                    metadata,
                    worker,
                    prepared.sensitive_values,
                    attempt_deadline=worker_cleanup_deadline,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "worker_protocol_failed", "The private worker launch pipe failed."
                ),
                worker_pid=worker.pid,
            )

        try:
            worker_identity = capture_process_identity(
                worker.pid, launch_nonce=spec.launch_nonce
            )
            _validate_worker_process_identity(worker_identity)
        except TimeoutError:
            timeout_updates = _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
            if not _terminate_owned_process(
                worker, deadline=worker_cleanup_deadline
            ):
                return _cleanup_pending_response(
                    metadata,
                    worker,
                    prepared.sensitive_values,
                    response_updates=timeout_updates,
                    attempt_deadline=worker_cleanup_deadline,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="timed_out",
                error=_launch_failure_error(
                    "worker_identity_timeout",
                    "Internal worker identity validation exceeded the launch deadline.",
                ),
                worker_pid=worker.pid,
                **timeout_updates,
            )
        except (OSError, TypeError, ValueError, RuntimeSecurityError) as exc:
            if not _terminate_owned_process(
                worker, deadline=worker_cleanup_deadline
            ):
                return _cleanup_pending_response(
                    metadata,
                    worker,
                    prepared.sensitive_values,
                    attempt_deadline=worker_cleanup_deadline,
                )
            error = (
                exc
                if isinstance(exc, RuntimeSecurityError)
                else _process_identity_unverified(worker.pid, "internal worker")
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_process_identity",
                error=error,
                worker_pid=worker.pid,
            )
        try:
            registration_updates: dict[str, Any] = {
                "worker_pid": worker.pid,
                "worker_process_identity": worker_identity.to_dict(),
            }
            if reservation is not None:
                registration_updates["team_id"] = reservation.team_id
                registration_updates["team_manifest_path"] = str(
                    TEAMS_DIR / f"{reservation.team_id}.json"
                )
            metadata = update_metadata(run_dir, **registration_updates)
            append_event(
                run_dir,
                {"type": "stream_worker_started", "worker_pid": worker.pid},
            )
            _append_unsafe_runtime_event(prepared, run_dir)
            _publish_latest_run(metadata)
            if not _register_background_worker_watcher(
                str(metadata["run_id"]), worker
            ):
                raise OrchestratorError(
                    "The isolated worker watcher could not be registered."
                )
            with _ACTIVE_WORKER_HANDLES_LOCK:
                registered_worker = _ACTIVE_WORKER_HANDLES.get(
                    str(metadata["run_id"])
                )
            if registered_worker is not worker or worker.poll() is not None:
                raise OrchestratorError(
                    "The isolated worker exited before gate opening."
                )
            if admission is not None:
                admission_active = False
                admission.__exit__(None, None, None)
            if reservation is not None:
                reservation.register(str(metadata["run_id"]))
            if reservation is None:
                metadata = _open_worker_start_gate(run_dir)
                metadata = _wait_for_worker_handoff_ready(
                    run_dir, worker, deadline=worker_deadline
                )
                metadata = _accept_worker_handoff(
                    run_dir,
                    worker,
                    launch_nonce=spec.launch_nonce,
                )
            if not _detach_owned_process_record(worker):
                raise OrchestratorError(
                    "The isolated worker launch ownership could not be released."
                )
        except Exception:
            if not _terminate_owned_process(
                worker, deadline=worker_cleanup_deadline
            ):
                return _cleanup_pending_response(
                    metadata,
                    worker,
                    prepared.sensitive_values,
                    attempt_deadline=worker_cleanup_deadline,
                )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=prepared.sensitive_values,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "artifact_write_failed",
                    "Streaming launch metadata could not be persisted before gate opening.",
                ),
                worker_pid=worker.pid,
            )
        return {
            **metadata,
            "status": "starting",
            "worker_pid": worker.pid,
            "poll": {
                "tool": "cc_poll_run",
                "run_id": metadata["run_id"],
                "event_offset": 0,
                "stdout_offset": 0,
                "stderr_offset": 0,
            },
        }
    finally:
        if admission_active:
            try:
                assert admission is not None
                admission.__exit__(None, None, None)
            except Exception:
                pass


def _prepare_streaming_agent(
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
    allow_unsafe_runtime: bool = False,
    _admission_reservation: _LaunchAdmissionReservation | None = None,
) -> PreparedWorkerLaunch:
    if not isinstance(task, str) or not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    _check_deadline(
        message="Route resolution exceeded the launch transaction deadline."
    )
    provider = get_provider(route["profile"])
    _check_deadline(
        message="Provider resolution exceeded the launch transaction deadline."
    )
    model_policy = load_json(POLICY_PATH)
    default_write = bool(
        model_policy.get("safety", {}).get("default_write_enabled", False)
    )
    write_enabled = allow_write or default_write
    permission_mode = route["permission_mode"] if not write_enabled else "acceptEdits"
    timeout = timeout_seconds or int(route["timeout_seconds"])
    timeout = min(
        timeout,
        int(model_policy.get("safety", {}).get("max_timeout_seconds", 1800)),
    )
    selected_model = model_override or route.get("model_override") or provider.model
    timeout = clamp_timeout_for_model(selected_model, timeout)
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
    paths = _guarded_launch_paths(effective_cwd)
    prompt = build_prompt(
        role, task, context, artifact_root=paths["artifact_root"]
    )
    _check_deadline(
        message="Prompt construction exceeded the launch transaction deadline."
    )
    arguments = ["-p", "--output-format", "stream-json", "--verbose"]
    if include_partial_messages:
        arguments.append("--include-partial-messages")
    arguments.extend(
        ["--permission-mode", permission_mode, "--no-session-persistence"]
    )
    prepared = prepare_worker_launch(
        mode="streaming",
        prompt=prompt,
        provider_env=provider.env,
        model_override=selected_model,
        cwd=effective_cwd,
        workspace_root=paths["workspace_root"],
        artifact_root=paths["artifact_root"],
        permission_mode=permission_mode,
        timeout_seconds=timeout,
        arguments=tuple(arguments),
        safe_route_metadata={
            "role": role,
            "task_type": route["task_type"],
            "profile": {
                "id": provider.id,
                "name": provider.name,
                "model": selected_model,
                "provider_default_model": provider.model,
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
            "output_format": output_format,
            "include_partial_messages": include_partial_messages,
            "output_budget": budget,
            "stop_reason": None,
            "route_reason": route.get("reason", ""),
        },
        allow_unsafe_runtime=allow_unsafe_runtime,
        selected_model=selected_model,
        skip_cost_guard=skip_cost_guard,
        sensitive_values=(task, context or ""),
        admission_reservation=_admission_reservation,
    )
    _check_deadline(
        message="Runtime preparation exceeded the launch transaction deadline."
    )
    return prepared


@_guard_public_launch_transaction(timeout_position=6)
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
    allow_unsafe_runtime: bool = False,
    _admission_reservation: _LaunchAdmissionReservation | None = None,
    _prepared_launch: PreparedWorkerLaunch | None = None,
) -> dict[str, Any]:
    prepared = _prepared_launch or _prepare_streaming_agent(
        task=task,
        role=role,
        task_type=task_type,
        profile=profile,
        model_override=model_override,
        allow_write=allow_write,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        context=context,
        output_format=output_format,
        include_partial_messages=include_partial_messages,
        max_output_bytes=max_output_bytes,
        max_events_bytes=max_events_bytes,
        soft_output_bytes=soft_output_bytes,
        output_budget_policy=output_budget_policy,
        kill_on_excessive_output=kill_on_excessive_output,
        final_only=final_only,
        final_max_chars=final_max_chars,
        skip_cost_guard=skip_cost_guard,
        allow_unsafe_runtime=allow_unsafe_runtime,
        _admission_reservation=_admission_reservation,
    )
    if _prepared_launch is not None:
        if prepared.admission_reservation is not _admission_reservation:
            raise OrchestratorError("Prepared launch admission reservation changed before start.")
        expected_unsafe = prepared.launch_spec.trust_level == "local_unsafe"
        if expected_unsafe != bool(allow_unsafe_runtime):
            raise OrchestratorError("Prepared launch approval does not match this request.")
    return start_prepared_worker_launch(prepared)


_WORKER_ARGUMENT_KINDS = {
    "-p": "prompt_stdin",
    "--output-format": "output_format_flag",
    "json": "json_format",
    "stream-json": "stream_json_format",
    "--permission-mode": "permission_mode_flag",
    "plan": "plan_permission",
    "acceptEdits": "accept_edits_permission",
    "--no-session-persistence": "no_session_persistence",
    "--verbose": "verbose",
    "--include-partial-messages": "include_partial_messages",
}


def _runtime_not_trusted(message: str) -> RuntimeSecurityError:
    return _security_error(
        "runtime_not_trusted",
        message,
        suggested_action="Start a fresh launch through the controller.",
    )


def _read_exact(stream: Any, length: int) -> bytes:
    deadline = _effective_deadline()

    def read_chunk(size: int) -> bytes:
        try:
            stream.fileno()
        except (AttributeError, OSError, TypeError, ValueError):
            return stream.read(size)
        if os.name != "nt":
            return stream.read(size)
        result: list[bytes] = []
        errors: list[BaseException] = []
        completed = threading.Event()

        def read() -> None:
            try:
                result.append(stream.read(size))
            except BaseException as exc:
                errors.append(exc)
            finally:
                completed.set()

        reader = threading.Thread(
            target=read,
            name=f"cc-deadline-reader-{uuid.uuid4().hex[:8]}",
            daemon=True,
        )
        reader.start()
        while not completed.wait(_remaining_deadline(deadline, 0.01)):
            if deadline is not None and time.monotonic() >= deadline:
                if reader.native_id is not None:
                    try:
                        import ctypes

                        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        thread_handle = kernel32.OpenThread(
                            0x0001, False, int(reader.native_id)
                        )
                        if thread_handle:
                            try:
                                kernel32.CancelSynchronousIo(thread_handle)
                            finally:
                                kernel32.CloseHandle(thread_handle)
                    except Exception:
                        pass
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
                completed.wait(0.05)
                raise TimeoutError(
                    "The private worker protocol exceeded the launch deadline."
                )
        if errors:
            raise errors[0]
        return result[0] if result else b""

    def wait_readable() -> None:
        try:
            fd = int(stream.fileno())
        except (AttributeError, OSError, TypeError, ValueError):
            return
        while True:
            _check_deadline(
                deadline,
                "The private worker protocol exceeded the launch deadline.",
            )
            if os.name == "nt":
                return
            else:
                import select

                readable, _writable, _exceptional = select.select(
                    [fd], [], [], _remaining_deadline(deadline, 0.01)
                )
                if readable:
                    return
            threading.Event().wait(_remaining_deadline(deadline, 0.005))

    chunks: list[bytes] = []
    remaining = length
    while remaining:
        wait_readable()
        chunk = read_chunk(remaining)
        if not chunk:
            raise _runtime_not_trusted("Internal worker launch payload is incomplete.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_protocol_trailer(stream: Any) -> bytes:
    deadline = _effective_deadline()
    try:
        fd = int(stream.fileno())
    except (AttributeError, OSError, TypeError, ValueError):
        return stream.read(1)
    while True:
        _check_deadline(
            deadline, "The private worker protocol exceeded the launch deadline."
        )
        if os.name == "nt":
            try:
                import ctypes
                import msvcrt
                from ctypes import wintypes

                available = wintypes.DWORD()
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                ok = kernel32.PeekNamedPipe(
                    msvcrt.get_osfhandle(fd),
                    None,
                    0,
                    None,
                    ctypes.byref(available),
                    None,
                )
                if not ok and ctypes.get_last_error() in {109, 232, 233}:
                    return b""
                if ok and int(available.value) > 0:
                    return stream.read(1)
            except Exception:
                return stream.read(1)
        else:
            import select

            readable, _writable, _exceptional = select.select(
                [fd], [], [], _remaining_deadline(deadline, 0.01)
            )
            if readable:
                return stream.read(1)
        threading.Event().wait(_remaining_deadline(deadline, 0.005))


def _read_bounded_payload(stream: Any, limit: int, label: str) -> bytes:
    raw_length = _read_exact(stream, 8)
    length = struct.unpack("!Q", raw_length)[0]
    if length > limit:
        raise _runtime_not_trusted(f"Internal worker {label} exceeds its size limit.")
    return _read_exact(stream, length)


def _wait_for_controller_worker_identity(run_dir: Path) -> dict[str, Any]:
    deadline = _effective_deadline() or (time.monotonic() + 5.0)
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = read_metadata(run_dir)
        if latest.get("worker_process_identity") is not None:
            return latest
        if str(latest.get("status") or "").startswith("blocked_"):
            break
        time.sleep(0.01)
    raise _runtime_not_trusted("Controller worker identity was not published in time.")


def _parse_worker_frame(
    run_dir: Path, frame: bytes
) -> tuple[dict[str, Any], ExecutableIdentity, tuple[str, ...]]:
    metadata = _wait_for_controller_worker_identity(run_dir)
    public = metadata.get("runtime_launch")
    if not isinstance(public, dict):
        raise _runtime_not_trusted("Public runtime launch metadata is missing.")
    worker_launch = metadata.get("worker_launch")
    if not isinstance(worker_launch, dict) or worker_launch.get("nonce_consumed") is not False:
        raise _runtime_not_trusted("Internal worker launch nonce is missing or consumed.")
    if hashlib.sha256(frame).hexdigest() != public.get("launch_contract_sha256"):
        raise _runtime_not_trusted("Private launch frame does not match its public contract.")
    try:
        payload = json.loads(frame.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _runtime_not_trusted("Private launch frame is invalid.") from exc
    expected_fields = {
        "runtime_id",
        "protocol_version",
        "executable_identity",
        "arguments",
        "cwd",
        "permission_mode",
        "timeout_seconds",
        "environment_keys",
        "trust_level",
        "policy_decision_id",
        "launch_nonce",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise _runtime_not_trusted("Private launch frame has an invalid shape.")
    nonce = os.environ.get(INTERNAL_WORKER_NONCE_ENV)
    if (
        not nonce
        or payload.get("launch_nonce") != nonce
        or public.get("launch_nonce") != nonce
    ):
        raise _runtime_not_trusted("Internal worker launch nonce is missing or forged.")
    for key in (
        "runtime_id",
        "protocol_version",
        "cwd",
        "permission_mode",
        "timeout_seconds",
        "trust_level",
        "policy_decision_id",
    ):
        if payload.get(key) != public.get(key):
            raise _runtime_not_trusted("Private launch frame conflicts with public metadata.")
    if payload.get("protocol_version") != 1:
        raise _runtime_not_trusted("Internal worker protocol version is unsupported.")
    if payload.get("executable_identity") != public.get("executable_identity"):
        raise _runtime_not_trusted("Executable identity contract does not match metadata.")
    try:
        identity = ExecutableIdentity.from_public_dict(payload["executable_identity"])
    except (TypeError, ValueError) as exc:
        raise _runtime_not_trusted("Executable identity contract is invalid.") from exc
    arguments_value = payload.get("arguments")
    if not isinstance(arguments_value, list) or not all(
        isinstance(item, str) and item in _WORKER_ARGUMENT_KINDS
        for item in arguments_value
    ):
        raise _runtime_not_trusted("Runtime argument contract is invalid.")
    arguments = tuple(arguments_value)
    if [_WORKER_ARGUMENT_KINDS[item] for item in arguments] != public.get(
        "argument_kinds"
    ):
        raise _runtime_not_trusted("Runtime argument kinds do not match metadata.")
    environment_keys = payload.get("environment_keys")
    if (
        not isinstance(environment_keys, list)
        or environment_keys != public.get("environment_keys")
        or not all(isinstance(key, str) and key in os.environ for key in environment_keys)
    ):
        raise _runtime_not_trusted("Validated runtime environment is unavailable.")
    worker_identity_data = metadata.get("worker_process_identity")
    try:
        worker_identity = ProcessIdentity.from_dict(worker_identity_data)
    except (TypeError, ValueError) as exc:
        raise _runtime_not_trusted("Controller worker identity is invalid.") from exc
    if worker_identity.pid != os.getpid() or worker_identity.launch_nonce != nonce:
        raise _runtime_not_trusted("Controller worker identity is not bound to this process.")
    _validate_worker_process_identity(worker_identity)
    return metadata, identity, arguments


def _team_manifest_payload(metadata: Mapping[str, Any]) -> dict[str, Any] | None:
    team_id = metadata.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        return None
    manifest_path = metadata.get("team_manifest_path")
    if not isinstance(manifest_path, str) or not manifest_path:
        return None
    try:
        payload = _read_bounded_regular_file(
            Path(manifest_path), MAX_MANAGED_ARTIFACT_BYTES
        )
        manifest = json.loads(payload.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(manifest, dict) or manifest.get("team_id") != team_id:
        return None
    return manifest


def _validate_team_worker_identity(
    metadata: Mapping[str, Any],
    *,
    expected_nonce: str,
    expected_pid: int | None = None,
) -> ProcessIdentity:
    try:
        recorded = ProcessIdentity.from_dict(
            metadata.get("worker_process_identity")
        )
    except (TypeError, ValueError) as exc:
        raise _runtime_not_trusted(
            "Controller worker identity evidence is invalid."
        ) from exc
    controller_pid = metadata.get("controller_pid")
    worker_pid = metadata.get("worker_pid")
    if (
        not isinstance(controller_pid, int)
        or isinstance(controller_pid, bool)
        or controller_pid <= 0
        or not isinstance(worker_pid, int)
        or isinstance(worker_pid, bool)
        or worker_pid <= 0
        or recorded.pid != worker_pid
        or recorded.parent_pid != controller_pid
        or recorded.launch_nonce != expected_nonce
        or (expected_pid is not None and worker_pid != expected_pid)
    ):
        raise _runtime_not_trusted(
            "Controller worker identity ownership does not match this process."
        )
    comparison = compare_process_identity(
        recorded, expected_launch_nonce=expected_nonce
    )
    live = comparison.live
    if (
        comparison.state != "match"
        or live is None
        or live.pid != worker_pid
        or live.parent_pid != controller_pid
        or live.launch_nonce != expected_nonce
    ):
        raise _runtime_not_trusted(
            "Controller worker process identity is no longer stable."
        )
    for field_name in ("process_group_id", "session_id"):
        expected_value = getattr(recorded, field_name)
        if expected_value is not None and getattr(live, field_name) != expected_value:
            raise _runtime_not_trusted(
                "Controller worker process ownership evidence changed."
            )
    return recorded


def _mark_team_worker_ready(
    run_dir: Path, nonce: str
) -> dict[str, Any]:
    with artifact_lock(run_dir):
        metadata = read_metadata(run_dir)
        if str(metadata.get("status") or "") not in {"starting", "running"}:
            raise _runtime_not_trusted("Controller closed the worker start gate.")
        public = metadata.get("runtime_launch")
        worker_launch = metadata.get("worker_launch")
        if (
            not isinstance(public, Mapping)
            or not isinstance(worker_launch, Mapping)
            or public.get("launch_nonce") != nonce
            or worker_launch.get("nonce_consumed") is not True
            or worker_launch.get("start_gate") != "closed"
            or worker_launch.get("team_preflight_complete") is not True
            or not worker_launch.get("scope_policy_identity")
            or not isinstance(metadata.get("git_before"), Mapping)
            or not metadata["git_before"].get("evidence_complete")
        ):
            raise _runtime_not_trusted(
                "Internal worker launch nonce is unavailable."
            )
        recorded = _validate_team_worker_identity(
            metadata, expected_nonce=nonce, expected_pid=os.getpid()
        )
        if worker_launch.get("team_ready") is True:
            return metadata
        ready_at = utc_now_iso()
        updated_launch = dict(worker_launch)
        updated_launch.update(
            {
                "team_ready": True,
                "team_ready_at": ready_at,
                "team_ready_sha256": hashlib.sha256(
                    (
                        f"{metadata.get('team_id')}:{run_dir.name}:"
                        f"{recorded.pid}:{recorded.creation_token}"
                    ).encode("utf-8")
                ).hexdigest(),
            }
        )
        metadata["worker_launch"] = updated_launch
        _atomic_write_bytes(run_dir / "metadata.json", _metadata_bytes(metadata))
        return metadata


def _complete_team_worker_preflight(
    run_dir: Path,
    nonce: str,
    pinned_scope: Mapping[str, Any],
) -> dict[str, Any]:
    with artifact_lock(run_dir):
        metadata = read_metadata(run_dir)
        public = metadata.get("runtime_launch")
        worker_launch = metadata.get("worker_launch")
        git_before = metadata.get("git_before")
        if (
            str(metadata.get("status") or "") not in {"starting", "running"}
            or not isinstance(public, Mapping)
            or public.get("launch_nonce") != nonce
            or not isinstance(worker_launch, Mapping)
            or worker_launch.get("nonce_consumed") is not True
            or not isinstance(git_before, Mapping)
            or not git_before.get("evidence_complete")
        ):
            raise _runtime_not_trusted(
                "Team member preflight evidence is incomplete."
            )
        scope_identity = pinned_scope.get("sha256")
        if not isinstance(scope_identity, str) or not scope_identity:
            scope_identity = "absent"
        updated_launch = dict(worker_launch)
        updated_launch.update(
            {
                "team_preflight_complete": True,
                "team_preflight_completed_at": utc_now_iso(),
                "scope_policy_identity": scope_identity,
            }
        )
        metadata["worker_launch"] = updated_launch
        _atomic_write_bytes(run_dir / "metadata.json", _metadata_bytes(metadata))
    return _mark_team_worker_ready(run_dir, nonce)


def _wait_for_team_authorization(
    run_dir: Path, metadata: Mapping[str, Any]
) -> dict[str, Any]:
    operation_deadline = _effective_deadline()
    if operation_deadline is None:
        raise _runtime_not_trusted(
            "Streaming transaction deadline is unavailable."
        )
    gate_deadline: float | None = None
    while True:
        latest = read_metadata(run_dir)
        if str(latest.get("status") or "") not in {"starting", "running"}:
            raise _runtime_not_trusted(
                "Controller closed the team authorization gate."
            )
        if _team_own_authorization_ready(latest):
            return latest
        if gate_deadline is None and _team_all_members_ready(latest):
            gate_deadline = (
                time.monotonic() + WORKER_START_GATE_TIMEOUT_SECONDS
            )
        effective = operation_deadline
        if gate_deadline is not None:
            effective = min(effective, gate_deadline)
        if time.monotonic() >= effective:
            raise _runtime_not_trusted(
                "Team authorization gate did not open in time."
            )
        time.sleep(min(0.01, max(0.001, effective - time.monotonic())))


def _team_all_members_ready(metadata: Mapping[str, Any]) -> bool:
    manifest = _team_manifest_payload(metadata)
    if manifest is None or manifest.get("status") not in {"prepared", "authorized"}:
        return False
    runs = manifest.get("runs")
    if not isinstance(runs, list) or not runs:
        return False
    for item in runs:
        if not isinstance(item, Mapping):
            return False
        run_id = item.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
            return False
        try:
            member = read_metadata(safe_run_dir(run_id))
        except Exception:
            return False
        launch = member.get("worker_launch")
        if (
            member.get("team_id") != metadata.get("team_id")
            or str(member.get("status") or "") not in {"starting", "running"}
            or not isinstance(launch, Mapping)
            or launch.get("team_ready") is not True
            or launch.get("nonce_consumed") is not True
            or launch.get("team_preflight_complete") is not True
            or not launch.get("scope_policy_identity")
        ):
            return False
    return True


def _team_start_barrier_ready(metadata: Mapping[str, Any]) -> bool:
    team_id = metadata.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        return True
    manifest = _team_manifest_payload(metadata)
    if manifest is None:
        return False
    if manifest.get("status") != "authorized":
        return False
    runs = manifest.get("runs")
    if not isinstance(runs, list) or not runs:
        return False
    own_run_id = str(metadata.get("run_id") or "")
    own_entry: Mapping[str, Any] | None = None
    for item in runs:
        if not isinstance(item, Mapping):
            return False
        run_id = item.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
            return False
        try:
            member = read_metadata(safe_run_dir(run_id))
            nonce = str(
                (member.get("runtime_launch") or {}).get("launch_nonce") or ""
            )
            recorded = _validate_team_worker_identity(
                member, expected_nonce=nonce
            )
        except Exception:
            return False
        launch = member.get("worker_launch")
        if (
            member.get("team_id") != team_id
            or str(member.get("status") or "") not in {"starting", "running"}
            or not isinstance(launch, Mapping)
            or launch.get("team_ready") is not True
            or launch.get("nonce_consumed") is not True
            or launch.get("team_preflight_complete") is not True
            or item.get("worker_pid") != recorded.pid
            or item.get("worker_creation_token") != recorded.creation_token
        ):
            return False
        if run_id == own_run_id:
            own_entry = item
    if own_entry is None:
        return False
    identity_data = metadata.get("worker_process_identity")
    if not isinstance(identity_data, Mapping):
        return False
    if (
        own_entry.get("worker_pid") != metadata.get("worker_pid")
        or own_entry.get("worker_creation_token")
        != identity_data.get("creation_token")
    ):
            return False
    return True


def _team_own_authorization_ready(metadata: Mapping[str, Any]) -> bool:
    manifest = _team_manifest_payload(metadata)
    if manifest is None or manifest.get("status") != "authorized":
        return False
    own_run_id = str(metadata.get("run_id") or "")
    identity = metadata.get("worker_process_identity")
    if not isinstance(identity, Mapping):
        return False
    for item in manifest.get("runs") or []:
        if (
            isinstance(item, Mapping)
            and item.get("run_id") == own_run_id
            and item.get("worker_pid") == metadata.get("worker_pid")
            and item.get("worker_creation_token")
            == identity.get("creation_token")
        ):
            return True
    return False


def _wait_for_controller_handoff_acceptance(
    run_dir: Path, metadata: Mapping[str, Any]
) -> dict[str, Any]:
    worker_launch = metadata.get("worker_launch")
    if (
        isinstance(worker_launch, Mapping)
        and worker_launch.get("controller_handoff") == "team_managed"
    ):
        return dict(metadata)
    operation_deadline = _effective_deadline()
    if operation_deadline is None:
        raise _runtime_not_trusted(
            "Streaming transaction deadline is unavailable."
        )
    handoff_deadline = min(
        operation_deadline,
        time.monotonic() + WORKER_START_GATE_TIMEOUT_SECONDS,
    )
    while time.monotonic() < handoff_deadline:
        latest = read_metadata(run_dir)
        launch = latest.get("worker_launch")
        if str(latest.get("status") or "") not in {"starting", "running"}:
            raise _runtime_not_trusted(
                "Controller closed the worker handoff gate."
            )
        if (
            isinstance(launch, Mapping)
            and launch.get("nonce_consumed") is True
            and launch.get("controller_handoff") == "accepted"
        ):
            return latest
        time.sleep(
            min(0.01, max(0.001, handoff_deadline - time.monotonic()))
        )
    raise _runtime_not_trusted(
        "Controller did not accept the worker handoff in time."
    )


def _consume_worker_nonce(run_dir: Path, nonce: str) -> dict[str, Any]:
    operation_deadline = _effective_deadline() or (
        time.monotonic() + INTERNAL_WORKER_NONCE_TTL_SECONDS
    )
    initial = read_metadata(run_dir)
    initial_launch = initial.get("worker_launch")
    team_launch = (
        isinstance(initial_launch, Mapping)
        and initial_launch.get("controller_handoff") == "team_managed"
    )
    if not team_launch:
        gate_deadline = (
            time.monotonic() + WORKER_START_GATE_TIMEOUT_SECONDS
        )
        while True:
            latest = read_metadata(run_dir)
            status = str(latest.get("status") or "")
            if status not in {"starting", "running"}:
                raise _runtime_not_trusted(
                    "Controller closed the worker start gate."
                )
            try:
                _read_worker_start_gate(run_dir)
            except FileNotFoundError:
                pass
            except OrchestratorError as exc:
                if not (run_dir / WORKER_START_GATE_FILENAME).exists():
                    pass
                else:
                    raise _runtime_not_trusted("Worker start gate is invalid.") from exc
            else:
                break
            effective_gate_deadline = min(operation_deadline, gate_deadline)
            if time.monotonic() >= effective_gate_deadline:
                raise _runtime_not_trusted(
                    "Worker start gate did not open in time."
                )
            time.sleep(0.01)
    else:
        registration_deadline = min(
            operation_deadline,
            time.monotonic() + WORKER_START_GATE_TIMEOUT_SECONDS,
        )
        while True:
            latest = read_metadata(run_dir)
            if str(latest.get("status") or "") not in {"starting", "running"}:
                raise _runtime_not_trusted(
                    "Controller closed the team worker registration gate."
                )
            if (
                isinstance(latest.get("team_id"), str)
                and latest.get("worker_pid") == os.getpid()
                and isinstance(latest.get("worker_process_identity"), Mapping)
            ):
                break
            if time.monotonic() >= registration_deadline:
                raise _runtime_not_trusted(
                    "Team worker registration did not complete in time."
                )
            time.sleep(0.01)
    with artifact_lock(run_dir):
        metadata = read_metadata(run_dir)
        launch_state = metadata.get("worker_launch")
        team_launch = (
            isinstance(launch_state, Mapping)
            and launch_state.get("controller_handoff") == "team_managed"
        )
        gate = None if team_launch else _read_worker_start_gate(run_dir)
        if str(metadata.get("status") or "") not in {"starting", "running"}:
            raise _runtime_not_trusted("Controller closed the worker start gate.")
        public = metadata.get("runtime_launch")
        worker_launch = metadata.get("worker_launch")
        expected_handoff = "team_managed" if team_launch else "pending"
        if (
            not isinstance(public, dict)
            or not isinstance(worker_launch, dict)
            or public.get("launch_nonce") != nonce
            or worker_launch.get("nonce_consumed") is not False
            or worker_launch.get("start_gate") != "closed"
            or worker_launch.get("controller_handoff") != expected_handoff
        ):
            raise _runtime_not_trusted("Internal worker launch nonce is unavailable.")
        try:
            recorded_identity = ProcessIdentity.from_dict(
                metadata.get("worker_process_identity")
            )
        except (TypeError, ValueError) as exc:
            raise _runtime_not_trusted(
                "Controller worker identity evidence is invalid."
            ) from exc
        controller_pid = metadata.get("controller_pid")
        worker_pid = metadata.get("worker_pid")
        if (
            not isinstance(controller_pid, int)
            or isinstance(controller_pid, bool)
            or controller_pid <= 0
            or worker_pid != os.getpid()
            or recorded_identity.pid != os.getpid()
            or recorded_identity.parent_pid != controller_pid
            or recorded_identity.launch_nonce != nonce
        ):
            raise _runtime_not_trusted(
                "Controller worker identity ownership does not match this process."
            )
        if not team_launch and (
            not isinstance(gate, Mapping)
            or gate.get("state") != "open"
            or gate.get("run_id") != run_dir.name
            or gate.get("launch_nonce") != nonce
            or gate.get("worker_pid") != os.getpid()
            or gate.get("worker_creation_token") != recorded_identity.creation_token
        ):
            raise _runtime_not_trusted(
                "Controller worker identity ownership does not match this process."
            )
        identity_check = compare_process_identity(
            recorded_identity, expected_launch_nonce=nonce
        )
        live_identity = identity_check.live
        if (
            identity_check.state != "match"
            or live_identity is None
            or live_identity.parent_pid != controller_pid
            or live_identity.pid != os.getpid()
            or live_identity.launch_nonce != nonce
        ):
            raise _runtime_not_trusted(
                "Controller worker process identity is no longer stable."
            )
        for field_name in ("process_group_id", "session_id"):
            expected_value = getattr(recorded_identity, field_name)
            if (
                expected_value is not None
                and getattr(live_identity, field_name) != expected_value
            ):
                raise _runtime_not_trusted(
                    "Controller worker process ownership evidence changed."
                )
        expires_raw = worker_launch.get("nonce_expires_at")
        try:
            expires_at = datetime.fromisoformat(str(expires_raw))
        except ValueError as exc:
            raise _runtime_not_trusted("Internal worker launch nonce expiry is invalid.") from exc
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise _runtime_not_trusted("Internal worker launch nonce has expired.")
        worker_launch = dict(worker_launch)
        worker_launch.update(
            {
                "nonce_consumed": True,
                "nonce_consumed_at": utc_now_iso(),
                **(
                    {
                        "controller_handoff": "ready",
                        "controller_handoff_ready_at": utc_now_iso(),
                    }
                    if not team_launch
                    else {}
                ),
            }
        )
        metadata["worker_launch"] = worker_launch
        _atomic_write_bytes(run_dir / "metadata.json", _metadata_bytes(metadata))
        return metadata


def _worker_security_failure(
    run_dir: Path,
    error: RuntimeSecurityError,
    *,
    response_updates: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    updates = dict(response_updates or {})
    timed_out = _has_timeout_evidence(
        updates
    ) or _transaction_deadline_expired(
        fallback=_effective_deadline()
    )
    if timed_out:
        updates.update(
            _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
        )
    status = (
        "timed_out"
        if timed_out
        else "blocked_runtime_identity"
        if error.code == "runtime_identity_changed"
        else "blocked_runtime_security"
    )
    response = {
        "ok": False,
        "run_id": run_dir.name,
        "status": status,
        "security_error": error.to_dict(),
        **updates,
    }
    scope = _terminal_artifact_scope() if timed_out else contextlib.nullcontext()
    with scope:
        try:
            metadata = read_metadata(run_dir)
        except Exception:
            metadata = {"run_id": run_dir.name, "terminal_state_count": 0}
        if (
            metadata.get("status") in {None, "starting", "running"}
            and metadata.get("worker_pid") in {None, os.getpid()}
        ):
            recorded = _record_blocked_launch(
                run_dir,
                metadata,
                status=status,
                error=error,
                worker_pid=os.getpid(),
                **updates,
            )
            response.update(
                {
                    "persisted": recorded.get("persisted", False),
                    "persistence_state": recorded.get(
                        "persistence_state", "degraded"
                    ),
                }
            )
    return response


def _stream_worker_inner(run_id: str) -> dict[str, Any]:
    """Consume one controller-approved launch and own the runtime child handle."""
    run_dir = safe_run_dir(run_id)
    try:
        frame = _read_bounded_payload(
            sys.stdin.buffer, PRIVATE_LAUNCH_FRAME_LIMIT, "frame"
        )
        prompt_bytes = _read_bounded_payload(
            sys.stdin.buffer, PROMPT_BYTES_LIMIT, "prompt"
        )
        metadata, executable_identity, arguments = _parse_worker_frame(
            run_dir, frame
        )
        expected_prompt_bytes = metadata.get("prompt_bytes")
        if (
            not isinstance(expected_prompt_bytes, int)
            or isinstance(expected_prompt_bytes, bool)
            or expected_prompt_bytes != len(prompt_bytes)
        ):
            raise _runtime_not_trusted(
                "Internal worker prompt length does not match metadata."
            )
        if _read_protocol_trailer(sys.stdin.buffer) != b"":
            raise _runtime_not_trusted(
                "Internal worker launch payload has trailing data."
            )
        nonce = str(metadata["runtime_launch"]["launch_nonce"])
        metadata = _consume_worker_nonce(run_dir, nonce)
        metadata = _wait_for_controller_handoff_acceptance(
            run_dir, metadata
        )
        if not executable_identity.matches_current_file():
            raise _runtime_identity_changed(executable_identity.canonical_path)
    except RuntimeSecurityError as error:
        return _worker_security_failure(run_dir, error)
    except TimeoutError:
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted(
                "Internal worker launch state exceeded its deadline."
            ),
            response_updates=_worker_cleanup_response_updates(
                timed_out=True, stopped=False
            ),
        )
    except (OSError, OrchestratorError, TypeError, ValueError):
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted(
                "Internal worker launch state could not be verified."
            ),
        )

    timeout = int(metadata.get("timeout_seconds") or 1800)
    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    workspace_root = Path(
        str(metadata.get("workspace_root") or cwd)
    ).resolve()
    command = _runtime_command(executable_identity, arguments)
    environment_keys = json.loads(frame.decode("utf-8"))["environment_keys"]
    runtime_env = {key: os.environ[key] for key in environment_keys}
    sensitive_values = _normalize_sensitive_values(
        (
            *_prompt_sensitive_values(prompt_bytes),
            *(
                value
                for key, value in runtime_env.items()
                if value and should_redact_key(key, value)
            ),
            *(
                secret
                for value in runtime_env.values()
                if value
                for secret in _endpoint_sensitive_values(value)
            ),
        )
    )
    try:
        append_event(
            run_dir, {"type": "stream_worker_ready", "worker_pid": os.getpid()}
        )
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed", "Worker readiness metadata could not be persisted."
            ),
        )
    try:
        git_before_raw = capture_git_snapshot(
            run_dir, workspace_root, "before", sensitive_values
        )
        if (
            git_before_raw.get("ok") is not True
            or git_before_raw.get("evidence_complete") is not True
            or git_before_raw.get("_raw_evidence_complete") is not True
        ):
            raise OrchestratorError("Pre-launch Git evidence is unavailable.")
        metadata = update_metadata(
            run_dir,
            git_before=_git_snapshot_projection(
                git_before_raw, sensitive_values
            ),
        )
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed",
                "Pre-launch Git evidence could not be persisted safely.",
            ),
        )
    try:
        pinned_scope = _pin_write_scope_policy(workspace_root)
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "write_scope_invalid",
                "The write-scope policy could not be pinned before runtime launch.",
            ),
        )
    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True
    event_lock = threading.Lock()
    budget_lock = threading.Lock()
    budget = output_budget_from_metadata(metadata, run_dir)
    budget_stop = threading.Event()
    actual_route_recorded = threading.Event()
    route_mismatch_recorded = threading.Event()
    if not executable_identity.matches_current_file():
        return _worker_security_failure(
            run_dir, _runtime_identity_changed(executable_identity.canonical_path)
        )
    launch_deadline = _effective_deadline()
    if launch_deadline is None:
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted("Streaming transaction deadline is unavailable."),
        )
    if metadata.get("team_id"):
        try:
            metadata = _complete_team_worker_preflight(
                run_dir, nonce, pinned_scope
            )
            metadata = _wait_for_team_authorization(run_dir, metadata)
        except RuntimeSecurityError as error:
            return _worker_security_failure(run_dir, error)
        except Exception:
            return _worker_security_failure(
                run_dir,
                _runtime_not_trusted(
                    "Team member preflight or authorization could not be verified."
                ),
            )
    try:
        proc = _owned_process_popen(
            command,
            final_identity=executable_identity,
            cwd=str(cwd),
            env=runtime_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            **popen_kwargs,
        )
    except RuntimeSecurityError as error:
        return _worker_security_failure(run_dir, error)
    except TimeoutError:
        timeout_updates = _worker_cleanup_response_updates(
            timed_out=True, stopped=False
        )
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="timed_out",
            error=_launch_failure_error(
                "runtime_launch_timeout",
                "Runtime process creation exceeded the launch deadline.",
            ),
            **timeout_updates,
        )
    except OSError:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "runtime_launch_failed", "The approved runtime process could not be started."
            ),
        )
    try:
        started_monotonic = time.monotonic()
        runtime_deadline = _runtime_execution_deadline(
            launch_deadline, started_monotonic
        )
        timeout_cleanup_deadline = _owned_process_cleanup_deadline(
            proc,
            launch_deadline,
            timeout_evidence=True,
        )
        if timeout_cleanup_deadline is None:
            timeout_cleanup_deadline = launch_deadline
        io_cancel = threading.Event()
        io_errors: queue.Queue[tuple[str, BaseException]] = queue.Queue()
        stdout_queue: queue.Queue[bytes | None] = queue.Queue(maxsize=64)
        stderr_queue: queue.Queue[bytes | None] = queue.Queue(maxsize=64)
        termination_lock = threading.Lock()
        termination_requested = threading.Event()
        cleanup_pending = threading.Event()
        if time.monotonic() >= runtime_deadline:
            io_cancel.set()
    except Exception:
        if not _terminate_owned_process(proc, deadline=launch_deadline):
            raise _OwnedCleanupPending(proc)
        raise

    def terminate_child_once(*, timeout_cleanup: bool = False) -> None:
        with termination_lock:
            if termination_requested.is_set():
                return
            termination_requested.set()
            if not _terminate_owned_process(
                proc,
                deadline=(
                    timeout_cleanup_deadline
                    if timeout_cleanup
                    else launch_deadline
                ),
            ):
                cleanup_pending.set()

    def drain_output(
        stream: Any, destination: queue.Queue[bytes | None], source: str
    ) -> None:
        def enqueue(payload: bytes | None) -> bool:
            while not io_cancel.is_set():
                remaining = _remaining_deadline(launch_deadline, 0.05)
                if remaining <= 0:
                    return False
                try:
                    destination.put(payload, timeout=remaining)
                    return True
                except queue.Full:
                    continue
            return False

        try:
            pending = b""
            read_chunk = getattr(stream, "read1", stream.read)
            while True:
                chunk = read_chunk(64 * 1024)
                if not chunk:
                    break
                pending += (
                    chunk
                    if isinstance(chunk, bytes)
                    else str(chunk).encode("utf-8", errors="replace")
                )
                if b"\n" in pending:
                    complete_lines = pending.split(b"\n")
                    pending = complete_lines.pop()
                    for raw_line in complete_lines:
                        if not enqueue(raw_line + b"\n"):
                            return
                while len(pending) >= 64 * 1024:
                    if not enqueue(pending[: 64 * 1024]):
                        return
                    pending = pending[64 * 1024 :]
            if pending:
                enqueue(pending)
        except (OSError, ValueError) as exc:
            if not io_cancel.is_set():
                io_errors.put((source, exc))
        finally:
            if not io_cancel.is_set():
                enqueue(None)

    def pump_stdin() -> None:
        pipe = proc.stdin
        try:
            if pipe is None:
                raise BrokenPipeError("runtime stdin is unavailable")
            for offset in range(0, len(prompt_bytes), 64 * 1024):
                if io_cancel.is_set():
                    break
                _write_pipe_chunk(pipe, prompt_bytes[offset : offset + 64 * 1024])
            pipe.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            if not io_cancel.is_set():
                io_errors.put(("stdin", exc))
        finally:
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass
            proc.stdin = None

    def run_with_deadline(target: Any, *args: Any) -> None:
        token = _OPERATION_DEADLINE.set(launch_deadline)
        try:
            target(*args)
        finally:
            _OPERATION_DEADLINE.reset(token)

    started_io_threads: list[threading.Thread] = []
    try:
        drain_threads = [
            threading.Thread(
                target=run_with_deadline,
                args=(drain_output, proc.stdout, stdout_queue, "stdout"),
                name=f"cc-runtime-stdout-{run_id}",
                daemon=True,
            ),
            threading.Thread(
                target=run_with_deadline,
                args=(drain_output, proc.stderr, stderr_queue, "stderr"),
                name=f"cc-runtime-stderr-{run_id}",
                daemon=True,
            ),
        ]
        stdin_thread = threading.Thread(
            target=run_with_deadline,
            args=(pump_stdin,),
            name=f"cc-runtime-stdin-{run_id}",
            daemon=True,
        )
        for thread in drain_threads:
            thread.start()
            started_io_threads.append(thread)
        stdin_thread.start()
        started_io_threads.append(stdin_thread)
    except Exception:
        io_cancel.set()
        if not _terminate_owned_process(proc, deadline=launch_deadline):
            cleanup_pending.set()
        for pending_queue in (stdout_queue, stderr_queue):
            while True:
                try:
                    pending_queue.get_nowait()
                except queue.Empty:
                    break
        for thread in started_io_threads:
            remaining = _remaining_deadline(launch_deadline, 1.0)
            if remaining > 0:
                thread.join(timeout=remaining)
        if cleanup_pending.is_set() or any(
            thread.is_alive() for thread in started_io_threads
        ):
            raise _OwnedCleanupPending(proc, started_io_threads)
        raise

    def cleanup_initial_io(*, timed_out: bool = False) -> None:
        cleanup_deadline = (
            timeout_cleanup_deadline if timed_out else launch_deadline
        )
        io_cancel.set()
        terminate_child_once(timeout_cleanup=timed_out)
        remaining = _remaining_deadline(cleanup_deadline, 5.0)
        if remaining > 0:
            stdin_thread.join(timeout=remaining)
        while (
            any(thread.is_alive() for thread in drain_threads)
            and time.monotonic() < cleanup_deadline
        ):
            for pending_queue in (stdout_queue, stderr_queue):
                while True:
                    try:
                        pending_queue.get_nowait()
                    except queue.Empty:
                        break
            for thread in drain_threads:
                thread.join(
                    timeout=min(
                        0.01,
                        _remaining_deadline(cleanup_deadline, 0.01),
                    )
                )
        for pending_queue in (stdout_queue, stderr_queue):
            while True:
                try:
                    pending_queue.get_nowait()
                except queue.Empty:
                    break
        if (
            cleanup_pending.is_set()
            or proc.poll() is None
            or any(thread.is_alive() for thread in started_io_threads)
        ):
            raise _OwnedCleanupPending(
                proc,
                started_io_threads,
                response_updates=_worker_cleanup_response_updates(
                    timed_out=timed_out, stopped=False
                ),
            )

    try:
        try:
            child_identity = capture_process_identity(proc.pid, launch_nonce=nonce)
            _validate_started_identity(
                child_identity, executable_identity, process_kind="runtime child"
            )
            _check_deadline(
                launch_deadline,
                "Runtime identity validation exceeded the launch deadline.",
            )
            if not executable_identity.matches_current_file():
                raise _runtime_identity_changed(executable_identity.canonical_path)
            metadata = update_metadata(
                run_dir,
                status="running",
                child_pid=proc.pid,
                child_process_identity=child_identity.to_dict(),
            )
            _atomic_write_text(run_dir / "pid.txt", str(proc.pid))
            append_event(
                run_dir,
                {"type": "process_started", "pid": proc.pid, "status": "running"},
            )
        except TimeoutError:
            cleanup_initial_io(timed_out=True)
            timeout_updates = _worker_cleanup_response_updates(
                timed_out=True, stopped=False
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=sensitive_values,
                status="timed_out",
                error=_launch_failure_error(
                    "runtime_initialization_timeout",
                    "Runtime child initialization exceeded the launch deadline.",
                ),
                child_pid=proc.pid,
                **timeout_updates,
            )
        except RuntimeSecurityError as error:
            cleanup_initial_io()
            status = (
                "blocked_runtime_identity"
                if error.code == "runtime_identity_changed"
                else "blocked_process_identity"
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=sensitive_values,
                status=status,
                error=error,
                child_pid=proc.pid,
            )
        except (BrokenPipeError, OSError, TypeError, ValueError) as exc:
            cleanup_initial_io()
            error = (
                _process_identity_unverified(proc.pid, "runtime child")
                if isinstance(exc, (TypeError, ValueError))
                else _launch_failure_error(
                    "worker_protocol_failed", "The runtime prompt pipe failed."
                )
            )
            return _record_blocked_launch(
                run_dir,
                metadata,
                sensitive_values=sensitive_values,
                status=(
                    "blocked_process_identity"
                    if error.code == "process_identity_unverified"
                    else "blocked_runtime_launch"
                ),
                error=error,
                child_pid=proc.pid,
            )
    except _OwnedCleanupPending:
        raise
    except Exception:
        cleanup_initial_io()
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "artifact_write_failed", "Child process metadata could not be persisted."
            ),
            child_pid=proc.pid,
        )
    def persist_budget_unlocked(stop_reason: str | None = None) -> None:
        updates: dict[str, Any] = {"output_budget": dict(budget)}
        if stop_reason:
            updates["stop_reason"] = stop_reason
        update_metadata(run_dir, **updates)

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
        event = _scrub_guarded_value(event, sensitive_values)
        if not event_is_final_or_control(event):
            with budget_lock:
                budget["dropped_event_count"] = int(budget.get("dropped_event_count") or 0) + 1
            return
        encoded = (json.dumps(sanitize_for_json(event), ensure_ascii=False) + "\n").encode("utf-8", errors="replace")
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
        summary = _scrub_guarded_value(
            actual_route_from_payload(payload, declared_model=declared_model),
            sensitive_values,
        )
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

    def pump(
        source_queue: queue.Queue[bytes | None], out_path: Path, source: str
    ) -> None:
        try:
            with _open_managed_file(
                out_path, writable=True, verify_private=False
            ) as (out, _details):
                out.seek(0, os.SEEK_END)
                while True:
                    try:
                        raw_line = source_queue.get(
                            timeout=max(
                                0.001,
                                _remaining_deadline(launch_deadline, 0.05),
                            )
                        )
                    except queue.Empty:
                        if io_cancel.is_set() or time.monotonic() >= launch_deadline:
                            break
                        continue
                    if raw_line is None:
                        break
                    raw_bytes = (
                        len(raw_line)
                        if isinstance(raw_line, bytes)
                        else len(str(raw_line).encode("utf-8", errors="replace"))
                    )
                    if io_cancel.is_set() or time.monotonic() >= runtime_deadline:
                        with budget_lock:
                            budget["observed_output_bytes"] = int(
                                budget.get("observed_output_bytes") or 0
                            ) + raw_bytes
                            budget["dropped_output_bytes"] = int(
                                budget.get("dropped_output_bytes") or 0
                            ) + raw_bytes
                        continue
                    with budget_lock:
                        budget["observed_output_bytes"] = int(
                            budget.get("observed_output_bytes") or 0
                        ) + raw_bytes
                        discard_transport = budget.get("state") in {
                            "truncated",
                            "stopped",
                        }
                        if discard_transport:
                            budget["dropped_output_bytes"] = int(
                                budget.get("dropped_output_bytes") or 0
                            ) + raw_bytes
                    if discard_transport:
                        continue
                    line = (
                        raw_line.decode("utf-8", errors="replace")
                        if isinstance(raw_line, bytes)
                        else str(raw_line)
                    )
                    safe_line = _scrub_exact_text(line, sensitive_values)
                    raw_payload: Any | None = None
                    if source == "stdout":
                        try:
                            raw_payload = json.loads(line)
                            parsed_payload: Any = _scrub_guarded_value(
                                raw_payload, sensitive_values
                            )
                            safe_line = json.dumps(
                                parsed_payload, ensure_ascii=False
                            ) + ("\n" if line.endswith(("\n", "\r")) else "")
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
                            budget["dropped_output_bytes"] = int(budget.get("dropped_output_bytes") or 0) + raw_bytes
                        continue
                    if budget.get("final_only") and isinstance(parsed_payload, dict) and parsed_payload.get("type") == "result" and parsed_payload.get("result") is not None:
                        safe_line = _scrub_exact_text(
                            str(parsed_payload.get("result")), sensitive_values
                        ).rstrip("\r\n") + "\n"
                    safe_line_bytes = len(safe_line.encode("utf-8", errors="replace"))
                    write_line = True
                    with budget_lock:
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
                    safe_payload = safe_line.encode("utf-8", errors="replace")
                    if out.tell() + len(safe_payload) > MAX_MANAGED_ARTIFACT_BYTES:
                        raise OrchestratorError(
                            f"Managed artifact exceeds its size limit: {out_path.name}"
                        )
                    out.write(safe_payload)
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
        except Exception as exc:
            io_cancel.set()
            io_errors.put((source, exc))

    try:
        threads = [
            threading.Thread(target=run_with_deadline, args=(pump, stdout_queue, run_dir / "stdout.txt", "stdout"), daemon=True),
            threading.Thread(target=run_with_deadline, args=(pump, stderr_queue, run_dir / "stderr.txt", "stderr"), daemon=True),
        ]
        for thread in threads:
            thread.start()
            started_io_threads.append(thread)
    except Exception:
        io_cancel.set()
        terminate_child_once()
        for pending_queue in (stdout_queue, stderr_queue):
            while True:
                try:
                    pending_queue.get_nowait()
                except queue.Empty:
                    break
        for thread in started_io_threads:
            remaining = _remaining_deadline(launch_deadline, 1.0)
            if remaining > 0:
                thread.join(timeout=remaining)
        if (
            cleanup_pending.is_set()
            or proc.poll() is None
            or any(thread.is_alive() for thread in started_io_threads)
        ):
            raise _OwnedCleanupPending(proc, started_io_threads)
        raise _OwnedCleanupPending(proc, started_io_threads)

    timed_out = False
    stopped = False
    io_failed = False
    exit_code: int | None = None
    try:
        while True:
            try:
                io_source, io_error = io_errors.get_nowait()
            except queue.Empty:
                pass
            else:
                io_failed = True
                io_cancel.set()
                safe_append(
                    {
                        "type": "stream_pump_error",
                        "source": io_source,
                        "error": str(io_error),
                    }
                )
                terminate_child_once()
            exit_code = proc.poll()
            if exit_code is not None:
                break
            if _valid_stop_request(run_dir, metadata):
                stopped = True
                io_cancel.set()
                terminate_child_once()
            if budget_stop.is_set():
                stopped = True
                io_cancel.set()
                terminate_child_once()
            if not timed_out and time.monotonic() >= runtime_deadline:
                timed_out = True
                safe_append({"type": "timeout", "timeout_seconds": timeout})
                with budget_lock:
                    budget["stop_reason"] = "timeout"
                    persist_budget_unlocked("timeout")
                io_cancel.set()
                terminate_child_once(timeout_cleanup=True)
            sleep_deadline = (
                timeout_cleanup_deadline
                if timed_out
                else launch_deadline
                if stopped or io_failed
                else runtime_deadline
            )
            if not _sleep_stream_worker_iteration(
                sleep_deadline,
                termination_requested=(timed_out or stopped or io_failed),
            ):
                break
        try:
            wait_deadline = (
                timeout_cleanup_deadline if timed_out else runtime_deadline
            )
            remaining = _remaining_deadline(wait_deadline, 5.0)
            if remaining <= 0 and proc.poll() is None:
                raise subprocess.TimeoutExpired(proc.args, 0)
            exit_code = proc.wait(timeout=max(remaining, 0.001))
        except subprocess.TimeoutExpired:
            io_cancel.set()
            terminate_child_once(timeout_cleanup=timed_out)
            exit_code = proc.poll()
    finally:
        cleanup_deadline = (
            timeout_cleanup_deadline if timed_out else launch_deadline
        )
        if proc.poll() is None:
            io_cancel.set()
            terminate_child_once(timeout_cleanup=timed_out)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        remaining = _remaining_deadline(cleanup_deadline, 5.0)
        if remaining > 0:
            stdin_thread.join(timeout=remaining)
        io_pairs = tuple(zip(drain_threads, threads, (stdout_queue, stderr_queue)))
        while any(
            drain.is_alive() or pump_thread.is_alive()
            for drain, pump_thread, _pending in io_pairs
        ) and time.monotonic() < cleanup_deadline:
            for drain, pump_thread, pending_queue in io_pairs:
                if not pump_thread.is_alive():
                    while True:
                        try:
                            pending_queue.get_nowait()
                        except queue.Empty:
                            break
                remaining = _remaining_deadline(cleanup_deadline, 0.01)
                if remaining <= 0:
                    break
                drain.join(timeout=remaining)
                pump_thread.join(timeout=remaining)
        alive_threads = [
            thread.name for thread in started_io_threads if thread.is_alive()
        ]
        if alive_threads:
            raise _OwnedCleanupPending(
                proc,
                started_io_threads,
                response_updates=_worker_cleanup_response_updates(
                    timed_out=timed_out, stopped=stopped
                ),
            )
        if cleanup_pending.is_set() or proc.poll() is None:
            raise _OwnedCleanupPending(
                proc,
                started_io_threads,
                response_updates=_worker_cleanup_response_updates(
                    timed_out=timed_out, stopped=stopped
                ),
            )

    cleanup_confirmed = _release_owned_containment(
        proc,
        terminate_descendants=True,
        deadline=(timeout_cleanup_deadline if timed_out else launch_deadline),
        threads=tuple(started_io_threads),
    )
    if not cleanup_confirmed:
        _mark_owned_cleanup_incomplete(
            proc, "normal_completion_containment_unconfirmed"
        )
        raise _OwnedCleanupPending(
            proc,
            started_io_threads,
            response_updates=_worker_cleanup_response_updates(
                timed_out=timed_out, stopped=stopped
            ),
        )
    metadata = update_metadata(
        run_dir,
        cleanup_state="cleanup_confirmed",
        owned_process_pid=proc.pid,
        live_cleanup_threads=[],
    )

    while True:
        try:
            io_source, io_error = io_errors.get_nowait()
        except queue.Empty:
            break
        io_failed = True
        try:
            safe_append(
                {
                    "type": "stream_pump_error",
                    "source": io_source,
                    "error": str(io_error),
                }
            )
        except Exception:
            pass

    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    try:
        latest_metadata = read_metadata(run_dir)
    except Exception:
        latest_metadata = dict(metadata)
    stopped = stopped or bool(latest_metadata.get("stop_requested_at"))
    if timed_out:
        status = "timed_out"
        final_exit = 124
    elif stopped:
        status = "stopped"
        final_exit = -15 if exit_code is None else exit_code
    elif io_failed:
        status = "failed"
        final_exit = 1 if exit_code in {None, 0} else exit_code
    else:
        final_exit = 0 if exit_code is None else exit_code
        status = "succeeded" if final_exit == 0 else "failed"
    try:
        with budget_lock:
            budget.update(output_budget_from_metadata({"output_budget": budget}, run_dir))
            if stopped and not budget.get("stop_reason"):
                budget["stop_reason"] = "user_requested"
            terminal_budget = dict(budget)
    except Exception:
        with budget_lock:
            terminal_budget = dict(budget)
    if time.monotonic() >= launch_deadline and not stopped:
        timed_out = True
        status = "timed_out"
        final_exit = 124
        terminal_budget["stop_reason"] = "timeout"
    if timed_out:
        git_after_raw = _failed_git_snapshot(
            "after",
            TimeoutError(
                "Post-run Git evidence was not captured after timeout."
            ),
            sensitive_values,
            is_git_repo=bool(git_before_raw.get("is_git_repo")),
        )
    else:
        try:
            git_after_raw = capture_git_snapshot(
                run_dir,
                workspace_root,
                "after",
                sensitive_values,
                deadline=launch_deadline,
            )
        except Exception as exc:
            git_after_raw = _failed_git_snapshot(
                "after",
                exc,
                sensitive_values,
                is_git_repo=bool(git_before_raw.get("is_git_repo")),
            )
    git_finalization_failed = (
        git_after_raw.get("ok") is not True
        or git_after_raw.get("evidence_complete") is not True
        or git_after_raw.get(
            "_raw_evidence_complete",
            git_after_raw.get("evidence_complete"),
        )
        is not True
    )
    if time.monotonic() >= launch_deadline and not stopped:
        timed_out = True
        status = "timed_out"
        final_exit = 124
        terminal_budget["stop_reason"] = "timeout"
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)

    (
        scope_check_raw,
        scope_finalization_failed,
        scope_deadline_crossed,
    ) = _terminal_write_scope_evidence(
        run_id,
        workspace_root,
        git_before_raw,
        git_after_raw,
        pinned_scope,
        timed_out=timed_out,
    )
    if scope_deadline_crossed:
        timed_out = True
        status = "timed_out"
        final_exit = 124
        terminal_budget["stop_reason"] = "timeout"
    if (git_finalization_failed or scope_finalization_failed) and not timed_out:
        status = "failed"
        if final_exit in {None, 0}:
            final_exit = 1
    git_after = _git_snapshot_projection(git_after_raw, sensitive_values)
    scope_check = _scrub_guarded_value(scope_check_raw, sensitive_values)
    acceptance_status = (
        "pending_controller_review"
        if scope_check.get("ok") is True
        else "blocked_write_scope"
    )
    stop_reason = terminal_budget.get("stop_reason") or (
        "timeout" if timed_out else "user_requested" if stopped else None
    )
    terminal_updates = {
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "stdout_path": str(run_dir / "stdout.txt"),
        "stderr_path": str(run_dir / "stderr.txt"),
        "events_path": str(run_dir / "events.ndjson"),
        "output_budget": terminal_budget,
        "stop_reason": stop_reason,
        "git_after": git_after,
        "write_scope_check": scope_check,
        "acceptance_status": acceptance_status,
        "cleanup_state": "cleanup_confirmed",
        "owned_process_pid": proc.pid,
        "live_cleanup_threads": [],
        "status": status,
        "finished_at": utc_now_iso(),
        "exit_code": final_exit,
    }
    if io_failed:
        terminal_updates.update(
            {
                "acceptance_status": "blocked_artifact_finalization",
                "finalization_state": "failed",
                "finalization_error": {
                    "code": "artifact_finalization_failed",
                    "message": "Streaming execution artifacts could not be finalized safely.",
                },
            }
        )
    terminal_events: list[Mapping[str, Any]] = []
    if scope_check.get("ok") is not True:
        terminal_events.append(
            {
                "type": "write_scope_blocked",
                "status": "blocked",
                "violations": scope_check.get("violations", []),
            }
        )
    terminal_events.append(
        {
            "type": "process_exited",
            "status": status,
            "exit_code": final_exit,
            "duration_ms": duration_ms,
        }
    )
    return _persist_streaming_terminal_state(
        run_dir,
        latest_metadata,
        updates=terminal_updates,
        events=tuple(terminal_events),
        sensitive_values=sensitive_values,
        remove_pid=True,
        launch_deadline=launch_deadline,
    )


def _write_windows_console_input(handle: Any, text: str) -> None:
    """Inject the initial prompt into the new console without using argv or disk."""
    if os.name != "nt":
        raise OSError("Console input injection is only supported on Windows.")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class CharUnion(ctypes.Union):
        _fields_ = [("UnicodeChar", wintypes.WCHAR), ("AsciiChar", ctypes.c_char)]

    class KeyEventRecord(ctypes.Structure):
        _fields_ = [
            ("bKeyDown", wintypes.BOOL),
            ("wRepeatCount", wintypes.WORD),
            ("wVirtualKeyCode", wintypes.WORD),
            ("wVirtualScanCode", wintypes.WORD),
            ("uChar", CharUnion),
            ("dwControlKeyState", wintypes.DWORD),
        ]

    class EventUnion(ctypes.Union):
        _fields_ = [("KeyEvent", KeyEventRecord), ("padding", ctypes.c_byte * 16)]

    class InputRecord(ctypes.Structure):
        _fields_ = [("EventType", wintypes.WORD), ("Event", EventUnion)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    native_handle = msvcrt.get_osfhandle(handle.fileno())
    content = text.replace("\r\n", "\n").replace("\r", "\n") + "\r"
    for offset in range(0, len(content), 2048):
        chunk = content[offset : offset + 2048]
        records = (InputRecord * (len(chunk) * 2))()
        for index, character in enumerate(chunk):
            virtual_key = 0x0D if character == "\r" else 0
            for down in (True, False):
                record = records[index * 2 + (0 if down else 1)]
                record.EventType = 0x0001
                record.Event.KeyEvent.bKeyDown = down
                record.Event.KeyEvent.wRepeatCount = 1
                record.Event.KeyEvent.wVirtualKeyCode = virtual_key
                record.Event.KeyEvent.uChar.UnicodeChar = character
        written = wintypes.DWORD()
        if not kernel32.WriteConsoleInputW(
            native_handle,
            records,
            len(records),
            ctypes.byref(written),
        ) or written.value != len(records):
            raise OSError(ctypes.get_last_error(), "Could not inject the visible prompt")


def _visible_worker_inner(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    try:
        frame = _read_bounded_payload(
            sys.stdin.buffer, PRIVATE_LAUNCH_FRAME_LIMIT, "frame"
        )
        prompt_bytes = _read_bounded_payload(
            sys.stdin.buffer, PROMPT_BYTES_LIMIT, "prompt"
        )
        metadata, executable_identity, arguments = _parse_worker_frame(run_dir, frame)
        if metadata.get("mode") != "visible_window":
            raise _runtime_not_trusted("Visible worker mode does not match metadata.")
        if metadata.get("prompt_bytes") != len(prompt_bytes):
            raise _runtime_not_trusted("Visible worker prompt length does not match metadata.")
        if _read_protocol_trailer(sys.stdin.buffer) != b"":
            raise _runtime_not_trusted("Visible worker launch payload has trailing data.")
        nonce = str(metadata["runtime_launch"]["launch_nonce"])
        metadata = _consume_worker_nonce(run_dir, nonce)
        metadata = _wait_for_controller_handoff_acceptance(run_dir, metadata)
        if not executable_identity.matches_current_file():
            raise _runtime_identity_changed(executable_identity.canonical_path)
    except RuntimeSecurityError as error:
        return _worker_security_failure(run_dir, error)
    except Exception:
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted("Visible worker launch state could not be verified."),
        )

    cwd = Path(str(metadata.get("cwd") or Path.cwd()))
    workspace_root = Path(str(metadata.get("workspace_root") or cwd)).resolve()
    environment_keys = json.loads(frame.decode("utf-8"))["environment_keys"]
    runtime_env = {key: os.environ[key] for key in environment_keys}
    sensitive_values = _normalize_sensitive_values(
        (
            *_prompt_sensitive_values(prompt_bytes),
            *(value for key, value in runtime_env.items() if value and should_redact_key(key, value)),
        )
    )
    launch_deadline = _effective_deadline()
    if launch_deadline is None:
        return _worker_security_failure(
            run_dir, _runtime_not_trusted("Visible transaction deadline is unavailable.")
        )
    try:
        git_before_raw = capture_git_snapshot(
            run_dir, workspace_root, "before", sensitive_values
        )
        if not git_before_raw.get("evidence_complete"):
            raise OrchestratorError("Pre-launch Git evidence is unavailable.")
        metadata = update_metadata(
            run_dir,
            git_before=_git_snapshot_projection(git_before_raw, sensitive_values),
        )
        pinned_scope = _pin_write_scope_policy(workspace_root)
    except Exception:
        return _record_blocked_launch(
            run_dir,
            metadata,
            sensitive_values=sensitive_values,
            status="blocked_runtime_launch",
            error=_launch_failure_error(
                "write_scope_invalid", "Visible launch preflight could not be pinned."
            ),
        )
    if not executable_identity.matches_current_file():
        return _worker_security_failure(
            run_dir, _runtime_identity_changed(executable_identity.canonical_path)
        )

    console_in = None
    console_out = None
    proc: subprocess.Popen[bytes] | None = None
    started_monotonic = time.monotonic()
    timed_out = False
    try:
        console_in = open("CONIN$", "rb", buffering=0)
        console_out = open("CONOUT$", "wb", buffering=0)
        command = _runtime_command(executable_identity, arguments)
        proc = _owned_process_popen(
            command,
            final_identity=executable_identity,
            cwd=str(cwd),
            env=runtime_env,
            stdin=console_in,
            stdout=console_out,
            stderr=console_out,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        child_identity = capture_process_identity(proc.pid, launch_nonce=nonce)
        _validate_started_identity(
            child_identity, executable_identity, process_kind="visible runtime child"
        )
        if not executable_identity.matches_current_file():
            raise _runtime_identity_changed(executable_identity.canonical_path)
        metadata = update_metadata(
            run_dir,
            status="running",
            child_pid=proc.pid,
            child_process_identity=child_identity.to_dict(),
            visible_console_input="CONIN$",
        )
        _atomic_write_text(run_dir / "pid.txt", str(proc.pid))
        append_event(
            run_dir,
            {"type": "process_started", "pid": proc.pid, "status": "running"},
        )
        prompt_text = prompt_bytes.decode("utf-8")
        _write_windows_console_input(console_in, prompt_text)
        remaining = _remaining_deadline(
            _runtime_execution_deadline(launch_deadline, started_monotonic),
            float(metadata.get("timeout_seconds") or 1800),
        )
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, 0)
        exit_code = proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = 124
        if proc is not None:
            cleanup_deadline = _owned_process_cleanup_deadline(
                proc, launch_deadline, timeout_evidence=True
            )
            if not _terminate_owned_process(
                proc,
                deadline=cleanup_deadline,
            ):
                raise _OwnedCleanupPending(
                    proc,
                    response_updates=_worker_cleanup_response_updates(
                        timed_out=True, stopped=False
                    ),
                )
    except RuntimeSecurityError as error:
        if proc is not None and not _terminate_owned_process(
            proc, deadline=launch_deadline
        ):
            raise _OwnedCleanupPending(proc) from error
        return _worker_security_failure(run_dir, error)
    except _OwnedCleanupPending:
        raise
    except Exception as error:
        if proc is not None and not _terminate_owned_process(
            proc, deadline=launch_deadline
        ):
            raise _OwnedCleanupPending(proc) from error
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted("Visible runtime could not be started or supervised."),
        )
    finally:
        for handle in (console_in, console_out):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass

    assert proc is not None
    if proc.poll() is None:
        cleanup_confirmed = _terminate_owned_process(
            proc, deadline=launch_deadline
        )
    else:
        _close_process_streams(proc)
        cleanup_confirmed = _release_owned_containment(
            proc, terminate_descendants=True, deadline=launch_deadline
        )
    if not cleanup_confirmed:
        raise _OwnedCleanupPending(
            proc,
            response_updates=_worker_cleanup_response_updates(
                timed_out=timed_out, stopped=False
            ),
        )
    try:
        git_after_raw = capture_git_snapshot(
            run_dir, workspace_root, "after", sensitive_values
        )
        scope_check, _scope_failed, _scope_deadline_crossed = _terminal_write_scope_evidence(
            run_id,
            workspace_root,
            git_before_raw,
            git_after_raw,
            pinned_scope,
            timed_out=timed_out,
        )
    except Exception:
        git_after_raw = _failed_git_snapshot(
            "after", OrchestratorError("Visible post-run evidence failed."), sensitive_values
        )
        scope_check = {"ok": False, "violations": ["post_run_evidence_unavailable"]}
    status = "timed_out" if timed_out else "succeeded" if exit_code == 0 else "failed"
    updates = {
        "status": status,
        "finished_at": utc_now_iso(),
        "duration_ms": int((time.monotonic() - started_monotonic) * 1000),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stop_reason": "timeout" if timed_out else None,
        "git_after": _git_snapshot_projection(git_after_raw, sensitive_values),
        "write_scope_check": _scrub_guarded_value(scope_check, sensitive_values),
        "cleanup_state": "cleanup_confirmed",
    }
    return _persist_streaming_terminal_state(
        run_dir,
        metadata,
        updates=updates,
        events=(
            {
                "type": "process_exited",
                "status": status,
                "exit_code": exit_code,
                "duration_ms": updates["duration_ms"],
            },
        ),
        sensitive_values=sensitive_values,
        remove_pid=True,
        launch_deadline=launch_deadline,
    )


def visible_worker(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    try:
        initial = read_metadata(run_dir)
    except Exception:
        initial = {"run_id": run_id}
    deadline = initial.get("transaction_deadline_monotonic")
    if (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
    ):
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted("Visible transaction deadline evidence is invalid."),
        )
    token = _OPERATION_DEADLINE.set(float(deadline))
    try:
        try:
            return _visible_worker_inner(run_id)
        except _OwnedCleanupPending as pending:
            try:
                latest = read_metadata(run_dir)
            except Exception:
                latest = initial
            return _complete_isolated_worker_cleanup(run_dir, latest, pending)
    finally:
        _OPERATION_DEADLINE.reset(token)


def stream_worker(run_id: str) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    try:
        initial = read_metadata(run_dir)
    except Exception:
        initial = {"run_id": run_id}
    recorded_deadline = initial.get("transaction_deadline_monotonic")
    if (
        not isinstance(recorded_deadline, (int, float))
        or isinstance(recorded_deadline, bool)
        or not math.isfinite(float(recorded_deadline))
    ):
        return _worker_security_failure(
            run_dir,
            _runtime_not_trusted(
                "Inherited streaming transaction deadline evidence is missing or invalid."
            ),
        )
    deadline = float(recorded_deadline)
    token = _OPERATION_DEADLINE.set(deadline)
    try:
        try:
            return _stream_worker_inner(run_id)
        except _OwnedCleanupPending as pending:
            try:
                latest = read_metadata(run_dir)
            except Exception:
                latest = initial
            return _complete_isolated_worker_cleanup(
                run_dir, latest, pending
            )
        except Exception:
            metadata_read = True
            try:
                latest = read_metadata(run_dir)
            except Exception:
                latest = initial
                metadata_read = False
            timed_out = _has_timeout_evidence(latest) or (
                time.monotonic() >= deadline
            )
            cleanup_incomplete = (
                latest.get("status") == "cleanup_incomplete"
                or latest.get("cleanup_state") == "cleanup_incomplete"
            )
            child_pid_absent = metadata_read and latest.get("child_pid") is None
            post_run = not child_pid_absent
            if timed_out or cleanup_incomplete or post_run:
                terminal_status = (
                    "timed_out"
                    if timed_out
                    else "cleanup_incomplete"
                    if cleanup_incomplete
                    else "failed"
                )
                terminal_updates: dict[str, Any] = {
                    "status": terminal_status,
                    "finished_at": utc_now_iso(),
                    "exit_code": (
                        124
                        if timed_out
                        else None
                        if cleanup_incomplete
                        else 1
                    ),
                    "acceptance_status": "blocked_artifact_finalization",
                }
                if timed_out:
                    terminal_updates.update(
                        {"timed_out": True, "stop_reason": "timeout"}
                    )
                if cleanup_incomplete:
                    terminal_updates["cleanup_state"] = "cleanup_incomplete"
                if post_run and not timed_out and not cleanup_incomplete:
                    terminal_updates.update(
                        {
                            "finalization_state": "failed",
                            "finalization_error": {
                                "code": "artifact_finalization_failed",
                                "message": "Streaming execution artifacts could not be finalized safely.",
                            },
                        }
                    )
                return _persist_terminal_state(
                    run_dir,
                    latest,
                    updates=terminal_updates,
                    event={
                        "type": (
                            "cleanup_incomplete"
                            if cleanup_incomplete
                            else "process_exited"
                        ),
                        "status": terminal_status,
                        "exit_code": terminal_updates["exit_code"],
                    },
                    remove_pid=not cleanup_incomplete,
                    launch_deadline=deadline,
                )
            try:
                _unlink_managed_file(run_dir / "pid.txt")
            except Exception:
                pass
            return _record_blocked_launch(
                run_dir,
                latest,
                status="blocked_runtime_launch",
                error=_launch_failure_error(
                    "artifact_write_failed",
                    "Streaming execution artifacts could not be finalized safely.",
                ),
                child_pid=latest.get("child_pid"),
            )
    finally:
        _OPERATION_DEADLINE.reset(token)


def _process_identity_observation(
    metadata: Mapping[str, Any],
    *,
    pid_field: str,
    identity_field: str,
) -> dict[str, Any]:
    raw_pid = metadata.get(pid_field)
    if not isinstance(raw_pid, int) or isinstance(raw_pid, bool) or raw_pid <= 0:
        return {
            "pid": raw_pid,
            "alive": False,
            "owned": False,
            "state": "exited",
            "differing_fields": [],
            "expected": None,
        }
    raw_identity = metadata.get(identity_field)
    if not isinstance(raw_identity, Mapping):
        alive = pid_alive(raw_pid)
        return {
            "pid": raw_pid,
            "alive": alive,
            "owned": False,
            "state": "unverified" if alive else "exited",
            "differing_fields": [],
            "expected": None,
        }
    try:
        expected = ProcessIdentity.from_dict(raw_identity)
    except (TypeError, ValueError):
        alive = pid_alive(raw_pid)
        return {
            "pid": raw_pid,
            "alive": alive,
            "owned": False,
            "state": "unverified" if alive else "exited",
            "differing_fields": [],
            "expected": None,
        }
    launch = metadata.get("runtime_launch")
    launch_nonce = (
        str(launch.get("launch_nonce") or "")
        if isinstance(launch, Mapping)
        else ""
    )
    if expected.pid != raw_pid or not launch_nonce:
        differing = ["pid"] if expected.pid != raw_pid else ["launch_nonce"]
        return {
            "pid": raw_pid,
            "alive": True,
            "owned": False,
            "state": "mismatch" if expected.pid != raw_pid else "unverified",
            "differing_fields": differing,
            "expected": expected,
        }
    check = compare_process_identity(
        expected,
        expected_launch_nonce=launch_nonce,
    )
    return {
        "pid": raw_pid,
        "alive": check.state != "exited",
        "owned": check.state == "match",
        "state": check.state,
        "differing_fields": list(check.differing_fields),
        "expected": expected,
    }


def single_run_status(run_id: str, include_output_tail: bool = True, tail_chars: int = 4000) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
    status = str(metadata.get("status") or "unknown")
    child_pid = metadata.get("child_pid")
    worker_pid = metadata.get("worker_pid")
    owned_process_pid = metadata.get("owned_process_pid")
    child_identity = _process_identity_observation(
        metadata,
        pid_field="child_pid",
        identity_field="child_process_identity",
    )
    worker_identity = _process_identity_observation(
        metadata,
        pid_field="worker_pid",
        identity_field="worker_process_identity",
    )
    child_alive = bool(child_identity["alive"])
    worker_alive = bool(worker_identity["alive"])
    owned_process_alive = (
        pid_alive(int(owned_process_pid)) if owned_process_pid else False
    )
    cleanup_unconfirmed = (
        status in {"cleanup_pending", "cleanup_incomplete"}
        or metadata.get("cleanup_state") == "cleanup_incomplete"
    )
    active = (
        cleanup_unconfirmed
        or child_alive
        or worker_alive
        or owned_process_alive
    )
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
    input_tokens_est = max(0, int(metadata.get("prompt_tokens_est") or 0))
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
        "owned_process_pid": owned_process_pid,
        "worker_alive": worker_alive,
        "child_alive": child_alive,
        "owned_process_alive": owned_process_alive,
        "worker_identity_state": worker_identity["state"],
        "worker_identity_differing_fields": worker_identity[
            "differing_fields"
        ],
        "worker_owned": worker_identity["owned"],
        "child_identity_state": child_identity["state"],
        "child_identity_differing_fields": child_identity[
            "differing_fields"
        ],
        "child_owned": child_identity["owned"],
        "cleanup_state": metadata.get("cleanup_state"),
        "cleanup_owner": metadata.get("cleanup_owner"),
        "live_cleanup_threads": list(metadata.get("live_cleanup_threads") or []),
        "persistence_state": metadata.get("persistence_state"),
        "finalization_state": metadata.get("finalization_state"),
        "finalization_error": metadata.get("finalization_error"),
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "exit_code": metadata.get("exit_code"),
        "timed_out": bool(metadata.get("timed_out", False)),
        "acceptance_status": metadata.get("acceptance_status"),
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


def _stop_identity_failure(
    run_id: str,
    status: Mapping[str, Any],
    *,
    identity_state: str,
    differing_fields: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    mismatch = identity_state == "mismatch"
    code = "process_identity_mismatch" if mismatch else "process_identity_unverified"
    response_status = "identity_mismatch" if mismatch else "identity_unverified"
    error = _security_error(
        code,
        (
            "The recorded worker identity no longer matches the live process."
            if mismatch
            else "The worker identity could not be verified through a stable process capability."
        ),
        safe_details={
            "run_id": run_id,
            "differing_fields": list(differing_fields),
        },
        suggested_action=(
            "Do not retry termination by PID; inspect the run and clean up the owned process manually."
        ),
    )
    return {
        "ok": False,
        "run_id": run_id,
        "previous_status": status.get("status"),
        "status": response_status,
        "active": bool(status.get("active")),
        "stopped": False,
        "identity_state": identity_state,
        "differing_fields": list(differing_fields),
        "security_error": error.to_dict(),
        "next_step": error.suggested_action,
        "stop_results": [],
    }


def _valid_stop_request(run_dir: Path, metadata: Mapping[str, Any]) -> bool:
    try:
        payload = _read_bounded_regular_file(
            run_dir / "stop-requested.json",
            MAX_MANAGED_ARTIFACT_BYTES,
        )
        request = json.loads(payload.decode("utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    launch = metadata.get("runtime_launch")
    if not isinstance(request, Mapping) or not isinstance(launch, Mapping):
        return False
    return (
        request.get("run_id") == metadata.get("run_id")
        and request.get("launch_nonce") == launch.get("launch_nonce")
        and isinstance(request.get("request_id"), str)
        and bool(request.get("request_id"))
        and isinstance(request.get("requested_at"), str)
        and isinstance(request.get("force"), bool)
    )


def stop_run(run_id: str, force: bool = False, timeout_seconds: int = 5) -> dict[str, Any]:
    run_dir = safe_run_dir(run_id)
    metadata = read_metadata(run_dir)
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
    observation = _process_identity_observation(
        metadata,
        pid_field="worker_pid",
        identity_field="worker_process_identity",
    )
    expected_identity = observation.get("expected")
    if observation["state"] != "match" or not isinstance(
        expected_identity, ProcessIdentity
    ):
        return _stop_identity_failure(
            run_id,
            status,
            identity_state=str(observation["state"]),
            differing_fields=observation["differing_fields"],
        )
    launch = metadata.get("runtime_launch")
    launch_nonce = (
        str(launch.get("launch_nonce") or "")
        if isinstance(launch, Mapping)
        else ""
    )
    if not launch_nonce:
        return _stop_identity_failure(
            run_id,
            status,
            identity_state="unverified",
        )
    requested_at = utc_now_iso()
    request = {
        "request_id": uuid.uuid4().hex,
        "run_id": run_id,
        "launch_nonce": launch_nonce,
        "requested_at": requested_at,
        "force": force,
    }
    results: list[dict[str, Any]] = []
    _atomic_write_text(
        run_dir / "stop-requested.json",
        json.dumps(request, ensure_ascii=False, indent=2),
    )
    update_metadata(
        run_dir,
        status="stop_requested",
        stop_requested_at=requested_at,
        stop_reason="user_requested",
        stop_request_id=request["request_id"],
    )
    append_event(run_dir, {"type": "stop_requested", "force": force})
    deadline = time.monotonic() + max(0, int(timeout_seconds))
    refreshed = single_run_status(run_id, include_output_tail=False)
    while refreshed.get("active") and time.monotonic() < deadline:
        time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
        refreshed = single_run_status(run_id, include_output_tail=False)
    if refreshed.get("active"):
        if sys.platform != "win32":
            update_metadata(
                run_dir,
                cleanup_state="cleanup_incomplete",
                stop_cleanup_state="cleanup_incomplete",
            )
            failure = _stop_identity_failure(
                run_id,
                refreshed,
                identity_state="unverified",
                differing_fields=["process_tree_containment"],
            )
            failure["cleanup_state"] = "cleanup_incomplete"
            return failure
        with open_stable_process_capability(expected_identity) as capability:
            if capability.state != "match":
                after_capability = single_run_status(
                    run_id, include_output_tail=False
                )
                if capability.state == "exited" and not after_capability.get(
                    "active"
                ):
                    refreshed = after_capability
                else:
                    update_metadata(
                        run_dir,
                        cleanup_state="cleanup_incomplete",
                        stop_cleanup_state="cleanup_incomplete",
                    )
                    failure = _stop_identity_failure(
                        run_id,
                        after_capability,
                        identity_state=capability.state,
                        differing_fields=capability.differing_fields,
                    )
                    failure["cleanup_state"] = "cleanup_incomplete"
                    return failure
            else:
                results.append(
                    capability.terminate(
                        force=force,
                        wait_seconds=max(0, int(timeout_seconds)),
                    )
                )
    final = single_run_status(run_id, include_output_tail=False)
    stopped = not final.get("active")
    stopped_at = utc_now_iso()
    if stopped:
        update_metadata(run_dir, status="stopped", stopped_at=stopped_at, finished_at=stopped_at, exit_code=final.get("exit_code") if final.get("exit_code") is not None else -15, stop_reason="user_requested")
        append_event(run_dir, {"type": "stopped", "status": "stopped"})
        final = single_run_status(run_id, include_output_tail=False)
    else:
        update_metadata(
            run_dir,
            cleanup_state="cleanup_incomplete",
            stop_cleanup_state="cleanup_incomplete",
        )
    return {
        "ok": stopped,
        "run_id": run_id,
        "previous_status": status.get("status"),
        "status": final.get("status") if stopped else "cleanup_incomplete",
        "active": final.get("active"),
        "force": force,
        "stopped": stopped,
        "cleanup_state": (
            "cleanup_confirmed" if stopped else "cleanup_incomplete"
        ),
        "stop_results": results,
    }


def read_team_manifest(team_id: str) -> dict[str, Any]:
    if not TEAM_ID_RE.match(team_id):
        raise OrchestratorError(f"Invalid team id: {team_id}")
    path = TEAMS_DIR / f"{team_id}.json"
    try:
        payload = _read_bounded_regular_file(
            path, MAX_MANAGED_ARTIFACT_BYTES
        )
    except FileNotFoundError as exc:
        raise OrchestratorError(f"Team manifest not found: {team_id}") from exc
    return json.loads(payload.decode("utf-8"))


def _validate_team_authorization_manifest(
    team_id: str, data: Mapping[str, Any]
) -> None:
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise OrchestratorError("Team authorization has no members.")
    for item in runs:
        if not isinstance(item, Mapping):
            raise OrchestratorError("Team authorization member is invalid.")
        run_id = item.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
            raise OrchestratorError("Team authorization run id is invalid.")
        member = read_metadata(safe_run_dir(run_id))
        launch = member.get("worker_launch")
        nonce = str(
            (member.get("runtime_launch") or {}).get("launch_nonce") or ""
        )
        try:
            recorded = _validate_team_worker_identity(
                member, expected_nonce=nonce
            )
        except RuntimeSecurityError as exc:
            raise OrchestratorError(
                f"Team member {run_id} worker identity is no longer valid."
            ) from exc
        with _ACTIVE_WORKER_HANDLES_LOCK:
            owned = _ACTIVE_WORKER_HANDLES.get(run_id)
        if (
            member.get("team_id") != team_id
            or str(member.get("status") or "") not in {"starting", "running"}
            or member.get("stop_requested_at")
            or member.get("terminal_state_count")
            or not isinstance(launch, Mapping)
            or launch.get("team_ready") is not True
            or launch.get("nonce_consumed") is not True
            or launch.get("team_preflight_complete") is not True
            or not launch.get("scope_policy_identity")
            or not isinstance(member.get("git_before"), Mapping)
            or not member["git_before"].get("evidence_complete")
            or owned is None
            or owned.pid != recorded.pid
            or owned.poll() is not None
            or item.get("worker_pid") != recorded.pid
            or item.get("worker_creation_token") != recorded.creation_token
        ):
            raise OrchestratorError(
                f"Team member {run_id} is not ready for authorization."
            )
    # A sequential first pass is not a snapshot: a member validated early may
    # die while a later member is being checked. Recheck every owned handle at
    # the publication boundary so no dead precommit set can become visible.
    for item in runs:
        run_id = str(item["run_id"])
        with _ACTIVE_WORKER_HANDLES_LOCK:
            owned = _ACTIVE_WORKER_HANDLES.get(run_id)
        if owned is None or owned.poll() is not None:
            raise OrchestratorError(
                f"Team member {run_id} died during authorization validation."
            )


def write_team_manifest(team_id: str, data: dict[str, Any]) -> Path:
    _set_private_directory(TEAMS_DIR)
    path = TEAMS_DIR / f"{team_id}.json"
    precommit = None
    if data.get("status") == "authorized":
        precommit = lambda: _validate_team_authorization_manifest(
            team_id, data
        )
    return write_json_file(path, data, precommit=precommit)


@_guard_public_launch_transaction(timeout_position=5)
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
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    """Append instruction by stopping the run and restarting with recovered context."""
    if not instruction.strip():
        raise OrchestratorError("Instruction cannot be empty.")
    previous = poll_run(run_id, max_bytes=50000, include_output_tail=True)
    status = previous["status"]
    metadata = read_metadata(safe_run_dir(run_id))
    run_dir = safe_run_dir(run_id)
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
    launch_kwargs = {
        "task": task,
        "role": role or str(metadata.get("role") or "implementation"),
        "task_type": task_type or metadata.get("task_type"),
        "profile": selected_profile,
        "model_override": selected_model,
        "allow_write": bool(metadata.get("allow_write", False)),
        "timeout_seconds": timeout_seconds or metadata.get("timeout_seconds"),
        "cwd": Path(str(metadata.get("cwd") or Path.cwd())),
        "context": context,
        "max_output_bytes": (metadata.get("output_budget") or {}).get("max_output_bytes"),
        "max_events_bytes": (metadata.get("output_budget") or {}).get("max_events_bytes"),
        "soft_output_bytes": (metadata.get("output_budget") or {}).get("soft_output_bytes"),
        "output_budget_policy": (metadata.get("output_budget") or {}).get("policy"),
        "final_only": bool((metadata.get("output_budget") or {}).get("final_only", False)),
        "final_max_chars": (metadata.get("output_budget") or {}).get("final_max_chars"),
    }
    prepared = _prepare_streaming_agent(
        **launch_kwargs,
        allow_unsafe_runtime=allow_unsafe_runtime,
    )
    if status.get("active"):
        stop = stop_run(run_id, force=force, timeout_seconds=5)
        if not _stop_response_confirmed(stop):
            return {
                "ok": False,
                "status": "replacement_stop_failed",
                "old_run_id": run_id,
                "stop": stop,
                "error": "The old worker could not be stopped with verified cleanup; the replacement was not started.",
            }
    else:
        stop = {"ok": True, "status": "already_finished"}
    new_run = run_streaming_agent(
        **launch_kwargs,
        allow_unsafe_runtime=allow_unsafe_runtime,
        _prepared_launch=prepared,
    )
    if not _launch_response_succeeded(new_run):
        return {
            "ok": False,
            "status": "replacement_launch_failed",
            "old_run_id": run_id,
            "stop": stop,
            "new_run": new_run,
            "error": "The old worker stopped, but the replacement launch was not accepted.",
            **_security_response_fields(new_run),
        }
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


def _wait_for_team_members_ready(
    team_id: str,
    runs: list[dict[str, Any]],
    *,
    deadline: float,
) -> list[dict[str, Any]]:
    while True:
        ready: list[dict[str, Any]] = []
        pending = False
        for item in runs:
            run_id = str(item["run_id"])
            member = read_metadata(
                safe_run_dir(run_id), deadline=deadline
            )
            if (
                member.get("team_id") != team_id
                or str(member.get("status") or "") not in {"starting", "running"}
                or member.get("stop_requested_at")
                or member.get("terminal_state_count")
            ):
                raise OrchestratorError(
                    f"Team member {run_id} is not launchable at readiness."
                )
            try:
                recorded = ProcessIdentity.from_dict(
                    member.get("worker_process_identity")
                )
            except (TypeError, ValueError) as exc:
                raise OrchestratorError(
                    f"Team member {run_id} has invalid worker identity evidence."
                ) from exc
            with _ACTIVE_WORKER_HANDLES_LOCK:
                owned = _ACTIVE_WORKER_HANDLES.get(run_id)
            comparison = compare_process_identity(
                recorded,
                expected_launch_nonce=str(
                    (member.get("runtime_launch") or {}).get("launch_nonce")
                    or ""
                ),
            )
            if (
                owned is None
                or owned.pid != recorded.pid
                or owned.poll() is not None
                or comparison.state != "match"
            ):
                raise OrchestratorError(
                    f"Team member {run_id} worker ownership changed before readiness."
                )
            launch = member.get("worker_launch")
            if (
                not isinstance(launch, Mapping)
                or launch.get("team_ready") is not True
                or launch.get("nonce_consumed") is not True
                or launch.get("team_preflight_complete") is not True
                or not launch.get("scope_policy_identity")
                or not isinstance(member.get("git_before"), Mapping)
                or not member["git_before"].get("evidence_complete")
            ):
                pending = True
                continue
            ready.append(
                {
                    **item,
                    "worker_pid": recorded.pid,
                    "worker_creation_token": recorded.creation_token,
                    "ready_at": launch.get("team_ready_at"),
                    "ready_sha256": launch.get("team_ready_sha256"),
                }
            )
        if not pending and len(ready) == len(runs):
            return ready
        if time.monotonic() >= deadline:
            raise OrchestratorError(
                "Team members did not reach the shared readiness barrier in time."
            )
        time.sleep(min(0.01, _remaining_deadline(deadline, 0.01)))


@_guard_public_launch_transaction(timeout_position=4)
def spawn_role_team(
    task: str,
    roles: list[str] | None = None,
    cwd: Path | None = None,
    context: str | None = None,
    timeout_seconds: int | None = None,
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    selected_roles = roles or ["requirements", "architecture", "security", "testing"]
    if not selected_roles:
        raise OrchestratorError("At least one role is required.")
    team_deadline = _effective_deadline()
    if team_deadline is None:
        raise OrchestratorError("Team launch deadline is unavailable.")
    team_id = "team-" + new_run_id()
    runs: list[dict[str, Any]] = []
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
        reservation = _LaunchAdmissionReservation(
            team_id=team_id,
            owner_pid=os.getpid(),
            deadline=team_deadline,
        )
        manifest_path: Path | None = None
        authorization_attempted = False

        def rollback_registered_workers() -> dict[str, Any]:
            stops: list[dict[str, Any]] = []
            for item in runs:
                run_id = str(item["run_id"])
                with _ACTIVE_WORKER_HANDLES_LOCK:
                    worker = _ACTIVE_WORKER_HANDLES.get(run_id)
                if worker is None:
                    try:
                        member = read_metadata(safe_run_dir(run_id))
                        worker_pid = member.get("worker_pid")
                    except Exception:
                        worker_pid = None
                    already_stopped = (
                        isinstance(worker_pid, int)
                        and not pid_alive(worker_pid)
                    )
                    lock_reclaimed = (
                        _reclaim_artifact_lock_for_dead_process(
                            safe_run_dir(run_id),
                            worker_pid,
                            deadline=team_deadline,
                        )
                        if already_stopped
                        else False
                    )
                    stops.append(
                        {
                            "ok": already_stopped and lock_reclaimed,
                            "run_id": run_id,
                            "stopped": already_stopped,
                            "lock_reclaimed": lock_reclaimed,
                            **(
                                {}
                                if already_stopped
                                else {"error": "owned worker handle unavailable"}
                            ),
                        }
                    )
                    continue
                try:
                    _terminate_owned_process(worker, deadline=team_deadline)
                    stopped = worker.poll() is not None
                    lock_reclaimed = (
                        _reclaim_artifact_lock_for_dead_process(
                            safe_run_dir(run_id),
                            worker.pid,
                            deadline=team_deadline,
                        )
                        if stopped
                        else False
                    )
                    stops.append(
                        {
                            "ok": stopped and lock_reclaimed,
                            "run_id": run_id,
                            "stopped": stopped,
                            "lock_reclaimed": lock_reclaimed,
                        }
                    )
                except Exception as stop_exc:
                    stops.append(
                        {"ok": False, "run_id": run_id, "error": str(stop_exc)}
                    )
            failed = sum(1 for item in stops if not item.get("ok"))
            return {
                "attempted": True,
                "force": True,
                "stopped_count": len(stops) - failed,
                "failed_stop_count": failed,
                "stops": stops,
            }
        try:
            prepared_members: list[tuple[str, str, PreparedWorkerLaunch]] = []
            for role in selected_roles:
                member_context = "\n".join(
                    part for part in [f"Team id: {team_id}", context or ""] if part
                )
                prepared_members.append(
                    (
                        role,
                        member_context,
                        _prepare_streaming_agent(
                            task=task,
                            role=role,
                            cwd=cwd,
                            context=member_context,
                            timeout_seconds=timeout_seconds,
                            skip_cost_guard=True,
                            allow_unsafe_runtime=allow_unsafe_runtime,
                            _admission_reservation=reservation,
                        ),
                    )
                )
            for role, member_context, prepared in prepared_members:
                run = run_streaming_agent(
                    task=task,
                    role=role,
                    cwd=cwd,
                    context=member_context,
                    timeout_seconds=timeout_seconds,
                    skip_cost_guard=True,
                    allow_unsafe_runtime=allow_unsafe_runtime,
                    _admission_reservation=reservation,
                    _prepared_launch=prepared,
                )
                run_id = str(run["run_id"])
                runs.append(
                    {
                        "role": role,
                        "run_id": run_id,
                        "status": run["status"],
                        "profile": run.get("profile"),
                    }
                )
                if (
                    run.get("status") != "starting"
                    or run_id not in (reservation.registered_run_ids or [])
                ):
                    raise OrchestratorError(
                        f"Team child registration failed for role {role}."
                    )
            manifest = {
                "team_id": team_id,
                "created_at": utc_now_iso(),
                "status": "prepared",
                "cwd": str(cwd or Path.cwd()),
                "roles": selected_roles,
                "runs": runs,
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": len(selected_roles),
                "rollback": None,
            }
            manifest_path = write_team_manifest(team_id, manifest)
            registered = set(reservation.registered_run_ids or [])
            if registered != {str(item["run_id"]) for item in runs}:
                raise OrchestratorError(
                    "Team authorization registration set is incomplete."
                )
            authorized_runs = _wait_for_team_members_ready(
                team_id, runs, deadline=team_deadline
            )
            response = {
                "ok": True,
                "status": "launched",
                "team_id": team_id,
                "manifest_path": str(manifest_path),
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": len(selected_roles),
                "launched_count": len(runs),
                "runs": runs,
                "rollback": None,
            }
            authorized_manifest = {
                **manifest,
                "status": "authorized",
                "authorized_at": utc_now_iso(),
                "authorization_token": uuid.uuid4().hex,
                "runs": authorized_runs,
            }
            # All controller-side state is finalized before this one-way
            # publication. The precommit callback performs the last liveness
            # and identity check inside the atomic replacement boundary.
            reservation.active = False
            authorization_attempted = True
            write_team_manifest(team_id, authorized_manifest)
            return response
        except Exception as exc:
            rollback = rollback_registered_workers()
            security_fields = _security_response_fields(exc)
            decision_visible = False
            decision_payload: dict[str, Any] = {}
            candidate_manifest = manifest_path or (TEAMS_DIR / f"{team_id}.json")
            try:
                decision_payload = json.loads(
                    _read_bounded_regular_file(
                        candidate_manifest, MAX_MANAGED_ARTIFACT_BYTES
                    ).decode("utf-8")
                )
                decision_visible = str(
                    decision_payload.get("decision")
                    or decision_payload.get("status")
                    or ""
                ).upper() in {"COMMIT", "COMMITTED", "AUTHORIZED"}
            except Exception:
                decision_visible = False
            if decision_visible:
                status_name = "commit_indeterminate"
            elif authorization_attempted:
                status_name = "aborted"
            else:
                status_name = (
                    "rollback_incomplete"
                    if rollback["failed_stop_count"]
                    else "rolled_back_partial_launch"
                )
            manifest = {
                "team_id": team_id,
                "created_at": utc_now_iso(),
                "status": status_name,
                "error": str(exc),
                "cwd": str(cwd or Path.cwd()),
                "roles": selected_roles,
                "runs": runs,
                "active_before": active_before,
                "max_concurrent": max_concurrent,
                "requested_count": len(selected_roles),
                "rollback": rollback,
                **security_fields,
            }
            if decision_visible:
                path = candidate_manifest
            else:
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
                **security_fields,
            }
        finally:
            reservation.active = False
    raise OrchestratorError("Team admission ended without a result.")


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


@_guard_public_launch_transaction(timeout_position=3)
def cross_review(
    run_ids: list[str],
    reviewer_roles: list[str] | None = None,
    cwd: Path | None = None,
    timeout_seconds: int | None = None,
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    ids = resolve_team_run_ids(run_ids=run_ids)
    roles = reviewer_roles or ["security", "testing", "review"]
    bundle_lines = ["Review these previous worker outputs. Focus on contradictions, missed risks, and acceptance blockers.", ""]
    for run_id in ids:
        status = single_run_status(run_id, include_output_tail=True, tail_chars=6000)
        bundle_lines.extend([f"## Run {run_id} / role {status.get('role')} / status {status.get('status')}", str(status.get("stdout_tail", ""))[-6000:], ""])
    task = "Cross-review prior Claude Code worker outputs and produce second-round findings ordered by severity."
    spawned: list[dict[str, Any]] = []
    review_context = "\n".join(bundle_lines)
    prepared = [
        (
            role,
            _prepare_streaming_agent(
                task=task,
                role=role,
                cwd=cwd,
                context=review_context,
                timeout_seconds=timeout_seconds,
                allow_unsafe_runtime=allow_unsafe_runtime,
            ),
        )
        for role in roles
    ]

    def rollback_started_reviewers() -> dict[str, Any]:
        stops: list[dict[str, Any]] = []
        for item in spawned:
            run_id = item.get("run_id")
            if not isinstance(run_id, str) or not run_id:
                continue
            try:
                stop = stop_run(run_id, force=True)
            except Exception as exc:
                stop = {
                    "ok": False,
                    "status": "cleanup_incomplete",
                    "active": True,
                    "stopped": False,
                    "error": str(exc),
                }
            stops.append(
                {
                    "run_id": run_id,
                    "confirmed": _stop_response_confirmed(stop),
                    **{
                        key: stop.get(key)
                        for key in (
                            "ok",
                            "status",
                            "active",
                            "stopped",
                            "cleanup_state",
                        )
                    },
                }
            )
        failed = sum(1 for item in stops if not item["confirmed"])
        return {
            "attempted": bool(stops),
            "stopped_count": len(stops) - failed,
            "failed_stop_count": failed,
            "stops": stops,
        }

    for role, prepared_launch in prepared:
        run = run_streaming_agent(
            task=task,
            role=role,
            cwd=cwd,
            context=review_context,
            timeout_seconds=timeout_seconds,
            allow_unsafe_runtime=allow_unsafe_runtime,
            _prepared_launch=prepared_launch,
        )
        review_run = {
            "reviewer_role": role,
            "run_id": run.get("run_id"),
            "status": run.get("status"),
            "profile": run.get("profile"),
            **_security_response_fields(run),
        }
        if run.get("error"):
            review_run["error"] = run.get("error")
        if not _launch_response_succeeded(run):
            rollback = rollback_started_reviewers()
            status_name = (
                "rollback_incomplete"
                if rollback["failed_stop_count"]
                else "rolled_back_partial_launch"
                if rollback["attempted"]
                else "blocked_runtime_launch"
            )
            return {
                "ok": False,
                "status": status_name,
                "source_run_ids": ids,
                "review_runs": [*spawned, review_run],
                "failed_role": role,
                "error": "A prepared cross-review worker launch was not accepted.",
                "failed_launch": run,
                "rollback": rollback,
                **_security_response_fields(run),
            }
        spawned.append(review_run)
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


def _validate_write_scope_policy(
    root: Path, path: Path, scope: Any
) -> dict[str, Any]:
    if not isinstance(scope, Mapping):
        raise OrchestratorError("Write-scope policy must be a JSON object.")
    normalized = dict(scope)
    for key in ("allowed_paths", "denied_paths"):
        values = normalized.get(key, [])
        if not isinstance(values, list) or not all(
            isinstance(item, str) and item for item in values
        ):
            raise OrchestratorError(
                f"Write-scope policy field {key} must be a string list."
            )
        canonical_values: list[str] = []
        for item in values:
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = root / candidate
            canonical = candidate.resolve()
            if safe_relative(root, canonical) is None:
                raise OrchestratorError(
                    f"Write-scope policy field {key} contains an outside path."
                )
            canonical_values.append(str(canonical))
        normalized[key] = canonical_values
    max_diff_lines = normalized.get("max_diff_lines", 0)
    if (
        not isinstance(max_diff_lines, int)
        or isinstance(max_diff_lines, bool)
        or max_diff_lines < 0
    ):
        raise OrchestratorError(
            "Write-scope policy max_diff_lines must be a non-negative integer."
        )
    cwd_value = normalized.get("cwd")
    if cwd_value is not None and not isinstance(cwd_value, str):
        raise OrchestratorError("Write-scope policy cwd must be a string.")
    if cwd_value is not None:
        declared_root = Path(cwd_value)
        if not declared_root.is_absolute():
            declared_root = root / declared_root
        if declared_root.resolve() != root:
            raise OrchestratorError(
                "Write-scope policy cwd does not match the configured workspace root."
            )
    normalized["cwd"] = str(root)
    return normalized


def _pin_write_scope_policy(root: Path) -> dict[str, Any]:
    root = root.resolve()
    path = root / ".claude-code-orchestrator" / "write-scope.json"
    try:
        payload = _read_bounded_regular_file(path, 1024 * 1024)
    except FileNotFoundError:
        return {
            "path": str(path),
            "exists": False,
            "sha256": None,
            "scope": None,
        }
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("Write-scope policy is malformed.") from exc
    scope = _validate_write_scope_policy(root, path, parsed)
    return {
        "path": str(path),
        "exists": True,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "scope": scope,
    }


def _write_scope_policy_drift(pinned: Mapping[str, Any]) -> str | None:
    path = Path(str(pinned["path"]))
    try:
        payload = _read_bounded_regular_file(path, 1024 * 1024)
    except FileNotFoundError:
        return "deleted" if pinned.get("exists") else None
    except TimeoutError:
        raise
    except OSError:
        return "unreadable"
    if not pinned.get("exists"):
        return "created"
    try:
        json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "malformed"
    if hashlib.sha256(payload).hexdigest() != pinned.get("sha256"):
        return "changed"
    return None


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


def _check_write_scope_with_evidence(
    run_id: str | None,
    root: Path,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    pinned_scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _check_deadline(
        message="Write-scope evidence exceeded the launch deadline."
    )
    root = root.resolve()
    if pinned_scope is None:
        scope_path, scope = load_write_scope(root)
        if scope is not None:
            scope = _validate_write_scope_policy(root, scope_path, scope)
        policy_drift = None
    else:
        scope_path = Path(str(pinned_scope["path"]))
        scope_value = pinned_scope.get("scope")
        scope = dict(scope_value) if isinstance(scope_value, Mapping) else None
        policy_drift = _write_scope_policy_drift(pinned_scope)

    before_is_git = bool(before.get("is_git_repo"))
    after_is_git = bool(after.get("is_git_repo"))
    before_identity = before.get(
        "_raw_repository_identity", before.get("repository_identity")
    )
    after_identity = after.get(
        "_raw_repository_identity", after.get("repository_identity")
    )
    transition_paths: set[str] = set()
    transition_lines: set[tuple[str, str, str, int]] = set()
    transition_errors: list[str] = []
    if before_is_git and after_is_git:
        transition_paths, transition_lines, transition_errors = (
            _git_transition_evidence(root, before, after)
        )
    evidence_errors = list(transition_errors)
    for snapshot in (before, after):
        snapshot_errors = snapshot.get(
            "_raw_evidence_errors", snapshot.get("evidence_errors", [])
        )
        if isinstance(snapshot_errors, (list, tuple, set)):
            evidence_errors.extend(str(item) for item in snapshot_errors)
    has_snapshot_evidence = bool(before) or bool(after)
    evidence_incomplete = (
        before_is_git != after_is_git
        or (
            has_snapshot_evidence
            and any(
                snapshot.get("ok") is not True
                or snapshot.get("evidence_complete") is not True
                or snapshot.get(
                    "_raw_evidence_complete",
                    snapshot.get("evidence_complete"),
                )
                is not True
                for snapshot in (before, after)
            )
        )
        or bool(transition_errors)
    )
    if before_is_git and (
        not after_is_git
        or not after.get("ok")
        or not before_identity
        or not after_identity
        or before_identity != after_identity
    ):
        evidence_incomplete = True
    evidence_violations: list[dict[str, Any]] = []
    if evidence_incomplete:
        evidence_violations.append(
            {
                "type": "git_evidence_incomplete",
                "errors": sorted(set(evidence_errors)),
                "message": "Complete Git evidence was unavailable; acceptance is blocked.",
            }
        )
    if not scope:
        if policy_drift or evidence_violations:
            violations = list(evidence_violations)
            if policy_drift:
                violations.append(
                    {
                        "type": "scope_policy_drift",
                        "reason": policy_drift,
                        "message": "The pinned write-scope policy changed during launch.",
                    }
                )
            return {
                "ok": False,
                "status": "blocked",
                "run_id": run_id,
                "cwd": str(root),
                "scope_path": str(scope_path),
                "checked_paths": [],
                "changed_paths": [],
                "violation_count": len(violations),
                "violations": violations,
                "diff_lines": len(transition_lines),
                "diff_source": "git_transition_evidence",
                "max_diff_lines": 0,
                "rollback_recommendation": "Review diff and restore the pinned write-scope policy.",
            }
        return {
            "ok": True,
            "status": "no_scope",
            "run_id": run_id,
            "cwd": str(root),
            "scope_path": str(scope_path),
            "message": "No write-scope file found; Codex must review diff manually.",
            "violations": [],
        }

    if run_id and before and after:
        changed_paths = changed_paths_between_snapshots(dict(before), dict(after))
    elif (root / ".git").exists():
        changed_paths = current_git_changed_paths(root)
    else:
        changed_paths = []
    changed_paths = sorted(set(changed_paths) | transition_paths)

    allowed = [Path(item).resolve() for item in scope.get("allowed_paths", []) or []]
    denied = [Path(item).resolve() for item in scope.get("denied_paths", []) or []]
    violations: list[dict[str, Any]] = list(evidence_violations)
    if policy_drift:
        violations.append(
            {
                "type": "scope_policy_drift",
                "reason": policy_drift,
                "message": "The pinned write-scope policy changed during launch.",
            }
        )
    checked: list[str] = []
    for rel in changed_paths:
        normalized = _canonical_git_path(rel).strip("/")
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
    raw_diff = after.get("_raw_diff_text")
    if before_is_git and after_is_git:
        diff_lines = len(transition_lines)
        diff_source = "git_transition_evidence"
    elif isinstance(raw_diff, str):
        diff_lines = count_diff_changed_lines(raw_diff)
        diff_source = "run_after_memory_snapshot"
    elif after.get("diff_path") and Path(str(after["diff_path"])).exists():
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


def _terminal_write_scope_evidence(
    run_id: str,
    root: Path,
    git_before: Mapping[str, Any],
    git_after: Mapping[str, Any],
    pinned_scope: Mapping[str, Any],
    *,
    timed_out: bool,
) -> tuple[dict[str, Any], bool, bool]:
    def unavailable(violation_type: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "status": "blocked",
            "run_id": run_id,
            "cwd": str(root),
            "scope_path": str(pinned_scope.get("path") or ""),
            "checked_paths": [],
            "changed_paths": [],
            "violation_count": 1,
            "violations": [{"type": violation_type, "message": message}],
            "diff_lines": 0,
            "diff_source": "git_transition_evidence",
            "max_diff_lines": 0,
            "rollback_recommendation": (
                "Review the run artifacts before accepting changes."
            ),
        }

    deadline_expired = _transaction_deadline_expired(
        fallback=_effective_deadline()
    )
    if timed_out or deadline_expired:
        return (
            unavailable(
                "write_scope_not_evaluated_due_to_timeout",
                "Write-scope evidence was not evaluated after the launch deadline.",
            ),
            False,
            deadline_expired and not timed_out,
        )
    try:
        _check_deadline(
            message="Write-scope evidence exceeded the launch deadline."
        )
        return (
            _check_write_scope_with_evidence(
                run_id, root, git_before, git_after, pinned_scope
            ),
            False,
            False,
        )
    except TimeoutError:
        return (
            unavailable(
                "write_scope_not_evaluated_due_to_timeout",
                "Write-scope evidence exceeded the launch deadline.",
            ),
            False,
            True,
        )
    except Exception:
        return (
            unavailable(
                "write_scope_check_failed",
                "Write-scope evidence could not be evaluated safely.",
            ),
            True,
            False,
        )


def check_write_scope(
    run_id: str | None = None, cwd: Path | None = None
) -> dict[str, Any]:
    before: Mapping[str, Any] = {}
    after: Mapping[str, Any] = {}
    if run_id:
        run_dir = safe_run_dir(run_id)
        metadata = read_metadata(run_dir)
        root = Path(str(metadata.get("cwd") or cwd or Path.cwd())).resolve()
        authoritative = metadata.get("write_scope_check")
        if isinstance(authoritative, Mapping) and "ok" in authoritative:
            return sanitize_for_json(dict(authoritative))
        return {
            "ok": False,
            "status": "pending_authoritative_scope",
            "run_id": run_id,
            "cwd": str(root),
            "scope_path": str(
                root / ".claude-code-orchestrator" / "write-scope.json"
            ),
            "checked_paths": [],
            "changed_paths": [],
            "violation_count": 1,
            "violations": [
                {
                    "type": "authoritative_scope_pending",
                    "message": "Authoritative raw write-scope evidence is not available yet.",
                }
            ],
            "diff_lines": 0,
            "diff_source": "unavailable",
            "max_diff_lines": 0,
            "rollback_recommendation": None,
        }
    else:
        root = (cwd or Path.cwd()).resolve()
    return _check_write_scope_with_evidence(run_id, root, before, after)


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
    has_secret_value = bool(
        _contains_secret_value(line) or SECRET_ASSIGN_RE.search(line)
    )
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
    allow_unsafe_runtime: bool = False,
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
            "task_length": len(task),
        }
    started = time.time()
    run = run_agent(
        task=task,
        role=role,
        profile=profile,
        timeout_seconds=timeout_seconds,
        output_format="json",
        allow_unsafe_runtime=allow_unsafe_runtime,
    )
    launch_accepted = bool(
        isinstance(run, Mapping)
        and run.get("run_id")
        and str(run.get("status") or "")
        not in {
            "blocked_runtime_launch",
            "blocked_runtime_identity",
            "blocked_process_identity",
            "cleanup_pending",
            "cleanup_incomplete",
            "timed_out",
        }
        and run.get("ok") is not False
    )
    result = {
        "ok": launch_accepted and run.get("exit_code") == 0,
        "dry_run": False,
        "profile": provider.name,
        "model": route.get("model_override") or provider.model,
        "duration_ms": int((time.time() - started) * 1000),
        "run_id": run.get("run_id"),
        "exit_code": run.get("exit_code"),
        "stdout_tail": run.get("stdout_tail", "")[-2000:],
        **(
            {}
            if launch_accepted
            else {
                "status": run.get("status") or "benchmark_launch_failed",
                "error": run.get("error")
                or "The benchmark runtime launch was not accepted.",
                **_security_response_fields(run),
            }
        ),
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
    input_tokens = max(0, int(metadata.get("prompt_tokens_est") or 0))
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


def benchmark_suite(
    profile: str | None = None,
    execute: bool = False,
    timeout_seconds: int = 120,
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for task in BENCHMARK_SUITE_TASKS:
        result = benchmark_model(
            profile=profile,
            role=task["role"],
            task=task["task"],
            timeout_seconds=timeout_seconds,
            execute=execute,
            allow_unsafe_runtime=allow_unsafe_runtime,
        )
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


_QUEUE_THREAD_LOCK = threading.RLock()
QUEUE_LOCK_TIMEOUT_SECONDS = 30.0


@contextlib.contextmanager
def queue_lock() -> Any:
    """Serialize queue claims across threads and controller processes."""
    lock_path = QUEUE_PATH.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _QUEUE_THREAD_LOCK:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "r+b") as handle:
            handle.seek(0)
            deadline = _effective_deadline() or (
                time.monotonic() + QUEUE_LOCK_TIMEOUT_SECONDS
            )
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            raise OrchestratorError(
                                "Queue lock acquisition timed out."
                            ) from exc
                        time.sleep(0.05)
            else:
                import fcntl

                while True:
                    try:
                        fcntl.flock(
                            handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                        break
                    except BlockingIOError as exc:
                        if time.monotonic() >= deadline:
                            raise OrchestratorError(
                                "Queue lock acquisition timed out."
                            ) from exc
                        time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def get_secure_payload_store() -> SecurePayloadStore:
    return create_secure_payload_store()


def _public_queue_job(job: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in job.items()
        if key not in {"task", "context", "launch_claim"}
    }


def _launch_response_succeeded(run: Mapping[str, Any] | None) -> bool:
    return bool(
        isinstance(run, Mapping)
        and run.get("run_id")
        and str(run.get("status") or "") in {"starting", "running"}
        and run.get("ok") is not False
    )


def _security_response_fields(value: Any) -> dict[str, Any]:
    if isinstance(value, RuntimeSecurityError):
        return {
            "security_error": value.to_dict(),
            "next_step": value.suggested_action,
        }
    if not isinstance(value, Mapping):
        return {}
    security_error = value.get("security_error")
    if not isinstance(security_error, Mapping):
        return {}
    result = {"security_error": dict(security_error)}
    next_step = value.get("next_step") or security_error.get("suggested_action")
    if isinstance(next_step, str) and next_step:
        result["next_step"] = next_step
    return result


def _stop_response_confirmed(stop: Mapping[str, Any]) -> bool:
    status = str(stop.get("status") or "")
    return bool(
        stop.get("ok") is True
        and stop.get("active") is not True
        and (
            stop.get("stopped") is True
            or status in {"stopped", "already_stopped", "already_finished"}
        )
        and status
        not in {
            "cleanup_pending",
            "cleanup_incomplete",
            "identity_mismatch",
            "identity_unverified",
        }
    )


def _runtime_identity_digest(prepared: PreparedWorkerLaunch) -> str:
    public = prepared.launch_spec.executable_identity.to_public_dict()
    payload = json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _grant_integrity(grant: Mapping[str, Any], authenticator: bytes) -> str:
    covered = {
        key: grant.get(key)
        for key in (
            "grant_id",
            "job_id",
            "executable_identity_digest",
            "policy_decision_id",
            "expires_at",
            "max_uses",
            "uses_remaining",
            "consumed_at",
            "grant_reference",
        )
    }
    payload = json.dumps(covered, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(
        authenticator,
        b"cc-orchestrator-unsafe-runtime-grant-v1\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def _new_unsafe_runtime_grant(
    *,
    job_id: str,
    prepared: PreparedWorkerLaunch,
    timeout_seconds: int,
    grant_reference: str,
    authenticator: bytes,
) -> dict[str, Any]:
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=max(60, min(int(timeout_seconds), 900))
    )
    grant: dict[str, Any] = {
        "grant_id": uuid.uuid4().hex,
        "job_id": job_id,
        "executable_identity_digest": _runtime_identity_digest(prepared),
        "policy_decision_id": prepared.launch_spec.policy_decision_id,
        "expires_at": expires_at.isoformat(),
        "max_uses": 1,
        "uses_remaining": 1,
        "consumed_at": None,
        "grant_reference": grant_reference,
    }
    grant["integrity_hmac_sha256"] = _grant_integrity(grant, authenticator)
    return grant


def _grant_is_expired(grant: Mapping[str, Any]) -> bool:
    try:
        expires = datetime.fromisoformat(str(grant["expires_at"]))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return True
    return datetime.now(timezone.utc) >= expires.astimezone(timezone.utc)


def _grant_validation_error(
    grant: Any,
    *,
    job_id: str,
    duplicate_grant_ids: set[str],
) -> str | None:
    if not isinstance(grant, Mapping):
        return "unsafe_runtime_grant_missing"
    grant_id = str(grant.get("grant_id") or "")
    if not re.fullmatch(r"[a-f0-9]{32}", grant_id):
        return "unsafe_runtime_grant_invalid"
    if grant_id in duplicate_grant_ids:
        return "unsafe_runtime_grant_duplicate"
    if grant.get("job_id") != job_id:
        return "unsafe_runtime_grant_job_mismatch"
    if grant.get("max_uses") != 1 or grant.get("uses_remaining") != 1:
        return "unsafe_runtime_grant_consumed"
    if grant.get("consumed_at") is not None:
        return "unsafe_runtime_grant_replayed"
    if _grant_is_expired(grant):
        return "unsafe_runtime_grant_expired"
    return None


def _consume_unsafe_runtime_grant(
    grant: Mapping[str, Any],
    *,
    job_id: str,
    duplicate_grant_ids: set[str],
    store: SecurePayloadStore,
) -> str | None:
    error = _grant_validation_error(
        grant,
        job_id=job_id,
        duplicate_grant_ids=duplicate_grant_ids,
    )
    reference = grant.get("grant_reference") if isinstance(grant, Mapping) else None
    if error:
        if isinstance(reference, str):
            try:
                store.delete(reference)
            except SecurePayloadStoreError:
                pass
        return error
    if not isinstance(reference, str):
        return "unsafe_runtime_grant_invalid"
    try:
        authenticator = store.get(reference)
    except SecurePayloadStoreError:
        return "unsafe_runtime_grant_replayed"
    expected = _grant_integrity(grant, authenticator)
    if not hmac.compare_digest(
        str(grant.get("integrity_hmac_sha256") or ""), expected
    ):
        try:
            store.delete(reference)
        except SecurePayloadStoreError:
            pass
        return "unsafe_runtime_grant_tampered"
    try:
        store.delete(reference)
    except SecurePayloadStoreError:
        return "unsafe_runtime_grant_consume_failed"
    return None


def _decode_queue_payload(value: bytes) -> tuple[str, str | None]:
    try:
        payload = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurePayloadStoreError("Secure queue payload is invalid.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("task"), str):
        raise SecurePayloadStoreError("Secure queue payload is invalid.")
    context = payload.get("context")
    if context is not None and not isinstance(context, str):
        raise SecurePayloadStoreError("Secure queue payload is invalid.")
    return payload["task"], context


def _delete_queue_payload(job: dict[str, Any]) -> None:
    reference = job.get("payload_reference")
    if not isinstance(reference, str) or job.get("payload_deleted_at"):
        return
    try:
        get_secure_payload_store().delete(reference)
        job["payload_deleted_at"] = utc_now_iso()
    except (SecurePayloadStoreError, SecurePayloadStoreUnavailable) as exc:
        job["payload_delete_error"] = type(exc).__name__


def load_queue() -> dict[str, Any]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if QUEUE_PATH.exists():
        queue = json.loads(QUEUE_PATH.read_text(encoding="utf-8"))
        for job in queue.get("jobs", []):
            if "task" in job or "context" in job:
                if job.get("status") not in {"done", "failed", "cancelled", "timed_out"}:
                    job["status"] = "blocked_legacy_payload"
                job["legacy_payload_present"] = True
            if job.get("status") == "pending":
                job["status"] = "queued"
            elif job.get("status") == "succeeded":
                job["status"] = "done"
        return queue
    return {"created_at": utc_now_iso(), "updated_at": None, "jobs": []}


def save_queue(queue: dict[str, Any]) -> None:
    queue["updated_at"] = utc_now_iso()
    _atomic_write_bytes(
        QUEUE_PATH,
        (json.dumps(queue, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


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
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    policy = load_queue_policy()
    job_id = "job-" + new_run_id()
    effective_timeout = timeout_seconds or int(policy.get("default_timeout_seconds", 900))
    effective_retries = max_retries
    if max_retries == 0:
        effective_retries = int(policy.get("retry_write_enabled" if allow_write else "retry_failed_read_only", 0))
    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    payload = json.dumps(
        {"task": task, "context": context},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        store = get_secure_payload_store()
        payload_reference = store.put(payload_id=job_id, value=payload)
    except (SecurePayloadStoreUnavailable, SecurePayloadStoreError) as exc:
        return {
            "ok": False,
            "status": "secure_payload_store_unavailable",
            "error": "Deferred prompt could not be placed in an OS-protected store.",
            "security_error": {
                "code": "secure_payload_store_unavailable",
                "message": str(exc),
                "safe_details": {"job_id": job_id},
                "suggested_action": "Enable the native protected store and submit a new queue job.",
            },
        }
    grant: dict[str, Any] | None = None
    grant_reference: str | None = None
    try:
        if allow_unsafe_runtime:
            prepared = _prepare_streaming_agent(
                task=task,
                role=role,
                cwd=effective_cwd,
                context=context,
                timeout_seconds=effective_timeout,
                allow_write=allow_write,
                allow_unsafe_runtime=True,
            )
            if prepared.launch_spec.trust_level == "local_unsafe":
                authenticator = os.urandom(32)
                grant_reference = store.put(
                    payload_id=f"{job_id}-runtime-grant",
                    value=authenticator,
                )
                grant = _new_unsafe_runtime_grant(
                    job_id=job_id,
                    prepared=prepared,
                    timeout_seconds=effective_timeout,
                    grant_reference=grant_reference,
                    authenticator=authenticator,
                )
                effective_retries = 0
    except Exception:
        store.delete(payload_reference)
        if grant_reference is not None:
            store.delete(grant_reference)
        raise
    job = {
        "job_id": job_id,
        "status": "queued",
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "priority": priority if priority is not None else int(policy.get("default_priority", 100)),
        "role": role,
        "cwd": str(effective_cwd),
        "payload_reference": payload_reference,
        "task_length": len(task),
        "context_length": len(context or ""),
        "timeout_seconds": effective_timeout,
        "max_retries": effective_retries,
        "attempts": 0,
        "allow_write": allow_write,
        "timeout_policy": "stop",
        "retry_policy": (
            "unsafe_runtime_requires_new_submission"
            if grant is not None
            else "read_only_default" if not allow_write else "write_disabled_by_default"
        ),
        "unsafe_runtime_grant": grant,
        "runs": [],
    }
    try:
        with queue_lock():
            queue = load_queue()
            queue.setdefault("jobs", []).append(job)
            save_queue(queue)
    except Exception:
        store.delete(payload_reference)
        if grant_reference is not None:
            store.delete(grant_reference)
        raise
    return {"ok": True, "job": _public_queue_job(job), "queue_path": str(QUEUE_PATH)}


def refresh_queue_job(job: dict[str, Any]) -> dict[str, Any]:
    if (
        job.get("status")
        in {"cancel_pending_cleanup", "timeout_pending_cleanup"}
        and job.get("run_id")
    ):
        pending_status = str(job["status"])
        status = single_run_status(
            str(job["run_id"]), include_output_tail=False
        )
        if status.get("active") or status.get("cleanup_state") in {
            "cleanup_pending",
            "cleanup_incomplete",
        }:
            return job
        job["status"] = (
            "timed_out"
            if pending_status == "timeout_pending_cleanup"
            else "cancelled"
        )
        job["cleanup_state"] = "cleanup_confirmed"
        job["updated_at"] = utc_now_iso()
        _delete_queue_payload(job)
        return job
    if job.get("status") != "running" or not job.get("run_id"):
        return job
    status = single_run_status(str(job["run_id"]), include_output_tail=False)
    started_age = _iso_age_seconds(str(job.get("started_at") or ""))
    timeout = int(job.get("timeout_seconds") or 0)
    if status.get("active") and timeout and started_age is not None and started_age > timeout:
        stopped = stop_run(str(job["run_id"]), force=True)
        stop_confirmed = _stop_response_confirmed(stopped)
        job["status"] = (
            "timed_out" if stop_confirmed else "timeout_pending_cleanup"
        )
        job["cleanup_state"] = (
            "cleanup_confirmed"
            if stop_confirmed
            else str(
                stopped.get("cleanup_state")
                or stopped.get("status")
                or "cleanup_incomplete"
            )
        )
        job["timeout_stop"] = {
            key: stopped.get(key)
            for key in (
                "ok",
                "status",
                "active",
                "stopped",
                "cleanup_state",
            )
        }
        job["last_error"] = (
            f"Queue timeout after {timeout}s; stop result: "
            f"{stopped.get('status')}"
        )
        job["updated_at"] = utc_now_iso()
        if stop_confirmed:
            _delete_queue_payload(job)
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
    if job.get("status") in {"done", "failed", "cancelled", "timed_out"}:
        _delete_queue_payload(job)
    return job


def _reconcile_abandoned_queue_claim(job: dict[str, Any]) -> bool:
    intended_run_id = job.get("intended_run_id")
    if not isinstance(intended_run_id, str) or not RUN_ID_RE.fullmatch(
        intended_run_id
    ):
        return False
    try:
        observed = single_run_status(
            intended_run_id, include_output_tail=False
        )
    except Exception:
        return False
    observed_status = str(observed.get("status") or "")
    if not observed.get("active") and observed_status not in {
        "succeeded",
        "failed",
        "stopped",
        "timed_out",
        "cleanup_pending",
        "cleanup_incomplete",
    }:
        return False
    job["run_id"] = intended_run_id
    job.setdefault("runs", [])
    if intended_run_id not in job["runs"]:
        job["runs"].append(intended_run_id)
    job["attempts"] = max(1, int(job.get("attempts") or 0))
    job["updated_at"] = utc_now_iso()
    job["reconciled_at"] = utc_now_iso()
    job.pop("launch_claim", None)
    if observed.get("active"):
        job["status"] = "running"
        job.setdefault("started_at", job.get("launch_intent_at") or utc_now_iso())
        job["last_error"] = "queue_launch_claim_reconciled"
        return True
    if observed_status == "succeeded":
        job["status"] = "done"
    elif observed_status == "timed_out":
        job["status"] = "timed_out"
    elif observed_status in {"cleanup_pending", "cleanup_incomplete"}:
        job["status"] = "cleanup_incomplete"
        job["cleanup_state"] = observed_status
    else:
        job["status"] = "failed"
    job["last_error"] = f"queue_launch_claim_reconciled_{observed_status}"
    _delete_queue_payload(job)
    return True


def _queue_launch_claim_owner_state(launch_claim: object) -> str:
    if not isinstance(launch_claim, Mapping):
        return "unverified"
    claim_id = launch_claim.get("claim_id")
    owner_pid = launch_claim.get("owner_pid")
    identity_data = launch_claim.get("owner_process_identity")
    if (
        not isinstance(claim_id, str)
        or not claim_id
        or not isinstance(owner_pid, int)
        or isinstance(owner_pid, bool)
        or owner_pid <= 0
        or not isinstance(identity_data, Mapping)
    ):
        return "unverified"
    try:
        expected = ProcessIdentity.from_dict(identity_data)
    except (TypeError, ValueError):
        return "unverified"
    if expected.pid != owner_pid or expected.launch_nonce != claim_id:
        return "mismatch"
    return compare_process_identity(
        expected,
        expected_launch_nonce=claim_id,
    ).state


def _queue_occupied_count(
    run_snapshot: Mapping[str, Any], jobs: list[dict[str, Any]]
) -> int:
    active_count = max(0, int(run_snapshot.get("active_count") or 0))
    active_run_ids = {
        str(item.get("run_id"))
        for item in run_snapshot.get("runs", [])
        if isinstance(item, Mapping)
        and item.get("active")
        and isinstance(item.get("run_id"), str)
    }
    unidentified_active = max(0, active_count - len(active_run_ids))
    queue_run_ids = {
        str(job.get("run_id"))
        for job in jobs
        if job.get("status")
        in {
            "running",
            "cancel_pending_cleanup",
            "timeout_pending_cleanup",
            "cleanup_incomplete",
        }
        and isinstance(job.get("run_id"), str)
    }
    launching_run_ids = {
        str(job.get("intended_run_id"))
        for job in jobs
        if job.get("status") == "launching"
        and isinstance(job.get("intended_run_id"), str)
    }
    unidentified_launching = sum(
        1
        for job in jobs
        if job.get("status") == "launching"
        and not isinstance(job.get("intended_run_id"), str)
    )
    return (
        unidentified_active
        + len(active_run_ids | queue_run_ids | launching_run_ids)
        + unidentified_launching
    )


def queue_tick(max_concurrent: int | None = None) -> dict[str, Any]:
    run_snapshot = run_status(include_finished=False)
    guard = load_cost_guard()
    policy = load_queue_policy()
    limit = max_concurrent if max_concurrent is not None else min(int(policy.get("max_concurrent", 3)), int(guard.get("max_concurrent", 4)))
    slots = 0
    claims: list[dict[str, Any]] = []
    with queue_lock():
        queue = load_queue()
        jobs = [refresh_queue_job(job) for job in queue.get("jobs", [])]
        for job in jobs:
            if job.get("status") != "launching":
                continue
            launch_claim = job.get("launch_claim")
            claim_owner_state = _queue_launch_claim_owner_state(launch_claim)
            if claim_owner_state == "match":
                continue
            if _reconcile_abandoned_queue_claim(job):
                continue
            job["status"] = (
                "blocked_runtime_grant"
                if job.get("unsafe_runtime_grant") is not None
                else "blocked_launch_claim"
            )
            job["last_error"] = (
                "queue_launch_claim_abandoned"
                if claim_owner_state in {"mismatch", "exited"}
                else "queue_launch_claim_identity_unverified"
            )
            job["launch_claim_identity_state"] = claim_owner_state
            job["updated_at"] = utc_now_iso()
            job.pop("launch_claim", None)
            _delete_queue_payload(job)
        slots = max(0, limit - _queue_occupied_count(run_snapshot, jobs))
        counts = Counter(
            str((job.get("unsafe_runtime_grant") or {}).get("grant_id") or "")
            for job in jobs
            if isinstance(job.get("unsafe_runtime_grant"), Mapping)
        )
        duplicate_ids = {grant_id for grant_id, count in counts.items() if grant_id and count > 1}
        pending = sorted(
            [job for job in jobs if job.get("status") == "queued"],
            key=lambda item: (-int(item.get("priority") or 0), str(item.get("created_at") or "")),
        )
        for job in pending[:slots]:
            claim_id = uuid.uuid4().hex
            try:
                owner_identity = capture_process_identity(
                    os.getpid(), launch_nonce=claim_id
                )
            except (OSError, TypeError, ValueError):
                owner_identity = None
            if owner_identity is None or not owner_identity.supported:
                job["last_error"] = "queue_controller_identity_unverified"
                job["updated_at"] = utc_now_iso()
                continue
            grant = job.get("unsafe_runtime_grant")
            unsafe = grant is not None
            if unsafe:
                try:
                    store = get_secure_payload_store()
                    error = _consume_unsafe_runtime_grant(
                        grant,
                        job_id=str(job.get("job_id") or ""),
                        duplicate_grant_ids=duplicate_ids,
                        store=store,
                    )
                except SecurePayloadStoreUnavailable:
                    error = "secure_payload_store_unavailable"
                if error:
                    job["status"] = "blocked_runtime_grant"
                    job["last_error"] = error
                    job["updated_at"] = utc_now_iso()
                    continue
                grant["uses_remaining"] = 0
                grant["consumed_at"] = utc_now_iso()
            job["status"] = "launching"
            job["launch_claim"] = {
                "claim_id": claim_id,
                "owner_pid": os.getpid(),
                "owner_process_identity": owner_identity.to_dict(),
                "claimed_at": utc_now_iso(),
            }
            job["updated_at"] = utc_now_iso()
            claims.append(
                {
                    "job_id": job["job_id"],
                    "claim_id": claim_id,
                    "payload_reference": job.get("payload_reference"),
                    "role": job.get("role"),
                    "cwd": job.get("cwd"),
                    "timeout_seconds": job.get("timeout_seconds"),
                    "allow_write": bool(job.get("allow_write", False)),
                    "unsafe": unsafe,
                    "grant": dict(grant) if isinstance(grant, Mapping) else None,
                }
            )
        queue["jobs"] = jobs
        save_queue(queue)

    started: list[dict[str, Any]] = []
    for claim in claims:
        run: dict[str, Any] | None = None
        error_code: str | None = None
        error_message: str | None = None
        error_security_fields: dict[str, Any] = {}
        mismatch_stop: dict[str, Any] | None = None
        try:
            reference = claim.get("payload_reference")
            if not isinstance(reference, str):
                raise SecurePayloadStoreError("Secure payload reference is missing.")
            task, context = _decode_queue_payload(get_secure_payload_store().get(reference))
            prepared = _prepare_streaming_agent(
                task=task,
                role=str(claim.get("role") or "implementation"),
                cwd=Path(str(claim.get("cwd") or Path.cwd())),
                context=context,
                timeout_seconds=claim.get("timeout_seconds"),
                allow_write=bool(claim.get("allow_write", False)),
                allow_unsafe_runtime=bool(claim.get("unsafe")),
            )
            grant = claim.get("grant")
            if isinstance(grant, Mapping):
                if _runtime_identity_digest(prepared) != grant.get("executable_identity_digest"):
                    raise _runtime_identity_changed(prepared.launch_spec.executable_identity.canonical_path)
                if prepared.launch_spec.policy_decision_id != grant.get("policy_decision_id"):
                    raise _security_error(
                        "runtime_policy_drift",
                        "Runtime policy decision changed after queue approval.",
                        suggested_action="Submit a new queue job under the current policy.",
                    )
            intended_run_id = str(prepared.metadata().get("run_id") or "")
            if not RUN_ID_RE.fullmatch(intended_run_id):
                raise OrchestratorError(
                    "Prepared queue launch has no valid deterministic run id."
                )
            claim_still_current = False
            with queue_lock():
                queue = load_queue()
                job = next(
                    (
                        item
                        for item in queue.get("jobs", [])
                        if item.get("job_id") == claim["job_id"]
                    ),
                    None,
                )
                persisted_claim = (
                    job.get("launch_claim") if isinstance(job, Mapping) else None
                )
                persisted_claim_id = (
                    persisted_claim.get("claim_id")
                    if isinstance(persisted_claim, Mapping)
                    else persisted_claim
                )
                if (
                    isinstance(job, dict)
                    and job.get("status") == "launching"
                    and persisted_claim_id == claim["claim_id"]
                ):
                    job["intended_run_id"] = intended_run_id
                    job["launch_intent_at"] = utc_now_iso()
                    job["updated_at"] = utc_now_iso()
                    claim_still_current = True
                elif isinstance(job, dict) and job.get("status") == "cancelled":
                    job.pop("launch_claim", None)
                    job["updated_at"] = utc_now_iso()
                    _delete_queue_payload(job)
                save_queue(queue)
            if not claim_still_current:
                continue
            run = run_streaming_agent(
                task=task,
                role=str(claim.get("role") or "implementation"),
                cwd=Path(str(claim.get("cwd") or Path.cwd())),
                context=context,
                timeout_seconds=claim.get("timeout_seconds"),
                allow_write=bool(claim.get("allow_write", False)),
                allow_unsafe_runtime=bool(claim.get("unsafe")),
                _prepared_launch=prepared,
            )
            if run.get("run_id") and run.get("run_id") != intended_run_id:
                try:
                    mismatch_stop = stop_run(str(run["run_id"]), force=True)
                except Exception as exc:
                    mismatch_stop = {
                        "ok": False,
                        "status": "cleanup_incomplete",
                        "active": True,
                        "stopped": False,
                        "error": str(exc),
                    }
                run = {
                    **run,
                    "ok": False,
                    "status": "queue_launch_run_id_mismatch",
                }
                error_code = "queue_launch_run_id_mismatch"
                error_message = (
                    "Queue launch returned a run id different from its "
                    "persisted intent."
                )
        except (RuntimeSecurityError, SecurePayloadStoreError, SecurePayloadStoreUnavailable) as exc:
            error_code = getattr(exc, "code", None) or type(exc).__name__
            error_message = str(exc)
            error_security_fields = _security_response_fields(exc)
        except Exception as exc:
            error_code = type(exc).__name__
            error_message = str(exc)
        with queue_lock():
            queue = load_queue()
            job = next((item for item in queue.get("jobs", []) if item.get("job_id") == claim["job_id"]), None)
            if job is None:
                if run and run.get("run_id"):
                    stop_run(str(run["run_id"]), force=True)
                continue
            persisted_claim = job.get("launch_claim")
            persisted_claim_id = (
                persisted_claim.get("claim_id")
                if isinstance(persisted_claim, Mapping)
                else persisted_claim
            )
            if (
                persisted_claim_id != claim["claim_id"]
                or job.get("status") != "launching"
            ):
                if run and run.get("run_id"):
                    run_id = str(run["run_id"])
                    job["run_id"] = run_id
                    job.setdefault("runs", [])
                    if run_id not in job["runs"]:
                        job["runs"].append(run_id)
                    try:
                        stop = stop_run(run_id, force=True)
                    except Exception as exc:
                        stop = {
                            "ok": False,
                            "status": "cleanup_incomplete",
                            "active": True,
                            "stopped": False,
                            "error": str(exc),
                        }
                    job["cleanup_state"] = str(
                        stop.get("cleanup_state")
                        or stop.get("status")
                        or "cleanup_incomplete"
                    )
                    job["cancel_stop"] = {
                        key: stop.get(key)
                        for key in (
                            "ok",
                            "status",
                            "active",
                            "stopped",
                            "cleanup_state",
                        )
                    }
                    if _stop_response_confirmed(stop):
                        job["status"] = "cancelled"
                        job["cleanup_state"] = "cleanup_confirmed"
                        _delete_queue_payload(job)
                    else:
                        job["status"] = "cancel_pending_cleanup"
                        job["last_error"] = "queue_cancel_cleanup_unconfirmed"
                else:
                    _delete_queue_payload(job)
                job.pop("launch_claim", None)
                job["updated_at"] = utc_now_iso()
                save_queue(queue)
                continue
            job.pop("launch_claim", None)
            launch_succeeded = _launch_response_succeeded(run)
            if launch_succeeded:
                job["status"] = "running"
                job["run_id"] = run["run_id"]
                job["started_at"] = utc_now_iso()
                job["attempts"] = int(job.get("attempts") or 0) + 1
                job["updated_at"] = utc_now_iso()
                job.setdefault("runs", []).append(run["run_id"])
                started.append({"job_id": job["job_id"], "run_id": run["run_id"], "role": job.get("role")})
            else:
                cleanup_unconfirmed = (
                    mismatch_stop is not None
                    and not _stop_response_confirmed(mismatch_stop)
                )
                job["status"] = (
                    "cleanup_incomplete" if cleanup_unconfirmed else "failed"
                )
                run_security_fields = _security_response_fields(run)
                security_fields = error_security_fields or run_security_fields
                run_security_error = security_fields.get("security_error")
                job["last_error"] = (
                    error_code
                    or (
                        run_security_error.get("code")
                        if isinstance(run_security_error, Mapping)
                        else None
                    )
                    or str((run or {}).get("status") or "queue_launch_failed")
                )
                job["last_error_detail"] = (
                    error_message
                    or str((run or {}).get("error") or "Queue launch was not accepted.")
                )
                job.update(security_fields)
                if run and run.get("run_id"):
                    job["run_id"] = run["run_id"]
                    if run["run_id"] not in job.setdefault("runs", []):
                        job["runs"].append(run["run_id"])
                if mismatch_stop is not None:
                    job["cleanup_state"] = (
                        "cleanup_incomplete"
                        if cleanup_unconfirmed
                        else "cleanup_confirmed"
                    )
                    job["launch_stop"] = {
                        key: mismatch_stop.get(key)
                        for key in (
                            "ok",
                            "status",
                            "active",
                            "stopped",
                            "cleanup_state",
                        )
                    }
                job["updated_at"] = utc_now_iso()
                if not cleanup_unconfirmed:
                    _delete_queue_payload(job)
            save_queue(queue)

    with queue_lock():
        final_queue = load_queue()
        public_jobs = [_public_queue_job(job) for job in final_queue.get("jobs", [])]
    return {"ok": True, "queue_path": str(QUEUE_PATH), "max_concurrent": limit, "slots_used": len(started), "started": started, "jobs": public_jobs}


def queue_status(include_finished: bool = True) -> dict[str, Any]:
    with queue_lock():
        queue = load_queue()
        all_jobs = [refresh_queue_job(job) for job in queue.get("jobs", [])]
        queue["jobs"] = all_jobs
        save_queue(queue)
    jobs = all_jobs
    if not include_finished:
        jobs = [
            job
            for job in all_jobs
            if job.get("status")
            in {
                "queued",
                "launching",
                "running",
                "cancel_pending_cleanup",
                "timeout_pending_cleanup",
                "cleanup_incomplete",
            }
        ]
    counts: dict[str, int] = {}
    for job in all_jobs:
        counts[str(job.get("status") or "unknown")] = counts.get(str(job.get("status") or "unknown"), 0) + 1
    return {"ok": True, "queue_path": str(QUEUE_PATH), "policy": load_queue_policy(), "count": len(jobs), "state_counts": counts, "jobs": [_public_queue_job(job) for job in jobs]}


def migrate_legacy_queue_payloads(apply: bool = False) -> dict[str, Any]:
    """Move legacy plaintext queue prompts into the protected store transactionally."""
    with queue_lock():
        queue = load_queue()
        legacy = [
            job
            for job in queue.get("jobs", [])
            if "task" in job or "context" in job
        ]
        if not apply:
            return {
                "ok": True,
                "applied": False,
                "legacy_job_count": len(legacy),
                "job_ids": [str(job.get("job_id") or "") for job in legacy],
            }
        if not legacy:
            return {"ok": True, "applied": True, "migrated_count": 0, "jobs": []}
        try:
            store = get_secure_payload_store()
        except (SecurePayloadStoreUnavailable, SecurePayloadStoreError) as exc:
            return {
                "ok": False,
                "applied": False,
                "status": "secure_payload_store_unavailable",
                "error": str(exc),
            }
        created: list[str] = []
        migrated_ids: list[str] = []
        try:
            for job in legacy:
                task = job.get("task")
                context = job.get("context")
                if not isinstance(task, str) or (
                    context is not None and not isinstance(context, str)
                ):
                    raise SecurePayloadStoreError("Legacy queue payload is invalid.")
                value = json.dumps(
                    {"task": task, "context": context},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                reference = store.put(
                    payload_id=str(job.get("job_id") or uuid.uuid4().hex),
                    value=value,
                )
                created.append(reference)
                if store.get(reference) != value:
                    raise SecurePayloadStoreError(
                        "Protected payload retrieval verification failed."
                    )
                job["payload_reference"] = reference
                job["task_length"] = len(task)
                job["context_length"] = len(context or "")
                job.pop("task", None)
                job.pop("context", None)
                job.pop("legacy_payload_present", None)
                if job.get("status") == "blocked_legacy_payload":
                    job["status"] = "queued"
                job["updated_at"] = utc_now_iso()
                migrated_ids.append(str(job.get("job_id") or ""))
            save_queue(queue)
        except Exception:
            for reference in created:
                try:
                    store.delete(reference)
                except SecurePayloadStoreError:
                    pass
            raise
        return {
            "ok": True,
            "applied": True,
            "migrated_count": len(migrated_ids),
            "job_ids": migrated_ids,
        }


def queue_cancel(job_id: str) -> dict[str, Any]:
    if not QUEUE_JOB_ID_RE.match(job_id):
        raise OrchestratorError(f"Invalid queue job id: {job_id}")
    with queue_lock():
        queue = load_queue()
        for job in queue.get("jobs", []):
            if job.get("job_id") != job_id:
                continue
            run_id = job.get("run_id") or job.get("intended_run_id")
            stop: dict[str, Any] | None = None
            if job.get("status") in {
                "running",
                "launching",
                "cancel_pending_cleanup",
                "timeout_pending_cleanup",
                "cleanup_incomplete",
            } and isinstance(run_id, str):
                try:
                    stop = stop_run(run_id, force=True)
                except Exception as exc:
                    stop = {
                        "ok": False,
                        "status": "cleanup_incomplete",
                        "active": True,
                        "stopped": False,
                        "error": str(exc),
                    }
                job["run_id"] = run_id
                if run_id not in job.setdefault("runs", []):
                    job["runs"].append(run_id)
            if stop is not None and not _stop_response_confirmed(stop):
                job["status"] = "cancel_pending_cleanup"
                job["cleanup_state"] = str(
                    stop.get("cleanup_state")
                    or stop.get("status")
                    or "cleanup_incomplete"
                )
                job["last_error"] = "queue_cancel_cleanup_unconfirmed"
            else:
                job["status"] = "cancelled"
                job["cleanup_state"] = "cleanup_confirmed"
                _delete_queue_payload(job)
            job["updated_at"] = utc_now_iso()
            save_queue(queue)
            return {
                "ok": job["status"] == "cancelled",
                "job": _public_queue_job(job),
                "stop": stop,
            }
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
                "from pathlib import Path",
                "config = json.loads(Path(__file__).with_name('fake-config.json').read_text(encoding='utf-8'))",
                "steps = int(config['steps'])",
                "delay = float(config['delay'])",
                "payload_bytes = int(config['payload_bytes'])",
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
    mock_parent = Path(os.environ.get("PROGRAMDATA") or "C:/ProgramData") / "cc-orchestrator-mock"
    mock_dir = mock_parent / uuid.uuid4().hex[:12]
    mock_dir.mkdir(parents=True, exist_ok=False)
    launcher = write_fake_claude_launcher(mock_dir)

    def configure_fake_runtime(
        *, steps: int, delay: float, payload_bytes: int = 0
    ) -> None:
        _atomic_write_text(
            mock_dir / "fake-config.json",
            json.dumps(
                {
                    "steps": steps,
                    "delay": delay,
                    "payload_bytes": payload_bytes,
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        )

    configure_fake_runtime(steps=4, delay=0.05)
    fixture_token = _TEST_ONLY_RUNTIME_CANDIDATE.set(
        RuntimeExecutableCandidate(
            canonical_path=str(launcher.resolve()),
            source="explicit_mock_stream_test_fixture",
            trust_class="trusted_default",
        )
    )
    cleanup_mock_dir = os.environ.get("CC_ORCHESTRATOR_CLEAN_MOCK_DIR") == "1"
    try:
            configure_fake_runtime(steps=4, delay=0.05)
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

            configure_fake_runtime(steps=200, delay=0.1)
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

            configure_fake_runtime(steps=20, delay=0.01, payload_bytes=4096)
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

            configure_fake_runtime(steps=12, delay=0, payload_bytes=4096)
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
        _TEST_ONLY_RUNTIME_CANDIDATE.reset(fixture_token)
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
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
    """Open a guarded Claude Code runtime in a new Windows console."""
    if not task.strip():
        raise OrchestratorError("Task cannot be empty.")
    route = resolve_route(role=role, task_type=task_type, profile=profile)
    provider = get_provider(route["profile"])
    model_policy = load_json(POLICY_PATH)
    write_enabled = allow_write or bool(
        model_policy.get("safety", {}).get("default_write_enabled", False)
    )
    permission_mode = route["permission_mode"] if not write_enabled else "acceptEdits"
    timeout = min(
        int(route["timeout_seconds"]),
        int(model_policy.get("safety", {}).get("max_timeout_seconds", 1800)),
    )
    selected_model = route.get("model_override") or provider.model
    timeout = clamp_timeout_for_model(selected_model, timeout)
    effective_cwd = (cwd or Path.cwd()).expanduser().resolve()
    paths = _guarded_launch_paths(effective_cwd)
    prompt = build_prompt(role, task, context, artifact_root=paths["artifact_root"])
    prepared = prepare_worker_launch(
        mode="visible",
        prompt=prompt,
        provider_env=provider.env,
        model_override=route.get("model_override"),
        cwd=effective_cwd,
        workspace_root=paths["workspace_root"],
        artifact_root=paths["artifact_root"],
        permission_mode=permission_mode,
        timeout_seconds=timeout,
        arguments=(
            "--permission-mode",
            permission_mode,
            "--no-session-persistence",
        ),
        safe_route_metadata={
            "role": role,
            "task_type": route["task_type"],
            "profile": {
                "id": provider.id,
                "name": provider.name,
                "model": selected_model,
                "provider_default_model": provider.model,
                "endpoints": provider.endpoints,
            },
            "permission_mode": permission_mode,
            "allow_write": write_enabled,
            "route_reason": route.get("reason", ""),
            "visible_console": True,
        },
        allow_unsafe_runtime=allow_unsafe_runtime,
        selected_model=selected_model,
        sensitive_values=(task, context or ""),
    )
    if os.name != "nt":
        error = _security_error(
            "visible_runtime_unsupported",
            "Visible runtime launch is unavailable on this platform.",
            suggested_action="Use run-streaming and poll the guarded worker output.",
        )
        return {
            "ok": False,
            "status": "visible_runtime_unsupported",
            "error": error.message,
            "security_error": error.to_dict(),
        }
    return start_prepared_worker_launch(prepared)


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


def workflow_run(
    file: str | Path,
    task: str,
    cwd: Path | None = None,
    mock: bool = False,
    loop_guard: int = 50,
    allow_unsafe_runtime: bool = False,
) -> dict[str, Any]:
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
    persisted_spec = {
        key: value
        for key, value in spec.items()
        if not str(key).startswith("_") and key not in {"task", "context", "prompt"}
    }
    persisted_nodes: dict[str, Any] = {}
    for node_id, node in (persisted_spec.get("nodes") or {}).items():
        if isinstance(node, Mapping):
            persisted_nodes[str(node_id)] = {
                key: value
                for key, value in node.items()
                if key not in {"task", "context", "prompt"}
            }
        else:
            persisted_nodes[str(node_id)] = node
    persisted_spec["nodes"] = persisted_nodes
    source_text = json.dumps(persisted_spec, ensure_ascii=False, indent=2)
    _atomic_write_text(workflow_dir / "workflow.yaml", source_text + "\n")
    manifest = {
        "workflow_id": workflow_id,
        "source_file": spec.get("_source_file"),
        "task_length": len(task),
        "cwd": str((cwd or Path.cwd()).resolve()),
        "mock": mock,
        "created_at": utc_now_iso(),
    }
    write_json_file(workflow_dir / "manifest.json", manifest)
    status: dict[str, Any] = {
        "workflow_id": workflow_id,
        "status": "running",
        "task_length": len(task),
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
                    allow_unsafe_runtime=allow_unsafe_runtime,
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
    stopped: list[dict[str, Any]] = []
    for item in sorted(invalidated):
        node_state = (status.get("nodes") or {}).get(item)
        if not isinstance(node_state, dict) or not node_state.get("run_id"):
            continue
        try:
            stop = stop_run(str(node_state["run_id"]), force=True)
        except Exception as exc:
            stop = {
                "ok": False,
                "status": "cleanup_incomplete",
                "active": True,
                "stopped": False,
                "cleanup_state": "cleanup_incomplete",
                "error": str(exc),
            }
        confirmed = _stop_response_confirmed(stop)
        stopped.append({"node_id": item, "confirmed": confirmed, "stop": stop})
        if not confirmed:
            node_state["state"] = "cancel_pending_cleanup"
            node_state["cleanup_state"] = str(
                stop.get("cleanup_state")
                or stop.get("status")
                or "cleanup_incomplete"
            )
    if any(not item["confirmed"] for item in stopped):
        status["status"] = "cleanup_incomplete"
        status["block_reason"] = "workflow_retry_cleanup_unconfirmed"
        status.setdefault("decisions", []).append(
            workflow_decision(
                node_id,
                "block",
                "manual retry cleanup was not confirmed",
                invalidated=sorted(invalidated),
                requires_controller_takeover=True,
            )
        )
        write_workflow_status(workflow_dir, status)
        return {
            "ok": False,
            "workflow_id": workflow_id,
            "node_id": node_id,
            "invalidated": [],
            "pending_invalidation": sorted(invalidated),
            "stopped": stopped,
            "status": status["status"],
            "status_path": str(workflow_dir / "status.json"),
        }
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
    return {"ok": True, "workflow_id": workflow_id, "node_id": node_id, "invalidated": sorted(invalidated), "stopped": stopped, "status_path": str(workflow_dir / "status.json")}


def workflow_stop(workflow_id: str, force: bool = False, cwd: Path | None = None) -> dict[str, Any]:
    workflow_dir = safe_workflow_dir(workflow_id, cwd=cwd)
    status = read_json_file(workflow_dir / "status.json", {})
    stopped: list[dict[str, Any]] = []
    cleanup_states = {"cancel_pending_cleanup", "cleanup_incomplete"}
    for node_id, node in (status.get("nodes") or {}).items():
        if node.get("state") in {"running", *cleanup_states} and node.get("run_id"):
            try:
                stop = stop_run(str(node["run_id"]), force=force)
            except Exception as exc:
                stop = {
                    "ok": False,
                    "status": "cleanup_incomplete",
                    "active": True,
                    "stopped": False,
                    "cleanup_state": "cleanup_incomplete",
                    "error": str(exc),
                }
            confirmed = _stop_response_confirmed(stop)
            stopped.append(
                {"node_id": node_id, "confirmed": confirmed, "stop": stop}
            )
            node["state"] = (
                "cancelled" if confirmed else "cancel_pending_cleanup"
            )
            if not confirmed:
                node["cleanup_state"] = str(
                    stop.get("cleanup_state")
                    or stop.get("status")
                    or "cleanup_incomplete"
                )
            else:
                node["cleanup_state"] = "cleanup_confirmed"
    cleanup_incomplete = any(not item["confirmed"] for item in stopped) or any(
        node.get("state") in cleanup_states
        for node in (status.get("nodes") or {}).values()
    )
    status["status"] = (
        "cleanup_incomplete" if cleanup_incomplete else "cancelled"
    )
    status.setdefault("decisions", []).append(
        workflow_decision(None, "cancel", "workflow-stop requested", requires_controller_takeover=True)
    )
    write_workflow_status(workflow_dir, status)
    return {
        "ok": not cleanup_incomplete,
        "workflow_id": workflow_id,
        "stopped": stopped,
        "status": status["status"],
    }


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
        workflow_mock = workflow_run(workflow_path, task="mock task", cwd=Path(tmp), mock=True, allow_unsafe_runtime=False)
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
            workflow_run(workflow_path, task="real workflow should be disabled", cwd=Path(tmp), mock=False, allow_unsafe_runtime=False)
            real_workflow_run_rejected = False
        except OrchestratorError:
            real_workflow_run_rejected = True
        manual_retry_workflow = workflow_run(workflow_path, task="mock manual retry", cwd=Path(tmp), mock=True, allow_unsafe_runtime=False)
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
        missing_handoff_run = workflow_run(missing_handoff_path, task="mock missing handoff", cwd=Path(tmp), mock=True, allow_unsafe_runtime=False)
        missing_handoff_nodes = (missing_handoff_run.get("status") or {}).get("nodes") or {}

        max_retry_spec = json.loads(json.dumps(valid_workflow))
        max_retry_spec["nodes"]["testing"]["mock_status_sequence"] = ["fail", "fail", "fail"]
        max_retry_spec["nodes"]["quality_gate"]["on_fail"]["max_retries"] = 1
        max_retry_path = Path(tmp) / "max-retry-workflow.json"
        write_json_file(max_retry_path, max_retry_spec)
        max_retry_run = workflow_run(max_retry_path, task="mock max retry", cwd=Path(tmp), mock=True, allow_unsafe_runtime=False)
        max_retry_status = max_retry_run.get("status") or {}
        max_retry_nodes = max_retry_status.get("nodes") or {}
        max_retry_decisions = max_retry_status.get("decisions") or []
        loop_guard_run = workflow_run(workflow_path, task="mock loop guard", cwd=Path(tmp), mock=True, loop_guard=1, allow_unsafe_runtime=False)
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
    run.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    stream.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    send.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
    team = sub.add_parser("spawn-role-team")
    team.add_argument("task")
    team.add_argument("--roles", default="requirements,architecture,security,testing")
    team.add_argument("--cwd")
    team.add_argument("--context")
    team.add_argument("--timeout-seconds", type=int)
    team.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
    collect = sub.add_parser("collect-team-results")
    collect.add_argument("--team-id")
    collect.add_argument("--run-id", action="append", dest="run_ids")
    collect.add_argument("--tail-chars", type=int, default=8000)
    cross = sub.add_parser("cross-review")
    cross.add_argument("--run-id", action="append", dest="run_ids", required=True)
    cross.add_argument("--reviewer-roles", default="security,testing,review")
    cross.add_argument("--cwd")
    cross.add_argument("--timeout-seconds", type=int)
    cross.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    bench.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
    bench_suite = sub.add_parser("benchmark-suite")
    bench_suite.add_argument("--profile")
    bench_suite.add_argument("--timeout-seconds", type=int, default=120)
    bench_suite.add_argument("--execute", action="store_true")
    bench_suite.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    queue_submit_cmd.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
    queue_tick_cmd = sub.add_parser("queue-tick")
    queue_tick_cmd.add_argument("--max-concurrent", type=int)
    queue_status_cmd = sub.add_parser("queue-status")
    queue_status_cmd.add_argument("--active-only", action="store_true")
    queue_cancel_cmd = sub.add_parser("queue-cancel")
    queue_cancel_cmd.add_argument("--job-id", required=True)
    queue_migrate_cmd = sub.add_parser("queue-migrate-payloads")
    queue_migrate_cmd.add_argument("--apply", action="store_true")
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
    visible.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    workflow_run_cmd.add_argument("--allow-unsafe-runtime", action="store_true", help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.")
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
    visible_worker_cmd = sub.add_parser("_visible-worker")
    visible_worker_cmd.add_argument("--run-id", required=True)
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
                )
            )
        elif args.command == "benchmark-suite":
            print_json(benchmark_suite(profile=args.profile, execute=args.execute, timeout_seconds=args.timeout_seconds, allow_unsafe_runtime=args.allow_unsafe_runtime))
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
                )
            )
        elif args.command == "queue-tick":
            print_json(queue_tick(max_concurrent=args.max_concurrent))
        elif args.command == "queue-status":
            print_json(queue_status(include_finished=not args.active_only))
        elif args.command == "queue-cancel":
            print_json(queue_cancel(args.job_id))
        elif args.command == "queue-migrate-payloads":
            print_json(migrate_legacy_queue_payloads(apply=args.apply))
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
                    allow_unsafe_runtime=args.allow_unsafe_runtime,
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
            print_json(workflow_run(args.file, task=args.task, cwd=Path(args.cwd) if args.cwd else None, mock=args.mock, loop_guard=args.loop_guard, allow_unsafe_runtime=args.allow_unsafe_runtime))
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
        elif args.command == "_visible-worker":
            print_json(visible_worker(args.run_id))
        return 0
    except RuntimeSecurityError as exc:
        print_json(
            {
                "ok": False,
                "error": exc.message,
                "security_error": exc.to_dict(),
                "next_step": exc.suggested_action,
            }
        )
        return 2
    except OrchestratorError as exc:
        print_json({"ok": False, "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
