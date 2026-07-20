# Guarded Runtime Launch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Claude Code launch use one validated executable and environment contract, and make every destructive process operation prove ownership before signaling a PID.

**Architecture:** Add two stdlib-only security modules beside the current orchestrator. `runtime_security.py` owns policy parsing, provider-environment classification, executable identity, immutable launch specifications, structured errors, and audit events. `process_identity.py` owns cross-platform live-process evidence. `cc_orchestrator.py` remains the integration layer and routes one-shot, streaming, visible, follow-up, team, queue, and workflow launches through the shared builder; `server.py` only validates and forwards public request fields.

**Tech Stack:** Python 3.10/3.12 stdlib, Pydantic/FastMCP at the existing MCP boundary, `unittest`, GitHub Actions on Windows/Ubuntu/macOS, existing VitePress documentation.

## Global Constraints

- Preserve existing command names, MCP tool names, artifact locations, and safe CCSwitch profiles.
- Provider values may contain secrets. Never persist environment values, prompt contents, authorization headers, or an unredacted command.
- Send prompts to immediate workers and runtimes through anonymous stdin pipes. Do not create `prompt.txt` or place prompts in process argv.
- Do not persist task/context text in run, team, workflow, or follow-up artifacts. Persistent queue payloads use an OS-protected secret store and queue metadata contains only an opaque reference.
- Provider configuration never selects the runtime executable and never overrides absolute-deny environment keys.
- An unsafe custom runtime requires both a matching local policy entry and `allow_unsafe_runtime=true` on that launch request.
- `force` changes signal strength only. It never bypasses process-identity verification.
- Legacy run metadata stays readable but cannot authorize a destructive stop.
- Background, visible, queued, team, and workflow launches fail closed when the platform cannot capture the minimum process identity. Foreground one-shot may rely on its directly owned `Popen` handle.
- Tests must not depend on a real Claude Code installation, a real API key, or network access.
- Use `apply_patch` for manual edits and keep each task's commit focused.

## File Map

| File | Responsibility |
| --- | --- |
| `scripts/cc-orchestrator/runtime_security.py` | Security errors, policy loading, provider env classification, executable identity, immutable launch spec, safe metadata, audit events |
| `scripts/cc-orchestrator/process_identity.py` | Windows/Linux/macOS process evidence, comparison, support reporting |
| `scripts/cc-orchestrator/secure_payload_store.py` | OS-protected deferred queue payloads and fail-closed support reporting |
| `scripts/cc-orchestrator/cc_orchestrator.py` | Shared launch integration, worker lifecycle, public CLI, status/stop behavior |
| `scripts/cc-orchestrator/server.py` | MCP input fields, structured error envelope, public launch forwarding |
| `scripts/cc-orchestrator/config/runtime_security.example.json` | Documented repository-owned policy example without executable-specific hashes |
| `scripts/cc-orchestrator/tests/_support.py` | Stable module import helpers and fake-runtime fixtures |
| `scripts/cc-orchestrator/tests/test_runtime_security.py` | Policy, executable identity, immutable spec, errors, audit redaction |
| `scripts/cc-orchestrator/tests/test_process_identity.py` | Live identity capture/comparison and no-signal mismatch behavior |
| `scripts/cc-orchestrator/tests/test_guarded_launch.py` | End-to-end fake one-shot/stream/visible/queue/team/follow-up launch coverage |
| `scripts/cc-orchestrator/tests/test_public_surfaces.py` | CLI and MCP propagation/error-contract coverage |
| `scripts/cc-orchestrator/tests/test_secure_payload_store.py` | DPAPI/Keychain/Secret Service adapters, opaque queue records, cleanup |
| `scripts/cc-orchestrator/tests/test_install_preservation.py` | Installer/upgrade preservation of policy and audit key |
| `install/install.ps1` and `install/install.sh` | Preserve user-owned runtime policy and audit key during install/upgrade |
| `.gitignore` | Exclude user-owned runtime policy and audit key |
| `.github/workflows/runtime-checks.yml` | Cross-platform Python matrix and security test gates |
| `scripts/cc-orchestrator/README.md` | Operator configuration and failure recovery |
| `SKILL.md` | Controller-facing secure-launch rules |
| `version.json` and `scripts/cc-orchestrator/version.json` | Release metadata and preservation of user-owned policy |

---

### Task 1: Establish the stdlib security test harness and structured errors

**Files:**
- Create: `scripts/cc-orchestrator/tests/__init__.py`
- Create: `scripts/cc-orchestrator/tests/_support.py`
- Create: `scripts/cc-orchestrator/tests/test_runtime_security.py`
- Create: `scripts/cc-orchestrator/runtime_security.py`

- [ ] **Step 1: Add a stable test import helper**

```python
# scripts/cc-orchestrator/tests/_support.py
from __future__ import annotations

import sys
from pathlib import Path

ORCHESTRATOR_DIR = Path(__file__).resolve().parents[1]
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))
```

- [ ] **Step 2: Write failing tests for the security error contract**

```python
from _support import ORCHESTRATOR_DIR  # noqa: F401
from runtime_security import RuntimeSecurityError


class RuntimeSecurityErrorTests(unittest.TestCase):
    def test_error_has_stable_safe_payload(self) -> None:
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details={"keys": ["PATH"]},
            suggested_action="Remove the key from CCSwitch.",
        )
        self.assertEqual(error.to_dict()["code"], "provider_env_forbidden")
        self.assertNotIn("value", json.dumps(error.to_dict()).lower())
```

- [ ] **Step 3: Run the focused test and confirm the expected import failure**

Run: `python -m unittest discover -s scripts/cc-orchestrator/tests -p "test_runtime_security.py" -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'runtime_security'`.

- [ ] **Step 4: Implement the error type and shared data helpers**

```python
# scripts/cc-orchestrator/runtime_security.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class RuntimeSecurityError(RuntimeError):
    code: str
    message: str
    safe_details: Mapping[str, Any]
    suggested_action: str

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)
        object.__setattr__(self, "safe_details", MappingProxyType(dict(self.safe_details)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "safe_details": dict(self.safe_details),
            "suggested_action": self.suggested_action,
        }


def canonical_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=True)
```

- [ ] **Step 5: Run focused tests and commit**

Run: `python -m unittest discover -s scripts/cc-orchestrator/tests -p "test_runtime_security.py" -v`

Expected: PASS.

Run: `git add scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/tests && git commit -m "test: establish runtime security contract"`

---

### Task 2: Enforce provider environment policy and double authorization

**Files:**
- Modify: `scripts/cc-orchestrator/runtime_security.py`
- Modify: `scripts/cc-orchestrator/tests/test_runtime_security.py`
- Create: `scripts/cc-orchestrator/config/runtime_security.example.json`

- [ ] **Step 1: Add failing table tests for all environment classes**

Cover case-insensitive exact keys and prefixes:

```python
ABSOLUTE_DENY_CASES = [
    "PATH", "Path", "PATHEXT", "COMSPEC", "SHELL", "CLAUDE_CODE_BIN",
    "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "CC_ORCHESTRATOR_ARTIFACT_ROOT",
]

def test_forbidden_provider_keys_fail_closed(self) -> None:
    policy = RuntimeSecurityPolicy.default()
    for key in ABSOLUTE_DENY_CASES:
        with self.subTest(key=key), self.assertRaises(RuntimeSecurityError) as raised:
            policy.validate_provider_env({key: "fixture-secret"})
        self.assertEqual(raised.exception.code, "provider_env_forbidden")

def test_unknown_key_requires_local_allowlist(self) -> None:
    with self.assertRaises(RuntimeSecurityError) as raised:
        RuntimeSecurityPolicy.default().validate_provider_env({"VENDOR_REGION": "cn"})
    self.assertEqual(raised.exception.code, "provider_env_unrecognized")

def test_absolute_deny_cannot_be_allowlisted(self) -> None:
    with self.assertRaises(RuntimeSecurityError):
        RuntimeSecurityPolicy(extra_provider_env_keys=("PATH",))
```

Also prove the default allowlist accepts the supported Anthropic API/model/base URL variables and `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` without changing their values.

- [ ] **Step 2: Run the focused tests and confirm missing-policy failures**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_runtime_security.py -v`

Expected: FAIL because `RuntimeSecurityPolicy` is not implemented.

- [ ] **Step 3: Implement policy parsing and classification**

Add these public signatures:

```python
@dataclass(frozen=True)
class PinnedExecutableIdentity:
    canonical_path: str
    sha256: str
    size: int
    file_id: tuple[int, int] | None = None
    target_kind: str = "native"
    interpreter_identity: "PinnedExecutableIdentity | None" = None


@dataclass(frozen=True)
class ApprovedUnsafeRuntime:
    runtime_id: str
    identity: PinnedExecutableIdentity


@dataclass(frozen=True)
class RuntimeExecutableCandidate:
    canonical_path: str
    source: str
    trust_class: str  # trusted_default, discovered_unpinned, local_configured


@dataclass(frozen=True)
class RuntimeSecurityPolicy:
    runtime_executable: str | None = None
    extra_provider_env_keys: tuple[str, ...] = ()
    unsafe_runtimes: tuple[ApprovedUnsafeRuntime, ...] = ()
```

The complete public methods are `default() -> RuntimeSecurityPolicy`, `load(path: Path) -> RuntimeSecurityPolicy`, `validate_provider_env(provider_env: Mapping[str, str]) -> tuple[tuple[str, str], ...]`, `configured_runtime_path() -> Path | None`, and `find_unsafe_runtime(canonical_executable: Path) -> ApprovedUnsafeRuntime | None`. Policy parsing applies the same maximum chain depth and cycle rejection as live identity capture; authorization recursively compares every pinned wrapper/interpreter node.

Implementation rules:

- Normalize keys with `casefold()` on every platform.
- Reject absolute-deny keys before consulting the local allowlist.
- Reject unknown keys with `provider_env_unrecognized`; include only sorted key names in safe details.
- Return sorted immutable `(key, value)` tuples so later code cannot mutate the approved set.
- Reject malformed JSON, duplicate unsafe runtime ids, relative paths, non-hex digests, and allowlist entries that collide with absolute-deny keys.
- Treat `BASH_ENV`, `ENV`, `ZDOTDIR`, `PSModulePath`, `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`, `RUBYOPT`, `RUBYLIB`, `PERL5OPT`, `PERL5LIB`, `GIT_CONFIG*`, `GIT_SSH_COMMAND`, and `SSLKEYLOGFILE` as absolute-deny execution or exfiltration controls. Unknown keys remain denied unless explicitly allowlisted.
- Reject embedded NULs, duplicate case-folded key names, individual values above 32 KiB, and a validated environment block above 128 KiB.

- [ ] **Step 4: Add and validate the repository-owned example**

```json
{
  "schema_version": 1,
  "runtime_executable": null,
  "extra_provider_env_keys": ["VENDOR_REGION"],
  "unsafe_runtimes": []
}
```

The real user-owned file remains `runtime_security.override.json` and is not committed.

- [ ] **Step 5: Add failing double-authorization tests**

Use a temporary executable fixture and assert:

- default discovered runtime returns trust level `trusted_default` without a request flag;
- custom runtime with neither approval fails `runtime_not_trusted`;
- custom runtime with only policy approval fails `unsafe_runtime_request_missing`;
- custom runtime with only request approval fails `unsafe_runtime_policy_missing`;
- matching policy plus request flag returns `local_unsafe`;
- path, digest, or size mismatch fails closed.
- the same canonical path with `trusted_default` is accepted while `discovered_unpinned` still requires double authorization;
- unknown candidate source/trust class is rejected rather than inferred from path equality.
- a two- and four-level wrapper/interpreter chain requires every recursive policy pin to match; omission or replacement at any depth fails `runtime_identity_changed`.

This ordering is the stable contract: neither factor -> `runtime_not_trusted`; request only -> `unsafe_runtime_policy_missing`; policy only -> `unsafe_runtime_request_missing`; both present but pin mismatch -> `runtime_identity_changed`.

- [ ] **Step 6: Implement the decision function**

```python
@dataclass(frozen=True)
class RuntimeTrustDecision:
    runtime_id: str
    trust_level: str
    policy_decision_id: str


def authorize_runtime(
    *,
    candidate: RuntimeExecutableCandidate,
    identity: "ExecutableIdentity",
    policy: RuntimeSecurityPolicy,
    allow_unsafe_runtime: bool,
) -> RuntimeTrustDecision:
    executable = Path(candidate.canonical_path)
    if candidate.trust_class == "trusted_default":
        return trusted_default_decision(identity)
    approved = policy.find_unsafe_runtime(executable)
    if approved is None and not allow_unsafe_runtime:
        raise runtime_not_trusted(executable)
    if approved is None:
        raise unsafe_runtime_policy_missing(executable)
    if not allow_unsafe_runtime:
        raise unsafe_runtime_request_missing(executable)
    verify_unsafe_runtime_pin(approved, identity)
    return local_unsafe_decision(approved, identity)
```

Derive `policy_decision_id` from canonical path, candidate source/trust class, wrapper/interpreter digests, policy schema, and both authorization factors; never include environment values. Reject unknown trust classes. Equality with a path discovered as `discovered_unpinned` never upgrades it to trusted default.

- [ ] **Step 7: Run tests and commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_runtime_security.py -v`

Expected: PASS.

Run: `git add scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/config/runtime_security.example.json scripts/cc-orchestrator/tests/test_runtime_security.py && git commit -m "feat: enforce runtime provider policy"`

---

### Task 3: Build immutable launch and executable identity contracts

**Files:**
- Modify: `scripts/cc-orchestrator/runtime_security.py`
- Modify: `scripts/cc-orchestrator/tests/test_runtime_security.py`

- [ ] **Step 1: Write failing executable identity tests**

Create a temporary fake executable and assert canonical path, `st_size`, `st_mtime_ns`, SHA-256, script-wrapper classification, and `matches_current_file()`. Rewrite the file with equal length and force a later mtime; assert the identity no longer matches.

- [ ] **Step 2: Write failing deep-immutability and public-projection tests**

```python
spec = RuntimeLaunchSpec.create(
    runtime_id="claude-default",
    protocol_version=1,
    executable_identity=identity,
    arguments=("-p", "--output-format", "stream-json"),
    cwd=temp_dir,
    permission_mode="plan",
    timeout_seconds=60,
    environment=(("ANTHROPIC_API_KEY", fixture_secret),),
    trust_level="trusted_default",
    policy_decision_id="decision-1",
)
with self.assertRaises(TypeError):
    spec.environment["PATH"] = "bad"
public = json.dumps(spec.public_metadata())
self.assertNotIn(fixture_secret, public)
self.assertNotIn("prompt", public.lower())
self.assertEqual(spec.public_metadata()["environment_keys"], ["ANTHROPIC_API_KEY"])
self.assertEqual(
    hashlib.sha256(spec.private_frame()).hexdigest(),
    spec.public_metadata()["launch_contract_sha256"],
)
```

- [ ] **Step 3: Run tests and confirm missing identity/spec failures**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_runtime_security.py -v`

Expected: FAIL because `ExecutableIdentity` and `RuntimeLaunchSpec` are absent.

- [ ] **Step 4: Implement executable identity and exact comparison**

```python
@dataclass(frozen=True)
class ExecutableIdentity:
    canonical_path: str
    size: int
    mtime_ns: int
    sha256: str
    file_id: tuple[int, int] | None
    target_kind: str
    interpreter_identity: "ExecutableIdentity | None"

```

The complete methods are `capture(executable: str | Path) -> ExecutableIdentity`, `matches_current_file() -> bool`, `to_public_dict() -> dict[str, Any]`, and `from_public_dict(data: Mapping[str, Any]) -> ExecutableIdentity`. Parsing rejects missing or extra security fields instead of silently defaulting them.

Use `os.stat()` device/inode where meaningful and SHA-256 in 1 MiB chunks. Detect `.cmd`, `.bat`, `.ps1`, `.py`, and shebang wrappers; recursively capture one complete interpreter `ExecutableIdentity` with canonical path, size, mtime, digest, and file id. Reject wrapper cycles and chains deeper than four entries. Wrapper arguments remain tuples and every identity in the chain is validated at spec build, immediately before launch, and immediately after launch. Unsafe policy matching requires the pinned wrapper and interpreter path/digest/size fields to match.

- [ ] **Step 5: Implement the immutable launch spec and builder**

```python
@dataclass(frozen=True)
class RuntimeLaunchSpec:
    runtime_id: str
    protocol_version: int
    executable_identity: ExecutableIdentity
    arguments: tuple[str, ...]
    cwd: str
    permission_mode: str
    timeout_seconds: int
    environment_items: tuple[tuple[str, str], ...]
    trust_level: str
    policy_decision_id: str
    launch_nonce: str

    @property
    def environment(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.environment_items))

    def private_frame(self) -> bytes:
        payload = {
            "runtime_id": self.runtime_id,
            "protocol_version": self.protocol_version,
            "executable_identity": self.executable_identity.to_public_dict(),
            "arguments": list(self.arguments),
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
            "timeout_seconds": self.timeout_seconds,
            "environment_keys": sorted(key for key, _ in self.environment_items),
            "trust_level": self.trust_level,
            "policy_decision_id": self.policy_decision_id,
            "launch_nonce": self.launch_nonce,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def public_metadata(self) -> dict[str, Any]:
        frame = self.private_frame()
        return {
            "runtime_id": self.runtime_id,
            "protocol_version": self.protocol_version,
            "executable_identity": self.executable_identity.to_public_dict(),
            "argument_kinds": classify_argument_kinds(self.arguments),
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
            "timeout_seconds": self.timeout_seconds,
            "environment_keys": sorted(key for key, _ in self.environment_items),
            "trust_level": self.trust_level,
            "policy_decision_id": self.policy_decision_id,
            "launch_nonce": self.launch_nonce,
            "launch_contract_sha256": hashlib.sha256(frame).hexdigest(),
        }


def build_runtime_launch_spec(
    *,
    runtime_candidate: RuntimeExecutableCandidate,
    provider_env: Mapping[str, str],
    model_override: str | None,
    cwd: str | Path,
    workspace_root: str | Path,
    artifact_root: str | Path,
    permission_mode: str,
    timeout_seconds: int,
    arguments: tuple[str, ...],
    policy: RuntimeSecurityPolicy,
    allow_unsafe_runtime: bool,
) -> RuntimeLaunchSpec:
    validated_env = policy.validate_provider_env(provider_env)
    identity = ExecutableIdentity.capture(runtime_candidate.canonical_path)
    decision = authorize_runtime(
        candidate=runtime_candidate,
        identity=identity,
        policy=policy,
        allow_unsafe_runtime=allow_unsafe_runtime,
    )
    return create_launch_spec_from_validated_inputs(
        identity=identity,
        decision=decision,
        provider_env=validated_env,
        model_override=model_override,
        cwd=cwd,
        workspace_root=workspace_root,
        artifact_root=artifact_root,
        permission_mode=permission_mode,
        timeout_seconds=timeout_seconds,
        arguments=arguments,
    )
```

The builder validates environment keys before constructing the run directory, adds only controller-owned UTF-8/workspace variables after provider validation, and never reads `CLAUDE_CODE_BIN` from provider data.

- [ ] **Step 6: Run tests and commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_runtime_security.py -v`

Expected: PASS.

Run: `git add scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/tests/test_runtime_security.py && git commit -m "feat: add immutable runtime launch spec"`

---

### Task 4: Capture and compare cross-platform process identity

**Files:**
- Create: `scripts/cc-orchestrator/process_identity.py`
- Create: `scripts/cc-orchestrator/tests/test_process_identity.py`

- [ ] **Step 1: Write failing live-process tests**

Launch `sys.executable -c "import time; time.sleep(30)"`, capture its identity, and assert:

- PID, creation token, and canonical image path are present;
- the captured identity matches the live process;
- a changed creation token returns `mismatch`;
- a changed executable path returns `mismatch`;
- a missing creation token returns `unverified`;
- an exited process returns `exited`.

Always clean up the test-owned child in `finally` using its original `Popen` handle, not the new termination helper.

- [ ] **Step 2: Run and confirm missing-module failure**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_process_identity.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'process_identity'`.

- [ ] **Step 3: Implement the platform-neutral contract**

```python
@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_token: str | None
    executable_path: str | None
    parent_pid: int | None
    process_group_id: int | None
    launch_nonce: str
    supported: bool
    unsupported_reason: str | None = None

@dataclass(frozen=True)
class ProcessIdentityCheck:
    state: str  # match, exited, mismatch, unverified
    differing_fields: tuple[str, ...] = ()
    live: ProcessIdentity | None = None


def capture_process_identity(pid: int, *, launch_nonce: str) -> ProcessIdentity:
    return platform_reader().capture(pid, launch_nonce=launch_nonce)


def compare_process_identity(expected: ProcessIdentity) -> ProcessIdentityCheck:
    if not expected.supported:
        return ProcessIdentityCheck(state="unverified")
    live = capture_process_identity(expected.pid, launch_nonce=expected.launch_nonce)
    return compare_identity_fields(expected, live)


def process_identity_support() -> dict[str, Any]:
    return platform_reader().support_summary()
```

The complete `ProcessIdentity` methods are `to_dict() -> dict[str, Any]` and `from_dict(data: Mapping[str, Any]) -> ProcessIdentity`. Deserialization validates types, positive PID, nonce presence, and the minimum supported tuple.

- [ ] **Step 4: Implement each operating-system reader conservatively**

- Windows: use `OpenProcess`, `GetProcessTimes`, and `QueryFullProcessImageNameW`; obtain parent PID from a Toolhelp process snapshot. Encode the full creation FILETIME as the stable token and retain the verified process handle for same-process termination where possible.
- Linux: parse `/proc/<pid>/stat` without splitting inside the command name, combine boot id plus start ticks, read PPID/process group/session, and resolve `/proc/<pid>/exe`. Prefer `os.pidfd_open` plus `signal.pidfd_send_signal` when available.
- macOS: use a native high-resolution process start-time API when available; a second-resolution `ps lstart` value is support-reporting evidence, not sufficient destructive-stop evidence.
- Any missing minimum tuple of PID, creation token, and executable path returns `supported=False`; never invent a match.
- Normalize Windows `\\?\` prefixes and case, and normalize Linux deleted-image suffixes for comparison without treating a normal on-disk runtime upgrade as ownership loss.

- [ ] **Step 5: Add launch nonce and parent/group comparison tests**

The nonce is controller evidence and must match recorded metadata. Parent/group fields are compared when both expected and live values are available. A mismatch in either field returns `mismatch`; lack of optional evidence alone does not downgrade a valid minimum tuple.

- [ ] **Step 6: Run tests and commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_process_identity.py -v`

Expected: PASS on the current platform; platform-specific readers are unit-tested with mocked API/subprocess results.

Run: `git add scripts/cc-orchestrator/process_identity.py scripts/cc-orchestrator/tests/test_process_identity.py && git commit -m "feat: verify cross-platform process identity"`

---

### Task 5: Guard one-shot and streaming launch boundaries

**Files:**
- Modify: `scripts/cc-orchestrator/cc_orchestrator.py`
- Create: `scripts/cc-orchestrator/tests/test_guarded_launch.py`

- [ ] **Step 1: Make metadata updates atomic across controller and worker**

Add an artifact lock keyed by run id, write JSON to a same-directory temporary file, flush plus `fsync`, then `os.replace`. Route `write_metadata`, `update_metadata`, event sequence updates, and process identity records through the lock. Add a 100-update controller/worker concurrency test that continuously parses `metadata.json` and proves no identity fields are lost.

- [ ] **Step 2: Add a fake runtime fixture and failing integration tests**

The fixture writes its argv and selected environment key names to stdout but never echoes values. Tests must prove:

- a one-shot launch executes the canonical fake runtime path;
- a streaming launch stores `runtime_launch` public metadata and no secret value;
- one-shot and streaming prompts arrive through stdin and never appear in argv or `prompt.txt`;
- provider `PATH` and provider `CLAUDE_CODE_BIN` fail before the run directory is created;
- changing the fake executable after spec creation yields `runtime_identity_changed` and no runtime output;
- the worker never calls `claude_bin_path()` after metadata is written.
- direct `_stream-worker` calls with missing, forged, reused, or expired nonce fail without launching a child;
- `Popen` failure, broken prompt pipe, identity capture failure, and metadata-lock/write failure leave no worker/child alive and produce one deterministic blocked terminal state.

Patch the resolver and cost guard, not `subprocess.Popen`, for successful integration tests.

- [ ] **Step 3: Run tests and observe the current redirect/re-resolution failures**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_guarded_launch.py -v`

Expected: FAIL because `build_worker_env` accepts control keys and `stream_worker` re-resolves the executable.

- [ ] **Step 4: Add shared policy/runtime resolution helpers**

In `cc_orchestrator.py`, add:

```python
RUNTIME_SECURITY_POLICY_PATH = CONFIG_DIR / "runtime_security.override.json"


def load_runtime_security_policy() -> RuntimeSecurityPolicy:
    if not RUNTIME_SECURITY_POLICY_PATH.exists():
        return RuntimeSecurityPolicy.default()
    return RuntimeSecurityPolicy.load(RUNTIME_SECURITY_POLICY_PATH)


def resolve_runtime_candidate(
    policy: RuntimeSecurityPolicy,
) -> RuntimeExecutableCandidate:
    if policy.configured_runtime_path() is not None:
        return local_configured_candidate(policy.configured_runtime_path())
    return discover_claude_candidate(ignore_environment_override=True)
```

`discover_claude_candidate(ignore_environment_override=True)` keeps the existing platform candidate order but returns the selected path together with its source and trust class; it does not treat `CLAUDE_CODE_BIN` as automatically trusted. Existing local `CLAUDE_CODE_BIN` users receive an actionable migration error directing them to pin the executable in `runtime_security.override.json`; provider-supplied `CLAUDE_CODE_BIN` remains an absolute-deny error.

Only resolved candidates in recognized Claude Code install layouts are eligible for `trusted_default`: the existing WorkBuddy package layout, the official user-local Claude binary layout, and the `@anthropic-ai/claude-code` package binary layout. A bare PATH hit outside those layouts is `discovered_unpinned` and enters double authorization. Identity failure never falls through to a second candidate.

Wrapper launch chains are explicit. `.cmd`/`.bat` use an absolute verified `cmd.exe`; `.ps1` uses an absolute verified PowerShell host; Python scripts use an absolute verified Python interpreter; POSIX shebangs using `/usr/bin/env name` are rewritten to the currently resolved absolute verified interpreter. Public identity metadata records both wrapper and interpreter identities, and live process comparison expects the interpreter image for wrapper launches.

Keep `build_worker_env` as a compatibility wrapper, but route it through `RuntimeSecurityPolicy.validate_provider_env`; add explicit keyword-only `allow_unsafe_runtime=False` only to public launch functions, not to provider env validation.

Introduce a frozen in-memory `PreparedWorkerLaunch` containing the launch spec, raw prompt bytes, safe route metadata, and expected number of child launches. `prepare_worker_launch` performs every policy/identity check without creating artifacts. `start_prepared_worker_launch` is the only function allowed to create a run directory and start a worker. Follow-up and team paths use this two-phase API.

- [ ] **Step 5: Change `run_agent` to build before creating artifacts**

Update the signature:

```python
def run_agent(task: str, role: str = "implementation",
              task_type: str | None = None, profile: str | None = None,
              allow_write: bool = False, timeout_seconds: int | None = None,
              cwd: Path | None = None, context: str | None = None,
              output_format: str = "json",
              allow_unsafe_runtime: bool = False) -> dict[str, Any]:
```

Build `RuntimeLaunchSpec` immediately after route, timeout, prompt length/token estimate, and cwd calculation but before `run_dir.mkdir`. Send the original prompt, not the regex-redacted copy, and do not persist it. Replace `subprocess.run` with `Popen` plus `communicate(input=prompt, timeout=...)` so the prompt travels through stdin and the child identity can be captured after start. The child command uses `-p` without a prompt argument. Revalidate the executable immediately before `Popen` and immediately after identity capture. Persist:

```python
metadata["runtime_launch"] = launch_spec.public_metadata()
metadata["child_process_identity"] = child_identity.to_dict()
```

On post-start identity failure, terminate only through the still-owned `Popen` handle, record `blocked_runtime_identity`, and emit the security error.

- [ ] **Step 6: Change streaming controller and worker to consume one approved path**

Update the signature:

```python
def run_streaming_agent(task: str, role: str = "implementation",
                        task_type: str | None = None, profile: str | None = None,
                        model_override: str | None = None,
                        allow_write: bool = False,
                        timeout_seconds: int | None = None,
                        cwd: Path | None = None, context: str | None = None,
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
                        allow_unsafe_runtime: bool = False) -> dict[str, Any]:
```

Required sequence:

1. Build the launch spec before `run_dir.mkdir`.
2. Persist only `launch_spec.public_metadata()`.
3. Start the internal Python worker with absolute `sys.executable`, `-I -B`, the validated environment, and `stdin=PIPE`; explicitly insert only the trusted orchestrator directory before importing sibling security modules.
4. Write an 8-byte network-order frame length, `RuntimeLaunchSpec.private_frame()`, an 8-byte prompt length, and the original prompt bytes to worker stdin, then close the controller end. Cap the frame at 64 KiB and prompt at 1 MiB. Do not write either payload to an artifact or environment.
5. Capture and persist `worker_process_identity` using the launch nonce; pass the same controller-owned nonce in metadata and a reserved worker environment key.
6. In `stream_worker`, read the bounded private frame and prompt once from stdin; compare protocol version, nonce, one-time consumption state, and `launch_contract_sha256` against public metadata; then revalidate the wrapper/interpreter identity chain and invoke the exact command vector from the frame.
7. Start the runtime with prompt input through its stdin, capture `child_process_identity`, and revalidate the executable again.

If worker identity capture is unsupported, terminate the not-yet-detached worker through its owned `Popen` handle and return `process_identity_unverified`. If child identity capture is unsupported, the worker terminates its directly owned child and reports the same blocked state. No unsupported background process is left running.

The worker atomically marks a nonce consumed before child launch. A repeated internal-worker invocation for the same run returns `runtime_not_trusted` and cannot replay the prompt or start another child.

Remove the `claude_bin_path()` call at the current worker launch site. Output-budget and timeout termination must initially use a directly owned `Popen` handle; Task 7 will route metadata-driven signals through identity checks.

- [ ] **Step 7: Add blocked launch state and acceptance semantics**

`local_unsafe` runs set `acceptance_status="pending_controller_review"`. Identity changes set `status="blocked_runtime_identity"`, `exit_code=None`, and a structured security error. Safe launches preserve existing status behavior.

- [ ] **Step 8: Run focused and regression tests, then commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_runtime_security.py scripts/cc-orchestrator/tests/test_process_identity.py scripts/cc-orchestrator/tests/test_guarded_launch.py -v`

Run: `python scripts/cc-orchestrator/cc_orchestrator.py selftest`

Expected: all unit tests PASS and selftest returns `"ok": true`.

Run: `git add scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/tests/test_guarded_launch.py && git commit -m "feat: guard one-shot and streaming launches"`

---

### Task 6: Propagate authorization through every public launch path

**Files:**
- Modify: `scripts/cc-orchestrator/cc_orchestrator.py`
- Modify: `scripts/cc-orchestrator/server.py`
- Create: `scripts/cc-orchestrator/secure_payload_store.py`
- Modify: `scripts/cc-orchestrator/tests/test_guarded_launch.py`
- Create: `scripts/cc-orchestrator/tests/test_public_surfaces.py`
- Create: `scripts/cc-orchestrator/tests/test_secure_payload_store.py`

- [ ] **Step 1: Write failing call-graph tests**

Patch `run_streaming_agent` with an autospecced recorder and prove the exact `allow_unsafe_runtime` value reaches it from:

- `send_instruction`;
- `spawn_role_team` and rollback launches;
- `cross_review`;
- `benchmark_model` and `benchmark_suite`;
- `queue_submit` one-time grant plus `queue_tick` consumption;
- future real workflow node launch while the currently disabled real path preserves its compatibility error;
- MCP one-shot, streaming, visible, queue, team, follow-up, and workflow tools;
- CLI `run`, `run-streaming`, `run-visible`, `send-instruction`, `spawn-role-team`, `cross-review`, `benchmark-model`, `benchmark-suite`, `queue-submit`, and `workflow-run`.

Mock workflow mode does not launch and must accept but not consume the flag.
`mock-stream-test` must use an explicit test-only prepared runtime fixture and has a regression test proving its override cannot be reached from production CLI/MCP launch requests.

- [ ] **Step 2: Run and confirm rejected/missing argument failures**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_public_surfaces.py -v`

Expected: FAIL because public models, parser flags, and downstream signatures do not yet expose `allow_unsafe_runtime`.

- [ ] **Step 3: Add the request field to launch-capable Python APIs**

Add a final `allow_unsafe_runtime: bool = False` parameter to `send_instruction`, `spawn_role_team`, `cross_review`, `benchmark_model`, `benchmark_suite`, `queue_submit`, `run_visible_agent`, and `workflow_run`. Preserve every existing parameter and default before the new field so positional compatibility is unchanged.

Follow-up launches do not inherit unsafe approval from old metadata: prepare and authorize the new launch first, then stop the old run only after preflight succeeds. Team/cross-review calls prepare every member launch before starting the first child, preventing partial launch on policy failure.

Queue jobs never persist a reusable boolean. When an unsafe queue submission is approved, persist an `UnsafeRuntimeGrant` containing `job_id`, executable identity digest, policy decision id, expiry, `max_uses=1`, and a random grant id. `queue_tick` atomically consumes the grant and revalidates current policy plus executable identity before launch. Unsafe automatic retries are disabled and require a new submission/grant; safe jobs retain current retry behavior.

Use multiprocess tests for two simultaneous `queue_tick` calls and assert one grant consumption, one run id, and one runtime start. Also cover expiry, replay, copying a grant to another job, tampering with `job_id`, executable/policy drift, a crash after consumption, and proof that retry cannot recover or reuse a consumed grant.

- [ ] **Step 4: Move deferred prompts into an OS-protected payload store**

Create this interface:

```python
class SecurePayloadStore(ABC):
    @abstractmethod
    def put(self, *, payload_id: str, value: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def get(self, reference: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def delete(self, reference: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def health(self) -> dict[str, Any]:
        raise NotImplementedError
```

The production factory uses Windows DPAPI through `CryptProtectData`/`CryptUnprotectData`, macOS Keychain native APIs, and Linux Secret Service through `secret-tool` with secret bytes on stdin, never argv. If the native protected store is unavailable, `queue_submit` returns `secure_payload_store_unavailable` and writes no plaintext fallback. Tests inject an in-memory implementation and mocked native API results.

`queue.json` stores only an opaque reference, task/context lengths, timestamps, route fields, and the optional one-time runtime grant. `queue_tick` retrieves the payload immediately before preparation and deletes it after terminal completion/cancellation. Queue responses, team manifests, workflow state, follow-up metadata, and run metadata contain no task/context text. Legacy plaintext queue jobs are reported `blocked_legacy_payload`; an explicit migration transaction moves them into the protected store and atomically scrubs plaintext only after retrieval verification.

Add byte-for-byte scans over queue, team, workflow, run, report, dashboard, launcher, CLI/MCP output, and audit artifacts using short arbitrary fixture secrets that do not match token regexes.

- [ ] **Step 5: Replace the visible launcher with a guarded internal worker**

Add `_visible-worker --run-id` to the internal CLI. `run_visible_agent` builds the same launch spec before artifact creation and starts the internal worker directly with `CREATE_NEW_CONSOLE`, absolute `sys.executable`, and isolated mode:

```text
<absolute-python> -I -B <absolute-cc_orchestrator.py> _visible-worker --run-id <safe-run-id>
```

The helper inherits the validated environment, verifies the launch nonce, reads the initial prompt once from its anonymous stdin pipe, revalidates executable identity, launches the approved absolute runtime, and records helper/runtime identities. On Windows it reopens `CONIN$` after consuming the controller pipe and proxies console input to the runtime so takeover remains interactive. No PowerShell launcher or `prompt.txt` is persisted. Test `CREATE_NEW_CONSOLE`, pipe closure, `CONIN$` forwarding, and direct `_visible-worker` missing/forged/expired/consumed/replayed nonce rejection. On platforms without a tested visible-console implementation, complete security preflight and then return a structured `visible_runtime_unsupported` error with no run artifact; never fall back to PATH or a shell.

- [ ] **Step 6: Add MCP model fields and structured error forwarding**

Add this field to `RunAgentInput`, `QueueSubmitInput`, `SpawnRoleTeamInput`, `SendInstructionInput`, `CrossReviewInput`, `BenchmarkModelInput`, `BenchmarkSuiteInput`, and `WorkflowRunInput`:

```python
allow_unsafe_runtime: bool = Field(
    default=False,
    description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.",
)
```

Forward it explicitly at every call. Update `_error`:

```python
def _error(exc: Exception) -> str:
    if isinstance(exc, RuntimeSecurityError):
        return _json({
            "ok": False,
            "error": exc.message,
            "security_error": exc.to_dict(),
            "next_step": exc.suggested_action,
        })
    return _json({"ok": False, "error": str(exc), "next_step": "Check cc_healthcheck and profile names, then retry."})
```

- [ ] **Step 7: Add CLI flags and forwarding**

Each launch-capable parser, including benchmark commands, gets:

```python
parser.add_argument(
    "--allow-unsafe-runtime",
    action="store_true",
    help="Approve a custom runtime already pinned in runtime_security.override.json for this request only.",
)
```

Add an AST-based test that discovers direct calls to `run_agent`, `run_streaming_agent`, and `run_visible_agent` outside definitions/tests and fails if a launch-capable public caller omits the named argument.

Add wrapper fixtures for Windows `.cmd`, `.bat`, and `.ps1`, plus POSIX direct shebang and `/usr/bin/env` shebang. Replace the interpreter after spec creation and assert launch is blocked; for successful wrappers assert the recorded live image is the verified interpreter, not the wrapper filename.

The real workflow path remains disabled in this release and keeps its existing stable error. Mock workflow proves zero runtime builder and zero process calls. The shared builder requirement applies when real node execution is enabled in a later release and is enforced now by a source-level guard around the only future node-launch hook.

- [ ] **Step 8: Run surface tests and commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_public_surfaces.py scripts/cc-orchestrator/tests/test_secure_payload_store.py scripts/cc-orchestrator/tests/test_guarded_launch.py -v`

Expected: PASS.

Run: `git add scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/server.py scripts/cc-orchestrator/secure_payload_store.py scripts/cc-orchestrator/tests && git commit -m "feat: propagate guarded runtime authorization"`

---

### Task 7: Require identity evidence for status and every signal path

**Files:**
- Modify: `scripts/cc-orchestrator/cc_orchestrator.py`
- Modify: `scripts/cc-orchestrator/tests/test_process_identity.py`
- Modify: `scripts/cc-orchestrator/tests/test_guarded_launch.py`

- [ ] **Step 1: Write failing no-signal tests**

Mock the OS signal/taskkill layer and assert zero calls for:

- reused PID with changed creation token;
- matching PID with changed executable image path;
- missing/unsupported identity evidence;
- legacy metadata containing only `worker_pid`/`child_pid`;
- `force=True` with any non-match state;
- queue timeout, output-budget stop, workflow stop, and team rollback with mismatched identity.

Add exact-match positive tests for graceful child-before-worker termination, force escalation after the grace period, process-group/tree scope, repeated stop, and a process that exits between verification and signal. Simulate PID reuse in that last interval and assert the replacement receives no signal.

Add an AST/source audit test that fails when `os.kill`, `os.killpg`, `Popen.terminate`, `Popen.kill`, `Popen.send_signal`, `taskkill`, Windows `TerminateProcess`/Job termination, or pidfd signaling appears outside the reviewed owned-handle cleanup and unified identity-verified termination helpers.

- [ ] **Step 2: Run and confirm current PID-only termination failures**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_process_identity.py scripts/cc-orchestrator/tests/test_guarded_launch.py -v`

Expected: FAIL because `terminate_process_tree` currently accepts a PID alone.

- [ ] **Step 3: Change the termination signature and fail closed**

```python
def terminate_process_tree(
    expected_identity: ProcessIdentity,
    *,
    force: bool = False,
    wait_seconds: int = 5,
) -> dict[str, Any]:
    if sys.platform != "win32":
        return {
            "pid": expected_identity.pid,
            "attempted": False,
            "alive": True,
            "identity_state": "unverified",
            "differing_fields": ["process_tree_containment"],
        }
    capability = open_stable_process_capability(expected_identity)
    if capability.state != "match":
        return {
            "pid": expected_identity.pid,
            "attempted": False,
            "alive": capability.state != "exited",
            "identity_state": capability.state,
            "differing_fields": list(capability.differing_fields),
        }
    return capability.terminate(force=force, wait_seconds=wait_seconds)
```

Do not retain a public overload that accepts an integer PID. `open_stable_process_capability` can represent a Windows process handle whose creation/image evidence was queried from that same handle or a Linux pidfd opened before identity comparison, but a Linux pidfd proves only one process and therefore cannot authorize process-tree termination. Every POSIX platform returns `unverified` for controller-originated emergency tree termination. `taskkill`, controller-side `kill(pid)`, and controller-side `killpg` are removed.

Normal background stop is cooperative and capability-oriented: the controller writes a nonce-bound stop request, and the still-running worker uses its owned `Popen` handle plus the Windows Job Object to stop the child tree. Windows workers assign the runtime to a Job Object with kill-on-worker-close. Review established that Linux parent-death signals and process groups do not contain escaped or orphaned descendants, so production POSIX launch fails closed until a cgroup-v2 `cgroup.kill` guardian or equivalent kernel-enforced whole-tree backend is available. The built-in fake runtime retains a test-only process-group path. If cooperative stop fails, emergency termination targets only the verified Windows worker capability; unsupported platforms fail closed and report the containment repair action.

- [ ] **Step 4: Make status identity-aware**

`single_run_status` reports separate worker/child identity states. A live exact match is active and verified; a live mismatched or unverified PID is conservatively counted as active for concurrency limits but never as owned. Already-exited processes preserve existing final status inference. `run_dir_active`, cleanup, archive, queue, and workflow aggregation consume this same four-state result.

- [ ] **Step 5: Guard explicit and indirect stops**

Update `stop_run`, streaming timeout/output budget, queue timeout/cancel, workflow stop, team rollback, and follow-up pre-stop to verify the worker identity, write a nonce-bound cooperative request, and let the worker terminate its owned child tree. Only the Windows stable-capability emergency helper may signal from the controller, and only because the worker tree is Job-contained. POSIX cooperative timeout returns `cleanup_incomplete` without signaling a single PID. Identity mismatch emits `process_identity_mismatch`; missing capability/evidence emits `process_identity_unverified`. Verify identity before writing `stop-requested.json` or changing status to `stop_requested`. A failed stop blocks a follow-up restart unless the previous process is proven exited, and aggregate operations do not mark a node/team/job cancelled when any required stop is unverified.

- [ ] **Step 6: Add harmless real PID-reuse simulation**

Create metadata that points at a live test-owned sleeper PID but records a different creation token. Call `stop_run(force=True)`, assert `identity_mismatch`, then assert the sleeper is still alive before cleaning it up through its own `Popen` handle.

Run metadata/status/stop concurrency tests in separate spawned processes on every OS, not threads. Use the `spawn` multiprocessing context even on POSIX for the shared baseline; add a POSIX fork variant where supported.

- [ ] **Step 7: Run tests and commit**

Run: `python -m unittest scripts/cc-orchestrator/tests/test_process_identity.py scripts/cc-orchestrator/tests/test_guarded_launch.py -v`

Expected: PASS and every mismatch case records `attempted=false`.

Run: `git add scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/tests && git commit -m "feat: require process identity before termination"`

---

### Task 8: Add secret-free audit events and operator visibility

**Files:**
- Modify: `scripts/cc-orchestrator/runtime_security.py`
- Modify: `scripts/cc-orchestrator/cc_orchestrator.py`
- Modify: `scripts/cc-orchestrator/server.py`
- Modify: `scripts/cc-orchestrator/tests/test_runtime_security.py`
- Modify: `scripts/cc-orchestrator/tests/test_guarded_launch.py`

- [ ] **Step 1: Write failing audit-schema and secret-scan tests**

For each security error code, generate an event with a fixture API key and assert:

- the event has timestamp, code, severity, run id when known, runtime id, trust level, HMAC-pseudonymized provider id, decision id, safe field names, and recommended action;
- neither the event file nor any run artifact contains the fixture secret or prompt;
- file permissions exclude group/other access on POSIX;
- concurrent appends produce one valid JSON object per line.
- simultaneous first-use key creation in spawned processes produces one valid key and verifiable chain;
- symlink/reparse targets, short non-pattern secrets, and URL userinfo are rejected or sanitized.

- [ ] **Step 2: Implement one append-only audit writer**

```python
def append_security_event(
    *,
    artifact_root: Path,
    code: str,
    severity: str,
    run_id: str | None,
    runtime_id: str | None,
    trust_level: str | None,
    provider_id: str | None,
    policy_decision_id: str | None,
    safe_details: Mapping[str, Any],
    recommended_action: str,
) -> Path:
    event = build_safe_security_event(
        code=code,
        severity=severity,
        run_id=run_id,
        runtime_id=runtime_id,
        trust_level=trust_level,
        provider_id=provider_id,
        policy_decision_id=policy_decision_id,
        safe_details=safe_details,
        recommended_action=recommended_action,
    )
    assert_event_contains_no_secret(event)
    return append_locked_ndjson(
        artifact_root / "logs" / "security-events.ndjson", event
    )
```

Serialize only an explicit allowlist of fields. Pseudonymize provider ids with HMAC-SHA-256 and a locally generated 32-byte audit key stored in `config/runtime_security.audit.key`; never use an unkeyed hash for low-entropy identifiers. Reject symlink/reparse-point log targets, cap each event at 16 KiB, and reject the event before writing when either the serialized payload matches the existing secret regexes or contains any exact provider secret value known to the launch. Use the artifact lock, hash-chain each record to the previous record for local tamper evidence, and create the key, run directories, and log files with current-user-only permissions where supported.

Audit failure policy is explicit: a security rejection remains rejected even when its audit append fails; a `local_unsafe` launch fails closed when its high-severity event cannot be recorded; a trusted-default launch may continue with `audit_degraded=true`, and healthcheck must surface the repair action. The log is tamper-evident within the current user boundary, not a trusted external audit sink.

Inject key creation, lock acquisition, open, append, flush, and permission-setting failures. Assert each rejection stays rejected, unsafe launch never calls `Popen`, trusted-default behavior follows the degraded policy exactly, and a later healthcheck identifies the failed audit component.

- [ ] **Step 3: Emit events at every policy and identity decision boundary**

Emit at least:

- forbidden/unrecognized provider env;
- missing unsafe policy/request approval;
- successful `local_unsafe` authorization;
- pre/post launch executable identity change;
- process identity mismatch/unverified during status or stop.

Security failures before run creation use the cwd-derived artifact root and `run_id=None`.

- [ ] **Step 4: Extend healthcheck and operational reports**

`healthcheck()` adds a `runtime_security` object with canonical default path, configured runtime path when present, trust decision summary, policy path/existence, audit health, protected payload-store health, and process identity support. It may execute `--version` only for the trusted default runtime; a `local_unsafe` runtime is reported without execution. Dashboard/controller reports show counts by event code/severity and identity-unverified runs, never environment values. Every run/team/queue/workflow/report/health metadata builder projects provider base URLs/endpoints through one fixed `scheme://host:port` sanitizer that strips userinfo, paths, query strings, and fragments.

- [ ] **Step 5: Test MCP and CLI security envelopes**

CLI retains its JSON/error exit behavior and includes `security_error`. MCP `_error` returns the same structured object. Add assertions that messages name only safe keys/paths and suggest a concrete action.

Exercise every stable security code, plus `visible_runtime_unsupported`, through direct Python, CLI, and MCP envelopes. Lock exit-code precedence: controller security failures use exit code 2, runtime child failures preserve the child's recorded exit code, and timeouts preserve 124 plus a separate safe stop reason.

- [ ] **Step 6: Run tests and commit**

Run: `python -m unittest discover -s scripts/cc-orchestrator/tests -v`

Run: `python scripts/cc-orchestrator/cc_orchestrator.py healthcheck`

Expected: all tests PASS; healthcheck contains `runtime_security` without secret-like values.

Run: `git add scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/server.py scripts/cc-orchestrator/tests && git commit -m "feat: audit guarded runtime decisions"`

---

### Task 9: Document, version, and enforce the cross-platform release gate

**Files:**
- Modify: `.github/workflows/runtime-checks.yml`
- Modify: `scripts/cc-orchestrator/README.md`
- Modify: `SKILL.md`
- Modify: `version.json`
- Modify: `scripts/cc-orchestrator/version.json`
- Modify: `scripts/cc-orchestrator/cc_orchestrator.py`
- Modify: `install/install.ps1`
- Modify: `install/install.sh`
- Modify: `.gitignore`

- [ ] **Step 1: Extend selftest with security gates**

Add deterministic selftest gates for provider deny families, immutable public metadata, double authorization, and legacy stop refusal. Keep real process/API tests in `unittest`. Confirm `selftest` exits nonzero whenever any gate is false.

- [ ] **Step 2: Expand CI to the required matrix**

Change the OS matrix to:

```yaml
os:
  - ubuntu-latest
  - windows-latest
  - macos-latest
python-version:
  - "3.10"
  - "3.12"
```

Add steps:

```yaml
- name: Compile Python entrypoints and security modules
  run: python -m py_compile scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/server.py scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/process_identity.py scripts/cc-orchestrator/secure_payload_store.py

- name: Run guarded runtime unit and integration tests
  run: python -m unittest discover -s scripts/cc-orchestrator/tests -v

- name: Run orchestrator selftest
  run: python scripts/cc-orchestrator/cc_orchestrator.py selftest
```

Keep action SHAs pinned and add `docs/superpowers/**` and `SKILL.md` to path filters.

- [ ] **Step 3: Document the operator workflow**

Document:

- safe default behavior needs no new config;
- how to calculate a custom runtime path/digest and create `runtime_security.override.json`;
- why each unsafe launch still requires `--allow-unsafe-runtime` or MCP `allow_unsafe_runtime=true`;
- exact recovery for every security error code;
- why legacy/unverified runs cannot be force-stopped by the orchestrator;
- audit log path, fields, retention, degraded/fail-closed behavior, and rollback behavior;
- why immediate prompts are no longer persisted and why unsafe queued retries require a new grant.

Update `SKILL.md` so controllers never auto-set unsafe approval and always surface identity mismatch to the user.

- [ ] **Step 4: Bump release metadata consistently**

Set both version files to `0.8.0`, release date `2026-07-18`, and add guarded-runtime notes. Add `scripts/cc-orchestrator/config/runtime_security.override.json` and `scripts/cc-orchestrator/config/runtime_security.audit.key` to both `local_user_owned_files` arrays and `.gitignore`. Update both installers' copy exclusions and preservation/hash checks for these files. Assert both JSON files are identical and installer tests prove policy/key bytes survive an upgrade unchanged.

- [ ] **Step 5: Create installer preservation tests**

Create `scripts/cc-orchestrator/tests/test_install_preservation.py`. In temporary source/target trees, seed unique policy and audit-key bytes, run the installer preservation/copy logic for PowerShell and shell where the host supports it, and assert content plus SHA-256 are unchanged. On a host that cannot execute one installer, parse its declared preserved-file list and require both paths; CI supplies native execution on Windows and Ubuntu/macOS.

- [ ] **Step 6: Run the complete local release gate**

Run:

```powershell
python -m py_compile scripts/cc-orchestrator/cc_orchestrator.py scripts/cc-orchestrator/server.py scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/process_identity.py scripts/cc-orchestrator/secure_payload_store.py
python -m unittest discover -s scripts/cc-orchestrator/tests -v
python scripts/cc-orchestrator/cc_orchestrator.py selftest
python scripts/cc-orchestrator/cc_orchestrator.py mock-stream-test
python -c "import json, pathlib; a=json.loads(pathlib.Path('version.json').read_text(encoding='utf-8')); b=json.loads(pathlib.Path('scripts/cc-orchestrator/version.json').read_text(encoding='utf-8')); assert a == b"
python -m unittest scripts/cc-orchestrator/tests/test_install_preservation.py -v
npm ci
npm run docs:build
git diff --check
```

Expected:

- compilation succeeds;
- all new unit/integration tests pass;
- selftest returns `"ok": true`;
- mock stream reports all supported process-control gates and explicitly marks unsupported platform gates;
- version assertion succeeds;
- VitePress build succeeds;
- `git diff --check` is silent.

- [ ] **Step 7: Run repository-wide secret and unfinished-marker scans**

Run:

```powershell
rg -n "sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{20,}" . --glob '!node_modules/**' --glob '!.git/**'
$markers = @(('TO' + 'DO'), ('T' + 'BD'), ('FIX' + 'ME'), ('implement ' + 'later')) -join '|'
rg -n $markers scripts/cc-orchestrator/runtime_security.py scripts/cc-orchestrator/process_identity.py scripts/cc-orchestrator/tests
```

Expected: no real secrets and no unfinished implementation markers.

- [ ] **Step 8: Commit, push, and open the fork PR**

Run:

```powershell
git add .github/workflows/runtime-checks.yml scripts/cc-orchestrator/README.md SKILL.md version.json scripts/cc-orchestrator/version.json scripts/cc-orchestrator/cc_orchestrator.py
git commit -m "docs: release guarded runtime launch"
git push fork security/guarded-runtime-launch
gh pr create --repo rfdiosuao/claude-code-orchestrator-skill --base main --head security/guarded-runtime-launch --title "feat: add guarded runtime launch" --body-file .github/PULL_REQUEST_TEMPLATE.md
```

If the repository has no PR template, generate the body in the shell from verified results and pass `--body-file` from an artifact outside the repository. The PR must include the acceptance-criteria checklist, platform matrix links, residual risks, and revert instructions.

---

## Cross-Review Gate

Before merging:

- Requirements reviewer maps every design acceptance criterion to a passing test or documented operational check.
- Security reviewer confirms no integer-PID termination entry point remains and provider values never appear in persisted launch metadata.
- Test reviewer inspects failure-path assertions, especially no-signal behavior, wrapper runtimes, queue retries, and visible launches.
- Architecture reviewer confirms all launch call sites pass through `build_runtime_launch_spec` and resolves any review conflict.
- Operations reviewer confirms CI, audit-log location/permissions, user-owned policy preservation, and revert instructions.

Useful audit commands:

```powershell
rg -n "subprocess\.(run|Popen)\(|os\.kill\(|killpg|taskkill" scripts/cc-orchestrator --glob '*.py'
rg -n "claude_bin_path\(" scripts/cc-orchestrator/cc_orchestrator.py
rg -n "run_agent\(|run_streaming_agent\(|run_visible_agent\(" scripts/cc-orchestrator --glob '*.py'
```

Expected final shape:

- runtime process creation is limited to reviewed helper sites;
- `claude_bin_path()` is resolved by the controller, not the stream/visible worker;
- every metadata-driven signal path requires `ProcessIdentity`;
- every public launch path has an explicit `allow_unsafe_runtime` default of false.
