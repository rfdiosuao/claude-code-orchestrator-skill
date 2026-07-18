# Guarded Runtime Launch Design

Status: Approved for implementation planning
Date: 2026-07-18
Target branch: `security/guarded-runtime-launch`

## Context

The orchestrator currently copies arbitrary CCSwitch provider environment variables into the worker environment, then lets the streaming worker resolve the Claude Code executable again. Run status and stop operations treat a live PID as sufficient process ownership evidence. These behaviors create two related risks:

- provider configuration can influence executable discovery or language runtime behavior;
- stale metadata and PID reuse can cause status or stop operations to target an unrelated process.

The fork will remain compatibility-first. Existing CLI and MCP names, artifact paths, safe CCSwitch profiles, and Codex plus Claude Code behavior must continue to work.

## Goals

- Resolve and validate a runtime executable once before launch.
- Prevent provider environment data from controlling executable discovery, the Python or Node runtime, dynamic library loading, or orchestrator-owned paths.
- Require two independent approvals for a locally configured untrusted runtime.
- Record enough process identity to detect PID reuse and executable replacement.
- Refuse status or stop operations that cannot prove process ownership.
- Emit useful, secret-free security audit events.
- Preserve current behavior for safe CCSwitch profiles and the default Claude Code runtime.

## Non-Goals

- Adding non-Claude worker adapters.
- Renaming existing `cc_*` CLI or MCP operations.
- Replacing CCSwitch provider discovery.
- Building a resident broker or privileged service.
- Sandboxing network, filesystem, or operating-system capabilities.
- Hardening arbitrary MCP verification commands or MCP configuration write paths in this change.

## Design Principles

- Security decisions happen before a worker or child process starts.
- Provider data never selects the executable.
- Secret-bearing launch state stays in memory or the child environment and is never written to artifacts.
- Persisted metadata contains only a safe projection and cryptographic or operating-system identity evidence.
- A force flag may change termination strength, but it may not bypass identity verification.
- Old run metadata remains readable but cannot authorize a destructive process operation.

## Components

### RuntimeSecurityPolicy

`RuntimeSecurityPolicy` classifies provider environment keys and runtime executable configuration.

Provider environment keys have three classes:

1. Allowed provider data: known API, model, endpoint, and proxy variables needed by the supported runtime.
2. Policy-controlled additions: extra non-execution keys explicitly named in the local user policy.
3. Absolute deny: variables that control executable lookup, interpreters, module loading, dynamic libraries, shells, or orchestrator-owned paths.

The absolute-deny class includes exact names and platform-aware prefixes for:

- `PATH`, `Path`, `PATHEXT`, `COMSPEC`, and `SHELL`;
- `CLAUDE_CODE_BIN` when supplied by a provider profile;
- `PYTHONPATH`, `PYTHONHOME`, `NODE_OPTIONS`, and `NODE_PATH`;
- `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `DYLD_*`;
- `CC_ORCHESTRATOR_*`.

Provider data cannot override absolute-deny keys, even through the unsafe-runtime authorization path. A custom runtime executable is configured through the local runtime policy instead of provider environment data.

The user-owned policy file is `scripts/cc-orchestrator/config/runtime_security.override.json`. It is added to `local_user_owned_files` so upgrades and synchronization preserve it. The repository ships only an example file.

### Double Authorization

An executable outside the automatically trusted default Claude Code path requires both:

- a matching local policy entry containing the canonical executable path and expected file identity; and
- an explicit `allow_unsafe_runtime` value on the individual CLI or MCP request.

Either approval alone is insufficient. Successful use of this path sets the run trust level to `local_unsafe`, emits a high-severity security event, and leaves acceptance pending controller review.

### RuntimeLaunchSpec

`RuntimeLaunchSpec` is an immutable in-memory value created after route selection and before run creation. It contains:

- runtime id and protocol version;
- canonical executable path;
- executable identity;
- command arguments without prompt or secret values in its public projection;
- canonical working directory;
- permission mode and timeout;
- validated environment;
- trust level and policy decision id;
- a random launch nonce.

Immutability is deep: arguments and environment entries are stored as immutable tuples or read-only mappings, not mutable lists or dictionaries held by a frozen outer object.

The controller writes only `RuntimeLaunchSpec.public_metadata()` to `metadata.json`. The safe projection includes environment key names but no environment values, prompt, API key, authorization header, or complete secret-bearing argument list.

The streaming worker receives the canonical executable path and expected identity from metadata, receives validated secret values through its inherited environment, revalidates the executable immediately before `Popen`, and launches the absolute path. It does not call `claude_bin_path()` again.

### ExecutableIdentity

`ExecutableIdentity` records:

- canonical path with symlinks resolved;
- platform file identity when available;
- file size and nanosecond modification time;
- SHA-256 digest of the launch target;
- whether the target is a native executable or a script wrapper.

The identity is checked when the launch spec is built, immediately before child launch, and immediately after child start. A mismatch stops the new child if ownership is proven, marks the run `blocked_runtime_identity`, and emits `runtime_identity_changed`.

### ProcessIdentity

Each worker and child process gets a `ProcessIdentity` record:

- PID;
- process creation time;
- canonical executable path;
- parent PID;
- process group or session identity where available;
- executable file identity where available;
- launch nonce association.

Stop verification compares stable live-process evidence: PID, creation time, executable image path, parent relationship, and process group or session where supported. It does not require the executable file currently on disk to retain the launch-time digest, because an installed runtime may be upgraded while an older process is still running. Launch-time file identity remains audit evidence and protects the launch boundary.

Platform implementations use:

- Windows process query APIs for creation time and image path;
- Linux `/proc/<pid>/stat`, `/proc/<pid>/exe`, and process group data;
- macOS `ps` or native process APIs for start time, executable path, parent, and process group.

If a platform cannot collect the minimum identity tuple of PID, creation time, and executable path, the process may run but destructive stop operations are unavailable for that process. This unsupported state is explicit in metadata and reports.

## Launch Flow

1. Resolve the route and provider.
2. Classify provider environment keys.
3. Reject absolute-deny or unknown keys before creating a run directory.
4. Resolve the default or locally configured runtime executable to a canonical absolute path.
5. Evaluate trusted-path or double-authorization requirements.
6. Capture `ExecutableIdentity` and build immutable `RuntimeLaunchSpec`.
7. Create the run directory and write only public launch metadata.
8. Start the internal stream worker with the validated environment.
9. Revalidate the runtime identity in the stream worker.
10. Launch the child by absolute path and capture both process identities.
11. Use the recorded identities for status, poll, timeout, output-budget termination, and explicit stop.

One-shot, streaming, visible-window, follow-up, queue, team, and workflow launches all use the same policy and launch-spec builder. No public launch path may bypass it.

Visible-window launcher scripts contain no provider environment values. The visible helper inherits the already validated environment and receives only safe run identifiers and canonical paths in persisted launcher artifacts.

## Stop Flow

`stop_run` loads the recorded worker and child identities and compares them with live process evidence.

- Exact match: terminate the child tree, then the worker if needed.
- Process already exited: return `already_finished` without signaling any PID.
- PID exists but identity differs: return `identity_mismatch`, emit a critical security event, and do not signal it.
- Identity evidence is missing or unsupported: return `identity_unverified` and do not signal it.
- `force=true`: use stronger termination only after an exact identity match.

Legacy runs without `ProcessIdentity` remain readable and reportable. They cannot authorize `stop_run` or rollback behavior that sends process signals.

## Error Contract

Security failures return structured error data with a stable code, message, safe details, and suggested action. Initial codes are:

- `provider_env_forbidden`
- `provider_env_unrecognized`
- `runtime_not_trusted`
- `unsafe_runtime_policy_missing`
- `unsafe_runtime_request_missing`
- `runtime_identity_changed`
- `process_identity_mismatch`
- `process_identity_unverified`

Errors identify variable names or paths when safe, never their values. CLI and MCP surfaces preserve their current response envelopes and include the structured security error inside them.

## Security Audit Events

Append-only, secret-free events are written to `<artifact_root>/logs/security-events.ndjson`. Each event includes:

- timestamp and event code;
- severity;
- run id when one exists;
- runtime id and trust level;
- hashed provider id;
- rejected environment key names or identity mismatch fields;
- policy decision id;
- recommended controller action.

Event serialization passes through existing redaction and a dedicated assertion that rejects values matching known secret patterns. File permissions are restricted to the current user where the platform supports it.

## Integration Points

The implementation changes are intentionally centered in the current Python runtime module:

- `build_worker_env` becomes policy-driven and rejects provider control keys.
- `run_agent`, `run_streaming_agent`, and `run_visible_agent` build a launch spec.
- `stream_worker` consumes the absolute executable and expected identity.
- follow-up, queue, team, and workflow paths pass through the same launch APIs.
- `single_run_status` reports identity state instead of PID liveness alone.
- `terminate_process_tree` requires an expected identity.
- `stop_run` refuses unverified or mismatched processes.
- CLI and MCP launch inputs gain `allow_unsafe_runtime`, defaulting to false.
- healthcheck reports runtime path, trust level, and process-identity support without exposing secrets.

New code may be placed in a focused `runtime_security.py` module to avoid further growth of `cc_orchestrator.py`. The orchestration module remains the integration layer; policy parsing and platform identity collection remain independently testable.

## Compatibility

- Default Claude Code discovery remains supported, but its resolved absolute path is frozen per launch.
- Known safe Anthropic and proxy provider variables continue to work.
- Existing command and MCP names do not change.
- Existing metadata fields remain; new runtime security fields are additive.
- Safe profiles require no new flag or policy file.
- Unsafe provider execution controls that previously happened to work now fail with actionable security errors.
- Existing runs remain visible but destructive stop is disabled when ownership cannot be proven.

## Testing

### Unit Tests

- classify allowed, policy-controlled, unknown, and absolute-deny environment keys;
- reject provider attempts to set every execution-control variable family;
- preserve API credentials without writing their values to metadata or audit events;
- prove `RuntimeLaunchSpec` immutability;
- accept a trusted default executable;
- require both authorization factors for an untrusted executable;
- reject changed executable identity before and after launch;
- compare matching, exited, mismatched, and unverified process identities;
- verify security error and audit schemas.

### Integration Tests

- launch a fake runtime only by canonical absolute path;
- prove PATH and `CLAUDE_CODE_BIN` provider injection cannot redirect the child;
- modify the fake executable after launch-spec creation and verify launch is blocked;
- simulate PID reuse with a harmless unrelated process and verify no signal is sent;
- verify one-shot, streaming, visible, follow-up, queue, team, and mock workflow paths use the shared launch policy;
- run stop and output-budget termination through identity verification;
- scan all produced artifacts for fixture secrets.

### Compatibility and CI

- retain all existing selftest gates;
- run on Python 3.10 and 3.12;
- run on Windows, Ubuntu, and macOS;
- compile both Python entry points;
- build documentation;
- run the fake streaming pressure test where platform process controls are available;
- fail CI when selftest returns `ok=false` or a secret appears in generated artifacts.

## Rollout

The feature is developed on `security/guarded-runtime-launch` and merged into the fork's `main` through an internal pull request after all platform jobs pass.

No data migration rewrites existing runs. New fields are additive. The local runtime security override is user-owned and preserved by upgrades. Rollback is a revert pull request; local policy files and historical artifacts are not deleted.

The fork continues to track the upstream repository as a read-only remote. Upstream changes are reviewed and merged into the fork deliberately, with runtime-security tests acting as the compatibility gate.

## Acceptance Criteria

- Every public worker launch path uses `RuntimeLaunchSpec`.
- Provider profiles cannot control executable discovery, language runtime loading, dynamic libraries, shells, or orchestrator-owned paths.
- A non-default untrusted runtime requires both local policy approval and per-request approval.
- The worker launches the exact executable identity approved by the controller.
- Status and stop detect PID reuse and executable mismatch.
- No identity mismatch or unverified identity test sends a termination signal.
- Force stop cannot bypass identity verification.
- Metadata and security events contain no provider secret values or prompt contents.
- Safe existing profiles and all existing selftest behavior remain compatible.
- Windows, Ubuntu, and macOS CI pass on Python 3.10 and 3.12.

## Residual Risks

- Portable process introspection differs by operating system and may require conservative unsupported states.
- Script-wrapper runtimes add an interpreter identity that must be recorded in addition to the wrapper file.
- Executable identity checks reduce but do not fully eliminate every platform-specific time-of-check/time-of-use race.
- A local user who can modify both policy and executable files remains inside the trusted local boundary.
- This design does not sandbox an otherwise trusted runtime's network or filesystem behavior.
