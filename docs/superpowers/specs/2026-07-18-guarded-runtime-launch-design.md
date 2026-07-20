# Guarded Runtime Launch Design

Status: Approved; amended after requirements, architecture, security, and test cross-review
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
- Prompt text is sent through anonymous stdin pipes, not command arguments, environment variables, or `prompt.txt` artifacts.
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

The absolute-deny class also covers shell startup/module hooks, PowerShell/.NET startup hooks, Java/Ruby/Perl runtime options, Git configuration/SSH command injection, and TLS key logging. Validation rejects case-folded duplicate names, NUL bytes, oversized values, and oversized environment blocks. Unknown keys remain denied unless the local policy names them, and an absolute-deny key can never be locally allowlisted.

Provider data cannot override absolute-deny keys, even through the unsafe-runtime authorization path. A custom runtime executable is configured through the local runtime policy instead of provider environment data.

Trusted-default discovery ignores ambient `CLAUDE_CODE_BIN` and accepts only canonical candidates in recognized Claude Code installation layouts already supported by the project. An arbitrary PATH hit is classified as unpinned and requires double authorization. Identity failure never falls through to another candidate.

The user-owned policy file is `scripts/cc-orchestrator/config/runtime_security.override.json`. It is added to `local_user_owned_files` so upgrades and synchronization preserve it. The repository ships only an example file.

### Double Authorization

An executable outside the automatically trusted default Claude Code path requires both:

- a matching local policy entry containing the canonical executable path and expected file identity; and
- an explicit `allow_unsafe_runtime` value on the individual CLI or MCP request.

Either approval alone is insufficient. These are two confirmation channels within the same local-user trust boundary, not independent security principals. Successful use of this path sets the run trust level to `local_unsafe`, emits a high-severity security event, and leaves acceptance pending controller review.

Deferred queue approval is represented by a single-use grant bound to job id, executable identity, policy decision, and expiry. It is consumed atomically at launch and cannot authorize an automatic retry. Follow-ups require a new request approval. Team approval is scoped to the prepared members of that one parent request.

### Secure Deferred Payloads

Immediate task/context text is never persisted by the orchestrator. Team, workflow, run, follow-up, report, and dashboard artifacts retain only safe lengths, route metadata, and status evidence.

Queue execution requires deferred payload storage. Queue task/context bytes are placed in an OS-protected current-user store: Windows DPAPI, native macOS Keychain, or Linux Secret Service. Queue metadata contains only an opaque reference. Secrets are supplied to native stores through memory/stdin, never command arguments. When no protected backend is available, queue submission fails closed with `secure_payload_store_unavailable`; there is no plaintext fallback. Legacy plaintext queue records are blocked until an explicit transactional migration verifies protected retrieval and then scrubs the old fields.

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

A frozen `PreparedWorkerLaunch` combines the launch spec with raw prompt bytes and safe route metadata only in memory. Preparation performs all policy and executable checks without creating artifacts; starting a prepared launch is the only operation that creates a run directory. Follow-up prepares the replacement before stopping the old run, and team launches prepare all members before starting the first worker.

The streaming worker receives the canonical executable path and expected identity from metadata, receives validated secret values through its inherited environment, revalidates the executable immediately before `Popen`, and launches the absolute path. It does not call `claude_bin_path()` again.

The controller starts internal workers with an absolute Python path and isolated mode and associates the request with a controller-owned launch nonce. One anonymous stdin protocol carries a bounded, length-prefixed private launch frame followed by bounded prompt bytes. The private frame contains the exact approved wrapper/interpreter command chain and non-secret arguments; public metadata stores only argument kinds and the frame digest. The worker verifies protocol version, nonce, one-time consumption, frame digest, and executable identities before launch. Metadata stores prompt length/token estimates when needed, never plaintext prompt or an unkeyed prompt digest. Controller/worker metadata updates use a cross-process lock and atomic replacement.

### ExecutableIdentity

`ExecutableIdentity` records:

- canonical path with symlinks resolved;
- platform file identity when available;
- file size and nanosecond modification time;
- SHA-256 digest of the launch target;
- whether the target is a native executable or a script wrapper.

For wrappers, identity covers both the wrapper and the absolute interpreter actually launched. Windows batch and PowerShell wrappers use verified absolute hosts; POSIX `/usr/bin/env name` shebangs are resolved once to an absolute verified interpreter. Live process identity expects that interpreter image rather than incorrectly comparing it to the wrapper path.

The identity is checked when the launch spec is built, immediately before child launch, and immediately after child start. The shared operation deadline is also checked directly before each `Popen`, after containment publication, and before resuming a suspended Windows child; crossing the deadline cleans the newly owned child and records an explicit timeout. A mismatch stops the new child if ownership is proven, marks the run `blocked_runtime_identity`, and emits `runtime_identity_changed`.

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

If a platform cannot collect the minimum identity tuple of PID, creation time, and executable path, background, visible, queued, team, workflow, and `local_unsafe` launches fail closed. A trusted foreground one-shot launch may proceed because the controller retains the non-reusable `Popen` handle and performs timeout cleanup through that handle. Unsupported states remain explicit in healthcheck and reports.

## Launch Flow

1. Resolve the route and provider.
2. Classify provider environment keys.
3. Reject absolute-deny or unknown keys before creating a run directory.
4. Resolve the default or locally configured runtime executable to a canonical absolute path.
5. Evaluate trusted-path or double-authorization requirements.
6. Capture `ExecutableIdentity` and build immutable `RuntimeLaunchSpec`.
7. Create the run directory with current-user-only permissions and write only public launch metadata.
8. Start the internal stream or visible worker with the validated environment and a prompt stdin pipe.
9. Revalidate nonce and runtime identity in the worker.
10. Launch the child by absolute path, send the prompt through stdin, and capture both process identities.
11. Use owned handles where available and recorded identities for status, poll, timeout, output-budget termination, and explicit stop.

One-shot, streaming, visible-window, follow-up, queue, team, and workflow launches all use the same policy and launch-spec builder. No public launch path may bypass it. Team authorization is a one-way commit: once the authorized manifest is visible, a later fsync or controller error reports `commit_indeterminate` without rolling workers back. Pre-commit readiness timeout returns the common timeout envelope with exit code 124, starts all member terminations concurrently within their durable grace, waits for controller cleanup owners to quiesce, and only reports rollback success when whole-tree cleanup and root-process exit are both confirmed before the final lock sweep.

The Windows visible helper is the absolute isolated Python worker itself, started with `CREATE_NEW_CONSOLE`. It consumes the controller prompt pipe, reopens the console input for takeover, launches the approved runtime, and records helper/runtime identities. No PowerShell launcher is persisted. Unsupported visible-console platforms return a structured error after security preflight and never fall back to shell or PATH lookup.

## Stop Flow

`stop_run` loads the recorded worker and child identities and compares them with live process evidence.

- Exact match: send the nonce-bound cooperative request. On Windows, a cooperative timeout may terminate the verified Job-contained worker tree; on POSIX it remains `cleanup_incomplete` without a controller signal.
- Process already exited: return `already_finished` without signaling any PID.
- PID exists but identity differs: return `identity_mismatch`, emit a critical security event, and do not signal it.
- Identity evidence is missing or unsupported: return `identity_unverified` and do not signal it.
- `force=true`: use stronger controller termination only after an exact identity match and only where Windows Job containment proves the whole tree is owned.

Normal background termination is worker-owned. After controller verification, a nonce-bound cooperative request tells the live worker to stop its child through the worker's `Popen` handle and Windows Job Object. Controller emergency termination is allowed only through a Windows process handle verified from that same handle. Controller-side `taskkill`, raw PID signals, and process-group signals are prohibited. POSIX parent-death signals and process groups do not contain descendants that change group/session or outlive their direct parent, so production POSIX runtime launch fails closed until a delegated cgroup-v2 `cgroup.kill` backend or equivalent kernel-enforced whole-tree capability is implemented. The built-in fake runtime may use a test-only process group for self-tests. A stop request artifact or cancelled aggregate status is written only after verification, and unverified/incomplete child stops keep the parent operation blocked.

Legacy runs without `ProcessIdentity` remain readable and reportable. They cannot authorize `stop_run` or rollback behavior that sends process signals.

## Error Contract

Security failures return structured error data with a stable code, message, safe details, and suggested action. Initial codes are:

- `provider_env_forbidden`
- `provider_env_unrecognized`
- `runtime_not_trusted`
- `unsafe_runtime_policy_missing`
- `unsafe_runtime_request_missing`
- `runtime_identity_changed`
- `runtime_containment_unavailable`
- `process_identity_mismatch`
- `process_identity_unverified`
- `secure_payload_store_unavailable`
- `visible_runtime_unsupported`

Errors identify variable names or paths when safe, never their values. CLI and MCP surfaces preserve their current response envelopes and include the structured security error inside them.

## Security Audit Events

Append-only, secret-free events are written to `<artifact_root>/logs/security-events.ndjson`. Each event includes:

- timestamp and event code;
- severity;
- run id when one exists;
- runtime id and trust level;
- HMAC-pseudonymized provider id;
- rejected environment key names or identity mismatch fields;
- policy decision id;
- recommended controller action.

Event serialization uses an explicit field allowlist, origin-aware exact credential/endpoint-secret rejection plus pattern checks, a per-event size cap, symlink/reparse refusal, bounded cross-process locking, and a local hash chain. Detail values are never persisted; only allowlisted field names are retained. Prompt/task text cannot collide with fixed event vocabulary because it is neither serialized nor treated as an opaque audit secret. The 32-byte HMAC key lives under the workspace artifact root, not the installed skill directory. First use atomically establishes the key, an empty log, and an authenticated zero-event checkpoint. Once the key exists, a missing log or checkpoint is corruption and fails closed.

Every append fsyncs the log before replacing its authenticated checkpoint. A crash between those operations intentionally leaves the audit component unavailable; it must be restored from the last known-good log/checkpoint pair and is never automatically re-signed. Each append failure creates a unique strict-private generation marker in an independently initialized bootstrap tree scoped by an artifact-root digest and, when the normal audit tree has already been initialized, in that tree too. Every applicable marker destination is mandatory, so first-initialization failure remains visible across controller processes and partial persistence cannot pass silently. A complete verified append clears only generations observed after acquiring the audit lock, so a newer concurrent failure survives; long-lived processes reconcile stale in-memory failures against the shared marker set. Health always exposes failure count and byte capacity, and fails closed before the log can no longer accept a maximum-size event.

Windows strict audit objects require the current-user owner SID plus a protected current-user-only DACL. Directories are created relative to retained parent handles with `NtCreateFile(FILE_CREATE)` and the final security descriptor supplied atomically. The retained parent and created child handles both deny delete sharing through relative creation and ACL/identity verification. Existing names are handle-verified and never have their owner changed. For compatibility with existing workspaces, the artifact root itself is an outer container: initialization may replace its DACL with the protected current-user-only form but never changes its owner. Newly created audit subdirectories and files remain strict-owner objects. With no key/log/checkpoint/failure material, health reports `initialized=false` without treating the outer container as a corrupt audit chain.

Security rejection never becomes allowed because audit writing failed; `local_unsafe` fails closed on audit failure, while trusted-default launches may continue with an explicit degraded audit status. Status-time identity events use a cross-process pending claim in run metadata so concurrent dashboard/MCP polls cannot flood the audit log. Allowlisted pending markers are recoverable even after the observed process exits, failed appends remain pending, and a keyed deterministic `dedupe_id` checked under the audit lock makes both pre-append and post-append interruption retries idempotent without exposing run/marker material. This log is tamper-evident only within the current-user boundary, not an external trusted audit sink.

## Integration Points

The implementation changes are intentionally centered in the current Python runtime module:

- `build_worker_env` becomes policy-driven and rejects provider control keys.
- `run_agent`, `run_streaming_agent`, and `run_visible_agent` build a launch spec.
- `stream_worker` consumes the absolute executable and expected identity.
- follow-up, benchmark, queue, team, and future real workflow paths pass through the same launch APIs; current mock workflow launches no process.
- `single_run_status` reports identity state instead of PID liveness alone.
- `terminate_process_tree` requires an expected identity.
- `stop_run` refuses unverified or mismatched processes.
- CLI and MCP launch inputs gain `allow_unsafe_runtime`, defaulting to false.
- healthcheck reports runtime path, trust level, audit health, and process-identity support without exposing secrets; it executes `--version` only after capture, formal authorization, held-file verification, owned-process containment, and post-start process identity validation for a trusted default runtime.
- final JSON, profile Markdown, and persisted strategy-report projection inherits `*_url`/`*_uri` endpoint context recursively, strictly validates HTTP(S) origins, redacts endpoint non-strings and punctuation-prefixed embedded URI strings, drops URI-bearing mapping keys, and leaves Windows drive paths intact. Untrusted runtime JSON separately scrubs both keys and values with deterministic collision handling before any public or persisted output.
- all eleven public launch-capable CLI commands, including `queue-tick`, recursively use explicit timeout evidence `124`, controller security failure `2`, and an explicitly attributed runtime child exit code in that order. A bare child exit value of `124` remains a child result rather than timeout evidence. Private worker subcommands keep exit `0` so their structured controller protocol remains readable.

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
- Immediate prompts do not appear in process arguments or run artifacts; controller/worker metadata remains valid under concurrent updates.
- Task/context text does not appear in team, workflow, follow-up, report, dashboard, or queue metadata; deferred queue bytes use an OS-protected store or fail closed.
- Unsafe queue grants are single-use, identity-bound, expiring, and unavailable to automatic retries.
- Safe existing profiles and all existing selftest behavior remain compatible.
- Windows, Ubuntu, and macOS CI pass on Python 3.10 and 3.12.

## Residual Risks

- Portable process introspection differs by operating system and may require conservative unsupported states.
- Script-wrapper runtimes add an interpreter identity that must be recorded in addition to the wrapper file.
- Executable identity checks reduce but do not fully eliminate every platform-specific time-of-check/time-of-use race.
- A local user who can modify both policy and executable files remains inside the trusted local boundary.
- This design does not sandbox an otherwise trusted runtime's network or filesystem behavior.
