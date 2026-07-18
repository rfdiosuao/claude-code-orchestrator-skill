from __future__ import annotations

import json
import string
from hashlib import sha256
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


POLICY_SCHEMA_VERSION = 1
MAX_PROVIDER_ENV_VALUE_BYTES = 32 * 1024
MAX_PROVIDER_ENV_BYTES = 128 * 1024
MAX_IDENTITY_DEPTH = 4

_DEFAULT_PROVIDER_ENV_KEYS = frozenset(
    key.casefold()
    for key in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "ANTHROPIC_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    )
)
_ABSOLUTE_DENY_ENV_KEYS = frozenset(
    key.casefold()
    for key in (
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SHELL",
        "CLAUDE_CODE_BIN",
        "PYTHONPATH",
        "PYTHONHOME",
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "CC_ORCHESTRATOR_ARTIFACT_ROOT",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PSMODULEPATH",
        "DOTNET_STARTUP_HOOKS",
        "DOTNET_ADDITIONAL_DEPS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "GIT_SSH_COMMAND",
        "SSLKEYLOGFILE",
    )
)


def _freeze(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return MappingProxyType(
            {key: _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        frozen_values = (_freeze(item) for item in value)
        return tuple(sorted(frozen_values, key=repr))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("safe_details must contain JSON-compatible values")


def _thaw(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class RuntimeSecurityError(RuntimeError):
    code: str
    message: str
    safe_details: Mapping[str, Any]
    suggested_action: str

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)
        object.__setattr__(self, "safe_details", _freeze(self.safe_details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "safe_details": _thaw(self.safe_details),
            "suggested_action": self.suggested_action,
        }


def canonical_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=True)


def _policy_error(message: str, **safe_details: Any) -> RuntimeSecurityError:
    return RuntimeSecurityError(
        code="runtime_policy_invalid",
        message=message,
        safe_details=safe_details,
        suggested_action="Correct the runtime security policy and retry.",
    )


def _provider_env_error(
    code: str, message: str, **safe_details: Any
) -> RuntimeSecurityError:
    return RuntimeSecurityError(
        code=code,
        message=message,
        safe_details=safe_details,
        suggested_action="Remove the unsupported provider environment entry and retry.",
    )


def _is_absolute_deny_env_key(key: str) -> bool:
    folded = key.casefold()
    return folded in _ABSOLUTE_DENY_ENV_KEYS or folded.startswith("git_config")


def _validate_absolute_path(value: str, field: str) -> str:
    if not isinstance(value, str) or "\x00" in value or not Path(value).is_absolute():
        raise _policy_error("Runtime policy contains a non-absolute path.", field=field)
    return str(Path(value).expanduser().resolve(strict=False))


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
    trust_class: str


@dataclass(frozen=True)
class RuntimeTrustDecision:
    runtime_id: str
    trust_level: str
    policy_decision_id: str


def _validate_pinned_identity(
    identity: PinnedExecutableIdentity,
    *,
    depth: int = 1,
    seen: set[int] | None = None,
) -> None:
    if depth > MAX_IDENTITY_DEPTH:
        raise _policy_error("Runtime identity exceeds the maximum interpreter depth.")
    if not isinstance(identity, PinnedExecutableIdentity):
        raise _policy_error("Runtime policy contains an invalid executable identity.")
    seen = set() if seen is None else seen
    if id(identity) in seen:
        raise _policy_error("Runtime identity contains an interpreter cycle.")
    seen.add(id(identity))
    _validate_absolute_path(identity.canonical_path, "canonical_path")
    if (
        not isinstance(identity.sha256, str)
        or len(identity.sha256) != 64
        or any(character not in string.hexdigits for character in identity.sha256)
    ):
        raise _policy_error("Runtime identity contains an invalid SHA-256 digest.")
    if not isinstance(identity.size, int) or isinstance(identity.size, bool) or identity.size < 0:
        raise _policy_error("Runtime identity contains an invalid file size.")
    if identity.file_id is not None and (
        not isinstance(identity.file_id, tuple)
        or len(identity.file_id) != 2
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in identity.file_id)
    ):
        raise _policy_error("Runtime identity contains an invalid file id.")
    if not isinstance(identity.target_kind, str) or not identity.target_kind:
        raise _policy_error("Runtime identity contains an invalid target kind.")
    if identity.interpreter_identity is not None:
        _validate_pinned_identity(
            identity.interpreter_identity, depth=depth + 1, seen=seen
        )


def _parse_identity(value: object) -> PinnedExecutableIdentity:
    if not isinstance(value, dict):
        raise _policy_error("Runtime policy identity must be an object.")
    allowed_keys = {
        "canonical_path",
        "sha256",
        "size",
        "file_id",
        "target_kind",
        "interpreter_identity",
    }
    if set(value) != allowed_keys:
        raise _policy_error("Runtime policy identity has an invalid shape.")
    file_id_value = value["file_id"]
    if file_id_value is None:
        file_id = None
    elif isinstance(file_id_value, list) and len(file_id_value) == 2:
        file_id = tuple(file_id_value)
    else:
        raise _policy_error("Runtime policy identity contains an invalid file id.")
    interpreter_value = value["interpreter_identity"]
    identity = PinnedExecutableIdentity(
        canonical_path=value["canonical_path"],
        sha256=value["sha256"],
        size=value["size"],
        file_id=file_id,
        target_kind=value["target_kind"],
        interpreter_identity=(
            None if interpreter_value is None else _parse_identity(interpreter_value)
        ),
    )
    _validate_pinned_identity(identity)
    return identity


@dataclass(frozen=True)
class RuntimeSecurityPolicy:
    runtime_executable: str | None = None
    extra_provider_env_keys: tuple[str, ...] = ()
    unsafe_runtimes: tuple[ApprovedUnsafeRuntime, ...] = ()

    def __post_init__(self) -> None:
        if self.runtime_executable is not None:
            _validate_absolute_path(self.runtime_executable, "runtime_executable")
        extra_keys = tuple(self.extra_provider_env_keys)
        unsafe_runtimes = tuple(self.unsafe_runtimes)
        object.__setattr__(self, "extra_provider_env_keys", extra_keys)
        object.__setattr__(self, "unsafe_runtimes", unsafe_runtimes)
        folded_keys: set[str] = set()
        for key in extra_keys:
            if not isinstance(key, str) or not key or "\x00" in key:
                raise _policy_error("Runtime policy contains an invalid provider environment key.")
            folded = key.casefold()
            if folded in folded_keys or _is_absolute_deny_env_key(key):
                raise _policy_error("Runtime policy allowlist collides with a denied key.")
            folded_keys.add(folded)
        runtime_ids: set[str] = set()
        for approved in unsafe_runtimes:
            if not isinstance(approved, ApprovedUnsafeRuntime) or not isinstance(approved.runtime_id, str) or not approved.runtime_id:
                raise _policy_error("Runtime policy contains an invalid unsafe runtime.")
            if approved.runtime_id in runtime_ids:
                raise _policy_error("Runtime policy contains duplicate unsafe runtime ids.")
            runtime_ids.add(approved.runtime_id)
            _validate_pinned_identity(approved.identity)

    @classmethod
    def default(cls) -> "RuntimeSecurityPolicy":
        return cls()

    @classmethod
    def load(cls, path: Path) -> "RuntimeSecurityPolicy":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _policy_error("Runtime policy JSON could not be read.", path=str(path)) from error
        if not isinstance(payload, dict):
            raise _policy_error("Runtime policy JSON must be an object.")
        expected_keys = {
            "schema_version",
            "runtime_executable",
            "extra_provider_env_keys",
            "unsafe_runtimes",
        }
        if set(payload) != expected_keys or payload["schema_version"] != POLICY_SCHEMA_VERSION:
            raise _policy_error("Runtime policy JSON has an unsupported schema.")
        if payload["runtime_executable"] is not None and not isinstance(payload["runtime_executable"], str):
            raise _policy_error("Runtime policy contains an invalid runtime executable.")
        if not isinstance(payload["extra_provider_env_keys"], list) or not all(
            isinstance(key, str) for key in payload["extra_provider_env_keys"]
        ):
            raise _policy_error("Runtime policy contains an invalid environment allowlist.")
        if not isinstance(payload["unsafe_runtimes"], list):
            raise _policy_error("Runtime policy contains an invalid unsafe runtime list.")
        unsafe_runtimes: list[ApprovedUnsafeRuntime] = []
        for approved in payload["unsafe_runtimes"]:
            if not isinstance(approved, dict) or set(approved) != {"runtime_id", "identity"}:
                raise _policy_error("Runtime policy contains an invalid unsafe runtime.")
            unsafe_runtimes.append(
                ApprovedUnsafeRuntime(
                    runtime_id=approved["runtime_id"], identity=_parse_identity(approved["identity"])
                )
            )
        return cls(
            runtime_executable=payload["runtime_executable"],
            extra_provider_env_keys=tuple(payload["extra_provider_env_keys"]),
            unsafe_runtimes=tuple(unsafe_runtimes),
        )

    def validate_provider_env(
        self, provider_env: Mapping[str, str]
    ) -> tuple[tuple[str, str], ...]:
        if not isinstance(provider_env, MappingABC):
            raise _provider_env_error(
                "provider_env_invalid", "Provider environment must be a mapping."
            )
        allowed_keys = _DEFAULT_PROVIDER_ENV_KEYS | {
            key.casefold() for key in self.extra_provider_env_keys
        }
        folded_keys: set[str] = set()
        entries: list[tuple[str, str]] = []
        for key, value in provider_env.items():
            if not isinstance(key, str) or not isinstance(value, str) or "\x00" in key or "\x00" in value:
                raise _provider_env_error(
                    "provider_env_invalid", "Provider environment contains an invalid entry."
                )
            folded = key.casefold()
            if folded in folded_keys:
                raise _provider_env_error(
                    "provider_env_invalid",
                    "Provider environment contains duplicate key names.",
                    keys=tuple(sorted([name for name, _ in entries] + [key])),
                )
            folded_keys.add(folded)
            entries.append((key, value))

        forbidden = sorted(key for key, _ in entries if _is_absolute_deny_env_key(key))
        if forbidden:
            raise _provider_env_error(
                "provider_env_forbidden",
                "Provider environment contains a forbidden key.",
                keys=tuple(forbidden),
            )
        unknown = sorted(
            key for key, _ in entries if key.casefold() not in allowed_keys
        )
        if unknown:
            raise _provider_env_error(
                "provider_env_unrecognized",
                "Provider environment contains unrecognized keys.",
                keys=tuple(unknown),
            )

        normalized: list[tuple[str, str]] = []
        total_bytes = 0
        for key, value in entries:
            value_bytes = len(value.encode("utf-8"))
            if value_bytes > MAX_PROVIDER_ENV_VALUE_BYTES:
                raise _provider_env_error(
                    "provider_env_too_large",
                    "Provider environment value exceeds the size limit.",
                    keys=(key,),
                )
            total_bytes += len(key.encode("utf-8")) + value_bytes
            if total_bytes > MAX_PROVIDER_ENV_BYTES:
                raise _provider_env_error(
                    "provider_env_too_large",
                    "Provider environment exceeds the total size limit.",
                    keys=tuple(sorted([name for name, _ in normalized] + [key])),
                )
            normalized.append((key, value))
        return tuple(sorted(normalized))

    def configured_runtime_path(self) -> Path | None:
        if self.runtime_executable is None:
            return None
        return canonical_path(self.runtime_executable)

    def find_unsafe_runtime(
        self, canonical_executable: Path
    ) -> ApprovedUnsafeRuntime | None:
        executable = canonical_path(canonical_executable)
        for approved in self.unsafe_runtimes:
            if Path(approved.identity.canonical_path).resolve(strict=False) == executable:
                return approved
        return None


def _runtime_error(code: str, message: str, executable: Path) -> RuntimeSecurityError:
    return RuntimeSecurityError(
        code=code,
        message=message,
        safe_details={"canonical_path": str(executable)},
        suggested_action="Review the runtime trust policy and retry.",
    )


def _identity_pin_matches(
    pinned: PinnedExecutableIdentity,
    observed: object,
    *,
    depth: int = 1,
    seen: set[tuple[int, int]] | None = None,
) -> bool:
    if depth > MAX_IDENTITY_DEPTH or observed is None:
        return False
    seen = set() if seen is None else seen
    pair = (id(pinned), id(observed))
    if pair in seen:
        return False
    seen.add(pair)
    try:
        observed_path = str(Path(observed.canonical_path).resolve(strict=False))
        pinned_path = str(Path(pinned.canonical_path).resolve(strict=False))
        fields_match = (
            pinned_path == observed_path
            and pinned.sha256 == observed.sha256
            and pinned.size == observed.size
            and pinned.file_id == observed.file_id
            and pinned.target_kind == observed.target_kind
        )
        if not fields_match:
            return False
        pinned_interpreter = pinned.interpreter_identity
        observed_interpreter = observed.interpreter_identity
    except (AttributeError, TypeError, ValueError):
        return False
    if pinned_interpreter is None or observed_interpreter is None:
        return pinned_interpreter is None and observed_interpreter is None
    return _identity_pin_matches(
        pinned_interpreter, observed_interpreter, depth=depth + 1, seen=seen
    )


def _identity_digests(identity: object) -> tuple[str, ...]:
    digests: list[str] = []
    current = identity
    seen: set[int] = set()
    for _ in range(MAX_IDENTITY_DEPTH + 1):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        try:
            digest = current.sha256
            current = current.interpreter_identity
        except AttributeError:
            break
        digests.append(str(digest))
    return tuple(digests)


def _decision_id(
    *,
    candidate: RuntimeExecutableCandidate,
    identity: object,
    policy_approval: bool,
    request_approval: bool,
) -> str:
    frame = {
        "canonical_path": str(Path(candidate.canonical_path).resolve(strict=False)),
        "source": candidate.source,
        "trust_class": candidate.trust_class,
        "identity_digests": _identity_digests(identity),
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_approval": policy_approval,
        "request_approval": request_approval,
    }
    return sha256(
        json.dumps(frame, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def authorize_runtime(
    *,
    candidate: RuntimeExecutableCandidate,
    identity: PinnedExecutableIdentity,
    policy: RuntimeSecurityPolicy,
    allow_unsafe_runtime: bool,
) -> RuntimeTrustDecision:
    if not isinstance(candidate, RuntimeExecutableCandidate):
        raise _runtime_error(
            "runtime_candidate_unrecognized",
            "Runtime candidate is not recognized.",
            Path.cwd(),
        )
    executable = canonical_path(candidate.canonical_path)
    if candidate.trust_class not in {
        "trusted_default",
        "discovered_unpinned",
        "local_configured",
    }:
        raise _runtime_error(
            "runtime_candidate_unrecognized",
            "Runtime candidate trust class is not recognized.",
            executable,
        )
    if candidate.trust_class == "trusted_default":
        return RuntimeTrustDecision(
            runtime_id="trusted-default",
            trust_level="trusted_default",
            policy_decision_id=_decision_id(
                candidate=candidate,
                identity=identity,
                policy_approval=True,
                request_approval=allow_unsafe_runtime,
            ),
        )

    approved = policy.find_unsafe_runtime(executable)
    if approved is None and not allow_unsafe_runtime:
        raise _runtime_error(
            "runtime_not_trusted", "Runtime is not trusted by the active policy.", executable
        )
    if approved is None:
        raise _runtime_error(
            "unsafe_runtime_policy_missing",
            "Unsafe runtime approval is missing from the local policy.",
            executable,
        )
    if not allow_unsafe_runtime:
        raise _runtime_error(
            "unsafe_runtime_request_missing",
            "Unsafe runtime use requires explicit request approval.",
            executable,
        )
    if not _identity_pin_matches(approved.identity, identity):
        raise _runtime_error(
            "runtime_identity_changed",
            "Runtime identity no longer matches the approved pin.",
            executable,
        )
    return RuntimeTrustDecision(
        runtime_id=approved.runtime_id,
        trust_level="local_unsafe",
        policy_decision_id=_decision_id(
            candidate=candidate,
            identity=identity,
            policy_approval=True,
            request_approval=True,
        ),
    )
