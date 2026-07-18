from __future__ import annotations

import json
import ctypes
import os
import secrets
import shlex
import shutil
import string
import sys
from hashlib import sha256
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
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
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "LANG",
        "LC_ALL",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
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
    return folded in _ABSOLUTE_DENY_ENV_KEYS or folded.startswith(
        ("cc_orchestrator_", "dyld_", "git_config")
    )


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
class ExecutableIdentity:
    canonical_path: str
    size: int
    mtime_ns: int
    sha256: str
    file_id: tuple[int, int] | None
    target_kind: str
    interpreter_identity: "ExecutableIdentity | None"

    def __post_init__(self) -> None:
        file_id = self.file_id
        if file_id is not None:
            if (
                not isinstance(file_id, (list, tuple))
                or len(file_id) != 2
                or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                    for value in file_id
                )
            ):
                raise TypeError("Executable identity has an invalid file id.")
            object.__setattr__(self, "file_id", (file_id[0], file_id[1]))
        _validate_executable_identity(self, depth=1, seen=set())

    @classmethod
    def capture(cls, executable: str | Path) -> "ExecutableIdentity":
        return cls._capture(executable, depth=1, seen=set())

    @classmethod
    def _capture(
        cls,
        executable: str | Path,
        *,
        depth: int,
        seen: set[str],
    ) -> "ExecutableIdentity":
        if depth > MAX_IDENTITY_DEPTH:
            raise ValueError("Executable identity exceeds maximum interpreter depth.")
        path = canonical_path(executable)
        if not path.is_file():
            raise ValueError("Executable identity target must be a file.")
        path_key = os.path.normcase(str(path))
        if path_key in seen:
            raise ValueError("Executable identity contains an interpreter cycle.")
        seen.add(path_key)
        try:
            before = path.stat()
            digest = sha256()
            with path.open("rb") as executable_file:
                for chunk in iter(lambda: executable_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = path.stat()
            if _stat_identity(before) != _stat_identity(after):
                raise ValueError("Executable changed while its identity was captured.")
            target_kind, interpreter_path = _resolve_interpreter(path)
            interpreter_identity = (
                None
                if interpreter_path is None
                else cls._capture(
                    interpreter_path,
                    depth=depth + 1,
                    seen=seen,
                )
            )
            return cls(
                canonical_path=str(path),
                size=after.st_size,
                mtime_ns=after.st_mtime_ns,
                sha256=digest.hexdigest(),
                file_id=_file_id(after),
                target_kind=target_kind,
                interpreter_identity=interpreter_identity,
            )
        finally:
            seen.remove(path_key)

    def matches_current_file(self) -> bool:
        try:
            return self == type(self).capture(self.canonical_path)
        except (OSError, TypeError, ValueError):
            return False

    def to_public_dict(self) -> dict[str, Any]:
        return self._to_public_dict(depth=1, seen=set())

    def _to_public_dict(
        self, *, depth: int, seen: set[int]
    ) -> dict[str, Any]:
        if depth > MAX_IDENTITY_DEPTH or id(self) in seen:
            raise ValueError("Executable identity is cyclic or too deep.")
        seen.add(id(self))
        try:
            return {
                "canonical_path": self.canonical_path,
                "size": self.size,
                "mtime_ns": self.mtime_ns,
                "sha256": self.sha256,
                "file_id": None if self.file_id is None else list(self.file_id),
                "target_kind": self.target_kind,
                "interpreter_identity": (
                    None
                    if self.interpreter_identity is None
                    else self.interpreter_identity._to_public_dict(
                        depth=depth + 1, seen=seen
                    )
                ),
            }
        finally:
            seen.remove(id(self))

    @classmethod
    def from_public_dict(cls, data: Mapping[str, Any]) -> "ExecutableIdentity":
        return cls._from_public_dict(data, depth=1, seen=set())

    @classmethod
    def _from_public_dict(
        cls,
        data: Mapping[str, Any],
        *,
        depth: int,
        seen: set[int],
    ) -> "ExecutableIdentity":
        if depth > MAX_IDENTITY_DEPTH:
            raise ValueError("Executable identity exceeds maximum interpreter depth.")
        if not isinstance(data, MappingABC):
            raise TypeError("Executable identity must be a mapping.")
        if id(data) in seen:
            raise ValueError("Executable identity contains an interpreter cycle.")
        expected_fields = {
            "canonical_path",
            "size",
            "mtime_ns",
            "sha256",
            "file_id",
            "target_kind",
            "interpreter_identity",
        }
        if set(data) != expected_fields:
            raise ValueError("Executable identity has an invalid shape.")
        canonical = data["canonical_path"]
        size = data["size"]
        mtime_ns = data["mtime_ns"]
        digest = data["sha256"]
        file_id_data = data["file_id"]
        target_kind = data["target_kind"]
        interpreter_data = data["interpreter_identity"]
        if (
            not isinstance(canonical, str)
            or not canonical
            or "\x00" in canonical
            or not Path(canonical).is_absolute()
        ):
            raise ValueError("Executable identity has an invalid canonical path.")
        for field_name, value in (("size", size), ("mtime_ns", mtime_ns)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"Executable identity has an invalid {field_name}.")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in string.hexdigits for character in digest)
        ):
            raise ValueError("Executable identity has an invalid SHA-256 digest.")
        if file_id_data is None:
            file_id = None
        elif (
            isinstance(file_id_data, list)
            and len(file_id_data) == 2
            and all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in file_id_data
            )
        ):
            file_id = (file_id_data[0], file_id_data[1])
        else:
            raise TypeError("Executable identity has an invalid file id.")
        if target_kind not in {"native", "cmd", "powershell", "python", "shebang"}:
            raise ValueError("Executable identity has an invalid target kind.")
        if interpreter_data is not None and not isinstance(interpreter_data, MappingABC):
            raise TypeError("Executable interpreter identity must be a mapping or null.")
        seen.add(id(data))
        try:
            interpreter = (
                None
                if interpreter_data is None
                else cls._from_public_dict(
                    interpreter_data, depth=depth + 1, seen=seen
                )
            )
        finally:
            seen.remove(id(data))
        if (target_kind == "native") != (interpreter is None):
            raise ValueError("Executable identity has an inconsistent interpreter.")
        return cls(
            canonical_path=canonical,
            size=size,
            mtime_ns=mtime_ns,
            sha256=digest,
            file_id=file_id,
            target_kind=target_kind,
            interpreter_identity=interpreter,
        )


def _file_id(stat_result: os.stat_result) -> tuple[int, int] | None:
    if not stat_result.st_ino:
        return None
    return (stat_result.st_dev, stat_result.st_ino)


def _validate_executable_identity(
    identity: ExecutableIdentity,
    *,
    depth: int,
    seen: set[int],
) -> None:
    if depth > MAX_IDENTITY_DEPTH:
        raise ValueError("Executable identity exceeds maximum interpreter depth.")
    if not isinstance(identity, ExecutableIdentity):
        raise TypeError("Interpreter identity must be an ExecutableIdentity.")
    if id(identity) in seen:
        raise ValueError("Executable identity contains an interpreter cycle.")
    seen.add(id(identity))
    try:
        if (
            not isinstance(identity.canonical_path, str)
            or not identity.canonical_path
            or "\x00" in identity.canonical_path
            or not Path(identity.canonical_path).is_absolute()
        ):
            raise ValueError("Executable identity has an invalid canonical path.")
        try:
            resolved_path = str(
                Path(identity.canonical_path).expanduser().resolve(strict=False)
            )
        except (OSError, RuntimeError) as error:
            raise ValueError(
                "Executable identity has an invalid canonical path."
            ) from error
        if identity.canonical_path != resolved_path:
            raise ValueError("Executable identity path is not canonical.")
        for field_name, value in (
            ("size", identity.size),
            ("mtime_ns", identity.mtime_ns),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"Executable identity has an invalid {field_name}.")
        if (
            not isinstance(identity.sha256, str)
            or len(identity.sha256) != 64
            or any(
                character not in string.hexdigits for character in identity.sha256
            )
        ):
            raise ValueError("Executable identity has an invalid SHA-256 digest.")
        if identity.file_id is not None and (
            not isinstance(identity.file_id, tuple)
            or len(identity.file_id) != 2
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in identity.file_id
            )
        ):
            raise TypeError("Executable identity has an invalid file id.")
        if identity.target_kind not in {
            "native",
            "cmd",
            "powershell",
            "python",
            "shebang",
        }:
            raise ValueError("Executable identity has an invalid target kind.")
        interpreter = identity.interpreter_identity
        if interpreter is not None and not isinstance(interpreter, ExecutableIdentity):
            raise TypeError("Interpreter identity must be an ExecutableIdentity.")
        if (identity.target_kind == "native") != (interpreter is None):
            raise ValueError("Executable identity has an inconsistent interpreter.")
        if interpreter is not None:
            _validate_executable_identity(
                interpreter,
                depth=depth + 1,
                seen=seen,
            )
    finally:
        seen.remove(id(identity))


def _stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, tuple[int, int] | None]:
    return (
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
        _file_id(stat_result),
    )


def _resolve_interpreter(path: Path) -> tuple[str, Path | None]:
    suffix = path.suffix.casefold()
    if suffix in {".cmd", ".bat"}:
        return "cmd", _resolve_cmd_executable()
    if suffix == ".ps1":
        return "powershell", _resolve_powershell_executable()
    if suffix == ".py":
        return "python", canonical_path(sys.executable)

    try:
        with path.open("rb") as executable_file:
            first_line = executable_file.readline(4096)
    except OSError:
        raise
    if not first_line.startswith(b"#!"):
        return "native", None
    try:
        command = shlex.split(
            first_line[2:].decode("utf-8").strip(), posix=os.name != "nt"
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("Executable contains an invalid shebang.") from error
    if not command:
        raise ValueError("Executable contains an empty shebang.")
    interpreter = Path(command[0])
    if interpreter.name.casefold() == "env" and interpreter.as_posix() == "/usr/bin/env":
        if len(command) != 2 or not command[1] or os.path.basename(command[1]) != command[1]:
            raise ValueError("Executable contains an unsupported env shebang.")
        resolved = shutil.which(command[1])
        if resolved is None:
            raise FileNotFoundError(command[1])
        interpreter = Path(resolved)
    elif not interpreter.is_absolute():
        raise ValueError("Shebang interpreter must be absolute.")
    return "shebang", canonical_path(interpreter)


def _resolve_cmd_executable() -> Path:
    if os.name == "nt":
        candidate = _windows_system_directory() / "cmd.exe"
        return canonical_path(candidate)
    resolved = shutil.which("cmd.exe") or shutil.which("cmd")
    if resolved is None:
        raise FileNotFoundError("cmd.exe")
    return canonical_path(resolved)


def _resolve_powershell_executable() -> Path:
    if os.name == "nt":
        candidate = (
            _windows_system_directory()
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        return canonical_path(candidate)
    resolved = shutil.which("pwsh") or shutil.which("powershell")
    if resolved is None:
        raise FileNotFoundError("PowerShell")
    return canonical_path(resolved)


def _windows_system_directory() -> Path:
    buffer = ctypes.create_unicode_buffer(32_768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise OSError(ctypes.get_last_error(), "Could not resolve Windows system directory")
    return canonical_path(buffer.value)


def generate_launch_nonce() -> str:
    return secrets.token_hex(32)


_ARGUMENT_KINDS = {
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


def _validate_runtime_arguments(
    arguments: object,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[str, ...]:
    if not isinstance(arguments, (list, tuple)):
        raise TypeError("runtime arguments must be a sequence")
    normalized = tuple(arguments)
    for argument in normalized:
        if not isinstance(argument, str):
            raise TypeError("runtime arguments must be strings")
        if argument not in _ARGUMENT_KINDS:
            raise ValueError("runtime argument is outside the allowed vocabulary")
        if argument in forbidden_values:
            raise ValueError("environment values cannot appear in runtime arguments")
    return normalized


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
    launch_nonce: str = field(init=False, default_factory=generate_launch_nonce)

    def __post_init__(self) -> None:
        _validate_nonempty_string(self.runtime_id, "runtime_id")
        if (
            not isinstance(self.protocol_version, int)
            or isinstance(self.protocol_version, bool)
            or self.protocol_version < 1
        ):
            raise TypeError("protocol_version must be a positive integer")
        if not isinstance(self.executable_identity, ExecutableIdentity):
            raise TypeError("executable_identity must be an ExecutableIdentity")
        arguments = _validate_runtime_arguments(self.arguments)
        object.__setattr__(self, "arguments", arguments)
        if not isinstance(self.cwd, (str, Path)):
            raise TypeError("cwd must be a path")
        object.__setattr__(
            self, "cwd", str(Path(self.cwd).expanduser().resolve(strict=False))
        )
        if self.permission_mode not in {"plan", "acceptEdits"}:
            raise ValueError("permission_mode is not allowed")
        if (
            not isinstance(self.timeout_seconds, int)
            or isinstance(self.timeout_seconds, bool)
            or self.timeout_seconds < 1
        ):
            raise TypeError("timeout_seconds must be a positive integer")
        environment_items = _validate_environment_items(self.environment_items)
        object.__setattr__(self, "environment_items", environment_items)
        _validate_runtime_arguments(
            arguments,
            forbidden_values=tuple(value for _, value in environment_items),
        )
        _validate_nonempty_string(self.trust_level, "trust_level")
        _validate_nonempty_string(self.policy_decision_id, "policy_decision_id")
        if (
            len(self.launch_nonce) != 64
            or any(character not in string.hexdigits for character in self.launch_nonce)
        ):
            raise ValueError("launch nonce is invalid")

    @classmethod
    def create(
        cls,
        *,
        runtime_id: str,
        protocol_version: int,
        executable_identity: ExecutableIdentity,
        arguments: tuple[str, ...],
        cwd: str | Path,
        permission_mode: str,
        timeout_seconds: int,
        environment: Mapping[str, str],
        trust_level: str,
        policy_decision_id: str,
    ) -> "RuntimeLaunchSpec":
        if not isinstance(environment, MappingABC):
            raise TypeError("environment must be a mapping")
        environment_items = tuple(environment.items())
        return cls(
            runtime_id=runtime_id,
            protocol_version=protocol_version,
            executable_identity=executable_identity,
            arguments=arguments,
            cwd=str(cwd),
            permission_mode=permission_mode,
            timeout_seconds=timeout_seconds,
            environment_items=environment_items,
            trust_level=trust_level,
            policy_decision_id=policy_decision_id,
        )

    @property
    def environment(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.environment_items))

    def private_frame(self) -> bytes:
        frame = {
            "runtime_id": self.runtime_id,
            "protocol_version": self.protocol_version,
            "executable_identity": self.executable_identity.to_public_dict(),
            "arguments": list(self.arguments),
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
            "timeout_seconds": self.timeout_seconds,
            "environment_keys": [key for key, _ in self.environment_items],
            "trust_level": self.trust_level,
            "policy_decision_id": self.policy_decision_id,
            "launch_nonce": self.launch_nonce,
        }
        return json.dumps(
            frame, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def public_metadata(self) -> dict[str, Any]:
        frame = self.private_frame()
        return {
            "runtime_id": self.runtime_id,
            "protocol_version": self.protocol_version,
            "executable_identity": self.executable_identity.to_public_dict(),
            "argument_kinds": [_ARGUMENT_KINDS[value] for value in self.arguments],
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
            "timeout_seconds": self.timeout_seconds,
            "environment_keys": [key for key, _ in self.environment_items],
            "trust_level": self.trust_level,
            "policy_decision_id": self.policy_decision_id,
            "launch_nonce": self.launch_nonce,
            "launch_contract_sha256": sha256(frame).hexdigest(),
        }


def _validate_nonempty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TypeError(f"{field_name} must be a non-empty string")


def _validate_environment_items(
    entries: object,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(entries, (list, tuple)):
        raise TypeError("environment_items must be a sequence")
    normalized: list[tuple[str, str]] = []
    folded_keys: set[str] = set()
    for entry in entries:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise TypeError("environment_items contains an invalid pair")
        key, value = entry
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "\x00" in key
            or "\x00" in value
        ):
            raise TypeError("environment_items contains an invalid entry")
        folded = key.casefold()
        if folded in folded_keys:
            raise ValueError("environment_items contains duplicate keys")
        folded_keys.add(folded)
        normalized.append((key, value))
    return tuple(sorted(normalized))


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
    validated_provider = policy.validate_provider_env(provider_env)
    argument_items = _validate_runtime_arguments(
        arguments,
        forbidden_values=tuple(value for _, value in validated_provider),
    )
    identity = ExecutableIdentity.capture(runtime_candidate.canonical_path)
    decision = authorize_runtime(
        candidate=runtime_candidate,
        identity=identity,
        policy=policy,
        allow_unsafe_runtime=allow_unsafe_runtime,
    )
    environment = dict(validated_provider)
    if model_override is not None:
        _validate_nonempty_string(model_override, "model_override")
        environment["ANTHROPIC_MODEL"] = model_override
    environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    environment["CC_ORCHESTRATOR_WORKSPACE_ROOT"] = str(
        Path(workspace_root).expanduser().resolve(strict=False)
    )
    environment["CC_ORCHESTRATOR_ARTIFACT_ROOT"] = str(
        Path(artifact_root).expanduser().resolve(strict=False)
    )
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    if os.name != "nt":
        environment["LANG"] = "C.UTF-8"
        environment["LC_ALL"] = "C.UTF-8"
    else:
        environment.pop("LANG", None)
        environment.pop("LC_ALL", None)
    return RuntimeLaunchSpec.create(
        runtime_id=decision.runtime_id,
        protocol_version=1,
        executable_identity=identity,
        arguments=argument_items,
        cwd=cwd,
        permission_mode=permission_mode,
        timeout_seconds=timeout_seconds,
        environment=environment,
        trust_level=decision.trust_level,
        policy_decision_id=decision.policy_decision_id,
    )


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
        schema_version = payload.get("schema_version")
        if (
            set(payload) != expected_keys
            or not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != POLICY_SCHEMA_VERSION
        ):
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
            total_bytes += len(key.encode("utf-8")) + 1 + value_bytes + 1
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
    if type(allow_unsafe_runtime) is not bool:
        raise _runtime_error(
            "unsafe_runtime_request_invalid",
            "Unsafe runtime request approval must be a boolean.",
            executable,
        )
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
