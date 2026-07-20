from __future__ import annotations

import json
import inspect
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: F401
import runtime_security
from runtime_security import (
    ApprovedUnsafeRuntime,
    PinnedExecutableIdentity,
    RuntimeExecutableCandidate,
    RuntimeSecurityError,
    RuntimeSecurityPolicy,
    authorize_runtime,
)

ExecutableIdentity = getattr(runtime_security, "ExecutableIdentity", None)
RuntimeLaunchSpec = getattr(runtime_security, "RuntimeLaunchSpec", None)
build_runtime_launch_spec = getattr(runtime_security, "build_runtime_launch_spec", None)


ABSOLUTE_DENY_CASES = [
    "PATH", "Path", "PATHEXT", "COMSPEC", "SHELL", "CLAUDE_CODE_BIN",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "LANG", "LC_ALL",
    "PYTHONIOENCODING", "PYTHONUTF8",
    "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "CC_ORCHESTRATOR_ARTIFACT_ROOT", "BASH_ENV", "ENV", "ZDOTDIR",
    "PSModulePath", "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
    "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL", "GIT_SSH_COMMAND", "SSLKEYLOGFILE",
]


class ExecutableIdentityTests(unittest.TestCase):
    def test_identity_contract_exists(self) -> None:
        self.assertIsNotNone(ExecutableIdentity)

    def test_capture_records_strict_metadata_and_chunked_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.bin"
            payload = b"a" * (1024 * 1024) + b"tail"
            executable.write_bytes(payload)

            identity = ExecutableIdentity.capture(executable)

            stat = executable.stat()
            self.assertEqual(identity.canonical_path, str(executable.resolve(strict=True)))
            self.assertEqual(identity.size, len(payload))
            self.assertEqual(identity.mtime_ns, stat.st_mtime_ns)
            self.assertEqual(identity.sha256, sha256(payload).hexdigest())
            expected_file_id = (
                (stat.st_dev, stat.st_ino) if stat.st_dev or stat.st_ino else None
            )
            self.assertEqual(identity.file_id, expected_file_id)
            self.assertEqual(identity.target_kind, "native")
            self.assertIsNone(identity.interpreter_identity)
            self.assertTrue(identity.matches_current_file())

    def test_current_match_detects_metadata_and_digest_only_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.bin"
            executable.write_bytes(b"first")
            metadata_identity = ExecutableIdentity.capture(executable)
            later_mtime = metadata_identity.mtime_ns + 1_000_000_000
            executable.write_bytes(b"other")
            os.utime(executable, ns=(later_mtime, later_mtime))
            self.assertFalse(metadata_identity.matches_current_file())

            digest_identity = ExecutableIdentity.capture(executable)
            executable.write_bytes(b"third")
            os.utime(
                executable,
                ns=(digest_identity.mtime_ns, digest_identity.mtime_ns),
            )
            self.assertFalse(digest_identity.matches_current_file())

    def test_public_identity_round_trip_is_strict_and_recursive(self) -> None:
        interpreter = ExecutableIdentity.capture(sys.executable)
        identity = replace(
            interpreter,
            target_kind="python",
            interpreter_identity=interpreter,
        )

        public = identity.to_public_dict()

        self.assertEqual(ExecutableIdentity.from_public_dict(public), identity)
        invalid = (
            {key: value for key, value in public.items() if key != "mtime_ns"},
            {**public, "extra": True},
            {**public, "size": True},
            {**public, "mtime_ns": "1"},
            {**public, "sha256": "z" * 64},
            {**public, "file_id": [1, True]},
        )
        for payload in invalid:
            with self.subTest(keys=tuple(payload)), self.assertRaises(
                (TypeError, ValueError)
            ):
                ExecutableIdentity.from_public_dict(payload)

        cyclic = dict(public)
        cyclic["interpreter_identity"] = cyclic
        with self.assertRaises((TypeError, ValueError)):
            ExecutableIdentity.from_public_dict(cyclic)

        too_deep = ExecutableIdentity.capture(sys.executable).to_public_dict()
        for _ in range(4):
            too_deep = {**public, "interpreter_identity": too_deep}
        with self.assertRaises((TypeError, ValueError)):
            ExecutableIdentity.from_public_dict(too_deep)

    def test_direct_construction_defensively_copies_file_id_for_launch_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            captured = ExecutableIdentity.capture(sys.executable)
            source_file_id = [11, 22]
            identity = ExecutableIdentity(
                canonical_path=captured.canonical_path,
                size=captured.size,
                mtime_ns=captured.mtime_ns,
                sha256=captured.sha256,
                file_id=source_file_id,
                target_kind="native",
                interpreter_identity=None,
            )
            spec = RuntimeLaunchSpec.create(
                runtime_id="fixture-runtime",
                protocol_version=1,
                executable_identity=identity,
                arguments=("-p",),
                cwd=directory,
                permission_mode="plan",
                timeout_seconds=30,
                environment={},
                trust_level="trusted_default",
                policy_decision_id="decision-fixture",
            )
            original_frame = spec.private_frame()
            original_hash = spec.public_metadata()["launch_contract_sha256"]

            source_file_id[0] = 99
            source_file_id.append(33)

            self.assertEqual(identity.file_id, (11, 22))
            self.assertEqual(spec.private_frame(), original_frame)
            self.assertEqual(
                spec.public_metadata()["launch_contract_sha256"], original_hash
            )

    def test_direct_construction_rejects_invalid_scalars_and_recursive_chains(self) -> None:
        captured = ExecutableIdentity.capture(sys.executable)
        noncanonical_path = str(
            Path(captured.canonical_path).parent
            / "unused-directory"
            / ".."
            / Path(captured.canonical_path).name
        )
        invalid_changes = (
            {"canonical_path": True},
            {"canonical_path": "relative.exe"},
            {"canonical_path": noncanonical_path},
            {"size": True},
            {"size": -1},
            {"mtime_ns": True},
            {"mtime_ns": -1},
            {"sha256": "bad"},
            {"file_id": [1, True]},
            {"file_id": [1]},
            {"target_kind": "unknown"},
            {"target_kind": "shebang", "interpreter_identity": object()},
            {"target_kind": "native", "interpreter_identity": captured},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes), self.assertRaises(
                (TypeError, ValueError)
            ):
                replace(captured, **changes)

        depth_four = captured
        for _ in range(3):
            depth_four = replace(
                captured,
                target_kind="shebang",
                interpreter_identity=depth_four,
            )
        with self.assertRaises(ValueError):
            replace(
                captured,
                target_kind="shebang",
                interpreter_identity=depth_four,
            )

        cyclic = replace(
            captured,
            target_kind="shebang",
            interpreter_identity=captured,
        )
        object.__setattr__(cyclic, "interpreter_identity", cyclic)
        with self.assertRaises(ValueError):
            replace(
                captured,
                target_kind="shebang",
                interpreter_identity=cyclic,
            )

    def test_python_and_shebang_wrappers_capture_full_interpreter_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            python_wrapper = directory / "runtime.py"
            python_wrapper.write_text("print('fixture')\n", encoding="utf-8")
            python_identity = ExecutableIdentity.capture(python_wrapper)
            expected_python = ExecutableIdentity.capture(sys.executable)
            self.assertEqual(python_identity.target_kind, "python")
            self.assertEqual(python_identity.interpreter_identity, expected_python)

            env_interpreter = shutil.which(Path(sys.executable).stem)
            if env_interpreter is None:
                self.skipTest("current Python interpreter is not on PATH")
            shebang_wrapper = directory / "runtime-wrapper"
            shebang_wrapper.write_text(
                f"#!/usr/bin/env {Path(sys.executable).stem}\nfixture\n",
                encoding="utf-8",
            )
            shebang_identity = ExecutableIdentity.capture(shebang_wrapper)
            self.assertEqual(shebang_identity.target_kind, "shebang")
            self.assertEqual(
                shebang_identity.interpreter_identity,
                ExecutableIdentity.capture(Path(env_interpreter).resolve(strict=True)),
            )
            self.assertTrue(shebang_identity.matches_current_file())

    def test_platform_wrappers_use_verified_absolute_interpreters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            cases = (("cmd", "cmd"), ("bat", "cmd"), ("ps1", "powershell"))
            for suffix, expected_kind in cases:
                wrapper = directory / f"runtime.{suffix}"
                wrapper.write_text("fixture\n", encoding="utf-8")
                try:
                    identity = ExecutableIdentity.capture(wrapper)
                except FileNotFoundError:
                    if os.name == "nt":
                        raise
                    continue
                with self.subTest(suffix=suffix):
                    self.assertEqual(identity.target_kind, expected_kind)
                    self.assertIsNotNone(identity.interpreter_identity)
                    self.assertTrue(Path(identity.interpreter_identity.canonical_path).is_absolute())
                    self.assertTrue(identity.interpreter_identity.matches_current_file())

    @unittest.skipUnless(os.name == "nt", "Windows interpreter verification")
    def test_windows_wrappers_ignore_forged_system_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            fake_cmd = directory / "System32" / "cmd.exe"
            fake_powershell = (
                directory
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            )
            for executable in (fake_cmd, fake_powershell):
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(b"forged")
            cmd_wrapper = directory / "runtime.cmd"
            ps_wrapper = directory / "runtime.ps1"
            cmd_wrapper.write_text("fixture\n", encoding="utf-8")
            ps_wrapper.write_text("fixture\n", encoding="utf-8")

            with patch.dict(os.environ, {"SystemRoot": str(directory)}):
                cmd_identity = ExecutableIdentity.capture(cmd_wrapper)
                ps_identity = ExecutableIdentity.capture(ps_wrapper)

            self.assertNotEqual(
                cmd_identity.interpreter_identity.canonical_path,
                str(fake_cmd.resolve(strict=True)),
            )
            self.assertNotEqual(
                ps_identity.interpreter_identity.canonical_path,
                str(fake_powershell.resolve(strict=True)),
            )

    def test_recursive_capture_rejects_cycles_and_chains_over_four_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            first = directory / "first"
            second = directory / "second"
            first.write_text(f"#!{second.resolve().as_posix()}\n", encoding="utf-8")
            second.write_text(f"#!{first.resolve().as_posix()}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                ExecutableIdentity.capture(first)

            wrappers = [directory / f"wrapper-{index}" for index in range(4)]
            for index, wrapper in enumerate(wrappers):
                interpreter = wrappers[index + 1] if index + 1 < len(wrappers) else Path(sys.executable)
                wrapper.write_text(
                    f"#!{interpreter.resolve().as_posix()}\n", encoding="utf-8"
                )
            accepted = ExecutableIdentity.capture(wrappers[1])
            self.assertEqual(self._identity_depth(accepted), 4)
            with self.assertRaises(ValueError):
                ExecutableIdentity.capture(wrappers[0])

    @staticmethod
    def _identity_depth(identity: ExecutableIdentity) -> int:
        depth = 0
        current = identity
        while current is not None:
            depth += 1
            current = current.interpreter_identity
        return depth


class RuntimeLaunchSpecTests(unittest.TestCase):
    arguments = (
        "-p",
        "--output-format",
        "stream-json",
        "--permission-mode",
        "plan",
        "--no-session-persistence",
        "--verbose",
        "--include-partial-messages",
    )

    def test_launch_spec_contract_exists(self) -> None:
        self.assertIsNotNone(RuntimeLaunchSpec)
        self.assertIsNotNone(build_runtime_launch_spec)

    def create_spec(
        self,
        directory: Path,
        *,
        arguments: object | None = None,
        environment: object | None = None,
    ) -> object:
        return RuntimeLaunchSpec.create(
            runtime_id="fixture-runtime",
            protocol_version=1,
            executable_identity=ExecutableIdentity.capture(sys.executable),
            arguments=list(self.arguments) if arguments is None else arguments,
            cwd=directory,
            permission_mode="plan",
            timeout_seconds=30,
            environment={"ANTHROPIC_API_KEY": "fixture-secret"}
            if environment is None
            else environment,
            trust_level="trusted_default",
            policy_decision_id="decision-fixture",
        )

    def test_spec_is_deeply_immutable_and_nonce_cannot_be_injected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            arguments = list(self.arguments)
            environment = {"ANTHROPIC_API_KEY": "fixture-secret"}
            spec = self.create_spec(
                directory, arguments=arguments, environment=environment
            )
            arguments.append("json")
            environment["ANTHROPIC_API_KEY"] = "changed-secret"

            self.assertEqual(spec.arguments, self.arguments)
            self.assertEqual(spec.environment["ANTHROPIC_API_KEY"], "fixture-secret")
            with self.assertRaises(TypeError):
                spec.environment["NEW_KEY"] = "value"
            with self.assertRaises(FrozenInstanceError):
                spec.cwd = "changed"
            self.assertNotIn("launch_nonce", inspect.signature(RuntimeLaunchSpec).parameters)
            with self.assertRaises(ValueError):
                replace(spec, launch_nonce="0" * 64)
            self.assertEqual(len(spec.launch_nonce), 64)
            int(spec.launch_nonce, 16)

            nonces = {self.create_spec(directory).launch_nonce for _ in range(1000)}
            self.assertEqual(len(nonces), 1000)

    def test_private_frame_is_exact_and_public_projection_contains_no_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            secret = "provider-secret-never-public"
            spec = self.create_spec(
                directory,
                environment={
                    "ANTHROPIC_API_KEY": secret,
                    "ANTHROPIC_MODEL": "provider-model-never-public",
                },
            )

            frame = spec.private_frame()
            decoded = json.loads(frame.decode("utf-8"))
            self.assertEqual(frame, spec.private_frame())
            self.assertEqual(
                set(decoded),
                {
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
                },
            )
            self.assertEqual(decoded["arguments"], list(self.arguments))
            self.assertEqual(
                decoded["environment_keys"], ["ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"]
            )
            self.assertEqual(
                decoded["executable_identity"],
                spec.executable_identity.to_public_dict(),
            )

            public = spec.public_metadata()
            serialized_public = json.dumps(public, sort_keys=True)
            self.assertEqual(
                public["launch_contract_sha256"], sha256(frame).hexdigest()
            )
            self.assertEqual(
                public["argument_kinds"],
                [
                    "prompt_stdin",
                    "output_format_flag",
                    "stream_json_format",
                    "permission_mode_flag",
                    "plan_permission",
                    "no_session_persistence",
                    "verbose",
                    "include_partial_messages",
                ],
            )
            self.assertNotIn("arguments", public)
            self.assertNotIn(secret, serialized_public)
            self.assertNotIn("provider-model-never-public", serialized_public)
            public["environment_keys"].append("MUTATED")
            self.assertNotIn("MUTATED", spec.public_metadata()["environment_keys"])

    def test_create_rejects_arguments_outside_claude_control_vocabulary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for arguments in (
                ("-p", "prompt text"),
                ("--model", "claude-secret"),
                ("-p", 1),
            ):
                with self.subTest(arguments=arguments), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    self.create_spec(directory, arguments=arguments)

            with self.assertRaises(ValueError):
                self.create_spec(
                    directory,
                    arguments=("-p", "json"),
                    environment={"ANTHROPIC_MODEL": "json"},
                )

    def test_builder_validates_provider_first_and_does_not_mutate_inputs(self) -> None:
        missing = Path(tempfile.gettempdir()) / "definitely-missing-runtime-task-3.exe"
        candidate = RuntimeExecutableCandidate(
            canonical_path=str(missing),
            source="fixture",
            trust_class="trusted_default",
        )
        provider_env = {"PATH": "provider-secret"}
        with self.assertRaises(RuntimeSecurityError) as raised:
            build_runtime_launch_spec(
                runtime_candidate=candidate,
                provider_env=provider_env,
                model_override=None,
                cwd=missing,
                workspace_root=missing,
                artifact_root=missing,
                permission_mode="plan",
                timeout_seconds=30,
                arguments=self.arguments,
                policy=RuntimeSecurityPolicy.default(),
                allow_unsafe_runtime=False,
            )
        self.assertEqual(raised.exception.code, "provider_env_forbidden")
        self.assertEqual(provider_env, {"PATH": "provider-secret"})

        provider_argument_cases = (
            ({"ANTHROPIC_MODEL": "json"}, ("-p", "json"), "environment values"),
            ({}, ("-p", "prompt text"), "allowed vocabulary"),
        )
        for environment, arguments, expected_message in provider_argument_cases:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(
                ValueError, expected_message
            ):
                build_runtime_launch_spec(
                    runtime_candidate=candidate,
                    provider_env=environment,
                    model_override=None,
                    cwd=missing,
                    workspace_root=missing,
                    artifact_root=missing,
                    permission_mode="plan",
                    timeout_seconds=30,
                    arguments=arguments,
                    policy=RuntimeSecurityPolicy.default(),
                    allow_unsafe_runtime=False,
                )

    def test_builder_overwrites_controller_owned_utf8_controls(self) -> None:
        class LeakyValidationPolicy(RuntimeSecurityPolicy):
            def validate_provider_env(self, provider_env: object) -> tuple[tuple[str, str], ...]:
                return tuple(sorted(provider_env.items()))

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            candidate = RuntimeExecutableCandidate(
                canonical_path=str(Path(sys.executable).resolve(strict=True)),
                source="fixture",
                trust_class="trusted_default",
            )
            spec = build_runtime_launch_spec(
                runtime_candidate=candidate,
                provider_env={
                    "PYTHONIOENCODING": "unsafe",
                    "PYTHONUTF8": "0",
                    "LANG": "unsafe",
                    "LC_ALL": "unsafe",
                },
                model_override=None,
                cwd=directory,
                workspace_root=directory,
                artifact_root=directory,
                permission_mode="plan",
                timeout_seconds=30,
                arguments=("-p",),
                policy=LeakyValidationPolicy(),
                allow_unsafe_runtime=False,
            )

            self.assertEqual(spec.environment["PYTHONIOENCODING"], "utf-8")
            self.assertEqual(spec.environment["PYTHONUTF8"], "1")
            if os.name == "nt":
                self.assertNotIn("LANG", spec.environment)
                self.assertNotIn("LC_ALL", spec.environment)
            else:
                self.assertEqual(spec.environment["LANG"], "C.UTF-8")
                self.assertEqual(spec.environment["LC_ALL"], "C.UTF-8")

    def test_builder_canonicalizes_paths_authorizes_and_adds_owned_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            cwd = directory / "cwd"
            workspace = directory / "workspace"
            artifacts = directory / "artifacts"
            for path in (cwd, workspace, artifacts):
                path.mkdir()
            candidate = RuntimeExecutableCandidate(
                canonical_path=str(Path(sys.executable).resolve(strict=True)),
                source="fixture",
                trust_class="trusted_default",
            )
            provider_env = {"ANTHROPIC_API_KEY": "provider-secret"}

            spec = build_runtime_launch_spec(
                runtime_candidate=candidate,
                provider_env=provider_env,
                model_override="controller-model",
                cwd=cwd / ".." / "cwd",
                workspace_root=workspace / ".." / "workspace",
                artifact_root=artifacts / ".." / "artifacts",
                permission_mode="plan",
                timeout_seconds=30,
                arguments=self.arguments,
                policy=RuntimeSecurityPolicy.default(),
                allow_unsafe_runtime=False,
            )

            self.assertEqual(spec.cwd, str(cwd.resolve(strict=True)))
            self.assertEqual(spec.runtime_id, "trusted-default")
            self.assertEqual(spec.trust_level, "trusted_default")
            self.assertEqual(spec.environment["ANTHROPIC_API_KEY"], "provider-secret")
            self.assertEqual(spec.environment["ANTHROPIC_MODEL"], "controller-model")
            self.assertEqual(
                spec.environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1"
            )
            self.assertEqual(
                spec.environment["CC_ORCHESTRATOR_WORKSPACE_ROOT"],
                str(workspace.resolve(strict=True)),
            )
            self.assertEqual(
                spec.environment["CC_ORCHESTRATOR_ARTIFACT_ROOT"],
                str(artifacts.resolve(strict=True)),
            )
            self.assertEqual(spec.environment["PYTHONIOENCODING"], "utf-8")
            self.assertEqual(spec.environment["PYTHONUTF8"], "1")
            self.assertEqual(provider_env, {"ANTHROPIC_API_KEY": "provider-secret"})

            with self.assertRaises(ValueError):
                build_runtime_launch_spec(
                    runtime_candidate=candidate,
                    provider_env={"ANTHROPIC_MODEL": "json"},
                    model_override=None,
                    cwd=cwd,
                    workspace_root=workspace,
                    artifact_root=artifacts,
                    permission_mode="plan",
                    timeout_seconds=30,
                    arguments=("-p", "json"),
                    policy=RuntimeSecurityPolicy.default(),
                    allow_unsafe_runtime=False,
                )


class ProviderEnvironmentPolicyTests(unittest.TestCase):
    def test_supported_provider_keys_are_preserved_in_sorted_immutable_pairs(self) -> None:
        provider_env = {
            "ANTHROPIC_API_KEY": "test-api-key",
            "ANTHROPIC_AUTH_TOKEN": "test-auth-token",
            "ANTHROPIC_MODEL": "claude-test",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "opus-test",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "sonnet-test",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "haiku-test",
            "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME": "opus-name-test",
            "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME": "sonnet-name-test",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME": "haiku-name-test",
            "ANTHROPIC_BASE_URL": "https://provider.example.test/v1",
            "HTTP_PROXY": "http://proxy.example.test",
            "HTTPS_PROXY": "https://proxy.example.test",
            "NO_PROXY": "localhost,.example.test",
        }

        validated = RuntimeSecurityPolicy.default().validate_provider_env(provider_env)

        self.assertIsInstance(validated, tuple)
        self.assertEqual(validated, tuple(sorted(provider_env.items())))

    def test_absolute_deny_keys_fail_closed_before_local_allowlist(self) -> None:
        policy = RuntimeSecurityPolicy(extra_provider_env_keys=("VENDOR_REGION",))
        for key in ABSOLUTE_DENY_CASES + ["GIT_CONFIG_FAKE"]:
            with self.subTest(key=key), self.assertRaises(RuntimeSecurityError) as raised:
                policy.validate_provider_env({key: "fixture-secret"})
            self.assertEqual(raised.exception.code, "provider_env_forbidden")

    def test_unknown_key_requires_local_allowlist_with_safe_sorted_names(self) -> None:
        with self.assertRaises(RuntimeSecurityError) as raised:
            RuntimeSecurityPolicy.default().validate_provider_env(
                {"Z_VENDOR": "secret-z", "A_VENDOR": "secret-a"}
            )

        self.assertEqual(raised.exception.code, "provider_env_unrecognized")
        self.assertEqual(raised.exception.safe_details["keys"], ("A_VENDOR", "Z_VENDOR"))
        self.assertNotIn("secret", json.dumps(raised.exception.to_dict()))

    def test_explicit_non_execution_allowlist_is_accepted(self) -> None:
        validated = RuntimeSecurityPolicy(
            extra_provider_env_keys=("VENDOR_REGION",)
        ).validate_provider_env({"VENDOR_REGION": "cn"})

        self.assertEqual(validated, (("VENDOR_REGION", "cn"),))

    def test_absolute_deny_cannot_be_allowlisted(self) -> None:
        for key in (
            "PATH",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
            "LANG",
            "LC_ALL",
            "DYLD_LIBRARY_PATH",
            "dyld_insert_libraries",
            "CC_ORCHESTRATOR_WORKSPACE_ROOT",
            "cc_orchestrator_workspace_root",
        ):
            with self.subTest(key=key):
                with self.assertRaises(RuntimeSecurityError) as raised:
                    RuntimeSecurityPolicy(extra_provider_env_keys=(key,))
                self.assertEqual(raised.exception.code, "runtime_policy_invalid")

    def test_absolute_deny_prefixes_cannot_be_supplied_with_case_variants(self) -> None:
        policy = RuntimeSecurityPolicy.default()
        for key in (
            "DYLD_LIBRARY_PATH",
            "dyld_library_path",
            "CC_ORCHESTRATOR_WORKSPACE_ROOT",
            "cc_orchestrator_workspace_root",
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeSecurityError) as raised:
                policy.validate_provider_env({key: "fixture-secret"})
            self.assertEqual(raised.exception.code, "provider_env_forbidden")

    def test_provider_environment_rejects_folded_duplicates_nuls_and_size_limits(self) -> None:
        policy = RuntimeSecurityPolicy.default()
        invalid_cases = (
            {"ANTHROPIC_API_KEY": "one", "anthropic_api_key": "two"},
            {"ANTHROPIC_API_KEY\x00": "one"},
            {"ANTHROPIC_API_KEY": "one\x00two"},
            {"ANTHROPIC_API_KEY": "x" * (32 * 1024 + 1)},
            {
                "ANTHROPIC_API_KEY": "x" * (32 * 1024),
                "ANTHROPIC_AUTH_TOKEN": "x" * (32 * 1024),
                "ANTHROPIC_MODEL": "x" * (32 * 1024),
                "ANTHROPIC_DEFAULT_OPUS_MODEL": "x" * (32 * 1024),
                "ANTHROPIC_DEFAULT_SONNET_MODEL": "x",
            },
        )
        for provider_env in invalid_cases:
            with self.subTest(provider_env=tuple(provider_env)), self.assertRaises(
                RuntimeSecurityError
            ) as raised:
                policy.validate_provider_env(provider_env)
            self.assertNotIn("x" * 100, json.dumps(raised.exception.to_dict()))

    def test_provider_environment_serialized_block_size_has_exact_boundaries(self) -> None:
        keys = (
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
        )

        def environment_at_size(total_bytes: int) -> dict[str, str]:
            remaining = total_bytes - sum(len(key.encode("utf-8")) + 2 for key in keys)
            provider_env = {}
            for key in keys:
                value_size = min(remaining, 32 * 1024)
                provider_env[key] = "x" * value_size
                remaining -= value_size
            self.assertEqual(remaining, 0)
            self.assertEqual(
                sum(
                    len(key.encode("utf-8")) + 1 + len(value.encode("utf-8")) + 1
                    for key, value in provider_env.items()
                ),
                total_bytes,
            )
            return provider_env

        policy = RuntimeSecurityPolicy.default()
        accepted = environment_at_size(128 * 1024)
        self.assertEqual(policy.validate_provider_env(accepted), tuple(sorted(accepted.items())))
        rejected = environment_at_size(128 * 1024 + 1)
        with self.assertRaises(RuntimeSecurityError) as raised:
            policy.validate_provider_env(rejected)
        self.assertEqual(raised.exception.code, "provider_env_too_large")


class RuntimeSecurityPolicyConfigTests(unittest.TestCase):
    def write_policy(self, directory: Path, payload: object) -> Path:
        path = directory / "runtime_security.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_loads_example_shape_and_canonical_configured_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            executable = directory / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            policy_path = self.write_policy(
                directory,
                {
                    "schema_version": 1,
                    "runtime_executable": str(executable),
                    "extra_provider_env_keys": ["VENDOR_REGION"],
                    "unsafe_runtimes": [],
                },
            )

            policy = RuntimeSecurityPolicy.load(policy_path)

            self.assertEqual(policy.configured_runtime_path(), executable.resolve())
            self.assertEqual(
                policy.validate_provider_env({"VENDOR_REGION": "cn"}),
                (("VENDOR_REGION", "cn"),),
            )

    def test_policy_load_rejects_malformed_and_unsafe_configurations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            identity = {
                "canonical_path": str(directory / "runtime.exe"),
                "sha256": "a" * 64,
                "size": 1,
                "file_id": [1, 2],
                "target_kind": "native",
                "interpreter_identity": None,
            }
            base = {
                "schema_version": 1,
                "runtime_executable": None,
                "extra_provider_env_keys": [],
                "unsafe_runtimes": [{"runtime_id": "one", "identity": identity}],
            }
            invalid_payloads = [
                "not-json",
                {**base, "schema_version": True},
                {**base, "runtime_executable": "relative.exe"},
                {**base, "extra_provider_env_keys": ["PATH"]},
                {**base, "unsafe_runtimes": base["unsafe_runtimes"] * 2},
                {**base, "unsafe_runtimes": [{"runtime_id": "one", "identity": {**identity, "sha256": "bad"}}]},
                {**base, "unsafe_runtimes": [{"runtime_id": "one", "identity": {**identity, "canonical_path": "relative.exe"}}]},
                {
                    **base,
                    "unsafe_runtimes": [
                        {
                            "runtime_id": "one",
                            "identity": {
                                **identity,
                                "interpreter_identity": {
                                    **identity,
                                    "interpreter_identity": {
                                        **identity,
                                        "interpreter_identity": {
                                            **identity,
                                            "interpreter_identity": identity,
                                        },
                                    },
                                },
                            },
                        }
                    ],
                },
            ]
            for payload in invalid_payloads:
                with self.subTest(payload_type=type(payload).__name__), self.assertRaises(
                    RuntimeSecurityError
                ) as raised:
                    path = directory / "runtime_security.json"
                    if isinstance(payload, str):
                        path.write_text(payload, encoding="utf-8")
                    else:
                        self.write_policy(directory, payload)
                    RuntimeSecurityPolicy.load(path)
                self.assertEqual(raised.exception.code, "runtime_policy_invalid")

    def test_find_unsafe_runtime_uses_canonical_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = (Path(temp_dir) / "runtime.exe")
            executable.write_text("fixture", encoding="utf-8")
            identity = PinnedExecutableIdentity(
                canonical_path=str(executable.resolve()), sha256="a" * 64, size=7
            )
            policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(
                    ApprovedUnsafeRuntime("fixture", identity),
                )
            )

            self.assertEqual(policy.find_unsafe_runtime(executable.resolve()), policy.unsafe_runtimes[0])


class RuntimeAuthorizationTests(unittest.TestCase):
    def identity_chain(self, executable: Path, depth: int) -> PinnedExecutableIdentity:
        identity = None
        for index in reversed(range(depth)):
            identity = PinnedExecutableIdentity(
                canonical_path=str(executable.resolve()),
                sha256=f"{index + 1:064x}",
                size=index + 1,
                file_id=(index + 1, index + 2),
                target_kind="script" if index else "native",
                interpreter_identity=identity,
            )
        assert identity is not None
        return identity

    def candidate(self, executable: Path, trust_class: str) -> RuntimeExecutableCandidate:
        return RuntimeExecutableCandidate(
            canonical_path=str(executable.resolve()),
            source="fixture-discovery",
            trust_class=trust_class,
        )

    def test_trusted_default_requires_no_unsafe_request_and_decision_binds_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            identity = self.identity_chain(executable, 1)

            first = authorize_runtime(
                candidate=self.candidate(executable, "trusted_default"),
                identity=identity,
                policy=RuntimeSecurityPolicy.default(),
                allow_unsafe_runtime=False,
            )
            second = authorize_runtime(
                candidate=RuntimeExecutableCandidate(
                    canonical_path=str(executable.resolve()),
                    source="other-fixture-discovery",
                    trust_class="trusted_default",
                ),
                identity=identity,
                policy=RuntimeSecurityPolicy.default(),
                allow_unsafe_runtime=False,
            )

            self.assertEqual(first.trust_level, "trusted_default")
            self.assertNotEqual(first.policy_decision_id, second.policy_decision_id)

    def test_unsafe_decision_binds_the_complete_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            identity = self.identity_chain(executable, 1)
            candidate = self.candidate(executable, "local_configured")
            first_policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", identity),)
            )
            second_policy = RuntimeSecurityPolicy(
                extra_provider_env_keys=("CUSTOM_PROVIDER_OPTION",),
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", identity),),
            )

            first = authorize_runtime(
                candidate=candidate,
                identity=identity,
                policy=first_policy,
                allow_unsafe_runtime=True,
            )
            second = authorize_runtime(
                candidate=candidate,
                identity=identity,
                policy=second_policy,
                allow_unsafe_runtime=True,
            )

            self.assertNotEqual(first.policy_decision_id, second.policy_decision_id)

    def test_discovered_path_still_requires_both_unsafe_authorization_factors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            identity = self.identity_chain(executable, 1)
            candidate = self.candidate(executable, "discovered_unpinned")
            approved_policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", identity),)
            )
            cases = (
                (RuntimeSecurityPolicy.default(), False, "runtime_not_trusted"),
                (RuntimeSecurityPolicy.default(), True, "unsafe_runtime_policy_missing"),
                (approved_policy, False, "unsafe_runtime_request_missing"),
            )
            for policy, request_flag, expected_code in cases:
                with self.subTest(expected_code=expected_code), self.assertRaises(
                    RuntimeSecurityError
                ) as raised:
                    authorize_runtime(
                        candidate=candidate,
                        identity=identity,
                        policy=policy,
                        allow_unsafe_runtime=request_flag,
                    )
                self.assertEqual(raised.exception.code, expected_code)

            decision = authorize_runtime(
                candidate=candidate,
                identity=identity,
                policy=approved_policy,
                allow_unsafe_runtime=True,
            )
            self.assertEqual(decision.runtime_id, "local-fixture")
            self.assertEqual(decision.trust_level, "local_unsafe")

    def test_unsafe_runtime_request_approval_requires_a_literal_bool(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            identity = self.identity_chain(executable, 1)
            candidate = self.candidate(executable, "local_configured")
            policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", identity),)
            )

            for request_flag in ("false", "true", 1, 0, None, [], {}):
                with self.subTest(request_flag=repr(request_flag)), self.assertRaises(
                    RuntimeSecurityError
                ) as raised:
                    authorize_runtime(
                        candidate=candidate,
                        identity=identity,
                        policy=policy,
                        allow_unsafe_runtime=request_flag,
                    )
                self.assertEqual(raised.exception.code, "unsafe_runtime_request_invalid")
                self.assertEqual(
                    raised.exception.safe_details["canonical_path"], str(executable.resolve())
                )
                self.assertNotIn("local_unsafe", json.dumps(raised.exception.to_dict()))

    def test_trust_class_is_not_inferred_from_a_matching_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            identity = self.identity_chain(executable, 1)

            with self.assertRaises(RuntimeSecurityError) as raised:
                authorize_runtime(
                    candidate=self.candidate(executable, "unrecognized"),
                    identity=identity,
                    policy=RuntimeSecurityPolicy.default(),
                    allow_unsafe_runtime=False,
                )

            self.assertEqual(raised.exception.code, "runtime_candidate_unrecognized")

    def test_unsafe_runtime_pin_compares_every_recursive_identity_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            pinned = self.identity_chain(executable, 2)
            candidate = self.candidate(executable, "local_configured")
            policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", pinned),)
            )
            mismatches = (
                replace(pinned, canonical_path=str(executable.parent / "other.exe")),
                replace(pinned, sha256="f" * 64),
                replace(pinned, size=999),
                replace(pinned, file_id=(99, 100)),
                replace(pinned, target_kind="wrapper"),
                replace(pinned, interpreter_identity=None),
                replace(
                    pinned,
                    interpreter_identity=replace(pinned.interpreter_identity, sha256="e" * 64),
                ),
            )
            for identity in mismatches:
                with self.subTest(identity=identity), self.assertRaises(
                    RuntimeSecurityError
                ) as raised:
                    authorize_runtime(
                        candidate=candidate,
                        identity=identity,
                        policy=policy,
                        allow_unsafe_runtime=True,
                    )
                self.assertEqual(raised.exception.code, "runtime_identity_changed")

    def test_four_level_pin_rejects_omitted_or_replaced_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "runtime.exe"
            executable.write_text("fixture", encoding="utf-8")
            pinned = self.identity_chain(executable, 4)
            policy = RuntimeSecurityPolicy(
                unsafe_runtimes=(ApprovedUnsafeRuntime("local-fixture", pinned),)
            )
            candidate = self.candidate(executable, "local_configured")
            matching = authorize_runtime(
                candidate=candidate,
                identity=pinned,
                policy=policy,
                allow_unsafe_runtime=True,
            )
            self.assertEqual(matching.trust_level, "local_unsafe")

            omitted = replace(pinned, interpreter_identity=pinned.interpreter_identity.interpreter_identity)
            replaced = replace(
                pinned,
                interpreter_identity=replace(
                    pinned.interpreter_identity,
                    interpreter_identity=self.identity_chain(executable, 1),
                ),
            )
            for identity in (omitted, replaced):
                with self.subTest(identity=identity), self.assertRaises(
                    RuntimeSecurityError
                ) as raised:
                    authorize_runtime(
                        candidate=candidate,
                        identity=identity,
                        policy=policy,
                        allow_unsafe_runtime=True,
                    )
                self.assertEqual(raised.exception.code, "runtime_identity_changed")


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

    def test_error_defensively_freezes_nested_input(self) -> None:
        nested_input = {
            "metadata": {"blocked": True},
            "keys": ["PATH"],
            "set_like": {"alpha", "beta"},
        }
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details=nested_input,
            suggested_action="Remove the key from CCSwitch.",
        )

        nested_input["metadata"]["blocked"] = False
        nested_input["keys"].append("HOME")
        nested_input["set_like"].add("gamma")

        payload = error.to_dict()
        safe_details = payload["safe_details"]
        self.assertEqual(safe_details["metadata"], {"blocked": True})
        self.assertEqual(safe_details["keys"], ["PATH"])
        self.assertEqual(set(safe_details["set_like"]), {"alpha", "beta"})
        json.dumps(payload)

    def test_to_dict_returns_independent_nested_json_payload(self) -> None:
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details={
                "metadata": {"blocked": True},
                "keys": ["PATH"],
                "set_like": {"alpha", "beta"},
            },
            suggested_action="Remove the key from CCSwitch.",
        )

        first_payload = error.to_dict()
        first_payload["safe_details"]["metadata"]["blocked"] = False
        first_payload["safe_details"]["keys"].append("HOME")
        first_payload["safe_details"]["set_like"].append("gamma")

        second_payload = error.to_dict()
        safe_details = second_payload["safe_details"]
        self.assertEqual(safe_details["metadata"], {"blocked": True})
        self.assertEqual(safe_details["keys"], ["PATH"])
        self.assertEqual(set(safe_details["set_like"]), {"alpha", "beta"})
        json.dumps(first_payload)
        json.dumps(second_payload)
