from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: F401
from runtime_security import (
    ApprovedUnsafeRuntime,
    PinnedExecutableIdentity,
    RuntimeExecutableCandidate,
    RuntimeSecurityError,
    RuntimeSecurityPolicy,
    authorize_runtime,
)


ABSOLUTE_DENY_CASES = [
    "PATH", "Path", "PATHEXT", "COMSPEC", "SHELL", "CLAUDE_CODE_BIN",
    "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "CC_ORCHESTRATOR_ARTIFACT_ROOT", "BASH_ENV", "ENV", "ZDOTDIR",
    "PSModulePath", "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
    "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL", "GIT_SSH_COMMAND", "SSLKEYLOGFILE",
]


class ProviderEnvironmentPolicyTests(unittest.TestCase):
    def test_supported_provider_keys_are_preserved_in_sorted_immutable_pairs(self) -> None:
        provider_env = {
            "ANTHROPIC_API_KEY": "test-api-key",
            "ANTHROPIC_AUTH_TOKEN": "test-auth-token",
            "ANTHROPIC_MODEL": "claude-test",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "opus-test",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "sonnet-test",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "haiku-test",
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
        with self.assertRaises(RuntimeSecurityError) as raised:
            RuntimeSecurityPolicy(extra_provider_env_keys=("PATH",))
        self.assertEqual(raised.exception.code, "runtime_policy_invalid")

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
