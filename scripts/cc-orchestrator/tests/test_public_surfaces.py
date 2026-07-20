from __future__ import annotations

import asyncio
import ast
import contextlib
import hashlib
import importlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: E402

import cc_orchestrator as orchestrator  # noqa: E402
from secure_payload_store import (  # noqa: E402
    InMemorySecurePayloadStore,
    SecurePayloadStoreError,
    SecurePayloadStoreUnavailable,
)


PUBLIC_APIS = (
    "send_instruction",
    "spawn_role_team",
    "cross_review",
    "benchmark_model",
    "benchmark_suite",
    "queue_submit",
    "run_visible_agent",
    "workflow_run",
)

CLI_COMMANDS = (
    "run",
    "run-streaming",
    "run-visible",
    "send-instruction",
    "spawn-role-team",
    "cross-review",
    "benchmark-model",
    "benchmark-suite",
    "queue-submit",
    "workflow-run",
)


class PublicSurfaceContractTests(unittest.TestCase):
    def test_identity_risk_projection_counts_worker_and_child_states(self) -> None:
        risky = (
            {"worker_identity_state": "unverified"},
            {"child_identity_state": "mismatch"},
            {"status": "identity_unverified"},
            {
                "security_error": {
                    "code": "process_identity_mismatch"
                }
            },
        )
        for item in risky:
            with self.subTest(item=item):
                self.assertTrue(orchestrator._identity_risk_observed(item))
        self.assertFalse(
            orchestrator._identity_risk_observed(
                {
                    "worker_identity_state": "match",
                    "child_identity_state": "exited",
                    "status": "succeeded",
                }
            )
        )

    def test_launch_capable_python_apis_end_with_request_approval(self) -> None:
        for name in PUBLIC_APIS:
            with self.subTest(name=name):
                signature = inspect.signature(getattr(orchestrator, name))
                parameter = list(signature.parameters.values())[-1]
                self.assertEqual(parameter.name, "allow_unsafe_runtime")
                self.assertIs(parameter.default, False)

    def test_benchmark_model_forwards_exact_approval(self) -> None:
        provider = orchestrator.Provider(
            id="fixture",
            name="Fixture",
            app_type="claude",
            settings={"env": {}, "model": "fixture-model"},
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        with (
            patch.object(orchestrator, "resolve_route", return_value={"profile": "fixture", "model_override": None}),
            patch.object(orchestrator, "get_provider", return_value=provider),
            patch.object(orchestrator, "run_agent", return_value={"exit_code": 0, "run_id": "run-1", "stdout_tail": ""}) as launch,
            patch.object(orchestrator, "append_model_benchmark_history"),
            patch.object(orchestrator, "build_model_registry"),
        ):
            orchestrator.benchmark_model(execute=True, allow_unsafe_runtime=True)
        self.assertIs(launch.call_args.kwargs["allow_unsafe_runtime"], True)

    def test_benchmark_suite_forwards_exact_approval_to_every_item(self) -> None:
        with (
            patch.object(
                orchestrator, "benchmark_model", return_value={"ok": True}
            ) as benchmark,
            patch.object(orchestrator, "append_model_benchmark_history"),
            patch.object(orchestrator, "build_model_registry"),
        ):
            orchestrator.benchmark_suite(execute=True, allow_unsafe_runtime=True)
        self.assertEqual(benchmark.call_count, len(orchestrator.BENCHMARK_SUITE_TASKS))
        self.assertTrue(all(call.kwargs["allow_unsafe_runtime"] is True for call in benchmark.call_args_list))

    def test_mock_workflow_accepts_but_does_not_consume_approval(self) -> None:
        spec = {
            "schema_version": 1,
            "id": "surface-fixture",
            "nodes": {
                "review": {
                    "type": "worker",
                    "role": "review",
                    "task": "review fixture",
                    "outputs": "review_handoff",
                }
            },
        }
        with tempfile.TemporaryDirectory(prefix="workflow-surface-") as temp:
            root = Path(temp)
            path = root / "workflow.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            with (
                patch.object(orchestrator, "run_streaming_agent") as launch,
                patch.object(orchestrator, "prepare_worker_launch") as prepare,
            ):
                result = orchestrator.workflow_run(
                    path,
                    task="fixture",
                    cwd=root,
                    mock=True,
                    allow_unsafe_runtime=True,
                )
        self.assertTrue(result["ok"])
        launch.assert_not_called()
        prepare.assert_not_called()

    def test_real_workflow_keeps_stable_disabled_error(self) -> None:
        with self.assertRaisesRegex(orchestrator.OrchestratorError, "Real workflow-run is not enabled"):
            orchestrator.workflow_run(
                "unused.json",
                task="fixture",
                mock=False,
                allow_unsafe_runtime=True,
            )

    def test_cli_launch_commands_define_request_scoped_flag(self) -> None:
        source = (ORCHESTRATOR_DIR / "cc_orchestrator.py").read_text(encoding="utf-8")
        for command in CLI_COMMANDS:
            with self.subTest(command=command):
                marker = f'sub.add_parser("{command}")'
                start = source.index(marker)
                next_parser = source.find("sub.add_parser(", start + len(marker))
                section = source[start : next_parser if next_parser >= 0 else len(source)]
                self.assertIn('"--allow-unsafe-runtime"', section)

    def test_direct_launch_calls_always_name_request_approval(self) -> None:
        source = (ORCHESTRATOR_DIR / "cc_orchestrator.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        offenders: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"run_agent", "run_streaming_agent", "run_visible_agent"}:
                continue
            ancestor = parents.get(node)
            while ancestor is not None and not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ancestor = parents.get(ancestor)
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)) and ancestor.name == "mock_stream_test":
                continue
            if not any(keyword.arg == "allow_unsafe_runtime" for keyword in node.keywords):
                offenders.append(node.lineno)
        self.assertEqual(offenders, [], f"launch calls missing named approval at lines {offenders}")

    def test_mcp_models_and_error_contract_are_security_aware(self) -> None:
        source = (ORCHESTRATOR_DIR / "server.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        classes = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }
        for name in (
            "RunAgentInput",
            "QueueSubmitInput",
            "SpawnRoleTeamInput",
            "SendInstructionInput",
            "CrossReviewInput",
            "BenchmarkModelInput",
            "BenchmarkSuiteInput",
            "WorkflowRunInput",
        ):
            with self.subTest(model=name):
                fields = {
                    target.id
                    for statement in classes[name].body
                    if isinstance(statement, ast.AnnAssign)
                    and isinstance((target := statement.target), ast.Name)
                }
                self.assertIn("allow_unsafe_runtime", fields)
        self.assertIn("RuntimeSecurityError", source)
        self.assertIn('"security_error": exc.to_dict()', source)

    def test_cli_and_mcp_public_calls_name_request_approval(self) -> None:
        expected = {
            "run_agent",
            "run_streaming_agent",
            "run_visible_agent",
            "send_instruction",
            "spawn_role_team",
            "cross_review",
            "benchmark_model",
            "benchmark_suite",
            "queue_submit",
            "workflow_run",
        }
        for filename in ("cc_orchestrator.py", "server.py"):
            tree = ast.parse((ORCHESTRATOR_DIR / filename).read_text(encoding="utf-8"))
            parents: dict[ast.AST, ast.AST] = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            offenders = []
            for node in ast.walk(tree):
                if (
                    not isinstance(node, ast.Call)
                    or not isinstance(node.func, ast.Name)
                    or node.func.id not in expected
                    or any(keyword.arg == "allow_unsafe_runtime" for keyword in node.keywords)
                ):
                    continue
                ancestor = parents.get(node)
                while ancestor is not None and not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ancestor = parents.get(ancestor)
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)) and ancestor.name == "mock_stream_test":
                    continue
                offenders.append((node.func.id, node.lineno))
            self.assertEqual(offenders, [], f"{filename} missing approval forwarding: {offenders}")

    def test_cli_launch_commands_forward_the_exact_request_value(self) -> None:
        cases = (
            ("run_agent", ["run", "fixture-task"]),
            ("run_streaming_agent", ["run-streaming", "fixture-task"]),
            ("run_visible_agent", ["run-visible", "fixture-task"]),
            (
                "send_instruction",
                ["send-instruction", "--run-id", "run-fixture", "continue"],
            ),
            ("spawn_role_team", ["spawn-role-team", "fixture-task"]),
            ("cross_review", ["cross-review", "--run-id", "run-fixture"]),
            ("benchmark_model", ["benchmark-model"]),
            ("benchmark_suite", ["benchmark-suite"]),
            ("queue_submit", ["queue-submit", "fixture-task"]),
            (
                "workflow_run",
                ["workflow-run", "--file", "fixture.json", "--task", "fixture-task"],
            ),
        )
        for target, argv in cases:
            for approved in (False, True):
                with self.subTest(target=target, approved=approved):
                    requested = ["cc-orchestrator", *argv]
                    if approved:
                        requested.append("--allow-unsafe-runtime")
                    with (
                        patch.object(sys, "argv", requested),
                        patch.object(
                            orchestrator, target, return_value={"ok": True}
                        ) as launch,
                        patch.object(orchestrator, "print_json"),
                    ):
                        exit_code = orchestrator.main()
                    self.assertEqual(exit_code, 0)
                    self.assertIs(
                        launch.call_args.kwargs["allow_unsafe_runtime"], approved
                    )

    def test_mcp_launch_tools_forward_the_exact_request_value(self) -> None:
        server = importlib.import_module("server")
        cases = (
            ("cc_run_agent", "run_agent", server.RunAgentInput, {"task": "fixture"}),
            (
                "cc_run_streaming_agent",
                "run_streaming_agent",
                server.RunStreamingAgentInput,
                {"task": "fixture"},
            ),
            (
                "cc_run_visible_agent",
                "run_visible_agent",
                server.RunAgentInput,
                {"task": "fixture"},
            ),
            (
                "cc_send_instruction",
                "send_instruction",
                server.SendInstructionInput,
                {"run_id": "run-fixture", "instruction": "continue"},
            ),
            (
                "cc_spawn_role_team",
                "spawn_role_team",
                server.SpawnRoleTeamInput,
                {"task": "fixture"},
            ),
            (
                "cc_cross_review",
                "cross_review",
                server.CrossReviewInput,
                {"run_ids": ["run-fixture"]},
            ),
            (
                "cc_benchmark_model",
                "benchmark_model",
                server.BenchmarkModelInput,
                {},
            ),
            (
                "cc_benchmark_suite",
                "benchmark_suite",
                server.BenchmarkSuiteInput,
                {},
            ),
            (
                "cc_queue_submit",
                "queue_submit",
                server.QueueSubmitInput,
                {"task": "fixture"},
            ),
            (
                "cc_workflow_run",
                "workflow_run",
                server.WorkflowRunInput,
                {"file": "fixture.json", "task": "fixture", "mock": True},
            ),
        )
        for handler_name, target, model, values in cases:
            for approved in (False, True):
                with self.subTest(handler=handler_name, approved=approved):
                    params = model(**values, allow_unsafe_runtime=approved)
                    with patch.object(
                        server, target, return_value={"ok": True}
                    ) as launch:
                        response = asyncio.run(getattr(server, handler_name)(params))
                    self.assertTrue(json.loads(response)["ok"])
                    self.assertIs(
                        launch.call_args.kwargs["allow_unsafe_runtime"], approved
                    )

    def test_cli_and_mcp_preserve_structured_runtime_security_errors(self) -> None:
        from runtime_security import RuntimeSecurityError

        error = RuntimeSecurityError(
            code="runtime_not_trusted",
            message="Runtime approval is missing.",
            safe_details={"source": "fixture"},
            suggested_action="Approve the pinned runtime for this request.",
        )
        with (
            patch.object(sys, "argv", ["cc-orchestrator", "run", "fixture"]),
            patch.object(orchestrator, "run_agent", side_effect=error),
            patch.object(orchestrator, "print_json") as output,
        ):
            self.assertEqual(orchestrator.main(), 2)
        cli_payload = output.call_args.args[0]
        self.assertEqual(
            cli_payload["security_error"]["code"], "runtime_not_trusted"
        )

        server = importlib.import_module("server")
        with patch.object(server, "run_agent", side_effect=error):
            response = asyncio.run(
                server.cc_run_agent(server.RunAgentInput(task="fixture"))
            )
        mcp_payload = json.loads(response)
        self.assertEqual(
            mcp_payload["security_error"]["code"], "runtime_not_trusted"
        )
        self.assertEqual(mcp_payload["next_step"], error.suggested_action)

    def test_cli_launch_results_use_security_timeout_and_child_exit_codes(
        self,
    ) -> None:
        commands = (
            ("run_agent", ["run", "fixture"]),
            ("run_streaming_agent", ["run-streaming", "fixture"]),
            ("run_visible_agent", ["run-visible", "fixture"]),
            (
                "send_instruction",
                ["send-instruction", "--run-id", "run-fixture", "fixture"],
            ),
            ("spawn_role_team", ["spawn-role-team", "fixture"]),
            (
                "cross_review",
                ["cross-review", "--run-id", "run-fixture"],
            ),
            ("benchmark_model", ["benchmark-model", "--execute"]),
            ("benchmark_suite", ["benchmark-suite", "--execute"]),
            ("queue_submit", ["queue-submit", "fixture"]),
            ("queue_tick", ["queue-tick"]),
            (
                "workflow_run",
                [
                    "workflow-run",
                    "--file",
                    "fixture.json",
                    "--task",
                    "fixture",
                ],
            ),
        )
        results = (
            (
                {
                    "ok": False,
                    "status": "blocked_runtime_security",
                    "security_error": {"code": "runtime_not_trusted"},
                },
                2,
            ),
            (
                {
                    "ok": False,
                    "status": "timed_out",
                    "timed_out": True,
                    "exit_code": 124,
                },
                124,
            ),
            (
                {
                    "ok": False,
                    "status": "failed",
                    "child_pid": 4242,
                    "exit_code": 7,
                },
                7,
            ),
            (
                {
                    "ok": False,
                    "status": "failed",
                    "child_pid": 4242,
                    "exit_code": 7,
                    "security_error": {"code": "runtime_identity_changed"},
                },
                2,
            ),
            (
                {
                    "ok": False,
                    "tasks": [
                        {
                            "run_id": "run-timeout-fixture",
                            "status": "timed_out",
                            "timed_out": True,
                            "exit_code": 124,
                        },
                        {
                            "security_error": {
                                "code": "runtime_not_trusted"
                            }
                        },
                        {
                            "run_id": "run-child-fixture",
                            "child_pid": 4242,
                            "exit_code": 9,
                        },
                    ],
                },
                124,
            ),
        )
        for target, argv in commands:
            for result, expected in results:
                with self.subTest(target=target, expected=expected), patch.object(
                    sys, "argv", ["cc-orchestrator", *argv]
                ), patch.object(
                    orchestrator, target, return_value=result
                ), patch.object(orchestrator, "print_json"):
                    self.assertEqual(orchestrator.main(), expected)
        nested_results = (
            ({"ok": False, "runs": [{"timed_out": True}]}, 124),
            (
                {
                    "ok": False,
                    "tasks": [
                        {"security_error": {"code": "runtime_not_trusted"}}
                    ],
                },
                2,
            ),
            (
                {
                    "ok": False,
                    "tasks": [
                        {"run_id": "run-fixture", "exit_code": 9}
                    ],
                },
                9,
            ),
            (
                {
                    "ok": False,
                    "tasks": [
                        {
                            "run_id": "run-fixture",
                            "status": "failed",
                            "timed_out": False,
                            "exit_code": 124,
                        },
                        {
                            "security_error": {
                                "code": "runtime_not_trusted"
                            }
                        },
                    ],
                },
                2,
            ),
            (
                {
                    "ok": False,
                    "tasks": [
                        {"timed_out": "false", "status": "failed"},
                        {
                            "security_error": {
                                "code": "runtime_not_trusted"
                            }
                        },
                    ],
                },
                2,
            ),
        )
        for result, expected in nested_results:
            with self.subTest(nested_expected=expected):
                self.assertEqual(
                    orchestrator._cli_launch_result_exit_code(result),
                    expected,
                )
        for target, argv in (
            ("stream_worker", ["_stream-worker", "--run-id", "run-fixture"]),
            ("visible_worker", ["_visible-worker", "--run-id", "run-fixture"]),
        ):
            with self.subTest(target=target), patch.object(
                sys, "argv", ["cc-orchestrator", *argv]
            ), patch.object(
                orchestrator,
                target,
                return_value={
                    "ok": False,
                    "security_error": {"code": "worker_protocol_invalid"},
                },
            ), patch.object(orchestrator, "print_json"):
                self.assertEqual(orchestrator.main(), 0)

    def test_every_stable_security_code_has_matching_cli_and_mcp_envelopes(
        self,
    ) -> None:
        from runtime_security import (
            SECURITY_AUDIT_POLICY,
            RuntimeSecurityError,
        )

        server = importlib.import_module("server")
        for code, policy in SECURITY_AUDIT_POLICY.items():
            with self.subTest(code=code):
                error = RuntimeSecurityError(
                    code=code,
                    message="A guarded runtime security decision was rejected.",
                    safe_details={"component": "fixture"},
                    suggested_action=policy["recommended_action"],
                )
                with patch.object(
                    sys, "argv", ["cc-orchestrator", "run", "fixture"]
                ), patch.object(
                    orchestrator, "run_agent", side_effect=error
                ), patch.object(orchestrator, "print_json") as output:
                    self.assertEqual(orchestrator.main(), 2)
                cli = output.call_args.args[0]
                mcp = json.loads(server._error(error))
                self.assertEqual(cli["security_error"], error.to_dict())
                self.assertEqual(mcp["security_error"], error.to_dict())
                self.assertEqual(mcp["next_step"], policy["recommended_action"])

    def test_provider_endpoint_projection_is_shared_by_python_and_mcp(self) -> None:
        endpoint = (
            "https://user:pass@Example.Invalid:8443/private/path"
            "?token=query-secret#fragment-secret"
        )
        projected = "https://example.invalid:8443"
        self.assertEqual(orchestrator.project_public_endpoint(endpoint), projected)
        nested = orchestrator.project_public_endpoint_values(
            {
                "base_url": endpoint,
                "items": [
                    endpoint,
                    "ftp://user:pass@example.invalid/private?token=secret",
                    "file://user:pass/private?token=secret",
                    "mailto:user@example.invalid?subject=private",
                    "ordinary text",
                ],
                "callback_url": {
                    "primary": "file://private/path",
                },
                "nested": {"url": "ftp://private/path"},
            }
        )
        self.assertEqual(nested["base_url"], projected)
        self.assertEqual(
            nested["items"],
            [projected, "[REDACTED]", "[REDACTED]", "[REDACTED]", "ordinary text"],
        )
        self.assertEqual(nested["callback_url"]["primary"], "[REDACTED]")
        self.assertEqual(nested["nested"]["url"], "[REDACTED]")
        for unsafe_endpoint in (
            "ftp://user:pass@example.invalid/private?token=secret",
            "file://user:pass/private?token=secret",
            "user:pass@example.invalid/private?token=secret",
            "not a valid endpoint",
        ):
            with self.subTest(endpoint=unsafe_endpoint):
                self.assertEqual(
                    orchestrator.project_public_endpoint(unsafe_endpoint),
                    "[REDACTED]",
                )
                self.assertEqual(
                    orchestrator.project_public_endpoint_values(
                        {"proxy_url": unsafe_endpoint}
                    )["proxy_url"],
                    "[REDACTED]",
                )
                self.assertEqual(
                    orchestrator.project_public_endpoint_values(
                        {"endpoint": {"primary": unsafe_endpoint}}
                    )["endpoint"]["primary"],
                    "[REDACTED]",
                )

        for malformed in (
            "https://example.invalid\\private-secret/path",
            "https://example.invalid private-secret/path",
            "https://example.invalid/%ZZ/private-secret",
            "https://example.invalid:99999/private-secret",
            "https://example.invalid:0/private-secret",
            "https://example.invalid:",
            "https://example.invalid:/private-secret",
            "https://[::1]garbage/private-secret",
        ):
            with self.subTest(malformed=malformed):
                self.assertEqual(
                    orchestrator.project_public_endpoint(malformed),
                    "[REDACTED]",
                )
        self.assertEqual(
            orchestrator.project_public_endpoint_values({"endpoint": 42})[
                "endpoint"
            ],
            "[REDACTED]",
        )
        secret_uri = (
            "https://alice:fixture-pass@example.invalid/private/path"
            "?token=fixture-query"
        )
        projected_envelope = orchestrator.project_public_endpoint_values(
            {
                secret_uri: "mapping-key-value",
                "reason": f"prefix {secret_uri} suffix",
                "windows_path": r"C:\Users\fixture\project",
            }
        )
        serialized_envelope = json.dumps(projected_envelope)
        self.assertNotIn("fixture-pass", serialized_envelope)
        self.assertNotIn("private/path", serialized_envelope)
        self.assertNotIn("fixture-query", serialized_envelope)
        self.assertNotIn(secret_uri, projected_envelope)
        self.assertNotIn("mapping-key-value", serialized_envelope)
        self.assertEqual(projected_envelope["reason"], "[REDACTED]")
        self.assertEqual(
            projected_envelope["windows_path"], r"C:\Users\fixture\project"
        )
        self.assertEqual(
            orchestrator.project_public_endpoint_values(
                {"windows_path": r"C:relative\project"}
            )["windows_path"],
            r"C:relative\project",
        )
        single_letter_uri = (
            "x://alice:fixture-pass@example.invalid/private/path"
            "?token=fixture-query"
        )
        self.assertEqual(
            orchestrator.project_public_endpoint_values(
                {"reason": single_letter_uri}
            )["reason"],
            "[REDACTED]",
        )
        opaque_single_letter_uri = (
            "x:alice:fixture-pass@example.invalid/private?token=fixture-query"
        )
        projected_opaque = orchestrator.project_public_endpoint_values(
            {
                "reason": opaque_single_letter_uri,
                opaque_single_letter_uri: "opaque-mapping-key-value",
            }
        )
        self.assertEqual(projected_opaque, {"reason": "[REDACTED]"})

        server = importlib.import_module("server")
        provider = orchestrator.Provider(
            id="endpoint-fixture",
            name="Endpoint Fixture",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_BASE_URL": endpoint,
                    "ANTHROPIC_MODEL": "fixture-model",
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[endpoint],
        )
        route = {
            "role": "testing",
            "task_type": "test",
            "profile": provider.id,
            "model_override": None,
            "permission_mode": "plan",
            "timeout_seconds": 30,
            "reason": "fixture",
            "route": {},
            "auto_selection": None,
            "selection_role": "testing",
        }
        with patch.object(server, "resolve_route", return_value=route), patch.object(
            server, "get_provider", return_value=provider
        ):
            response = asyncio.run(
                server.cc_pick_profile(server.PickProfileInput())
            )
        payload = response
        self.assertIn(projected, payload)
        for forbidden in (
            "user",
            "pass",
            "private/path",
            "query-secret",
            "fragment-secret",
        ):
            self.assertNotIn(forbidden, payload)

        malicious_provider = orchestrator.Provider(
            id=secret_uri,
            name=f"provider {secret_uri}",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_BASE_URL": secret_uri,
                    "ANTHROPIC_MODEL": secret_uri,
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[secret_uri],
        )
        malicious_route = {
            **route,
            "profile": secret_uri,
            "reason": f"selected from {secret_uri}",
        }
        with patch.object(
            server, "resolve_route", return_value=malicious_route
        ), patch.object(
            server, "get_provider", return_value=malicious_provider
        ):
            for response_format in (
                server.ResponseFormat.JSON,
                server.ResponseFormat.MARKDOWN,
            ):
                response = asyncio.run(
                    server.cc_pick_profile(
                        server.PickProfileInput(
                            response_format=response_format
                        )
                    )
                )
                for forbidden in (
                    "fixture-pass",
                    "private/path",
                    "fixture-query",
                ):
                    self.assertNotIn(forbidden, response)

        with patch("builtins.print") as output:
            orchestrator.print_json(
                {"reason": f"selected from {secret_uri}", secret_uri: "x"}
            )
        rendered_cli = output.call_args.args[0]
        self.assertNotIn("fixture-pass", rendered_cli)
        self.assertNotIn("private/path", rendered_cli)
        self.assertNotIn("fixture-query", rendered_cli)

        with patch.object(
            sys, "argv", ["cc-orchestrator", "pick"]
        ), patch.object(
            orchestrator, "resolve_route", return_value=route
        ), patch.object(
            orchestrator, "get_provider", return_value=provider
        ), patch.object(orchestrator, "print_json") as cli_output:
            self.assertEqual(orchestrator.main(), 0)
        cli_payload = json.dumps(
            cli_output.call_args.args[0], ensure_ascii=False
        )
        self.assertIn(projected, cli_payload)
        for forbidden in (
            "user",
            "pass",
            "private/path",
            "query-secret",
            "fragment-secret",
        ):
            self.assertNotIn(forbidden, cli_payload)

    def test_punctuation_prefixed_https_uri_cannot_bypass_projection(self) -> None:
        secret_uri = (
            "https://prefix-user:prefix-pass@example.invalid/private/path"
            "?token=prefix-token#prefix-fragment"
        )
        for prefix in (".", "+"):
            with self.subTest(prefix=prefix):
                decorated_uri = f"{prefix}{secret_uri}"
                projected = orchestrator.project_public_endpoint_values(
                    {
                        "reason": decorated_uri,
                        "callback_url": decorated_uri,
                        decorated_uri: "mapping-value-must-not-survive",
                    }
                )
                self.assertEqual(projected["reason"], "[REDACTED]")
                self.assertEqual(projected["callback_url"], "[REDACTED]")
                self.assertNotIn(decorated_uri, projected)
                serialized = json.dumps(projected, ensure_ascii=False)
                for forbidden in (
                    "prefix-user",
                    "prefix-pass",
                    "private/path",
                    "prefix-token",
                    "prefix-fragment",
                    "mapping-value-must-not-survive",
                ):
                    self.assertNotIn(forbidden, serialized)

    def test_url_and_uri_contexts_project_nested_and_non_string_values(
        self,
    ) -> None:
        secret_uri = (
            "https://nested-user:nested-pass@example.invalid/private/path"
            "?token=nested-query#nested-fragment"
        )
        projected = orchestrator.project_public_endpoint_values(
            {
                "callback_url": {
                    "primary": secret_uri,
                    "credentials": {
                        "username": "plain-nested-user",
                        "password": "plain-nested-pass",
                    },
                    "candidates": [8443, False, {"token": "plain-token"}, None],
                },
                "redirect_uri": 42,
            }
        )
        self.assertEqual(
            projected,
            {
                "callback_url": {
                    "primary": "https://example.invalid",
                    "credentials": {
                        "username": "[REDACTED]",
                        "password": "[REDACTED]",
                    },
                    "candidates": [
                        "[REDACTED]",
                        "[REDACTED]",
                        {"token": "[REDACTED]"},
                        None,
                    ],
                },
                "redirect_uri": "[REDACTED]",
            },
        )
        serialized = json.dumps(projected, ensure_ascii=False)
        for forbidden in (
            "nested-user",
            "nested-pass",
            "private/path",
            "nested-query",
            "nested-fragment",
            "plain-token",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_model_score_markdown_and_reports_apply_final_uri_projection(
        self,
    ) -> None:
        server = importlib.import_module("server")
        malicious_uri = (
            "https://report-user:report-pass@example.invalid/private/model"
            "?token=report-token#report-fragment"
        )
        safe_origin = "https://example.invalid"
        forbidden_values = (
            "report-user",
            "report-pass",
            "private/model",
            "report-token",
            "report-fragment",
        )
        scores = {
            "models": [
                {
                    "model": malicious_uri,
                    "profile_name": malicious_uri,
                    "overall": 9.5,
                    "role_scores": {"testing": 9.5},
                }
            ]
        }
        plan = {
            "steps": [
                {
                    "role": "testing",
                    "profile": malicious_uri,
                    "model": malicious_uri,
                    "permission_mode": "plan",
                    "selection_score": 9.5,
                }
            ]
        }

        with patch.object(server, "score_models", return_value=scores):
            markdown = asyncio.run(
                server.cc_score_models(
                    server.ListProfilesInput(
                        response_format=server.ResponseFormat.MARKDOWN
                    )
                )
            )
        self.assertIn(safe_origin, markdown)
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, markdown)

        with tempfile.TemporaryDirectory(prefix="report-projection-") as temp:
            report_dir = Path(temp)
            with patch.object(
                orchestrator, "score_models", return_value=scores
            ), patch.object(
                orchestrator, "run_workflow_plan", return_value=plan
            ):
                result = orchestrator.write_reports(output_dir=report_dir)

            persisted_scores = json.loads(
                (report_dir / "model_scores.json").read_text(encoding="utf-8")
            )
            persisted_strategy = (
                report_dir / "multi_agent_strategy.md"
            ).read_text(encoding="utf-8")

        self.assertEqual(persisted_scores["models"][0]["model"], safe_origin)
        self.assertEqual(
            persisted_scores["models"][0]["profile_name"], safe_origin
        )
        self.assertEqual(
            result["workflow_plan"]["steps"][0]["profile"], safe_origin
        )
        self.assertEqual(
            result["workflow_plan"]["steps"][0]["model"], safe_origin
        )
        self.assertIn(safe_origin, persisted_strategy)

        public_outputs = {
            "persisted_scores": json.dumps(
                persisted_scores, ensure_ascii=False
            ),
            "persisted_strategy": persisted_strategy,
            "returned_result": json.dumps(result, ensure_ascii=False),
        }
        for surface, content in public_outputs.items():
            for forbidden in forbidden_values:
                with self.subTest(surface=surface, forbidden=forbidden):
                    self.assertNotIn(forbidden, content)

    def test_mock_runtime_fixture_is_not_a_public_request_field(self) -> None:
        server = importlib.import_module("server")
        with self.assertRaises(Exception):
            server.RunAgentInput(task="fixture", test_runtime_candidate="forged")
        self.assertIsNone(orchestrator._TEST_ONLY_RUNTIME_CANDIDATE.get())
        source = inspect.getsource(orchestrator.main)
        self.assertNotIn("test-runtime-candidate", source)

    def test_follow_up_prepares_before_stop_and_forwards_exact_approval(self) -> None:
        events: list[str] = []
        metadata = {
            "role": "review",
            "task_type": "review",
            "cwd": str(Path.cwd()),
            "timeout_seconds": 120,
            "allow_write": False,
            "profile": {"name": "fixture", "model": "fixture-model"},
            "output_budget": {},
        }
        with tempfile.TemporaryDirectory(prefix="follow-up-") as temp:
            run_dir = Path(temp)
            (run_dir / "events.ndjson").write_text("", encoding="utf-8")
            prepared = SimpleNamespace()
            with (
                patch.object(orchestrator, "poll_run", return_value={"status": {"active": True, "status": "running"}}),
                patch.object(orchestrator, "safe_run_dir", return_value=run_dir),
                patch.object(orchestrator, "read_metadata", return_value=metadata),
                patch.object(orchestrator, "_prepare_streaming_agent", side_effect=lambda **kwargs: events.append(f"prepare:{kwargs['allow_unsafe_runtime']}") or prepared),
                patch.object(orchestrator, "stop_run", side_effect=lambda *_args, **_kwargs: events.append("stop") or {"ok": True, "stopped": True, "active": False, "status": "stopped"}),
                patch.object(orchestrator, "run_streaming_agent", side_effect=lambda **kwargs: events.append(f"start:{kwargs['allow_unsafe_runtime']}") or {"run_id": "new", "profile": {"name": "fixture", "model": "fixture-model"}}),
                patch.object(orchestrator, "update_metadata"),
            ):
                orchestrator.send_instruction("old", "continue", allow_unsafe_runtime=True)
        self.assertEqual(events, ["prepare:True", "stop", "start:True"])

    def test_follow_up_preflight_failure_does_not_stop_old_run(self) -> None:
        metadata = {
            "role": "review",
            "cwd": str(Path.cwd()),
            "profile": {},
            "output_budget": {},
        }
        with tempfile.TemporaryDirectory(prefix="follow-up-fail-") as temp:
            run_dir = Path(temp)
            with (
                patch.object(orchestrator, "poll_run", return_value={"status": {"active": True, "status": "running"}}),
                patch.object(orchestrator, "safe_run_dir", return_value=run_dir),
                patch.object(orchestrator, "read_metadata", return_value=metadata),
                patch.object(orchestrator, "_prepare_streaming_agent", side_effect=RuntimeError("blocked")),
                patch.object(orchestrator, "stop_run") as stop,
            ):
                with self.assertRaisesRegex(RuntimeError, "blocked"):
                    orchestrator.send_instruction("old", "continue", allow_unsafe_runtime=True)
        stop.assert_not_called()

    def test_follow_up_stop_failure_never_starts_replacement(self) -> None:
        metadata = {
            "role": "review",
            "cwd": str(Path.cwd()),
            "profile": {},
            "output_budget": {},
        }
        with tempfile.TemporaryDirectory(prefix="follow-up-stop-fail-") as temp:
            run_dir = Path(temp)
            with (
                patch.object(orchestrator, "poll_run", return_value={"status": {"active": True, "status": "running"}}),
                patch.object(orchestrator, "safe_run_dir", return_value=run_dir),
                patch.object(orchestrator, "read_metadata", return_value=metadata),
                patch.object(orchestrator, "_prepare_streaming_agent", return_value=object()) as prepare,
                patch.object(orchestrator, "stop_run", return_value={"ok": False, "status": "identity_unverified", "active": True, "stopped": False}),
                patch.object(orchestrator, "run_streaming_agent") as start,
            ):
                result = orchestrator.send_instruction(
                    "old", "continue", allow_unsafe_runtime=True
                )
        prepare.assert_called_once()
        start.assert_not_called()
        self.assertEqual(result["status"], "replacement_stop_failed")

    def test_follow_up_blocked_replacement_is_not_reported_as_success(self) -> None:
        metadata = {
            "role": "review",
            "cwd": str(Path.cwd()),
            "profile": {},
            "output_budget": {},
        }
        blocked = {
            "ok": False,
            "run_id": "blocked-replacement",
            "status": "blocked_runtime_launch",
            "security_error": {
                "code": "runtime_not_trusted",
                "suggested_action": "Approve a pinned runtime.",
            },
        }
        with tempfile.TemporaryDirectory(prefix="follow-up-blocked-") as temp:
            run_dir = Path(temp)
            with (
                patch.object(
                    orchestrator,
                    "poll_run",
                    return_value={"status": {"active": False, "status": "failed"}},
                ),
                patch.object(orchestrator, "safe_run_dir", return_value=run_dir),
                patch.object(orchestrator, "read_metadata", return_value=metadata),
                patch.object(
                    orchestrator, "_prepare_streaming_agent", return_value=object()
                ),
                patch.object(
                    orchestrator, "run_streaming_agent", return_value=blocked
                ),
                patch.object(orchestrator, "update_metadata") as update,
            ):
                result = orchestrator.send_instruction("old", "continue")
        update.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "replacement_launch_failed")
        self.assertEqual(
            result["security_error"]["code"], "runtime_not_trusted"
        )

    def test_team_prepares_every_member_before_first_start(self) -> None:
        events: list[str] = []
        prepared_by_role: dict[str, object] = {}

        def prepare(**kwargs):
            role = kwargs["role"]
            events.append(f"prepare:{role}:{kwargs['allow_unsafe_runtime']}")
            prepared_by_role[role] = object()
            return prepared_by_role[role]

        def start(**kwargs):
            role = kwargs["role"]
            events.append(f"start:{role}:{kwargs['allow_unsafe_runtime']}")
            reservation = kwargs["_admission_reservation"]
            run_id = f"run-{role}"
            reservation.register(run_id)
            return {"run_id": run_id, "status": "starting", "profile": {}}

        @contextlib.contextmanager
        def unlocked():
            yield

        with (
            patch.object(orchestrator, "launch_lock", side_effect=unlocked),
            patch.object(orchestrator, "run_status", return_value={"active_count": 0}),
            patch.object(orchestrator, "max_concurrent_limit", return_value=8),
            patch.object(orchestrator, "_prepare_streaming_agent", side_effect=prepare),
            patch.object(orchestrator, "run_streaming_agent", side_effect=start),
            patch.object(orchestrator, "write_team_manifest", return_value=Path("team.json")),
            patch.object(orchestrator, "_wait_for_team_members_ready", side_effect=lambda _team, runs, **_kwargs: runs),
        ):
            result = orchestrator.spawn_role_team(
                "fixture", roles=["requirements", "security"], allow_unsafe_runtime=True
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            events,
            [
                "prepare:requirements:True",
                "prepare:security:True",
                "start:requirements:True",
                "start:security:True",
            ],
        )

    def test_team_later_preflight_failure_starts_zero_members(self) -> None:
        calls = 0

        def prepare(**_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("second preflight blocked")
            return object()

        @contextlib.contextmanager
        def unlocked():
            yield

        with (
            patch.object(orchestrator, "launch_lock", side_effect=unlocked),
            patch.object(orchestrator, "run_status", return_value={"active_count": 0}),
            patch.object(orchestrator, "max_concurrent_limit", return_value=8),
            patch.object(orchestrator, "_prepare_streaming_agent", side_effect=prepare),
            patch.object(orchestrator, "run_streaming_agent") as start,
            patch.object(orchestrator, "write_team_manifest", return_value=Path("team.json")),
        ):
            result = orchestrator.spawn_role_team(
                "fixture", roles=["requirements", "security"], allow_unsafe_runtime=True
            )
        start.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(result["launched_count"], 0)

    def test_cross_review_prepares_every_reviewer_before_start(self) -> None:
        events: list[str] = []
        with (
            patch.object(orchestrator, "resolve_team_run_ids", return_value=["source"]),
            patch.object(orchestrator, "single_run_status", return_value={"role": "review", "status": "succeeded", "stdout_tail": "done"}),
            patch.object(orchestrator, "_prepare_streaming_agent", side_effect=lambda **kwargs: events.append(f"prepare:{kwargs['role']}") or object()),
            patch.object(orchestrator, "run_streaming_agent", side_effect=lambda **kwargs: events.append(f"start:{kwargs['role']}:{kwargs['allow_unsafe_runtime']}") or {"run_id": f"run-{kwargs['role']}", "status": "starting", "profile": {}}),
        ):
            orchestrator.cross_review(
                ["source"], reviewer_roles=["security", "testing"], allow_unsafe_runtime=True
            )
        self.assertEqual(events, ["prepare:security", "prepare:testing", "start:security:True", "start:testing:True"])

    def test_cross_review_later_preflight_failure_starts_zero_reviewers(self) -> None:
        calls = 0

        def prepare(**_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("review preflight blocked")
            return object()

        with (
            patch.object(orchestrator, "resolve_team_run_ids", return_value=["source"]),
            patch.object(orchestrator, "single_run_status", return_value={"role": "review", "status": "succeeded", "stdout_tail": "done"}),
            patch.object(orchestrator, "_prepare_streaming_agent", side_effect=prepare),
            patch.object(orchestrator, "run_streaming_agent") as start,
        ):
            with self.assertRaisesRegex(RuntimeError, "review preflight blocked"):
                orchestrator.cross_review(
                    ["source"], reviewer_roles=["security", "testing"], allow_unsafe_runtime=True
                )
        start.assert_not_called()

    def test_cross_review_blocked_child_is_not_reported_as_success(self) -> None:
        blocked = {
            "ok": False,
            "run_id": "blocked-review",
            "status": "blocked_runtime_launch",
            "security_error": {
                "code": "runtime_not_trusted",
                "suggested_action": "Approve a pinned runtime.",
            },
        }
        with (
            patch.object(orchestrator, "resolve_team_run_ids", return_value=["source"]),
            patch.object(
                orchestrator,
                "single_run_status",
                return_value={
                    "role": "review",
                    "status": "succeeded",
                    "stdout_tail": "done",
                },
            ),
            patch.object(
                orchestrator, "_prepare_streaming_agent", return_value=object()
            ),
            patch.object(
                orchestrator, "run_streaming_agent", return_value=blocked
            ),
        ):
            result = orchestrator.cross_review(
                ["source"], reviewer_roles=["review"]
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "blocked_runtime_launch")
        self.assertEqual(
            result["security_error"]["code"], "runtime_not_trusted"
        )

    def test_cross_review_rolls_back_prior_reviewers_after_blocked_launch(self) -> None:
        launches = [
            {"run_id": "review-first", "status": "starting", "profile": {}},
            {
                "ok": False,
                "run_id": "review-blocked",
                "status": "blocked_runtime_launch",
                "security_error": {"code": "runtime_not_trusted"},
            },
        ]
        with (
            patch.object(
                orchestrator, "resolve_team_run_ids", return_value=["source"]
            ),
            patch.object(
                orchestrator,
                "single_run_status",
                return_value={
                    "role": "review",
                    "status": "succeeded",
                    "stdout_tail": "done",
                },
            ),
            patch.object(
                orchestrator, "_prepare_streaming_agent", return_value=object()
            ),
            patch.object(
                orchestrator, "run_streaming_agent", side_effect=launches
            ) as launch,
            patch.object(
                orchestrator,
                "stop_run",
                return_value={"ok": True, "stopped": True, "active": False},
            ) as stop,
        ):
            result = orchestrator.cross_review(
                ["source"],
                reviewer_roles=["security", "testing", "review"],
            )
        self.assertEqual(launch.call_count, 2)
        stop.assert_called_once_with("review-first", force=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "rolled_back_partial_launch")
        self.assertEqual(result["rollback"]["failed_stop_count"], 0)
        self.assertEqual(
            result["failed_launch"]["security_error"]["code"],
            "runtime_not_trusted",
        )

    def test_cross_review_reports_incomplete_rollback(self) -> None:
        launches = [
            {"run_id": "review-first", "status": "starting", "profile": {}},
            {"ok": False, "status": "blocked_runtime_launch"},
        ]
        with (
            patch.object(
                orchestrator, "resolve_team_run_ids", return_value=["source"]
            ),
            patch.object(
                orchestrator,
                "single_run_status",
                return_value={"role": "review", "stdout_tail": "done"},
            ),
            patch.object(
                orchestrator, "_prepare_streaming_agent", return_value=object()
            ),
            patch.object(
                orchestrator, "run_streaming_agent", side_effect=launches
            ),
            patch.object(
                orchestrator,
                "stop_run",
                return_value={
                    "ok": False,
                    "status": "cleanup_incomplete",
                    "active": True,
                    "stopped": False,
                },
            ),
        ):
            result = orchestrator.cross_review(
                ["source"], reviewer_roles=["security", "testing"]
            )
        self.assertEqual(result["status"], "rollback_incomplete")
        self.assertEqual(result["rollback"]["failed_stop_count"], 1)

    def test_team_and_benchmark_preserve_structured_launch_errors(self) -> None:
        from runtime_security import RuntimeSecurityError

        error = RuntimeSecurityError(
            code="runtime_not_trusted",
            message="Runtime is not trusted.",
            safe_details={},
            suggested_action="Approve a pinned runtime.",
        )

        @contextlib.contextmanager
        def unlocked():
            yield

        with (
            patch.object(orchestrator, "launch_lock", side_effect=unlocked),
            patch.object(orchestrator, "run_status", return_value={"active_count": 0}),
            patch.object(orchestrator, "max_concurrent_limit", return_value=4),
            patch.object(
                orchestrator, "_prepare_streaming_agent", side_effect=error
            ),
            patch.object(orchestrator, "write_team_manifest", return_value=Path("team.json")),
        ):
            team = orchestrator.spawn_role_team("fixture", roles=["review"])
        self.assertFalse(team["ok"])
        self.assertEqual(team["security_error"]["code"], "runtime_not_trusted")

        provider = orchestrator.Provider(
            id="fixture",
            name="Fixture",
            app_type="claude",
            settings={"env": {}, "model": "fixture-model"},
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        blocked = {
            "ok": False,
            "run_id": "blocked-benchmark",
            "status": "blocked_runtime_launch",
            "security_error": error.to_dict(),
        }
        with (
            patch.object(
                orchestrator,
                "resolve_route",
                return_value={"profile": "fixture", "model_override": None},
            ),
            patch.object(orchestrator, "get_provider", return_value=provider),
            patch.object(orchestrator, "run_agent", return_value=blocked),
            patch.object(orchestrator, "append_model_benchmark_history"),
            patch.object(orchestrator, "build_model_registry"),
        ):
            benchmark = orchestrator.benchmark_model(execute=True)
        self.assertFalse(benchmark["ok"])
        self.assertEqual(
            benchmark["security_error"]["code"], "runtime_not_trusted"
        )

    def test_workflow_stop_preserves_unconfirmed_cleanup_state(self) -> None:
        workflow = {
            "status": "running",
            "nodes": {
                "review": {"state": "running", "run_id": "run-review"}
            },
            "decisions": [],
        }
        persisted: dict[str, object] = {}
        with tempfile.TemporaryDirectory(prefix="workflow-stop-") as temp:
            with (
                patch.object(
                    orchestrator, "safe_workflow_dir", return_value=Path(temp)
                ),
                patch.object(
                    orchestrator, "read_json_file", return_value=workflow
                ),
                patch.object(
                    orchestrator,
                    "stop_run",
                    return_value={
                        "ok": False,
                        "status": "identity_unverified",
                        "active": True,
                        "stopped": False,
                    },
                ),
                patch.object(
                    orchestrator,
                    "write_workflow_status",
                    side_effect=lambda _path, value: persisted.update(value),
                ),
            ):
                result = orchestrator.workflow_stop("workflow-fixture")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "cleanup_incomplete")
        self.assertEqual(
            persisted["nodes"]["review"]["state"],
            "cancel_pending_cleanup",
        )
        self.assertEqual(persisted["status"], "cleanup_incomplete")

    def test_workflow_stop_retries_pending_cleanup_without_false_success(self) -> None:
        workflow = {
            "status": "cleanup_incomplete",
            "nodes": {
                "review": {
                    "state": "cancel_pending_cleanup",
                    "run_id": "run-review",
                }
            },
            "decisions": [],
        }
        with tempfile.TemporaryDirectory(prefix="workflow-restop-") as temp:
            with (
                patch.object(
                    orchestrator, "safe_workflow_dir", return_value=Path(temp)
                ),
                patch.object(
                    orchestrator, "read_json_file", return_value=workflow
                ),
                patch.object(
                    orchestrator,
                    "stop_run",
                    return_value={
                        "ok": False,
                        "status": "identity_unverified",
                        "active": True,
                        "stopped": False,
                    },
                ) as stop,
                patch.object(orchestrator, "write_workflow_status"),
            ):
                result = orchestrator.workflow_stop("workflow-fixture")
        stop.assert_called_once_with("run-review", force=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "cleanup_incomplete")
        self.assertEqual(
            workflow["nodes"]["review"]["state"],
            "cancel_pending_cleanup",
        )

    def test_workflow_retry_keeps_run_evidence_until_cleanup_is_confirmed(self) -> None:
        workflow = {
            "status": "running",
            "nodes": {
                "build": {"state": "running", "run_id": "run-build"}
            },
            "decisions": [],
        }
        with tempfile.TemporaryDirectory(prefix="workflow-retry-") as temp:
            with (
                patch.object(
                    orchestrator, "safe_workflow_dir", return_value=Path(temp)
                ),
                patch.object(
                    orchestrator, "read_json_file", return_value=workflow
                ),
                patch.object(orchestrator, "load_workflow_spec", return_value={}),
                patch.object(
                    orchestrator, "workflow_nodes", return_value={"build": {}}
                ),
                patch.object(
                    orchestrator, "workflow_descendants", return_value=set()
                ),
                patch.object(
                    orchestrator,
                    "stop_run",
                    return_value={
                        "ok": False,
                        "status": "identity_unverified",
                        "active": True,
                        "stopped": False,
                    },
                ) as stop,
                patch.object(orchestrator, "write_workflow_status"),
            ):
                retry = orchestrator.workflow_retry_node(
                    "workflow-fixture", "build"
                )
                stopped = orchestrator.workflow_stop("workflow-fixture")
        self.assertFalse(retry["ok"])
        self.assertEqual(retry["status"], "cleanup_incomplete")
        self.assertEqual(retry["invalidated"], [])
        self.assertEqual(workflow["nodes"]["build"]["run_id"], "run-build")
        self.assertEqual(
            workflow["nodes"]["build"]["state"],
            "cancel_pending_cleanup",
        )
        self.assertFalse(stopped["ok"])
        self.assertEqual(stopped["status"], "cleanup_incomplete")
        self.assertEqual(stop.call_count, 2)

    def test_workflow_retry_invalidates_only_after_confirmed_stop(self) -> None:
        workflow = {
            "status": "running",
            "nodes": {
                "build": {"state": "running", "run_id": "run-build"}
            },
            "decisions": [],
        }
        with tempfile.TemporaryDirectory(prefix="workflow-retry-ok-") as temp:
            with (
                patch.object(
                    orchestrator, "safe_workflow_dir", return_value=Path(temp)
                ),
                patch.object(
                    orchestrator, "read_json_file", return_value=workflow
                ),
                patch.object(orchestrator, "load_workflow_spec", return_value={}),
                patch.object(
                    orchestrator, "workflow_nodes", return_value={"build": {}}
                ),
                patch.object(
                    orchestrator, "workflow_descendants", return_value=set()
                ),
                patch.object(
                    orchestrator,
                    "stop_run",
                    return_value={
                        "ok": True,
                        "status": "stopped",
                        "active": False,
                        "stopped": True,
                    },
                ) as stop,
                patch.object(orchestrator, "write_workflow_status"),
            ):
                result = orchestrator.workflow_retry_node(
                    "workflow-fixture", "build"
                )
        stop.assert_called_once_with("run-build", force=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["invalidated"], ["build"])
        self.assertNotIn("run_id", workflow["nodes"]["build"])
        self.assertEqual(workflow["nodes"]["build"]["state"], "pending")

    def test_workflow_retry_accepts_already_finished_run_as_confirmed(self) -> None:
        workflow = {
            "status": "failed",
            "nodes": {
                "build": {"state": "failed", "run_id": "run-build"}
            },
            "decisions": [],
        }
        with tempfile.TemporaryDirectory(prefix="workflow-retry-finished-") as temp:
            with (
                patch.object(
                    orchestrator, "safe_workflow_dir", return_value=Path(temp)
                ),
                patch.object(
                    orchestrator, "read_json_file", return_value=workflow
                ),
                patch.object(orchestrator, "load_workflow_spec", return_value={}),
                patch.object(
                    orchestrator, "workflow_nodes", return_value={"build": {}}
                ),
                patch.object(
                    orchestrator, "workflow_descendants", return_value=set()
                ),
                patch.object(
                    orchestrator,
                    "stop_run",
                    return_value={
                        "ok": True,
                        "status": "already_finished",
                        "active": False,
                    },
                ),
                patch.object(orchestrator, "write_workflow_status"),
            ):
                result = orchestrator.workflow_retry_node(
                    "workflow-fixture", "build"
                )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["invalidated"], ["build"])
        self.assertNotIn("run_id", workflow["nodes"]["build"])
        self.assertEqual(workflow["nodes"]["build"]["state"], "pending")

    def test_visible_launch_uses_guarded_builder_without_launcher_files(self) -> None:
        provider = orchestrator.Provider(
            id="fixture",
            name="Fixture",
            app_type="claude",
            settings={"env": {}, "model": "fixture-model"},
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        route = {
            "profile": "fixture",
            "permission_mode": "plan",
            "timeout_seconds": 120,
            "task_type": "review",
            "model_override": None,
            "reason": "fixture",
        }
        prepared = SimpleNamespace(
            metadata=lambda: {
                "artifact_root": "fixture-artifact-root",
                "profile": {"id": "fixture"},
            },
            launch_spec=SimpleNamespace(
                runtime_id="trusted-default",
                trust_level="trusted_default",
                policy_decision_id="fixture-decision",
            ),
            sensitive_values=("visible-secret",),
        )
        with tempfile.TemporaryDirectory(prefix="visible-surface-") as temp:
            root = Path(temp)
            paths = {
                "workspace_root": root,
                "artifact_root": root / ".agent-workspace" / "claude-code-orchestrator",
                "runs": root / ".agent-workspace" / "claude-code-orchestrator" / "runs",
            }
            with (
                patch.object(orchestrator, "resolve_route", return_value=route),
                patch.object(orchestrator, "get_provider", return_value=provider),
                patch.object(orchestrator, "load_json", return_value={"safety": {}}),
                patch.object(orchestrator, "clamp_timeout_for_model", side_effect=lambda _model, timeout: timeout),
                patch.object(orchestrator, "_guarded_launch_paths", return_value=paths),
                patch.object(orchestrator, "build_prompt", return_value="visible-secret"),
                patch.object(orchestrator, "prepare_worker_launch", return_value=prepared) as prepare,
                patch.object(orchestrator, "start_prepared_worker_launch", return_value={"ok": True}) as start,
                patch.object(orchestrator, "_append_policy_security_audit") as audit,
            ):
                result = orchestrator.run_visible_agent(
                    "visible-secret", allow_unsafe_runtime=True, cwd=root
                )
        self.assertEqual(prepare.call_args.kwargs["mode"], "visible")
        self.assertIs(prepare.call_args.kwargs["allow_unsafe_runtime"], True)
        if orchestrator.os.name == "nt":
            start.assert_called_once_with(prepared)
            self.assertTrue(result["ok"])
        else:
            start.assert_not_called()
            self.assertEqual(result["status"], "visible_runtime_unsupported")
            audit.assert_called_once()
            self.assertIsNone(audit.call_args.kwargs["run_id"])
        source = inspect.getsource(orchestrator.run_visible_agent)
        self.assertNotIn("prompt.txt", source)
        self.assertNotIn("start-visible.ps1", source)
        self.assertNotIn("powershell", source.casefold())

    def test_visible_controller_and_worker_contract_is_isolated(self) -> None:
        controller = inspect.getsource(orchestrator._start_streaming_controller)
        visible = inspect.getsource(orchestrator._visible_worker_inner)
        self.assertIn('str(Path(sys.executable).resolve())', controller)
        self.assertIn('"-I"', controller)
        self.assertIn('"-B"', controller)
        self.assertIn('"CREATE_NEW_CONSOLE"', controller)
        self.assertIn('open("CONIN$"', visible)
        self.assertIn("_parse_worker_frame", visible)
        self.assertIn("_consume_worker_nonce", visible)
        self.assertIn("_validate_started_identity", visible)
        parser_source = inspect.getsource(orchestrator.main)
        marker = 'sub.add_parser("_visible-worker")'
        section = parser_source[parser_source.index(marker):]
        section = section[: section.find("args = parser.parse_args()")]
        self.assertNotIn("allow-unsafe-runtime", section)

    @unittest.skipUnless(os.name == "nt", "requires Windows console launch flags")
    def test_visible_controller_uses_exact_isolated_command_and_closes_pipe(self) -> None:
        class RecordingPipe:
            def __init__(self) -> None:
                self.payload = bytearray()
                self.closed = False

            def write(self, value: bytes) -> int:
                self.payload.extend(value)
                return len(value)

            def flush(self) -> None:
                return None

            def close(self) -> None:
                self.closed = True

        pipe = RecordingPipe()
        worker = SimpleNamespace(pid=424242, stdin=pipe, poll=lambda: None)
        spec = SimpleNamespace(
            environment={},
            launch_nonce="a" * 64,
            timeout_seconds=60,
            private_frame=lambda: b"private-frame",
        )
        prepared = SimpleNamespace(
            launch_spec=spec,
            prompt_bytes=b"visible-prompt",
            admission_reservation=None,
            sensitive_values=(),
            skip_cost_guard=True,
            selected_model="fixture-model",
        )
        metadata = {"run_id": "20260719-120000-visible01"}
        identity = SimpleNamespace(
            supported=True,
            executable_path=str(Path(sys.executable).resolve()),
            to_dict=lambda: {
                "pid": worker.pid,
                "creation_token": "fixture",
                "executable_path": str(Path(sys.executable).resolve()),
            },
        )
        captured: dict[str, object] = {}

        @contextlib.contextmanager
        def admission():
            yield

        def spawn(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            return worker

        def register(run_id, process):
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                orchestrator._ACTIVE_WORKER_HANDLES[run_id] = process
            return True

        def merge(_run_dir, **updates):
            return {**metadata, **updates}

        deadline_token = orchestrator._OPERATION_DEADLINE.set(
            time.monotonic() + 30
        )
        try:
            with (
                patch.object(orchestrator, "launch_lock", side_effect=admission),
                patch.object(
                    orchestrator,
                    "_spawn_detached_internal_worker",
                    side_effect=spawn,
                ),
                patch.object(
                    orchestrator, "capture_process_identity", return_value=identity
                ),
                patch.object(orchestrator, "update_metadata", side_effect=merge),
                patch.object(orchestrator, "append_event"),
                patch.object(orchestrator, "_append_unsafe_runtime_event"),
                patch.object(orchestrator, "_publish_latest_run"),
                patch.object(
                    orchestrator,
                    "_register_background_worker_watcher",
                    side_effect=register,
                ),
                patch.object(
                    orchestrator,
                    "_open_worker_start_gate",
                    return_value=metadata,
                ),
                patch.object(
                    orchestrator,
                    "_wait_for_worker_handoff_ready",
                    return_value=metadata,
                ),
                patch.object(
                    orchestrator,
                    "_accept_worker_handoff",
                    return_value=metadata,
                ),
                patch.object(
                    orchestrator, "_detach_owned_process_record", return_value=True
                ),
            ):
                result = orchestrator._start_streaming_controller(
                    prepared,
                    Path.cwd(),
                    metadata,
                    worker_subcommand="_visible-worker",
                    visible_console=True,
                )
        finally:
            orchestrator._OPERATION_DEADLINE.reset(deadline_token)
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                orchestrator._ACTIVE_WORKER_HANDLES.pop(metadata["run_id"], None)

        expected = [
            str(Path(sys.executable).resolve()),
            "-I",
            "-B",
            str(Path(orchestrator.__file__).resolve()),
            "_visible-worker",
            "--run-id",
            metadata["run_id"],
        ]
        self.assertEqual(captured["command"], expected)
        kwargs = captured["kwargs"]
        self.assertEqual(
            kwargs["creationflags"], subprocess.CREATE_NEW_CONSOLE
        )
        self.assertIs(kwargs["stdin"], subprocess.PIPE)
        self.assertIsNone(kwargs["stdout"])
        self.assertIsNone(kwargs["stderr"])
        self.assertNotIn("shell", kwargs)
        self.assertTrue(pipe.closed)
        self.assertIsNone(worker.stdin)
        self.assertEqual(result["status"], "starting")

    def test_visible_cleanup_failure_keeps_pid_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visible-cleanup-") as temp:
            run_id = orchestrator.new_run_id()
            run_dir = Path(temp) / run_id
            run_dir.mkdir()
            metadata = {
                "run_id": run_id,
                "status": "running",
                "transaction_deadline_monotonic": time.monotonic() + 5,
            }
            orchestrator.write_metadata(run_dir, metadata)
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pending = orchestrator._OwnedCleanupPending(child)
            try:
                with (
                    patch.object(orchestrator, "safe_run_dir", return_value=run_dir),
                    patch.object(
                        orchestrator, "_visible_worker_inner", side_effect=pending
                    ),
                    patch.object(
                        orchestrator, "_bounded_process_cleanup", return_value=False
                    ),
                ):
                    result = orchestrator.visible_worker(run_id)
                persisted = orchestrator.read_metadata(run_dir)
                self.assertEqual(result["status"], "cleanup_incomplete")
                self.assertEqual(
                    persisted["cleanup_state"], "cleanup_incomplete"
                )
                self.assertEqual(int((run_dir / "pid.txt").read_text()), child.pid)
            finally:
                child.terminate()
                child.wait(timeout=10)

    def test_workflow_artifacts_do_not_persist_outer_or_node_task(self) -> None:
        outer_secret = "wf-outer-short"
        node_secret = "wf-node-short"
        spec = {
            "schema_version": 1,
            "id": "workflow-secret-scan",
            "nodes": {
                "review": {
                    "role": "review",
                    "task": node_secret,
                    "outputs": "review_handoff",
                }
            },
        }
        with tempfile.TemporaryDirectory(prefix="workflow-secret-") as temp:
            root = Path(temp)
            source_path = root / "input.json"
            source_path.write_text(json.dumps(spec), encoding="utf-8")
            result = orchestrator.workflow_run(
                source_path,
                task=outer_secret,
                cwd=root,
                mock=True,
                allow_unsafe_runtime=False,
            )
            artifact_root = root / orchestrator.AGENT_WORKSPACE_DIRNAME / orchestrator.ARTIFACT_NAMESPACE
            artifacts = b"".join(
                path.read_bytes()
                for path in artifact_root.rglob("*")
                if path.is_file()
            )
        self.assertTrue(result["ok"])
        self.assertNotIn(outer_secret.encode(), artifacts)
        self.assertNotIn(node_secret.encode(), artifacts)


class QueueAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="queue-surface-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = InMemorySecurePayloadStore()
        self.patches = [
            patch.object(orchestrator, "QUEUE_PATH", self.root / "queue.json"),
            patch.object(orchestrator, "get_secure_payload_store", return_value=self.store),
            patch.object(orchestrator, "run_status", return_value={"active_count": 0}),
            patch.object(orchestrator, "load_cost_guard", return_value={"max_concurrent": 4}),
            patch.object(orchestrator, "load_queue_policy", return_value={
                "max_concurrent": 4,
                "default_priority": 100,
                "default_timeout_seconds": 120,
                "retry_failed_read_only": 1,
                "retry_write_enabled": 0,
                "stop_timed_out": True,
            }),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    @staticmethod
    def _prepared(*, identity="identity-a", policy="policy-a", unsafe=True):
        run_id = orchestrator.new_run_id()
        executable = SimpleNamespace(
            canonical_path="C:/fixture/claude.exe",
            to_public_dict=lambda: {"canonical_path": identity, "sha256": identity},
        )
        launch_spec = SimpleNamespace(
            runtime_id="fixture-runtime",
            trust_level="local_unsafe" if unsafe else "trusted_default",
            policy_decision_id=policy,
            executable_identity=executable,
        )
        return SimpleNamespace(
            launch_spec=launch_spec,
            metadata=lambda run_id=run_id: {"run_id": run_id},
        )

    def _submit_unsafe(self, *, task="qz-secret", context="cx-secret"):
        prepared = self._prepared()
        with patch.object(orchestrator, "_prepare_streaming_agent", return_value=prepared):
            result = orchestrator.queue_submit(
                task,
                context=context,
                cwd=self.root,
                allow_unsafe_runtime=True,
            )
        self.assertTrue(result["ok"])
        return result, prepared

    def _mutate_job(self, update) -> dict:
        with orchestrator.queue_lock():
            queue = orchestrator.load_queue()
            job = queue["jobs"][0]
            update(job)
            orchestrator.save_queue(queue)
            return job

    def test_queue_persists_only_opaque_payload_reference(self) -> None:
        result, _prepared = self._submit_unsafe()
        serialized = self.root.joinpath("queue.json").read_bytes()
        response = json.dumps(result, ensure_ascii=False).encode("utf-8")
        for secret in (b"qz-secret", b"cx-secret"):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, response)
        self.assertIn(b"payload_reference", serialized)
        self.assertNotIn(b'"allow_unsafe_runtime"', serialized)

    def test_queue_store_rejection_is_audited_without_prompt_text(self) -> None:
        secret = "queue-store-secret-fixture"
        with patch.object(
            self.store,
            "put",
            side_effect=SecurePayloadStoreUnavailable(
                "fixture protected store unavailable"
            ),
        ):
            result = orchestrator.queue_submit(secret, cwd=self.root)

        self.assertFalse(result["ok"], result)
        self.assertEqual(
            result["security_error"]["code"],
            "secure_payload_store_unavailable",
        )
        audit_root = (
            self.root
            / orchestrator.AGENT_WORKSPACE_DIRNAME
            / orchestrator.ARTIFACT_NAMESPACE
        )
        health = orchestrator.security_audit_health(audit_root)
        self.assertTrue(health["ok"], health)
        self.assertEqual(
            health["counts_by_code"].get("secure_payload_store_unavailable"),
            1,
        )
        audit_bytes = orchestrator._security_audit_paths(audit_root)[
            "log"
        ].read_bytes()
        self.assertNotIn(secret.encode("utf-8"), audit_bytes)

    def test_unsafe_grant_is_consumed_once_and_replay_is_blocked(self) -> None:
        _result, prepared = self._submit_unsafe()
        with (
            patch.object(orchestrator, "_prepare_streaming_agent", return_value=prepared),
            patch.object(
                orchestrator,
                "run_streaming_agent",
                return_value={
                    "run_id": prepared.metadata()["run_id"],
                    "status": "starting",
                },
            ) as launch,
        ):
            first = orchestrator.queue_tick()
            self.assertEqual(first["slots_used"], 1)
            self._mutate_job(
                lambda job: (
                    job.update({"status": "queued", "run_id": None}),
                    job["unsafe_runtime_grant"].update(
                        {"uses_remaining": 1, "consumed_at": None}
                    ),
                )
            )
            second = orchestrator.queue_tick()
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(second["slots_used"], 0)
        self.assertEqual(second["jobs"][0]["last_error"], "unsafe_runtime_grant_replayed")

    def test_grant_copy_and_unkeyed_tampering_are_rejected(self) -> None:
        mutations = (
            (
                "job_mismatch",
                lambda job: job["unsafe_runtime_grant"].update(
                    {"job_id": "job-forged"}
                ),
                "unsafe_runtime_grant_job_mismatch",
            ),
            (
                "grant_id",
                lambda job: job["unsafe_runtime_grant"].update(
                    {"grant_id": "f" * 32}
                ),
                "unsafe_runtime_grant_tampered",
            ),
            (
                "unkeyed_digest",
                lambda job: job["unsafe_runtime_grant"].update(
                    {
                        "policy_decision_id": "forged-policy",
                        "integrity_hmac_sha256": hashlib.sha256(
                            b"attacker-controlled"
                        ).hexdigest(),
                    }
                ),
                "unsafe_runtime_grant_tampered",
            ),
        )
        for name, mutate, expected in mutations:
            with self.subTest(name=name):
                self.root.joinpath("queue.json").unlink(missing_ok=True)
                self.store = InMemorySecurePayloadStore()
                self._submit_unsafe()
                self._mutate_job(mutate)
                with (
                    patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
                    patch.object(orchestrator, "run_streaming_agent") as launch,
                ):
                    result = orchestrator.queue_tick()
                prepare.assert_not_called()
                launch.assert_not_called()
                self.assertEqual(result["jobs"][0]["last_error"], expected)

    def test_copied_grant_cannot_authorize_a_second_job(self) -> None:
        first, _prepared = self._submit_unsafe(task="first-private")
        second = orchestrator.queue_submit("second-private")
        self.assertTrue(second["ok"])
        with orchestrator.queue_lock():
            queue = orchestrator.load_queue()
            copied = dict(queue["jobs"][0]["unsafe_runtime_grant"])
            queue["jobs"][1]["unsafe_runtime_grant"] = copied
            orchestrator.save_queue(queue)
        with (
            patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            result = orchestrator.queue_tick()
        prepare.assert_not_called()
        launch.assert_not_called()
        errors = {job.get("last_error") for job in result["jobs"]}
        self.assertIn("unsafe_runtime_grant_duplicate", errors)

    def test_blocked_launch_response_with_run_id_is_not_marked_running(self) -> None:
        for launch_status in (
            "blocked_runtime_launch",
            "timed_out",
            "cleanup_incomplete",
        ):
            with self.subTest(launch_status=launch_status):
                self.root.joinpath("queue.json").unlink(missing_ok=True)
                self.store = InMemorySecurePayloadStore()
                _result, prepared = self._submit_unsafe()
                with (
                    patch.object(
                        orchestrator,
                        "_prepare_streaming_agent",
                        return_value=prepared,
                    ),
                    patch.object(
                        orchestrator,
                        "run_streaming_agent",
                        return_value={
                            "ok": False,
                            "run_id": prepared.metadata()["run_id"],
                            "status": launch_status,
                            "security_error": {
                                "code": "runtime_not_trusted",
                                "suggested_action": "Approve a pinned runtime.",
                            },
                        },
                    ),
                ):
                    result = orchestrator.queue_tick()
                self.assertEqual(result["slots_used"], 0)
                self.assertEqual(result["jobs"][0]["status"], "failed")
                self.assertIsNotNone(
                    result["jobs"][0].get("payload_deleted_at")
                )
                self.assertEqual(
                    result["jobs"][0]["security_error"]["code"],
                    "runtime_not_trusted",
                )

    def test_global_active_plus_launching_claim_consumes_distinct_capacity(self) -> None:
        first = orchestrator.queue_submit("first-safe")
        second = orchestrator.queue_submit("second-safe")
        self.assertTrue(first["ok"] and second["ok"])
        claim_id = "live-mixed-claim"
        owner_identity = orchestrator.capture_process_identity(
            os.getpid(), launch_nonce=claim_id
        )
        self._mutate_job(
            lambda job: job.update(
                {
                    "status": "launching",
                    "launch_claim": {
                        "claim_id": claim_id,
                        "owner_pid": os.getpid(),
                        "owner_process_identity": owner_identity.to_dict(),
                        "claimed_at": "2026-01-01T00:00:00+00:00",
                    },
                }
            )
        )
        with (
            patch.object(orchestrator, "run_status", return_value={"active_count": 1}),
            patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            result = orchestrator.queue_tick(max_concurrent=2)
        prepare.assert_not_called()
        launch.assert_not_called()
        self.assertEqual(result["slots_used"], 0)

    def test_cancel_race_with_unconfirmed_stop_keeps_run_evidence(self) -> None:
        submitted = orchestrator.queue_submit("cancel-race-safe")
        self.assertTrue(submitted["ok"])
        job_id = submitted["job"]["job_id"]
        intended_run_id = orchestrator.new_run_id()

        def launch(**_kwargs):
            with orchestrator.queue_lock():
                queue = orchestrator.load_queue()
                queue["jobs"][0]["status"] = "cancelled"
                orchestrator.save_queue(queue)
            return {"run_id": intended_run_id, "status": "starting"}

        with (
            patch.object(
                orchestrator,
                "_prepare_streaming_agent",
                return_value=SimpleNamespace(
                    metadata=lambda: {"run_id": intended_run_id}
                ),
            ),
            patch.object(orchestrator, "run_streaming_agent", side_effect=launch),
            patch.object(
                orchestrator,
                "stop_run",
                return_value={
                    "ok": False,
                    "status": "cleanup_incomplete",
                    "active": True,
                    "stopped": False,
                },
            ),
        ):
            result = orchestrator.queue_tick()
        job = next(item for item in result["jobs"] if item["job_id"] == job_id)
        self.assertEqual(job["status"], "cancel_pending_cleanup")
        self.assertEqual(job["run_id"], intended_run_id)
        self.assertEqual(job["cleanup_state"], "cleanup_incomplete")

    def test_abandoned_claim_with_launch_intent_reconciles_existing_run(self) -> None:
        submitted = orchestrator.queue_submit("intent-safe")
        self.assertTrue(submitted["ok"])
        intended_run_id = orchestrator.new_run_id()
        self._mutate_job(
            lambda job: job.update(
                {
                    "status": "launching",
                    "intended_run_id": intended_run_id,
                    "launch_claim": {
                        "claim_id": "dead-intent-claim",
                        "owner_pid": 2147483647,
                        "claimed_at": "2026-01-01T00:00:00+00:00",
                    },
                }
            )
        )
        with (
            patch.object(
                orchestrator,
                "single_run_status",
                return_value={
                    "run_id": intended_run_id,
                    "active": True,
                    "status": "running",
                },
            ),
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            result = orchestrator.queue_tick(max_concurrent=1)
        launch.assert_not_called()
        self.assertEqual(result["jobs"][0]["status"], "running")
        self.assertEqual(result["jobs"][0]["run_id"], intended_run_id)

    def test_queue_rejects_runtime_run_id_different_from_intent(self) -> None:
        submitted = orchestrator.queue_submit("intent-mismatch-safe")
        self.assertTrue(submitted["ok"])
        prepared = self._prepared(unsafe=False)
        unexpected_run_id = orchestrator.new_run_id()
        with (
            patch.object(
                orchestrator,
                "_prepare_streaming_agent",
                return_value=prepared,
            ),
            patch.object(
                orchestrator,
                "run_streaming_agent",
                return_value={
                    "run_id": unexpected_run_id,
                    "status": "starting",
                },
            ),
            patch.object(
                orchestrator,
                "stop_run",
                return_value={"ok": True, "stopped": True, "active": False},
            ) as stop,
        ):
            result = orchestrator.queue_tick()
        stop.assert_called_once_with(unexpected_run_id, force=True)
        self.assertEqual(result["slots_used"], 0)
        self.assertEqual(result["jobs"][0]["status"], "failed")
        self.assertEqual(
            result["jobs"][0]["last_error"],
            "queue_launch_run_id_mismatch",
        )

    def test_queue_timeout_waits_for_confirmed_cleanup(self) -> None:
        submitted = orchestrator.queue_submit("timeout-safe")
        self.assertTrue(submitted["ok"])
        with orchestrator.queue_lock():
            queue = orchestrator.load_queue()
            job = queue["jobs"][0]
        reference = job["payload_reference"]
        job.update(
            {
                "status": "running",
                "run_id": orchestrator.new_run_id(),
                "started_at": "2000-01-01T00:00:00+00:00",
                "timeout_seconds": 1,
            }
        )
        with (
            patch.object(
                orchestrator,
                "single_run_status",
                return_value={"active": True, "status": "running"},
            ),
            patch.object(
                orchestrator,
                "stop_run",
                return_value={
                    "ok": False,
                    "status": "identity_unverified",
                    "active": True,
                    "stopped": False,
                },
            ),
        ):
            pending = orchestrator.refresh_queue_job(job)
        self.assertEqual(pending["status"], "timeout_pending_cleanup")
        self.assertEqual(self.store.get(reference), b'{"task":"timeout-safe","context":null}')

        with patch.object(
            orchestrator,
            "single_run_status",
            return_value={"active": False, "status": "timed_out"},
        ):
            terminal = orchestrator.refresh_queue_job(pending)
        self.assertEqual(terminal["status"], "timed_out")
        with self.assertRaises(SecurePayloadStoreError):
            self.store.get(reference)

    def test_dead_launch_claim_is_terminal_and_cannot_retry(self) -> None:
        _result, _prepared = self._submit_unsafe()

        def abandon(job):
            grant = job["unsafe_runtime_grant"]
            self.store.delete(grant["grant_reference"])
            grant.update({"uses_remaining": 0, "consumed_at": "2026-01-01T00:00:00+00:00"})
            job.update({
                "status": "launching",
                "launch_claim": {
                    "claim_id": "dead-claim",
                    "owner_pid": 2147483647,
                    "claimed_at": "2026-01-01T00:00:00+00:00",
                },
            })

        self._mutate_job(abandon)
        with (
            patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            result = orchestrator.queue_tick()
        prepare.assert_not_called()
        launch.assert_not_called()
        self.assertEqual(result["jobs"][0]["status"], "blocked_runtime_grant")
        self.assertEqual(
            result["jobs"][0]["last_error"],
            "queue_launch_claim_identity_unverified",
        )

    def test_reused_live_owner_pid_does_not_keep_launch_claim_alive(self) -> None:
        result = orchestrator.queue_submit("reused-pid-task")
        self.assertTrue(result["ok"])
        claim_id = "reused-live-pid-claim"
        owner_identity = orchestrator.capture_process_identity(
            os.getpid(), launch_nonce=claim_id
        ).to_dict()
        owner_identity["creation_token"] = "forged-creation-token"
        self._mutate_job(
            lambda job: job.update(
                {
                    "status": "launching",
                    "launch_claim": {
                        "claim_id": claim_id,
                        "owner_pid": os.getpid(),
                        "owner_process_identity": owner_identity,
                        "claimed_at": "2026-01-01T00:00:00+00:00",
                    },
                }
            )
        )
        with patch.object(orchestrator, "run_streaming_agent") as launch:
            tick = orchestrator.queue_tick(max_concurrent=1)
        launch.assert_not_called()
        job = tick["jobs"][0]
        self.assertEqual(job["status"], "blocked_launch_claim")
        self.assertEqual(job["last_error"], "queue_launch_claim_abandoned")
        self.assertEqual(job["launch_claim_identity_state"], "mismatch")

    def test_unverified_controller_identity_does_not_consume_unsafe_grant(self) -> None:
        _result, _prepared = self._submit_unsafe()
        with orchestrator.queue_lock():
            before = orchestrator.load_queue()["jobs"][0]
        payload_reference = before["payload_reference"]
        grant_reference = before["unsafe_runtime_grant"]["grant_reference"]

        def unsupported_identity(pid: int, *, launch_nonce: str):
            return orchestrator.ProcessIdentity(
                pid=pid,
                creation_token=None,
                executable_path=None,
                parent_pid=None,
                process_group_id=None,
                session_id=None,
                launch_nonce=launch_nonce,
                supported=False,
                unsupported_reason="fixture query failure",
            )

        with (
            patch.object(
                orchestrator,
                "capture_process_identity",
                side_effect=unsupported_identity,
            ),
            patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            tick = orchestrator.queue_tick(max_concurrent=1)
        prepare.assert_not_called()
        launch.assert_not_called()
        job = tick["jobs"][0]
        self.assertEqual(job["status"], "queued")
        self.assertEqual(
            job["last_error"], "queue_controller_identity_unverified"
        )
        with orchestrator.queue_lock():
            persisted = orchestrator.load_queue()["jobs"][0]
        grant = persisted["unsafe_runtime_grant"]
        self.assertEqual(grant["uses_remaining"], 1)
        self.assertIsNone(grant["consumed_at"])
        self.assertTrue(self.store.get(payload_reference))
        self.assertTrue(self.store.get(grant_reference))

    def test_live_launching_job_is_visible_and_consumes_capacity(self) -> None:
        result = orchestrator.queue_submit("safe-task")
        self.assertTrue(result["ok"])
        claim_id = "live-claim"
        owner_identity = orchestrator.capture_process_identity(
            os.getpid(), launch_nonce=claim_id
        )
        self._mutate_job(lambda job: job.update({
            "status": "launching",
            "launch_claim": {
                "claim_id": claim_id,
                "owner_pid": os.getpid(),
                "owner_process_identity": owner_identity.to_dict(),
                "claimed_at": "2026-01-01T00:00:00+00:00",
            },
        }))
        status = orchestrator.queue_status(include_finished=False)
        self.assertEqual(status["count"], 1)
        self.assertEqual(status["jobs"][0]["status"], "launching")
        with patch.object(orchestrator, "run_streaming_agent") as launch:
            tick = orchestrator.queue_tick(max_concurrent=1)
        launch.assert_not_called()
        self.assertEqual(tick["slots_used"], 0)

    def test_expired_grant_never_prepares_or_starts(self) -> None:
        self._submit_unsafe()
        def expire(job):
            grant = job["unsafe_runtime_grant"]
            authenticator = self.store.get(grant["grant_reference"])
            grant["expires_at"] = "2000-01-01T00:00:00+00:00"
            grant["integrity_hmac_sha256"] = orchestrator._grant_integrity(
                grant, authenticator
            )

        self._mutate_job(expire)
        with (
            patch.object(orchestrator, "_prepare_streaming_agent") as prepare,
            patch.object(orchestrator, "run_streaming_agent") as launch,
        ):
            result = orchestrator.queue_tick()
        prepare.assert_not_called()
        launch.assert_not_called()
        self.assertEqual(result["jobs"][0]["last_error"], "unsafe_runtime_grant_expired")

    def test_policy_and_identity_drift_consume_grant_without_start(self) -> None:
        for changed in (
            self._prepared(policy="policy-b"),
            self._prepared(identity="identity-b"),
        ):
            with self.subTest(changed=changed.launch_spec.policy_decision_id):
                self.root.joinpath("queue.json").unlink(missing_ok=True)
                self.store = InMemorySecurePayloadStore()
                with patch.object(orchestrator, "get_secure_payload_store", return_value=self.store):
                    self._submit_unsafe()
                    with (
                        patch.object(orchestrator, "_prepare_streaming_agent", return_value=changed),
                        patch.object(orchestrator, "run_streaming_agent") as launch,
                    ):
                        result = orchestrator.queue_tick()
                launch.assert_not_called()
                self.assertEqual(result["jobs"][0]["status"], "failed")
                self.assertEqual(result["jobs"][0]["unsafe_runtime_grant"]["uses_remaining"], 0)
                self.assertEqual(len(result["attempts"]), 1, result)
                self.assertEqual(
                    result["attempts"][0]["security_error"]["code"],
                    (
                        "runtime_policy_drift"
                        if changed.launch_spec.policy_decision_id == "policy-b"
                        else "runtime_identity_changed"
                    ),
                )
        audit_root = (
            self.root
            / orchestrator.AGENT_WORKSPACE_DIRNAME
            / orchestrator.ARTIFACT_NAMESPACE
        )
        health = orchestrator.security_audit_health(audit_root)
        self.assertTrue(health["ok"], health)
        self.assertEqual(health["counts_by_code"].get("runtime_policy_drift"), 1)
        self.assertEqual(
            health["counts_by_code"].get("runtime_identity_changed"), 1
        )

    def test_concurrent_ticks_claim_and_start_only_once(self) -> None:
        _result, prepared = self._submit_unsafe()
        count = 0
        count_lock = threading.Lock()

        def launch(**kwargs):
            nonlocal count
            with count_lock:
                count += 1
            time.sleep(0.05)
            return {
                "run_id": kwargs["_prepared_launch"].metadata()["run_id"],
                "status": "starting",
            }

        with (
            patch.object(orchestrator, "_prepare_streaming_agent", return_value=prepared),
            patch.object(orchestrator, "run_streaming_agent", side_effect=launch),
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _item: orchestrator.queue_tick(), range(2)))
        self.assertEqual(count, 1)
        self.assertEqual(sum(item["slots_used"] for item in results), 1)

    def test_two_controller_processes_start_one_runtime(self) -> None:
        prepared = self._prepared()
        token = "a" * 32
        payload_path = self.root / f"{token}.payload"
        payload_path.write_bytes(b'{"task":"multiprocess","context":null}')
        grant_token = "b" * 32
        authenticator = b"multiprocess-grant-authenticator"
        (self.root / f"{grant_token}.payload").write_bytes(authenticator)
        job_id = "job-multiprocess"
        grant = orchestrator._new_unsafe_runtime_grant(
            job_id=job_id,
            prepared=prepared,
            timeout_seconds=120,
            grant_reference=f"ccsp:memory:{grant_token}",
            authenticator=authenticator,
        )
        orchestrator.save_queue({
            "created_at": "fixture",
            "jobs": [{
                "job_id": job_id,
                "status": "queued",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "priority": 100,
                "role": "review",
                "cwd": str(self.root),
                "payload_reference": f"ccsp:memory:{token}",
                "task_length": 12,
                "context_length": 0,
                "timeout_seconds": 120,
                "max_retries": 0,
                "attempts": 0,
                "allow_write": False,
                "unsafe_runtime_grant": grant,
                "runs": [],
            }],
        })
        helper = self.root / "queue_worker.py"
        helper.write_text(
            "\n".join([
                "import json, os, sys, time",
                "from pathlib import Path",
                "from types import SimpleNamespace",
                f"sys.path.insert(0, {str(ORCHESTRATOR_DIR)!r})",
                "import cc_orchestrator as o",
                f"root = Path({str(self.root)!r})",
                "o.QUEUE_PATH = root / 'queue.json'",
                "o.run_status = lambda **kwargs: {'active_count': 0}",
                "o.single_run_status = lambda *args, **kwargs: {'active': True, 'status': 'running'}",
                "o.load_cost_guard = lambda: {'max_concurrent': 4}",
                "o.load_queue_policy = lambda: {'max_concurrent': 4, 'default_timeout_seconds': 120}",
                "class Store:",
                "    def get(self, reference): return (root / (reference.rsplit(':', 1)[1] + '.payload')).read_bytes()",
                "    def delete(self, reference): (root / (reference.rsplit(':', 1)[1] + '.payload')).unlink(missing_ok=True)",
                "o.get_secure_payload_store = lambda: Store()",
                "identity = SimpleNamespace(canonical_path='C:/fixture/claude.exe', to_public_dict=lambda: {'canonical_path': 'identity-a', 'sha256': 'identity-a'})",
                "prepared_run_id = o.new_run_id()",
                "prepared = SimpleNamespace(launch_spec=SimpleNamespace(trust_level='local_unsafe', policy_decision_id='policy-a', executable_identity=identity), metadata=lambda: {'run_id': prepared_run_id})",
                "o._prepare_streaming_agent = lambda **kwargs: prepared",
                "def launch(**kwargs):",
                "    marker = root / 'runtime-started.txt'",
                "    try:",
                "        with marker.open('x', encoding='utf-8') as handle: handle.write(str(os.getpid()))",
                "    except FileExistsError:",
                "        with (root / 'duplicate-start.txt').open('a', encoding='utf-8') as handle: handle.write(str(os.getpid()) + '\\n')",
                "    time.sleep(0.15)",
                "    return {'run_id': kwargs['_prepared_launch'].metadata()['run_id'], 'status': 'starting'}",
                "o.run_streaming_agent = launch",
                "result = o.queue_tick(max_concurrent=4)",
                "(root / ('result-' + str(os.getpid()) + '.json')).write_text(json.dumps(result), encoding='utf-8')",
            ]) + "\n",
            encoding="utf-8",
        )
        processes = [
            subprocess.Popen(
                [sys.executable, str(helper)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        outputs = [process.communicate(timeout=30) for process in processes]
        diagnostics = [
            stderr.decode("utf-8", errors="replace")
            for _stdout, stderr in outputs
        ]
        self.assertEqual([process.returncode for process in processes], [0, 0], diagnostics)
        self.assertTrue((self.root / "runtime-started.txt").exists())
        self.assertFalse((self.root / "duplicate-start.txt").exists())
        queue = orchestrator.load_queue()
        self.assertEqual(queue["jobs"][0]["status"], "running")
        self.assertEqual(queue["jobs"][0]["unsafe_runtime_grant"]["uses_remaining"], 0)

    def test_two_processes_two_jobs_respect_max_concurrent_one(self) -> None:
        jobs = []
        for index, token in enumerate(("c" * 32, "d" * 32), start=1):
            (self.root / f"{token}.payload").write_bytes(
                json.dumps(
                    {"task": f"multiprocess-{index}", "context": None}
                ).encode("utf-8")
            )
            jobs.append(
                {
                    "job_id": f"job-multiprocess-{index}",
                    "status": "queued",
                    "created_at": f"2026-01-01T00:00:0{index}+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "priority": 100,
                    "role": "review",
                    "cwd": str(self.root),
                    "payload_reference": f"ccsp:memory:{token}",
                    "task_length": 14,
                    "context_length": 0,
                    "timeout_seconds": 120,
                    "max_retries": 0,
                    "attempts": 0,
                    "allow_write": False,
                    "runs": [],
                }
            )
        orchestrator.save_queue({"created_at": "fixture", "jobs": jobs})
        helper = self.root / "queue_two_job_worker.py"
        helper.write_text(
            "\n".join(
                [
                    "import json, os, sys, time",
                    "from pathlib import Path",
                    f"sys.path.insert(0, {str(ORCHESTRATOR_DIR)!r})",
                    "import cc_orchestrator as o",
                    f"root = Path({str(self.root)!r})",
                    "o.QUEUE_PATH = root / 'queue.json'",
                    "o.run_status = lambda **kwargs: {'active_count': 0}",
                    "o.single_run_status = lambda *args, **kwargs: {'active': True, 'status': 'running'}",
                    "o.load_cost_guard = lambda: {'max_concurrent': 1}",
                    "o.load_queue_policy = lambda: {'max_concurrent': 1, 'default_timeout_seconds': 120}",
                    "class Store:",
                    "    def get(self, reference): return (root / (reference.rsplit(':', 1)[1] + '.payload')).read_bytes()",
                    "    def delete(self, reference): (root / (reference.rsplit(':', 1)[1] + '.payload')).unlink(missing_ok=True)",
                    "o.get_secure_payload_store = lambda: Store()",
                    "from types import SimpleNamespace",
                    "def prepare(**kwargs):",
                    "    run_id = o.new_run_id()",
                    "    return SimpleNamespace(metadata=lambda: {'run_id': run_id})",
                    "o._prepare_streaming_agent = prepare",
                    "def launch(**kwargs):",
                    "    marker = root / 'two-job-runtime-started.txt'",
                    "    try:",
                    "        with marker.open('x', encoding='utf-8') as handle: handle.write(str(os.getpid()))",
                    "    except FileExistsError:",
                    "        with (root / 'two-job-duplicate-start.txt').open('a', encoding='utf-8') as handle: handle.write(str(os.getpid()) + '\\n')",
                    "    time.sleep(0.15)",
                    "    return {'run_id': kwargs['_prepared_launch'].metadata()['run_id'], 'status': 'starting'}",
                    "o.run_streaming_agent = launch",
                    "result = o.queue_tick(max_concurrent=1)",
                    "(root / ('two-job-result-' + str(os.getpid()) + '.json')).write_text(json.dumps(result), encoding='utf-8')",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        processes = [
            subprocess.Popen(
                [sys.executable, str(helper)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        outputs = [process.communicate(timeout=30) for process in processes]
        diagnostics = [
            stderr.decode("utf-8", errors="replace")
            for _stdout, stderr in outputs
        ]
        self.assertEqual(
            [process.returncode for process in processes], [0, 0], diagnostics
        )
        self.assertTrue((self.root / "two-job-runtime-started.txt").exists())
        self.assertFalse(
            (self.root / "two-job-duplicate-start.txt").exists()
        )
        queue = orchestrator.load_queue()
        states = sorted(job["status"] for job in queue["jobs"])
        self.assertEqual(states, ["queued", "running"])

    def test_legacy_migration_verifies_then_atomically_scrubs_plaintext(self) -> None:
        legacy = {
            "created_at": "fixture",
            "jobs": [{
                "job_id": "job-legacy",
                "status": "queued",
                "task": "legacy-short",
                "context": "legacy-context",
            }],
        }
        orchestrator.save_queue(legacy)
        preview = orchestrator.migrate_legacy_queue_payloads(apply=False)
        self.assertEqual(preview["legacy_job_count"], 1)
        applied = orchestrator.migrate_legacy_queue_payloads(apply=True)
        self.assertEqual(applied["migrated_count"], 1)
        serialized = self.root.joinpath("queue.json").read_bytes()
        self.assertNotIn(b"legacy-short", serialized)
        self.assertNotIn(b"legacy-context", serialized)
        queue = orchestrator.load_queue()
        payload = self.store.get(queue["jobs"][0]["payload_reference"])
        self.assertIn(b"legacy-short", payload)


if __name__ == "__main__":
    unittest.main()
