from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: E402

import cc_orchestrator as orchestrator  # noqa: E402
from process_identity import ProcessIdentity  # noqa: E402
from process_identity import capture_process_identity  # noqa: E402
from runtime_security import (  # noqa: E402
    RuntimeExecutableCandidate,
    RuntimeSecurityError,
    RuntimeSecurityPolicy,
)


FAKE_PROVIDER_SECRET = "fixture-provider-secret-7d1f"


def _unsupported_identity(pid: int, nonce: str) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        creation_token=None,
        executable_path=None,
        parent_pid=None,
        process_group_id=None,
        session_id=None,
        launch_nonce=nonce,
        supported=False,
        unsupported_reason="fixture identity unavailable",
    )


class GuardedLaunchFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="guarded-launch-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.artifact_root = (
            self.workspace
            / orchestrator.AGENT_WORKSPACE_DIRNAME
            / orchestrator.ARTIFACT_NAMESPACE
        )
        self.runs_dir = self.artifact_root / "runs"
        self.fake_runtime = self.workspace / "canonical_fake_runtime.py"
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import json, os, sys",
                    "prompt = sys.stdin.buffer.read()",
                    "selected = sorted(key for key in os.environ if key.startswith(('ANTHROPIC_', 'CC_ORCHESTRATOR_', 'PYTHON')))",
                    "print(json.dumps({'argv': sys.argv[1:], 'env_keys': selected, 'stdin_bytes': len(prompt)}), flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.provider = orchestrator.Provider(
            id="provider-fixture",
            name="Fixture Provider",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_API_KEY": FAKE_PROVIDER_SECRET,
                    "ANTHROPIC_MODEL": "fixture-model",
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        self.route = {
            "profile": self.provider.id,
            "permission_mode": "plan",
            "timeout_seconds": 10,
            "task_type": "code",
            "model_override": None,
            "reason": "fixture route",
        }
        self.patches = [
            patch.object(orchestrator, "RUNS_DIR", self.runs_dir),
            patch.object(orchestrator, "RUN_INDEX_DIR", self.runs_dir / "index"),
            patch.object(orchestrator, "ARTIFACT_ROOT", self.artifact_root),
            patch.object(orchestrator, "WORKSPACE_ROOT", self.workspace),
            patch.object(orchestrator, "resolve_route", return_value=self.route),
            patch.object(orchestrator, "get_provider", return_value=self.provider),
            patch.object(
                orchestrator,
                "load_runtime_security_policy",
                return_value=RuntimeSecurityPolicy.default(),
                create=True,
            ),
            patch.object(
                orchestrator,
                "resolve_runtime_candidate",
                return_value=RuntimeExecutableCandidate(
                    canonical_path=str(self.fake_runtime.resolve()),
                    source="fixture",
                    trust_class="trusted_default",
                ),
                create=True,
            ),
            patch.object(orchestrator, "enforce_cost_guard", side_effect=lambda _model, timeout: timeout),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def _run_dirs(self) -> list[Path]:
        if not self.runs_dir.exists():
            return []
        return sorted(
            path
            for path in self.runs_dir.iterdir()
            if path.is_dir() and orchestrator.RUN_ID_RE.match(path.name)
        )

    def _wait_for_terminal_metadata(
        self, run_dir: Path, timeout: float = 15.0
    ) -> dict[str, object]:
        deadline = time.time() + timeout
        latest: dict[str, object] = {}
        while time.time() < deadline:
            try:
                latest = json.loads(
                    (run_dir / "metadata.json").read_text(encoding="utf-8")
                )
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.02)
                continue
            if latest.get("status") not in {"starting", "running"}:
                return latest
            time.sleep(0.05)
        self.fail(f"run did not reach a terminal state: {latest}")

    def _scan_run(self, run_dir: Path) -> bytes:
        chunks: list[bytes] = []
        for path in run_dir.rglob("*"):
            if path.is_file():
                chunks.append(path.read_bytes())
        return b"\n".join(chunks)

    def _prepare(self, mode: str, prompt: str = "private fixture prompt") -> object:
        output_format = "json" if mode == "one_shot" else "stream-json"
        arguments = ["-p", "--output-format", output_format]
        if mode == "streaming":
            arguments.extend(["--verbose", "--include-partial-messages"])
        arguments.extend(
            ["--permission-mode", "plan", "--no-session-persistence"]
        )
        return orchestrator.prepare_worker_launch(
            mode=mode,
            prompt=prompt,
            provider_env=self.provider.env,
            model_override=None,
            cwd=self.workspace,
            workspace_root=self.workspace,
            artifact_root=self.artifact_root,
            permission_mode="plan",
            timeout_seconds=10,
            arguments=tuple(arguments),
            safe_route_metadata={
                "role": "testing",
                "task_type": "code",
                "profile": {"id": self.provider.id, "name": self.provider.name},
                "output_format": output_format,
                "include_partial_messages": mode == "streaming",
                "allow_write": False,
            },
            expected_child_launches=1,
            allow_unsafe_runtime=False,
        )

    def _direct_worker_protocol(
        self,
        prepared: object,
        *,
        nonce_env: str | None,
        expires_at: str | None = None,
        consumed: bool = False,
        truncate_prompt: bool = False,
    ) -> dict[str, object]:
        metadata = prepared.metadata()
        run_id = str(metadata["run_id"])
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True)
        for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
            (run_dir / name).write_text("", encoding="utf-8")
        nonce = prepared.launch_spec.launch_nonce
        env = dict(prepared.launch_spec.environment)
        if nonce_env is not None:
            env[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce_env
        worker = subprocess.Popen(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-B",
                str(Path(orchestrator.__file__).resolve()),
                "_stream-worker",
                "--run-id",
                run_id,
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            worker_identity = capture_process_identity(worker.pid, launch_nonce=nonce)
            metadata.update(
                {
                    "status": "starting",
                    "runtime_launch": prepared.launch_spec.public_metadata(),
                    "worker_pid": worker.pid,
                    "worker_process_identity": worker_identity.to_dict(),
                    "worker_launch": {
                        "nonce_consumed": consumed,
                        "nonce_expires_at": expires_at
                        or "2999-01-01T00:00:00+00:00",
                    },
                }
            )
            orchestrator.write_metadata(run_dir, metadata)
            frame = prepared.launch_spec.private_frame()
            protocol = len(frame).to_bytes(8, "big") + frame
            if truncate_prompt:
                protocol += (8).to_bytes(8, "big") + b"short"
            else:
                protocol += (0).to_bytes(8, "big")
            stdout, stderr = worker.communicate(input=protocol, timeout=10)
            self.assertEqual(
                worker.returncode, 0, stderr.decode("utf-8", errors="replace")
            )
            return json.loads(stdout.decode("utf-8"))
        finally:
            if worker.poll() is None:
                worker.terminate()
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait(timeout=5)
            for stream in (worker.stdin, worker.stdout, worker.stderr):
                if stream is not None:
                    stream.close()


class AtomicArtifactTests(GuardedLaunchFixture):
    def test_controller_and_worker_updates_are_atomic_and_lossless(self) -> None:
        run_id = orchestrator.new_run_id()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True)
        controller_identity = {"pid": os.getpid(), "kind": "controller"}
        worker_identity = {"pid": 24680, "kind": "worker"}
        orchestrator.write_metadata(
            run_dir,
            {
                "run_id": run_id,
                "controller_process_identity": controller_identity,
                "worker_process_identity": worker_identity,
                "controller_update": -1,
                "worker_update": -1,
            },
        )

        parse_errors: list[str] = []
        stop_reader = threading.Event()

        def continuously_parse() -> None:
            while not stop_reader.is_set():
                try:
                    orchestrator.read_metadata(run_dir)
                except (OSError, json.JSONDecodeError) as error:
                    parse_errors.append(str(error))

        reader = threading.Thread(target=continuously_parse, daemon=True)
        reader.start()
        worker_code = "\n".join(
            [
                "import sys",
                f"sys.path.insert(0, {str(ORCHESTRATOR_DIR)!r})",
                "from pathlib import Path",
                "import cc_orchestrator as c",
                f"run_dir = Path({str(run_dir)!r})",
                f"identity = {worker_identity!r}",
                "for value in range(100):",
                "    c.update_metadata(run_dir, worker_update=value, worker_process_identity=identity)",
                "    c.append_event(run_dir, {'type': 'worker_update', 'value': value})",
            ]
        )
        worker = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", worker_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            for value in range(100):
                orchestrator.update_metadata(
                    run_dir,
                    controller_update=value,
                    controller_process_identity=controller_identity,
                )
                orchestrator.append_event(
                    run_dir, {"type": "controller_update", "value": value}
                )
            stdout, stderr = worker.communicate(timeout=20)
            self.assertEqual(stdout, b"")
            self.assertEqual(worker.returncode, 0, stderr.decode("utf-8", errors="replace"))
        finally:
            if worker.poll() is None:
                worker.terminate()
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait(timeout=5)
            stop_reader.set()
            reader.join(timeout=5)

        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        events = [
            json.loads(line)
            for line in (run_dir / "events.ndjson").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(parse_errors, [])
        self.assertEqual(metadata["controller_update"], 99)
        self.assertEqual(metadata["worker_update"], 99)
        self.assertEqual(metadata["controller_process_identity"], controller_identity)
        self.assertEqual(metadata["worker_process_identity"], worker_identity)
        self.assertEqual(len(events), 200)
        self.assertEqual(sorted(event["seq"] for event in events), list(range(1, 201)))


class GuardedLaunchIntegrationTests(GuardedLaunchFixture):
    def test_provider_execution_controls_fail_before_run_creation(self) -> None:
        for forbidden_key in ("PATH", "CLAUDE_CODE_BIN"):
            with self.subTest(key=forbidden_key):
                provider = orchestrator.Provider(
                    id="bad-provider",
                    name="Bad Provider",
                    app_type="claude",
                    settings={"env": {forbidden_key: str(self.fake_runtime)}},
                    category=None,
                    provider_type=None,
                    is_current=True,
                    endpoints=[],
                )
                before = self._run_dirs()
                with patch.object(orchestrator, "get_provider", return_value=provider):
                    with self.assertRaises(RuntimeSecurityError) as raised:
                        orchestrator.run_agent("provider preflight", cwd=self.workspace)
                self.assertEqual(raised.exception.code, "provider_env_forbidden")
                self.assertEqual(self._run_dirs(), before)

    def test_one_shot_uses_canonical_runtime_and_prompt_stdin_only(self) -> None:
        task = "one-shot-private-prompt-51c4"
        result = orchestrator.run_agent(task, role="testing", cwd=self.workspace)
        run_dir = self.runs_dir / str(result["run_id"])
        payload = json.loads((run_dir / "stdout.txt").read_text(encoding="utf-8"))
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(payload["stdin_bytes"], metadata["prompt_bytes"])
        self.assertIn("-p", payload["argv"])
        self.assertNotIn(task, payload["argv"])
        self.assertFalse((run_dir / "prompt.txt").exists())
        self.assertEqual(
            metadata["runtime_launch"]["executable_identity"]["canonical_path"],
            str(self.fake_runtime.resolve()),
        )
        self.assertTrue(metadata["child_process_identity"]["supported"])
        artifact_bytes = self._scan_run(run_dir)
        self.assertNotIn(task.encode(), artifact_bytes)
        self.assertNotIn(FAKE_PROVIDER_SECRET.encode(), artifact_bytes)

    def test_streaming_uses_framed_stdin_and_public_launch_metadata(self) -> None:
        task = "stream-private-prompt-0f92"
        launch = orchestrator.run_streaming_agent(
            task,
            role="testing",
            cwd=self.workspace,
            max_output_bytes=100_000,
            max_events_bytes=100_000,
        )
        run_dir = self.runs_dir / str(launch["run_id"])
        metadata = self._wait_for_terminal_metadata(run_dir)
        payload = json.loads((run_dir / "stdout.txt").read_text(encoding="utf-8"))

        self.assertEqual(metadata["status"], "succeeded")
        self.assertEqual(payload["stdin_bytes"], metadata["prompt_bytes"])
        self.assertNotIn(task, payload["argv"])
        self.assertFalse((run_dir / "prompt.txt").exists())
        self.assertTrue(metadata["worker_process_identity"]["supported"])
        self.assertTrue(metadata["child_process_identity"]["supported"])
        self.assertTrue(metadata["worker_launch"]["nonce_consumed"])
        public_launch = metadata["runtime_launch"]
        self.assertIn("launch_contract_sha256", public_launch)
        self.assertIn("ANTHROPIC_API_KEY", public_launch["environment_keys"])
        artifact_bytes = self._scan_run(run_dir)
        self.assertNotIn(task.encode(), artifact_bytes)
        self.assertNotIn(FAKE_PROVIDER_SECRET.encode(), artifact_bytes)

    def test_executable_replacement_after_prepare_blocks_without_output(self) -> None:
        prepared = self._prepare("one_shot", "identity-change-private-2b6a")
        self.assertEqual(self._run_dirs(), [])
        self.fake_runtime.write_text("print('replacement must not run')\n", encoding="utf-8")

        result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))

        self.assertEqual(metadata["status"], "blocked_runtime_identity")
        self.assertIsNone(metadata["exit_code"])
        self.assertEqual(metadata["security_error"]["code"], "runtime_identity_changed")
        self.assertEqual((run_dir / "stdout.txt").read_text(encoding="utf-8"), "")

    def test_direct_stream_worker_replay_cannot_launch_another_child(self) -> None:
        launch = orchestrator.run_streaming_agent(
            "nonce-replay-private-f3ad", role="testing", cwd=self.workspace
        )
        run_dir = self.runs_dir / str(launch["run_id"])
        metadata = self._wait_for_terminal_metadata(run_dir)
        before_stdout = (run_dir / "stdout.txt").read_bytes()
        nonce = str(metadata["runtime_launch"]["launch_nonce"])
        env = orchestrator.build_worker_env(
            self.provider.env,
            workspace_root=self.workspace,
            artifact_root=self.artifact_root,
        )
        env[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        replay = subprocess.Popen(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-B",
                str(Path(orchestrator.__file__).resolve()),
                "_stream-worker",
                "--run-id",
                str(launch["run_id"]),
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            frame = self._prepare("streaming").launch_spec.private_frame()
            replay_input = (
                len(frame).to_bytes(8, "big")
                + frame
                + (0).to_bytes(8, "big")
            )
            stdout, stderr = replay.communicate(input=replay_input, timeout=10)
            self.assertEqual(replay.returncode, 0, stderr.decode("utf-8", errors="replace"))
        finally:
            if replay.poll() is None:
                replay.terminate()
                try:
                    replay.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    replay.kill()
                    replay.wait(timeout=5)
        response = json.loads(stdout.decode("utf-8"))
        self.assertEqual(response["security_error"]["code"], "runtime_not_trusted")
        self.assertEqual((run_dir / "stdout.txt").read_bytes(), before_stdout)

    def test_direct_worker_rejects_missing_forged_expired_and_consumed_nonce(self) -> None:
        cases = (
            {"nonce_env": None},
            {"nonce_env": "f" * 64},
            {
                "nonce_env": "approved",
                "expires_at": "2000-01-01T00:00:00+00:00",
            },
            {"nonce_env": "approved", "consumed": True},
        )
        for case in cases:
            with self.subTest(case=case):
                prepared = self._prepare("streaming")
                nonce_env = case["nonce_env"]
                if nonce_env == "approved":
                    nonce_env = prepared.launch_spec.launch_nonce
                response = self._direct_worker_protocol(
                    prepared,
                    nonce_env=nonce_env,
                    expires_at=case.get("expires_at"),
                    consumed=bool(case.get("consumed", False)),
                )
                self.assertEqual(
                    response["security_error"]["code"], "runtime_not_trusted"
                )
                run_dir = self.runs_dir / str(prepared.metadata()["run_id"])
                latest = orchestrator.read_metadata(run_dir)
                self.assertIsNone(latest.get("child_pid"))
                self.assertEqual((run_dir / "stdout.txt").read_text(encoding="utf-8"), "")

    def test_direct_worker_rejects_truncated_prompt_frame_without_child(self) -> None:
        prepared = self._prepare("streaming")
        response = self._direct_worker_protocol(
            prepared,
            nonce_env=prepared.launch_spec.launch_nonce,
            truncate_prompt=True,
        )
        self.assertEqual(response["security_error"]["code"], "runtime_not_trusted")
        run_dir = self.runs_dir / str(prepared.metadata()["run_id"])
        self.assertIsNone(orchestrator.read_metadata(run_dir).get("child_pid"))

    def test_streaming_replacement_after_prepare_blocks_without_runtime_output(self) -> None:
        prepared = self._prepare("streaming", "stream-identity-private-bf8e")
        self.fake_runtime.write_text("print('replacement must not run')\n", encoding="utf-8")
        result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = self._wait_for_terminal_metadata(run_dir)
        self.assertEqual(metadata["status"], "blocked_runtime_identity")
        self.assertEqual(metadata["security_error"]["code"], "runtime_identity_changed")
        self.assertEqual((run_dir / "stdout.txt").read_text(encoding="utf-8"), "")


class GuardedLaunchFailureTests(GuardedLaunchFixture):
    def test_popen_failure_records_one_blocked_state(self) -> None:
        prepared = self._prepare("one_shot")
        with patch.object(orchestrator.subprocess, "Popen", side_effect=OSError("fixture popen failure")):
            result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["status"], "blocked_runtime_launch")
        self.assertIsNone(metadata["exit_code"])
        self.assertEqual(metadata["security_error"]["code"], "runtime_launch_failed")
        self.assertEqual(metadata["terminal_state_count"], 1)

    def test_child_identity_failure_terminates_owned_process(self) -> None:
        prepared = self._prepare("one_shot")

        def unsupported(pid: int, *, launch_nonce: str) -> ProcessIdentity:
            return _unsupported_identity(pid, launch_nonce)

        with patch.object(orchestrator, "capture_process_identity", side_effect=unsupported, create=True):
            result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["status"], "blocked_process_identity")
        self.assertEqual(metadata["security_error"]["code"], "process_identity_unverified")
        self.assertFalse(orchestrator.pid_alive(int(metadata["child_pid"])))
        self.assertEqual((run_dir / "stdout.txt").read_text(encoding="utf-8"), "")

    def test_artifact_lock_failure_blocks_before_process_start(self) -> None:
        prepared = self._prepare("one_shot")
        with patch.object(
            orchestrator,
            "artifact_lock",
            side_effect=orchestrator.OrchestratorError("fixture lock failure"),
            create=True,
        ):
            result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["status"], "blocked_runtime_launch")
        self.assertEqual(metadata["security_error"]["code"], "artifact_write_failed")
        self.assertIsNone(metadata.get("child_pid"))

    def test_worker_identity_failure_terminates_original_worker_handle(self) -> None:
        def unsupported(pid: int, *, launch_nonce: str) -> ProcessIdentity:
            return _unsupported_identity(pid, launch_nonce)

        with patch.object(orchestrator, "capture_process_identity", side_effect=unsupported):
            result = orchestrator.run_streaming_agent(
                "worker-identity-private-146d", role="testing", cwd=self.workspace
            )
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = orchestrator.read_metadata(run_dir)
        self.assertEqual(metadata["status"], "blocked_process_identity")
        self.assertEqual(
            metadata["security_error"]["code"], "process_identity_unverified"
        )
        self.assertFalse(orchestrator.pid_alive(int(metadata["worker_pid"])))
        self.assertIsNone(metadata.get("child_pid"))

    def test_post_start_metadata_failure_terminates_child_and_blocks(self) -> None:
        prepared = self._prepare("one_shot")
        real_update = orchestrator.update_metadata
        calls = 0

        def fail_first_update(run_dir: Path, **updates: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise orchestrator.OrchestratorError("fixture metadata failure")
            return real_update(run_dir, **updates)

        with patch.object(orchestrator, "update_metadata", side_effect=fail_first_update):
            result = orchestrator.start_prepared_worker_launch(prepared)
        run_dir = self.runs_dir / str(result["run_id"])
        metadata = orchestrator.read_metadata(run_dir)
        self.assertEqual(metadata["status"], "blocked_runtime_launch")
        self.assertEqual(metadata["security_error"]["code"], "artifact_write_failed")
        self.assertFalse(orchestrator.pid_alive(int(metadata["child_pid"])))

    def test_stream_worker_child_identity_failure_uses_owned_handle(self) -> None:
        prepared = self._prepare("streaming")
        metadata = prepared.metadata()
        run_dir = self.runs_dir / str(metadata["run_id"])
        run_dir.mkdir(parents=True)
        for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
            (run_dir / name).write_text("", encoding="utf-8")
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata.update(
            {
                "status": "starting",
                "runtime_launch": prepared.launch_spec.public_metadata(),
                "worker_pid": os.getpid(),
                "worker_process_identity": worker_identity.to_dict(),
                "worker_launch": {
                    "nonce_consumed": False,
                    "nonce_expires_at": "2999-01-01T00:00:00+00:00",
                },
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = (
            len(frame).to_bytes(8, "big")
            + frame
            + (0).to_bytes(8, "big")
        )

        def unsupported(pid: int, *, launch_nonce: str) -> ProcessIdentity:
            return _unsupported_identity(pid, launch_nonce)

        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator, "capture_process_identity", side_effect=unsupported
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        latest = orchestrator.read_metadata(run_dir)
        self.assertEqual(latest["status"], "blocked_process_identity")
        self.assertEqual(
            latest["security_error"]["code"], "process_identity_unverified"
        )
        self.assertFalse(orchestrator.pid_alive(int(latest["child_pid"])))
        self.assertEqual(result["status"], "blocked_process_identity")


if __name__ == "__main__":
    unittest.main()
