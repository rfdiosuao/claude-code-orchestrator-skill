from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
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
from process_identity import ProcessIdentityCheck  # noqa: E402
from process_identity import capture_process_identity  # noqa: E402
from runtime_security import (  # noqa: E402
    ApprovedUnsafeRuntime,
    ExecutableIdentity,
    PinnedExecutableIdentity,
    RuntimeExecutableCandidate,
    RuntimeSecurityError,
    RuntimeSecurityPolicy,
)


FAKE_PROVIDER_SECRET = "fixture-provider-secret-7d1f"
REAL_ENFORCE_COST_GUARD = orchestrator.enforce_cost_guard


def _pinned_identity(identity: ExecutableIdentity) -> PinnedExecutableIdentity:
    return PinnedExecutableIdentity(
        canonical_path=identity.canonical_path,
        sha256=identity.sha256,
        size=identity.size,
        file_id=identity.file_id,
        target_kind=identity.target_kind,
        interpreter_identity=(
            None
            if identity.interpreter_identity is None
            else _pinned_identity(identity.interpreter_identity)
        ),
    )


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
        self.addCleanup(self._cleanup_owned_workers)
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

    def _cleanup_owned_workers(self) -> None:
        with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
            workers = list(orchestrator._ACTIVE_WORKER_HANDLES.values())
        for worker in workers:
            orchestrator._terminate_owned_process(worker)

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
            except (FileNotFoundError, PermissionError, json.JSONDecodeError):
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

    def _wait_for_pid_exit(self, pid: int, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline and orchestrator.pid_alive(pid):
            time.sleep(0.02)
        self.assertFalse(orchestrator.pid_alive(pid), f"process {pid} is still alive")

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

    def _publish_worker_gate(
        self, run_dir: Path, metadata: dict[str, object]
    ) -> None:
        payload = orchestrator._worker_start_gate_payload(metadata)
        orchestrator._atomic_write_text(
            run_dir / orchestrator.WORKER_START_GATE_FILENAME,
            json.dumps(payload, ensure_ascii=False, indent=2),
        )

    def _arm_worker_gate(self, run_dir: Path, prepared: object) -> None:
        nonce = prepared.launch_spec.launch_nonce
        identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        orchestrator.update_metadata(
            run_dir,
            worker_pid=os.getpid(),
            worker_process_identity=identity.to_dict(),
        )

    def _direct_worker_protocol(
        self,
        prepared: object,
        *,
        nonce_env: str | None,
        expires_at: str | None = None,
        consumed: bool = False,
        truncate_prompt: bool = False,
        prompt_payload: bytes = b"",
        trailing_payload: bytes = b"",
        gate: str = "open",
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
                        "start_gate": "closed",
                    },
                    "controller_pid": os.getpid(),
                }
            )
            orchestrator.write_metadata(run_dir, metadata)
            if gate == "open":
                self._publish_worker_gate(run_dir, metadata)
            frame = prepared.launch_spec.private_frame()
            protocol = len(frame).to_bytes(8, "big") + frame
            if truncate_prompt:
                protocol += (8).to_bytes(8, "big") + b"short"
            else:
                protocol += len(prompt_payload).to_bytes(8, "big") + prompt_payload
            protocol += trailing_payload
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
        self._wait_for_pid_exit(int(metadata["worker_pid"]))
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
        real_popen = subprocess.Popen

        def fail_runtime(command: object, *args: object, **kwargs: object) -> object:
            if str(self.fake_runtime) in " ".join(str(item) for item in command):
                raise OSError("fixture popen failure")
            return real_popen(command, *args, **kwargs)

        with patch.object(orchestrator.subprocess, "Popen", side_effect=fail_runtime):
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
        self.assertEqual(metadata["status"], "blocked_runtime_identity")
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
        self.assertFalse(result["persisted"])
        self.assertEqual(result["persistence_state"], "degraded")
        self.assertEqual(result["status"], "blocked_runtime_launch")
        self.assertEqual(result["security_error"]["code"], "artifact_write_failed")
        self.assertFalse((run_dir / "metadata.json").exists())

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
        self.fake_runtime.write_text(
            "import sys, time\n"
            "sys.stdout.buffer.write(b'Q' * (4 * 1024 * 1024))\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(2)\n",
            encoding="utf-8",
        )
        prepared = self._prepare("streaming", prompt="")
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
                    "start_gate": "closed",
                },
                "controller_pid": worker_identity.parent_pid,
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = (
            len(frame).to_bytes(8, "big")
            + frame
            + (0).to_bytes(8, "big")
        )

        def unsupported(pid: int, *, launch_nonce: str) -> ProcessIdentity:
            time.sleep(0.2)
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
        self.assertFalse(
            any(
                str(metadata["run_id"]) in thread.name
                for thread in threading.enumerate()
            )
        )


class ReviewFixResolverAndEnvironmentTests(GuardedLaunchFixture):
    def test_path_package_shape_never_establishes_trust(self) -> None:
        path_runtime = (
            self.workspace
            / "arbitrary"
            / "node_modules"
            / "@anthropic-ai"
            / "claude-code"
            / "bin"
            / "claude.exe"
        )
        path_runtime.parent.mkdir(parents=True)
        path_runtime.write_bytes(b"fixture")
        empty_home = self.workspace / "empty-home"
        empty_home.mkdir()
        with patch.object(orchestrator, "user_home", return_value=empty_home), patch.object(
            orchestrator.shutil, "which", return_value=str(path_runtime)
        ), patch.dict(os.environ, {"PROGRAMDATA": str(self.workspace / "none")}, clear=False):
            candidate = orchestrator.discover_claude_candidate(
                ignore_environment_override=True
            )
        self.assertEqual(candidate.canonical_path, str(path_runtime.resolve()))
        self.assertEqual(candidate.source, "path_discovery")
        self.assertEqual(candidate.trust_class, "discovered_unpinned")

    def test_controller_baseline_is_owned_and_starts_child_tool(self) -> None:
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import json, os, subprocess, sys",
                    "prompt = sys.stdin.buffer.read()",
                    "child = subprocess.run([sys.executable, '-c', 'print(\"child-ok\")'], capture_output=True, text=True, check=True)",
                    "keys = sorted(k for k in os.environ if k in {'SystemRoot','WINDIR','TEMP','TMP','HOME','USERPROFILE','TMPDIR'})",
                    "print(json.dumps({'child': child.stdout.strip(), 'keys': keys, 'stdin_bytes': len(prompt)}), flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        result = orchestrator.run_agent("baseline child startup", cwd=self.workspace)
        payload = json.loads(
            (self.runs_dir / str(result["run_id"]) / "stdout.txt").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(payload["child"], "child-ok")
        expected = {"TEMP", "TMP"} if os.name == "nt" else {"HOME"}
        self.assertTrue(expected.issubset(set(payload["keys"])), payload)

        baseline_key = "TEMP" if os.name == "nt" else "HOME"
        provider = orchestrator.Provider(
            id="baseline-override",
            name="Baseline Override",
            app_type="claude",
            settings={"env": {baseline_key: "provider-controlled"}},
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        permissive = RuntimeSecurityPolicy(extra_provider_env_keys=(baseline_key,))
        before = self._run_dirs()
        with patch.object(orchestrator, "get_provider", return_value=provider), patch.object(
            orchestrator,
            "load_runtime_security_policy",
            return_value=permissive,
        ):
            with self.assertRaises(RuntimeSecurityError) as raised:
                orchestrator.run_agent("baseline override", cwd=self.workspace)
        self.assertEqual(raised.exception.code, "provider_env_forbidden")
        self.assertEqual(self._run_dirs(), before)


class ReviewFixArtifactTests(GuardedLaunchFixture):
    def test_run_artifacts_and_atomic_temporaries_are_private(self) -> None:
        temporary_modes: list[int] = []
        real_replace = os.replace

        def inspect_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
            temporary_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
            real_replace(source, target)

        with patch.object(orchestrator.os, "replace", side_effect=inspect_replace):
            result = orchestrator.run_agent("private artifact modes", cwd=self.workspace)
        run_dir = self.runs_dir / str(result["run_id"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
            for path in run_dir.rglob("*"):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
            self.assertTrue(temporary_modes)
            self.assertTrue(all(mode == 0o600 for mode in temporary_modes))

    @unittest.skipUnless(os.name == "nt", "Windows DACL regression")
    def test_windows_private_acl_is_enforced_and_verified(self) -> None:
        target = self.workspace / "acl-target"
        target.mkdir()
        target_file = target / "artifact.txt"
        target_file.write_text("private", encoding="utf-8")
        icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
        for path in (target, target_file):
            granted = subprocess.run(
                [str(icacls), str(path), "/grant", "*S-1-1-0:F"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(granted.returncode, 0, granted.stderr)
            orchestrator._enforce_windows_private_acl(
                path, is_dir=path.is_dir()
            )
            acl = orchestrator._inspect_windows_private_acl(
                path, is_dir=path.is_dir()
            )
            self.assertTrue(acl["protected"])
            self.assertEqual(acl["ace_sids"], [acl["current_user_sid"]])
            self.assertFalse(acl["has_inherited_aces"])
            self.assertTrue(acl["exact"])

        observed_replacements: list[dict[str, object]] = []
        real_replace = orchestrator._windows_replace_relative

        def inspect_replacement(
            source: Path, destination: Path, parent_handle: object
        ) -> None:
            observed_replacements.append(
                orchestrator._inspect_windows_private_acl(
                    Path(source), is_dir=False
                )
            )
            real_replace(source, destination, parent_handle)

        with patch.object(
            orchestrator,
            "_windows_replace_relative",
            side_effect=inspect_replacement,
        ):
            orchestrator._atomic_write_text(target_file, "replacement")
        self.assertTrue(observed_replacements)
        self.assertTrue(all(item["exact"] for item in observed_replacements))
        self.assertTrue(
            orchestrator._inspect_windows_private_acl(
                target_file, is_dir=False
            )["exact"]
        )

    def test_blocked_transition_merges_current_metadata_or_degrades(self) -> None:
        run_id = orchestrator.new_run_id()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True)
        current = {
            "run_id": run_id,
            "status": "starting",
            "worker_process_identity": {"creation_token": "preserve-me"},
        }
        orchestrator.write_metadata(run_dir, current)
        stale = {"run_id": run_id, "status": "starting"}
        error = orchestrator._launch_failure_error("fixture_failure", "fixture")
        merged = orchestrator._record_blocked_launch(
            run_dir, stale, status="blocked_runtime_launch", error=error
        )
        persisted = orchestrator.read_metadata(run_dir)
        self.assertEqual(
            persisted["worker_process_identity"], current["worker_process_identity"]
        )
        self.assertTrue(merged["persisted"])

        before = json.loads(json.dumps(persisted))
        with patch.object(
            orchestrator,
            "artifact_lock",
            side_effect=orchestrator.OrchestratorError("lock unavailable"),
        ):
            degraded = orchestrator._record_blocked_launch(
                run_dir,
                stale,
                status="blocked_runtime_launch",
                error=error,
                child_pid=999,
            )
        self.assertFalse(degraded["persisted"])
        self.assertEqual(degraded["persistence_state"], "degraded")
        self.assertEqual(orchestrator.read_metadata(run_dir), before)

    def test_real_atomic_replace_failure_never_claims_persistence(self) -> None:
        run_id = orchestrator.new_run_id()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True)
        original = {"run_id": run_id, "status": "starting", "identity": "stable"}
        orchestrator.write_metadata(run_dir, original)
        error = orchestrator._launch_failure_error("fixture_failure", "fixture")
        replacement_target = (
            orchestrator
            if os.name == "nt"
            else orchestrator.os
        )
        replacement_name = (
            "_windows_replace_relative" if os.name == "nt" else "replace"
        )
        with patch.object(
            replacement_target,
            replacement_name,
            side_effect=OSError("replace failed"),
        ):
            degraded = orchestrator._record_blocked_launch(
                run_dir,
                original,
                status="blocked_runtime_launch",
                error=error,
            )
        self.assertFalse(degraded["persisted"])
        self.assertEqual(degraded["persistence_state"], "degraded")
        self.assertEqual(orchestrator.read_metadata(run_dir), original)


class ReviewFixScrubbingTests(GuardedLaunchFixture):
    def test_exact_prompt_secret_and_endpoint_components_are_scrubbed(self) -> None:
        secret = "arbitrary-secret-value-q7"
        endpoint_password = "userinfo-password-r8"
        endpoint_query = "query-secret-s9"
        provider = orchestrator.Provider(
            id="echo-provider",
            name="Echo Provider",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_API_KEY": secret,
                    "ANTHROPIC_MODEL": "fixture-model",
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[
                f"https://user:{endpoint_password}@example.invalid/api?token={endpoint_query}&region=test"
            ],
        )
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import json, os, sys",
                    "prompt = sys.stdin.buffer.read().decode('utf-8')",
                    "print(json.dumps({'prompt_echo': prompt, 'secret_echo': os.environ['ANTHROPIC_API_KEY']}), flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        task = 'exact-echo-task-u4\nquoted-"task-value"'
        context = 'exact-context-v5\nquoted-"context-value"'
        with patch.object(orchestrator, "get_provider", return_value=provider):
            one_shot = orchestrator.run_agent(
                task, context=context, cwd=self.workspace
            )
            streaming = orchestrator.run_streaming_agent(
                task, context=context, cwd=self.workspace
            )
        stream_dir = self.runs_dir / str(streaming["run_id"])
        terminal = self._wait_for_terminal_metadata(stream_dir)
        self._wait_for_pid_exit(int(terminal["worker_pid"]))
        one_dir = self.runs_dir / str(one_shot["run_id"])
        forbidden = (
            task,
            context,
            "exact-echo-task-u4",
            "quoted-",
            "exact-context-v5",
            secret,
            endpoint_password,
            endpoint_query,
        )
        for value in forbidden:
            self.assertNotIn(value.encode(), self._scan_run(one_dir))
            self.assertNotIn(value.encode(), self._scan_run(stream_dir))
            self.assertNotIn(value, json.dumps(one_shot, ensure_ascii=False))
            self.assertNotIn(value, json.dumps(streaming, ensure_ascii=False))
        self.assertIn("[REDACTED]", (one_dir / "stdout.txt").read_text(encoding="utf-8"))
        self.assertIn("[REDACTED]", (stream_dir / "events.ndjson").read_text(encoding="utf-8"))


class ReviewFixGateAndOwnershipTests(GuardedLaunchFixture):
    def test_controller_failure_after_identity_keeps_gate_closed_and_cleans_worker(self) -> None:
        with patch.object(
            orchestrator,
            "_open_worker_start_gate",
            side_effect=OSError("gate write failed"),
            create=True,
        ) as gate:
            result = orchestrator.run_streaming_agent(
                "gate failure cleanup", cwd=self.workspace
            )
        self.assertTrue(gate.called)
        self.assertEqual(result["status"], "blocked_runtime_launch")
        self.assertFalse(orchestrator.pid_alive(int(result["worker_pid"])))
        self.assertIsNone(result.get("child_pid"))
        self.assertNotEqual(
            (result.get("worker_launch") or {}).get("start_gate"), "open"
        )

    def test_closed_gate_times_out_without_nonce_consumption_or_child(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        with patch.object(
            orchestrator, "WORKER_START_GATE_TIMEOUT_SECONDS", 0.1, create=True
        ):
            response = self._direct_worker_protocol(
                prepared,
                nonce_env=prepared.launch_spec.launch_nonce,
                gate="closed",
            )
        self.assertEqual(response["security_error"]["code"], "runtime_not_trusted")
        latest = orchestrator.read_metadata(
            self.runs_dir / str(prepared.metadata()["run_id"])
        )
        self.assertFalse(latest["worker_launch"]["nonce_consumed"])
        self.assertIsNone(latest.get("child_pid"))

    def test_pid_reuse_evidence_blocks_atomically_before_nonce_consumption(self) -> None:
        prepared = self._prepare("streaming", prompt="")
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
                "controller_pid": worker_identity.parent_pid,
                "worker_launch": {
                    "nonce_consumed": False,
                    "nonce_expires_at": "2999-01-01T00:00:00+00:00",
                    "start_gate": "closed",
                },
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = len(frame).to_bytes(8, "big") + frame + (0).to_bytes(8, "big")
        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        mismatch = ProcessIdentityCheck(
            state="mismatch", differing_fields=("creation_token",)
        )
        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator, "compare_process_identity", return_value=mismatch, create=True
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        self.assertEqual(result["security_error"]["code"], "runtime_not_trusted")
        latest = orchestrator.read_metadata(run_dir)
        self.assertFalse(latest["worker_launch"]["nonce_consumed"])
        self.assertIsNone(latest.get("child_pid"))


class ReviewFixLifecycleTests(GuardedLaunchFixture):
    def test_output_before_input_pressure_does_not_deadlock(self) -> None:
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import json, sys",
                    "sys.stdout.buffer.write(b'X' * 300000)",
                    "sys.stdout.buffer.flush()",
                    "prompt = sys.stdin.buffer.read()",
                    "sys.stdout.buffer.write(b'\\n' + json.dumps({'stdin_bytes': len(prompt)}).encode() + b'\\n')",
                    "sys.stdout.buffer.flush()",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        task = "P" * 700_000
        launch = orchestrator.run_streaming_agent(
            task,
            cwd=self.workspace,
            timeout_seconds=5,
            max_output_bytes=900_000,
            max_events_bytes=1_500_000,
        )
        run_dir = self.runs_dir / str(launch["run_id"])
        metadata = self._wait_for_terminal_metadata(run_dir, timeout=15)
        self.assertEqual(metadata["status"], "succeeded", metadata)
        self.assertIn("stdin_bytes", (run_dir / "stdout.txt").read_text(encoding="utf-8"))

    def test_one_shot_timeout_drains_partial_output(self) -> None:
        marker = "partial-timeout-output-v3"
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import sys, time",
                    "sys.stdin.buffer.read()",
                    f"print({marker!r}, flush=True)",
                    "time.sleep(30)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        result = orchestrator.run_agent(
            "timeout partial output", cwd=self.workspace, timeout_seconds=1
        )
        run_dir = self.runs_dir / str(result["run_id"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], 124)
        self.assertIn(marker, (run_dir / "stdout.txt").read_text(encoding="utf-8"))
        self.assertFalse(orchestrator.pid_alive(int(result["child_pid"])))

    def test_streaming_admission_is_serialized_under_launch_lock(self) -> None:
        shared_lock = threading.Lock()
        state_lock = threading.Lock()
        state = {"held": False, "active_guards": 0, "max_guards": 0}
        observations: list[bool] = []

        class AdmissionLock:
            def __enter__(self) -> None:
                shared_lock.acquire()
                state["held"] = True

            def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
                state["held"] = False
                shared_lock.release()

        def guarded(_model: str | None, timeout: int) -> int:
            with state_lock:
                observations.append(bool(state["held"]))
                state["active_guards"] += 1
                state["max_guards"] = max(
                    state["max_guards"], state["active_guards"]
                )
            time.sleep(0.1)
            with state_lock:
                state["active_guards"] -= 1
            return timeout

        results: list[dict[str, object]] = []

        def launch(index: int) -> None:
            results.append(
                orchestrator.run_streaming_agent(
                    f"concurrent admission {index}", cwd=self.workspace
                )
            )

        with patch.object(orchestrator, "launch_lock", side_effect=lambda: AdmissionLock()), patch.object(
            orchestrator, "enforce_cost_guard", side_effect=guarded
        ):
            threads = [threading.Thread(target=launch, args=(index,)) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
        self.assertEqual(len(results), 2)
        self.assertEqual(observations, [True, True])
        self.assertEqual(state["max_guards"], 1)
        for result in results:
            self._wait_for_terminal_metadata(
                self.runs_dir / str(result["run_id"])
            )


class ReviewFixContractTests(GuardedLaunchFixture):
    def test_prepared_admission_state_is_private(self) -> None:
        prepared = orchestrator.prepare_worker_launch(
            mode="streaming",
            prompt="private admission",
            provider_env=self.provider.env,
            model_override="fixture-model",
            cwd=self.workspace,
            workspace_root=self.workspace,
            artifact_root=self.artifact_root,
            permission_mode="plan",
            timeout_seconds=10,
            arguments=(
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--permission-mode",
                "plan",
                "--no-session-persistence",
            ),
            safe_route_metadata={},
            expected_child_launches=1,
            allow_unsafe_runtime=False,
            selected_model="fixture-model",
            skip_cost_guard=True,
        )
        self.assertEqual(prepared.selected_model, "fixture-model")
        self.assertTrue(prepared.skip_cost_guard)
        self.assertNotIn("skip_cost_guard", prepared.metadata())

    def test_local_unsafe_acceptance_is_initialized_and_preserved_when_blocked(self) -> None:
        observed = ExecutableIdentity.capture(self.fake_runtime)
        policy = RuntimeSecurityPolicy(
            runtime_executable=str(self.fake_runtime.resolve()),
            unsafe_runtimes=(
                ApprovedUnsafeRuntime(
                    runtime_id="fixture-unsafe",
                    identity=_pinned_identity(observed),
                ),
            ),
        )
        candidate = RuntimeExecutableCandidate(
            canonical_path=str(self.fake_runtime.resolve()),
            source="runtime_security.override.json",
            trust_class="local_configured",
        )
        with patch.object(
            orchestrator, "load_runtime_security_policy", return_value=policy
        ), patch.object(
            orchestrator, "resolve_runtime_candidate", return_value=candidate
        ):
            launch = orchestrator.run_streaming_agent(
                "unsafe acceptance",
                cwd=self.workspace,
                allow_unsafe_runtime=True,
            )
        self.assertEqual(launch["acceptance_status"], "pending_controller_review")
        active_status = orchestrator.single_run_status(str(launch["run_id"]))
        self.assertEqual(
            active_status["acceptance_status"], "pending_controller_review"
        )
        terminal = self._wait_for_terminal_metadata(
            self.runs_dir / str(launch["run_id"])
        )
        self.assertEqual(terminal["acceptance_status"], "pending_controller_review")

        with patch.object(
            orchestrator, "load_runtime_security_policy", return_value=policy
        ), patch.object(
            orchestrator, "resolve_runtime_candidate", return_value=candidate
        ), patch.object(
            orchestrator,
            "capture_process_identity",
            side_effect=lambda pid, *, launch_nonce: _unsupported_identity(
                pid, launch_nonce
            ),
        ):
            blocked = orchestrator.run_streaming_agent(
                "unsafe blocked acceptance",
                cwd=self.workspace,
                allow_unsafe_runtime=True,
            )
        self.assertEqual(blocked["status"], "blocked_process_identity")
        self.assertEqual(blocked["acceptance_status"], "pending_controller_review")

    def test_one_shot_post_start_identity_failure_uses_runtime_identity_status(self) -> None:
        prepared = self._prepare("one_shot")
        with patch.object(
            orchestrator,
            "capture_process_identity",
            side_effect=lambda pid, *, launch_nonce: _unsupported_identity(
                pid, launch_nonce
            ),
        ):
            result = orchestrator.start_prepared_worker_launch(prepared)
        self.assertEqual(result["status"], "blocked_runtime_identity")
        self.assertEqual(
            result["security_error"]["code"], "process_identity_unverified"
        )

    def test_frame_requires_metadata_prompt_length_and_exact_eof(self) -> None:
        for trailing in (b"", b"trailing"):
            with self.subTest(trailing=bool(trailing)):
                prepared = self._prepare("streaming", prompt="length-bound-prompt")
                response = self._direct_worker_protocol(
                    prepared,
                    nonce_env=prepared.launch_spec.launch_nonce,
                    prompt_payload=b"" if not trailing else prepared.prompt_bytes,
                    trailing_payload=trailing,
                )
                self.assertEqual(
                    response["security_error"]["code"], "runtime_not_trusted"
                )
                latest = orchestrator.read_metadata(
                    self.runs_dir / str(prepared.metadata()["run_id"])
                )
                self.assertIsNone(latest.get("child_pid"))

    def test_event_sequence_is_controller_owned_and_recovers_after_seq_write_failure(self) -> None:
        run_id = orchestrator.new_run_id()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True)
        real_atomic_text = orchestrator._atomic_write_text

        def fail_seq(path: Path, text: str) -> None:
            if path.name == "event_seq.txt":
                raise OSError("seq write failed")
            real_atomic_text(path, text)

        with patch.object(orchestrator, "_atomic_write_text", side_effect=fail_seq):
            with self.assertRaises(OSError):
                orchestrator.append_event(
                    run_dir, {"type": "first", "seq": 999}
                )
        orchestrator.append_event(run_dir, {"type": "second", "seq": 999})
        events = [
            json.loads(line)
            for line in (run_dir / "events.ndjson").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([event["seq"] for event in events], [1, 2])


class SecondReviewPublicationTests(GuardedLaunchFixture):
    def test_gate_publication_has_no_post_replace_permission_step(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        self._arm_worker_gate(run_dir, prepared)
        target = run_dir / orchestrator.WORKER_START_GATE_FILENAME
        real_set_private = orchestrator._set_private_file

        def reject_post_publication(path: Path) -> None:
            if Path(path) == target:
                raise OSError("post-publication permission fault")
            real_set_private(Path(path))

        with patch.object(
            orchestrator, "_set_private_file", side_effect=reject_post_publication
        ):
            opened = orchestrator._open_worker_start_gate(run_dir)
        self.assertEqual(opened["worker_launch"]["start_gate"], "open")
        self.assertEqual(
            orchestrator.read_metadata(run_dir)["worker_launch"]["start_gate"],
            "closed",
        )
        self.assertTrue(target.is_file())

    def test_gate_is_not_published_when_lock_release_fails(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, _metadata = orchestrator._initialize_prepared_run(prepared)
        self._arm_worker_gate(run_dir, prepared)

        class FaultingRelease:
            def __enter__(self) -> None:
                return None

            def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
                raise OSError("lock release fault")

        with patch.object(
            orchestrator, "artifact_lock", return_value=FaultingRelease()
        ):
            with self.assertRaises(OSError):
                orchestrator._open_worker_start_gate(run_dir)
        self.assertEqual(
            orchestrator.read_metadata(run_dir)["worker_launch"]["start_gate"],
            "closed",
        )
        self.assertFalse(
            (run_dir / orchestrator.WORKER_START_GATE_FILENAME).exists()
        )

    def test_gate_verification_fault_keeps_controller_worker_agreement(self) -> None:
        def reject_open_gate(path: Path, *, is_dir: bool = False) -> None:
            candidate = Path(path)
            if not is_dir and candidate.is_file():
                payload = candidate.read_bytes()
                if b'"state": "open"' in payload:
                    raise OSError("pre-publication verification fault")

        with patch.object(
            orchestrator,
            "_verify_private_path",
            side_effect=reject_open_gate,
            create=True,
        ):
            result = orchestrator.run_streaming_agent(
                "gate publication fault", cwd=self.workspace
            )
        self.assertEqual(result.get("status"), "blocked_runtime_launch", result)
        self._wait_for_pid_exit(int(result["worker_pid"]))
        metadata = orchestrator.read_metadata(
            self.runs_dir / str(result["run_id"])
        )
        self.assertNotEqual(
            (metadata.get("worker_launch") or {}).get("start_gate"), "open"
        )
        self.assertIsNone(metadata.get("child_pid"))

    def test_admission_release_fault_keeps_gate_closed_and_worker_owned(self) -> None:
        class FaultingAdmissionRelease:
            def __enter__(self) -> None:
                return None

            def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
                raise OSError("admission release fault")

        with patch.object(
            orchestrator,
            "launch_lock",
            return_value=FaultingAdmissionRelease(),
        ):
            result = orchestrator.run_streaming_agent(
                "admission release before gate", cwd=self.workspace
            )
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self._wait_for_pid_exit(int(result["worker_pid"]))
        metadata = orchestrator.read_metadata(
            self.runs_dir / str(result["run_id"])
        )
        self.assertEqual(
            metadata["worker_launch"]["start_gate"], "closed"
        )
        self.assertIsNone(metadata.get("child_pid"))


class SecondReviewTransportTests(GuardedLaunchFixture):
    def _write_pressure_runtime(
        self, *, newline: bool, marker: Path, sleep_after_input: float = 0.0
    ) -> None:
        chunk = "(b'X' * 4095 + b'\\n')" if newline else "(b'Y' * 4096)"
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import hashlib, json, pathlib, sys, time",
                    f"chunk = {chunk}",
                    "for _ in range(768):",
                    "    sys.stdout.buffer.write(chunk)",
                    "sys.stdout.buffer.flush()",
                    "prompt = sys.stdin.buffer.read()",
                    f"pathlib.Path({str(marker)!r}).write_text(json.dumps({{'bytes': len(prompt), 'sha256': hashlib.sha256(prompt).hexdigest()}}), encoding='utf-8')",
                    f"time.sleep({sleep_after_input!r})",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def test_truncate_drains_newline_pressure_and_finishes_stdin(self) -> None:
        marker = self.workspace / "newline-stdin-complete.txt"
        self._write_pressure_runtime(newline=True, marker=marker)
        launch = orchestrator.run_streaming_agent(
            "truncate newline pressure",
            cwd=self.workspace,
            timeout_seconds=6,
            max_output_bytes=64 * 1024,
            max_events_bytes=512 * 1024,
            output_budget_policy="truncate",
        )
        metadata = self._wait_for_terminal_metadata(
            self.runs_dir / str(launch["run_id"]), timeout=12
        )
        self.assertEqual(metadata["status"], "succeeded", metadata)
        self.assertEqual(metadata["output_budget"]["state"], "truncated")
        self.assertTrue(marker.is_file())
        delivered = json.loads(marker.read_text(encoding="utf-8"))
        expected = orchestrator.build_prompt(
            "implementation",
            "truncate newline pressure",
            None,
            artifact_root=self.artifact_root,
        ).encode("utf-8")
        self.assertEqual(delivered["bytes"], len(expected))
        self.assertEqual(delivered["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(delivered["bytes"], metadata["prompt_bytes"])
        self._wait_for_pid_exit(int(metadata["child_pid"]))
        self._wait_for_pid_exit(int(metadata["worker_pid"]))

    def test_truncate_drains_no_newline_pressure_and_finishes_stdin(self) -> None:
        marker = self.workspace / "no-newline-stdin-complete.txt"
        self._write_pressure_runtime(newline=False, marker=marker)
        launch = orchestrator.run_streaming_agent(
            "truncate no-newline pressure",
            cwd=self.workspace,
            timeout_seconds=6,
            max_output_bytes=64 * 1024,
            max_events_bytes=512 * 1024,
            output_budget_policy="truncate",
        )
        metadata = self._wait_for_terminal_metadata(
            self.runs_dir / str(launch["run_id"]), timeout=12
        )
        self.assertEqual(metadata["status"], "succeeded", metadata)
        self.assertEqual(metadata["output_budget"]["state"], "truncated")
        self.assertTrue(marker.is_file())
        delivered = json.loads(marker.read_text(encoding="utf-8"))
        expected = orchestrator.build_prompt(
            "implementation",
            "truncate no-newline pressure",
            None,
            artifact_root=self.artifact_root,
        ).encode("utf-8")
        self.assertEqual(delivered["bytes"], len(expected))
        self.assertEqual(delivered["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(delivered["bytes"], metadata["prompt_bytes"])
        self._wait_for_pid_exit(int(metadata["child_pid"]))
        self._wait_for_pid_exit(int(metadata["worker_pid"]))

    def test_stop_policy_terminates_once_under_no_newline_pressure(self) -> None:
        marker = self.workspace / "stop-policy-stdin.txt"
        self._write_pressure_runtime(
            newline=False, marker=marker, sleep_after_input=3.0
        )
        launch = orchestrator.run_streaming_agent(
            "stop no-newline pressure",
            cwd=self.workspace,
            timeout_seconds=6,
            max_output_bytes=64 * 1024,
            max_events_bytes=512 * 1024,
            output_budget_policy="stop",
        )
        metadata = self._wait_for_terminal_metadata(
            self.runs_dir / str(launch["run_id"]), timeout=12
        )
        self.assertEqual(metadata["status"], "stopped", metadata)
        self.assertEqual(metadata["stop_reason"], "output_budget_exceeded")
        self._wait_for_pid_exit(int(metadata["child_pid"]))
        self._wait_for_pid_exit(int(metadata["worker_pid"]))

    def test_truncate_pressure_does_not_disable_deadline(self) -> None:
        marker = self.workspace / "deadline-stdin.txt"
        self._write_pressure_runtime(
            newline=False, marker=marker, sleep_after_input=3.0
        )
        started = time.monotonic()
        launch = orchestrator.run_streaming_agent(
            "truncate deadline pressure",
            cwd=self.workspace,
            timeout_seconds=1,
            max_output_bytes=64 * 1024,
            max_events_bytes=512 * 1024,
            output_budget_policy="truncate",
        )
        metadata = self._wait_for_terminal_metadata(
            self.runs_dir / str(launch["run_id"]), timeout=8
        )
        self.assertEqual(metadata["status"], "timed_out", metadata)
        self.assertLess(time.monotonic() - started, 6.0)
        self._wait_for_pid_exit(int(metadata["child_pid"]))
        self._wait_for_pid_exit(int(metadata["worker_pid"]))


class SecondReviewScrubAndScannerTests(GuardedLaunchFixture):
    def test_terminal_snapshots_scope_filenames_and_errors_are_scrubbed(self) -> None:
        task_secret = "terminal-task-secret-z5"
        context_secret = "terminal-context-secret-y6"

        def snapshot(
            _run_dir: Path,
            _cwd: Path,
            label: str,
            _sensitive_values: tuple[str, ...] = (),
            deadline: float | None = None,
        ) -> dict[str, object]:
            del deadline
            if label == "after":
                return {
                    "ok": False,
                    "changed_paths": [f"src/{task_secret}.py"],
                    "untracked_paths": [f"reports/{context_secret}.txt"],
                    "error": f"git error includes {task_secret}",
                }
            return {"ok": True, "changed_paths": []}

        scope = {
            "ok": False,
            "violations": [f"forbidden/{context_secret}.txt"],
            "error": f"scope error includes {task_secret}",
        }
        with patch.object(
            orchestrator, "capture_git_snapshot", side_effect=snapshot
        ), patch.object(
            orchestrator, "_check_write_scope_with_evidence", return_value=scope
        ):
            result = orchestrator.run_agent(
                task_secret, context=context_secret, cwd=self.workspace
            )
        run_dir = self.runs_dir / str(result["run_id"])
        for secret in (task_secret, context_secret):
            self.assertNotIn(secret.encode(), self._scan_run(run_dir))
            self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))
        metadata = orchestrator.read_metadata(run_dir)
        self.assertIn(
            orchestrator.SCRUBBED_VALUE,
            json.dumps(metadata["git_after"], ensure_ascii=False),
        )
        self.assertIn(
            orchestrator.SCRUBBED_VALUE,
            json.dumps(metadata["write_scope_check"], ensure_ascii=False),
        )

    def test_endpoint_environment_components_are_scrubbed_inside_prose(self) -> None:
        endpoint_user = "endpoint-user-u7"
        endpoint_password = "endpoint-password-p8"
        endpoint_query = "endpoint-query-q9"
        endpoint = (
            f"https://{endpoint_user}:{endpoint_password}@example.invalid/api"
            f"?token={endpoint_query}&region=test"
        )
        provider = orchestrator.Provider(
            id="endpoint-env-provider",
            name="Endpoint Env Provider",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_API_KEY": FAKE_PROVIDER_SECRET,
                    "ANTHROPIC_MODEL": "fixture-model",
                    "ANTHROPIC_BASE_URL": endpoint,
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import os, sys",
                    "sys.stdin.buffer.read()",
                    "print('endpoint prose is ' + os.environ['ANTHROPIC_BASE_URL'], flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        with patch.object(orchestrator, "get_provider", return_value=provider):
            one_shot = orchestrator.run_agent("endpoint prose", cwd=self.workspace)
            streaming = orchestrator.run_streaming_agent(
                "endpoint prose", cwd=self.workspace
            )
        stream_dir = self.runs_dir / str(streaming["run_id"])
        self._wait_for_terminal_metadata(stream_dir)
        for run_dir in (
            self.runs_dir / str(one_shot["run_id"]),
            stream_dir,
        ):
            payload = self._scan_run(run_dir)
            for secret in (endpoint_user, endpoint_password, endpoint_query):
                self.assertNotIn(secret.encode(), payload)
            self.assertIn(orchestrator.SCRUBBED_VALUE.encode(), payload)

    def test_secret_scanner_is_bounded_on_long_delimiter_free_lines(self) -> None:
        script = "\n".join(
            [
                "import sys, time",
                f"sys.path.insert(0, {str(ORCHESTRATOR_DIR)!r})",
                "import cc_orchestrator as c",
                "started = time.monotonic()",
                "for size in (64 * 1024, 256 * 1024):",
                "    value = 'A' * size",
                "    assert c.redact(value) == value",
                "    assert c.classify_secret_line(value, 'fixture', 1) is None",
                "value = 'sk-' * (128 * 1024 // 3)",
                "assert c.classify_secret_line(value, 'fixture', 1) is not None",
                "assert '...' in c.redact(value)",
                "print(time.monotonic() - started)",
            ]
        )
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", script],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail("secret scanner exceeded the two-second wall-clock bound")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertLess(float(completed.stdout.strip()), 1.5)
        self.assertIsNotNone(
            orchestrator.classify_secret_line(
                "prefix sk-abcdefghijklmnopqrstuvwxyz", "fixture", 1
            )
        )


class SecondReviewSecurityEventTests(GuardedLaunchFixture):
    def _unsafe_policy(self) -> tuple[RuntimeSecurityPolicy, RuntimeExecutableCandidate]:
        observed = ExecutableIdentity.capture(self.fake_runtime)
        policy = RuntimeSecurityPolicy(
            runtime_executable=str(self.fake_runtime.resolve()),
            unsafe_runtimes=(
                ApprovedUnsafeRuntime(
                    runtime_id="fixture-unsafe-event",
                    identity=_pinned_identity(observed),
                ),
            ),
        )
        candidate = RuntimeExecutableCandidate(
            canonical_path=str(self.fake_runtime.resolve()),
            source="runtime_security.override.json",
            trust_class="local_configured",
        )
        return policy, candidate

    def test_local_unsafe_event_precedes_one_shot_popen_and_stream_gate(self) -> None:
        policy, candidate = self._unsafe_policy()
        one_shot_observation: list[list[dict[str, object]]] = []
        real_popen = subprocess.Popen

        def observe_one_shot(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            run_dir = self._run_dirs()[-1]
            one_shot_observation.append(
                [
                    json.loads(line)
                    for line in (run_dir / "events.ndjson").read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip()
                ]
            )
            return real_popen(*args, **kwargs)

        common = (
            patch.object(orchestrator, "load_runtime_security_policy", return_value=policy),
            patch.object(orchestrator, "resolve_runtime_candidate", return_value=candidate),
        )
        with common[0], common[1], patch.object(
            orchestrator.subprocess, "Popen", side_effect=observe_one_shot
        ):
            orchestrator.run_agent(
                "unsafe event one shot",
                cwd=self.workspace,
                allow_unsafe_runtime=True,
            )
        self.assertTrue(one_shot_observation)
        unsafe = one_shot_observation[0][-1]
        self.assertEqual(unsafe["type"], "unsafe_runtime_approved")
        self.assertEqual(unsafe["severity"], "high")
        self.assertEqual(unsafe["trust_level"], "local_unsafe")

        gate_observation: list[list[dict[str, object]]] = []
        real_open_gate = orchestrator._open_worker_start_gate

        def observe_gate(run_dir: Path) -> dict[str, object]:
            gate_observation.append(
                [
                    json.loads(line)
                    for line in (run_dir / "events.ndjson").read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip()
                ]
            )
            return real_open_gate(run_dir)

        with patch.object(
            orchestrator, "load_runtime_security_policy", return_value=policy
        ), patch.object(
            orchestrator, "resolve_runtime_candidate", return_value=candidate
        ), patch.object(
            orchestrator, "_open_worker_start_gate", side_effect=observe_gate
        ):
            launch = orchestrator.run_streaming_agent(
                "unsafe event streaming",
                cwd=self.workspace,
                allow_unsafe_runtime=True,
            )
        self._wait_for_terminal_metadata(self.runs_dir / str(launch["run_id"]))
        self.assertTrue(gate_observation)
        event_types = [event["type"] for event in gate_observation[0]]
        self.assertIn("unsafe_runtime_approved", event_types)
        stream_unsafe = next(
            event
            for event in gate_observation[0]
            if event["type"] == "unsafe_runtime_approved"
        )
        self.assertEqual(stream_unsafe["severity"], "high")


class SecondReviewArtifactWalkTests(GuardedLaunchFixture):
    def test_scrub_walk_rejects_links_and_oversized_files(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        outside = self.workspace / "outside-secret.txt"
        outside.write_text("outside", encoding="utf-8")
        link = run_dir / "linked.txt"
        try:
            os.symlink(outside, link)
        except OSError:
            link = None
        if link is not None:
            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator._scrub_run_artifacts(run_dir, ("outside",))
            link.unlink()

        oversized = run_dir / "oversized.bin"
        with oversized.open("wb") as handle:
            handle.seek(32 * 1024 * 1024)
            handle.write(b"x")
        with self.assertRaises(orchestrator.OrchestratorError):
            orchestrator._scrub_run_artifacts(run_dir, ("secret",))


class SecondReviewEventSequenceTests(GuardedLaunchFixture):
    def test_event_sequence_uses_sidecar_without_full_log_scan(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        events_path = run_dir / "events.ndjson"
        events_path.write_text(
            "".join(
                json.dumps({"seq": seq, "type": "fixture"}) + "\n"
                for seq in range(1, 5001)
            ),
            encoding="utf-8",
        )
        (run_dir / "event_seq.txt").write_text(
            json.dumps({"seq": 5000, "events_bytes": events_path.stat().st_size}),
            encoding="utf-8",
        )
        real_read_text = Path.read_text

        def reject_event_read(path: Path, *args: object, **kwargs: object) -> str:
            if Path(path) == events_path:
                raise AssertionError("events log was fully rescanned")
            return real_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", reject_event_read), patch.object(
            orchestrator,
            "_last_complete_event",
            side_effect=AssertionError("sidecar fast path was not used"),
        ):
            orchestrator.append_event(run_dir, {"type": "next", "seq": 999})
        last = json.loads(events_path.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(last["seq"], 5001)

    def test_event_sequence_recovers_last_complete_event_and_truncates_tail(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        events_path = run_dir / "events.ndjson"
        events_path.write_bytes(
            json.dumps({"seq": 7, "type": "complete"}).encode() + b"\n{\"seq\": 8"
        )
        orchestrator.append_event(run_dir, {"type": "recovered"})
        events = [
            json.loads(line)
            for line in events_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([event["seq"] for event in events], [7, 8])


class ThirdReviewGateArtifactTests(GuardedLaunchFixture):
    def test_gate_publication_preserves_concurrent_terminal_metadata(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, _metadata = orchestrator._initialize_prepared_run(prepared)
        self._arm_worker_gate(run_dir, prepared)
        real_replace = orchestrator._replace_prepared_atomic_write
        gate_name = getattr(
            orchestrator, "WORKER_START_GATE_FILENAME", "worker-start-gate.json"
        )

        def interleave(temporary: Path, target: Path) -> None:
            if Path(target).name == gate_name:
                orchestrator.update_metadata(
                    run_dir,
                    status="stopped",
                    stop_requested_at="fixture-stop",
                    terminal_state_count=1,
                )
            real_replace(temporary, target)

        with patch.object(
            orchestrator,
            "_replace_prepared_atomic_write",
            side_effect=interleave,
        ):
            orchestrator._open_worker_start_gate(run_dir)
        metadata = orchestrator.read_metadata(run_dir)
        self.assertEqual(metadata["status"], "stopped")
        self.assertEqual(metadata["stop_requested_at"], "fixture-stop")
        self.assertEqual(metadata["terminal_state_count"], 1)
        self.assertTrue((run_dir / gate_name).is_file())

    def test_gate_publication_preserves_arbitrary_concurrent_fields(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, _metadata = orchestrator._initialize_prepared_run(prepared)
        self._arm_worker_gate(run_dir, prepared)
        real_replace = orchestrator._replace_prepared_atomic_write
        gate_name = getattr(
            orchestrator, "WORKER_START_GATE_FILENAME", "worker-start-gate.json"
        )

        def interleave(temporary: Path, target: Path) -> None:
            if Path(target).name == gate_name:
                orchestrator.update_metadata(
                    run_dir,
                    arbitrary_controller_field={"preserve": [1, 2, 3]},
                    status="running",
                )
            real_replace(temporary, target)

        with patch.object(
            orchestrator,
            "_replace_prepared_atomic_write",
            side_effect=interleave,
        ):
            orchestrator._open_worker_start_gate(run_dir)
        metadata = orchestrator.read_metadata(run_dir)
        self.assertEqual(
            metadata["arbitrary_controller_field"], {"preserve": [1, 2, 3]}
        )
        self.assertEqual(metadata["status"], "running")
        self.assertTrue((run_dir / gate_name).is_file())


class ThirdReviewGitEvidenceTests(GuardedLaunchFixture):
    def _initialize_git_workspace(self) -> None:
        completed = subprocess.run(
            ["git", "init"],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def _write_scope(self, denied_name: str) -> None:
        scope_dir = self.workspace / ".claude-code-orchestrator"
        scope_dir.mkdir()
        (scope_dir / "write-scope.json").write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [str(self.workspace / denied_name)],
                    "max_diff_lines": 100,
                }
            ),
            encoding="utf-8",
        )

    def _write_git_mutating_runtime(self) -> None:
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import pathlib, sys",
                    "prompt = sys.stdin.buffer.read().decode('utf-8')",
                    "task = prompt.rsplit('\\nTask:\\n', 1)[1].split('\\n\\nAdditional context:\\n', 1)[0].strip()",
                    "pathlib.Path(task).write_text('changed', encoding='utf-8')",
                    "print('done', flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def test_raw_git_evidence_enforces_sensitive_denied_path(self) -> None:
        self._initialize_git_workspace()
        self._write_git_mutating_runtime()
        denied_name = "denied-sensitive-task-path"
        self._write_scope(denied_name)
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                (self.workspace / denied_name).unlink(missing_ok=True)
                if streaming:
                    launch = orchestrator.run_streaming_agent(
                        denied_name, cwd=self.workspace
                    )
                    run_dir = self.runs_dir / str(launch["run_id"])
                    metadata = self._wait_for_terminal_metadata(run_dir)
                else:
                    metadata = orchestrator.run_agent(
                        denied_name, cwd=self.workspace
                    )
                    run_dir = self.runs_dir / str(metadata["run_id"])
                self.assertEqual(
                    metadata["acceptance_status"], "blocked_write_scope", metadata
                )
                violation_types = {
                    item["type"]
                    for item in metadata["write_scope_check"]["violations"]
                }
                self.assertIn("denied_path", violation_types)
                self.assertNotIn(denied_name.encode(), self._scan_run(run_dir))

    def test_git_artifacts_are_scrubbed_before_each_atomic_write(self) -> None:
        self._initialize_git_workspace()
        secret = "raw-git-artifact-secret"
        (self.workspace / secret).write_text("changed", encoding="utf-8")
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        observed: list[bytes] = []
        real_atomic = orchestrator._atomic_write_bytes

        def inspect(path: Path, payload: bytes) -> None:
            if Path(path).name.startswith("git_after"):
                observed.append(payload)
                self.assertNotIn(secret.encode(), payload)
            real_atomic(path, payload)

        with patch.object(orchestrator, "_atomic_write_bytes", side_effect=inspect):
            snapshot = orchestrator.capture_git_snapshot(
                run_dir,
                self.workspace,
                "after",
                sensitive_values=(secret,),
            )
        self.assertTrue(snapshot["ok"], snapshot)
        self.assertGreaterEqual(len(observed), 5)
        self.assertNotIn(secret.encode(), self._scan_run(run_dir))

    def test_boundary_crashes_never_expose_raw_git_artifacts(self) -> None:
        self._initialize_git_workspace()
        self._write_git_mutating_runtime()

        class InjectedCrash(BaseException):
            pass

        for boundary in ("metadata", "scope", "event", "final_scrub"):
            with self.subTest(boundary=boundary):
                secret = f"crash-secret-{boundary}"
                (self.workspace / secret).unlink(missing_ok=True)
                real_update = orchestrator.update_metadata
                real_scope = getattr(
                    orchestrator, "_check_write_scope_with_evidence", None
                )
                real_append = orchestrator.append_event
                real_scrub = orchestrator._scrub_run_artifacts
                scrub_calls = 0

                def update(run_dir: Path, **updates: object) -> dict[str, object]:
                    if boundary == "metadata" and "git_after" in updates:
                        raise InjectedCrash()
                    return real_update(run_dir, **updates)

                def scope(*args: object, **kwargs: object) -> dict[str, object]:
                    if boundary == "scope":
                        raise InjectedCrash()
                    if real_scope is None:
                        return {"ok": True, "violations": []}
                    return real_scope(*args, **kwargs)

                def append(run_dir: Path, event: dict[str, object]) -> None:
                    if boundary == "event" and event.get("type") == "process_exited":
                        raise InjectedCrash()
                    real_append(run_dir, event)

                def scrub(run_dir: Path, values: tuple[str, ...]) -> None:
                    nonlocal scrub_calls
                    scrub_calls += 1
                    if boundary == "final_scrub" and scrub_calls > 1:
                        raise InjectedCrash()
                    real_scrub(run_dir, values)

                before = set(self._run_dirs())
                with patch.object(
                    orchestrator, "update_metadata", side_effect=update
                ), patch.object(
                    orchestrator,
                    "_check_write_scope_with_evidence",
                    side_effect=scope,
                    create=True,
                ), patch.object(
                    orchestrator, "append_event", side_effect=append
                ), patch.object(
                    orchestrator, "_scrub_run_artifacts", side_effect=scrub
                ):
                    with self.assertRaises(InjectedCrash):
                        orchestrator.run_agent(secret, cwd=self.workspace)
                created = [path for path in self._run_dirs() if path not in before]
                self.assertEqual(len(created), 1)
                self.assertNotIn(secret.encode(), self._scan_run(created[0]))


class ThirdReviewEndpointEncodingTests(GuardedLaunchFixture):
    def test_raw_and_decoded_endpoint_components_are_scrubbed(self) -> None:
        raw_user = "encoded%2Duser+literal"
        decoded_user = "encoded-user+literal"
        raw_password = "encoded%2Bpassword"
        decoded_password = "encoded+password"
        raw_query = "query%2Dsecret+space"
        decoded_query = "query-secret space"
        endpoint = (
            f"https://{raw_user}:{raw_password}@example.invalid/api"
            f"?token={raw_query}&region=test"
        )
        provider = orchestrator.Provider(
            id="encoded-endpoint-provider",
            name="Encoded Endpoint Provider",
            app_type="claude",
            settings={
                "env": {
                    "ANTHROPIC_API_KEY": FAKE_PROVIDER_SECRET,
                    "ANTHROPIC_MODEL": "fixture-model",
                    "ANTHROPIC_BASE_URL": endpoint,
                }
            },
            category=None,
            provider_type=None,
            is_current=True,
            endpoints=[],
        )
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import os, sys",
                    "from urllib.parse import parse_qsl, unquote, urlsplit",
                    "sys.stdin.buffer.read()",
                    "endpoint = os.environ['ANTHROPIC_BASE_URL']",
                    "parsed = urlsplit(endpoint)",
                    "decoded = (unquote(parsed.username or ''), unquote(parsed.password or ''), dict(parse_qsl(parsed.query)).get('token', ''))",
                    "print('raw endpoint prose: ' + endpoint, flush=True)",
                    "print('decoded endpoint prose: ' + ' | '.join(decoded), flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        with patch.object(orchestrator, "get_provider", return_value=provider):
            one_shot = orchestrator.run_agent(
                "encoded endpoint prose", cwd=self.workspace
            )
            streaming = orchestrator.run_streaming_agent(
                "encoded endpoint prose", cwd=self.workspace
            )
        stream_dir = self.runs_dir / str(streaming["run_id"])
        self._wait_for_terminal_metadata(stream_dir)
        forbidden = (
            raw_user,
            decoded_user,
            raw_password,
            decoded_password,
            raw_query,
            decoded_query,
        )
        for run_dir in (
            self.runs_dir / str(one_shot["run_id"]),
            stream_dir,
        ):
            payload = self._scan_run(run_dir)
            for value in forbidden:
                self.assertNotIn(value.encode(), payload)


class ThirdReviewEventRecoveryTests(GuardedLaunchFixture):
    def test_stale_ahead_sidecar_is_ignored_on_size_mismatch(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        events_path = run_dir / "events.ndjson"
        events_path.write_text(
            json.dumps({"seq": 7, "type": "complete"}) + "\n",
            encoding="utf-8",
        )
        (run_dir / "event_seq.txt").write_text(
            json.dumps({"seq": 99, "events_bytes": 0}), encoding="utf-8"
        )
        orchestrator.append_event(run_dir, {"type": "recovered"})
        events = [
            json.loads(line)
            for line in events_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([event["seq"] for event in events], [7, 8])
        sidecar = json.loads(
            (run_dir / "event_seq.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(sidecar["seq"], 8)


class ThirdReviewHandleBindingTests(GuardedLaunchFixture):
    def test_swap_to_link_between_discovery_and_open_is_rejected(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        victim = run_dir / "victim.txt"
        victim.write_text("safe", encoding="utf-8")
        outside = self.workspace / "outside.txt"
        outside.write_text("outside-secret", encoding="utf-8")
        backup = run_dir / "victim.original"
        swapped = False

        if os.name == "nt":
            real_open = getattr(orchestrator, "_open_windows_managed_file", None)
            self.assertIsNotNone(real_open)

            def swap_then_open(path: Path, *args: object, **kwargs: object) -> object:
                nonlocal swapped
                if Path(path) == victim and not swapped:
                    victim.replace(backup)
                    os.symlink(outside, victim)
                    swapped = True
                return real_open(path, *args, **kwargs)

            opener_patch = patch.object(
                orchestrator,
                "_open_windows_managed_file",
                side_effect=swap_then_open,
            )
        else:
            real_open = os.open

            def swap_then_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                relative_victim = (
                    kwargs.get("dir_fd") is not None
                    and Path(path) == Path(victim.name)
                )
                if (Path(path) == victim or relative_victim) and not swapped:
                    victim.replace(backup)
                    os.symlink(outside, victim)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            opener_patch = patch.object(
                orchestrator.os, "open", side_effect=swap_then_open
            )
        with opener_patch:
            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator._scrub_run_artifacts(run_dir, ("outside-secret",))
        self.assertTrue(swapped)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside-secret")


class FourthReviewNonceTransactionTests(GuardedLaunchFixture):
    def test_stop_between_gate_poll_and_lock_leaves_nonce_unconsumed(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, _metadata = orchestrator._initialize_prepared_run(prepared)
        nonce = prepared.launch_spec.launch_nonce
        identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata = orchestrator.update_metadata(
            run_dir,
            worker_pid=os.getpid(),
            worker_process_identity=identity.to_dict(),
            controller_pid=identity.parent_pid,
        )
        self._publish_worker_gate(run_dir, metadata)
        real_read_gate = orchestrator._read_worker_start_gate
        calls = 0

        def stop_after_poll(path: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            gate = real_read_gate(path)
            if calls == 1:
                orchestrator.update_metadata(
                    run_dir,
                    status="stopped",
                    stop_requested_at="fixture-stop",
                    terminal_state_count=1,
                )
            return gate

        with patch.object(
            orchestrator, "_read_worker_start_gate", side_effect=stop_after_poll
        ):
            with self.assertRaises(RuntimeSecurityError):
                orchestrator._consume_worker_nonce(run_dir, nonce)
        latest = orchestrator.read_metadata(run_dir)
        self.assertEqual(latest["status"], "stopped")
        self.assertFalse(latest["worker_launch"]["nonce_consumed"])
        self.assertIsNone(latest.get("child_pid"))


class FourthReviewScopeFixture(GuardedLaunchFixture):
    denied_name = "sensitive-denied-fourth-cycle"

    def _initialize_git_workspace(self) -> None:
        completed = subprocess.run(
            ["git", "init"],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def _scope_path(self) -> Path:
        return self.workspace / ".claude-code-orchestrator" / "write-scope.json"

    def _write_scope(self, denied_name: str | None = None) -> Path:
        path = self._scope_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [
                        str(self.workspace / (denied_name or self.denied_name))
                    ],
                    "max_diff_lines": 100,
                }
            ),
            encoding="utf-8",
        )
        return path

    def _write_mutating_runtime(self, replacement: str = "changed") -> None:
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import pathlib, sys",
                    "prompt = sys.stdin.buffer.read().decode('utf-8')",
                    "task = prompt.rsplit('\\nTask:\\n', 1)[1].split('\\n\\nAdditional context:\\n', 1)[0].strip()",
                    f"pathlib.Path(task).write_text({replacement!r}, encoding='utf-8')",
                    "print('done', flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def _run_sensitive_denied_path(self) -> tuple[dict[str, object], Path]:
        self._initialize_git_workspace()
        self._write_scope()
        self._write_mutating_runtime()
        metadata = orchestrator.run_agent(self.denied_name, cwd=self.workspace)
        run_dir = self.runs_dir / str(metadata["run_id"])
        self.assertEqual(metadata["acceptance_status"], "blocked_write_scope")
        return metadata, run_dir


class FourthReviewAuthoritativeScopeTests(FourthReviewScopeFixture):
    def test_active_run_without_terminal_scope_never_reuses_projection(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        self.assertNotIn("write_scope_check", metadata)
        with patch.object(
            orchestrator,
            "_check_write_scope_with_evidence",
            side_effect=AssertionError("scrubbed projection was re-evaluated"),
        ):
            scope = orchestrator.check_write_scope(run_id=run_dir.name)
        self.assertFalse(scope["ok"], scope)
        self.assertEqual(scope["status"], "pending_authoritative_scope")

    def test_public_scope_api_uses_authoritative_terminal_result(self) -> None:
        metadata, _run_dir = self._run_sensitive_denied_path()
        scope = orchestrator.check_write_scope(run_id=str(metadata["run_id"]))
        self.assertFalse(scope["ok"], scope)
        self.assertIn(
            "denied_path", {item["type"] for item in scope["violations"]}
        )

    def test_risk_scoring_and_cli_preserve_authoritative_scope_denial(self) -> None:
        metadata, _run_dir = self._run_sensitive_denied_path()
        run_id = str(metadata["run_id"])
        with patch.object(
            orchestrator,
            "secret_scan_run",
            return_value={
                "ok": True,
                "finding_count": 0,
                "blocking_count": 0,
            },
        ):
            risks = orchestrator.detect_failure_modes(run_id)
            score = orchestrator.score_worker(run_id, solved=True, apply=False)
        self.assertIn(
            "write_scope_violation",
            {item["code"] for item in risks["flags"]},
        )
        self.assertFalse(score["scope_ok"])

        output = io.StringIO()
        with patch.object(
            sys,
            "argv",
            [str(orchestrator.__file__), "check-write-scope", "--run-id", run_id],
        ), contextlib.redirect_stdout(output):
            orchestrator.main()
        cli_scope = json.loads(output.getvalue())
        self.assertFalse(cli_scope["ok"], cli_scope)

    def test_verify_run_gate_uses_authoritative_scope_denial(self) -> None:
        metadata, _run_dir = self._run_sensitive_denied_path()
        run_id = str(metadata["run_id"])
        with patch.object(orchestrator, "REPORTS_DIR", self.workspace / "reports"), patch.object(
            orchestrator,
            "secret_scan_run",
            return_value={"ok": True, "finding_count": 0, "blocking_count": 0},
        ), patch.object(
            orchestrator,
            "score_worker",
            return_value={"quality_score": 0},
        ):
            verification = orchestrator.verify_run(run_id, include_diff=False)
        self.assertFalse(verification["gates"]["write_scope_ok"])
        self.assertFalse(verification["write_scope"]["ok"])


class FourthReviewWriterHandleTests(GuardedLaunchFixture):
    def _private_run_dir(self) -> Path:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
            orchestrator._atomic_write_text(run_dir / name, "")
        return run_dir

    def test_event_append_swap_cannot_modify_outside_file(self) -> None:
        run_dir = self._private_run_dir()
        events = run_dir / "events.ndjson"
        outside = self.workspace / "outside-events.txt"
        outside.write_text("outside", encoding="utf-8")
        backup = run_dir / "events.original"
        real_open = orchestrator._open_managed_file
        attack_fired = False

        @contextlib.contextmanager
        def swap_on_append(path: Path, *args: object, **kwargs: object) -> object:
            nonlocal attack_fired
            if Path(path) == events and kwargs.get("writable") and not attack_fired:
                events.replace(backup)
                os.symlink(outside, events)
                attack_fired = True
            try:
                with real_open(path, *args, **kwargs) as opened:
                    yield opened
            finally:
                if Path(path) == events and attack_fired and events.is_symlink():
                    events.unlink()
                    backup.replace(events)

        with patch.object(orchestrator, "_open_managed_file", swap_on_append):
            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator.append_event(run_dir, {"type": "outside-race"})
        self.assertTrue(attack_fired)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

    def test_atomic_snapshot_swap_cannot_publish_or_modify_outside_file(self) -> None:
        completed = subprocess.run(
            ["git", "init"], cwd=self.workspace, capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        (self.workspace / "changed.txt").write_text("changed", encoding="utf-8")
        run_dir = self._private_run_dir()
        outside = self.workspace / "outside-snapshot.txt"
        outside.write_text("outside", encoding="utf-8")
        attack_fired = False
        if os.name == "nt":
            real_create = orchestrator._create_windows_private_file

            @contextlib.contextmanager
            def swap_native_temp(path: Path) -> object:
                nonlocal attack_fired
                with real_create(path) as handle:
                    candidate = Path(path)
                    if candidate.name.startswith(".git_after") and not attack_fired:
                        backup = candidate.with_name(candidate.name + ".original")
                        candidate.replace(backup)
                        os.symlink(outside, candidate)
                        attack_fired = True
                    yield handle

            writer_patch = patch.object(
                orchestrator, "_create_windows_private_file", side_effect=swap_native_temp
            )
        else:
            real_prepare = orchestrator._prepare_private_atomic_write

            def swap_native_temp(path: Path, payload: bytes, *args: object, **kwargs: object) -> Path:
                nonlocal attack_fired
                candidate = real_prepare(path, payload, *args, **kwargs)
                if Path(path).name.startswith("git_after") and not attack_fired:
                    backup = candidate.with_name(candidate.name + ".original")
                    candidate.replace(backup)
                    os.symlink(outside, candidate)
                    attack_fired = True
                return candidate

            writer_patch = patch.object(
                orchestrator, "_prepare_private_atomic_write", side_effect=swap_native_temp
            )

        with writer_patch:
            snapshot = orchestrator.capture_git_snapshot(
                run_dir, self.workspace, "after"
            )
        self.assertTrue(attack_fired)
        self.assertFalse(snapshot["ok"], snapshot)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
        for path in run_dir.glob("git_after*"):
            self.assertFalse(path.is_symlink(), path)

    def test_stream_output_swap_cannot_modify_outside_file(self) -> None:
        self.fake_runtime.write_text(
            "import sys\nsys.stdin.buffer.read()\nprint('stream-output', flush=True)\n",
            encoding="utf-8",
        )
        prepared = self._prepare("streaming", prompt="")
        metadata = prepared.metadata()
        run_dir = self._private_run_dir()
        original_run_id = run_dir.name
        metadata["run_id"] = original_run_id
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata.update(
            {
                "status": "starting",
                "runtime_launch": prepared.launch_spec.public_metadata(),
                "worker_pid": os.getpid(),
                "worker_process_identity": worker_identity.to_dict(),
                "controller_pid": worker_identity.parent_pid,
                "worker_launch": {
                    "nonce_consumed": False,
                    "nonce_expires_at": "2999-01-01T00:00:00+00:00",
                    "start_gate": "closed",
                },
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = len(frame).to_bytes(8, "big") + frame + (0).to_bytes(8, "big")
        outside = self.workspace / "outside-output.txt"
        outside.write_text("outside", encoding="utf-8")
        stdout_path = run_dir / "stdout.txt"
        backup = run_dir / "stdout.original"
        real_open = orchestrator._open_managed_file
        attack_fired = False

        @contextlib.contextmanager
        def swap_on_append(path: Path, *args: object, **kwargs: object) -> object:
            nonlocal attack_fired
            if Path(path) == stdout_path and kwargs.get("writable") and not attack_fired:
                stdout_path.replace(backup)
                os.symlink(outside, stdout_path)
                attack_fired = True
            try:
                with real_open(path, *args, **kwargs) as opened:
                    yield opened
            finally:
                if Path(path) == stdout_path and attack_fired and stdout_path.is_symlink():
                    stdout_path.unlink()
                    backup.replace(stdout_path)

        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(orchestrator, "_open_managed_file", swap_on_append):
            result = orchestrator.stream_worker(original_run_id)
        self.assertTrue(attack_fired)
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")


class FourthReviewTeamAdmissionTests(GuardedLaunchFixture):
    def test_real_team_launch_uses_one_nonreentrant_admission(self) -> None:
        depth = 0

        @contextlib.contextmanager
        def nonreentrant_lock(*_args: object, **_kwargs: object) -> object:
            nonlocal depth
            if depth:
                raise AssertionError("nested launch admission")
            depth += 1
            try:
                yield
            finally:
                depth -= 1

        with patch.object(orchestrator, "launch_lock", nonreentrant_lock), patch.object(
            orchestrator, "TEAMS_DIR", self.artifact_root / "teams"
        ), patch.object(orchestrator, "max_concurrent_limit", return_value=4), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ):
            team = orchestrator.spawn_role_team(
                "real team compatibility",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertTrue(team["ok"], team)
        self.assertEqual(team["launched_count"], 2)
        for item in team["runs"]:
            metadata = self._wait_for_terminal_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertNotEqual(metadata["status"], "blocked_runtime_launch")

    def test_team_rolls_back_when_child_registration_fails(self) -> None:
        real_register = orchestrator._LaunchAdmissionReservation.register
        registration_count = 0

        def fail_second_registration(
            reservation: object, run_id: str
        ) -> None:
            nonlocal registration_count
            registration_count += 1
            if registration_count == 2:
                raise OSError("second child registration failed")
            real_register(reservation, run_id)

        with patch.object(orchestrator, "launch_lock", side_effect=lambda: contextlib.nullcontext()), patch.object(
            orchestrator, "TEAMS_DIR", self.artifact_root / "teams"
        ), patch.object(orchestrator, "max_concurrent_limit", return_value=4), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator._LaunchAdmissionReservation,
            "register",
            new=fail_second_registration,
        ):
            team = orchestrator.spawn_role_team(
                "registration rollback",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertFalse(team["ok"], team)
        self.assertIn(
            team["status"], {"rolled_back_partial_launch", "rollback_incomplete"}
        )
        self.assertTrue(team["rollback"]["attempted"])


class FourthReviewPinnedScopeTests(FourthReviewScopeFixture):
    def _write_scope_mutating_runtime(self, operation: str) -> None:
        scope_path = self._scope_path()
        operations = {
            "delete": f"pathlib.Path({str(scope_path)!r}).unlink()",
            "malformed": f"pathlib.Path({str(scope_path)!r}).write_text('{{', encoding='utf-8')",
            "drift": (
                f"pathlib.Path({str(scope_path)!r}).write_text("
                "json.dumps({'cwd': '.', 'allowed_paths': [], 'denied_paths': [], 'max_diff_lines': 0}), encoding='utf-8')"
            ),
        }
        self.fake_runtime.write_text(
            "import json, pathlib, sys\n"
            "sys.stdin.buffer.read()\n"
            f"{operations[operation]}\n"
            "print('done', flush=True)\n",
            encoding="utf-8",
        )

    def test_scope_delete_malformed_and_drift_after_popen_fail_closed(self) -> None:
        self._initialize_git_workspace()
        for operation in ("delete", "malformed", "drift"):
            with self.subTest(operation=operation):
                self._write_scope()
                self._write_scope_mutating_runtime(operation)
                result = orchestrator.run_agent(
                    f"scope {operation}", cwd=self.workspace
                )
                self.assertEqual(
                    result["acceptance_status"], "blocked_write_scope", result
                )
                self.assertIn(
                    "scope_policy_drift",
                    {
                        item["type"]
                        for item in result["write_scope_check"]["violations"]
                    },
                )

    def test_malformed_initial_scope_blocks_before_runtime_popen(self) -> None:
        self._initialize_git_workspace()
        scope_path = self._scope_path()
        scope_path.parent.mkdir(parents=True)
        scope_path.write_text("{", encoding="utf-8")
        marker = self.workspace / "runtime-started.txt"
        self.fake_runtime.write_text(
            "import pathlib, sys\n"
            "sys.stdin.buffer.read()\n"
            f"pathlib.Path({str(marker)!r}).write_text('started', encoding='utf-8')\n",
            encoding="utf-8",
        )
        result = orchestrator.run_agent("malformed scope", cwd=self.workspace)
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertFalse(marker.exists())


class FourthReviewGitCompletenessTests(FourthReviewScopeFixture):
    def _write_same_size_mutator(self) -> None:
        self.fake_runtime.write_text(
            "import pathlib, sys\n"
            "prompt = sys.stdin.buffer.read().decode('utf-8')\n"
            "task = prompt.rsplit('\\nTask:\\n', 1)[1].split('\\n\\nAdditional context:\\n', 1)[0].strip()\n"
            "path = pathlib.Path(task)\n"
            "with path.open('r+b') as handle:\n"
            "    first = handle.read(1)\n"
            "    handle.seek(0)\n"
            "    handle.write(b'Z' if first != b'Z' else b'Y')\n"
            "print('done', flush=True)\n",
            encoding="utf-8",
        )

    def test_large_predirty_denied_file_is_fully_hashed(self) -> None:
        self._initialize_git_workspace()
        denied = "large-denied.bin"
        self._write_scope(denied)
        with (self.workspace / denied).open("wb") as handle:
            handle.truncate(20_000_001)
        self._write_same_size_mutator()
        result = orchestrator.run_agent(denied, cwd=self.workspace)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "denied_path",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )

    def test_denied_file_beyond_one_thousand_predirty_paths_is_hashed(self) -> None:
        self._initialize_git_workspace()
        denied = "zzzz-denied.bin"
        self._write_scope(denied)
        for index in range(1001):
            (self.workspace / f"predirty-{index:04d}.txt").write_text(
                "x", encoding="utf-8"
            )
        (self.workspace / denied).write_bytes(b"x")
        self._write_same_size_mutator()
        result = orchestrator.run_agent(denied, cwd=self.workspace)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "denied_path",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )

    def test_hash_read_failure_marks_git_evidence_incomplete(self) -> None:
        self._initialize_git_workspace()
        denied = "unreadable-denied.bin"
        self._write_scope(denied)
        target = self.workspace / denied
        target.write_bytes(b"x")
        self._write_same_size_mutator()
        real_hash = orchestrator.file_sha256
        target_reads = 0

        def fail_target(path: Path, *args: object, **kwargs: object) -> dict[str, object]:
            nonlocal target_reads
            if Path(path).resolve() == target.resolve():
                target_reads += 1
                if target_reads > 2:
                    raise OSError("fixture read failure")
            return real_hash(path, *args, **kwargs)

        with patch.object(orchestrator, "file_sha256", side_effect=fail_target):
            result = orchestrator.run_agent(denied, cwd=self.workspace)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "git_evidence_incomplete",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )


class FourthReviewDeadlineTests(GuardedLaunchFixture):
    def test_one_shot_validation_and_artifacts_consume_single_deadline(self) -> None:
        self.fake_runtime.write_text(
            "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(5)\n",
            encoding="utf-8",
        )
        real_capture = orchestrator.capture_process_identity
        real_update = orchestrator.update_metadata
        child_update_seen = False

        def delayed_capture(pid: int, *, launch_nonce: str) -> ProcessIdentity:
            time.sleep(0.65)
            return real_capture(pid, launch_nonce=launch_nonce)

        def delayed_update(run_dir: Path, **updates: object) -> dict[str, object]:
            nonlocal child_update_seen
            if "child_pid" in updates and not child_update_seen:
                child_update_seen = True
                time.sleep(0.65)
            return real_update(run_dir, **updates)

        started = time.monotonic()
        with patch.object(
            orchestrator, "capture_process_identity", side_effect=delayed_capture
        ), patch.object(orchestrator, "update_metadata", side_effect=delayed_update):
            result = orchestrator.run_agent(
                "single deadline", cwd=self.workspace, timeout_seconds=1
            )
        elapsed = time.monotonic() - started
        self.assertTrue(result["timed_out"], result)
        self.assertLess(elapsed, 1.9)
        self._wait_for_pid_exit(int(result["child_pid"]))

    def test_streaming_timeout_uses_monotonic_deadline_after_wall_rollback(self) -> None:
        self.fake_runtime.write_text(
            "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(2)\n",
            encoding="utf-8",
        )
        prepared = orchestrator.prepare_worker_launch(
            mode="streaming",
            prompt="",
            provider_env=self.provider.env,
            model_override=None,
            cwd=self.workspace,
            workspace_root=self.workspace,
            artifact_root=self.artifact_root,
            permission_mode="plan",
            timeout_seconds=1,
            arguments=(
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--include-partial-messages",
                "--permission-mode",
                "plan",
                "--no-session-persistence",
            ),
            safe_route_metadata={
                "role": "testing",
                "task_type": "code",
                "profile": {"id": self.provider.id, "name": self.provider.name},
                "output_format": "stream-json",
                "include_partial_messages": True,
                "allow_write": False,
            },
            expected_child_launches=1,
            allow_unsafe_runtime=False,
        )
        metadata = prepared.metadata()
        run_dir = self.runs_dir / str(metadata["run_id"])
        orchestrator._set_private_directory(run_dir)
        for name in ("stdout.txt", "stderr.txt", "events.ndjson"):
            orchestrator._atomic_write_text(run_dir / name, "")
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata.update(
            {
                "status": "starting",
                "runtime_launch": prepared.launch_spec.public_metadata(),
                "worker_pid": os.getpid(),
                "worker_process_identity": worker_identity.to_dict(),
                "controller_pid": worker_identity.parent_pid,
                "worker_launch": {
                    "nonce_consumed": False,
                    "nonce_expires_at": "2999-01-01T00:00:00+00:00",
                    "start_gate": "closed",
                },
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = len(frame).to_bytes(8, "big") + frame + (0).to_bytes(8, "big")
        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        real_popen = subprocess.Popen
        real_wall = time.time
        child_started = threading.Event()

        def mark_child(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            child_started.set()
            return child

        def rolled_back_wall() -> float:
            now = real_wall()
            return now - 3600 if child_started.is_set() else now

        started = time.monotonic()
        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(orchestrator.subprocess, "Popen", side_effect=mark_child), patch.object(
            orchestrator.time, "time", side_effect=rolled_back_wall
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        elapsed = time.monotonic() - started
        self.assertEqual(result["status"], "timed_out", result)
        self.assertLess(elapsed, 1.9)
        self._wait_for_pid_exit(int(result["child_pid"]))


class FourthReviewDirectoryHandleTests(GuardedLaunchFixture):
    def test_directory_swap_during_permission_walk_is_rejected(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        nested = run_dir / "nested"
        orchestrator._set_private_directory(nested)
        orchestrator._atomic_write_text(nested / "inside.txt", "inside")
        outside = self.workspace / "outside-directory"
        outside.mkdir()
        outside_file = outside / "outside.txt"
        outside_file.write_text("outside", encoding="utf-8")
        backup = run_dir / "nested.original"
        swapped = False

        if os.name == "nt":
            real_open = orchestrator._open_windows_managed_directory

            def swap_directory(path: Path, *args: object, **kwargs: object) -> object:
                nonlocal swapped
                if Path(path) == nested and not swapped:
                    nested.replace(backup)
                    os.symlink(outside, nested, target_is_directory=True)
                    swapped = True
                return real_open(path, *args, **kwargs)

            opener_patch = patch.object(
                orchestrator,
                "_open_windows_managed_directory",
                side_effect=swap_directory,
            )
        else:
            real_open = os.open

            def swap_directory(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                is_relative_nested = (
                    kwargs.get("dir_fd") is not None
                    and Path(path) == Path(nested.name)
                    and bool(flags & getattr(os, "O_DIRECTORY", 0))
                )
                if is_relative_nested and not swapped:
                    nested.replace(backup)
                    os.symlink(outside, nested, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            opener_patch = patch.object(orchestrator.os, "open", side_effect=swap_directory)
        with opener_patch:
            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator._secure_run_artifacts(run_dir)
        self.assertTrue(swapped)
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "outside")


class FifthReviewWorkspaceScopeTests(FourthReviewScopeFixture):
    def test_relative_scope_is_canonicalized_against_workspace_not_process_cwd(self) -> None:
        self._initialize_git_workspace()
        scope_path = self._scope_path()
        scope_path.parent.mkdir(parents=True, exist_ok=True)
        scope_path.write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": ["."],
                    "denied_paths": [self.denied_name],
                    "max_diff_lines": 100,
                }
            ),
            encoding="utf-8",
        )
        self._write_mutating_runtime()
        other = self.workspace / "controller-cwd"
        other.mkdir()
        old_cwd = Path.cwd()
        try:
            os.chdir(other)
            result = orchestrator.run_agent(self.denied_name, cwd=self.workspace)
        finally:
            os.chdir(old_cwd)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "denied_path",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )

    def test_nested_launch_cwd_uses_configured_workspace_for_policy_and_git(self) -> None:
        self._initialize_git_workspace()
        self._write_scope("nested-denied.txt")
        target = self.workspace / "nested-denied.txt"
        nested = self.workspace / "src" / "nested"
        nested.mkdir(parents=True)
        self._write_mutating_runtime()

        one_shot = orchestrator.run_agent(str(target), cwd=nested)
        self.assertEqual(one_shot["workspace_root"], str(self.workspace))
        self.assertEqual(one_shot["acceptance_status"], "blocked_write_scope", one_shot)
        target.unlink()

        streaming = orchestrator.run_streaming_agent(
            str(target), cwd=nested, timeout_seconds=5
        )
        terminal = self._wait_for_terminal_metadata(
            self.runs_dir / str(streaming["run_id"]), timeout=10
        )
        self.assertEqual(terminal["workspace_root"], str(self.workspace))
        self.assertEqual(terminal["acceptance_status"], "blocked_write_scope", terminal)
        self._wait_for_pid_exit(int(terminal["worker_pid"]))

    def test_policy_declared_root_mismatch_blocks_before_popen(self) -> None:
        self._initialize_git_workspace()
        scope_path = self._scope_path()
        scope_path.parent.mkdir(parents=True, exist_ok=True)
        scope_path.write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace / "different-root"),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [],
                    "max_diff_lines": 100,
                }
            ),
            encoding="utf-8",
        )
        marker = self.workspace / "mismatched-policy-started.txt"
        self.fake_runtime.write_text(
            "import pathlib, sys\n"
            "sys.stdin.buffer.read()\n"
            f"pathlib.Path({str(marker)!r}).write_text('started', encoding='utf-8')\n",
            encoding="utf-8",
        )
        result = orchestrator.run_agent("mismatched root", cwd=self.workspace)
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertFalse(marker.exists())

    def test_launch_cwd_outside_configured_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="outside-workspace-") as outside:
            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator.run_agent("outside root", cwd=Path(outside))


class FifthReviewGitStateTests(FourthReviewScopeFixture):
    target_name = "state-denied.txt"

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed

    def _remove_git_tree(self, path: Path) -> None:
        if not path.exists():
            return

        def make_writable_and_retry(
            operation: object, candidate: str, _details: object
        ) -> None:
            os.chmod(candidate, stat.S_IWRITE)
            operation(candidate)

        shutil.rmtree(path, onerror=make_writable_and_retry)

    def _initialize_committed_repo(self, *, second_commit: bool = False) -> Path:
        self._initialize_git_workspace()
        self._git("config", "user.name", "Task Five Fixture")
        self._git("config", "user.email", "task-five@example.invalid")
        target = self.workspace / self.target_name
        target.write_text("base\n", encoding="utf-8")
        self._git("add", self.target_name)
        self._git("commit", "-m", "base")
        if second_commit:
            target.write_text("second\n", encoding="utf-8")
            self._git("add", self.target_name)
            self._git("commit", "-m", "second")
        self._write_scope(self.target_name)
        return target

    def _write_git_runtime(self, lines: list[str]) -> None:
        git_bin = shutil.which("git")
        self.assertIsNotNone(git_bin)
        body = "\n".join(lines).replace("['git',", "[GIT,")
        self.fake_runtime.write_text(
            "import pathlib, shutil, subprocess, sys\n"
            "sys.stdin.buffer.read()\n"
            + f"GIT = {git_bin!r}\n"
            + body
            + "\nprint('done', flush=True)\n",
            encoding="utf-8",
        )

    def _assert_transition_denied(self, lines: list[str]) -> dict[str, object]:
        self._write_git_runtime(lines)
        result = orchestrator.run_agent("git transition", cwd=self.workspace)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "denied_path",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )
        return result

    def test_commit_transition_is_attributed(self) -> None:
        target = self._initialize_committed_repo()
        self._assert_transition_denied(
            [
                f"pathlib.Path({str(target)!r}).write_text('committed\\n', encoding='utf-8')",
                f"subprocess.run(['git', 'add', {self.target_name!r}], cwd={str(self.workspace)!r}, check=True)",
                f"subprocess.run(['git', 'commit', '-m', 'runtime'], cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL)",
            ]
        )

    def test_reset_and_checkout_transitions_are_attributed(self) -> None:
        for operation in ("reset", "checkout"):
            with self.subTest(operation=operation):
                if (self.workspace / ".git").exists():
                    self._remove_git_tree(self.workspace / ".git")
                self._initialize_committed_repo(second_commit=True)
                command = ["git", "reset", "--hard", "HEAD^"] if operation == "reset" else ["git", "checkout", "--detach", "HEAD^"]
                self._assert_transition_denied(
                    [f"subprocess.run({command!r}, cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"]
                )

    def test_stage_and_unstage_transitions_are_attributed(self) -> None:
        for operation in ("stage", "unstage"):
            with self.subTest(operation=operation):
                if (self.workspace / ".git").exists():
                    self._remove_git_tree(self.workspace / ".git")
                target = self._initialize_committed_repo()
                target.write_text("predirty\n", encoding="utf-8")
                if operation == "unstage":
                    self._git("add", self.target_name)
                    command = ["git", "reset", "HEAD", "--", self.target_name]
                else:
                    command = ["git", "add", self.target_name]
                self._assert_transition_denied(
                    [f"subprocess.run({command!r}, cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL)"]
                )

    def test_index_only_transition_is_attributed(self) -> None:
        self._initialize_committed_repo()
        self._assert_transition_denied(
            [
                f"blob = subprocess.check_output(['git', 'hash-object', '-w', '--stdin'], cwd={str(self.workspace)!r}, input=b'index-only\\n').decode().strip()",
                f"subprocess.run(['git', 'update-index', '--cacheinfo', '100644', blob, {self.target_name!r}], cwd={str(self.workspace)!r}, check=True)",
            ]
        )

    def test_git_disappearance_and_replacement_fail_continuity(self) -> None:
        for operation in ("disappear", "replace"):
            with self.subTest(operation=operation):
                if (self.workspace / ".git").exists():
                    self._remove_git_tree(self.workspace / ".git")
                self._remove_git_tree(self.workspace / ".git-original")
                self._initialize_committed_repo()
                if operation == "disappear":
                    lines = [f"shutil.rmtree({str(self.workspace / '.git')!r})"]
                else:
                    lines = [
                        f"pathlib.Path({str(self.workspace / '.git')!r}).rename({str(self.workspace / '.git-original')!r})",
                        f"subprocess.run(['git', 'init'], cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
                    ]
                self._write_git_runtime(lines)
                result = orchestrator.run_agent("repo continuity", cwd=self.workspace)
                self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
                self.assertIn(
                    "git_evidence_incomplete",
                    {item["type"] for item in result["write_scope_check"]["violations"]},
                )


class FifthReviewLifecycleBoundaryTests(GuardedLaunchFixture):
    def test_every_one_shot_post_popen_artifact_failure_is_blocked_and_reaped(self) -> None:
        self.fake_runtime.write_text(
            "import sys\nsys.stdin.buffer.read()\nprint('complete', flush=True)\n",
            encoding="utf-8",
        )
        cases = ("output", "git", "metadata", "event", "scrub", "permissions")
        for case in cases:
            with self.subTest(case=case):
                active = False
                failed = False
                children: list[subprocess.Popen[bytes]] = []
                real_popen = orchestrator.subprocess.Popen
                real_atomic = orchestrator._atomic_write_text
                real_git = orchestrator.capture_git_snapshot
                real_update = orchestrator.update_metadata
                real_event = orchestrator.append_event
                real_scrub = orchestrator._scrub_run_artifacts
                real_secure = orchestrator._secure_run_artifacts

                def mark_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
                    nonlocal active
                    child = real_popen(*args, **kwargs)
                    active = True
                    children.append(child)
                    return child

                def should_fail(kind: str) -> bool:
                    nonlocal failed
                    if active and case == kind and not failed:
                        failed = True
                        return True
                    return False

                def atomic(path: Path, text: str, *args: object, **kwargs: object) -> None:
                    if Path(path).name == "stdout.txt" and should_fail("output"):
                        raise OSError("fixture output failure")
                    real_atomic(path, text, *args, **kwargs)

                def git(*args: object, **kwargs: object) -> dict[str, object]:
                    if len(args) >= 3 and args[2] == "after" and should_fail("git"):
                        raise OSError("fixture Git failure")
                    return real_git(*args, **kwargs)

                def update(run_dir: Path, **updates: object) -> dict[str, object]:
                    if "finished_at" in updates and should_fail("metadata"):
                        raise OSError("fixture metadata failure")
                    return real_update(run_dir, **updates)

                def event(run_dir: Path, payload: dict[str, object], *args: object, **kwargs: object) -> None:
                    if payload.get("type") == "process_exited" and should_fail("event"):
                        raise OSError("fixture event failure")
                    real_event(run_dir, payload, *args, **kwargs)

                def scrub(*args: object, **kwargs: object) -> None:
                    if should_fail("scrub"):
                        raise OSError("fixture scrub failure")
                    real_scrub(*args, **kwargs)

                def secure(*args: object, **kwargs: object) -> None:
                    if should_fail("permissions"):
                        raise OSError("fixture permission failure")
                    real_secure(*args, **kwargs)

                with patch.object(orchestrator.subprocess, "Popen", side_effect=mark_popen), patch.object(
                    orchestrator, "_atomic_write_text", side_effect=atomic
                ), patch.object(orchestrator, "capture_git_snapshot", side_effect=git), patch.object(
                    orchestrator, "update_metadata", side_effect=update
                ), patch.object(orchestrator, "append_event", side_effect=event), patch.object(
                    orchestrator, "_scrub_run_artifacts", side_effect=scrub
                ), patch.object(orchestrator, "_secure_run_artifacts", side_effect=secure):
                    result = orchestrator.run_agent(
                        f"lifecycle {case}", cwd=self.workspace, timeout_seconds=3
                    )
                self.assertTrue(failed, case)
                self.assertEqual(result["status"], "blocked_runtime_launch", result)
                self.assertIn(result["persistence_state"], {"persisted", "degraded"})
                if result["persistence_state"] == "persisted":
                    self.assertEqual(result["terminal_state_count"], 1)
                for child in children:
                    self._wait_for_pid_exit(child.pid)

    def test_stream_final_permission_failure_is_blocked_and_reaped(self) -> None:
        self.fake_runtime.write_text(
            "import sys\nsys.stdin.buffer.read()\nprint('complete', flush=True)\n",
            encoding="utf-8",
        )
        prepared = self._prepare("streaming", prompt="stream lifecycle")
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata = orchestrator.update_metadata(
            run_dir,
            worker_pid=os.getpid(),
            worker_process_identity=worker_identity.to_dict(),
            controller_pid=worker_identity.parent_pid,
        )
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = (
            len(frame).to_bytes(8, "big")
            + frame
            + len(prepared.prompt_bytes).to_bytes(8, "big")
            + prepared.prompt_bytes
        )
        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        real_popen = orchestrator.subprocess.Popen
        real_secure = orchestrator._secure_run_artifacts
        child: subprocess.Popen[bytes] | None = None
        active = False
        failed = False

        def mark_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal active, child
            child = real_popen(*args, **kwargs)
            active = True
            return child

        def fail_final(*args: object, **kwargs: object) -> None:
            nonlocal failed
            if active and not failed:
                failed = True
                raise OSError("fixture final permission failure")
            real_secure(*args, **kwargs)

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(orchestrator.subprocess, "Popen", side_effect=mark_popen), patch.object(
            orchestrator, "_secure_run_artifacts", side_effect=fail_final
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        self.assertTrue(failed)
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertIsNotNone(child)
        self._wait_for_pid_exit(child.pid)


class FifthReviewTeamTransactionTests(GuardedLaunchFixture):
    def test_all_members_are_registered_and_persisted_before_any_gate_opens(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_update = orchestrator.update_metadata
        real_manifest = orchestrator.write_team_manifest
        authorization_published = False
        authorizations: list[str] = []

        def no_post_authorization_update(
            *args: object, **kwargs: object
        ) -> dict[str, object]:
            if authorization_published:
                raise AssertionError("metadata write after first team gate")
            return real_update(*args, **kwargs)

        def verify_authorization(
            team_id: str, data: dict[str, object]
        ) -> Path:
            nonlocal authorization_published
            if authorization_published:
                raise AssertionError("manifest write after first team gate")
            if data.get("status") == "authorized":
                run_dirs = self._run_dirs()
                self.assertEqual(len(run_dirs), 2)
                metadata_items = [
                    orchestrator.read_metadata(path) for path in run_dirs
                ]
                prepared = orchestrator.read_team_manifest(team_id)
                self.assertEqual(prepared["status"], "prepared")
                self.assertEqual(
                    {item["run_id"] for item in prepared["runs"]},
                    {path.name for path in run_dirs},
                )
                self.assertTrue(
                    all(item.get("worker_pid") for item in metadata_items)
                )
                authorizations.append(team_id)
            path = real_manifest(team_id, data)
            if data.get("status") == "authorized":
                authorization_published = True
            return path

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(orchestrator, "run_status", return_value={"active_count": 0}), patch.object(
            orchestrator, "update_metadata", side_effect=no_post_authorization_update
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=verify_authorization
        ):
            team = orchestrator.spawn_role_team(
                "transactional team",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertTrue(team["ok"], team)
        self.assertEqual(len(authorizations), 1)
        for item in team["runs"]:
            terminal = self._wait_for_terminal_metadata(
                self.runs_dir / str(item["run_id"]), timeout=10
            )
            self._wait_for_pid_exit(int(terminal["worker_pid"]))

    def test_partial_gate_failure_never_allows_a_team_child_popen(self) -> None:
        real_manifest = orchestrator.write_team_manifest
        authorization_calls = 0

        def fail_authorization(
            team_id: str, data: dict[str, object]
        ) -> Path:
            nonlocal authorization_calls
            if data.get("status") == "authorized":
                authorization_calls += 1
                time.sleep(0.5)
                raise OSError("fixture authorization failure")
            return real_manifest(team_id, data)

        with patch.object(
            orchestrator, "TEAMS_DIR", self.artifact_root / "teams"
        ), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=fail_authorization
        ):
            team = orchestrator.spawn_role_team(
                "partial gate failure",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertFalse(team["ok"], team)
        self.assertEqual(authorization_calls, 1, team)
        for item in team["runs"]:
            lock_dir = self.runs_dir / f".{item['run_id']}.artifact.lock"
            self.assertFalse(lock_dir.exists(), team)
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertIsNone(metadata.get("child_pid"), metadata)
            self._wait_for_pid_exit(int(metadata["worker_pid"]))


class FifthReviewDeadlineTests(GuardedLaunchFixture):
    def test_atomic_replace_retries_share_the_launch_deadline(self) -> None:
        self.fake_runtime.write_text(
            "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(5)\n",
            encoding="utf-8",
        )
        real_popen = orchestrator.subprocess.Popen
        real_replace = (
            orchestrator._windows_replace_relative
            if os.name == "nt"
            else orchestrator.os.replace
        )
        active = False
        attack_until = 0.0
        attacked = False
        children: list[subprocess.Popen[bytes]] = []

        def mark_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal active, attack_until
            child = real_popen(*args, **kwargs)
            children.append(child)
            active = True
            attack_until = time.monotonic() + 2.5
            return child

        def delay_metadata_replace(source: object, target: object, *args: object, **kwargs: object) -> None:
            nonlocal attacked
            if active and Path(target).name == "metadata.json" and time.monotonic() < attack_until:
                attacked = True
                raise PermissionError("fixture delayed replace")
            real_replace(source, target, *args, **kwargs)

        replace_patch = (
            patch.object(
                orchestrator,
                "_windows_replace_relative",
                side_effect=delay_metadata_replace,
            )
            if os.name == "nt"
            else patch.object(
                orchestrator.os,
                "replace",
                side_effect=delay_metadata_replace,
            )
        )

        started = time.monotonic()
        with patch.object(
            orchestrator.subprocess, "Popen", side_effect=mark_popen
        ), replace_patch:
            result = orchestrator.run_agent(
                "replace deadline", cwd=self.workspace, timeout_seconds=1
            )
        elapsed = time.monotonic() - started
        self.assertTrue(attacked)
        self.assertLess(elapsed, 1.9)
        self.assertIn(result["status"], {"timed_out", "blocked_runtime_launch"})
        for child in children:
            self._wait_for_pid_exit(child.pid)


class FifthReviewHandleBoundaryTests(GuardedLaunchFixture):
    def test_abandoned_same_process_artifact_lock_is_reclaimed(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        lock_dir = run_dir.parent / f".{run_dir.name}.artifact.lock"
        lock_dir.mkdir()
        (lock_dir / "owner.pid").write_text(str(os.getpid()), encoding="ascii")

        with orchestrator.artifact_lock(run_dir, timeout_seconds=0.05):
            self.assertTrue(lock_dir.exists())

        self.assertFalse(lock_dir.exists())

    def test_atomic_replace_parent_swap_fires_at_native_boundary_and_fails_closed(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "metadata.json"
        orchestrator._atomic_write_text(target, '{"state":"before"}')
        outside = self.workspace / "outside-replacement"
        outside.mkdir()
        backup = run_dir.with_name(run_dir.name + ".original")
        attack_fired = False

        if os.name == "nt":
            real_replace = orchestrator._windows_replace_relative

            def swap_parent(
                temporary: Path, destination: Path, parent_handle: object
            ) -> None:
                nonlocal attack_fired
                attack_fired = True
                run_dir.replace(backup)
                os.symlink(outside, run_dir, target_is_directory=True)
                try:
                    real_replace(temporary, destination, parent_handle)
                finally:
                    run_dir.unlink()
                    backup.replace(run_dir)

            replacement_patch = patch.object(
                orchestrator,
                "_windows_replace_relative",
                side_effect=swap_parent,
            )
            with replacement_patch:
                with self.assertRaises((OSError, orchestrator.OrchestratorError)):
                    orchestrator._atomic_write_text(target, '{"state":"after"}')
        else:
            real_replace = orchestrator._posix_replace_relative

            def swap_parent(
                temporary: Path, destination: Path, parent_handle: int
            ) -> None:
                nonlocal attack_fired
                attack_fired = True
                run_dir.replace(backup)
                os.symlink(outside, run_dir, target_is_directory=True)
                try:
                    real_replace(temporary, destination, parent_handle)
                finally:
                    run_dir.unlink()
                    backup.replace(run_dir)

            with patch.object(
                orchestrator, "_posix_replace_relative", side_effect=swap_parent
            ):
                orchestrator._atomic_write_text(target, '{"state":"after"}')
            self.assertEqual(target.read_text(encoding="utf-8"), '{"state":"after"}')

        self.assertTrue(attack_fired)
        self.assertEqual(list(outside.iterdir()), [])


class SixthReviewGitEvidenceTests(FourthReviewScopeFixture):
    target_name = "sixth-state.txt"

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed

    def _remove_git(self) -> None:
        git_dir = self.workspace / ".git"
        if not git_dir.exists():
            return

        def writable_retry(operation: object, candidate: str, _details: object) -> None:
            os.chmod(candidate, stat.S_IWRITE)
            operation(candidate)

        shutil.rmtree(git_dir, onerror=writable_retry)

    def _initialize_repo(
        self, *, with_scope: bool = True, max_diff_lines: int = 100
    ) -> Path:
        self._remove_git()
        scope_root = self.workspace / ".claude-code-orchestrator"
        if scope_root.exists():
            shutil.rmtree(scope_root)
        self._initialize_git_workspace()
        self._git("config", "user.name", "Task Six Fixture")
        self._git("config", "user.email", "task-six@example.invalid")
        target = self.workspace / self.target_name
        target.write_text("base\n", encoding="utf-8")
        self._git("add", self.target_name)
        self._git("commit", "-m", "base")
        if with_scope:
            scope_root.mkdir()
            (scope_root / "write-scope.json").write_text(
                json.dumps(
                    {
                        "cwd": str(self.workspace),
                        "allowed_paths": [str(self.workspace)],
                        "denied_paths": [str(target)],
                        "max_diff_lines": max_diff_lines,
                    }
                ),
                encoding="utf-8",
            )
        return target

    def _write_runtime(self, lines: list[str]) -> None:
        git_bin = shutil.which("git")
        self.assertIsNotNone(git_bin)
        body = "\n".join(lines).replace("['git',", "[GIT,")
        self.fake_runtime.write_text(
            "import pathlib, shutil, subprocess, sys\n"
            "sys.stdin.buffer.read()\n"
            + f"GIT = {git_bin!r}\n"
            + body
            + "\nprint('done', flush=True)\n",
            encoding="utf-8",
        )

    def test_outer_worktree_top_level_mismatch_blocks_both_modes(self) -> None:
        self._initialize_git_workspace()
        self._git("config", "user.name", "Task Six Fixture")
        self._git("config", "user.email", "task-six@example.invalid")
        nested = self.workspace / "configured-root"
        nested.mkdir()
        tracked = nested / "tracked.txt"
        tracked.write_text("tracked\n", encoding="utf-8")
        self._git("add", "configured-root/tracked.txt")
        self._git("commit", "-m", "outer")
        marker = self.workspace / "outer-root-runtime-started.txt"
        self.fake_runtime.write_text(
            "import pathlib, sys\n"
            "sys.stdin.buffer.read()\n"
            f"pathlib.Path({str(marker)!r}).write_text('started', encoding='utf-8')\n",
            encoding="utf-8",
        )

        with patch.object(orchestrator, "WORKSPACE_ROOT", nested):
            one_shot = orchestrator.run_agent("outer root", cwd=nested)
        self.assertEqual(one_shot["status"], "blocked_runtime_launch", one_shot)
        self.assertFalse(marker.exists())

        with patch.object(orchestrator, "WORKSPACE_ROOT", nested):
            streaming = orchestrator.run_streaming_agent(
                "outer root", cwd=nested, timeout_seconds=5
            )
        terminal = self._wait_for_terminal_metadata(
            self.runs_dir / str(streaming["run_id"]), timeout=10
        )
        self.assertEqual(terminal["status"], "blocked_runtime_launch", terminal)
        self.assertFalse(marker.exists())
        self._wait_for_pid_exit(int(terminal["worker_pid"]))

    def test_same_status_index_blob_transition_is_attributed(self) -> None:
        target = self._initialize_repo()
        target.write_text("index-one\n", encoding="utf-8")
        self._git("add", self.target_name)
        target.write_text("worktree-stable\n", encoding="utf-8")
        self._write_runtime(
            [
                "blob = subprocess.check_output([GIT, 'hash-object', '-w', '--stdin'], "
                f"cwd={str(self.workspace)!r}, input=b'index-two\\n').decode().strip()",
                f"subprocess.run([GIT, 'update-index', '--cacheinfo', '100644', blob, {self.target_name!r}], cwd={str(self.workspace)!r}, check=True)",
            ]
        )
        result = orchestrator.run_agent("index blob", cwd=self.workspace)
        violation_types = {
            item["type"] for item in result["write_scope_check"]["violations"]
        }
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertTrue(
            {"denied_path", "git_evidence_incomplete"} & violation_types, result
        )

    def test_empty_commit_and_index_flag_transitions_fail_closed(self) -> None:
        cases = {
            "empty_commit": [
                f"subprocess.run([GIT, 'commit', '--allow-empty', '-m', 'empty'], cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL)"
            ],
            "index_flag": [
                f"subprocess.run([GIT, 'update-index', '--assume-unchanged', {self.target_name!r}], cwd={str(self.workspace)!r}, check=True)"
            ],
        }
        for case, lines in cases.items():
            with self.subTest(case=case):
                self._initialize_repo()
                self._write_runtime(lines)
                result = orchestrator.run_agent(case, cwd=self.workspace)
                violation_types = {
                    item["type"]
                    for item in result["write_scope_check"]["violations"]
                }
                self.assertEqual(
                    result["acceptance_status"], "blocked_write_scope", result
                )
                self.assertTrue(
                    {"denied_path", "git_evidence_incomplete"} & violation_types,
                    result,
                )

    def test_broken_head_continuity_precedes_no_scope_success(self) -> None:
        self._initialize_repo(with_scope=False)
        self._write_runtime(
            [f"pathlib.Path({str(self.workspace / '.git' / 'HEAD')!r}).unlink()"]
        )
        result = orchestrator.run_agent("break head", cwd=self.workspace)
        self.assertEqual(result["acceptance_status"], "blocked_write_scope", result)
        self.assertIn(
            "git_evidence_incomplete",
            {item["type"] for item in result["write_scope_check"]["violations"]},
        )

    def test_staged_and_committed_deltas_count_toward_max_diff_lines(self) -> None:
        for transition in ("staged", "committed"):
            with self.subTest(transition=transition):
                target = self._initialize_repo(max_diff_lines=1)
                scope_path = self._scope_path()
                scope = json.loads(scope_path.read_text(encoding="utf-8"))
                scope["denied_paths"] = []
                scope_path.write_text(json.dumps(scope), encoding="utf-8")
                lines = [
                    f"pathlib.Path({str(target)!r}).write_text('one\\ntwo\\nthree\\n', encoding='utf-8')",
                    f"subprocess.run([GIT, 'add', {self.target_name!r}], cwd={str(self.workspace)!r}, check=True)",
                ]
                if transition == "committed":
                    lines.append(
                        f"subprocess.run([GIT, 'commit', '-m', 'delta'], cwd={str(self.workspace)!r}, check=True, stdout=subprocess.DEVNULL)"
                    )
                self._write_runtime(lines)
                result = orchestrator.run_agent(transition, cwd=self.workspace)
                self.assertEqual(
                    result["acceptance_status"], "blocked_write_scope", result
                )
                self.assertIn(
                    "max_diff_lines",
                    {
                        item["type"]
                        for item in result["write_scope_check"]["violations"]
                    },
                )


class SixthReviewLifecycleTests(GuardedLaunchFixture):
    def test_unconfirmed_deadline_cleanup_retains_owned_reaper(self) -> None:
        release = threading.Event()

        class Stream:
            def close(self) -> None:
                pass

        class UnreapedProcess:
            args = ("unreaped-fixture",)
            pid = 424242
            stdin = Stream()
            stdout = Stream()
            stderr = Stream()

            def __init__(self) -> None:
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def terminate(self) -> None:
                pass

            def kill(self) -> None:
                pass

            def wait(self, timeout: float | None = None) -> int:
                if timeout is not None:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                release.wait(2)
                self.returncode = -9
                return self.returncode

        process = UnreapedProcess()
        try:
            orchestrator._terminate_owned_process(
                process, deadline=time.monotonic() - 1
            )
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                retained = any(
                    handle is process
                    for handle in orchestrator._ACTIVE_WORKER_HANDLES.values()
                )
            self.assertTrue(retained)
        finally:
            release.set()
            deadline = time.time() + 3
            while time.time() < deadline:
                with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                    if all(
                        handle is not process
                        for handle in orchestrator._ACTIVE_WORKER_HANDLES.values()
                    ):
                        break
                time.sleep(0.01)

    def test_unreaped_launch_returns_explicit_nonterminal_degraded_state(self) -> None:
        release = threading.Event()

        class Stream:
            def close(self) -> None:
                pass

        class UnreapedLaunch:
            args = ("unreaped-launch",)
            pid = 424243
            stdin = Stream()
            stdout = Stream()
            stderr = Stream()

            def __init__(self) -> None:
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def terminate(self) -> None:
                pass

            def kill(self) -> None:
                pass

            def wait(self, timeout: float | None = None) -> int:
                if timeout is not None:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                release.wait(2)
                self.returncode = -9
                return self.returncode

        process = UnreapedLaunch()
        try:
            with patch.object(
                orchestrator.subprocess, "Popen", return_value=process
            ), patch.object(
                orchestrator,
                "capture_process_identity",
                side_effect=OSError("identity unavailable"),
            ):
                result = orchestrator.run_agent(
                    "unreaped cleanup", cwd=self.workspace, timeout_seconds=1
                )
            self.assertEqual(result["status"], "cleanup_pending", result)
            self.assertEqual(result["terminal_state_count"], 0)
            self.assertEqual(result["persistence_state"], "degraded")
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(result["run_id"])
            )
            self.assertNotIn(
                metadata.get("status"),
                {
                    "succeeded",
                    "failed",
                    "timed_out",
                    "stopped",
                    "blocked_runtime_launch",
                    "blocked_runtime_identity",
                    "blocked_process_identity",
                    "blocked_runtime_security",
                },
            )
        finally:
            release.set()

    def _direct_stream_fixture(self) -> tuple[object, Path, dict[str, object], bytes, dict[str, str]]:
        prepared = self._prepare("streaming", prompt="thread lifecycle")
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata = orchestrator.update_metadata(
            run_dir,
            worker_pid=os.getpid(),
            worker_process_identity=worker_identity.to_dict(),
            controller_pid=worker_identity.parent_pid,
        )
        self._publish_worker_gate(run_dir, metadata)
        frame = prepared.launch_spec.private_frame()
        protocol = (
            len(frame).to_bytes(8, "big")
            + frame
            + len(prepared.prompt_bytes).to_bytes(8, "big")
            + prepared.prompt_bytes
        )
        environment = dict(prepared.launch_spec.environment)
        environment[orchestrator.INTERNAL_WORKER_NONCE_ENV] = nonce
        return prepared, run_dir, metadata, protocol, environment

    def test_stream_thread_start_failure_reaps_child_and_started_threads(self) -> None:
        _prepared, run_dir, metadata, protocol, environment = (
            self._direct_stream_fixture()
        )
        real_popen = orchestrator.subprocess.Popen
        real_start = threading.Thread.start
        children: list[subprocess.Popen[bytes]] = []
        starts = 0

        def mark_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            if kwargs.get("stdin") is subprocess.PIPE:
                children.append(child)
                self.addCleanup(
                    orchestrator._terminate_owned_process,
                    child,
                    deadline=time.monotonic() + 5,
                )
            return child

        def fail_second_start(thread: threading.Thread) -> None:
            nonlocal starts
            if thread.name.startswith("cc-runtime-"):
                starts += 1
                if starts == 2:
                    raise RuntimeError("fixture thread start failure")
            real_start(thread)

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=mark_popen
        ), patch.object(
            threading.Thread, "start", new=fail_second_start
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertEqual(len(children), 1)
        self._wait_for_pid_exit(children[0].pid, timeout=3)
        self.assertFalse(
            any(
                thread.is_alive() and thread.name.startswith("cc-runtime-")
                for thread in threading.enumerate()
            )
        )
        self.assertFalse((run_dir / "pid.txt").exists())

    def test_failure_cleanup_inherits_the_effective_launch_deadline(self) -> None:
        real_terminate = orchestrator._terminate_owned_process
        observed: list[float | None] = []

        def terminate(
            process: subprocess.Popen[bytes], *, deadline: float | None = None
        ) -> bool:
            observed.append(deadline)
            return real_terminate(
                process,
                deadline=deadline if deadline is not None else time.monotonic() + 5,
            )

        with patch.object(
            orchestrator, "capture_process_identity", side_effect=OSError("identity")
        ), patch.object(orchestrator, "_terminate_owned_process", side_effect=terminate):
            result = orchestrator.run_agent(
                "identity cleanup", cwd=self.workspace, timeout_seconds=2
            )
        self.assertEqual(result["status"], "blocked_runtime_identity", result)

        observed.clear()
        with patch.object(
            orchestrator, "_write_pipe_chunk", side_effect=BrokenPipeError("protocol")
        ), patch.object(orchestrator, "_terminate_owned_process", side_effect=terminate):
            result = orchestrator.run_streaming_agent(
                "protocol cleanup", cwd=self.workspace, timeout_seconds=2
            )
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertTrue(observed)
        self.assertTrue(all(deadline is not None for deadline in observed), observed)


class SixthReviewTeamAuthorizationTests(GuardedLaunchFixture):
    def test_team_uses_one_authorization_manifest_and_no_member_gates(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        statuses: list[str] = []
        authorized = False

        def observe_manifest(team_id: str, data: dict[str, object]) -> Path:
            nonlocal authorized
            if authorized:
                raise AssertionError("team write after authorization publication")
            path = real_manifest(team_id, data)
            status = str(data.get("status"))
            statuses.append(status)
            if status == "authorized":
                authorized = True
            return path

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator,
            "_open_worker_start_gate",
            side_effect=AssertionError("per-member team gate is forbidden"),
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=observe_manifest
        ):
            team = orchestrator.spawn_role_team(
                "atomic authorization",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertTrue(team["ok"], team)
        self.assertEqual(statuses, ["prepared", "authorized"])
        for item in team["runs"]:
            run_dir = self.runs_dir / str(item["run_id"])
            self.assertFalse(
                (run_dir / orchestrator.WORKER_START_GATE_FILENAME).exists()
            )
            terminal = self._wait_for_terminal_metadata(run_dir, timeout=10)
            self._wait_for_pid_exit(int(terminal["worker_pid"]))

    def test_member_terminal_before_authorization_rolls_back_zero_children(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        attacked = False

        def stop_member(team_id: str, data: dict[str, object]) -> Path:
            nonlocal attacked
            path = real_manifest(team_id, data)
            if data.get("status") == "prepared" and not attacked:
                attacked = True
                first = data["runs"][0]
                orchestrator.update_metadata(
                    self.runs_dir / str(first["run_id"]),
                    status="stopped",
                    stop_requested_at="fixture-stop",
                    terminal_state_count=1,
                )
            return path

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=stop_member
        ):
            team = orchestrator.spawn_role_team(
                "revalidation",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertTrue(attacked)
        self.assertFalse(team["ok"], team)
        for item in team["runs"]:
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertIsNone(metadata.get("child_pid"), metadata)
            self._wait_for_pid_exit(int(metadata["worker_pid"]))

    def test_authorization_publication_failure_rolls_back_zero_children(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        authorization_attempted = False

        def fail_authorization(team_id: str, data: dict[str, object]) -> Path:
            nonlocal authorization_attempted
            if data.get("status") == "authorized":
                authorization_attempted = True
                raise OSError("fixture authorization publication failure")
            return real_manifest(team_id, data)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=fail_authorization
        ):
            team = orchestrator.spawn_role_team(
                "authorization failure",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )
        self.assertTrue(authorization_attempted)
        self.assertFalse(team["ok"], team)
        for item in team["runs"]:
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertIsNone(metadata.get("child_pid"), metadata)
            self._wait_for_pid_exit(int(metadata["worker_pid"]))


class SixthReviewCapabilityTests(GuardedLaunchFixture):
    def test_atomic_publication_rejects_source_swap_after_prepare(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "metadata.json"
        orchestrator._atomic_write_text(target, '{"state":"before"}')
        attack_fired = False

        if os.name == "nt":
            real_replace = orchestrator._windows_replace_relative

            def swap_source(
                temporary: Path, destination: Path, parent_handle: object
            ) -> None:
                nonlocal attack_fired
                backup = temporary.with_name(temporary.name + ".verified")
                temporary.replace(backup)
                temporary.write_text('{"state":"attacker"}', encoding="utf-8")
                attack_fired = True
                try:
                    real_replace(temporary, destination, parent_handle)
                finally:
                    temporary.unlink(missing_ok=True)
                    if backup.exists():
                        backup.replace(temporary)

            replacement = patch.object(
                orchestrator, "_windows_replace_relative", side_effect=swap_source
            )
        else:
            real_replace = orchestrator._posix_replace_relative

            def swap_source(
                temporary: Path, destination: Path, parent_handle: int
            ) -> None:
                nonlocal attack_fired
                backup = temporary.with_name(temporary.name + ".verified")
                temporary.replace(backup)
                temporary.write_text('{"state":"attacker"}', encoding="utf-8")
                attack_fired = True
                try:
                    real_replace(temporary, destination, parent_handle)
                finally:
                    temporary.unlink(missing_ok=True)
                    if backup.exists():
                        backup.replace(temporary)

            replacement = patch.object(
                orchestrator, "_posix_replace_relative", side_effect=swap_source
            )

        with replacement:
            with self.assertRaises((OSError, orchestrator.OrchestratorError)):
                orchestrator._atomic_write_text(target, '{"state":"after"}')
        self.assertTrue(attack_fired)
        self.assertEqual(target.read_text(encoding="utf-8"), '{"state":"before"}')

    @unittest.skipUnless(os.name == "nt", "Windows post-handle ancestor regression")
    def test_windows_enumeration_rejects_post_handle_ancestor_swap(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        orchestrator._atomic_write_text(run_dir / "inside.txt", "inside-secret")
        outside = self.workspace / "outside-enumeration"
        outside.mkdir()
        outside_file = outside / "outside.txt"
        outside_file.write_text("outside-secret", encoding="utf-8")
        backup = run_dir.with_name(run_dir.name + ".original")
        real_open = orchestrator._open_managed_directory
        attack_fired = False

        @contextlib.contextmanager
        def swap_after_open(
            path: Path, *, writable: bool = False, verify_private: bool = True
        ) -> object:
            nonlocal attack_fired
            with real_open(
                path, writable=writable, verify_private=verify_private
            ) as opened:
                if Path(path) == run_dir and not attack_fired:
                    run_dir.replace(backup)
                    os.symlink(outside, run_dir, target_is_directory=True)
                    attack_fired = True
                    try:
                        yield opened
                    finally:
                        run_dir.unlink()
                        backup.replace(run_dir)
                else:
                    yield opened

        with patch.object(
            orchestrator, "_open_managed_directory", side_effect=swap_after_open
        ):
            with self.assertRaises((OSError, orchestrator.OrchestratorError)):
                orchestrator._scrub_run_artifacts(
                    run_dir, ("inside-secret", "outside-secret")
                )
        self.assertTrue(attack_fired)
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "outside-secret")

    def test_artifact_lock_is_owner_bearing_at_visibility_and_recovers_legacy_ownerless(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        run_dir.mkdir(parents=True)
        lock_path = run_dir.parent / f".{run_dir.name}.artifact.lock"
        with orchestrator.artifact_lock(run_dir, timeout_seconds=0.2):
            self.assertTrue(lock_path.is_file())
            owner = json.loads(lock_path.read_text(encoding="ascii"))
            self.assertEqual(owner["pid"], os.getpid())
            self.assertTrue(owner["token"])
        self.assertFalse(lock_path.exists())

        lock_path.mkdir()
        old = time.time() - 120
        os.utime(lock_path, (old, old))
        with orchestrator.artifact_lock(run_dir, timeout_seconds=0.2):
            self.assertTrue(lock_path.is_file())
        self.assertFalse(lock_path.exists())


class ReviewFixWrapperChecks(GuardedLaunchFixture):
    def test_last_moment_wrapper_swaps_are_blocked_by_final_chain_checks(self) -> None:
        wrappers = [
            (
                self.workspace / "runtime.py",
                "import sys\nsys.stdin.buffer.read()\n",
                "# replacement\nimport sys\nsys.stdin.buffer.read()\n",
            ),
            (
                self.workspace / "runtime-shebang",
                f"#!{Path(sys.executable).resolve()}\nimport sys\nsys.stdin.buffer.read()\n",
                f"#!{Path(sys.executable).resolve()}\n# replacement\nimport sys\nsys.stdin.buffer.read()\n",
            ),
        ]
        if os.name == "nt":
            wrappers.extend(
                [
                    (
                        self.workspace / "runtime.cmd",
                        "@echo off\r\nset /p CC_INPUT=\r\n",
                        "@echo off\r\nrem replacement\r\nset /p CC_INPUT=\r\n",
                    ),
                    (
                        self.workspace / "runtime.ps1",
                        "[Console]::In.ReadToEnd() | Out-Null\r\n",
                        "# replacement\r\n[Console]::In.ReadToEnd() | Out-Null\r\n",
                    ),
                ]
            )
        for wrapper, original, replacement in wrappers:
            with self.subTest(wrapper=wrapper.suffix or "shebang"):
                wrapper.write_text(original, encoding="utf-8")
                try:
                    ExecutableIdentity.capture(wrapper)
                except (FileNotFoundError, OSError, ValueError) as error:
                    self.skipTest(str(error))
                candidate = RuntimeExecutableCandidate(
                    canonical_path=str(wrapper.resolve()),
                    source="fixture",
                    trust_class="trusted_default",
                )
                with patch.object(
                    orchestrator, "resolve_runtime_candidate", return_value=candidate
                ):
                    prepared = self._prepare("one_shot")
                real_popen = subprocess.Popen

                def swap_then_start(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
                    command = args[0] if args else kwargs.get("args", [])
                    if str(wrapper) in " ".join(str(item) for item in command):
                        wrapper.write_text(replacement, encoding="utf-8")
                    return real_popen(*args, **kwargs)

                with patch.object(
                    orchestrator.subprocess, "Popen", side_effect=swap_then_start
                ):
                    result = orchestrator.start_prepared_worker_launch(prepared)
                self.assertEqual(result["status"], "blocked_runtime_identity")
                self.assertFalse(orchestrator.pid_alive(int(result["child_pid"])))


if __name__ == "__main__":
    unittest.main()
