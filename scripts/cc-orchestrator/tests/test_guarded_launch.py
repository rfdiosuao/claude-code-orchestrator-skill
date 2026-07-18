from __future__ import annotations

import io
import json
import os
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
                        "start_gate": gate,
                    },
                    "controller_pid": os.getpid(),
                }
            )
            orchestrator.write_metadata(run_dir, metadata)
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
                    "start_gate": "open",
                },
                "controller_pid": worker_identity.parent_pid,
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
        real_replace = os.replace

        def inspect_replacement(source: str, destination: str) -> None:
            observed_replacements.append(
                orchestrator._inspect_windows_private_acl(
                    Path(source), is_dir=False
                )
            )
            real_replace(source, destination)

        with patch.object(orchestrator.os, "replace", side_effect=inspect_replacement):
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
        with patch.object(orchestrator.os, "replace", side_effect=OSError("replace failed")):
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
        self._wait_for_terminal_metadata(stream_dir)
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
                    "start_gate": "open",
                },
            }
        )
        orchestrator.write_metadata(run_dir, metadata)
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
        target = run_dir / "metadata.json"
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
            "open",
        )

    def test_gate_is_not_published_when_lock_release_fails(self) -> None:
        prepared = self._prepare("streaming", prompt="")
        run_dir, _metadata = orchestrator._initialize_prepared_run(prepared)

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

    def test_gate_verification_fault_keeps_controller_worker_agreement(self) -> None:
        def reject_open_gate(path: Path, *, is_dir: bool = False) -> None:
            candidate = Path(path)
            if not is_dir and candidate.is_file():
                payload = candidate.read_bytes()
                if b'"start_gate": "open"' in payload:
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
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
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
                    "import pathlib, sys, time",
                    f"chunk = {chunk}",
                    "for _ in range(768):",
                    "    sys.stdout.buffer.write(chunk)",
                    "sys.stdout.buffer.flush()",
                    "prompt = sys.stdin.buffer.read()",
                    f"pathlib.Path({str(marker)!r}).write_text(str(len(prompt)), encoding='utf-8')",
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
        self.assertGreater(int(marker.read_text(encoding="utf-8")), 0)
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

        def snapshot(_run_dir: Path, _cwd: Path, label: str) -> dict[str, object]:
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
        ), patch.object(orchestrator, "check_write_scope", return_value=scope):
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
