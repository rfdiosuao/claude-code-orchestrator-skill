from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import os
import shutil
import socket
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


def _native_unprivileged_ubuntu_or_macos() -> bool:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return False
    if sys.platform == "darwin":
        return True
    if not sys.platform.startswith("linux"):
        return False
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return False
    return any(
        line.strip().casefold() == "id=ubuntu"
        for line in os_release.splitlines()
    )


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
                "transaction_deadline_monotonic": time.monotonic() + 8,
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
                "transaction_deadline_monotonic": time.monotonic() + 8,
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
            "timeout partial output", cwd=self.workspace, timeout_seconds=2
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
        real_prepare = orchestrator._prepare_private_atomic_write

        def reject_open_gate(
            path: Path, payload: bytes, *args: object, **kwargs: object
        ) -> Path:
            if (
                Path(path).name == orchestrator.WORKER_START_GATE_FILENAME
                and b'"state": "open"' in payload
            ):
                raise OSError("pre-publication verification fault")
            return real_prepare(path, payload, *args, **kwargs)

        with patch.object(
            orchestrator,
            "_prepare_private_atomic_write",
            side_effect=reject_open_gate,
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

        def interleave(
            temporary: Path, target: Path, **kwargs: object
        ) -> None:
            if Path(target).name == gate_name:
                orchestrator.update_metadata(
                    run_dir,
                    status="stopped",
                    stop_requested_at="fixture-stop",
                    terminal_state_count=1,
                )
            real_replace(temporary, target, **kwargs)

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

        def interleave(
            temporary: Path, target: Path, **kwargs: object
        ) -> None:
            if Path(target).name == gate_name:
                orchestrator.update_metadata(
                    run_dir,
                    arbitrary_controller_field={"preserve": [1, 2, 3]},
                    status="running",
                )
            real_replace(temporary, target, **kwargs)

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
            real_open = getattr(
                orchestrator, "_open_windows_relative_managed_file", None
            )
            self.assertIsNotNone(real_open)

            def swap_then_open(
                parent_handle: object,
                name: str,
                *args: object,
                **kwargs: object,
            ) -> object:
                nonlocal swapped
                if name == victim.name and not swapped:
                    victim.replace(backup)
                    os.symlink(outside, victim)
                    swapped = True
                return real_open(parent_handle, name, *args, **kwargs)

            opener_patch = patch.object(
                orchestrator,
                "_open_windows_relative_managed_file",
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
        attacker_paths: list[Path] = []
        if os.name == "nt":
            real_create = orchestrator._create_windows_private_file

            @contextlib.contextmanager
            def swap_native_temp(
                path: Path, *args: object, **kwargs: object
            ) -> object:
                nonlocal attack_fired
                with real_create(path, *args, **kwargs) as handle:
                    candidate = Path(path)
                    if candidate.name.startswith(".git_after") and not attack_fired:
                        backup = candidate.with_name(candidate.name + ".original")
                        candidate.replace(backup)
                        os.symlink(outside, candidate)
                        attacker_paths.append(candidate)
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
        if os.name == "nt":
            self.assertTrue(snapshot["ok"], snapshot)
        else:
            self.assertFalse(snapshot["ok"], snapshot)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
        for attacker_path in attacker_paths:
            if attacker_path.is_symlink():
                attacker_path.unlink()
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
                "transaction_deadline_monotonic": time.monotonic() + 8,
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
                if target_reads > 1:
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
                "transaction_deadline_monotonic": time.monotonic() + 1.5,
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
            real_open = orchestrator._open_windows_relative_managed_directory

            def swap_directory(
                parent_handle: object,
                name: str,
                *args: object,
                **kwargs: object,
            ) -> object:
                nonlocal swapped
                if name == nested.name and not swapped:
                    nested.replace(backup)
                    os.symlink(outside, nested, target_is_directory=True)
                    swapped = True
                return real_open(parent_handle, name, *args, **kwargs)

            opener_patch = patch.object(
                orchestrator,
                "_open_windows_relative_managed_directory",
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
            encoding="utf-8",
            errors="replace",
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
            transaction_deadline_monotonic=time.monotonic() + 8,
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
            self.assertEqual(result["persistence_state"], "persisted")
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
            deadline = time.time() + 3
            while time.time() < deadline and any(
                thread.name.startswith("cc-cleanup-owner-")
                for thread in threading.enumerate()
            ):
                time.sleep(0.02)

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
            transaction_deadline_monotonic=time.monotonic() + 8,
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
            if os.name == "nt":
                orchestrator._atomic_write_text(target, '{"state":"after"}')
            else:
                with self.assertRaises((OSError, orchestrator.OrchestratorError)):
                    orchestrator._atomic_write_text(target, '{"state":"after"}')
        self.assertTrue(attack_fired)
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            '{"state":"after"}' if os.name == "nt" else '{"state":"before"}',
        )

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
        real_list = orchestrator._windows_list_directory_handle
        attack_fired = False

        def swap_after_enumeration(handle: object) -> list[str]:
            nonlocal attack_fired
            names = real_list(handle)
            if not attack_fired and "inside.txt" in names:
                run_dir.replace(backup)
                os.symlink(outside, run_dir, target_is_directory=True)
                attack_fired = True
            return names

        try:
            with patch.object(
                orchestrator,
                "_windows_list_directory_handle",
                side_effect=swap_after_enumeration,
            ):
                orchestrator._scrub_run_artifacts(
                    run_dir, ("inside-secret", "outside-secret")
                )
        finally:
            if run_dir.is_symlink():
                run_dir.unlink()
            if backup.exists():
                backup.replace(run_dir)
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


class SeventhReviewArtifactLockTests(GuardedLaunchFixture):
    def test_concurrent_stale_reclaimers_never_create_two_holders(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        lock_path = run_dir.parent / f".{run_dir.name}.artifact.lock"
        stale_pid = 999_999_999
        self.assertFalse(orchestrator.pid_alive(stale_pid))
        orchestrator._atomic_write_text(
            lock_path,
            json.dumps({"pid": stale_pid, "token": "stale-generation"}),
        )

        real_replace = orchestrator.os.replace
        reclaim_barrier = threading.Barrier(2)
        holder_entered = threading.Event()
        replace_count = 0
        replace_guard = threading.Lock()
        active_holders = 0
        max_holders = 0
        holder_guard = threading.Lock()
        errors: list[BaseException] = []

        def ordered_replace(source: object, destination: object, *args: object, **kwargs: object) -> None:
            nonlocal replace_count
            source_path = Path(source) if isinstance(source, (str, os.PathLike)) else None
            destination_path = (
                Path(destination)
                if isinstance(destination, (str, os.PathLike))
                else None
            )
            if (
                source_path == lock_path
                and destination_path is not None
                and destination_path.name.startswith(lock_path.name + ".released-")
            ):
                with replace_guard:
                    replace_count += 1
                    position = replace_count
                try:
                    reclaim_barrier.wait(timeout=0.5)
                except threading.BrokenBarrierError:
                    pass
                if position > 1:
                    holder_entered.wait(2)
            real_replace(source, destination, *args, **kwargs)

        def contender() -> None:
            nonlocal active_holders, max_holders
            try:
                with orchestrator.artifact_lock(run_dir, timeout_seconds=3):
                    with holder_guard:
                        active_holders += 1
                        max_holders = max(max_holders, active_holders)
                        holder_entered.set()
                    time.sleep(0.15)
                    with holder_guard:
                        active_holders -= 1
            except BaseException as exc:
                errors.append(exc)

        with patch.object(orchestrator.os, "replace", side_effect=ordered_replace):
            contenders = [threading.Thread(target=contender) for _ in range(2)]
            for thread in contenders:
                thread.start()
            for thread in contenders:
                thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in contenders))
        self.assertEqual(errors, [])
        self.assertEqual(max_holders, 1)
        self.assertFalse(lock_path.exists())


class SeventhReviewLifecycleTests(GuardedLaunchFixture):
    def _direct_stream_fixture(
        self,
    ) -> tuple[object, Path, dict[str, object], bytes, dict[str, str]]:
        prepared = self._prepare("streaming", prompt="constructor lifecycle")
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        nonce = prepared.launch_spec.launch_nonce
        worker_identity = capture_process_identity(os.getpid(), launch_nonce=nonce)
        metadata = orchestrator.update_metadata(
            run_dir,
            worker_pid=os.getpid(),
            worker_process_identity=worker_identity.to_dict(),
            controller_pid=worker_identity.parent_pid,
            transaction_deadline_monotonic=time.monotonic() + 8,
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

    def test_thread_constructor_failure_cannot_leave_stream_child_alive(self) -> None:
        _prepared, run_dir, metadata, protocol, environment = (
            self._direct_stream_fixture()
        )
        real_popen = orchestrator.subprocess.Popen
        real_thread = threading.Thread
        children: list[subprocess.Popen[bytes]] = []
        constructor_failed = False

        def capture_child(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            if kwargs.get("stdin") is subprocess.PIPE:
                children.append(child)
                self.addCleanup(
                    orchestrator._terminate_owned_process,
                    child,
                    deadline=time.monotonic() + 5,
                )
            return child

        def construct_thread(*args: object, **kwargs: object) -> threading.Thread:
            nonlocal constructor_failed
            name = str(kwargs.get("name") or "")
            if name.startswith("cc-runtime-stdout-") and not constructor_failed:
                constructor_failed = True
                raise RuntimeError("fixture thread constructor failure")
            return real_thread(*args, **kwargs)

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=capture_child
        ), patch.object(
            orchestrator.threading, "Thread", side_effect=construct_thread
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))

        self.assertTrue(constructor_failed)
        self.assertEqual(len(children), 1)
        self.assertIn(
            result["status"], {"blocked_runtime_launch", "cleanup_pending"}, result
        )
        self._wait_for_pid_exit(children[0].pid, timeout=3)
        self.assertFalse((run_dir / "pid.txt").exists())
        self.assertFalse(
            any(
                thread.is_alive() and thread.name.startswith("cc-runtime-")
                for thread in threading.enumerate()
            )
        )


class SeventhReviewTeamTests(GuardedLaunchFixture):
    def _wait_for_team_workers(self, team: dict[str, object]) -> None:
        for item in team.get("runs", []):
            if not isinstance(item, dict):
                continue
            run_dir = self.runs_dir / str(item["run_id"])
            try:
                metadata = self._wait_for_terminal_metadata(run_dir, timeout=10)
            except AssertionError:
                metadata = orchestrator.read_metadata(run_dir)
            worker_pid = metadata.get("worker_pid")
            if isinstance(worker_pid, int):
                self._wait_for_pid_exit(worker_pid, timeout=5)

    def test_slow_valid_team_preparation_does_not_start_gate_timeout(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_run = orchestrator.run_streaming_agent
        calls = 0

        def delayed_member(*args: object, **kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 2:
                time.sleep(0.35)
            return real_run(*args, **kwargs)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "WORKER_START_GATE_TIMEOUT_SECONDS", 0.1
        ), patch.object(
            orchestrator, "run_streaming_agent", side_effect=delayed_member
        ):
            team = orchestrator.spawn_role_team(
                "slow team preparation",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=4,
            )

        self.assertTrue(team["ok"], team)
        manifest = json.loads(Path(str(team["manifest_path"])).read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "authorized")
        self.assertTrue(all(item.get("ready_at") for item in manifest["runs"]))
        self._wait_for_team_workers(team)

    def test_member_termination_in_final_authorization_window_blocks_all_children(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        attacked = False

        def terminate_before_authorization(
            team_id: str, data: dict[str, object]
        ) -> Path:
            nonlocal attacked
            if data.get("status") == "authorized" and not attacked:
                run_id = str(data["runs"][0]["run_id"])
                with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                    worker = orchestrator._ACTIVE_WORKER_HANDLES.get(run_id)
                self.assertIsNotNone(worker)
                assert worker is not None
                orchestrator._terminate_owned_process(
                    worker, deadline=time.monotonic() + 3
                )
                attacked = True
            return real_manifest(team_id, data)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=terminate_before_authorization
        ):
            team = orchestrator.spawn_role_team(
                "final authorization termination",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=5,
            )

        self.assertTrue(attacked)
        self.assertFalse(team["ok"], team)
        self.assertEqual(team["rollback"]["failed_stop_count"], 0, team)
        for item in team["runs"]:
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertIsNone(metadata.get("child_pid"), metadata)
            worker_pid = metadata.get("worker_pid")
            if isinstance(worker_pid, int):
                self._wait_for_pid_exit(worker_pid)

    def test_team_manifests_never_persist_raw_task_or_context(self) -> None:
        team_dir = self.artifact_root / "teams"
        task_secret = "team-task-secret-seventh-83d1"
        context_secret = "team-context-secret-seventh-5c92"

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=0
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ):
            blocked = orchestrator.spawn_role_team(
                task_secret,
                roles=["testing"],
                cwd=self.workspace,
                context=context_secret,
                timeout_seconds=3,
            )

        real_manifest = orchestrator.write_team_manifest

        def fail_authorization(team_id: str, data: dict[str, object]) -> Path:
            if data.get("status") == "authorized":
                raise OSError("fixture authorization failure")
            return real_manifest(team_id, data)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=2
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=fail_authorization
        ):
            rolled_back = orchestrator.spawn_role_team(
                task_secret,
                roles=["testing"],
                cwd=self.workspace,
                context=context_secret,
                timeout_seconds=3,
            )

        for result in (blocked, rolled_back):
            payload = Path(str(result["manifest_path"])).read_bytes()
            self.assertNotIn(task_secret.encode(), payload)
            self.assertNotIn(context_secret.encode(), payload)
        self.assertFalse(rolled_back["ok"], rolled_back)
        for item in rolled_back["runs"]:
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            worker_pid = metadata.get("worker_pid")
            if isinstance(worker_pid, int):
                self._wait_for_pid_exit(worker_pid)


class SeventhReviewGitAndDeadlineTests(GuardedLaunchFixture):
    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", *args],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed

    def _initialize_git_scope(self, max_diff_lines: int = 1) -> Path:
        if shutil.which("git") is None:
            self.skipTest("git is unavailable")
        self._git("init")
        self._git("config", "user.name", "Task Seven Fixture")
        self._git("config", "user.email", "task-seven@example.invalid")
        target = self.workspace / "layer-neutral.txt"
        target.write_text("base\n", encoding="utf-8")
        self._git("add", target.name)
        self._git("commit", "-m", "base")
        scope_dir = self.workspace / ".claude-code-orchestrator"
        scope_dir.mkdir()
        (scope_dir / "write-scope.json").write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [],
                    "max_diff_lines": max_diff_lines,
                }
            ),
            encoding="utf-8",
        )
        return target

    def test_unstage_and_reset_do_not_double_count_the_same_logical_lines(self) -> None:
        target = self._initialize_git_scope(max_diff_lines=1)
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target.write_text("base\none\ntwo\n", encoding="utf-8")
        self._git("add", target.name)
        before = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "before"
        )
        self._git("reset")
        after_unstage = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "after-unstage"
        )
        pinned = orchestrator._pin_write_scope_policy(self.workspace)
        unstage_check = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, before, after_unstage, pinned
        )
        self.assertEqual(unstage_check["diff_lines"], 0, unstage_check)
        self.assertNotIn(
            "max_diff_lines",
            {item["type"] for item in unstage_check["violations"]},
        )

        target.write_text("base\none\ntwo\nthree\n", encoding="utf-8")
        after_change = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "after-change"
        )
        boundary_check = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, after_unstage, after_change, pinned
        )
        self.assertEqual(boundary_check["diff_lines"], 1, boundary_check)
        self.assertNotIn(
            "max_diff_lines",
            {item["type"] for item in boundary_check["violations"]},
        )

    def test_one_shot_popen_does_not_replace_transaction_deadline(self) -> None:
        prepared = self._prepare("one_shot", prompt="deadline identity")
        real_popen = orchestrator.subprocess.Popen
        real_capture = orchestrator.capture_process_identity
        before_popen: list[float | None] = []
        after_popen: list[float | None] = []

        def capture_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            before_popen.append(orchestrator._effective_deadline())
            return real_popen(*args, **kwargs)

        def capture_identity(*args: object, **kwargs: object) -> ProcessIdentity:
            after_popen.append(orchestrator._effective_deadline())
            return real_capture(*args, **kwargs)

        with patch.object(
            orchestrator.subprocess, "Popen", side_effect=capture_popen
        ), patch.object(
            orchestrator, "capture_process_identity", side_effect=capture_identity
        ):
            result = orchestrator.start_prepared_worker_launch(prepared)

        self.assertEqual(result.get("exit_code"), 0, result)
        self.assertEqual(len(before_popen), 1)
        self.assertTrue(after_popen)
        self.assertEqual(before_popen[0], after_popen[0])

    def test_stream_protocol_and_initialization_share_total_deadline(self) -> None:
        real_initialize = orchestrator._initialize_prepared_run
        real_write = orchestrator._write_pipe_chunk

        def delayed_initialize(prepared: object) -> tuple[Path, dict[str, object]]:
            time.sleep(0.55)
            return real_initialize(prepared)

        def delayed_write(pipe: object, payload: bytes) -> None:
            time.sleep(0.18)
            real_write(pipe, payload)

        started = time.monotonic()
        with patch.object(
            orchestrator, "_initialize_prepared_run", side_effect=delayed_initialize
        ), patch.object(
            orchestrator, "_write_pipe_chunk", side_effect=delayed_write
        ):
            result = orchestrator.run_streaming_agent(
                "single transaction deadline",
                cwd=self.workspace,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1.3, (elapsed, result))
        self.assertIn(
            result["status"], {"blocked_runtime_launch", "cleanup_pending"}, result
        )
        worker_pid = result.get("worker_pid") or result.get("owned_process_pid")
        if isinstance(worker_pid, int):
            self._wait_for_pid_exit(worker_pid, timeout=5)


class SeventhReviewManagedReaderTests(GuardedLaunchFixture):
    def test_event_sidecar_and_log_reads_reject_links(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        orchestrator._atomic_write_text(run_dir / "events.ndjson", "")
        outside = self.workspace / "outside-events.ndjson"
        outside.write_text('{"seq":41,"type":"outside"}\n', encoding="utf-8")
        seq_outside = self.workspace / "outside-seq.txt"
        seq_outside.write_text('{"seq":41,"events_bytes":0}', encoding="utf-8")
        try:
            os.symlink(outside, run_dir / "linked-events.ndjson")
            os.symlink(seq_outside, run_dir / "event_seq.txt")
        except OSError as exc:
            self.skipTest(f"links unavailable: {exc}")

        with self.assertRaises((OSError, orchestrator.OrchestratorError)):
            orchestrator.read_events(run_dir / "linked-events.ndjson")
        with self.assertRaises((OSError, orchestrator.OrchestratorError)):
            orchestrator.append_event(run_dir, {"type": "inside"})
        self.assertEqual(
            seq_outside.read_text(encoding="utf-8"),
            '{"seq":41,"events_bytes":0}',
        )

    def test_event_log_read_remains_bound_after_parent_swap(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        events_path = run_dir / "events.ndjson"
        orchestrator._atomic_write_text(
            events_path, '{"seq":1,"type":"inside"}\n'
        )
        outside = self.workspace / "outside-reader"
        outside.mkdir()
        (outside / "events.ndjson").write_text(
            '{"seq":99,"type":"outside"}\n', encoding="utf-8"
        )
        backup = run_dir.with_name(run_dir.name + ".reader-original")
        file_backup = events_path.with_name(events_path.name + ".reader-original")
        real_open = orchestrator._open_managed_file
        attack_fired = False

        @contextlib.contextmanager
        def swap_after_open(
            path: Path, *, writable: bool = False, verify_private: bool = True
        ) -> object:
            nonlocal attack_fired
            with real_open(
                path, writable=writable, verify_private=verify_private
            ) as opened:
                if Path(path) == events_path and not attack_fired:
                    if os.name == "nt":
                        events_path.replace(file_backup)
                        os.symlink(outside / "events.ndjson", events_path)
                    else:
                        run_dir.replace(backup)
                        os.symlink(outside, run_dir, target_is_directory=True)
                    attack_fired = True
                    try:
                        yield opened
                    finally:
                        if os.name == "nt":
                            events_path.unlink()
                            file_backup.replace(events_path)
                        else:
                            run_dir.unlink()
                            backup.replace(run_dir)
                else:
                    yield opened

        with patch.object(
            orchestrator, "_open_managed_file", side_effect=swap_after_open
        ):
            events = orchestrator.read_events(events_path)
        self.assertTrue(attack_fired)
        self.assertEqual([event["type"] for event in events], ["inside"])


class EighthReviewArtifactLockTests(GuardedLaunchFixture):
    def test_concurrent_legacy_directory_reclaimers_cannot_retire_successor(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        lock_path = run_dir.parent / f".{run_dir.name}.artifact.lock"
        lock_path.mkdir()
        stale_pid = 999_999_999
        self.assertFalse(orchestrator.pid_alive(stale_pid))
        (lock_path / "owner.pid").write_text(
            json.dumps({"pid": stale_pid, "token": "legacy-stale"}),
            encoding="ascii",
        )

        real_retire = orchestrator._retire_artifact_lock_directory
        reclaim_barrier = threading.Barrier(2)
        retire_count = 0
        retire_guard = threading.Lock()
        active_holders = 0
        max_holders = 0
        holder_guard = threading.Lock()
        errors: list[BaseException] = []

        def observed_retire(
            source: Path,
            suffix: str,
            expected_identity: tuple[int, int] | None = None,
            retained_handle: object | None = None,
            *args: object,
            **kwargs: object,
        ) -> bool:
            nonlocal retire_count
            if Path(source) == lock_path:
                with retire_guard:
                    retire_count += 1
            return real_retire(
                source,
                suffix,
                expected_identity,
                retained_handle,
                *args,
                **kwargs,
            )

        def contender() -> None:
            nonlocal active_holders, max_holders
            try:
                reclaim_barrier.wait(timeout=2)
                with orchestrator.artifact_lock(run_dir, timeout_seconds=4):
                    with holder_guard:
                        active_holders += 1
                        max_holders = max(max_holders, active_holders)
                    time.sleep(0.2)
                    with holder_guard:
                        active_holders -= 1
            except BaseException as exc:
                errors.append(exc)

        with patch.object(
            orchestrator,
            "_retire_artifact_lock_directory",
            side_effect=observed_retire,
        ):
            contenders = [threading.Thread(target=contender) for _ in range(2)]
            for thread in contenders:
                thread.start()
            for thread in contenders:
                thread.join(timeout=7)

        self.assertTrue(all(not thread.is_alive() for thread in contenders))
        self.assertEqual(errors, [])
        self.assertEqual(retire_count, 1)
        self.assertEqual(max_holders, 1)
        self.assertFalse(lock_path.exists())


class EighthReviewLifecycleTests(GuardedLaunchFixture):
    def _direct_stream_fixture(
        self,
    ) -> tuple[object, Path, dict[str, object], bytes, dict[str, str]]:
        prepared, run_dir, metadata, protocol, environment = (
            SeventhReviewLifecycleTests._direct_stream_fixture(self)
        )
        metadata = orchestrator.update_metadata(
            run_dir,
            transaction_deadline_monotonic=time.monotonic() + 8,
        )
        return prepared, run_dir, metadata, protocol, environment

    def test_second_pump_constructor_failure_reaps_child_and_started_threads(self) -> None:
        _prepared, run_dir, metadata, protocol, environment = (
            self._direct_stream_fixture()
        )
        real_popen = orchestrator.subprocess.Popen
        real_thread = threading.Thread
        children: list[subprocess.Popen[bytes]] = []
        pump_constructors = 0
        attack_fired = False

        def capture_child(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            if kwargs.get("stdin") is subprocess.PIPE:
                children.append(child)
                self.addCleanup(
                    orchestrator._terminate_owned_process,
                    child,
                    deadline=time.monotonic() + 5,
                )
            return child

        def construct_thread(*args: object, **kwargs: object) -> threading.Thread:
            nonlocal pump_constructors, attack_fired
            thread_args = kwargs.get("args")
            if (
                isinstance(thread_args, tuple)
                and thread_args
                and getattr(thread_args[0], "__name__", "") == "pump"
            ):
                pump_constructors += 1
                if pump_constructors == 2:
                    attack_fired = True
                    raise RuntimeError("fixture second pump constructor failure")
            return real_thread(*args, **kwargs)

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=capture_child
        ), patch.object(
            orchestrator.threading, "Thread", side_effect=construct_thread
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))

        self.assertTrue(attack_fired)
        self.assertEqual(len(children), 1)
        self.assertIn(
            result["status"], {"blocked_runtime_launch", "cleanup_pending"}, result
        )
        self._wait_for_pid_exit(children[0].pid, timeout=4)
        self.assertFalse((run_dir / "pid.txt").exists())
        self.assertFalse(
            any(
                thread.is_alive() and thread.name.startswith("cc-runtime-")
                for thread in threading.enumerate()
            )
        )

    def test_one_shot_exception_immediately_after_popen_reaps_child(self) -> None:
        prepared = self._prepare("one_shot", prompt="one-shot lifecycle boundary")
        real_popen = orchestrator.subprocess.Popen
        children: list[subprocess.Popen[bytes]] = []

        def capture_child(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            children.append(child)
            self.addCleanup(
                orchestrator._terminate_owned_process,
                child,
                deadline=time.monotonic() + 5,
            )
            return child

        with patch.object(
            orchestrator.subprocess, "Popen", side_effect=capture_child
        ), patch.object(
            orchestrator,
            "_runtime_execution_deadline",
            side_effect=RuntimeError("fixture post-Popen failure"),
        ):
            result = orchestrator.start_prepared_worker_launch(prepared)

        self.assertEqual(len(children), 1)
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self._wait_for_pid_exit(children[0].pid, timeout=4)

    def test_isolated_worker_persists_and_owns_process_and_thread_cleanup(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        deadline = time.monotonic() + 5
        orchestrator.write_metadata(
            run_dir,
            {
                "run_id": run_dir.name,
                "status": "running",
                "transaction_deadline_monotonic": deadline,
                "worker_pid": os.getpid(),
                "terminal_state_count": 0,
            },
        )
        orchestrator._atomic_write_text(run_dir / "events.ndjson", "")
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(
            orchestrator._terminate_owned_process,
            child,
            deadline=time.monotonic() + 5,
        )
        pump = threading.Thread(
            target=child.wait,
            name=f"cc-runtime-fixture-{run_dir.name}",
            daemon=True,
        )
        pump.start()
        pending = orchestrator._OwnedCleanupPending(child)
        pending.threads = (pump,)

        with patch.object(
            orchestrator, "_stream_worker_inner", side_effect=pending
        ):
            result = orchestrator.stream_worker(run_dir.name)

        self.assertIsNotNone(child.poll(), result)
        pump.join(timeout=2)
        self.assertFalse(pump.is_alive())
        persisted = orchestrator.read_metadata(run_dir)
        self.assertTrue(result.get("persisted"), result)
        self.assertNotEqual(result.get("status"), "cleanup_pending", result)
        self.assertEqual(persisted.get("cleanup_state"), "cleanup_confirmed")
        self.assertEqual(persisted.get("live_cleanup_threads"), [])
        self.assertTrue(
            any(event.get("type") == "cleanup_pending" for event in orchestrator.read_events(run_dir / "events.ndjson"))
        )


class EighthReviewDeadlineTests(GuardedLaunchFixture):
    def test_slow_route_preparation_consumes_the_original_deadline(self) -> None:
        popen_called = False

        def slow_route(*args: object, **kwargs: object) -> dict[str, object]:
            time.sleep(1.15)
            return dict(self.route)

        def reject_popen(*args: object, **kwargs: object) -> object:
            nonlocal popen_called
            popen_called = True
            raise AssertionError("runtime must not start after preparation deadline")

        started = time.monotonic()
        with patch.object(
            orchestrator, "resolve_route", side_effect=slow_route
        ), patch.object(orchestrator.subprocess, "Popen", side_effect=reject_popen):
            result = orchestrator.run_agent(
                "slow preparation deadline",
                cwd=self.workspace,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started

        self.assertFalse(popen_called)
        self.assertLess(elapsed, 1.5, (elapsed, result))
        self.assertEqual(result["status"], "blocked_runtime_launch", result)
        self.assertTrue(result.get("timed_out"), result)

    def test_isolated_worker_rejects_missing_or_invalid_inherited_deadline(self) -> None:
        for label, value in (
            ("missing", None),
            ("string", "later"),
            ("nan", float("nan")),
        ):
            with self.subTest(label=label):
                run_dir = self.runs_dir / orchestrator.new_run_id()
                orchestrator._set_private_directory(run_dir)
                metadata: dict[str, object] = {
                    "run_id": run_dir.name,
                    "status": "starting",
                    "timeout_seconds": 1,
                }
                if label != "missing":
                    metadata["transaction_deadline_monotonic"] = value
                orchestrator.write_metadata(run_dir, metadata)
                with patch.object(
                    orchestrator,
                    "_stream_worker_inner",
                    return_value={"status": "unexpected-inner-call"},
                ) as inner:
                    result = orchestrator.stream_worker(run_dir.name)
                self.assertFalse(inner.called, result)
                self.assertEqual(result["status"], "blocked_runtime_security", result)


class EighthReviewTeamTests(GuardedLaunchFixture):
    def _wait_for_team_workers(self, team: dict[str, object]) -> None:
        SeventhReviewTeamTests._wait_for_team_workers(self, team)

    def test_authorization_observes_nonce_git_and_scope_after_readiness(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        observed: list[dict[str, object]] = []

        def inspect_authorization(
            team_id: str, data: dict[str, object]
        ) -> Path:
            if data.get("status") == "authorized":
                for item in data.get("runs", []):
                    assert isinstance(item, dict)
                    member = orchestrator.read_metadata(
                        self.runs_dir / str(item["run_id"])
                    )
                    launch = dict(member.get("worker_launch") or {})
                    observed.append(
                        {
                            "nonce_consumed": launch.get("nonce_consumed"),
                            "team_preflight_complete": launch.get(
                                "team_preflight_complete"
                            ),
                            "git_before": member.get("git_before"),
                            "scope_policy_identity": launch.get(
                                "scope_policy_identity"
                            ),
                        }
                    )
            return real_manifest(team_id, data)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=3
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=inspect_authorization
        ):
            team = orchestrator.spawn_role_team(
                "post-ready preparation",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=6,
            )

        self.assertTrue(team["ok"], team)
        self.assertEqual(len(observed), 2)
        for evidence in observed:
            self.assertTrue(evidence["nonce_consumed"], evidence)
            self.assertTrue(evidence["team_preflight_complete"], evidence)
            self.assertTrue(evidence["scope_policy_identity"], evidence)
            git_before = evidence["git_before"]
            self.assertIsInstance(git_before, dict)
            assert isinstance(git_before, dict)
            self.assertNotEqual(git_before.get("state"), "pending_worker_capture")
            self.assertTrue(git_before.get("evidence_complete"), git_before)
        self._wait_for_team_workers(team)

    def test_member_death_after_final_validation_cannot_publish_authorization(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_write = orchestrator.write_json_file
        attacked = False

        def kill_after_validation(
            path: Path, data: object, **kwargs: object
        ) -> Path:
            nonlocal attacked
            if (
                isinstance(data, dict)
                and data.get("status") == "authorized"
                and not attacked
            ):
                run_id = str(data["runs"][0]["run_id"])
                with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                    worker = orchestrator._ACTIVE_WORKER_HANDLES.get(run_id)
                self.assertIsNotNone(worker)
                assert worker is not None
                orchestrator._terminate_owned_process(
                    worker, deadline=time.monotonic() + 3
                )
                attacked = True
            return real_write(path, data, **kwargs)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=3
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_json_file", side_effect=kill_after_validation
        ):
            team = orchestrator.spawn_role_team(
                "final publication death window",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=6,
            )

        self.assertTrue(attacked)
        self.assertFalse(team["ok"], team)
        manifest = json.loads(
            Path(str(team["manifest_path"])).read_text(encoding="utf-8")
        )
        self.assertNotEqual(manifest["status"], "authorized", manifest)
        for item in team["runs"]:
            metadata = orchestrator.read_metadata(
                self.runs_dir / str(item["run_id"])
            )
            self.assertIsNone(metadata.get("child_pid"), metadata)
        self._wait_for_team_workers(team)

    def test_every_team_manifest_omits_prompt_plaintext_and_unkeyed_digests(self) -> None:
        team_dir = self.artifact_root / "teams"
        task_secret = "eighth-team-task-f12a73"
        context_secret = "eighth-team-context-9be441"
        forbidden = {
            task_secret,
            context_secret,
            hashlib.sha256(task_secret.encode("utf-8")).hexdigest(),
            hashlib.sha256(context_secret.encode("utf-8")).hexdigest(),
        }

        def assert_manifest_safe(result: dict[str, object]) -> None:
            manifest = json.loads(
                Path(str(result["manifest_path"])).read_text(encoding="utf-8")
            )

            def strings(value: object) -> list[str]:
                if isinstance(value, str):
                    return [value]
                if isinstance(value, dict):
                    return [
                        item
                        for key, child in value.items()
                        for item in [*strings(key), *strings(child)]
                    ]
                if isinstance(value, list):
                    return [item for child in value for item in strings(child)]
                return []

            persisted = strings(manifest)
            for secret in forbidden:
                self.assertFalse(
                    any(secret in value for value in persisted),
                    (secret, manifest),
                )

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=0
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ):
            blocked = orchestrator.spawn_role_team(
                task_secret,
                roles=["testing"],
                cwd=self.workspace,
                context=context_secret,
                timeout_seconds=4,
            )
        assert_manifest_safe(blocked)

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=2
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ):
            launched = orchestrator.spawn_role_team(
                task_secret,
                roles=["testing"],
                cwd=self.workspace,
                context=context_secret,
                timeout_seconds=5,
            )
        self.assertTrue(launched["ok"], launched)
        assert_manifest_safe(launched)
        self._wait_for_team_workers(launched)


class EighthReviewGitTests(SeventhReviewGitAndDeadlineTests):
    def test_unicode_and_quoted_path_stage_unstage_is_layer_neutral(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is unavailable")
        self._git("init")
        self._git("config", "user.name", "Task Eight Fixture")
        self._git("config", "user.email", "task-eight@example.invalid")
        # Non-ASCII forces Git's quoted display form while remaining a legal
        # native filename on Windows.
        target = self.workspace / "quoted snow-\u96ea.txt"
        target.write_text("base\n", encoding="utf-8")
        self._git("add", target.name)
        self._git("commit", "-m", "base")
        scope_dir = self.workspace / ".claude-code-orchestrator"
        scope_dir.mkdir()
        (scope_dir / "write-scope.json").write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [],
                    "max_diff_lines": 1,
                }
            ),
            encoding="utf-8",
        )
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target.write_text("base\none\n", encoding="utf-8")
        self._git("add", target.name)
        before = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "quoted-before"
        )
        self._git("reset")
        after_unstage = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "quoted-after-unstage"
        )
        pinned = orchestrator._pin_write_scope_policy(self.workspace)
        unstage = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, before, after_unstage, pinned
        )
        self.assertEqual(unstage["diff_lines"], 0, unstage)

        target.write_text("base\none\ntwo\n", encoding="utf-8")
        after_change = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "quoted-after-change"
        )
        changed = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, after_unstage, after_change, pinned
        )
        self.assertEqual(changed["diff_lines"], 1, changed)
        self.assertNotIn(
            "max_diff_lines",
            {item["type"] for item in changed["violations"]},
        )
        normalized = target.name.replace("\\", "/")
        self.assertIn(normalized, changed["changed_paths"], changed)


@unittest.skipUnless(os.name == "nt", "Windows capability-relative regressions")
class SeventhReviewWindowsCapabilityTests(GuardedLaunchFixture):
    def test_writable_open_does_not_touch_swapped_parent_target(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        victim = run_dir / "victim.txt"
        orchestrator._atomic_write_text(victim, "inside")
        outside = self.workspace / "outside-writable"
        outside.mkdir()
        outside_victim = outside / "victim.txt"
        outside_victim.write_text("outside", encoding="utf-8")
        before_acl = orchestrator._inspect_windows_private_acl(
            outside_victim, is_dir=False
        )["entries"]
        backup = run_dir.with_name(run_dir.name + ".writable-original")
        real_open = orchestrator._open_windows_managed_directory
        attack_fired = False

        @contextlib.contextmanager
        def swap_parent(
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
            orchestrator, "_open_windows_managed_directory", side_effect=swap_parent
        ):
            try:
                with orchestrator._open_managed_file(
                    victim, writable=True, verify_private=False
                ) as (handle, _details):
                    handle.seek(0)
                    handle.write(b"safe")
                    handle.truncate()
            except (OSError, orchestrator.OrchestratorError):
                pass
        self.assertTrue(attack_fired)
        self.assertEqual(outside_victim.read_text(encoding="utf-8"), "outside")
        self.assertEqual(
            orchestrator._inspect_windows_private_acl(
                outside_victim, is_dir=False
            )["entries"],
            before_acl,
        )

    def test_atomic_temp_creation_uses_retained_parent_capability(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "metadata.json"
        orchestrator._atomic_write_text(target, '{"state":"before"}')
        outside = self.workspace / "outside-temp"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("outside", encoding="utf-8")
        before_names = sorted(path.name for path in outside.iterdir())
        backup = run_dir.with_name(run_dir.name + ".temp-original")
        real_open = orchestrator._open_windows_managed_directory
        real_create = orchestrator._create_windows_private_file
        attack_fired = False
        escaped_to_path = False

        @contextlib.contextmanager
        def swap_parent(
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

        @contextlib.contextmanager
        def observe_create(path: Path, *args: object, **kwargs: object) -> object:
            nonlocal escaped_to_path
            if kwargs.get("parent_handle") is None and Path(path).parent == run_dir:
                escaped_to_path = escaped_to_path or run_dir.is_symlink()
            with real_create(path, *args, **kwargs) as handle:
                yield handle

        with patch.object(
            orchestrator, "_open_windows_managed_directory", side_effect=swap_parent
        ), patch.object(
            orchestrator, "_create_windows_private_file", side_effect=observe_create
        ):
            try:
                orchestrator._atomic_write_text(target, '{"state":"after"}')
            except (OSError, orchestrator.OrchestratorError):
                pass
        self.assertTrue(attack_fired)
        self.assertFalse(escaped_to_path)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside")
        self.assertEqual(sorted(path.name for path in outside.iterdir()), before_names)

    def test_enumeration_uses_retained_directory_handle_after_validation(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        orchestrator._atomic_write_text(run_dir / "inside.txt", "inside")
        outside = self.workspace / "outside-enumeration-seven"
        outside.mkdir()
        outside_file = outside / "outside.txt"
        outside_file.write_text("outside", encoding="utf-8")
        backup = run_dir.with_name(run_dir.name + ".enum-original")
        real_open_directory = orchestrator._open_windows_managed_directory
        real_open_file = orchestrator._open_managed_file
        directory_calls = 0
        attack_fired = False
        outside_read = False

        @contextlib.contextmanager
        def swap_after_validation(
            path: Path, *, writable: bool = False, verify_private: bool = True
        ) -> object:
            nonlocal directory_calls, attack_fired
            if Path(path) == run_dir:
                directory_calls += 1
                call = directory_calls
            else:
                call = 0
            with real_open_directory(
                path, writable=writable, verify_private=verify_private
            ) as opened:
                yield opened
            if call == 2 and not attack_fired:
                run_dir.replace(backup)
                os.symlink(outside, run_dir, target_is_directory=True)
                attack_fired = True

        @contextlib.contextmanager
        def observe_file(
            path: Path, *, writable: bool = False, verify_private: bool = True
        ) -> object:
            nonlocal outside_read
            if Path(path).name == outside_file.name:
                outside_read = True
            with real_open_file(
                path, writable=writable, verify_private=verify_private
            ) as opened:
                yield opened

        try:
            with patch.object(
                orchestrator,
                "_open_windows_managed_directory",
                side_effect=swap_after_validation,
            ), patch.object(
                orchestrator, "_open_managed_file", side_effect=observe_file
            ):
                try:
                    orchestrator._iter_managed_artifacts(run_dir)
                except (OSError, orchestrator.OrchestratorError):
                    pass
        finally:
            if run_dir.is_symlink():
                run_dir.unlink()
            if backup.exists():
                backup.replace(run_dir)
        self.assertTrue(attack_fired)
        self.assertFalse(outside_read)
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "outside")


@unittest.skipUnless(os.name == "nt", "Windows capability-relative regressions")
class EighthReviewWindowsCapabilityTests(GuardedLaunchFixture):
    def test_same_name_real_directory_replacement_cannot_redirect_scrubbing(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        orchestrator._atomic_write_text(run_dir / "same-name.txt", "inside")
        backup = run_dir.with_name(run_dir.name + ".eighth-original")
        replacement_file: Path | None = None
        real_list = orchestrator._windows_list_directory_handle
        attack_fired = False

        def replace_after_enumeration(handle: object) -> list[str]:
            nonlocal attack_fired, replacement_file
            names = real_list(handle)
            if not attack_fired and "same-name.txt" in names:
                run_dir.replace(backup)
                run_dir.mkdir()
                replacement_file = run_dir / "same-name.txt"
                replacement_file.write_text(
                    "outside-eighth-secret", encoding="utf-8"
                )
                attack_fired = True
            return names

        escaped_content = ""
        try:
            with patch.object(
                orchestrator,
                "_windows_list_directory_handle",
                side_effect=replace_after_enumeration,
            ):
                try:
                    orchestrator._scrub_run_artifacts(
                        run_dir, ("outside-eighth-secret",)
                    )
                except (OSError, orchestrator.OrchestratorError):
                    pass
            self.assertTrue(attack_fired)
            assert replacement_file is not None
            escaped_content = replacement_file.read_text(encoding="utf-8")
        finally:
            if run_dir.exists():
                shutil.rmtree(run_dir)
            if backup.exists():
                backup.replace(run_dir)
        self.assertEqual(escaped_content, "outside-eighth-secret")

    def test_atomic_replace_uses_retained_temp_source_handle_after_name_swap(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "metadata.json"
        orchestrator._atomic_write_text(target, '{"state":"before"}')
        real_replace = orchestrator._windows_replace_relative
        attacked_paths: list[tuple[Path, Path]] = []

        def replace_temp_name(
            temporary_path: Path, destination: Path, parent_handle: object
        ) -> None:
            retained = temporary_path.with_name(
                temporary_path.name + ".retained-original"
            )
            temporary_path.replace(retained)
            temporary_path.write_text("attacker replacement", encoding="utf-8")
            attacked_paths.append((temporary_path, retained))
            real_replace(temporary_path, destination, parent_handle)

        try:
            with patch.object(
                orchestrator,
                "_windows_replace_relative",
                side_effect=replace_temp_name,
            ):
                orchestrator._atomic_write_text(target, '{"state":"after"}')
            self.assertTrue(attacked_paths)
            self.assertEqual(target.read_text(encoding="utf-8"), '{"state":"after"}')
        finally:
            for attacker, retained in attacked_paths:
                attacker.unlink(missing_ok=True)
                retained.unlink(missing_ok=True)


@unittest.skipUnless(os.name == "posix", "native POSIX capability CI requirement")
class SeventhReviewPosixCapabilityTests(GuardedLaunchFixture):
    def test_posix_openat_linkat_modes_no_follow_and_cleanup(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "state.json"
        orchestrator._atomic_write_text(target, '{"state":"one"}')
        orchestrator._atomic_write_text(target, '{"state":"two"}')
        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        outside = self.workspace / "outside-posix.txt"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(outside, run_dir / "linked.txt")
        with self.assertRaises((OSError, orchestrator.OrchestratorError)):
            orchestrator._read_bounded_regular_file(run_dir / "linked.txt", 100)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
        self.assertEqual(orchestrator._PREPARED_ATOMIC_PARENTS, {})


@unittest.skipUnless(os.name == "posix", "native POSIX ninth-cycle lock regression")
class NinthReviewLegacyLockTests(GuardedLaunchFixture):
    def test_multiprocess_legacy_reclaimers_cannot_retire_a_successor(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        lock_path = run_dir.parent / f".{run_dir.name}.artifact.lock"
        lock_path.mkdir()
        stale_pid = 999_999_999
        (lock_path / "owner.pid").write_text(
            json.dumps({"pid": stale_pid, "token": "ninth-stale"}),
            encoding="ascii",
        )
        script = "\n".join(
            [
                "import os, pathlib, sys, time",
                f"sys.path.insert(0, {str(ORCHESTRATOR_DIR)!r})",
                "import cc_orchestrator as o",
                "run_dir = pathlib.Path(sys.argv[1])",
                "go = pathlib.Path(sys.argv[2])",
                "markers = pathlib.Path(sys.argv[3])",
                "timeline = pathlib.Path(sys.argv[4])",
                "real_match = o._artifact_lock_directory_path_matches_generation",
                "calls = 0",
                "def synchronized_match(path, generation):",
                "    global calls",
                "    calls += 1",
                "    matched = real_match(path, generation)",
                "    if calls == 2 and matched:",
                "        (markers / str(os.getpid())).write_text('ready')",
                "        deadline = time.monotonic() + 1.0",
                "        while len(list(markers.iterdir())) < 2 and time.monotonic() < deadline:",
                "            time.sleep(0.005)",
                "    return matched",
                "o._artifact_lock_directory_path_matches_generation = synchronized_match",
                "while not go.exists(): time.sleep(0.005)",
                "with o.artifact_lock(run_dir, timeout_seconds=5):",
                "    with timeline.open('a', encoding='ascii') as out:",
                "        out.write(f'enter {os.getpid()} {time.monotonic()}\\n'); out.flush()",
                "    time.sleep(0.25)",
                "    with timeline.open('a', encoding='ascii') as out:",
                "        out.write(f'exit {os.getpid()} {time.monotonic()}\\n'); out.flush()",
            ]
        )
        go = self.workspace / "legacy-go"
        markers = self.workspace / "legacy-markers"
        markers.mkdir()
        timeline = self.workspace / "legacy-timeline.txt"
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(run_dir), str(go), str(markers), str(timeline)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        go.write_text("go", encoding="ascii")
        completed = [process.communicate(timeout=10) for process in processes]
        for process, (_stdout, stderr) in zip(processes, completed):
            self.assertEqual(process.returncode, 0, stderr)
        intervals: dict[str, dict[str, float]] = {}
        for line in timeline.read_text(encoding="ascii").splitlines():
            kind, pid, value = line.split()
            intervals.setdefault(pid, {})[kind] = float(value)
        self.assertEqual(len(intervals), 2, intervals)
        ordered = sorted(intervals.values(), key=lambda item: item["enter"])
        self.assertGreaterEqual(ordered[1]["enter"], ordered[0]["exit"])
        self.assertFalse(lock_path.exists())


class NinthReviewLaunchLockTests(GuardedLaunchFixture):
    def test_live_long_holder_remains_exclusive_with_atomic_owner_evidence(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        active = 0
        maximum = 0
        guard = threading.Lock()
        errors: list[BaseException] = []

        def holder() -> None:
            nonlocal active, maximum
            try:
                with orchestrator.launch_lock(timeout_seconds=2, stale_seconds=0.02):
                    lock_path = self.runs_dir / ".launch.lock"
                    owner_path = lock_path if lock_path.is_file() else lock_path / "owner.json"
                    owner = json.loads(owner_path.read_text(encoding="utf-8"))
                    self.assertEqual(owner["pid"], os.getpid())
                    self.assertTrue(owner.get("token"), owner)
                    self.assertTrue(owner.get("generation"), owner)
                    with guard:
                        active += 1
                        maximum = max(maximum, active)
                    entered.set()
                    release.wait(1)
                    with guard:
                        active -= 1
            except BaseException as exc:
                errors.append(exc)

        first = threading.Thread(target=holder)
        second = threading.Thread(target=holder)
        first.start()
        self.assertTrue(entered.wait(2))
        time.sleep(0.08)
        second.start()
        time.sleep(0.12)
        release.set()
        first.join(timeout=3)
        second.join(timeout=3)
        self.assertEqual(errors, [])
        self.assertEqual(maximum, 1)

    def test_old_launch_owner_cannot_delete_same_name_successor(self) -> None:
        context = orchestrator.launch_lock(timeout_seconds=1, stale_seconds=0)
        context.__enter__()
        lock_path = self.runs_dir / ".launch.lock"
        retired = self.runs_dir / ".launch.lock.old-generation"
        lock_path.replace(retired)
        successor = {
            "pid": os.getpid(),
            "token": "successor-token",
            "generation": "successor-generation",
            "created_at": orchestrator.utc_now_iso(),
        }
        if retired.is_dir():
            lock_path.mkdir()
            (lock_path / "owner.json").write_text(
                json.dumps(successor), encoding="utf-8"
            )
        else:
            lock_path.write_text(json.dumps(successor), encoding="utf-8")
        context.__exit__(None, None, None)
        self.assertTrue(lock_path.exists())
        if lock_path.is_dir():
            shutil.rmtree(lock_path)
            shutil.rmtree(retired)
        else:
            lock_path.unlink()
            retired.unlink()


class NinthReviewCleanupOwnershipTests(GuardedLaunchFixture):
    def test_direct_cleanup_pending_is_persisted_and_owned_by_nondaemon_thread(self) -> None:
        release = threading.Event()

        class Stream:
            def close(self) -> None:
                pass

        class PendingProcess:
            args = ("ninth-pending",)
            pid = 424299
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
                release.wait(3)
                self.returncode = -9
                return self.returncode

        process = PendingProcess()
        pump = threading.Thread(
            target=release.wait,
            name="cc-runtime-ninth-live-pump",
            daemon=True,
        )
        pump.start()
        pending = orchestrator._OwnedCleanupPending(process, (pump,))
        prepared = self._prepare("one_shot", prompt="durable cleanup owner")
        try:
            with patch.object(
                orchestrator, "_start_one_shot_launch_inner", side_effect=pending
            ):
                result = orchestrator.start_prepared_worker_launch(prepared)
            run_dir = self.runs_dir / str(result["run_id"])
            persisted = orchestrator.read_metadata(run_dir)
            self.assertEqual(result["status"], "cleanup_pending", result)
            self.assertEqual(persisted["status"], "cleanup_pending", persisted)
            self.assertTrue(persisted.get("persisted"), persisted)
            self.assertIn(pump.name, persisted.get("live_cleanup_threads", []))
            owners = [
                thread
                for thread in threading.enumerate()
                if thread.name.startswith("cc-cleanup-owner-")
            ]
            self.assertTrue(owners)
            self.assertTrue(all(not thread.daemon for thread in owners))
        finally:
            release.set()
            pump.join(timeout=2)
            deadline = time.time() + 3
            while time.time() < deadline and any(
                thread.name.startswith("cc-cleanup-owner-")
                for thread in threading.enumerate()
            ):
                time.sleep(0.02)


class NinthReviewLifecycleTests(EighthReviewLifecycleTests):
    def test_second_pump_failure_waits_for_descendant_retained_pipe(self) -> None:
        descendant_ready = self.workspace / "ninth-descendant-ready"
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import pathlib, subprocess, sys",
                    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1.1)'], stdout=sys.stdout, stderr=sys.stderr, close_fds=False)",
                    f"pathlib.Path({str(descendant_ready)!r}).write_text('ready')",
                    "sys.stdin.buffer.read()",
                    "print('parent-finished', flush=True)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        _prepared, run_dir, metadata, protocol, environment = (
            self._direct_stream_fixture()
        )
        real_thread = threading.Thread
        real_popen = orchestrator.subprocess.Popen
        pump_constructors = 0
        retained_streams: list[object] = []

        class RetainedPipe:
            def __init__(self, stream: object) -> None:
                self.stream = stream

            def read(self, *args: object, **kwargs: object) -> object:
                return self.stream.read(*args, **kwargs)

            def read1(self, *args: object, **kwargs: object) -> object:
                read1 = getattr(self.stream, "read1", self.stream.read)
                return read1(*args, **kwargs)

            def close(self) -> None:
                pass

        def retain_child_pipes(
            *args: object, **kwargs: object
        ) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            if kwargs.get("stdin") is subprocess.PIPE:
                if child.stdout is not None:
                    retained_streams.append(child.stdout)
                    child.stdout = RetainedPipe(child.stdout)
                if child.stderr is not None:
                    retained_streams.append(child.stderr)
                    child.stderr = RetainedPipe(child.stderr)
            return child

        def fail_second_pump(*args: object, **kwargs: object) -> threading.Thread:
            nonlocal pump_constructors
            thread_args = kwargs.get("args")
            if (
                isinstance(thread_args, tuple)
                and thread_args
                and getattr(thread_args[0], "__name__", "") == "pump"
            ):
                pump_constructors += 1
                if pump_constructors == 2:
                    deadline = time.monotonic() + 2
                    while (
                        not descendant_ready.exists()
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    self.assertTrue(descendant_ready.exists())
                    raise RuntimeError("ninth second pump failure")
            return real_thread(*args, **kwargs)

        started = time.monotonic()
        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=retain_child_pipes
        ), patch.object(orchestrator.threading, "Thread", side_effect=fail_second_pump):
            result = orchestrator.stream_worker(str(metadata["run_id"]))
        for stream in retained_streams:
            stream.close()
        elapsed = time.monotonic() - started
        self.assertEqual(pump_constructors, 2)
        self.assertGreaterEqual(elapsed, 0.9, (elapsed, result))
        self.assertFalse(
            any(
                thread.is_alive() and thread.name.startswith("cc-runtime-")
                for thread in threading.enumerate()
            )
        )
        persisted = orchestrator.read_metadata(run_dir)
        self.assertIn(persisted.get("live_cleanup_threads"), (None, []))


class NinthReviewTeamTests(EighthReviewTeamTests):
    def test_authorization_publication_is_the_final_controller_commit(self) -> None:
        team_dir = self.artifact_root / "teams"
        real_manifest = orchestrator.write_team_manifest
        authorized = False
        writes_after_authorization: list[str] = []
        killed = False

        def kill_after_publication(team_id: str, data: dict[str, object]) -> Path:
            nonlocal authorized, killed
            if authorized:
                writes_after_authorization.append(str(data.get("status")))
            path = real_manifest(team_id, data)
            if data.get("status") == "authorized" and not killed:
                authorized = True
                run_id = str(data["runs"][0]["run_id"])
                with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                    worker = orchestrator._ACTIVE_WORKER_HANDLES.get(run_id)
                self.assertIsNotNone(worker)
                assert worker is not None
                orchestrator._terminate_owned_process(
                    worker, deadline=time.monotonic() + 3
                )
                killed = True
            return path

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=3
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=kill_after_publication
        ):
            team = orchestrator.spawn_role_team(
                "post-publication member death",
                roles=["testing", "review"],
                cwd=self.workspace,
                timeout_seconds=6,
            )

        self.assertTrue(killed)
        self.assertTrue(team["ok"], team)
        self.assertEqual(writes_after_authorization, [])
        manifest = json.loads(
            Path(str(team["manifest_path"])).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "authorized", manifest)
        self._wait_for_team_workers(team)

    def test_worker_performs_no_peer_validation_after_authorization_observation(self) -> None:
        prepared, run_dir, metadata, protocol, environment = (
            EighthReviewLifecycleTests._direct_stream_fixture(self)
        )
        metadata = orchestrator.update_metadata(
            run_dir,
            team_id="team-ninth-observation",
            team_manifest_path=str(self.workspace / "team-ninth.json"),
        )

        def latest(*_args: object, **_kwargs: object) -> dict[str, object]:
            return orchestrator.read_metadata(run_dir)

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator, "_complete_team_worker_preflight", side_effect=latest
        ), patch.object(
            orchestrator, "_wait_for_team_authorization", side_effect=latest
        ), patch.object(
            orchestrator,
            "_team_start_barrier_ready",
            side_effect=AssertionError("peer validation after commit is forbidden"),
        ) as peer_validation:
            result = orchestrator.stream_worker(str(metadata["run_id"]))

        self.assertFalse(peer_validation.called, result)
        self.assertEqual(result.get("status"), "succeeded", result)
        self.assertEqual(result.get("exit_code"), 0, result)


@unittest.skipUnless(os.name == "nt", "Windows retained-temp cleanup regression")
class NinthReviewWindowsCleanupTests(GuardedLaunchFixture):
    def test_prepare_failure_deletes_only_the_retained_temp_source(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "metadata.json"
        real_secure = orchestrator._secure_private_writable_handle
        attacker: Path | None = None
        retained: Path | None = None

        def swap_then_fail(handle: object, path: Path) -> None:
            nonlocal attacker, retained
            real_secure(handle, path)
            retained = path.with_name(path.name + ".retained")
            path.replace(retained)
            path.write_text("attacker-successor", encoding="utf-8")
            attacker = path
            raise OSError("ninth preparation failure")

        try:
            with patch.object(
                orchestrator,
                "_secure_private_writable_handle",
                side_effect=swap_then_fail,
            ):
                with self.assertRaises(OSError):
                    orchestrator._prepare_private_atomic_write(target, b"approved")
            assert attacker is not None and retained is not None
            self.assertTrue(attacker.exists())
            self.assertEqual(attacker.read_text(encoding="utf-8"), "attacker-successor")
            self.assertFalse(retained.exists())
        finally:
            if attacker is not None:
                attacker.unlink(missing_ok=True)
            if retained is not None:
                retained.unlink(missing_ok=True)


class NinthReviewDeadlineTests(GuardedLaunchFixture):
    def test_direct_two_phase_launch_inherits_preparation_deadline_evidence(self) -> None:
        prepared = self._prepare("one_shot", prompt="direct deadline evidence")
        deadline = prepared.transaction_deadline_monotonic
        observed: list[float | None] = []
        real_popen = orchestrator.subprocess.Popen

        def observe_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            observed.append(orchestrator._effective_deadline())
            return real_popen(*args, **kwargs)

        with patch.object(orchestrator.subprocess, "Popen", side_effect=observe_popen):
            result = orchestrator.start_prepared_worker_launch(prepared)
        self.assertEqual(result.get("exit_code"), 0, result)
        self.assertEqual(observed, [deadline])

        invalid = self._prepare("one_shot", prompt="invalid deadline evidence")
        object.__setattr__(invalid, "transaction_deadline_monotonic", float("nan"))
        with self.assertRaises(orchestrator.OrchestratorError):
            orchestrator.start_prepared_worker_launch(invalid)

    def test_team_sequential_preparation_shares_one_total_wall_deadline(self) -> None:
        team_dir = self.artifact_root / "teams"
        observed: list[float | None] = []

        def slow_member(*_args: object, **kwargs: object) -> dict[str, object]:
            observed.append(orchestrator._effective_deadline())
            time.sleep(0.38)
            orchestrator._check_deadline()
            reservation = kwargs["_admission_reservation"]
            run_id = orchestrator.new_run_id()
            reservation.register(run_id)
            return {"run_id": run_id, "status": "starting", "profile": {}}

        def write_fixture_manifest(team_id: str, data: dict[str, object]) -> Path:
            team_dir.mkdir(parents=True, exist_ok=True)
            path = team_dir / f"{team_id}.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return path

        with patch.object(orchestrator, "TEAMS_DIR", team_dir), patch.object(
            orchestrator, "max_concurrent_limit", return_value=4
        ), patch.object(
            orchestrator, "run_status", return_value={"active_count": 0}
        ), patch.object(
            orchestrator, "run_streaming_agent", side_effect=slow_member
        ), patch.object(
            orchestrator, "write_team_manifest", side_effect=write_fixture_manifest
        ), patch.object(
            orchestrator,
            "_wait_for_team_members_ready",
            side_effect=lambda _team, runs, deadline: runs,
        ):
            started = time.monotonic()
            result = orchestrator.spawn_role_team(
                "shared team deadline",
                roles=["requirements", "testing", "review"],
                cwd=self.workspace,
                timeout_seconds=1,
            )
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1.35, (elapsed, result))
        self.assertTrue(observed)
        self.assertTrue(all(value is not None for value in observed), observed)
        self.assertEqual(len(set(observed)), 1, observed)
        self.assertFalse(result.get("ok", False), result)


class NinthReviewGitTests(SeventhReviewGitAndDeadlineTests):
    def test_stage_movement_plus_real_edit_counts_only_the_logical_edit(self) -> None:
        target = self._initialize_git_scope(max_diff_lines=1)
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target.write_text("base\npredirty\n", encoding="utf-8")
        before_stage = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "ninth-before-stage"
        )
        self._git("add", target.name)
        target.write_text("base\npredirty\nactual\n", encoding="utf-8")
        after_stage = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "ninth-after-stage"
        )
        pinned = orchestrator._pin_write_scope_policy(self.workspace)
        stage_result = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, before_stage, after_stage, pinned
        )
        self.assertEqual(stage_result["diff_lines"], 1, stage_result)
        self.assertNotIn(
            "max_diff_lines",
            {item["type"] for item in stage_result["violations"]},
        )

        self._git("reset")
        target.write_text("base\npredirty\nactual\nsecond\n", encoding="utf-8")
        after_unstage = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "ninth-after-unstage"
        )
        unstage_result = orchestrator._check_write_scope_with_evidence(
            run_dir.name, self.workspace, after_stage, after_unstage, pinned
        )
        self.assertEqual(unstage_result["diff_lines"], 1, unstage_result)


@unittest.skipUnless(os.name == "posix", "native POSIX ninth-cycle CI gate")
class NinthReviewPosixGateTests(SeventhReviewGitAndDeadlineTests):
    def test_native_posix_gate_preserves_backslashes_and_capabilities(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is unavailable")
        self._git("init")
        self._git("config", "user.name", "Task Nine POSIX Fixture")
        self._git("config", "user.email", "task-nine@example.invalid")
        literal = "literal\\path-\u96ea.txt"
        target = self.workspace / literal
        target.write_text("base\n", encoding="utf-8")
        self._git("add", literal)
        self._git("commit", "-m", "base")
        scope_dir = self.workspace / ".claude-code-orchestrator"
        scope_dir.mkdir()
        (scope_dir / "write-scope.json").write_text(
            json.dumps(
                {
                    "cwd": str(self.workspace),
                    "allowed_paths": [str(self.workspace)],
                    "denied_paths": [],
                    "max_diff_lines": 1,
                }
            ),
            encoding="utf-8",
        )
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        before = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "ninth-posix-before"
        )
        target.write_text("base\nedit\n", encoding="utf-8")
        after = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "ninth-posix-after"
        )
        result = orchestrator._check_write_scope_with_evidence(
            run_dir.name,
            self.workspace,
            before,
            after,
            orchestrator._pin_write_scope_policy(self.workspace),
        )
        self.assertIn(literal, result["changed_paths"], result)
        self.assertIn(literal, result["checked_paths"], result)
        self.assertNotIn(literal.replace("\\", "/"), result["changed_paths"])
        state = run_dir / "ninth-state.json"
        orchestrator._atomic_write_text(state, '{"state":"one"}')
        orchestrator._atomic_write_text(state, '{"state":"two"}')
        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        outside = self.workspace / "ninth-outside.txt"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(outside, run_dir / "ninth-link.txt")
        with self.assertRaises((OSError, orchestrator.OrchestratorError)):
            orchestrator._read_bounded_regular_file(run_dir / "ninth-link.txt", 100)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
        self.assertEqual(orchestrator._PREPARED_ATOMIC_PARENTS, {})


class TenthReviewFixture(GuardedLaunchFixture):
    class FakeStream:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self, pid: int, *, ignore_terminate: bool = False) -> None:
            self.args = ("tenth-owned-process", str(pid))
            self.pid = pid
            self.stdin = TenthReviewFixture.FakeStream()
            self.stdout = TenthReviewFixture.FakeStream()
            self.stderr = TenthReviewFixture.FakeStream()
            self.returncode: int | None = None
            self.ignore_terminate = ignore_terminate
            self.wait_timeouts: list[float | None] = []
            self.terminate_calls = 0
            self.kill_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminate_calls += 1
            if not self.ignore_terminate:
                self.returncode = -15

        def kill(self) -> None:
            self.kill_calls += 1
            self.returncode = -9

        def wait(self, timeout: float | None = None) -> int:
            self.wait_timeouts.append(timeout)
            if self.returncode is None:
                if timeout is not None:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                self.returncode = -9
            return self.returncode

        def force_exit(self) -> None:
            self.returncode = -9

    class StartFailingThread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.name = str(kwargs.get("name") or "tenth-start-failure")
            self.daemon = bool(kwargs.get("daemon", False))
            self.target = kwargs.get("target")

        def start(self) -> None:
            raise RuntimeError("tenth thread start failure")

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:
            return None

    def _prepare_with_timeout(
        self, mode: str, prompt: str, timeout_seconds: int = 1
    ) -> object:
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
            timeout_seconds=timeout_seconds,
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

    def _non_git_snapshot(self, label: str = "tenth") -> dict[str, object]:
        return {
            "ok": True,
            "label": label,
            "is_git_repo": False,
            "evidence_complete": True,
            "evidence_errors": [],
            "_raw_evidence_complete": True,
            "_raw_evidence_errors": [],
        }

    def _absent_scope_pin(self) -> dict[str, object]:
        return {
            "path": str(
                self.workspace
                / ".claude-code-orchestrator"
                / "write-scope.json"
            ),
            "exists": False,
            "scope": None,
            "sha256": None,
        }

    def _force_cleanup_fake(self, process: FakeProcess) -> None:
        if process.poll() is None:
            process.terminate()
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            process.force_exit()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    def _launch_lock_key(self, path: Path) -> str:
        return os.path.normcase(str(path.resolve(strict=False)))

    def _launch_lock_owner(self, path: Path) -> dict[str, object]:
        owner_path = path / "owner.json" if path.is_dir() else path
        return json.loads(owner_path.read_text(encoding="utf-8"))

    def _cleanup_exact_launch_context(self, context: object) -> None:
        path = Path(str(context.path))
        key = self._launch_lock_key(path)
        with orchestrator._PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
            if (
                orchestrator._PROCESS_LAUNCH_LOCK_TOKENS.get(key)
                == context.token
            ):
                orchestrator._PROCESS_LAUNCH_LOCK_TOKENS.pop(key, None)
        try:
            owner = self._launch_lock_owner(path)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if (
            owner.get("token") == context.token
            and owner.get("generation") == context.generation
        ):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)

    def _install_fake_workers(
        self, run_ids: list[str], first_pid: int
    ) -> dict[str, FakeProcess]:
        workers = {
            run_id: self.FakeProcess(first_pid + index)
            for index, run_id in enumerate(run_ids)
        }
        with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
            orchestrator._ACTIVE_WORKER_HANDLES.update(workers)
        return workers

    def _remove_fake_workers(self, workers: dict[str, FakeProcess]) -> None:
        with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
            for run_id, worker in workers.items():
                if orchestrator._ACTIVE_WORKER_HANDLES.get(run_id) is worker:
                    orchestrator._ACTIVE_WORKER_HANDLES.pop(run_id, None)
        for worker in workers.values():
            self._force_cleanup_fake(worker)


class TenthReviewLaunchLockTests(TenthReviewFixture):
    def test_publication_failure_rolls_back_generation_token_and_reacquires(self) -> None:
        context = orchestrator.launch_lock(timeout_seconds=0.5, stale_seconds=0)
        lock_path = context.path
        key = self._launch_lock_key(lock_path)
        real_publish = orchestrator._publish_artifact_lock_candidate
        published = threading.Event()

        def publish_then_fail(candidate: Path, target: Path) -> None:
            real_publish(candidate, target)
            published.set()
            raise OSError("tenth failure after publication")

        reacquired = False
        try:
            with patch.object(
                orchestrator,
                "_publish_artifact_lock_candidate",
                side_effect=publish_then_fail,
            ):
                with self.assertRaises(orchestrator.OrchestratorError):
                    context.__enter__()
            self.assertTrue(published.is_set())
            generation_removed = not lock_path.exists()
            with orchestrator._PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                token_removed = key not in orchestrator._PROCESS_LAUNCH_LOCK_TOKENS
            with orchestrator.launch_lock(
                timeout_seconds=0.5, stale_seconds=0
            ):
                reacquired = True
            self.assertTrue(generation_removed)
            self.assertTrue(token_removed)
            self.assertTrue(reacquired)
        finally:
            self._cleanup_exact_launch_context(context)

    def test_publication_failure_preserves_same_name_successor_and_token(self) -> None:
        context = orchestrator.launch_lock(timeout_seconds=0.5, stale_seconds=0)
        lock_path = context.path
        key = self._launch_lock_key(lock_path)
        retired = lock_path.with_name(lock_path.name + ".tenth-original")
        successor_token = "tenth-successor-token"
        successor_generation = "tenth-successor-generation"
        real_publish = orchestrator._publish_artifact_lock_candidate
        successor_installed = threading.Event()

        def publish_swap_and_fail(candidate: Path, target: Path) -> None:
            real_publish(candidate, target)
            target.replace(retired)
            target.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "token": successor_token,
                        "generation": successor_generation,
                    }
                ),
                encoding="utf-8",
            )
            orchestrator._PROCESS_LAUNCH_LOCK_TOKENS[key] = successor_token
            successor_installed.set()
            raise OSError("tenth successor installed after publication")

        try:
            with patch.object(
                orchestrator,
                "_publish_artifact_lock_candidate",
                side_effect=publish_swap_and_fail,
            ):
                with self.assertRaises(orchestrator.OrchestratorError):
                    context.__enter__()
            self.assertTrue(successor_installed.is_set())
            self.assertEqual(
                self._launch_lock_owner(lock_path).get("token"), successor_token
            )
            self.assertEqual(
                self._launch_lock_owner(lock_path).get("generation"),
                successor_generation,
            )
            with orchestrator._PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                self.assertEqual(
                    orchestrator._PROCESS_LAUNCH_LOCK_TOKENS.get(key),
                    successor_token,
                )
        finally:
            self._cleanup_exact_launch_context(context)
            with orchestrator._PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                if (
                    orchestrator._PROCESS_LAUNCH_LOCK_TOKENS.get(key)
                    == successor_token
                ):
                    orchestrator._PROCESS_LAUNCH_LOCK_TOKENS.pop(key, None)
            lock_path.unlink(missing_ok=True)
            retired.unlink(missing_ok=True)

    def test_release_contention_keeps_the_original_deadline(self) -> None:
        context = orchestrator.launch_lock(timeout_seconds=1, stale_seconds=0)
        release_entered = threading.Event()
        unblock_fault = threading.Event()
        acquired = threading.Event()
        observed_deadlines: list[float | None] = []
        errors: list[BaseException] = []
        original_deadline: list[float] = []

        @contextlib.contextmanager
        def contended_generation(
            _path: Path, *, deadline: float | None = None
        ) -> object:
            observed_deadlines.append(deadline)
            release_entered.set()
            remaining = (
                None
                if deadline is None
                else max(0.0, deadline - time.monotonic())
            )
            if not unblock_fault.wait(remaining):
                raise OSError("tenth release lock deadline")
            raise OSError("tenth release lock unblocked")
            yield None

        def owner() -> None:
            deadline = time.monotonic() + 0.25
            original_deadline.append(deadline)
            token = orchestrator._OPERATION_DEADLINE.set(deadline)
            try:
                context.__enter__()
                acquired.set()
                with patch.object(
                    orchestrator,
                    "_locked_artifact_lock_generation",
                    side_effect=contended_generation,
                ):
                    context.__exit__(None, None, None)
            except BaseException as exc:
                errors.append(exc)
            finally:
                orchestrator._OPERATION_DEADLINE.reset(token)

        thread = threading.Thread(target=owner, name="tenth-release-contention")
        try:
            thread.start()
            self.assertTrue(acquired.wait(2))
            self.assertTrue(release_entered.wait(2))
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(observed_deadlines), 1)
            self.assertIsNotNone(observed_deadlines[0])
            assert observed_deadlines[0] is not None
            self.assertAlmostEqual(
                observed_deadlines[0], original_deadline[0], delta=0.02
            )
        finally:
            unblock_fault.set()
            thread.join(timeout=2)
            self._cleanup_exact_launch_context(context)


class TenthReviewCleanupOwnershipTests(TenthReviewFixture):
    def test_cleanup_pending_constructor_failure_runs_bounded_caller_cleanup(self) -> None:
        process = self.FakeProcess(510301)
        with orchestrator._ACTIVE_CLEANUP_OWNERS_LOCK:
            owners_before = set(orchestrator._ACTIVE_CLEANUP_OWNERS)
        failure: BaseException | None = None
        try:
            with patch.object(
                orchestrator.threading,
                "Thread",
                side_effect=RuntimeError("tenth cleanup constructor failure"),
            ):
                try:
                    orchestrator._cleanup_pending_response({}, process)
                except BaseException as exc:
                    failure = exc
            self.assertIsNone(failure)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.wait_timeouts)
            self.assertTrue(
                all(timeout is not None for timeout in process.wait_timeouts),
                process.wait_timeouts,
            )
            self.assertTrue(
                all(
                    stream.closed
                    for stream in (process.stdin, process.stdout, process.stderr)
                )
            )
            with orchestrator._ACTIVE_CLEANUP_OWNERS_LOCK:
                self.assertEqual(
                    set(orchestrator._ACTIVE_CLEANUP_OWNERS), owners_before
                )
        finally:
            self._force_cleanup_fake(process)

    def test_cleanup_pending_start_failure_runs_bounded_caller_cleanup(self) -> None:
        process = self.FakeProcess(510302)
        with orchestrator._ACTIVE_CLEANUP_OWNERS_LOCK:
            owners_before = set(orchestrator._ACTIVE_CLEANUP_OWNERS)
        try:
            with patch.object(
                orchestrator.threading,
                "Thread",
                side_effect=self.StartFailingThread,
            ):
                orchestrator._cleanup_pending_response({}, process)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.wait_timeouts)
            self.assertTrue(
                all(timeout is not None for timeout in process.wait_timeouts),
                process.wait_timeouts,
            )
            self.assertTrue(
                all(
                    stream.closed
                    for stream in (process.stdin, process.stdout, process.stderr)
                )
            )
            with orchestrator._ACTIVE_CLEANUP_OWNERS_LOCK:
                self.assertEqual(
                    set(orchestrator._ACTIVE_CLEANUP_OWNERS), owners_before
                )
        finally:
            self._force_cleanup_fake(process)

    def test_reaper_constructor_failure_runs_bounded_caller_cleanup(self) -> None:
        process = self.FakeProcess(510303)
        run_id = "tenth-reaper-constructor"
        failure: BaseException | None = None
        try:
            with patch.object(
                orchestrator.threading,
                "Thread",
                side_effect=RuntimeError("tenth reaper constructor failure"),
            ):
                try:
                    orchestrator._retain_worker_handle(run_id, process)
                except BaseException as exc:
                    failure = exc
            self.assertIsNone(failure)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.wait_timeouts)
            self.assertTrue(
                all(timeout is not None for timeout in process.wait_timeouts),
                process.wait_timeouts,
            )
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                self.assertIsNot(
                    orchestrator._ACTIVE_WORKER_HANDLES.get(run_id), process
                )
        finally:
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                if orchestrator._ACTIVE_WORKER_HANDLES.get(run_id) is process:
                    orchestrator._ACTIVE_WORKER_HANDLES.pop(run_id, None)
            self._force_cleanup_fake(process)

    def test_reaper_start_failure_runs_bounded_caller_cleanup(self) -> None:
        process = self.FakeProcess(510304)
        run_id = "tenth-reaper-start"
        failure: BaseException | None = None
        try:
            with patch.object(
                orchestrator.threading,
                "Thread",
                side_effect=self.StartFailingThread,
            ):
                try:
                    orchestrator._retain_worker_handle(run_id, process)
                except BaseException as exc:
                    failure = exc
            self.assertIsNone(failure)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.wait_timeouts)
            self.assertTrue(
                all(timeout is not None for timeout in process.wait_timeouts),
                process.wait_timeouts,
            )
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                self.assertIsNot(
                    orchestrator._ACTIVE_WORKER_HANDLES.get(run_id), process
                )
        finally:
            with orchestrator._ACTIVE_WORKER_HANDLES_LOCK:
                if orchestrator._ACTIVE_WORKER_HANDLES.get(run_id) is process:
                    orchestrator._ACTIVE_WORKER_HANDLES.pop(run_id, None)
            self._force_cleanup_fake(process)

    def test_nonexiting_descendant_is_contained_and_releases_inherited_pipes(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(3)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])
        child_code = "\n".join(
            [
                "import os, socket",
                f"sock = socket.create_connection(('127.0.0.1', {port}))",
                "sock.sendall((str(os.getpid()) + '\\n').encode('ascii'))",
                "sock.recv(1)",
            ]
        )
        self.fake_runtime.write_text(
            "\n".join(
                [
                    "import subprocess, sys, threading",
                    f"child_code = {child_code!r}",
                    "subprocess.Popen([sys.executable, '-c', child_code], stdout=sys.stdout, stderr=sys.stderr, close_fds=False)",
                    "sys.stdin.buffer.read()",
                    "threading.Event().wait()",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prepared = self._prepare_with_timeout(
            "one_shot", "tenth descendant containment", timeout_seconds=1
        )
        real_popen = orchestrator.subprocess.Popen
        processes: list[subprocess.Popen[bytes]] = []
        streams: list[tuple[object | None, object | None]] = []
        connection: socket.socket | None = None
        descendant_pid: int | None = None

        def capture_process(
            *args: object, **kwargs: object
        ) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            streams.append((process.stdout, process.stderr))
            return process

        try:
            started = time.monotonic()
            with patch.object(
                orchestrator,
                "capture_git_snapshot",
                side_effect=lambda *_args, **_kwargs: self._non_git_snapshot(),
            ), patch.object(
                orchestrator,
                "_pin_write_scope_policy",
                return_value=self._absent_scope_pin(),
            ), patch.object(
                orchestrator.subprocess, "Popen", side_effect=capture_process
            ):
                result = orchestrator.start_prepared_worker_launch(prepared)
            elapsed = time.monotonic() - started
            connection, _address = listener.accept()
            connection.settimeout(2)
            payload = b""
            while b"\n" not in payload:
                payload += connection.recv(64)
            descendant_pid = int(payload.splitlines()[0])
            self.assertEqual(len(processes), 1)
            self.assertLess(elapsed, 1.75, (elapsed, result))
            self.assertIsNotNone(processes[0].poll())
            self.assertFalse(
                orchestrator.pid_alive(descendant_pid),
                f"descendant {descendant_pid} escaped owned containment",
            )
            self.assertTrue(
                all(
                    stream is None or getattr(stream, "closed", False)
                    for pair in streams
                    for stream in pair
                ),
                streams,
            )
            self.assertFalse(
                any(
                    thread.is_alive()
                    and thread.name.startswith(
                        ("cc-cleanup-owner-", "cc-worker-reaper-")
                    )
                    for thread in threading.enumerate()
                )
            )
            self.assertTrue(result.get("timed_out"), result)
        finally:
            if connection is not None:
                try:
                    connection.sendall(b"x")
                    connection.shutdown(socket.SHUT_WR)
                    while connection.recv(256):
                        pass
                except OSError:
                    pass
                connection.close()
            listener.close()
            for process in reversed(processes):
                orchestrator._terminate_owned_process(
                    process, deadline=time.monotonic() + 2
                )


@unittest.skipUnless(os.name == "nt", "Windows tenth-cycle publication regression")
class TenthReviewWindowsPublicationTests(TenthReviewFixture):
    def test_initial_source_fstat_failure_deletes_retained_source_not_successor(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "tenth-state.json"
        real_create = orchestrator._create_windows_private_file
        real_fstat = orchestrator.os.fstat
        contexts: list[object] = []
        temporary: list[Path] = []
        retained: list[Path] = []
        attacked = threading.Event()

        class TrackingContext:
            def __init__(self, context: object, path: Path) -> None:
                self.context = context
                self.path = Path(path)
                self.handle: object | None = None
                self.exited = False

            def __enter__(self) -> object:
                self.handle = self.context.__enter__()
                temporary.append(self.path)
                return self.handle

            def __exit__(self, *args: object) -> object:
                self.exited = True
                return self.context.__exit__(*args)

        def tracking_create(path: Path, **kwargs: object) -> TrackingContext:
            context = TrackingContext(real_create(path, **kwargs), path)
            contexts.append(context)
            return context

        def fail_initial_source_fstat(fd: int) -> object:
            for raw_context in contexts:
                context = raw_context
                handle = getattr(context, "handle", None)
                if (
                    handle is not None
                    and handle.fileno() == fd
                    and not attacked.is_set()
                ):
                    source = Path(str(context.path))
                    moved = source.with_name(source.name + ".retained")
                    source.replace(moved)
                    source.write_text("tenth-successor", encoding="utf-8")
                    retained.append(moved)
                    attacked.set()
                    raise OSError("tenth initial source fstat failure")
            return real_fstat(fd)

        try:
            with patch.object(
                orchestrator,
                "_create_windows_private_file",
                side_effect=tracking_create,
            ), patch.object(
                orchestrator.os, "fstat", side_effect=fail_initial_source_fstat
            ):
                with self.assertRaises(OSError):
                    orchestrator._prepare_private_atomic_write(target, b"approved")
            self.assertTrue(attacked.is_set())
            self.assertTrue(temporary)
            successor_survived = temporary[0].exists()
            successor_content = (
                temporary[0].read_text(encoding="utf-8")
                if successor_survived
                else None
            )
            self.assertTrue(successor_survived)
            self.assertEqual(successor_content, "tenth-successor")
            self.assertTrue(retained)
            self.assertFalse(retained[0].exists())
            self.assertTrue(all(getattr(context, "exited") for context in contexts))
            self.assertTrue(
                all(
                    getattr(getattr(context, "handle", None), "closed", False)
                    for context in contexts
                )
            )
        finally:
            for context in contexts:
                if not getattr(context, "exited", False):
                    context.__exit__(None, None, None)
            for path in [*temporary, *retained]:
                path.unlink(missing_ok=True)


@unittest.skipUnless(
    _native_unprivileged_ubuntu_or_macos(),
    "requires native unprivileged Ubuntu or macOS",
)
class TenthReviewNativePublicationTests(TenthReviewFixture):
    def test_atomic_replacement_uses_named_source_without_at_empty_path(self) -> None:
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target = run_dir / "tenth-native-state.json"
        target.write_text('{"state":"before"}', encoding="utf-8")
        target.chmod(0o600)
        real_cdll = ctypes.CDLL
        libc = real_cdll(None, use_errno=True)
        flags_seen: list[int] = []

        class LibcProxy:
            def __getattr__(self, name: str) -> object:
                return getattr(libc, name)

            def linkat(self, *args: object) -> int:
                flags_seen.append(int(args[-1]))
                return int(libc.linkat(*args))

        failure: BaseException | None = None
        with patch.object(ctypes, "CDLL", return_value=LibcProxy()):
            try:
                orchestrator._atomic_write_text(target, '{"state":"after"}')
            except BaseException as exc:
                failure = exc
        self.assertIsNone(failure)
        self.assertEqual(target.read_text(encoding="utf-8"), '{"state":"after"}')
        self.assertTrue(flags_seen)
        self.assertTrue(all(flags == 0 for flags in flags_seen), flags_seen)
        leftovers = [
            path.name
            for path in run_dir.iterdir()
            if path.name != target.name
        ]
        self.assertEqual(leftovers, [])

    def test_launch_lock_publication_is_exclusive_and_cleans_named_sources(self) -> None:
        contexts = [
            orchestrator.launch_lock(timeout_seconds=2, stale_seconds=0)
            for _ in range(2)
        ]
        start = threading.Barrier(3)
        release_first = threading.Event()
        both_attempted = threading.Event()
        guard = threading.Lock()
        active = 0
        maximum = 0
        entries = 0
        publish_calls = 0
        errors: list[BaseException] = []
        real_publish = orchestrator._publish_artifact_lock_candidate

        def observed_publish(candidate: Path, target: Path) -> None:
            nonlocal publish_calls
            with guard:
                publish_calls += 1
                if publish_calls >= 2:
                    both_attempted.set()
            real_publish(candidate, target)

        def contender(context: object) -> None:
            nonlocal active, maximum, entries
            try:
                start.wait(timeout=2)
                with context:
                    with guard:
                        active += 1
                        maximum = max(maximum, active)
                        entries += 1
                        ordinal = entries
                    if ordinal == 1:
                        release_first.wait(2)
                    with guard:
                        active -= 1
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(
                target=contender,
                args=(context,),
                name=f"tenth-native-lock-{index}",
            )
            for index, context in enumerate(contexts)
        ]
        try:
            with patch.object(
                orchestrator,
                "_publish_artifact_lock_candidate",
                side_effect=observed_publish,
            ):
                for thread in threads:
                    thread.start()
                start.wait(timeout=2)
                self.assertTrue(both_attempted.wait(2))
                release_first.set()
                for thread in threads:
                    thread.join(timeout=3)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(entries, 2)
            self.assertEqual(maximum, 1)
            lock_path = self.runs_dir / ".launch.lock"
            self.assertFalse(lock_path.exists())
            self.assertEqual(
                list(self.runs_dir.glob(".launch.lock.*")), []
            )
            key = self._launch_lock_key(lock_path)
            with orchestrator._PROCESS_LAUNCH_LOCK_TOKENS_LOCK:
                self.assertNotIn(key, orchestrator._PROCESS_LAUNCH_LOCK_TOKENS)
        finally:
            release_first.set()
            for thread in threads:
                thread.join(timeout=2)
            for context in contexts:
                self._cleanup_exact_launch_context(context)


class TenthReviewFinalIdentityTests(TenthReviewFixture):
    def test_one_shot_replacement_after_scope_pin_never_reaches_runtime_popen(self) -> None:
        prepared = self._prepare_with_timeout(
            "one_shot", "tenth one-shot adjacent identity", timeout_seconds=2
        )
        real_pin = orchestrator._pin_write_scope_policy
        replaced = threading.Event()
        runtime_calls: list[tuple[object, ...]] = []

        def pin_then_replace(root: Path) -> object:
            pinned = real_pin(root)
            self.fake_runtime.write_text(
                "raise SystemExit('tenth replacement')\n", encoding="utf-8"
            )
            replaced.set()
            return pinned

        def reject_popen(*args: object, **_kwargs: object) -> object:
            runtime_calls.append(args)
            raise OSError("runtime Popen must remain unreachable")

        with patch.object(
            orchestrator,
            "capture_git_snapshot",
            side_effect=lambda *_args, **_kwargs: self._non_git_snapshot(),
        ), patch.object(
            orchestrator,
            "_pin_write_scope_policy",
            side_effect=pin_then_replace,
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=reject_popen
        ):
            result = orchestrator.start_prepared_worker_launch(prepared)

        self.assertTrue(replaced.is_set())
        self.assertEqual(runtime_calls, [])
        self.assertEqual(result.get("status"), "blocked_runtime_identity", result)

    def test_team_replacement_after_decision_wait_never_reaches_runtime_popen(self) -> None:
        prepared, run_dir, metadata, protocol, environment = (
            EighthReviewLifecycleTests._direct_stream_fixture(self)
        )
        team_id = "team-" + orchestrator.new_run_id()
        metadata = orchestrator.update_metadata(
            run_dir,
            team_id=team_id,
            team_manifest_path=str(self.artifact_root / "teams" / team_id / "decision.json"),
        )
        replaced = threading.Event()
        runtime_calls: list[tuple[object, ...]] = []

        def latest(*_args: object, **_kwargs: object) -> dict[str, object]:
            return orchestrator.read_metadata(run_dir)

        def decide_then_replace(
            *_args: object, **_kwargs: object
        ) -> dict[str, object]:
            self.fake_runtime.write_text(
                "raise SystemExit('tenth team replacement')\n", encoding="utf-8"
            )
            replaced.set()
            return orchestrator.read_metadata(run_dir)

        def reject_popen(*args: object, **_kwargs: object) -> object:
            runtime_calls.append(args)
            raise OSError("team runtime Popen must remain unreachable")

        with patch.dict(os.environ, environment, clear=True), patch.object(
            sys, "stdin", type("FixtureStdin", (), {"buffer": io.BytesIO(protocol)})()
        ), patch.object(
            orchestrator,
            "capture_git_snapshot",
            side_effect=lambda *_args, **_kwargs: self._non_git_snapshot(),
        ), patch.object(
            orchestrator,
            "_pin_write_scope_policy",
            return_value=self._absent_scope_pin(),
        ), patch.object(
            orchestrator, "_complete_team_worker_preflight", side_effect=latest
        ), patch.object(
            orchestrator, "_wait_for_team_authorization", side_effect=decide_then_replace
        ), patch.object(
            orchestrator.subprocess, "Popen", side_effect=reject_popen
        ):
            result = orchestrator.stream_worker(str(metadata["run_id"]))

        self.assertTrue(replaced.is_set())
        self.assertEqual(runtime_calls, [])
        self.assertEqual(result.get("status"), "blocked_runtime_identity", result)


class TenthReviewDeadlineChannelTests(TenthReviewFixture):
    def test_silent_open_peer_frame_read_stops_at_total_deadline(self) -> None:
        prepared = self._prepare_with_timeout(
            "streaming", "tenth silent frame peer", timeout_seconds=1
        )
        run_dir, metadata = orchestrator._initialize_prepared_run(prepared)
        deadline = time.monotonic() + 0.25
        orchestrator.update_metadata(
            run_dir, transaction_deadline_monotonic=deadline
        )
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, "rb", buffering=0)
        read_entered = threading.Event()
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        class ObservedReader:
            def read(self, size: int = -1) -> bytes:
                read_entered.set()
                return reader.read(size)

            def fileno(self) -> int:
                return reader.fileno()

            def close(self) -> None:
                reader.close()

        fixture_stdin = type(
            "TenthSilentStdin", (), {"buffer": ObservedReader()}
        )()

        def consume() -> None:
            try:
                results.append(orchestrator.stream_worker(str(metadata["run_id"])))
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=consume, name="tenth-silent-frame-reader")
        started = time.monotonic()
        try:
            with patch.object(sys, "stdin", fixture_stdin):
                thread.start()
                self.assertTrue(read_entered.wait(1))
                thread.join(timeout=1)
                elapsed = time.monotonic() - started
                self.assertFalse(thread.is_alive())
                self.assertLess(elapsed, 0.9, elapsed)
                self.assertEqual(errors, [])
                self.assertTrue(results)
                self.assertIn(
                    results[0].get("status"),
                    {"blocked_runtime_security", "blocked_runtime_launch"},
                    results[0],
                )
        finally:
            os.close(write_fd)
            thread.join(timeout=2)
            reader.close()

    def test_peer_that_never_reads_large_frame_write_stops_at_deadline(self) -> None:
        prepared = self._prepare_with_timeout(
            "streaming", "x" * (512 * 1024), timeout_seconds=1
        )
        real_popen = orchestrator.subprocess.Popen
        peers: list[subprocess.Popen[bytes]] = []
        peer_spawned = threading.Event()
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def silent_peer(*_args: object, **_kwargs: object) -> subprocess.Popen[bytes]:
            kwargs: dict[str, object] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if os.name == "posix":
                kwargs["start_new_session"] = True
            elif os.name == "nt":
                kwargs["creationflags"] = getattr(
                    subprocess, "CREATE_NO_WINDOW", 0
                )
            peer = real_popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import threading; threading.Event().wait()",
                ],
                **kwargs,
            )
            peers.append(peer)
            peer_spawned.set()
            return peer

        def launch() -> None:
            try:
                results.append(orchestrator.start_prepared_worker_launch(prepared))
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=launch, name="tenth-stalled-frame-writer")
        started = time.monotonic()
        try:
            with patch.object(
                orchestrator.subprocess, "Popen", side_effect=silent_peer
            ):
                thread.start()
                self.assertTrue(peer_spawned.wait(2))
                thread.join(timeout=1.75)
                elapsed = time.monotonic() - started
                self.assertFalse(thread.is_alive())
                self.assertLess(elapsed, 1.6, elapsed)
                self.assertEqual(errors, [])
                self.assertTrue(results)
                self.assertIn(
                    results[0].get("status"),
                    {
                        "blocked_runtime_launch",
                        "blocked_runtime_security",
                        "cleanup_incomplete",
                    },
                    results[0],
                )
        finally:
            for peer in peers:
                orchestrator._terminate_owned_process(
                    peer, deadline=time.monotonic() + 2
                )
            thread.join(timeout=2)


class TenthReviewTeamDecisionTests(TenthReviewFixture):
    def _team_identity(self, worker: TenthReviewFixture.FakeProcess, nonce: str) -> ProcessIdentity:
        return ProcessIdentity(
            pid=worker.pid,
            creation_token=f"creation-{worker.pid}",
            executable_path=str(Path(sys.executable).resolve()),
            parent_pid=os.getpid(),
            process_group_id=None,
            session_id=None,
            launch_nonce=nonce,
            supported=True,
        )

    def _team_member_metadata(
        self, team_id: str, run_id: str, identity: ProcessIdentity
    ) -> dict[str, object]:
        return {
            "run_id": run_id,
            "team_id": team_id,
            "status": "starting",
            "worker_pid": identity.pid,
            "worker_process_identity": identity.to_dict(),
            "runtime_launch": {"launch_nonce": identity.launch_nonce},
            "worker_launch": {
                "team_ready": True,
                "nonce_consumed": True,
                "team_preflight_complete": True,
                "scope_policy_identity": "tenth-scope",
            },
            "git_before": {"evidence_complete": True},
        }

    def _synthetic_team_patches(
        self, workers: dict[str, TenthReviewFixture.FakeProcess]
    ) -> tuple[object, object]:
        run_ids = iter(workers)

        def launch_member(*_args: object, **kwargs: object) -> dict[str, object]:
            run_id = next(run_ids)
            reservation = kwargs["_admission_reservation"]
            reservation.register(run_id)
            return {
                "run_id": run_id,
                "status": "starting",
                "profile": {"id": "tenth"},
            }

        def ready_members(
            _team_id: str,
            runs: list[dict[str, object]],
            *,
            deadline: float,
        ) -> list[dict[str, object]]:
            self.assertGreater(deadline, time.monotonic())
            return [
                {
                    **item,
                    "worker_pid": workers[str(item["run_id"])].pid,
                    "worker_creation_token": (
                        f"creation-{workers[str(item['run_id'])].pid}"
                    ),
                }
                for item in runs
            ]

        return launch_member, ready_members

    def test_member_death_during_sequential_precommit_cannot_authorize(self) -> None:
        team_id = "team-" + orchestrator.new_run_id()
        run_ids = [orchestrator.new_run_id(), orchestrator.new_run_id()]
        workers = self._install_fake_workers(run_ids, 510401)
        identities = {
            run_id: self._team_identity(workers[run_id], f"nonce-{index}")
            for index, run_id in enumerate(run_ids)
        }
        metadata = {
            run_id: self._team_member_metadata(team_id, run_id, identities[run_id])
            for run_id in run_ids
        }
        authorization = {
            "team_id": team_id,
            "status": "authorized",
            "runs": [
                {
                    "run_id": run_id,
                    "worker_pid": identities[run_id].pid,
                    "worker_creation_token": identities[run_id].creation_token,
                }
                for run_id in run_ids
            ],
        }
        first_validated = threading.Event()
        validation_order: list[str] = []

        def read_member(run_dir: Path, **_kwargs: object) -> dict[str, object]:
            return metadata[run_dir.name]

        def sequential_validation(
            member: dict[str, object], *, expected_nonce: str, **_kwargs: object
        ) -> ProcessIdentity:
            run_id = str(member["run_id"])
            validation_order.append(run_id)
            if run_id == run_ids[0]:
                first_validated.set()
            else:
                self.assertTrue(first_validated.is_set())
                workers[run_ids[0]].force_exit()
            self.assertEqual(expected_nonce, identities[run_id].launch_nonce)
            return identities[run_id]

        failure: BaseException | None = None
        path: Path | None = None
        try:
            with patch.object(
                orchestrator, "TEAMS_DIR", self.artifact_root / "teams"
            ), patch.object(
                orchestrator, "read_metadata", side_effect=read_member
            ), patch.object(
                orchestrator,
                "_validate_team_worker_identity",
                side_effect=sequential_validation,
            ):
                try:
                    path = orchestrator.write_team_manifest(team_id, authorization)
                except BaseException as exc:
                    failure = exc
            visible_authorization = False
            if path is not None and path.exists():
                visible_authorization = (
                    json.loads(path.read_text(encoding="utf-8")).get("status")
                    == "authorized"
                )
            self.assertEqual(validation_order, run_ids)
            self.assertTrue(first_validated.is_set())
            self.assertIsNotNone(workers[run_ids[0]].poll())
            self.assertTrue(
                failure is not None or not visible_authorization,
                "a member died during sequential validation but authorization became visible",
            )
        finally:
            self._remove_fake_workers(workers)

    def test_member_death_after_precommit_is_abort_or_postcommit_not_rollback(self) -> None:
        run_ids = [orchestrator.new_run_id(), orchestrator.new_run_id()]
        workers = self._install_fake_workers(run_ids, 510411)
        launch_member, ready_members = self._synthetic_team_patches(workers)
        team_dir = self.artifact_root / "teams"
        real_replace = orchestrator._replace_prepared_atomic_write
        precommit_complete = threading.Event()

        def fail_before_visibility(
            temporary_path: Path,
            path: Path,
            *,
            deadline: float | None = None,
            precommit: object | None = None,
        ) -> None:
            if precommit is not None and path.parent == team_dir:
                precommit()
                precommit_complete.set()
                workers[run_ids[0]].force_exit()
                raise OSError("tenth member death before decision visibility")
            real_replace(
                temporary_path,
                path,
                deadline=deadline,
                precommit=precommit,
            )

        try:
            with patch.object(
                orchestrator, "TEAMS_DIR", team_dir
            ), patch.object(
                orchestrator, "max_concurrent_limit", return_value=4
            ), patch.object(
                orchestrator, "run_status", return_value={"active_count": 0}
            ), patch.object(
                orchestrator, "run_streaming_agent", side_effect=launch_member
            ), patch.object(
                orchestrator, "_wait_for_team_members_ready", side_effect=ready_members
            ), patch.object(
                orchestrator, "_validate_team_authorization_manifest", return_value=None
            ), patch.object(
                orchestrator,
                "_reclaim_artifact_lock_for_dead_process",
                return_value=True,
            ), patch.object(
                orchestrator,
                "_replace_prepared_atomic_write",
                side_effect=fail_before_visibility,
            ):
                result = orchestrator.spawn_role_team(
                    "tenth precommit death",
                    roles=["testing", "review"],
                    cwd=self.workspace,
                    timeout_seconds=2,
                )
            self.assertTrue(precommit_complete.is_set())
            self.assertIn(
                result.get("status"),
                {"aborted", "committed_runtime_failed", "commit_indeterminate"},
                result,
            )
            self.assertNotIn(
                result.get("status"),
                {"rolled_back_partial_launch", "rollback_incomplete"},
            )
        finally:
            self._remove_fake_workers(workers)

    def test_postpublication_directory_fsync_failure_preserves_commit_decision(self) -> None:
        run_ids = [orchestrator.new_run_id(), orchestrator.new_run_id()]
        workers = self._install_fake_workers(run_ids, 510421)
        launch_member, ready_members = self._synthetic_team_patches(workers)
        team_dir = self.artifact_root / "teams"
        real_replace = orchestrator._replace_prepared_atomic_write
        decision_visible = threading.Event()

        def fail_after_visibility(
            temporary_path: Path,
            path: Path,
            *,
            deadline: float | None = None,
            precommit: object | None = None,
        ) -> None:
            real_replace(
                temporary_path,
                path,
                deadline=deadline,
                precommit=precommit,
            )
            if path.name == "decision.json" or (
                precommit is not None and path.parent == team_dir
            ):
                decision_visible.set()
                raise OSError("tenth directory fsync failed after visibility")

        try:
            with patch.object(
                orchestrator, "TEAMS_DIR", team_dir
            ), patch.object(
                orchestrator, "max_concurrent_limit", return_value=4
            ), patch.object(
                orchestrator, "run_status", return_value={"active_count": 0}
            ), patch.object(
                orchestrator, "run_streaming_agent", side_effect=launch_member
            ), patch.object(
                orchestrator, "_wait_for_team_members_ready", side_effect=ready_members
            ), patch.object(
                orchestrator, "_validate_team_authorization_manifest", return_value=None
            ), patch.object(
                orchestrator,
                "_reclaim_artifact_lock_for_dead_process",
                return_value=True,
            ), patch.object(
                orchestrator,
                "_replace_prepared_atomic_write",
                side_effect=fail_after_visibility,
            ):
                result = orchestrator.spawn_role_team(
                    "tenth postpublication fsync",
                    roles=["testing", "review"],
                    cwd=self.workspace,
                    timeout_seconds=2,
                )
            payloads = []
            for path in team_dir.rglob("*.json"):
                try:
                    payloads.append(json.loads(path.read_text(encoding="utf-8")))
                except json.JSONDecodeError:
                    continue
            committed = [
                payload
                for payload in payloads
                if str(
                    payload.get("decision")
                    or payload.get("state")
                    or payload.get("status")
                    or ""
                ).upper()
                in {"COMMIT", "COMMITTED", "AUTHORIZED"}
            ]
            aborted = [
                payload
                for payload in payloads
                if str(
                    payload.get("decision")
                    or payload.get("state")
                    or payload.get("status")
                    or ""
                ).upper()
                in {"ABORT", "ABORTED"}
            ]
            self.assertTrue(decision_visible.is_set())
            self.assertIn(
                result.get("status"),
                {"committed", "commit_indeterminate", "committed_runtime_failed"},
                result,
            )
            self.assertTrue(committed, payloads)
            self.assertEqual(aborted, [])
            self.assertNotIn(
                result.get("status"),
                {"rolled_back_partial_launch", "rollback_incomplete"},
            )
        finally:
            self._remove_fake_workers(workers)


class TenthReviewGitFixture(TenthReviewFixture):
    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return SeventhReviewGitAndDeadlineTests._git(self, *args)

    def _initialize_git_scope(self, max_diff_lines: int = 1) -> Path:
        return SeventhReviewGitAndDeadlineTests._initialize_git_scope(
            self, max_diff_lines=max_diff_lines
        )


class TenthReviewGitMultiplicityTests(TenthReviewGitFixture):
    def test_duplicate_predirty_lines_survive_layer_movement_as_counter_evidence(self) -> None:
        target = self._initialize_git_scope(max_diff_lines=1)
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        target.write_text("base\nduplicate\n", encoding="utf-8")
        self._git("add", target.name)
        target.write_text("base\nduplicate\nduplicate\n", encoding="utf-8")
        before = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "tenth-before-layer-move"
        )
        self._git("add", target.name)
        target.write_text(
            "base\nduplicate\nduplicate\nreal-edit\n", encoding="utf-8"
        )
        after = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "tenth-after-layer-move"
        )
        result = orchestrator._check_write_scope_with_evidence(
            run_dir.name,
            self.workspace,
            before,
            after,
            orchestrator._pin_write_scope_policy(self.workspace),
        )
        self.assertEqual(result["diff_lines"], 1, result)
        self.assertNotIn(
            "max_diff_lines",
            {item["type"] for item in result["violations"]},
        )


@unittest.skipUnless(os.name == "posix", "POSIX surrogate-escape path regression")
class TenthReviewPosixPathEncodingTests(TenthReviewGitFixture):
    def test_non_utf8_unicode_and_backslash_names_recover_distinct_exact_bytes(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is unavailable")
        self._git("init")
        self._git("config", "user.name", "Task Ten POSIX Fixture")
        self._git("config", "user.email", "task-ten@example.invalid")
        raw_names = [
            b"invalid-\xff.txt",
            b"invalid-\xfe.txt",
            "unicode-\u96ea.txt".encode("utf-8"),
            b"literal\\backslash.txt",
        ]
        root_bytes = os.fsencode(str(self.workspace))
        for raw_name in raw_names:
            fd = os.open(
                os.path.join(root_bytes, raw_name),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, b"base\n")
            finally:
                os.close(fd)
        self._git("add", "-A")
        self._git("commit", "-m", "tenth path base")
        for raw_name in raw_names:
            fd = os.open(
                os.path.join(root_bytes, raw_name), os.O_WRONLY | os.O_APPEND
            )
            try:
                os.write(fd, b"edit\n")
            finally:
                os.close(fd)
        run_dir = self.runs_dir / orchestrator.new_run_id()
        orchestrator._set_private_directory(run_dir)
        snapshot = orchestrator.capture_git_snapshot(
            run_dir, self.workspace, "tenth-posix-paths"
        )
        actual = list(snapshot.get("_raw_changed_paths") or [])
        expected = [os.fsdecode(raw_name) for raw_name in raw_names]
        self.assertTrue(snapshot.get("evidence_complete"), snapshot)
        self.assertEqual(len(actual), len(raw_names), actual)
        self.assertEqual(set(actual), set(expected))
        self.assertEqual({os.fsencode(path) for path in actual}, set(raw_names))


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
