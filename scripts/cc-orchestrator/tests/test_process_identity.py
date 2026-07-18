from __future__ import annotations

import errno
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: F401
import process_identity
from process_identity import (
    ProcessIdentity,
    capture_process_identity,
    compare_process_identity,
    process_identity_support,
)


def supported_identity(**changes: object) -> ProcessIdentity:
    values = {
        "pid": 4321,
        "creation_token": "boot:123",
        "executable_path": str(Path(sys.executable).resolve()),
        "parent_pid": 1234,
        "process_group_id": 4321,
        "session_id": 1234,
        "launch_nonce": "nonce-fixture",
        "supported": True,
        "unsupported_reason": None,
    }
    values.update(changes)
    return ProcessIdentity(**values)


class ProcessIdentityContractTests(unittest.TestCase):
    def test_identity_is_frozen_and_strictly_round_trips(self) -> None:
        identity = supported_identity()

        self.assertEqual(ProcessIdentity.from_dict(identity.to_dict()), identity)
        with self.assertRaises(FrozenInstanceError):
            identity.pid = 99  # type: ignore[misc]

    def test_from_dict_rejects_invalid_shapes_and_scalar_types(self) -> None:
        valid = supported_identity().to_dict()
        invalid = (
            {key: value for key, value in valid.items() if key != "session_id"},
            {**valid, "extra": "value"},
            {**valid, "pid": True},
            {**valid, "pid": 0},
            {**valid, "creation_token": ""},
            {**valid, "executable_path": 3},
            {**valid, "parent_pid": True},
            {**valid, "parent_pid": 0},
            {**valid, "process_group_id": -1},
            {**valid, "session_id": -1},
            {**valid, "launch_nonce": ""},
            {**valid, "supported": 1},
            {**valid, "unsupported_reason": "unexpected"},
        )

        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(
                (TypeError, ValueError)
            ):
                ProcessIdentity.from_dict(payload)

    def test_from_dict_rejects_inconsistent_unsupported_records(self) -> None:
        unsupported = supported_identity(
            creation_token=None,
            executable_path=None,
            parent_pid=None,
            process_group_id=None,
            session_id=None,
            supported=False,
            unsupported_reason="access denied",
        ).to_dict()

        self.assertFalse(ProcessIdentity.from_dict(unsupported).supported)
        invalid = (
            {**unsupported, "unsupported_reason": None},
            {**unsupported, "unsupported_reason": ""},
            {**unsupported, "supported": True},
            {
                **unsupported,
                "creation_token": "boot:123",
                "executable_path": "/bin/python",
            },
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(
                (TypeError, ValueError)
            ):
                ProcessIdentity.from_dict(payload)

    def test_capture_rejects_invalid_pid_and_nonce(self) -> None:
        for pid in (True, 0, -1, "1"):
            with self.subTest(pid=pid), self.assertRaises((TypeError, ValueError)):
                capture_process_identity(pid, launch_nonce="nonce")  # type: ignore[arg-type]
        for nonce in (None, "", 1):
            with self.subTest(nonce=nonce), self.assertRaises((TypeError, ValueError)):
                capture_process_identity(1, launch_nonce=nonce)  # type: ignore[arg-type]


class ProcessIdentityComparisonTests(unittest.TestCase):
    def test_exact_minimum_tuple_matches_with_missing_optional_live_fields(self) -> None:
        expected = supported_identity()
        live = supported_identity(
            parent_pid=None,
            process_group_id=None,
            session_id=None,
            launch_nonce="live-reader-nonce",
        )

        with patch.object(process_identity, "capture_process_identity", return_value=live):
            check = compare_process_identity(expected)

        self.assertEqual(check.state, "match")
        self.assertEqual(check.differing_fields, ())
        self.assertEqual(check.live, live)

    def test_stable_and_available_optional_mismatches_are_sorted(self) -> None:
        expected = supported_identity()
        live = supported_identity(
            creation_token="other-token",
            executable_path=str(Path(sys.executable).resolve()) + ".other",
            parent_pid=5,
            process_group_id=6,
            session_id=7,
            launch_nonce="reader-nonce",
        )

        with patch.object(process_identity, "capture_process_identity", return_value=live):
            check = compare_process_identity(expected)

        self.assertEqual(check.state, "mismatch")
        self.assertEqual(
            check.differing_fields,
            (
                "creation_token",
                "executable_path",
                "parent_pid",
                "process_group_id",
                "session_id",
            ),
        )
        self.assertEqual(check.live, live)

    def test_controller_nonce_mismatch_short_circuits_without_live_capture(self) -> None:
        expected = supported_identity()

        with patch.object(process_identity, "capture_process_identity") as capture:
            check = compare_process_identity(
                expected,
                expected_launch_nonce="different-controller-nonce",
            )

        self.assertEqual(check.state, "mismatch")
        self.assertEqual(check.differing_fields, ("launch_nonce",))
        self.assertIsNone(check.live)
        capture.assert_not_called()

    def test_missing_or_failed_minimum_evidence_is_unverified(self) -> None:
        missing_expected = supported_identity(
            creation_token=None,
            supported=False,
            unsupported_reason="creation token unavailable",
        )
        self.assertEqual(compare_process_identity(missing_expected).state, "unverified")

        expected = supported_identity()
        live = supported_identity(
            creation_token=None,
            executable_path=None,
            supported=False,
            unsupported_reason="access denied",
        )
        with patch.object(process_identity, "capture_process_identity", return_value=live):
            check = compare_process_identity(expected)
        self.assertEqual(check.state, "unverified")
        self.assertEqual(check.differing_fields, ())
        self.assertEqual(check.live, live)

    def test_confirmed_absence_is_exited(self) -> None:
        expected = supported_identity()
        live = supported_identity(
            creation_token=None,
            executable_path=None,
            parent_pid=None,
            process_group_id=None,
            session_id=None,
            supported=False,
            unsupported_reason="process exited",
        )
        with patch.object(process_identity, "capture_process_identity", return_value=live):
            check = compare_process_identity(expected)
        self.assertEqual(check.state, "exited")
        self.assertEqual(check.live, live)

    def test_windows_and_linux_path_display_variants_compare_equal(self) -> None:
        windows_expected = supported_identity(executable_path=r"C:\Python\PYTHON.EXE")
        windows_live = supported_identity(executable_path=r"\\?\c:\python\python.exe")
        linux_expected = supported_identity(executable_path="/tmp/python")
        linux_live = supported_identity(executable_path="/tmp/python (deleted)")

        with patch.object(process_identity, "_is_windows", return_value=True), patch.object(
            process_identity, "capture_process_identity", return_value=windows_live
        ):
            self.assertEqual(compare_process_identity(windows_expected).state, "match")
        with patch.object(process_identity, "_is_windows", return_value=False), patch.object(
            process_identity, "capture_process_identity", return_value=linux_live
        ):
            self.assertEqual(compare_process_identity(linux_expected).state, "match")


class LinuxProcessReaderTests(unittest.TestCase):
    def test_parser_handles_spaces_and_closing_parentheses_in_command(self) -> None:
        tail = ["S", "7", "8", "9", *(["0"] * 15), "12345"]
        stat = f"321 (worker name ) with spaces) {' '.join(tail)}"

        parsed = process_identity._parse_linux_stat(stat, expected_pid=321)

        self.assertEqual(parsed, (7, 8, 9, "12345"))

    def test_linux_reader_captures_boot_scoped_start_and_proc_fields(self) -> None:
        tail = ["S", "7", "8", "9", *(["0"] * 15), "12345"]
        stat = f"321 (worker name) {' '.join(tail)}"

        def read_text(path: Path, **_: object) -> str:
            return stat if str(path).endswith("stat") else "boot-id-fixture\n"

        with patch.object(Path, "read_text", autospec=True, side_effect=read_text), patch.object(
            os, "readlink", return_value="/usr/bin/python3"
        ):
            identity = process_identity._capture_linux(321, launch_nonce="nonce")

        self.assertEqual(identity.creation_token, "boot-id-fixture:12345")
        self.assertEqual(identity.executable_path, "/usr/bin/python3")
        self.assertEqual(identity.parent_pid, 7)
        self.assertEqual(identity.process_group_id, 8)
        self.assertEqual(identity.session_id, 9)
        self.assertTrue(identity.supported)

    def test_linux_reader_distinguishes_exit_permission_and_malformed_proc(self) -> None:
        cases = (
            (FileNotFoundError(), "process exited"),
            (PermissionError(), "access denied"),
            ("bad stat", "process information malformed"),
        )
        for result, reason in cases:
            side_effect = result if isinstance(result, BaseException) else None
            return_value = result if isinstance(result, str) else None
            with self.subTest(reason=reason), patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=side_effect,
                return_value=return_value,
            ):
                identity = process_identity._capture_linux(321, launch_nonce="nonce")
            self.assertFalse(identity.supported)
            self.assertEqual(identity.unsupported_reason, reason)


class FakeWindowsApi:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.open_error: BaseException | None = None
        self.query_error: BaseException | None = None

    def open_process(self, pid: int) -> int:
        if self.open_error:
            raise self.open_error
        return 91

    def creation_filetime(self, handle: int) -> tuple[int, int]:
        if self.query_error:
            raise self.query_error
        return (0x12345678, 0x9ABCDEF0)

    def executable_path(self, handle: int) -> str:
        return r"\\?\C:\Python\python.exe"

    def parent_pid(self, pid: int) -> int:
        return 41

    def session_id(self, pid: int) -> int:
        return 3

    def close_handle(self, handle: int) -> None:
        self.closed.append(handle)


class WindowsProcessReaderTests(unittest.TestCase):
    def test_windows_reader_uses_full_filetime_and_closes_process_handle(self) -> None:
        api = FakeWindowsApi()

        identity = process_identity._capture_windows(42, launch_nonce="nonce", api=api)

        self.assertEqual(
            identity.creation_token,
            str((0x12345678 << 32) | 0x9ABCDEF0),
        )
        self.assertEqual(identity.executable_path, r"C:\Python\python.exe")
        self.assertEqual(identity.parent_pid, 41)
        self.assertIsNone(identity.process_group_id)
        self.assertEqual(identity.session_id, 3)
        self.assertTrue(identity.supported)
        self.assertEqual(api.closed, [91])

    def test_windows_reader_closes_handle_on_query_failure_and_classifies_errors(self) -> None:
        api = FakeWindowsApi()
        api.query_error = PermissionError(errno.EACCES, "denied")
        identity = process_identity._capture_windows(42, launch_nonce="nonce", api=api)
        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "access denied")
        self.assertEqual(api.closed, [91])

        api = FakeWindowsApi()
        api.open_error = ProcessLookupError(87, "gone")
        identity = process_identity._capture_windows(42, launch_nonce="nonce", api=api)
        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process exited")
        self.assertEqual(api.closed, [])

    def test_windows_reader_fails_closed_when_native_api_is_unavailable(self) -> None:
        with patch.object(
            process_identity,
            "_WindowsApi",
            side_effect=OSError(errno.ENOSYS, "unavailable"),
        ):
            identity = process_identity._capture_windows(42, launch_nonce="nonce")

        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process query failed")


class FakeMacApi:
    def __init__(self) -> None:
        self.error: BaseException | None = None

    def executable_path(self, pid: int) -> str:
        if self.error:
            raise self.error
        return "/usr/bin/python3"

    def bsd_info(self, pid: int) -> object:
        if self.error:
            raise self.error
        return SimpleNamespace(
            start_sec=1_725_000_001,
            start_usec=234_567,
            parent_pid=41,
            process_group_id=42,
        )


class MacProcessReaderTests(unittest.TestCase):
    def test_macos_reader_captures_high_resolution_native_bsd_info(self) -> None:
        identity = process_identity._capture_macos(
            42, launch_nonce="nonce", api=FakeMacApi()
        )

        self.assertEqual(identity.creation_token, "1725000001:234567")
        self.assertEqual(identity.executable_path, "/usr/bin/python3")
        self.assertEqual(identity.parent_pid, 41)
        self.assertEqual(identity.process_group_id, 42)
        self.assertIsNone(identity.session_id)
        self.assertTrue(identity.supported)

    def test_macos_reader_distinguishes_native_exit_permission_and_api_failure(self) -> None:
        cases = (
            (ProcessLookupError(errno.ESRCH, "gone"), "process exited"),
            (PermissionError(errno.EPERM, "denied"), "access denied"),
            (OSError(errno.EIO, "failure"), "process query failed"),
        )
        for error, reason in cases:
            api = FakeMacApi()
            api.error = error
            with self.subTest(reason=reason):
                identity = process_identity._capture_macos(
                    42, launch_nonce="nonce", api=api
                )
            self.assertFalse(identity.supported)
            self.assertEqual(identity.unsupported_reason, reason)

    def test_macos_reader_fails_closed_when_native_api_is_unavailable(self) -> None:
        with patch.object(
            process_identity,
            "_MacApi",
            side_effect=OSError(errno.ENOSYS, "unavailable"),
        ):
            identity = process_identity._capture_macos(42, launch_nonce="nonce")

        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process query failed")


class LiveProcessIdentityTests(unittest.TestCase):
    def test_current_platform_live_capture_match_mismatch_and_exit(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            shell=False,
        )
        try:
            identity = capture_process_identity(child.pid, launch_nonce="live-nonce")
            self.assertTrue(identity.supported, identity.unsupported_reason)
            self.assertEqual(identity.pid, child.pid)
            self.assertTrue(identity.creation_token)
            self.assertTrue(identity.executable_path)
            self.assertEqual(
                os.path.normcase(str(Path(identity.executable_path).resolve())),
                os.path.normcase(str(Path(sys.executable).resolve())),
            )
            self.assertEqual(compare_process_identity(identity).state, "match")
            self.assertEqual(
                compare_process_identity(
                    replace(identity, creation_token=identity.creation_token + "-changed")
                ).differing_fields,
                ("creation_token",),
            )
            self.assertEqual(
                compare_process_identity(
                    replace(identity, executable_path=identity.executable_path + ".changed")
                ).differing_fields,
                ("executable_path",),
            )
            if identity.parent_pid is not None:
                self.assertEqual(
                    compare_process_identity(
                        replace(identity, parent_pid=identity.parent_pid + 1)
                    ).differing_fields,
                    ("parent_pid",),
                )

            child.terminate()
            child.wait(timeout=10)
            self.assertEqual(compare_process_identity(identity).state, "exited")
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)

    def test_support_summary_is_safe_and_reports_pidfd_without_signaling(self) -> None:
        summary = process_identity_support()

        self.assertEqual(summary["platform"], sys.platform)
        self.assertIs(type(summary["supported"]), bool)
        self.assertIn("pidfd_available", summary)
        self.assertIs(type(summary["pidfd_available"]), bool)
        self.assertNotIn("signal", summary)


if __name__ == "__main__":
    unittest.main()
