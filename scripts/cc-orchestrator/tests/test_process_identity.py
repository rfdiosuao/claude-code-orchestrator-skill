from __future__ import annotations

import ctypes
import errno
import os
import struct
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

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


def _patch_ctypes_last_error(value: int) -> object:
    return patch.object(
        ctypes,
        "get_last_error",
        return_value=value,
        create=True,
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

    def test_direct_construction_rejects_every_unserializable_state(self) -> None:
        valid = supported_identity().to_dict()
        invalid = (
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
            {
                **valid,
                "supported": False,
                "unsupported_reason": "query failed",
            },
        )

        for values in invalid:
            with self.subTest(values=values), self.assertRaises(
                (TypeError, ValueError)
            ):
                ProcessIdentity(**values)


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

    def test_live_pid_mismatch_is_reported_deterministically(self) -> None:
        expected = supported_identity(pid=4321)
        live = supported_identity(pid=9999)

        with patch.object(process_identity, "capture_process_identity", return_value=live):
            check = compare_process_identity(expected)

        self.assertEqual(check.state, "mismatch")
        self.assertEqual(check.differing_fields, ("pid",))
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

    def test_path_display_normalization_is_platform_specific(self) -> None:
        windows_expected = supported_identity(executable_path=r"C:\Python\PYTHON.EXE")
        windows_live = supported_identity(executable_path=r"\\?\c:\python\python.exe")
        linux_expected = supported_identity(executable_path="/tmp/python")
        linux_live = supported_identity(executable_path="/tmp/python (deleted)")

        with patch.object(process_identity.sys, "platform", "win32"), patch.object(
            process_identity, "capture_process_identity", return_value=windows_live
        ):
            self.assertEqual(compare_process_identity(windows_expected).state, "match")
        with patch.object(process_identity.sys, "platform", "linux"), patch.object(
            process_identity, "capture_process_identity", return_value=linux_live
        ):
            self.assertEqual(compare_process_identity(linux_expected).state, "match")
        with patch.object(process_identity.sys, "platform", "darwin"), patch.object(
            process_identity, "capture_process_identity", return_value=linux_live
        ):
            check = compare_process_identity(linux_expected)
            self.assertEqual(check.state, "mismatch")
            self.assertEqual(check.differing_fields, ("executable_path",))


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
        decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")
        cases = (
            (FileNotFoundError(), "process exited"),
            (PermissionError(), "access denied"),
            ("bad stat", "process information malformed"),
            (decode_error, "process information malformed"),
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

    def test_linux_reader_rejects_torn_pid_reuse_evidence(self) -> None:
        def stat(start: str, parent: str = "7") -> str:
            tail = ["S", parent, "8", "9", *(["0"] * 15), start]
            return f"321 (worker) {' '.join(tail)}"

        stat_values = iter((stat("12345"), stat("99999")))

        def read_text(path: Path, **_: object) -> str:
            if str(path).endswith("stat"):
                return next(stat_values)
            return "boot-id-fixture\n"

        with patch.object(Path, "read_text", autospec=True, side_effect=read_text), patch.object(
            os, "readlink", return_value="/usr/bin/python3"
        ):
            identity = process_identity._capture_linux(321, launch_nonce="nonce")

        self.assertFalse(identity.supported)
        self.assertEqual(
            identity.unsupported_reason, "process identity changed during capture"
        )

    def test_linux_second_stat_disappearance_is_exited(self) -> None:
        tail = ["S", "7", "8", "9", *(["0"] * 15), "12345"]
        first_stat = f"321 (worker) {' '.join(tail)}"
        stat_results = iter((first_stat, FileNotFoundError()))

        def read_text(path: Path, **_: object) -> str:
            if not str(path).endswith("stat"):
                return "boot-id-fixture\n"
            result = next(stat_results)
            if isinstance(result, BaseException):
                raise result
            return result

        with patch.object(Path, "read_text", autospec=True, side_effect=read_text), patch.object(
            os, "readlink", return_value="/usr/bin/python3"
        ):
            identity = process_identity._capture_linux(321, launch_nonce="nonce")

        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process exited")


class FakeWindowsApi:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.open_error: BaseException | None = None
        self.query_error: BaseException | None = None
        self.wait_effects: list[BaseException | None] = [None, None]
        self.queries: list[str] = []

    def open_process(self, pid: int) -> int:
        if self.open_error:
            raise self.open_error
        return 91

    def creation_filetime(self, handle: int) -> tuple[int, int]:
        self.queries.append("creation_filetime")
        if self.query_error:
            raise self.query_error
        return (0x12345678, 0x9ABCDEF0)

    def executable_path(self, handle: int) -> str:
        self.queries.append("executable_path")
        return r"\\?\C:\Python\python.exe"

    def parent_pid(self, pid: int) -> int:
        self.queries.append("parent_pid")
        return 41

    def session_id(self, pid: int) -> int:
        self.queries.append("session_id")
        return 3

    def close_handle(self, handle: int) -> None:
        self.closed.append(handle)

    def assert_running(self, handle: int) -> None:
        effect = self.wait_effects.pop(0)
        if effect is not None:
            raise effect


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

    def test_windows_reader_rechecks_same_handle_after_successful_queries(self) -> None:
        api = FakeWindowsApi()
        api.wait_effects = [None, ProcessLookupError(errno.ESRCH, "signaled")]

        identity = process_identity._capture_windows(42, launch_nonce="nonce", api=api)

        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process exited")
        self.assertEqual(
            api.queries,
            ["creation_filetime", "executable_path", "parent_pid", "session_id"],
        )
        self.assertEqual(api.closed, [91])

    def test_windows_wait_failure_is_unverified_before_or_after_queries(self) -> None:
        for effects, expected_queries in (
            ([OSError(errno.EIO, "wait failed")], []),
            ([None, OSError(errno.EIO, "wait failed")], [
                "creation_filetime",
                "executable_path",
                "parent_pid",
                "session_id",
            ]),
        ):
            api = FakeWindowsApi()
            api.wait_effects = effects
            with self.subTest(effects=len(effects)):
                identity = process_identity._capture_windows(
                    42, launch_nonce="nonce", api=api
                )
            self.assertFalse(identity.supported)
            self.assertEqual(identity.unsupported_reason, "process query failed")
            self.assertEqual(api.queries, expected_queries)
            self.assertEqual(api.closed, [91])


class WindowsNativeApiBoundaryTests(unittest.TestCase):
    @staticmethod
    def api_with_kernel(**functions: object) -> process_identity._WindowsApi:
        api = process_identity._WindowsApi.__new__(process_identity._WindowsApi)
        api._kernel32 = SimpleNamespace(**functions)
        from ctypes import wintypes

        api._wintypes = wintypes
        return api

    def test_kernel32_get_process_times_populates_full_filetime(self) -> None:
        def get_process_times(
            _handle: int,
            creation: object,
            _exit: object,
            _kernel: object,
            _user: object,
        ) -> int:
            value = ctypes.cast(
                creation, ctypes.POINTER(process_identity._FILETIME)
            ).contents
            value.dwHighDateTime = 0x12345678
            value.dwLowDateTime = 0x9ABCDEF0
            return 1

        api = self.api_with_kernel(GetProcessTimes=Mock(side_effect=get_process_times))

        self.assertEqual(
            api.creation_filetime(91), (0x12345678, 0x9ABCDEF0)
        )

    def test_kernel32_snapshot_is_closed_on_success_and_error(self) -> None:
        def process_first(_snapshot: int, entry_pointer: object) -> int:
            entry = ctypes.cast(
                entry_pointer, ctypes.POINTER(process_identity._PROCESSENTRY32W)
            ).contents
            entry.th32ProcessID = 42
            entry.th32ParentProcessID = 41
            return 1

        close = Mock(return_value=1)
        api = self.api_with_kernel(
            CreateToolhelp32Snapshot=Mock(return_value=77),
            Process32FirstW=Mock(side_effect=process_first),
            Process32NextW=Mock(return_value=0),
            CloseHandle=close,
        )
        self.assertEqual(api.parent_pid(42), 41)
        close.assert_called_once_with(77)

        close.reset_mock()
        api._kernel32.Process32FirstW = Mock(return_value=0)
        with _patch_ctypes_last_error(5), self.assertRaises(PermissionError):
            api.parent_pid(42)
        close.assert_called_once_with(77)

    def test_kernel32_wait_distinguishes_running_signaled_and_failed(self) -> None:
        wait = Mock(return_value=process_identity._WindowsApi.WAIT_TIMEOUT)
        api = self.api_with_kernel(WaitForSingleObject=wait)
        api.assert_running(91)

        wait.return_value = process_identity._WindowsApi.WAIT_OBJECT_0
        with self.assertRaises(ProcessLookupError):
            api.assert_running(91)

        wait.return_value = process_identity._WindowsApi.WAIT_FAILED
        with _patch_ctypes_last_error(31), self.assertRaises(OSError):
            api.assert_running(91)
        self.assertEqual(wait.call_args_list, [call(91, 0), call(91, 0), call(91, 0)])

    def test_last_error_patch_works_when_ctypes_attribute_is_absent(self) -> None:
        original = getattr(ctypes, "get_last_error", None)
        had_attribute = hasattr(ctypes, "get_last_error")
        if had_attribute:
            delattr(ctypes, "get_last_error")
        try:
            with _patch_ctypes_last_error(31):
                self.assertEqual(ctypes.get_last_error(), 31)
            self.assertFalse(hasattr(ctypes, "get_last_error"))
        finally:
            if had_attribute:
                ctypes.get_last_error = original


class FakeMacApi:
    def __init__(self) -> None:
        self.error: BaseException | None = None
        self.info_values: list[object] = []

    def executable_path(self, pid: int) -> str:
        if self.error:
            raise self.error
        return "/usr/bin/python3"

    def bsd_info(self, pid: int) -> object:
        if self.error:
            raise self.error
        value = SimpleNamespace(
            pid=42,
            start_sec=1_725_000_001,
            start_usec=234_567,
            parent_pid=41,
            process_group_id=42,
        )
        return self.info_values.pop(0) if self.info_values else value


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

    def test_macos_reader_rejects_torn_pid_reuse_evidence(self) -> None:
        api = FakeMacApi()
        first = api.bsd_info(42)
        api.info_values = [first, SimpleNamespace(**{**vars(first), "start_usec": 9})]

        identity = process_identity._capture_macos(42, launch_nonce="nonce", api=api)

        self.assertFalse(identity.supported)
        self.assertEqual(
            identity.unsupported_reason, "process identity changed during capture"
        )

    def test_macos_second_native_read_disappearance_is_exited(self) -> None:
        class DisappearingMacApi(FakeMacApi):
            def __init__(self) -> None:
                super().__init__()
                self.read_count = 0

            def bsd_info(self, pid: int) -> object:
                self.read_count += 1
                if self.read_count == 2:
                    raise ProcessLookupError(errno.ESRCH, "gone")
                return super().bsd_info(pid)

        identity = process_identity._capture_macos(
            42, launch_nonce="nonce", api=DisappearingMacApi()
        )

        self.assertFalse(identity.supported)
        self.assertEqual(identity.unsupported_reason, "process exited")


class MacNativeApiBoundaryTests(unittest.TestCase):
    @staticmethod
    def api_with_libproc(**functions: object) -> process_identity._MacApi:
        api = process_identity._MacApi.__new__(process_identity._MacApi)
        api._libproc = SimpleNamespace(**functions)
        return api

    def test_libproc_populates_path_and_complete_bsd_info(self) -> None:
        self.assertEqual(ctypes.sizeof(process_identity._PROC_BSDINFO), 136)
        self.assertEqual(process_identity._PROC_BSDINFO.pbi_pid.offset, 12)
        self.assertEqual(process_identity._PROC_BSDINFO.pbi_ppid.offset, 16)
        self.assertEqual(process_identity._PROC_BSDINFO.pbi_pgid.offset, 100)
        self.assertEqual(process_identity._PROC_BSDINFO.pbi_start_tvsec.offset, 120)
        self.assertEqual(process_identity._PROC_BSDINFO.pbi_start_tvusec.offset, 128)
        path_bytes = b"/usr/bin/python3"

        def proc_pidpath(_pid: int, buffer: object, _size: int) -> int:
            ctypes.memmove(buffer, path_bytes, len(path_bytes))
            return len(path_bytes)

        def proc_pidinfo(
            _pid: int,
            _flavor: int,
            _arg: int,
            info_pointer: object,
            size: int,
        ) -> int:
            self.assertEqual(size, 136)
            address = ctypes.cast(info_pointer, ctypes.c_void_p).value
            self.assertIsNotNone(address)
            raw = (ctypes.c_ubyte * 136).from_address(address)
            struct.pack_into("<I", raw, 12, 42)
            struct.pack_into("<I", raw, 16, 41)
            struct.pack_into("<I", raw, 100, 40)
            struct.pack_into("<Q", raw, 120, 1_725_000_001)
            struct.pack_into("<Q", raw, 128, 234_567)
            return 136

        api = self.api_with_libproc(
            proc_pidpath=Mock(side_effect=proc_pidpath),
            proc_pidinfo=Mock(side_effect=proc_pidinfo),
        )

        self.assertEqual(api.executable_path(42), "/usr/bin/python3")
        info = api.bsd_info(42)
        self.assertEqual(
            vars(info),
            {
                "pid": 42,
                "start_sec": 1_725_000_001,
                "start_usec": 234_567,
                "parent_pid": 41,
                "process_group_id": 40,
            },
        )

    def test_libproc_errors_classify_errno_and_incomplete_structures(self) -> None:
        for error_number, error_type in (
            (errno.ESRCH, ProcessLookupError),
            (errno.EPERM, PermissionError),
            (errno.EIO, OSError),
        ):
            api = self.api_with_libproc(proc_pidpath=Mock(return_value=0))
            with self.subTest(error=error_number), patch.object(
                ctypes, "get_errno", return_value=error_number
            ), self.assertRaises(error_type):
                api.executable_path(42)

        api = self.api_with_libproc(proc_pidinfo=Mock(return_value=1))
        with self.assertRaises(OSError):
            api.bsd_info(42)


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
