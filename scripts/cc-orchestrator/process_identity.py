from __future__ import annotations

import ctypes
import errno
import ntpath
import os
import posixpath
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping


_IDENTITY_FIELDS = (
    "pid",
    "creation_token",
    "executable_path",
    "parent_pid",
    "process_group_id",
    "session_id",
    "launch_nonce",
    "supported",
    "unsupported_reason",
)
_EXITED_REASON = "process exited"
_ACCESS_DENIED_REASON = "access denied"
_QUERY_FAILED_REASON = "process query failed"
_MALFORMED_REASON = "process information malformed"
_UNSTABLE_REASON = "process identity changed during capture"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or null")
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    return value


def _require_optional_int(
    value: object,
    field_name: str,
    *,
    allow_zero: bool,
) -> int | None:
    if value is None:
        return None
    if not _is_int(value):
        raise TypeError(f"{field_name} must be an integer or null")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise ValueError(f"{field_name} is out of range")
    return value


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_token: str | None
    executable_path: str | None
    parent_pid: int | None
    process_group_id: int | None
    session_id: int | None
    launch_nonce: str
    supported: bool
    unsupported_reason: str | None = None

    def __post_init__(self) -> None:
        if not _is_int(self.pid):
            raise TypeError("pid must be an integer")
        if self.pid <= 0:
            raise ValueError("pid must be positive")
        _require_optional_string(self.creation_token, "creation_token")
        _require_optional_string(self.executable_path, "executable_path")
        _require_optional_int(self.parent_pid, "parent_pid", allow_zero=False)
        _require_optional_int(
            self.process_group_id, "process_group_id", allow_zero=True
        )
        _require_optional_int(self.session_id, "session_id", allow_zero=True)
        if not isinstance(self.launch_nonce, str):
            raise TypeError("launch_nonce must be a string")
        if not self.launch_nonce:
            raise ValueError("launch_nonce must not be empty")
        if not isinstance(self.supported, bool):
            raise TypeError("supported must be a boolean")
        _require_optional_string(self.unsupported_reason, "unsupported_reason")

        has_minimum = self.creation_token is not None and self.executable_path is not None
        if self.supported and (not has_minimum or self.unsupported_reason is not None):
            raise ValueError("supported identity has inconsistent evidence")
        if not self.supported and self.unsupported_reason is None:
            raise ValueError("unsupported identity requires a reason")
        if not self.supported and has_minimum:
            raise ValueError("unsupported identity contains complete minimum evidence")

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in _IDENTITY_FIELDS}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProcessIdentity":
        if not isinstance(data, Mapping):
            raise TypeError("process identity must be a mapping")
        keys = set(data.keys())
        expected_keys = set(_IDENTITY_FIELDS)
        if keys != expected_keys:
            raise ValueError("process identity fields do not match the contract")
        if not all(isinstance(key, str) for key in data.keys()):
            raise TypeError("process identity field names must be strings")

        return cls(
            pid=data["pid"],
            creation_token=data["creation_token"],
            executable_path=data["executable_path"],
            parent_pid=data["parent_pid"],
            process_group_id=data["process_group_id"],
            session_id=data["session_id"],
            launch_nonce=data["launch_nonce"],
            supported=data["supported"],
            unsupported_reason=data["unsupported_reason"],
        )


@dataclass(frozen=True)
class ProcessIdentityCheck:
    state: str
    differing_fields: tuple[str, ...] = ()
    live: ProcessIdentity | None = None


def _unsupported(pid: int, launch_nonce: str, reason: str) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        creation_token=None,
        executable_path=None,
        parent_pid=None,
        process_group_id=None,
        session_id=None,
        launch_nonce=launch_nonce,
        supported=False,
        unsupported_reason=reason,
    )


def _validate_capture_arguments(pid: object, launch_nonce: object) -> tuple[int, str]:
    if not _is_int(pid):
        raise TypeError("pid must be an integer")
    if pid <= 0:
        raise ValueError("pid must be positive")
    if not isinstance(launch_nonce, str):
        raise TypeError("launch_nonce must be a string")
    if not launch_nonce:
        raise ValueError("launch_nonce must not be empty")
    return pid, launch_nonce


def capture_process_identity(pid: int, *, launch_nonce: str) -> ProcessIdentity:
    pid, launch_nonce = _validate_capture_arguments(pid, launch_nonce)
    if sys.platform == "win32":
        return _capture_windows(pid, launch_nonce=launch_nonce)
    if sys.platform.startswith("linux"):
        return _capture_linux(pid, launch_nonce=launch_nonce)
    if sys.platform == "darwin":
        return _capture_macos(pid, launch_nonce=launch_nonce)
    return _unsupported(pid, launch_nonce, "platform unsupported")


def _path_for_comparison(path: str) -> str:
    if sys.platform == "win32":
        path = _strip_windows_extended_prefix(path)
        return ntpath.normcase(ntpath.normpath(path))
    if sys.platform.startswith("linux") and path.endswith(" (deleted)"):
        path = path[: -len(" (deleted)")]
    return posixpath.normpath(path)


def compare_process_identity(
    expected: ProcessIdentity,
    *,
    expected_launch_nonce: str | None = None,
) -> ProcessIdentityCheck:
    if not isinstance(expected, ProcessIdentity):
        raise TypeError("expected must be a ProcessIdentity")
    if expected_launch_nonce is not None:
        if not isinstance(expected_launch_nonce, str) or not expected_launch_nonce:
            raise ValueError("expected_launch_nonce must be a non-empty string")
        if expected_launch_nonce != expected.launch_nonce:
            return ProcessIdentityCheck(
                state="mismatch", differing_fields=("launch_nonce",)
            )
    if (
        not expected.supported
        or not expected.creation_token
        or not expected.executable_path
        or not _is_int(expected.pid)
        or expected.pid <= 0
        or not expected.launch_nonce
    ):
        return ProcessIdentityCheck(state="unverified")

    try:
        live = capture_process_identity(
            expected.pid,
            launch_nonce=expected.launch_nonce,
        )
    except (OSError, ValueError, TypeError):
        return ProcessIdentityCheck(state="unverified")
    if not isinstance(live, ProcessIdentity):
        return ProcessIdentityCheck(state="unverified")
    if not live.supported:
        state = "exited" if live.unsupported_reason == _EXITED_REASON else "unverified"
        return ProcessIdentityCheck(state=state, live=live)
    if not live.creation_token or not live.executable_path:
        return ProcessIdentityCheck(state="unverified", live=live)

    differing: list[str] = []
    if expected.pid != live.pid:
        differing.append("pid")
    if expected.creation_token != live.creation_token:
        differing.append("creation_token")
    if _path_for_comparison(expected.executable_path) != _path_for_comparison(
        live.executable_path
    ):
        differing.append("executable_path")
    for field_name in ("parent_pid", "process_group_id", "session_id"):
        expected_value = getattr(expected, field_name)
        live_value = getattr(live, field_name)
        if (
            expected_value is not None
            and live_value is not None
            and expected_value != live_value
        ):
            differing.append(field_name)
    differing_fields = tuple(sorted(differing))
    return ProcessIdentityCheck(
        state="mismatch" if differing_fields else "match",
        differing_fields=differing_fields,
        live=live,
    )


def _parse_linux_stat(stat_text: str, *, expected_pid: int) -> tuple[int, int, int, str]:
    if not isinstance(stat_text, str):
        raise TypeError("stat data must be text")
    opening = stat_text.find("(")
    closing = stat_text.rfind(")")
    if opening <= 0 or closing <= opening:
        raise ValueError("invalid proc stat framing")
    try:
        parsed_pid = int(stat_text[:opening].strip())
    except ValueError as exc:
        raise ValueError("invalid proc stat pid") from exc
    if parsed_pid != expected_pid:
        raise ValueError("proc stat pid mismatch")
    fields = stat_text[closing + 1 :].split()
    if len(fields) < 20:
        raise ValueError("proc stat is truncated")
    try:
        parent_pid = int(fields[1])
        process_group_id = int(fields[2])
        session_id = int(fields[3])
        start_ticks = int(fields[19])
    except (IndexError, ValueError) as exc:
        raise ValueError("proc stat contains invalid numeric fields") from exc
    if parent_pid < 0 or process_group_id < 0 or session_id < 0 or start_ticks < 0:
        raise ValueError("proc stat contains out-of-range fields")
    return parent_pid, process_group_id, session_id, str(start_ticks)


def _capture_linux(
    pid: int,
    *,
    launch_nonce: str,
    proc_root: Path = Path("/proc"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
) -> ProcessIdentity:
    stat_path = proc_root / str(pid) / "stat"
    executable_link = proc_root / str(pid) / "exe"
    try:
        stat_text = stat_path.read_text(encoding="utf-8", errors="strict")
    except FileNotFoundError:
        return _unsupported(pid, launch_nonce, _EXITED_REASON)
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except UnicodeError:
        return _unsupported(pid, launch_nonce, _MALFORMED_REASON)
    except OSError:
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    try:
        parent_pid, process_group_id, session_id, start_ticks = _parse_linux_stat(
            stat_text, expected_pid=pid
        )
    except (TypeError, ValueError):
        return _unsupported(pid, launch_nonce, _MALFORMED_REASON)

    try:
        executable_path = os.readlink(executable_link)
    except FileNotFoundError:
        return _unsupported(pid, launch_nonce, _EXITED_REASON)
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except OSError:
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    if not isinstance(executable_path, str) or not executable_path:
        return _unsupported(pid, launch_nonce, _MALFORMED_REASON)

    try:
        verify_stat_text = stat_path.read_text(encoding="utf-8", errors="strict")
    except FileNotFoundError:
        return _unsupported(pid, launch_nonce, _EXITED_REASON)
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except UnicodeError:
        return _unsupported(pid, launch_nonce, _MALFORMED_REASON)
    except OSError:
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    try:
        verified_fields = _parse_linux_stat(verify_stat_text, expected_pid=pid)
    except (TypeError, ValueError):
        return _unsupported(pid, launch_nonce, _MALFORMED_REASON)
    if verified_fields != (
        parent_pid,
        process_group_id,
        session_id,
        start_ticks,
    ):
        return _unsupported(pid, launch_nonce, _UNSTABLE_REASON)

    try:
        boot_id = boot_id_path.read_text(encoding="ascii", errors="strict").strip()
        if not boot_id or any(character.isspace() for character in boot_id):
            raise ValueError("invalid boot id")
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except (OSError, UnicodeError, ValueError):
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)

    return ProcessIdentity(
        pid=pid,
        creation_token=f"{boot_id}:{start_ticks}",
        executable_path=executable_path,
        parent_pid=parent_pid or None,
        process_group_id=process_group_id or None,
        session_id=session_id or None,
        launch_nonce=launch_nonce,
        supported=True,
    )


def _strip_windows_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


class _FILETIME(ctypes.Structure):
    _fields_ = (("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32))


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    )


class _WindowsApi:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    TH32CS_SNAPPROCESS = 0x00000002
    ERROR_NO_MORE_FILES = 18
    ERROR_INVALID_PARAMETER = 87
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    WAIT_FAILED = 0xFFFFFFFF

    def __init__(self) -> None:
        from ctypes import wintypes

        self._wintypes = wintypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        self._kernel32.OpenProcess.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.GetProcessTimes.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
        )
        self._kernel32.GetProcessTimes.restype = wintypes.BOOL
        self._kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        self._kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self._kernel32.CreateToolhelp32Snapshot.argtypes = (
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self._kernel32.Process32FirstW.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_PROCESSENTRY32W),
        )
        self._kernel32.Process32FirstW.restype = wintypes.BOOL
        self._kernel32.Process32NextW.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_PROCESSENTRY32W),
        )
        self._kernel32.Process32NextW.restype = wintypes.BOOL
        self._kernel32.ProcessIdToSessionId.argtypes = (
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self._kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
        self._kernel32.WaitForSingleObject.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
        )
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD

    @staticmethod
    def _error(code: int | None = None) -> OSError:
        error_code = ctypes.get_last_error() if code is None else code
        if error_code == _WindowsApi.ERROR_INVALID_PARAMETER:
            return ProcessLookupError(error_code, "process unavailable")
        if error_code == 5:
            return PermissionError(error_code, "process access denied")
        return OSError(error_code, "process query failed")

    def open_process(self, pid: int) -> int:
        handle = self._kernel32.OpenProcess(
            self.PROCESS_QUERY_LIMITED_INFORMATION | self.SYNCHRONIZE,
            False,
            pid,
        )
        if not handle:
            raise self._error()
        return handle

    def close_handle(self, handle: int) -> None:
        self._kernel32.CloseHandle(handle)

    def assert_running(self, handle: int) -> None:
        result = self._kernel32.WaitForSingleObject(handle, 0)
        if result == self.WAIT_TIMEOUT:
            return
        if result == self.WAIT_OBJECT_0:
            raise ProcessLookupError(errno.ESRCH, "process unavailable")
        if result == self.WAIT_FAILED:
            raise self._error()
        raise OSError(errno.EIO, "unexpected process wait result")

    def creation_filetime(self, handle: int) -> tuple[int, int]:
        creation = _FILETIME()
        exit_time = _FILETIME()
        kernel = _FILETIME()
        user = _FILETIME()
        if not self._kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise self._error()
        return creation.dwHighDateTime, creation.dwLowDateTime

    def executable_path(self, handle: int) -> str:
        capacity = 32768
        buffer = ctypes.create_unicode_buffer(capacity)
        size = self._wintypes.DWORD(capacity)
        if not self._kernel32.QueryFullProcessImageNameW(
            handle, 0, buffer, ctypes.byref(size)
        ):
            raise self._error()
        return buffer.value[: size.value]

    def parent_pid(self, pid: int) -> int:
        snapshot = self._kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if snapshot == invalid_handle:
            raise self._error()
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                raise self._error()
            while True:
                if entry.th32ProcessID == pid:
                    return int(entry.th32ParentProcessID)
                if not self._kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    error_code = ctypes.get_last_error()
                    if error_code == self.ERROR_NO_MORE_FILES:
                        raise ProcessLookupError(pid, "process unavailable")
                    raise self._error(error_code)
        finally:
            self.close_handle(snapshot)

    def session_id(self, pid: int) -> int:
        session_id = self._wintypes.DWORD()
        if not self._kernel32.ProcessIdToSessionId(pid, ctypes.byref(session_id)):
            raise self._error()
        return int(session_id.value)


def _capture_windows(
    pid: int,
    *,
    launch_nonce: str,
    api: Any | None = None,
) -> ProcessIdentity:
    try:
        native = api if api is not None else _WindowsApi()
    except (AttributeError, OSError):
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    handle: int | None = None
    try:
        handle = native.open_process(pid)
        native.assert_running(handle)
        high, low = native.creation_filetime(handle)
        executable_path = native.executable_path(handle)
        parent_pid = native.parent_pid(pid)
        session_id = native.session_id(pid)
        native.assert_running(handle)
        if not executable_path:
            raise ValueError("empty executable path")
    except ProcessLookupError:
        return _unsupported(pid, launch_nonce, _EXITED_REASON)
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except OSError:
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    except (TypeError, ValueError, OverflowError):
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    finally:
        if handle is not None:
            native.close_handle(handle)
    creation_filetime = (int(high) << 32) | int(low)
    return ProcessIdentity(
        pid=pid,
        creation_token=str(creation_filetime),
        executable_path=ntpath.normpath(_strip_windows_extended_prefix(executable_path)),
        parent_pid=int(parent_pid) or None,
        process_group_id=None,
        session_id=int(session_id),
        launch_nonce=launch_nonce,
        supported=True,
    )


class _PROC_BSDINFO(ctypes.Structure):
    _fields_ = (
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    )


class _MacApi:
    PROC_PIDTBSDINFO = 3
    PROC_PIDPATHINFO_MAXSIZE = 4096

    def __init__(self) -> None:
        self._libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self._libproc.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        self._libproc.proc_pidpath.restype = ctypes.c_int
        self._libproc.proc_pidinfo.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        self._libproc.proc_pidinfo.restype = ctypes.c_int

    @staticmethod
    def _raise_last_error() -> None:
        error_code = ctypes.get_errno()
        if error_code == errno.ESRCH:
            raise ProcessLookupError(error_code, "process unavailable")
        if error_code in (errno.EACCES, errno.EPERM):
            raise PermissionError(error_code, "process access denied")
        raise OSError(error_code or errno.EIO, "process query failed")

    def executable_path(self, pid: int) -> str:
        buffer = ctypes.create_string_buffer(self.PROC_PIDPATHINFO_MAXSIZE)
        length = self._libproc.proc_pidpath(pid, buffer, len(buffer))
        if length <= 0:
            self._raise_last_error()
        return os.fsdecode(buffer.raw[:length].split(b"\0", 1)[0])

    def bsd_info(self, pid: int) -> object:
        info = _PROC_BSDINFO()
        size = self._libproc.proc_pidinfo(
            pid,
            self.PROC_PIDTBSDINFO,
            0,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if size != ctypes.sizeof(info):
            if size <= 0:
                self._raise_last_error()
            raise OSError(errno.EIO, "incomplete process information")
        return SimpleNamespace(
            pid=int(info.pbi_pid),
            start_sec=int(info.pbi_start_tvsec),
            start_usec=int(info.pbi_start_tvusec),
            parent_pid=int(info.pbi_ppid),
            process_group_id=int(info.pbi_pgid),
        )


def _capture_macos(
    pid: int,
    *,
    launch_nonce: str,
    api: Any | None = None,
) -> ProcessIdentity:
    try:
        native = api if api is not None else _MacApi()
    except (AttributeError, OSError):
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    try:
        first_info = native.bsd_info(pid)
        executable_path = native.executable_path(pid)
        second_info = native.bsd_info(pid)
        first_fields = (
            int(first_info.pid),
            int(first_info.start_sec),
            int(first_info.start_usec),
            int(first_info.parent_pid),
            int(first_info.process_group_id),
        )
        second_fields = (
            int(second_info.pid),
            int(second_info.start_sec),
            int(second_info.start_usec),
            int(second_info.parent_pid),
            int(second_info.process_group_id),
        )
        native_pid, start_sec, start_usec, parent_pid, process_group_id = first_fields
        if (
            not executable_path
            or native_pid != pid
            or start_sec < 0
            or start_usec < 0
            or start_usec >= 1_000_000
            or parent_pid < 0
            or process_group_id < 0
        ):
            raise ValueError("invalid native process information")
        if second_fields != first_fields:
            return _unsupported(pid, launch_nonce, _UNSTABLE_REASON)
    except ProcessLookupError:
        return _unsupported(pid, launch_nonce, _EXITED_REASON)
    except PermissionError:
        return _unsupported(pid, launch_nonce, _ACCESS_DENIED_REASON)
    except (OSError, TypeError, ValueError, OverflowError):
        return _unsupported(pid, launch_nonce, _QUERY_FAILED_REASON)
    return ProcessIdentity(
        pid=pid,
        creation_token=f"{start_sec}:{start_usec}",
        executable_path=posixpath.normpath(executable_path),
        parent_pid=parent_pid or None,
        process_group_id=process_group_id or None,
        session_id=None,
        launch_nonce=launch_nonce,
        supported=True,
    )


def process_identity_support() -> dict[str, Any]:
    pidfd_available = callable(getattr(os, "pidfd_open", None))
    supported = False
    reason: str | None = None
    mechanism: str | None = None
    if sys.platform == "win32":
        mechanism = "windows_native_api"
        try:
            _WindowsApi()
            supported = True
        except (AttributeError, OSError):
            reason = "native process API unavailable"
    elif sys.platform.startswith("linux"):
        mechanism = "procfs"
        supported = Path("/proc/self/stat").is_file() and Path(
            "/proc/sys/kernel/random/boot_id"
        ).is_file()
        if not supported:
            reason = "procfs identity evidence unavailable"
    elif sys.platform == "darwin":
        mechanism = "libproc"
        try:
            _MacApi()
            supported = True
        except (AttributeError, OSError):
            reason = "native process API unavailable"
    else:
        reason = "platform unsupported"
    return {
        "platform": sys.platform,
        "supported": supported,
        "unsupported_reason": reason,
        "mechanism": mechanism,
        "minimum_fields": ("pid", "creation_token", "executable_path"),
        "pidfd_available": pidfd_available,
    }
