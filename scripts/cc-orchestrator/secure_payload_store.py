#!/usr/bin/env python3
"""OS-protected storage for deferred orchestrator prompts."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


REFERENCE_RE = re.compile(r"^ccsp:(memory|windows|macos|linux):([a-f0-9]{32})$")
SERVICE_NAME = "cc-orchestrator-secure-payload"


class SecurePayloadStoreError(RuntimeError):
    """A protected payload could not be stored or recovered."""


class SecurePayloadStoreUnavailable(SecurePayloadStoreError):
    """No tested native protected store is available."""


class SecurePayloadStore(ABC):
    @abstractmethod
    def put(self, *, payload_id: str, value: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def get(self, reference: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def delete(self, reference: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def health(self) -> dict[str, Any]:
        raise NotImplementedError


def _new_reference(backend: str) -> tuple[str, str]:
    token = uuid.uuid4().hex
    return token, f"ccsp:{backend}:{token}"


def _reference_token(reference: str, backend: str) -> str:
    match = REFERENCE_RE.fullmatch(reference)
    if match is None or match.group(1) != backend:
        raise SecurePayloadStoreError("Invalid secure payload reference.")
    return match.group(2)


class InMemorySecurePayloadStore(SecurePayloadStore):
    """Deterministic injectable test backend; never selected by production factory."""

    def __init__(self) -> None:
        self._values: dict[str, bytes] = {}
        self._lock = threading.RLock()

    def put(self, *, payload_id: str, value: bytes) -> str:
        del payload_id
        token, reference = _new_reference("memory")
        with self._lock:
            self._values[token] = bytes(value)
        return reference

    def get(self, reference: str) -> bytes:
        token = _reference_token(reference, "memory")
        with self._lock:
            try:
                return bytes(self._values[token])
            except KeyError as exc:
                raise SecurePayloadStoreError("Secure payload was not found.") from exc

    def delete(self, reference: str) -> None:
        token = _reference_token(reference, "memory")
        with self._lock:
            self._values.pop(token, None)

    def health(self) -> dict[str, Any]:
        return {"ok": True, "backend": "memory", "production": False}


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(value: bytes) -> tuple[_DATA_BLOB, Any]:
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _DATA_BLOB(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


class WindowsDPAPIPayloadStore(SecurePayloadStore):
    def __init__(self, root: str | Path) -> None:
        if os.name != "nt":
            raise SecurePayloadStoreUnavailable("Windows DPAPI is unavailable on this platform.")
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _protect(self, value: bytes, *, decrypt: bool = False) -> bytes:
        source, source_buffer = _blob(value)
        entropy, entropy_buffer = _blob(SERVICE_NAME.encode("ascii"))
        output = _DATA_BLOB()
        if decrypt:
            ok = self._crypt32.CryptUnprotectData(
                ctypes.byref(source), None, ctypes.byref(entropy), None, None, 0x1,
                ctypes.byref(output),
            )
        else:
            ok = self._crypt32.CryptProtectData(
                ctypes.byref(source), SERVICE_NAME, ctypes.byref(entropy), None, None, 0x1,
                ctypes.byref(output),
            )
        if not ok:
            raise SecurePayloadStoreError(f"DPAPI operation failed with error {ctypes.get_last_error()}.")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            self._kernel32.LocalFree(output.pbData)

    def _path(self, token: str) -> Path:
        return self.root / f"{token}.dpapi"

    def put(self, *, payload_id: str, value: bytes) -> str:
        del payload_id
        token, reference = _new_reference("windows")
        protected = self._protect(bytes(value))
        fd, temporary = tempfile.mkstemp(prefix=f".{token}-", dir=str(self.root))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(protected)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path(token))
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return reference

    def get(self, reference: str) -> bytes:
        token = _reference_token(reference, "windows")
        try:
            protected = self._path(token).read_bytes()
        except FileNotFoundError as exc:
            raise SecurePayloadStoreError("Secure payload was not found.") from exc
        return self._protect(protected, decrypt=True)

    def delete(self, reference: str) -> None:
        token = _reference_token(reference, "windows")
        try:
            self._path(token).unlink()
        except FileNotFoundError:
            pass

    def health(self) -> dict[str, Any]:
        return {"ok": True, "backend": "windows_dpapi", "root": str(self.root)}


class _CommandPayloadStore(SecurePayloadStore):
    backend: str

    def __init__(self, executable: str) -> None:
        path = Path(executable).expanduser()
        if not path.is_absolute():
            raise SecurePayloadStoreUnavailable("Protected-store executable must be absolute.")
        self.executable = str(path.resolve(strict=False))

    def _run(self, argv: list[str], *, value: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        environment = {
            key: os.environ[key]
            for key in (
                "DBUS_SESSION_BUS_ADDRESS",
                "DISPLAY",
                "HOME",
                "WAYLAND_DISPLAY",
                "XDG_RUNTIME_DIR",
            )
            if os.environ.get(key)
        }
        environment.update({"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        try:
            result = subprocess.run(
                argv,
                input=value,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecurePayloadStoreError(
                f"{self.backend} protected-store operation could not be executed."
            ) from exc
        if result.returncode != 0:
            raise SecurePayloadStoreError(
                f"{self.backend} protected-store operation failed with exit code {result.returncode}."
            )
        return result

    @staticmethod
    def _pack(value: bytes) -> bytes:
        raw = bytes(value)
        return b"ccsp1:" + base64.b64encode(raw) + b":" + hashlib.sha256(raw).hexdigest().encode("ascii")

    @staticmethod
    def _unpack(value: bytes) -> bytes:
        framed = value[:-1] if value.endswith(b"\n") else value
        try:
            prefix, encoded, digest = framed.split(b":", 2)
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise SecurePayloadStoreError("Protected payload framing is invalid.") from exc
        if prefix != b"ccsp1" or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest().encode("ascii"), digest
        ):
            raise SecurePayloadStoreError("Protected payload integrity check failed.")
        return raw

    def health(self) -> dict[str, Any]:
        return {"ok": True, "backend": self.backend, "executable": self.executable}


class LinuxSecretServicePayloadStore(_CommandPayloadStore):
    backend = "linux"

    def put(self, *, payload_id: str, value: bytes) -> str:
        del payload_id
        token, reference = _new_reference(self.backend)
        self._run(
            [self.executable, "store", "--label", SERVICE_NAME, "service", SERVICE_NAME, "payload", token],
            value=self._pack(value),
        )
        return reference

    def get(self, reference: str) -> bytes:
        token = _reference_token(reference, self.backend)
        result = self._run(
            [self.executable, "lookup", "service", SERVICE_NAME, "payload", token]
        )
        return self._unpack(result.stdout)

    def delete(self, reference: str) -> None:
        token = _reference_token(reference, self.backend)
        self._run([self.executable, "clear", "service", SERVICE_NAME, "payload", token])


class MacOSKeychainPayloadStore(SecurePayloadStore):
    """Generic-password storage through Security.framework SecItem APIs."""

    backend = "macos"
    _UTF8 = 0x08000100
    _ITEM_NOT_FOUND = -25300

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise SecurePayloadStoreUnavailable("macOS Keychain is unavailable on this platform.")
        try:
            self._security = ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security"
            )
            self._cf = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
            self._configure_apis()
        except (OSError, ValueError, AttributeError) as exc:
            raise SecurePayloadStoreUnavailable("macOS Keychain APIs are unavailable.") from exc

    def _configure_apis(self) -> None:
        self._cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        self._cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        self._cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
        self._cf.CFDataCreate.restype = ctypes.c_void_p
        self._cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
        self._cf.CFDataGetLength.restype = ctypes.c_long
        self._cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        self._cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        self._cf.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._cf.CFDictionaryCreate.restype = ctypes.c_void_p
        self._cf.CFRelease.argtypes = [ctypes.c_void_p]
        self._security.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._security.SecItemAdd.restype = ctypes.c_int32
        self._security.SecItemCopyMatching.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self._security.SecItemCopyMatching.restype = ctypes.c_int32
        self._security.SecItemDelete.argtypes = [ctypes.c_void_p]
        self._security.SecItemDelete.restype = ctypes.c_int32

    @staticmethod
    def _symbol(library: Any, name: str) -> int:
        value = ctypes.c_void_p.in_dll(library, name).value
        if not value:
            raise SecurePayloadStoreUnavailable(f"Keychain symbol {name} is unavailable.")
        return int(value)

    def _string(self, value: str) -> int:
        result = self._cf.CFStringCreateWithCString(None, value.encode("utf-8"), self._UTF8)
        if not result:
            raise SecurePayloadStoreError("Could not create a Keychain string.")
        return int(result)

    def _dictionary(self, pairs: list[tuple[int, int]]) -> int:
        keys = (ctypes.c_void_p * len(pairs))(*(key for key, _value in pairs))
        values = (ctypes.c_void_p * len(pairs))(*(value for _key, value in pairs))
        key_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self._cf, "kCFTypeDictionaryKeyCallBacks"))
        value_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self._cf, "kCFTypeDictionaryValueCallBacks"))
        result = self._cf.CFDictionaryCreate(
            None, keys, values, len(pairs), key_callbacks, value_callbacks
        )
        if not result:
            raise SecurePayloadStoreError("Could not create a Keychain query.")
        return int(result)

    def _query(self, token: str, *, value: bytes | None = None, return_data: bool = False) -> tuple[int, list[int]]:
        owned = [self._string(SERVICE_NAME), self._string(token)]
        pairs = [
            (self._symbol(self._security, "kSecClass"), self._symbol(self._security, "kSecClassGenericPassword")),
            (self._symbol(self._security, "kSecAttrService"), owned[0]),
            (self._symbol(self._security, "kSecAttrAccount"), owned[1]),
        ]
        if value is not None:
            buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
            data = self._cf.CFDataCreate(None, buffer, len(value))
            if not data:
                raise SecurePayloadStoreError("Could not create Keychain payload data.")
            owned.append(int(data))
            pairs.append((self._symbol(self._security, "kSecValueData"), int(data)))
        if return_data:
            pairs.append(
                (
                    self._symbol(self._security, "kSecReturnData"),
                    self._symbol(self._cf, "kCFBooleanTrue"),
                )
            )
        return self._dictionary(pairs), owned

    def put(self, *, payload_id: str, value: bytes) -> str:
        del payload_id
        token, reference = _new_reference(self.backend)
        query, owned = self._query(token, value=bytes(value))
        try:
            status = int(self._security.SecItemAdd(query, None))
            if status != 0:
                raise SecurePayloadStoreError(f"Keychain add failed with status {status}.")
        finally:
            self._cf.CFRelease(query)
            for item in owned:
                self._cf.CFRelease(item)
        return reference

    def get(self, reference: str) -> bytes:
        token = _reference_token(reference, self.backend)
        query, owned = self._query(token, return_data=True)
        result = ctypes.c_void_p()
        try:
            status = int(self._security.SecItemCopyMatching(query, ctypes.byref(result)))
            if status == self._ITEM_NOT_FOUND:
                raise SecurePayloadStoreError("Secure payload was not found.")
            if status != 0 or not result.value:
                raise SecurePayloadStoreError(f"Keychain lookup failed with status {status}.")
            length = int(self._cf.CFDataGetLength(result))
            pointer = self._cf.CFDataGetBytePtr(result)
            return ctypes.string_at(pointer, length)
        finally:
            if result.value:
                self._cf.CFRelease(result)
            self._cf.CFRelease(query)
            for item in owned:
                self._cf.CFRelease(item)

    def delete(self, reference: str) -> None:
        token = _reference_token(reference, self.backend)
        query, owned = self._query(token)
        try:
            status = int(self._security.SecItemDelete(query))
            if status not in {0, self._ITEM_NOT_FOUND}:
                raise SecurePayloadStoreError(f"Keychain delete failed with status {status}.")
        finally:
            self._cf.CFRelease(query)
            for item in owned:
                self._cf.CFRelease(item)

    def health(self) -> dict[str, Any]:
        return {"ok": True, "backend": "macos_keychain", "native_api": "SecItem"}


def create_secure_payload_store(*, root: str | Path | None = None) -> SecurePayloadStore:
    if os.name == "nt":
        if root is None:
            root = Path.home() / ".cc-orchestrator" / "secure-payloads"
        return WindowsDPAPIPayloadStore(root)
    if sys.platform == "darwin":
        return MacOSKeychainPayloadStore()
    if sys.platform.startswith("linux"):
        executable = shutil.which("secret-tool")
        if not executable:
            raise SecurePayloadStoreUnavailable("Linux Secret Service is unavailable.")
        return LinuxSecretServicePayloadStore(executable)
    raise SecurePayloadStoreUnavailable("A supported native secure payload store is unavailable.")


__all__ = [
    "InMemorySecurePayloadStore",
    "LinuxSecretServicePayloadStore",
    "MacOSKeychainPayloadStore",
    "SecurePayloadStore",
    "SecurePayloadStoreError",
    "SecurePayloadStoreUnavailable",
    "WindowsDPAPIPayloadStore",
    "create_secure_payload_store",
]
