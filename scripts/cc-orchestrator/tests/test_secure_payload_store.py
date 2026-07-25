from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: E402, F401

import secure_payload_store as stores  # noqa: E402


class SecurePayloadStoreContractTests(unittest.TestCase):
    def test_in_memory_store_round_trip_uses_opaque_reference(self) -> None:
        store = stores.InMemorySecurePayloadStore()
        secret = b"xy-short-arbitrary-secret"
        reference = store.put(payload_id="job-fixture", value=secret)
        self.assertNotIn(secret.decode(), reference)
        self.assertEqual(store.get(reference), secret)
        store.delete(reference)
        with self.assertRaises(stores.SecurePayloadStoreError):
            store.get(reference)

    def test_store_copies_mutable_input(self) -> None:
        store = stores.InMemorySecurePayloadStore()
        value = bytearray(b"mutable-secret")
        reference = store.put(payload_id="job-fixture", value=value)
        value[:] = b"x" * len(value)
        self.assertEqual(store.get(reference), b"mutable-secret")

    def test_linux_secret_tool_receives_secret_on_stdin_only(self) -> None:
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            class Result:
                returncode = 0
                stdout = b""
                stderr = b""
            return Result()

        store = stores.LinuxSecretServicePayloadStore(executable=str(Path(sys.executable).resolve()))
        secret = b"stdin-only-secret"
        with patch.object(stores.subprocess, "run", side_effect=fake_run):
            reference = store.put(payload_id="job-fixture", value=secret)
        argv, kwargs = calls[0]
        self.assertNotIn(secret.decode(), " ".join(argv))
        self.assertEqual(store._unpack(kwargs["input"]), secret)
        self.assertTrue(reference.startswith("ccsp:linux:"))

    def test_linux_backend_preserves_only_required_session_environment(self) -> None:
        captured = {}

        def fake_run(_argv, **kwargs):
            captured.update(kwargs["env"])

            class Result:
                returncode = 0
                stdout = b""
                stderr = b""

            return Result()

        store = stores.LinuxSecretServicePayloadStore(
            executable=str(Path(sys.executable).resolve())
        )
        with (
            patch.dict(
                os.environ,
                {
                    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/fixture/dbus",
                    "XDG_RUNTIME_DIR": "/fixture/runtime",
                    "UNRELATED_SECRET": "must-not-cross",
                },
                clear=True,
            ),
            patch.object(stores.subprocess, "run", side_effect=fake_run),
        ):
            store.put(payload_id="job-fixture", value=b"fixture")
        self.assertEqual(
            captured["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/fixture/dbus"
        )
        self.assertEqual(captured["XDG_RUNTIME_DIR"], "/fixture/runtime")
        self.assertNotIn("UNRELATED_SECRET", captured)
        self.assertEqual(captured["PATH"], "")

    def test_command_backend_normalizes_process_failures(self) -> None:
        store = stores.LinuxSecretServicePayloadStore(
            executable=str(Path(sys.executable).resolve())
        )
        for failure in (OSError("missing"), stores.subprocess.TimeoutExpired([], 20)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(stores.subprocess, "run", side_effect=failure):
                    with self.assertRaises(stores.SecurePayloadStoreError):
                        store.put(payload_id="job-fixture", value=b"fixture")

    def test_unavailable_factory_fails_closed(self) -> None:
        with (
            patch.object(stores.os, "name", "posix"),
            patch.object(stores.sys, "platform", "linux"),
            patch.object(stores.shutil, "which", return_value=None),
        ):
            with self.assertRaisesRegex(stores.SecurePayloadStoreUnavailable, "unavailable"):
                stores.create_secure_payload_store()

    @unittest.skipUnless(os.name == "nt", "requires Windows DPAPI")
    def test_windows_dpapi_round_trip_and_ciphertext_at_rest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dpapi-store-") as temp:
            store = stores.WindowsDPAPIPayloadStore(temp)
            secret = b"short-dpapi-secret"
            reference = store.put(payload_id="job-fixture", value=secret)
            files = list(Path(temp).glob("*.dpapi"))
            self.assertEqual(len(files), 1)
            self.assertNotIn(secret, files[0].read_bytes())
            self.assertEqual(store.get(reference), secret)
            store.delete(reference)
            self.assertFalse(files[0].exists())

    @unittest.skipUnless(os.name == "nt", "requires Windows DPAPI")
    def test_windows_dpapi_rejects_damaged_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dpapi-damage-") as temp:
            store = stores.WindowsDPAPIPayloadStore(temp)
            reference = store.put(payload_id="job-fixture", value=b"fixture")
            payload = next(Path(temp).glob("*.dpapi"))
            payload.write_bytes(b"not-a-valid-dpapi-blob")
            with self.assertRaises(stores.SecurePayloadStoreError):
                store.get(reference)

    def test_macos_backend_uses_native_secitem_api(self) -> None:
        source = Path(stores.__file__).read_text(encoding="utf-8")
        start = source.index("class MacOSKeychainPayloadStore")
        end = source.index("def create_secure_payload_store", start)
        implementation = source[start:end]
        self.assertIn("SecItemAdd", implementation)
        self.assertIn("SecItemCopyMatching", implementation)
        self.assertIn("SecItemDelete", implementation)
        self.assertNotIn("subprocess", implementation)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS Keychain")
    def test_macos_keychain_round_trip_and_delete(self) -> None:
        store = stores.MacOSKeychainPayloadStore()
        secret = b"macos-keychain-fixture"
        reference = store.put(payload_id="job-fixture", value=secret)
        try:
            self.assertEqual(store.get(reference), secret)
        finally:
            store.delete(reference)
        with self.assertRaises(stores.SecurePayloadStoreError):
            store.get(reference)


if __name__ == "__main__":
    unittest.main()
