from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "release_manifest.py"
sys.path.insert(0, str(SCRIPT.parent))
from release_manifest import canonical_bytes

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PUBLIC_KEY = FIXTURES / "release_test_public.json"
PRIVATE_KEY = FIXTURES / "release_test_private.json"


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "nested").mkdir()
        (self.root / "alpha.txt").write_bytes(b"alpha\n")
        (self.root / "nested" / "data.bin").write_bytes(bytes(range(64)))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *arguments: object, success: bool = True) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), *(str(item) for item in arguments)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if success:
            self.assertEqual(completed.returncode, 0, completed.stderr)
        else:
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
        return completed

    def create_and_sign(self) -> None:
        self.run_tool("create", self.root)
        self.run_tool(
            "sign",
            self.root / "release-manifest.json",
            "--private-key",
            PRIVATE_KEY,
        )

    def verify(self, success: bool = True) -> subprocess.CompletedProcess[str]:
        return self.run_tool(
            "verify", self.root, "--public-key", PUBLIC_KEY, success=success
        )

    def test_round_trip_is_canonical_and_signed(self) -> None:
        self.create_and_sign()
        raw = (self.root / "release-manifest.json").read_bytes()
        manifest = json.loads(raw)
        self.assertEqual(
            raw,
            (
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        self.assertEqual(
            [entry["path"] for entry in manifest["files"]],
            ["alpha.txt", "nested/data.bin"],
        )
        self.assertEqual(manifest["files"][0]["length"], 6)
        self.verify()

    def test_rejects_missing_extra_and_modified_files(self) -> None:
        for mutation in ("missing", "extra", "modified"):
            with self.subTest(mutation=mutation):
                self.create_and_sign()
                if mutation == "missing":
                    (self.root / "alpha.txt").unlink()
                elif mutation == "extra":
                    (self.root / "extra.txt").write_text("extra", encoding="utf-8")
                else:
                    (self.root / "alpha.txt").write_text("tampered", encoding="utf-8")
                self.verify(success=False)
                if mutation == "missing":
                    (self.root / "alpha.txt").write_bytes(b"alpha\n")
                elif mutation == "extra":
                    (self.root / "extra.txt").unlink()
                else:
                    (self.root / "alpha.txt").write_bytes(b"alpha\n")

    def test_rejects_duplicate_path_and_bad_signature(self) -> None:
        self.create_and_sign()
        path = self.root / "release-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["files"].append(dict(manifest["files"][0]))
        path.write_bytes(canonical_bytes(manifest))
        result = self.verify(success=False)
        self.assertIn("duplicate manifest path", result.stderr)

        self.run_tool("create", self.root)
        self.run_tool("sign", path, "--private-key", PRIVATE_KEY)
        signature = self.root / "release-manifest.sig"
        signature.write_text("A" + signature.read_text(encoding="ascii")[1:], encoding="ascii")
        result = self.verify(success=False)
        self.assertIn("signature", result.stderr)

    def test_rejects_noncanonical_manifest_and_missing_signature(self) -> None:
        self.run_tool("create", self.root)
        path = self.root / "release-manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        result = self.run_tool(
            "sign", path, "--private-key", PRIVATE_KEY, success=False
        )
        self.assertIn("canonically encoded", result.stderr)

        self.run_tool("create", self.root)
        result = self.verify(success=False)
        self.assertIn("signature", result.stderr)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_rejects_symlink_payload(self) -> None:
        outside = self.root.parent / "outside-release-file"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        result = self.run_tool("create", self.root, success=False)
        self.assertIn("contains a link", result.stderr)

    def test_rejects_hard_link_payload(self) -> None:
        source = self.root / "alpha.txt"
        linked = self.root / "linked.txt"
        try:
            os.link(source, linked)
        except OSError as exc:
            self.skipTest(f"hard-link creation unavailable: {exc}")
        result = self.run_tool("create", self.root, success=False)
        self.assertIn("hard-linked", result.stderr)


if __name__ == "__main__":
    unittest.main()
