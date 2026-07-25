from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _support import ORCHESTRATOR_DIR  # noqa: F401

import cc_orchestrator as orchestrator
import server


class RepairMcpPathsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="managed-mcp-")
        self.root = Path(self.temporary.name)
        self.artifact_root = (
            self.root
            / orchestrator.AGENT_WORKSPACE_DIRNAME
            / orchestrator.ARTIFACT_NAMESPACE
        )
        self.artifact_root.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_rejects_non_root_and_unsafe_mcp_paths(self) -> None:
        candidates = (
            str(self.root / ".mcp.json"),
            "../.mcp.json",
            "nested/.mcp.json",
            "other.json",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(orchestrator.OrchestratorError):
                    orchestrator.repair_mcp_paths(
                        cwd=self.root, mcp_path=candidate, create=True
                    )

    def test_requires_an_existing_initialized_workspace(self) -> None:
        uninitialized = self.root / "uninitialized"
        uninitialized.mkdir()
        with self.assertRaisesRegex(
            orchestrator.OrchestratorError, "not initialized"
        ):
            orchestrator.repair_mcp_paths(cwd=uninitialized, create=True)

    def test_dry_run_does_not_create_file(self) -> None:
        result = orchestrator.repair_mcp_paths(
            cwd=self.root, create=True, apply=False
        )
        self.assertTrue(result["changed"])
        self.assertFalse(result["applied"])
        self.assertFalse((self.root / ".mcp.json").exists())

    def test_apply_atomically_writes_root_mcp_file(self) -> None:
        result = orchestrator.repair_mcp_paths(
            cwd=self.root, mcp_path=".mcp.json", create=True, apply=True
        )
        target = self.root / ".mcp.json"
        self.assertTrue(result["applied"])
        self.assertEqual(Path(result["path"]), target)
        payload = json.loads(target.read_text(encoding="utf-8"))
        env = payload["claude-code-orchestrator"]["env"]
        self.assertEqual(env["CC_ORCHESTRATOR_WORKSPACE_ROOT"], str(self.root))
        self.assertFalse(list(self.root.glob("..mcp.json.*.tmp")))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_rejects_symlink_target(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        target = self.root / ".mcp.json"
        try:
            target.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(
            orchestrator.OrchestratorError, "symlink or reparse"
        ):
            orchestrator.repair_mcp_paths(cwd=self.root, apply=True)

    def test_rejects_hard_link_target(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text('{"secret":"must-not-be-backed-up"}', encoding="utf-8")
        target = self.root / ".mcp.json"
        try:
            os.link(outside, target)
        except OSError as exc:
            self.skipTest(f"hard-link creation unavailable: {exc}")
        with self.assertRaisesRegex(orchestrator.OrchestratorError, "hard link"):
            orchestrator.repair_mcp_paths(cwd=self.root, apply=True)
        self.assertFalse(list(self.root.glob(".mcp.json.backup.*")))

    def test_backups_are_unique_within_one_second(self) -> None:
        target = self.root / ".mcp.json"
        target.write_text("{}", encoding="utf-8")
        first = orchestrator.repair_mcp_paths(cwd=self.root, apply=True)
        target.write_text("{}", encoding="utf-8")
        second = orchestrator.repair_mcp_paths(cwd=self.root, apply=True)
        self.assertNotEqual(first["backup_path"], second["backup_path"])
        self.assertTrue(Path(first["backup_path"]).is_file())
        self.assertTrue(Path(second["backup_path"]).is_file())

    def test_mcp_entry_uses_the_shared_service_validation(self) -> None:
        params = server.RepairMcpPathsInput(
            cwd=str(self.root),
            mcp_path="../.mcp.json",
            create=True,
            apply=True,
        )
        result = json.loads(asyncio.run(server.cc_repair_mcp_paths(params)))
        self.assertFalse(result["ok"])
        self.assertIn("must not contain", result["error"])
        self.assertFalse((self.root.parent / ".mcp.json").exists())


if __name__ == "__main__":
    unittest.main()
