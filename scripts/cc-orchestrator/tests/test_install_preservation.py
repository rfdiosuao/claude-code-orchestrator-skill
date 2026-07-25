from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_ROOT = REPO_ROOT / "scripts" / "cc-orchestrator"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

import cc_orchestrator as orchestrator  # noqa: E402


SKILL_RELATIVE = Path("skills") / "claude-code-orchestrator"
OVERRIDE_RELATIVE = (
    Path("scripts")
    / "cc-orchestrator"
    / "config"
    / "runtime_security.override.json"
)
AUDIT_KEY_NAME = "runtime_security.audit.key"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class InstallerPreservationTests(unittest.TestCase):
    def test_both_installers_preserve_only_the_installed_runtime_override(self) -> None:
        powershell = (REPO_ROOT / "install" / "install.ps1").read_text(
            encoding="utf-8"
        )
        shell = (REPO_ROOT / "install" / "install.sh").read_text(encoding="utf-8")
        powershell_copy = next(
            line for line in powershell.splitlines() if line.startswith("robocopy ")
        )
        powershell_preserve = powershell.split("$preserveRelative = @(", 1)[1].split(
            "\n)", 1
        )[0]
        shell_copy = shell.split("for relative in \\", 1)[0]
        shell_preserve = shell.split("for relative in \\", 1)[1].split("; do", 1)[0]
        for copy_section, preserve_section in (
            (powershell_copy, powershell_preserve),
            (shell_copy, shell_preserve),
        ):
            self.assertIn("runtime_security.override.json", copy_section)
            self.assertIn(AUDIT_KEY_NAME, copy_section)
            self.assertIn("runtime_security.override.json", preserve_section)
            self.assertNotIn(AUDIT_KEY_NAME, preserve_section)

    def test_release_manifests_agree_and_declare_runtime_override(self) -> None:
        root_manifest = json.loads(
            (REPO_ROOT / "version.json").read_text(encoding="utf-8")
        )
        portable_manifest = json.loads(
            (REPO_ROOT / "scripts" / "cc-orchestrator" / "version.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(root_manifest, portable_manifest)
        self.assertIn(
            "scripts/cc-orchestrator/config/runtime_security.override.json",
            root_manifest["local_user_owned_files"],
        )
        self.assertNotIn(
            f"scripts/cc-orchestrator/config/{AUDIT_KEY_NAME}",
            root_manifest["local_user_owned_files"],
        )
        self.assertIn(
            f"**/{AUDIT_KEY_NAME}",
            (REPO_ROOT / ".gitignore").read_text(encoding="utf-8"),
        )

    def test_native_installer_preserves_override_and_ignores_workspace_audit_key(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="cco-install-test-") as temp_dir:
            root = Path(temp_dir)
            codex_home = root / "codex-home"
            installed_override = codex_home / SKILL_RELATIVE / OVERRIDE_RELATIVE
            installed_override.parent.mkdir(parents=True)
            override_payload = b'{"selftest":"preserve-me"}\n'
            installed_override.write_bytes(override_payload)

            audit_key = (
                root
                / "project"
                / ".agent-workspace"
                / "claude-code-orchestrator"
                / "config"
                / AUDIT_KEY_NAME
            )
            audit_key.parent.mkdir(parents=True)
            audit_payload = bytes(range(32))
            audit_key.write_bytes(audit_payload)
            before_override = digest(override_payload)
            before_audit = digest(audit_payload)

            release_root = root / "release"
            shutil.copytree(
                REPO_ROOT,
                release_root,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".agent-workspace",
                    "node_modules",
                    "__pycache__",
                    "*.pyc",
                ),
            )
            source_canary_root = release_root / ".cco-audit-key-canary"
            source_canary = source_canary_root / "custom-artifacts" / AUDIT_KEY_NAME
            source_canary.parent.mkdir(parents=True)
            source_canary.write_bytes(audit_payload)
            manifest_tool = release_root / "scripts" / "release_manifest.py"
            private_key = (
                release_root
                / "scripts"
                / "cc-orchestrator"
                / "tests"
                / "fixtures"
                / "release_test_private.json"
            )
            public_key = private_key.with_name("release_test_public.json")
            subprocess.run(
                [sys.executable, str(manifest_tool), "create", str(release_root)],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(manifest_tool),
                    "sign",
                    str(release_root / "release-manifest.json"),
                    "--private-key",
                    str(private_key),
                ],
                check=True,
            )

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["CC_ORCHESTRATOR_ARTIFACT_ROOT"] = str(audit_key.parent.parent)
            if os.name == "nt":
                powershell = shutil.which("pwsh") or shutil.which("powershell")
                if powershell is None:
                    self.fail("PowerShell is required by the Windows installer test")
                command = [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(release_root / "install" / "install.ps1"),
                    "-CodexHome",
                    str(codex_home),
                    "-TrustedPublicKey",
                    str(public_key),
                ]
            else:
                bash = shutil.which("bash")
                rsync = shutil.which("rsync")
                if bash is None or rsync is None:
                    self.fail("bash and rsync are required by the POSIX installer test")
                env["CODEX_HOME"] = str(codex_home)
                command = [
                    bash,
                    str(release_root / "install" / "install.sh"),
                    str(public_key),
                ]

            try:
                completed = subprocess.run(
                    command,
                    cwd=audit_key.parents[3],
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=180,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stdout + completed.stderr,
                )
                self.assertEqual(
                    digest(installed_override.read_bytes()), before_override
                )
                self.assertEqual(digest(audit_key.read_bytes()), before_audit)
                self.assertEqual(digest(source_canary.read_bytes()), before_audit)
                installed_root = codex_home / SKILL_RELATIVE
                self.assertEqual(list(installed_root.rglob(AUDIT_KEY_NAME)), [])
            finally:
                shutil.rmtree(source_canary_root, ignore_errors=True)

    def test_upgrade_receipt_includes_runtime_override_but_not_audit_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cco-upgrade-receipt-") as temp_dir:
            root = Path(temp_dir)
            policy = root / "runtime_security.override.json"
            state = root / "version_state.json"
            policy.write_bytes(b'{"fixture":"policy"}\n')
            with (
                patch.object(orchestrator, "RUNTIME_SECURITY_POLICY_PATH", policy),
                patch.object(orchestrator, "VERSION_STATE_PATH", state),
            ):
                receipt = orchestrator.upgrade_check(apply=True)
            runtime_items = [
                item
                for item in receipt["preserved_files"]
                if item["path"] == str(policy)
            ]
            self.assertEqual(len(runtime_items), 1)
            self.assertTrue(runtime_items[0]["exists"])
            self.assertEqual(runtime_items[0]["sha256"], digest(policy.read_bytes()))
            self.assertTrue(
                any(
                    action["type"] == "preserve_runtime_security_override"
                    for action in receipt["actions"]
                )
            )
            self.assertNotIn(AUDIT_KEY_NAME, json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
