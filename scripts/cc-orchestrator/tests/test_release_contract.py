from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_VERSION = "0.8.0"
AUDIT_KEY_NAME = "runtime_security.audit.key"


def read_text(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def read_json(relative: str) -> object:
    return json.loads(read_text(relative))


def workflow_paths(workflow: str, event: str) -> set[str]:
    lines = workflow.splitlines()
    event_line = f"  {event}:"
    try:
        event_start = lines.index(event_line)
    except ValueError as exc:
        raise AssertionError(f"workflow trigger {event!r} is missing") from exc

    event_end = len(lines)
    for index in range(event_start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            event_end = index
            break
        if line.startswith("  ") and not line.startswith("    "):
            event_end = index
            break

    try:
        paths_start = lines.index("    paths:", event_start + 1, event_end)
    except ValueError as exc:
        raise AssertionError(f"workflow trigger {event!r} has no paths filter") from exc

    paths: set[str] = set()
    for line in lines[paths_start + 1 : event_end]:
        match = re.match(r"^      -\s+(.+?)\s*$", line)
        if match:
            paths.add(match.group(1).strip("'\""))
        elif line.strip():
            break
    return paths


class ReleaseContractTests(unittest.TestCase):
    def test_release_manifests_match_guarded_runtime_release(self) -> None:
        root_manifest = read_json("version.json")
        portable_manifest = read_json("scripts/cc-orchestrator/version.json")

        self.assertEqual(root_manifest, portable_manifest)
        self.assertIsInstance(root_manifest, dict)
        self.assertEqual(root_manifest["version"], EXPECTED_VERSION)
        self.assertEqual(root_manifest["released_at"], "2026-07-18")
        notes = root_manifest["notes"]
        self.assertIsInstance(notes, list)
        self.assertIn("guarded runtime", " ".join(notes).lower())

    def test_package_metadata_matches_release_and_pins_vite_override(self) -> None:
        package = read_json("package.json")
        package_lock = read_json("package-lock.json")

        self.assertEqual(package["version"], EXPECTED_VERSION)
        self.assertEqual(package_lock["version"], EXPECTED_VERSION)
        self.assertEqual(package_lock["packages"][""]["version"], EXPECTED_VERSION)
        self.assertEqual(package["overrides"]["vite"], "6.4.3")

    def test_readmes_show_current_release_in_badge_and_version_label(self) -> None:
        expectations = {
            "README.md": r"Current version:\s*v?0\.8\.0",
            "README.zh-CN.md": r"当前版本[：:]\s*v?0\.8\.0",
        }
        for relative, current_version_pattern in expectations.items():
            with self.subTest(readme=relative):
                readme = read_text(relative)
                self.assertRegex(
                    readme,
                    r"img\.shields\.io/badge/version-v?0\.8\.0(?:[-/?#\"'])",
                )
                self.assertRegex(readme, current_version_pattern)

    def test_runtime_workflow_contains_complete_release_gate(self) -> None:
        workflow = read_text(".github/workflows/runtime-checks.yml")
        required_commands = (
            "python -m unittest discover -s scripts/cc-orchestrator/tests -v",
            "python -m unittest -v\n          test_process_identity",
            "test_guarded_launch.TenthReviewPosixPathEncodingTests",
            "Verify production selftest fails closed",
            "python scripts/cc-orchestrator/cc_orchestrator.py mock-stream-test --timeout-seconds 60",
            "npm run docs:build",
            "npm audit --audit-level=moderate",
        )
        for command in required_commands:
            with self.subTest(command=command):
                self.assertIn(command, workflow)
        self.assertIn("runs-on: windows-latest", workflow)
        self.assertIn("runtime-posix:", workflow)
        self.assertIn("if: runner.os == 'Linux'", workflow)

        required_paths = {
            "install/**",
            "docs/superpowers/**",
            "docs-site/**",
            "SKILL.md",
            ".gitignore",
            ".github/workflows/deploy-docs.yml",
        }
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                missing_paths = required_paths - workflow_paths(workflow, event)
                self.assertEqual(
                    missing_paths,
                    set(),
                    f"{event} paths are missing {sorted(missing_paths)}",
                )
        self.assertIn(
            'git diff --check "${{ github.event.before }}" "${{ github.sha }}"',
            workflow,
        )

    def test_installers_exclude_audit_key_without_preserving_it(self) -> None:
        powershell = read_text("install/install.ps1")
        powershell_copy = powershell.split("robocopy ", 1)[1].split(
            "if ($LASTEXITCODE", 1
        )[0]
        self.assertIn("/XF", powershell_copy)
        self.assertIn(AUDIT_KEY_NAME, powershell_copy.split("/XF", 1)[1])
        powershell_preserve = powershell.split("$preserveRelative = @(", 1)[1].split(
            "\n)", 1
        )[0]
        self.assertNotIn(AUDIT_KEY_NAME, powershell_preserve)

        shell = read_text("install/install.sh")
        shell_copy, shell_preserve_tail = shell.split("for relative in \\", 1)
        self.assertRegex(
            shell_copy,
            rf"--exclude(?:=|\s+)[\"']{re.escape(AUDIT_KEY_NAME)}[\"']",
        )
        shell_preserve = shell_preserve_tail.split("; do", 1)[0]
        self.assertNotIn(AUDIT_KEY_NAME, shell_preserve)

    def test_docs_deploy_waits_for_successful_main_runtime_checks(self) -> None:
        workflow = read_text(".github/workflows/deploy-docs.yml")
        for contract in (
            "workflow_run:",
            "- Runtime checks",
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.head_branch == 'main'",
            "cancel-in-progress: false",
            "ref: ${{ github.event.workflow_run.head_sha }}",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertEqual(
            workflow.count("EXPECTED_SHA: ${{ github.event.workflow_run.head_sha }}"),
            2,
        )
        self.assertEqual(
            workflow.count(
                'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"'
            ),
            2,
        )
        for contract in (
            "Verify production selftest fails closed",
            "assert completed.returncode != 0",
            'payload["runtime_security"]["process_tree_containment"]',
            'assert containment["supported"] is False',
            'assert containment["mechanism"] is None',
            'assert containment["test_only"] is False',
        ):
            with self.subTest(posix_selftest_contract=contract):
                self.assertIn(contract, workflow)

    def test_public_docs_state_the_guarded_execution_platform_boundary(self) -> None:
        expectations = {
            "README.md": "Production guarded worker execution is currently Windows-only",
            "README.zh-CN.md": "生产级 guarded worker 执行目前仅支持 Windows",
            "docs-site/changelog.md": "Production guarded worker execution is currently Windows-only",
            "docs-site/zh/changelog.md": "生产级 guarded worker 执行目前仅支持 Windows",
        }
        for relative, notice in expectations.items():
            with self.subTest(document=relative):
                self.assertIn(notice, read_text(relative))

    def test_public_docs_limit_mock_mcp_to_local_stdio(self) -> None:
        expectations = {
            "SKILL.md": "local same-user `stdio` diagnostics only",
            "scripts/cc-orchestrator/README.md": "local, same-user `stdio` process",
            "docs-site/guide/mcp.md": "local, same-user `stdio` only",
            "docs-site/zh/guide/mcp.md": "仅限本机、同一用户的 `stdio`",
        }
        for relative, notice in expectations.items():
            with self.subTest(document=relative):
                document = read_text(relative)
                self.assertIn(notice, document)
                self.assertIn("cc_mock_stream_test", document)

    def test_mock_mcp_tool_requires_explicit_local_diagnostics_opt_in(self) -> None:
        runtime_root = REPO_ROOT / "scripts" / "cc-orchestrator"
        probe = (
            "import server; "
            "print(int('cc_mock_stream_test' in "
            "server.mcp._tool_manager._tools))"
        )

        def registered(value: str | None) -> bool:
            environment = os.environ.copy()
            environment.pop(
                "CC_ORCHESTRATOR_ENABLE_LOCAL_DIAGNOSTICS", None
            )
            if value is not None:
                environment[
                    "CC_ORCHESTRATOR_ENABLE_LOCAL_DIAGNOSTICS"
                ] = value
            completed = subprocess.run(
                [sys.executable, "-c", probe],
                cwd=runtime_root,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
            )
            return completed.stdout.strip() == "1"

        self.assertFalse(registered(None))
        self.assertFalse(registered("0"))
        self.assertTrue(registered("1"))

    def test_public_install_commands_use_immutable_fork_release_tag(self) -> None:
        documents = (
            "README.md",
            "README.zh-CN.md",
            "docs-site/guide/getting-started.md",
            "docs-site/zh/guide/getting-started.md",
        )
        release_archive = (
            "https://github.com/rfdiosuao/"
            "claude-code-orchestrator-skill/archive/refs/tags/v0.8.0.zip"
        )
        for relative in documents:
            with self.subTest(document=relative):
                document = read_text(relative)
                self.assertIn(release_archive, document)
                self.assertIn("SHA-256", document)
                self.assertNotIn("archive/refs/heads/main.zip", document)


if __name__ == "__main__":
    unittest.main()
