from __future__ import annotations

from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

import cc_orchestrator as orchestrator  # noqa: E402


class SelftestCliContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_trusted_darwin_aliases_are_canonicalized_without_realpath(self) -> None:
        for alias in ("etc", "tmp", "var"):
            with self.subTest(alias=alias), patch.object(
                orchestrator, "_HOST_IS_DARWIN", True
            ), patch.object(
                orchestrator, "_open_posix_directory_fd", return_value=123
            ) as open_alias, patch.object(orchestrator.os, "close") as close_fd:
                canonical = orchestrator._canonical_posix_managed_path(
                    Path(f"/{alias}/fixture/private")
                )

            self.assertEqual(
                canonical, Path(f"/private/{alias}/fixture/private")
            )
            open_alias.assert_called_once_with(Path("/") / alias)
            close_fd.assert_called_once_with(123)

    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_darwin_alias_fails_closed_when_system_identity_is_untrusted(
        self,
    ) -> None:
        details = SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o755,
            st_uid=501,
            st_dev=1,
            st_ino=2,
            st_ctime_ns=3,
        )
        with patch.object(
            orchestrator.os, "stat", return_value=details
        ), patch.object(
            orchestrator.os, "readlink", return_value="private/var"
        ):
            with self.assertRaisesRegex(
                orchestrator.OrchestratorError, "not trusted"
            ):
                orchestrator._darwin_root_alias_evidence(42, "var")

    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_darwin_alias_rejects_noncanonical_link_text(self) -> None:
        details = SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o755,
            st_uid=0,
            st_dev=1,
            st_ino=2,
            st_ctime_ns=3,
        )
        with patch.object(
            orchestrator.os, "stat", return_value=details
        ), patch.object(
            orchestrator.os,
            "readlink",
            return_value="private/../private/var",
        ):
            with self.assertRaisesRegex(
                orchestrator.OrchestratorError, "not trusted"
            ):
                orchestrator._darwin_root_alias_evidence(42, "var")

    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_darwin_compatibility_never_resolves_arbitrary_ancestors(self) -> None:
        with (
            patch.object(orchestrator, "_HOST_IS_DARWIN", True),
            patch.object(orchestrator, "_open_posix_directory_fd") as open_alias,
        ):
            canonical = orchestrator._canonical_posix_managed_path(
                Path("/Users/fixture/project/linked/artifact")
            )

        self.assertEqual(
            canonical, Path("/Users/fixture/project/linked/artifact")
        )
        open_alias.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_security_audit_identity_is_stable_across_darwin_aliases(self) -> None:
        with patch.object(
            orchestrator, "_HOST_IS_DARWIN", True
        ), patch.object(
            orchestrator, "_open_posix_directory_fd", return_value=123
        ), patch.object(
            orchestrator,
            "_darwin_volume_is_case_sensitive",
            return_value=False,
        ), patch.object(orchestrator.os, "close"):
            aliased = orchestrator._security_audit_paths(
                Path("/var/folders/fixture/artifacts")
            )
            canonical = orchestrator._security_audit_paths(
                Path("/private/var/folders/fixture/artifacts")
            )

        self.assertEqual(aliased["root"], canonical["root"])
        self.assertEqual(aliased["bootstrap_failures"], canonical["bootstrap_failures"])

    @unittest.skipUnless(os.name == "posix", "Darwin audit identity contract")
    def test_security_audit_identity_preserves_raw_tail_components(
        self,
    ) -> None:
        with patch.object(orchestrator, "_HOST_IS_DARWIN", True):
            upper = Path("/private/var/Project/Artifacts")
            lower = Path("/private/var/project/artifacts")
            self.assertNotEqual(
                orchestrator._security_audit_root_identity(upper),
                orchestrator._security_audit_root_identity(lower),
            )

    @unittest.skipUnless(os.name == "posix", "Darwin audit identity contract")
    def test_security_audit_identity_uses_length_delimited_tail(
        self,
    ) -> None:
        with patch.object(orchestrator, "_HOST_IS_DARWIN", True):
            upper = Path("/private/var/project/ab/c")
            lower = Path("/private/var/project/a/bc")
            self.assertNotEqual(
                orchestrator._security_audit_root_identity(upper),
                orchestrator._security_audit_root_identity(lower),
            )

    @unittest.skipUnless(
        orchestrator._HOST_IS_DARWIN, "Darwin volume capability contract"
    )
    def test_darwin_volume_case_query_matches_observed_filesystem(self) -> None:
        with tempfile.TemporaryDirectory(prefix="darwin-case-volume-") as temp:
            root = Path(temp)
            probe = root / "CaseProbe"
            probe.write_text("probe", encoding="utf-8")
            observed_sensitive = not (root / "caseprobe").exists()

            self.assertEqual(
                orchestrator._darwin_volume_is_case_sensitive(root),
                observed_sensitive,
            )

    @unittest.skipUnless(os.name == "posix", "Darwin path aliases are POSIX-only")
    def test_darwin_system_anchor_case_variants_are_rejected(self) -> None:
        with patch.object(orchestrator, "_HOST_IS_DARWIN", True):
            for path in (Path("/VAR/fixture"), Path("/Private/TMP/fixture")):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(
                        orchestrator.OrchestratorError, "canonical lowercase"
                    ):
                        orchestrator._canonical_posix_managed_path(path)
                    with self.assertRaisesRegex(
                        orchestrator.OrchestratorError, "canonical lowercase"
                    ):
                        orchestrator._posix_directory_components(path, 42)

    @unittest.skipUnless(os.name == "posix", "POSIX mkdirat safety contract")
    def test_private_directory_creation_rejects_linked_ancestor_before_side_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="posix-link-parent-") as temp:
            root = Path(temp).resolve()
            outside = root / "outside"
            outside.mkdir()
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            escaped = outside / "must-not-exist"

            with self.assertRaises(orchestrator.OrchestratorError):
                orchestrator._set_private_directory(linked / escaped.name)

            self.assertFalse(escaped.exists())

    @unittest.skipUnless(
        orchestrator._HOST_IS_DARWIN, "Darwin anchor safety contract"
    )
    def test_darwin_system_anchor_cannot_be_created_or_privatized(self) -> None:
        for alias in ("etc", "tmp", "var"):
            with self.subTest(alias=alias), self.assertRaisesRegex(
                orchestrator.OrchestratorError,
                "cannot be used as managed private directories",
            ):
                orchestrator._set_private_directory(Path("/") / alias)
            for anchor in (Path("/") / alias, Path("/private") / alias):
                with self.subTest(writable_anchor=anchor), self.assertRaisesRegex(
                    orchestrator.OrchestratorError, "cannot be made writable"
                ):
                    with orchestrator._open_posix_managed_directory(
                        anchor, writable=True, verify_private=False
                    ):
                        self.fail("Darwin system anchor was opened writable")

    def test_selftest_fails_when_production_containment_is_unavailable(self) -> None:
        containment = {
            "supported": False,
            "mechanism": None,
            "reason": "fixture unavailable",
            "test_only": False,
        }
        with patch.object(
            orchestrator,
            "runtime_tree_containment_support",
            return_value=containment,
        ):
            result = orchestrator.selftest()

        self.assertFalse(result["ok"], result)
        self.assertFalse(
            result["checks"]["runtime_process_tree_containment"]
        )
        self.assertEqual(
            result["runtime_security"]["process_tree_containment"],
            containment,
        )

    def test_mock_stream_artifacts_use_absolute_private_temp_and_clean_by_default(
        self,
    ) -> None:
        parent = orchestrator._mock_stream_parent()
        self.assertTrue(parent.is_absolute(), parent)
        if os.name != "nt":
            self.assertEqual(
                parent.parent,
                Path(tempfile.gettempdir()).resolve(),
            )
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CC_ORCHESTRATOR_CLEAN_MOCK_DIR", None)
            self.assertTrue(orchestrator._mock_stream_cleanup_enabled())
        with patch.dict(
            os.environ, {"CC_ORCHESTRATOR_CLEAN_MOCK_DIR": "0"}
        ):
            self.assertFalse(orchestrator._mock_stream_cleanup_enabled())

    def test_mock_stream_initialization_failure_removes_private_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="mock-init-cleanup-") as temp:
            parent = Path(temp).resolve()
            with (
                patch.object(
                    orchestrator, "_mock_stream_parent", return_value=parent
                ),
                patch.object(
                    orchestrator,
                    "write_fake_claude_launcher",
                    side_effect=OSError("fixture launcher failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    OSError, "fixture launcher failure"
                ):
                    orchestrator.mock_stream_test(timeout_seconds=1)
            self.assertEqual(list(parent.iterdir()), [])

    def test_mock_stream_cleanup_retries_transient_directory_use(self) -> None:
        path = Path(tempfile.gettempdir()) / "mock-cleanup-retry-fixture"
        with patch.object(
            orchestrator.shutil,
            "rmtree",
            side_effect=[PermissionError("fixture busy"), None],
        ) as remove:
            orchestrator._remove_mock_stream_directory(path)
        self.assertEqual(remove.call_count, 2)

    def test_cli_returns_nonzero_when_any_selftest_gate_fails(self) -> None:
        result = {"ok": False, "checks": {"fixture_gate": False}}
        with (
            patch.object(orchestrator, "selftest", return_value=result),
            patch.object(orchestrator, "print_json") as print_json,
            patch.object(sys, "argv", ["cc_orchestrator.py", "selftest"]),
        ):
            self.assertEqual(orchestrator.main(), 1)
        print_json.assert_called_once_with(result)

    def test_mock_stream_cli_uses_release_timeout_and_fails_closed(self) -> None:
        result = {"ok": False, "gates": {"fixture_gate": False}}
        with (
            patch.object(
                orchestrator, "mock_stream_test", return_value=result
            ) as mock_stream_test,
            patch.object(orchestrator, "print_json") as print_json,
            patch.object(sys, "argv", ["cc_orchestrator.py", "mock-stream-test"]),
        ):
            self.assertEqual(orchestrator.main(), 1)
        mock_stream_test.assert_called_once_with(timeout_seconds=60)
        print_json.assert_called_once_with(result)


if __name__ == "__main__":
    unittest.main()
