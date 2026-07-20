from __future__ import annotations

from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

import cc_orchestrator as orchestrator  # noqa: E402


class SelftestCliContractTests(unittest.TestCase):
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
