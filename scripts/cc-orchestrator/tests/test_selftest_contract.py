from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

import cc_orchestrator as orchestrator  # noqa: E402


class SelftestCliContractTests(unittest.TestCase):
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
