from __future__ import annotations

import json
import unittest

from _support import ORCHESTRATOR_DIR  # noqa: F401
from runtime_security import RuntimeSecurityError


class RuntimeSecurityErrorTests(unittest.TestCase):
    def test_error_has_stable_safe_payload(self) -> None:
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details={"keys": ["PATH"]},
            suggested_action="Remove the key from CCSwitch.",
        )
        self.assertEqual(error.to_dict()["code"], "provider_env_forbidden")
        self.assertNotIn("value", json.dumps(error.to_dict()).lower())
