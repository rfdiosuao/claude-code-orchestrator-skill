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

    def test_error_defensively_freezes_nested_input(self) -> None:
        nested_input = {
            "metadata": {"blocked": True},
            "keys": ["PATH"],
            "set_like": {"alpha", "beta"},
        }
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details=nested_input,
            suggested_action="Remove the key from CCSwitch.",
        )

        nested_input["metadata"]["blocked"] = False
        nested_input["keys"].append("HOME")
        nested_input["set_like"].add("gamma")

        payload = error.to_dict()
        safe_details = payload["safe_details"]
        self.assertEqual(safe_details["metadata"], {"blocked": True})
        self.assertEqual(safe_details["keys"], ["PATH"])
        self.assertEqual(set(safe_details["set_like"]), {"alpha", "beta"})
        json.dumps(payload)

    def test_to_dict_returns_independent_nested_json_payload(self) -> None:
        error = RuntimeSecurityError(
            code="provider_env_forbidden",
            message="Provider environment contains a forbidden key.",
            safe_details={
                "metadata": {"blocked": True},
                "keys": ["PATH"],
                "set_like": {"alpha", "beta"},
            },
            suggested_action="Remove the key from CCSwitch.",
        )

        first_payload = error.to_dict()
        first_payload["safe_details"]["metadata"]["blocked"] = False
        first_payload["safe_details"]["keys"].append("HOME")
        first_payload["safe_details"]["set_like"].append("gamma")

        second_payload = error.to_dict()
        safe_details = second_payload["safe_details"]
        self.assertEqual(safe_details["metadata"], {"blocked": True})
        self.assertEqual(safe_details["keys"], ["PATH"])
        self.assertEqual(set(safe_details["set_like"]), {"alpha", "beta"})
        json.dumps(first_payload)
        json.dumps(second_payload)
