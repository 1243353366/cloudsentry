"""Regression tests verifying review 8 defect fixes."""
from __future__ import annotations

import os
import subprocess
import unittest

from reverse_shell_decoy import collectors
from reverse_shell_decoy.simulator import DecoySession, MAX_COMMANDS


class Review8FixesTests(unittest.TestCase):
    def test_item1_partial_cloud_status_when_truncated(self) -> None:
        """Item 1: partial cloud results carry customer_authorized_integration_partial."""
        result = collectors._result(
            provider="cloudflare",
            since="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
            events=[{"id": 1}],
            pages_fetched=1,
            truncated=True,
            warnings=[],
        )
        self.assertEqual(result["coverage"]["truncated"], True)
        self.assertEqual(result["integration_status"]["state"], "customer_authorized_integration_partial")
        self.assertEqual(result["integration_status"]["reason"], "bounded_read_only_request_truncated")

    def test_item2_deadline_unenforced_warning_when_socket_missing(self) -> None:
        """Item 2: deadline_unenforced warning is added to warnings list if socket not exposed."""
        class DummyResponse:
            def read(self, n: int) -> bytes:
                return b"fake-data"

        warnings: list[str] = []
        raw = collectors._read_response_bytes(DummyResponse(), warnings=warnings)
        self.assertEqual(raw, b"fake-data")
        self.assertTrue(any("deadline_unenforced" in w for w in warnings))

    def test_item4_execute_with_event_at_cap(self) -> None:
        """Item 4: DecoySession.execute_with_event returns (output, event) or None at cap."""
        session = DecoySession(persona="linux")
        output, event = session.execute_with_event("whoami")
        self.assertEqual(output, "root\n")
        self.assertIsNotNone(event)
        self.assertEqual(event["verb"], "whoami")

        # Fill to cap
        for _ in range(MAX_COMMANDS):
            session.events.append({"fake": True})
        
        capped_output, capped_event = session.execute_with_event("whoami")
        self.assertIn("maximum command count reached", capped_output)
        self.assertIsNone(capped_event)

    def test_item5_token_count_allowlist_numeric_type_requirement(self) -> None:
        """Item 5: token metric fields require numeric types; non-numeric values are pruned."""
        event = {
            "valid_token_count": 42,
            "valid_float_count": 3.14,
            "string_token_count": "100",
            "boolean_token_count": True,
            "nested_token_count": {"sub": 1},
            "other_field": "safe",
        }
        sanitized = collectors._sanitize_event(event, 0)
        self.assertEqual(sanitized.get("valid_token_count"), 42)
        self.assertEqual(sanitized.get("valid_float_count"), 3.14)
        self.assertNotIn("string_token_count", sanitized)
        self.assertNotIn("boolean_token_count", sanitized)
        self.assertNotIn("nested_token_count", sanitized)
        self.assertEqual(sanitized.get("other_field"), "safe")

    def test_item6_launcher_python_override_validation(self) -> None:
        """Item 6: launchers validate absolute executable path for CLOUDSENTRY_PYTHON."""
        launcher = os.path.join(os.path.dirname(__file__), "..", "scripts", "tarpit.sh")
        # Relative path must fail
        proc = subprocess.run(
            ["/bin/sh", launcher],
            env={"CLOUDSENTRY_PYTHON": "python3"},
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("must be an absolute path", proc.stderr)


if __name__ == "__main__":
    unittest.main()
