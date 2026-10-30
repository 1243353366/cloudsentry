import json
from pathlib import Path
import tempfile
import unittest

from reverse_shell_decoy.operations import build_operations_summary
from reverse_shell_decoy.summary import build_summary


class OperationsRegressionTests(unittest.TestCase):
    def test_unhashable_phase_and_overflowing_utc_are_discarded(self):
        records = [
            {"event_type": "service_budget", "source_kind": "decoy_service_control", "interaction_observed": False,
             "phase": [], "timestamp_utc": "2026-10-30T00:00:00Z"},
            {"event_type": "connecting", "session_id": "session", "timestamp_utc": "0001-01-01T00:00:00+23:59"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in records) + "\n")
            result = build_operations_summary(str(path))
        self.assertEqual(result["audit"]["accepted_records"], 0)
        self.assertEqual(result["audit"]["discarded_records"]["invalid_or_unsupported_record"], 2)

    def test_budget_control_is_not_a_visitor_session(self):
        records = [
            {"simulation": True, "event_type": "service_budget", "source_kind": "decoy_service_control", "session_id": "service"},
            {"simulation": True, "event_type": "connecting", "source_kind": "decoy_service_interaction", "session_id": "visitor-session"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in records) + "\n")
            result = build_summary({}, decoy_audit=str(path))
        self.assertEqual(result["decoy"]["sessions"], 1)

    def test_fractional_timestamp_order_is_chronological(self):
        records = [
            {"event_type": "connecting", "session_id": "session", "timestamp_utc": "2026-10-30T00:00:00.1Z"},
            {"event_type": "close", "session_id": "session", "timestamp_utc": "2026-10-30T00:00:00Z"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in records) + "\n")
            result = build_operations_summary(str(path))
        self.assertEqual(result["audit"]["first_valid_timestamp_utc"], "2026-10-30T00:00:00.000000Z")
        self.assertEqual(result["audit"]["last_valid_timestamp_utc"], "2026-10-30T00:00:00.100000Z")


if __name__ == "__main__":
    unittest.main()
