import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverse_shell_decoy.summary import build_summary, markdown, safe


class SummaryTests(unittest.TestCase):
    def test_no_input_does_not_scan(self):
        with self.assertRaises(ValueError):
            build_summary({})

    def test_missing_providers_are_unknown_not_connected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cloud.json"
            path.write_text("{}")
            parsed = {"events": [{"event_id": "1", "timestamp_utc": "2026-10-29T12:00:00Z", "category": "identity"}],
                      "findings": [{"confidence": "low"}], "source_is_synthetic": False, "warnings": []}
            with patch("reverse_shell_decoy.cloud.analyze_cloud_logs", return_value=parsed):
                result = build_summary({"aws": str(path)})
        self.assertEqual(result["providers"]["render"]["status"], "not_supplied")
        self.assertEqual(result["non_demo_indicator_confidence_counts"], {"low": 1})
        self.assertFalse(result["automatic_actions"])
        self.assertIn("unknown coverage", markdown(result))

    def test_demo_excluded_from_real_indicator_counts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "demo.json"
            p.write_text("{}")
            with patch("reverse_shell_decoy.cloud.analyze_cloud_logs", return_value={"events": [], "findings": [{"confidence": "medium"}], "source_is_synthetic": True}):
                result = build_summary({"cloudflare": str(p)})
        self.assertEqual(result["non_demo_indicator_confidence_counts"], {})
        self.assertEqual(result["providers"]["cloudflare"]["status"], "synthetic_demo")

    def test_decoy_is_a_separate_source(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "audit.jsonl"
            p.write_text(json.dumps({"simulation": True, "event_type": "command", "session_id": "example", "verb": "cat", "blocked": True}) + "\n")
            result = build_summary({}, decoy_audit=str(p))
        self.assertEqual(result["decoy"]["commands"], 1)
        self.assertEqual(result["decoy"]["file_read_attempts"], 1)
        self.assertEqual(result["decoy"]["blocked"], 1)
        self.assertEqual(result["host"]["status"], "not_supplied")
        self.assertEqual(result["non_demo_indicator_confidence_counts"], {})

    def test_markdown_field_escaping(self):
        escaped = safe("![remote](https://example.invalid/x)\n<script>")
        self.assertNotIn("![remote]", escaped)
        self.assertNotIn("<script>", escaped)


if __name__ == "__main__":
    unittest.main()
