"""Tests for the bounded, JSON-only text-pattern trail."""
from __future__ import annotations

from hashlib import sha256
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.investigator import build_report
from reverse_shell_decoy.trail import TEXT_PATTERN_STATEMENT, build_trail, main


def _write_jsonl(path: Path, records: list[object]) -> Path:
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


class TrailTests(unittest.TestCase):
    def test_safe_classification_and_source_hashes_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command_hash = "a" * 64
            audit = _write_jsonl(
                root / "console.jsonl",
                [
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "interaction_observed": True,
                        "timestamp_utc": "2026-10-29T22:00:01Z",
                        "command_sha256": command_hash,
                        "blocked": True,
                        "language_indicator": "php",
                        "token_indicators": ["php_network_api", "process_api"],
                        "command": "not copied",
                        "args": ["not copied"],
                        "raw_payload": "not copied",
                        "credentials": "not copied",
                        "peer_ip": "203.0.113.19",
                        "remote_os": "not copied",
                        "skill_score": 99,
                    }
                ],
            )
            raw = audit.read_bytes()

            trail = build_trail([str(audit)])

            self.assertEqual(trail["authorization_status"], "not_established")
            self.assertEqual(trail["statement"], TEXT_PATTERN_STATEMENT)
            self.assertEqual(
                trail["source_references"],
                [{"source_index": 1, "source_file_sha256": sha256(raw).hexdigest()}],
            )
            event = trail["timeline"][0]
            self.assertEqual(event["command_sha256"], command_hash)
            self.assertEqual(event["language_indicator"], "php")
            self.assertEqual(event["token_indicators"], ["php_network_api", "process_api"])
            self.assertTrue(event["blocked"])
            self.assertEqual(event["timestamp_utc"], "2026-10-29T22:00:01Z")
            self.assertIn("source_file_sha256", event)
            self.assertIn("physical_line_sha256", event)
            self.assertEqual(trail["counts"]["language_indicators"], {"php": 1})
            self.assertEqual(
                trail["counts"]["token_indicators"],
                {"php_network_api": 1, "process_api": 1},
            )
            rendered = json.dumps(trail)
            for forbidden in (
                "not copied",
                "raw_payload",
                "credentials",
                "203.0.113.19",
                "remote_os",
                "skill_score",
            ):
                self.assertNotIn(forbidden, rendered)

    def test_invalid_language_and_token_fields_are_excluded_with_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = _write_jsonl(
                Path(directory) / "invalid.jsonl",
                [
                    {
                        "simulation": True,
                        "source": "in_memory_decoy",
                        "language_indicator": "php; arbitrary text",
                        "token_indicators": ["php_network_api", "anything_else"],
                        "payload": {"untrusted": ["nested"]},
                    },
                    {
                        "simulation": True,
                        "source": "in_memory_decoy",
                        "language_indicator": "python",
                        "token_indicators": ["php_network_api"] * 7,
                    },
                ],
            )

            report = build_report([str(audit)])
            trail = build_trail([str(audit)])

            self.assertNotIn("language_indicator", report["timeline"][0])
            self.assertNotIn("token_indicators", report["timeline"][0])
            self.assertEqual(report["timeline"][1]["language_indicator"], "python")
            self.assertNotIn("token_indicators", report["timeline"][1])
            warnings = report["counts"]["warning_counts"]
            self.assertEqual(warnings["invalid_language_indicator_excluded"], 1)
            self.assertEqual(warnings["invalid_token_indicators_excluded"], 2)
            self.assertEqual(trail["counts"]["language_indicators"], {"python": 1})
            self.assertEqual(trail["counts"]["token_indicators"], {})
            rendered = json.dumps(trail)
            self.assertNotIn("arbitrary text", rendered)
            self.assertNotIn("anything_else", rendered)
            self.assertNotIn("untrusted", rendered)

    def test_input_hash_is_retained_without_timestamp_when_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = _write_jsonl(
                Path(directory) / "local.jsonl",
                [
                    {
                        "simulation": True,
                        "source": "in_memory_decoy",
                        "input_sha256": "b" * 64,
                        "language_indicator": "unknown",
                        "token_indicators": [],
                    }
                ],
            )

            event = build_trail([str(audit)])["timeline"][0]

            self.assertEqual(event["input_sha256"], "b" * 64)
            self.assertNotIn("timestamp_utc", event)
            self.assertEqual(event["language_indicator"], "unknown")
            self.assertEqual(event["token_indicators"], [])

    def test_cli_emits_one_json_object_to_stdout_without_exec_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = _write_jsonl(
                Path(directory) / "audit.jsonl",
                [{"simulation": True, "source": "in_memory_decoy"}],
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), mock.patch.object(
                subprocess, "run", side_effect=AssertionError("exec")
            ), mock.patch("os.system", side_effect=AssertionError("exec")), contextlib.redirect_stdout(
                stdout
            ), contextlib.redirect_stderr(stderr):
                result = main(["--audit", str(audit)])

            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            parsed = json.loads(stdout.getvalue())
            self.assertEqual(parsed["authorization_status"], "not_established")
            self.assertEqual(stdout.getvalue().count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
