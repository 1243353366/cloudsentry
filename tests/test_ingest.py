"""Tests for bounded, local-only untrusted log imports."""
from __future__ import annotations

from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.ingest import ingest_logs, ingest_pasted


class IngestLogsTests(unittest.TestCase):
    def test_text_import_hashes_raw_input_redacts_and_preserves_source_timestamp(self) -> None:
        raw = b"2026-01-02T03:04:05Z Authorization: Bearer very-secret-token\nplain line\n"
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "operator.log"
            log.write_bytes(raw)

            result = ingest_logs(log)

        self.assertEqual(result["filename"], "operator.log")
        self.assertEqual(result["sha256"], sha256(raw).hexdigest())
        self.assertEqual(result["source_kind"], "imported_real_log")
        self.assertFalse(result["simulation"])
        self.assertTrue(result["ingested_at"].endswith("Z"))
        self.assertEqual(result["record_count"], 2)
        first = result["records"][0]
        self.assertEqual(first["line_number"], 1)
        self.assertEqual(first["timestamp"], "2026-01-02T03:04:05Z")
        self.assertNotIn("very-secret-token", first["message"])
        self.assertIn("[REDACTED]", first["message"])
        self.assertEqual(first["record_sha256"], sha256(raw.splitlines(keepends=True)[0]).hexdigest())
        self.assertTrue(any("untrusted" in notice.lower() for notice in result["notices"]))
        self.assertTrue(any("identity" in notice.lower() for notice in result["notices"]))

    def test_jsonl_filters_fields_redacts_and_warns_without_crashing(self) -> None:
        valid = {
            "timestamp": "2025-06-01T12:00:00+00:00",
            "time": 1_748_779_200,
            "event": "connection",
            "pid": 42,
            "message": "password=hunter2",
            "source_ip": "198.51.100.20",
            "remote_address": "203.0.113.8",
            "remote_port": 443,
            "local_address": "192.0.2.44",
            "local_port": 51515,
            "session_id": "audit-session-1",
            "input_sha256": "a" * 64,
            "event_id": "evt-1",
            "claimed_os": "unverified-client-os",
            "inferred_os": "unverified-heuristic-os",
            "simulation": True,
            "hostname": "not-retained",
            "username": "not-retained",
            "args": ["not-retained"],
            "env": {"TOKEN": "not-retained"},
        }
        raw = (json.dumps(valid) + "\nnot json\n[\"not an object\"]\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "events.jsonl"
            log.write_bytes(raw)
            result = ingest_logs(log, format="jsonl")

        self.assertEqual(result["sha256"], sha256(raw).hexdigest())
        self.assertEqual(result["record_count"], 1)
        record = result["records"][0]
        self.assertEqual(record["timestamp"], "2025-06-01T12:00:00+00:00")
        self.assertEqual(record["time"], 1_748_779_200)
        self.assertEqual(record["event"], "connection")
        self.assertEqual(record["pid"], 42)
        self.assertEqual(record["source_ip"], "198.51.100.20")
        self.assertEqual(record["remote_address"], "203.0.113.8")
        self.assertEqual(record["remote_port"], 443)
        self.assertEqual(record["local_address"], "192.0.2.44")
        self.assertEqual(record["local_port"], 51515)
        self.assertEqual(record["session_id"], "audit-session-1")
        self.assertEqual(record["input_sha256"], "a" * 64)
        self.assertEqual(record["event_id"], "evt-1")
        self.assertEqual(record["claimed_os"], "unverified-client-os")
        self.assertEqual(record["inferred_os"], "unverified-heuristic-os")
        self.assertTrue(record["simulation"])
        self.assertNotIn("hunter2", record["message"])
        self.assertNotIn("hostname", record)
        self.assertNotIn("username", record)
        self.assertNotIn("args", record)
        self.assertNotIn("env", record)
        self.assertEqual(len(result["warnings"]), 2)
        self.assertTrue(all("line" in warning for warning in result["warnings"]))
        notices = " ".join(result["notices"]).lower()
        self.assertIn("unverified claims", notices)
        self.assertIn("root simulation:false", notices)

    def test_deeply_nested_jsonl_is_malformed_not_an_exception_or_echo(self) -> None:
        # json.loads can raise RecursionError for adversarial nesting.  The C JSON
        # parser's exact nesting behavior varies by Python build, so force that
        # documented decoder failure path deterministically here.
        nested = b'{"message":"untrusted nested input"}\n'
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "nested.jsonl"
            log.write_bytes(nested)
            with patch(
                "reverse_shell_decoy.ingest.json.loads", side_effect=RecursionError
            ):
                result = ingest_logs(log, format="jsonl")

        self.assertEqual(result["records"], [])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("parse error at line 1", result["warnings"][0])
        self.assertNotIn("untrusted", result["warnings"][0])

    def test_rejects_symlinks_and_non_regular_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.log"
            target.write_text("safe\n", encoding="utf-8")
            link = root / "link.log"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                ingest_logs(link)

            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                ingest_logs(fifo)

    def test_hard_bounds_reject_without_returning_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            line_limited = root / "line.log"
            line_limited.write_bytes(b"abcd\n")
            with patch("reverse_shell_decoy.ingest.MAX_LINE_BYTES", 3):
                with self.assertRaisesRegex(ValueError, "line"):
                    ingest_logs(line_limited)

            record_limited = root / "records.log"
            record_limited.write_bytes(b"one\ntwo\n")
            with patch("reverse_shell_decoy.ingest.MAX_RECORDS", 1):
                with self.assertRaisesRegex(ValueError, "record"):
                    ingest_logs(record_limited)

            byte_limited = root / "bytes.log"
            byte_limited.write_bytes(b"abcd")
            with patch("reverse_shell_decoy.ingest.MAX_INPUT_BYTES", 3):
                with self.assertRaisesRegex(ValueError, "MiB"):
                    ingest_logs(byte_limited)

    def test_text_is_trimmed_and_unsupported_format_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "long.log"
            log.write_text("x" * 5000, encoding="utf-8")
            result = ingest_logs(log)
            self.assertEqual(len(result["records"][0]["message"]), 4096)
            self.assertTrue(any("truncated" in warning for warning in result["warnings"]))
            with self.assertRaisesRegex(ValueError, "format"):
                ingest_logs(log, format="xml")

    def test_pasted_input_stops_at_exact_marker_and_never_includes_it_in_hash(self) -> None:
        stream = StringIO("2026-01-02T03:04:05Z password=hunter2\nENDLOG\nignored\n")

        result = ingest_pasted(stream, marker="ENDLOG")

        self.assertEqual(result["filename"], "pasted-input")
        self.assertEqual(result["sha256"], sha256(b"2026-01-02T03:04:05Z password=hunter2\n").hexdigest())
        self.assertEqual(result["record_count"], 1)
        self.assertNotIn("hunter2", result["records"][0]["message"])
        self.assertNotIn("ENDLOG", result["records"][0]["message"])
        self.assertEqual(result["records"][0]["timestamp"], "2026-01-02T03:04:05Z")

        exact_stream = StringIO("ENDLOG-extra\nENDLOG\nignored\n")
        exact_result = ingest_pasted(exact_stream)
        self.assertEqual(exact_result["record_count"], 1)
        self.assertEqual(exact_result["records"][0]["message"], "ENDLOG-extra")

    def test_pasted_input_accepts_eof_and_states_clipboard_privacy_limits(self) -> None:
        stream = StringIO("first\nsecond")

        result = ingest_pasted(stream)

        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["sha256"], sha256(b"first\nsecond").hexdigest())
        notices = " ".join(result["notices"]).lower()
        self.assertIn("clipboard", notices)
        self.assertIn("not a hash of original logfile bytes", notices)
        self.assertIn("cannot authenticate", notices)
        self.assertEqual(result["source_kind"], "imported_real_log")
        self.assertFalse(result["simulation"])

    def test_pasted_jsonl_retains_safe_service_audit_endpoint_fields(self) -> None:
        stream = StringIO(
            json.dumps(
                {
                    "source_ip": "198.51.100.20",
                    "remote_address": "203.0.113.8",
                    "remote_port": 8443,
                    "local_address": "192.0.2.44",
                    "local_port": 51515,
                    "session_id": "service-audit-session",
                    "simulation": False,
                    "args": "must not survive",
                }
            )
            + "\nENDLOG\n"
        )

        result = ingest_pasted(stream, format="jsonl")

        record = result["records"][0]
        self.assertEqual(record["source_ip"], "198.51.100.20")
        self.assertEqual(record["remote_address"], "203.0.113.8")
        self.assertEqual(record["remote_port"], 8443)
        self.assertEqual(record["local_address"], "192.0.2.44")
        self.assertEqual(record["local_port"], 51515)
        self.assertEqual(record["session_id"], "service-audit-session")
        self.assertFalse(record["simulation"])
        self.assertFalse(result["simulation"])
        self.assertNotIn("args", record)

    def test_pasted_input_enforces_bounds_and_validates_marker(self) -> None:
        with patch("reverse_shell_decoy.ingest.MAX_RECORDS", 1):
            with self.assertRaisesRegex(ValueError, "record"):
                ingest_pasted(StringIO("one\ntwo\n"))
        with patch("reverse_shell_decoy.ingest.MAX_INPUT_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "MiB"):
                ingest_pasted(StringIO("abcd"))
        with self.assertRaisesRegex(ValueError, "whitespace"):
            ingest_pasted(StringIO(""), marker="END LOG")
        with self.assertRaisesRegex(ValueError, "64"):
            ingest_pasted(StringIO(""), marker="X" * 65)


if __name__ == "__main__":
    unittest.main()
