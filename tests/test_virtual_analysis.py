"""Safety boundaries for the synthetic-only virtual analysis facade."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.virtual_analysis import (
    IsolationUnavailableError, VirtualAnalysisComputer, main,
    require_remote_vm_backend, static_inspect,
)


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class VirtualAnalysisComputerTests(unittest.TestCase):
    def test_submit_is_hash_only_and_never_uses_host_execution_primitives(self):
        computer = VirtualAnalysisComputer()
        secret = "very-secret-value /tmp/chosen-name"
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess used")), \
             patch("socket.socket", side_effect=AssertionError("socket used")), \
             patch("builtins.open", side_effect=AssertionError("file opened")):
            report = computer.submit(f"echo {secret}")
        self.assertEqual(report["status"], "simulated")
        self.assertEqual(report["input_sha256"], hashlib.sha256(f"echo {secret}".encode()).hexdigest())
        self.assertTrue(report["simulation"])
        self.assertFalse(report["real_vm"])
        self.assertFalse(report["host_execution"])
        self.assertFalse(report["network_access"])
        self.assertFalse(report["credential_access"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, json.dumps(computer.audit_events))

    def test_event_schema_is_explicitly_an_in_memory_not_network_interaction(self):
        computer = VirtualAnalysisComputer()
        report = computer.submit("php -v")
        event = computer.audit_events[-1]
        self.assertEqual(report["status"], "simulated")
        self.assertEqual(event["event_type"], "command")
        self.assertEqual(event["session_id"], "virtual-analysis-1")
        self.assertEqual(event["source_kind"], "in_memory_decoy")
        self.assertFalse(event["interaction_observed"])
        self.assertTrue(event["synthetic_not_connection"])
        self.assertEqual(event["network_visitor"], "none")
        self.assertEqual(event["remote_os"], "none")
        self.assertEqual(event["response_mode"], "console")
        self.assertEqual(event["language_indicator"], "php")
        self.assertIsNotNone(event["input_sha256"])
        self.assertTrue(event["timestamp_utc"].endswith("Z"))
        json.dumps(event)

    def test_oversize_is_rejected_without_a_full_input_hash(self):
        computer = VirtualAnalysisComputer()
        report = computer.submit("x" * 4097)
        event = computer.audit_events[-1]
        self.assertEqual(report["status"], "blocked")
        self.assertIsNone(report["input_sha256"])
        self.assertIsNone(event["input_sha256"])
        self.assertEqual(event["reason"], "input_limit")
        self.assertEqual(event["verb"], "unsupported")

    def test_capability_requests_are_denied_without_dispatch(self):
        computer = VirtualAnalysisComputer()
        with patch.object(computer._session, "execute", side_effect=AssertionError("dispatched")):
            report = computer.submit("cat /proc/cpuinfo")
        self.assertEqual(report["status"], "blocked")
        event = computer.audit_events[-1]
        self.assertTrue(event["blocked"])
        self.assertEqual(event["reason"], "capability_unavailable")
        self.assertEqual(event["verb"], "unsupported")

    def test_state_fingerprints_report_virtual_file_counts_without_names(self):
        computer = VirtualAnalysisComputer()
        report = computer.submit("touch /tmp/only-first")
        event = computer.audit_events[-1]
        self.assertNotEqual(report["virtual_state_before_sha256"], report["virtual_state_after_sha256"])
        self.assertEqual(report["virtual_state_sha256"], computer.state_fingerprint)
        self.assertEqual(report["virtual_files_added"], 1)
        self.assertEqual(report["virtual_files_removed"], 0)
        self.assertEqual(event["virtual_files_added"], 1)
        self.assertNotIn("only-first", json.dumps(report))
        self.assertNotIn("only-first", json.dumps(event))

    def test_instances_are_isolated_reset_is_clean_and_audit_copies_are_defensive(self):
        first, second, pristine = VirtualAnalysisComputer(), VirtualAnalysisComputer(), VirtualAnalysisComputer()
        first.submit("touch /tmp/only-first")
        self.assertNotEqual(first.state_fingerprint, second.state_fingerprint)
        self.assertEqual(second.state_fingerprint, pristine.state_fingerprint)
        copied = first.audit_events
        copied[-1]["reason"] = "tampered"
        self.assertNotEqual(first.audit_events[-1]["reason"], "tampered")
        fresh = first.reset()
        self.assertEqual(first.submit("pwd")["status"], "closed")
        self.assertEqual(fresh.state_fingerprint, pristine.state_fingerprint)

    def test_request_cap_closes_and_audit_retention_remains_bounded(self):
        computer = VirtualAnalysisComputer()
        for _ in range(16):
            self.assertEqual(computer.submit("pwd")["status"], "simulated")
        self.assertEqual(computer.submit("pwd")["status"], "closed")
        self.assertEqual(computer.audit_events[-1]["reason"], "request_limit")
        for _ in range(40):
            computer.submit("pwd")
        self.assertLessEqual(len(computer.audit_events), 32)
        self.assertEqual(computer.audit_events[-1]["reason"], "synthetic_session_closed")

    def test_destroy_is_synthetic_fail_closed_and_cannot_resume(self):
        computer = VirtualAnalysisComputer()
        computer.submit("touch /tmp/temporary")
        computer.destroy()
        close = computer.audit_events[-1]
        report = computer.submit("pwd")
        self.assertEqual(close["event_type"], "close")
        self.assertEqual(close["source_kind"], "in_memory_decoy")
        self.assertFalse(close["interaction_observed"])
        self.assertEqual(report["status"], "closed")
        self.assertEqual(computer.audit_events[-1]["reason"], "synthetic_session_closed")

    def test_static_labels_and_denial_hashes_are_not_execution_or_guest_replay(self):
        labels = static_inspect("python socket.socket()")
        self.assertEqual(set(labels), {"language_indicator", "token_indicators"})
        self.assertEqual(labels["language_indicator"], "python")
        self.assertIn("python_socket_api", labels["token_indicators"])
        with self.assertRaises(ValueError):
            static_inspect("x" * 4097)
        self.assertEqual(VirtualAnalysisComputer().submit("cat /sys/kernel")["synthetic_output_sha256"],
                         VirtualAnalysisComputer().submit("cat /sys/kernel")["synthetic_output_sha256"])

    def test_remote_vm_requirement_always_fails_closed(self):
        with self.assertRaisesRegex(IsolationUnavailableError, "Remote VM backend is not configured"):
            require_remote_vm_backend()


class VirtualAnalysisCliTests(unittest.TestCase):
    def test_noninteractive_missing_consent_precedes_file_open_and_hides_path(self):
        output = io.StringIO()
        path = "/private/very-secret-sample.txt"
        with patch("reverse_shell_decoy.virtual_analysis.read_regular", side_effect=AssertionError("opened")) as reader, \
             patch("sys.stdin", io.StringIO("")), contextlib.redirect_stdout(output):
            self.assertEqual(main(["--sample", path]), 2)
        self.assertFalse(reader.called)
        self.assertEqual(json.loads(output.getvalue()), {"reason": "permission_or_input_unavailable", "status": "error"})
        self.assertNotIn(path, output.getvalue())

    def test_interactive_fresh_yes_precedes_selected_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("php -v", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with patch("sys.stdin", _TTY("y\n")), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(main(["--sample", str(path)]), 0)
        self.assertIn("Permission to read and process", errors.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "static")

    def test_require_vm_fails_before_permission_prompt_or_file_open(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch("reverse_shell_decoy.virtual_analysis.read_regular", side_effect=AssertionError("opened")) as reader, \
             patch("sys.stdin", _TTY("y\n")), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(main(["--require-vm", "--sample", "ignored.txt"]), 2)
        self.assertFalse(reader.called)
        self.assertEqual(json.loads(output.getvalue()), {"reason": "remote_vm_unavailable", "status": "error"})
        self.assertEqual(errors.getvalue(), "")

    def test_selected_utf8_regular_sample_has_one_hash_only_json_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            raw = b"<?php fsockopen('example.invalid', 4444);"
            path.write_bytes(raw)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--consent", "--sample", str(path)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["source_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("php_network_api", result["token_indicators"])
        self.assertNotIn("example.invalid", output.getvalue())
        self.assertEqual(len(output.getvalue().splitlines()), 1)

    def test_simulation_mode_is_explicit_and_never_returns_sample_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("echo selected-secret", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--consent", "--simulate", "--sample", str(path)]), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["simulation"])
        self.assertEqual(result["status"], "simulated")
        self.assertNotIn("selected-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
