"""Focused tests for the explicit, local-only operations summary."""
from __future__ import annotations

import contextlib
import hashlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import unittest

from reverse_shell_decoy import operations
from reverse_shell_decoy.operations import build_operations_summary, main, markdown


TIMESTAMP = "2030-01-02T03:04:05Z"


def event(event_type: str, session_id: str | None = "session-1", **extra: object) -> dict[str, object]:
    result: dict[str, object] = {"event_type": event_type, "timestamp_utc": TIMESTAMP}
    if session_id is not None:
        result["session_id"] = session_id
    result.update(extra)
    return result


def budget(phase: str = "started", **extra: object) -> dict[str, object]:
    result = event(
        "service_budget",
        None,
        source_kind="decoy_service_control",
        interaction_observed=False,
        simulation_scope="local_configuration_and_budget_counters",
        phase=phase,
        stop_reason="not_stopped" if phase == "started" else "operator_shutdown",
        limits={
            "max_sessions": 8,
            "max_sessions_total": 100,
            "max_commands": 100,
            "max_runtime_seconds": 600.0,
            "idle_timeout_seconds": 20,
            "session_timeout_seconds": 120,
            "max_input_bytes_total": 1024 * 1024,
            "max_output_bytes_total": 1024 * 1024,
            "max_session_input_bytes": 64 * 1024,
            "commands_per_second": 10,
        },
        usage={
            "input_bytes_total": 12,
            "output_bytes_total": 34,
            "accepted_connections": 1,
            "active_sessions": 0,
            "peak_active_sessions": 1,
            "elapsed_seconds": 0.25,
        },
    )
    result.update(extra)
    return result


class OperationsSummaryTests(unittest.TestCase):
    def write_jsonl(self, directory: str, records: list[object], name: str = "audit.jsonl") -> tuple[Path, bytes]:
        content = b"".join(
            item if isinstance(item, bytes) else json.dumps(item, separators=(",", ":")).encode("utf-8") + b"\n"
            for item in records
        )
        path = Path(directory) / name
        path.write_bytes(content)
        return path, content

    def test_valid_events_hash_sessions_and_never_echo_unsafe_fields(self) -> None:
        secret = "VERY-SECRET-ARGUMENT"
        peer_ip = "203.0.113.71"
        records = [
            event("connecting", peer_ip=peer_ip, attacker_identity="claimed-person"),
            event("command", verb="id", command=secret, arguments=[secret]),
            event("command", verb="uname", token_indicators=["process_api", secret]),
            event("command", verb="pwd", raw_command=secret),
            event("close", reason="completed"),
            budget(untrusted_note=secret, limits={**budget()["limits"], "unexpected_limit": secret}),
        ]
        with tempfile.TemporaryDirectory() as td:
            path, content = self.write_jsonl(td, records)
            result = build_operations_summary(str(path))

        self.assertEqual(result["audit"]["input_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["session_count"], 1)
        session = result["sessions"][0]
        self.assertEqual(session["session_ref_sha256"], hashlib.sha256(b"session-1").hexdigest())
        self.assertEqual(session["known_verbs"], ["id", "pwd", "uname"])
        self.assertEqual(session["token_indicators"], ["process_api"])
        self.assertEqual(
            {item["name"] for item in session["classifications"]},
            {"multi_command_pattern", "execution_related_text"},
        )
        self.assertTrue(all(item["confidence"] == "low" for item in session["classifications"]))
        self.assertEqual(result["budget_stats"]["status"], "supplied_unverified")
        self.assertEqual(result["budget_stats"]["events"][0]["limits"]["max_runtime_seconds"], 600.0)
        self.assertNotIn("unexpected_limit", result["budget_stats"]["events"][0]["limits"])
        rendered = json.dumps(result) + markdown(result)
        for forbidden in (secret, peer_ip, "claimed-person", "raw_command", "arguments"):
            self.assertNotIn(forbidden, rendered)

    def test_malformed_deep_and_overlong_records_are_counted_without_echoing_them(self) -> None:
        secret = b"MALFORMED-SECRET-MARKER"
        deep = (
            b'{"event_type":"connecting","timestamp_utc":"2030-01-02T03:04:05Z",'
            b'"session_id":"deep-session","extra":' + b"[" * 18 + b"0" + b"]" * 18 + b"}\n"
        )
        overlong = b'{"untrusted":"' + secret + b"-" + (b"x" * (operations.MAX_LINE_BYTES + 1)) + b'"}\n'
        records: list[object] = [
            b"{not json}\n",
            deep,
            overlong,
            event("connecting", "valid-session"),
        ]
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, records)
            result = build_operations_summary(str(path))

        discarded = result["audit"]["discarded_records"]
        self.assertGreaterEqual(discarded["malformed_or_deep_json"], 2)
        self.assertEqual(discarded["overlong_line"], 1)
        self.assertEqual(result["session_count"], 1)
        self.assertNotIn(secret.decode("ascii"), json.dumps(result) + markdown(result))

    def test_symlink_is_rejected_by_the_regular_file_reader(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            actual = Path(td) / "actual.jsonl"
            actual.write_text(json.dumps(event("connecting")) + "\n", encoding="utf-8")
            link = Path(td) / "audit-link.jsonl"
            link.symlink_to(actual)
            with self.assertRaisesRegex(ValueError, "regular file"):
                build_operations_summary(str(link))

    def test_session_quota_caps_hash_referenced_sessions_at_one_hundred(self) -> None:
        records = [event("connecting", f"session-{index}") for index in range(101)]
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, records)
            result = build_operations_summary(str(path))

        self.assertEqual(result["session_count"], 100)
        self.assertEqual(result["audit"]["discarded_records"]["session_limit_omitted"], 1)
        self.assertEqual(result["classification_counts"]["connection_only"], 100)
        self.assertEqual(result["uncertainty_counts"]["sessions_missing_close_event"], 100)

    def test_overlapping_categories_remain_low_confidence_observable_flags(self) -> None:
        records = [
            event("connecting", "ambiguous-session"),
            event("command", "ambiguous-session", verb="id", reason="command_rate_limit", token_indicators=["shell_path"]),
            event("command", "ambiguous-session", verb="uname"),
            event("command", "ambiguous-session", verb="pwd"),
            event("close", "ambiguous-session"),
        ]
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, records)
            result = build_operations_summary(str(path))

        labels = {item["name"] for item in result["sessions"][0]["classifications"]}
        self.assertEqual(labels, {"burst_pattern", "multi_command_pattern", "execution_related_text"})
        self.assertEqual(result["classification_counts"]["probe_like"], 0)
        self.assertIn("do not prove a human, scanner", result["classification_notice"])

    def test_missing_global_budget_record_is_unknown_not_a_clean_or_failure_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, [event("connecting"), event("close")])
            result = build_operations_summary(str(path))

        self.assertEqual(result["budget_stats"]["status"], "unknown")
        self.assertEqual(result["uncertainty_counts"]["service_budget_started_record_missing"], 1)
        self.assertEqual(result["uncertainty_counts"]["service_budget_stopped_record_missing"], 1)
        self.assertIn("not proof of service failure", result["limitations"][3].lower())

    def test_no_network_process_or_remote_inference_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, [event("connecting", peer_ip="198.51.100.5", remote_os="linux")])
            result = build_operations_summary(str(path))

        serialised = json.dumps(result)
        for forbidden_key in ("peer_ip", "remote_os", "cost_estimate", "attacker_identity"):
            self.assertNotIn(forbidden_key, serialised)
        self.assertFalse(result["automatic_actions"])
        source = inspect.getsource(operations)
        for forbidden_implementation in ("import socket", "import subprocess", "os.system(", "subprocess."):
            self.assertNotIn(forbidden_implementation, source)

    def test_required_audit_and_json_cli_are_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path, _ = self.write_jsonl(td, [event("connecting")])
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["--audit", str(path), "--json"]), 0)
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["title"], "Decoy operations summary")


if __name__ == "__main__":
    unittest.main()
