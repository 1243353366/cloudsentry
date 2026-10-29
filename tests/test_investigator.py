"""Tests for neutral, bounded investigator packet exports."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.evidence import verify_bundle
from reverse_shell_decoy.investigator import (
    MAX_AUDIT_BYTES,
    MAX_COMBINED_RECORDS,
    MAX_STATE_BYTES,
    build_report,
    export_report,
)


def _write_jsonl(path: Path, records: list[object]) -> Path:
    path.write_text("".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records), encoding="utf-8")
    return path


def _state(files: dict[str, str] | None = None) -> dict[str, object]:
    files = files or {"/root/credentials.txt": "SYNTHETIC ONLY\npassword=NOT-A-REAL-CREDENTIAL\n"}
    directories = ["/", "/root"]
    canonical = json.dumps(
        {"files": files, "directories": sorted(directories), "cwd": "/root"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return {
        "schema_version": "1.0",
        "state_kind": "synthetic_virtual_filesystem",
        "simulation": True,
        "timestamp_utc": "2026-10-29T22:00:00Z",
        "virtual_privilege": "root/admin; synthetic only",
        "state_sha256": sha256(canonical.encode("utf-8")).hexdigest(),
        "files": files,
        "directories": directories,
        "cwd": "/root",
    }


class InvestigatorReportTests(unittest.TestCase):
    def test_service_connection_is_logged_but_unverified_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(
                root / "service.jsonl",
                [
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "interaction_observed": True,
                        "timestamp_utc": "2026-10-29T22:00:01Z",
                        "peer_ip": "203.0.113.8",
                        "event_id": 7,
                        "scope": "synthetic_only",
                        "command": "cat /real/secret",
                        "args": ["untrusted"],
                        "environment": {"TOKEN": "secret"},
                        "credentials": "real-looking-but-excluded",
                        "unknown_field": "excluded",
                    }
                ],
            )

            report = build_report([str(audit)], case_label="operator-note")

            entry = report["timeline"][0]
            self.assertEqual(entry["classification"], "logged_interaction_unverified")
            self.assertEqual(entry["peer_ip"], "203.0.113.8")
            self.assertEqual(entry["source_basename"], "service.jsonl")
            self.assertEqual(entry["physical_line_index"], 1)
            self.assertNotIn("command", entry)
            self.assertNotIn("args", entry)
            self.assertNotIn("environment", entry)
            self.assertNotIn("credentials", entry)
            self.assertNotIn("unknown_field", entry)
            self.assertEqual(
                report["independent_claims"],
                {
                    "real_host_unauthorized_access": "not_established",
                    "visitor_identity": "unknown",
                    "remote_os": "unknown",
                    "authorization_status": "not_established",
                },
            )
            self.assertIn("connection_interaction", entry["observed_in_supplied_log"])
            self.assertIn("NAT", " ".join(report["limitations"]))
            self.assertNotIn(str(root), json.dumps(report))

    def test_state_loop_watch_digest_is_not_proof_and_effect_remains_synthetic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(
                root / "loop.jsonl",
                [
                    {
                        "simulation": True,
                        "source_kind": "bounded_defensive_state_loop",
                        "observation_is_real": True,
                        "scope": "virtual_state",
                        "timestamp_utc": "2026-10-29T22:00:02+00:00",
                        "state_sha256": "a" * 64,
                        "mutation": "virtual_marker",
                    }
                ],
            )
            report = build_report([str(audit)])
            entry = report["timeline"][0]

            self.assertEqual(entry["classification"], "claimed_local_digest_observation_unverified")
            self.assertIn("remain synthetic", " ".join(entry["synthetic_state_or_effects"]))
            self.assertEqual(report["independent_claims"]["real_host_unauthorized_access"], "not_established")
            self.assertNotIn("proof", json.dumps(entry).lower())

    def test_inbound_mirror_chunk_keeps_only_byte_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(
                root / "mirror.jsonl",
                [
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "event_type": "mirror_chunk",
                        "interaction_observed": True,
                        "peer_ip": "198.51.100.44",
                        "session_id": "session-1",
                        "timestamp_utc": "2026-10-29T22:00:04Z",
                        "byte_count": 48,
                        "chunk_sha256": "b" * 64,
                        "raw_payload": "rm -rf /",
                        "credentials": "excluded",
                    }
                ],
            )

            entry = build_report([str(audit)])["timeline"][0]

            self.assertEqual(entry["classification"], "logged_interaction_unverified")
            self.assertEqual(entry["event_type"], "mirror_chunk")
            self.assertEqual(entry["byte_count"], 48)
            self.assertEqual(entry["chunk_sha256"], "b" * 64)
            self.assertNotIn("raw_payload", entry)
            self.assertNotIn("credentials", entry)
            self.assertEqual(
                entry["synthetic_state_or_effects"],
                ["terminal responses and virtual session effects are synthetic"],
            )
            _write_jsonl(
                audit,
                [
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "interaction_observed": True,
                        "byte_count": "not-an-integer",
                        "chunk_sha256": "b" * 64,
                    }
                ],
            )
            invalid_count_entry = build_report([str(audit)])["timeline"][0]
            self.assertNotIn("byte_count", invalid_count_entry)

    def test_missing_time_and_invalid_records_are_counted_without_inventing_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "mixed.jsonl"
            audit.write_bytes(
                b'{"simulation":true,"source":"in_memory_decoy","verb":"id"}\n'
                b'not-json\n'
                b'{"simulation":false,"source":"in_memory_decoy"}\n'
                b'{"simulation":true,"source":"unknown"}\n'
            )

            report = build_report([str(audit)])

            self.assertEqual(len(report["timeline"]), 1)
            self.assertNotIn("timestamp_utc", report["timeline"][0])
            self.assertEqual(report["counts"]["missing_or_invalid_timestamp_count"], 1)
            self.assertEqual(report["counts"]["skipped_record_count"], 3)
            self.assertEqual(report["timeline_timestamp_range_utc"]["first"], None)
            self.assertEqual(report["timeline_timestamp_range_utc"]["last"], None)
            self.assertEqual(report["source_manifest"][0]["recognized_record_count"], 1)
            self.assertEqual(report["source_manifest"][0]["skipped_record_count"], 3)

    def test_export_creates_verified_private_packet_and_safe_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(
                root / "input.jsonl",
                [
                    {
                        "simulation": True,
                        "source_kind": "decoy_service_interaction",
                        "interaction_observed": True,
                        "timestamp_utc": "2026-10-29T22:00:03Z",
                        "peer_ip": "2001:db8::10",
                    }
                ],
            )
            state_path = root / "state.json"
            state_path.write_text(json.dumps(_state()), encoding="utf-8")
            packet = export_report([str(audit)], str(state_path), root / "packet.zip", "x](https://bad.example)")
            sidecar = packet.with_suffix(".md")

            self.assertEqual(verify_bundle(packet), {"valid": True, "warnings": [], "errors": []})
            self.assertTrue(sidecar.exists())
            self.assertEqual(stat.S_IMODE(packet.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(sidecar.stat().st_mode), 0o600)
            with zipfile.ZipFile(packet) as archive:
                report = json.loads(archive.read("detection.json"))
                self.assertIn("synthetic_state", report)
                self.assertEqual(
                    report["synthetic_state"]["files"]["/root/credentials.txt"],
                    "SYNTHETIC ONLY\npassword=NOT-A-REAL-CREDENTIAL\n",
                )
                self.assertEqual(json.loads(archive.read("simulation_audit.json")), [])
            markdown = sidecar.read_text(encoding="utf-8")
            self.assertNotIn("https://bad.example", markdown)
            self.assertNotIn("[x]", markdown)
            self.assertNotIn("password=", markdown)

    def test_state_rejects_hash_mismatch_and_non_simulation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(root / "audit.jsonl", [{"simulation": True, "source": "in_memory_decoy"}])
            bad_hash = _state()
            bad_hash["state_sha256"] = "0" * 64
            bad_hash_path = root / "bad-hash.json"
            bad_hash_path.write_text(json.dumps(bad_hash), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                build_report([str(audit)], str(bad_hash_path))

            non_simulation = _state()
            non_simulation["simulation"] = False
            non_simulation_path = root / "not-synthetic.json"
            non_simulation_path.write_text(json.dumps(non_simulation), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "simulation"):
                build_report([str(audit)], str(non_simulation_path))

    def test_state_accepts_only_bounded_optional_provenance_notice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(root / "audit.jsonl", [{"simulation": True, "source": "in_memory_decoy"}])
            state = _state()
            state["provenance_notice"] = "Synthetic snapshot only."
            state_path = root / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")

            report = build_report([str(audit)], str(state_path))

            self.assertIn("synthetic_state", report)
            self.assertNotIn("provenance_notice", report["synthetic_state"])
            state["unexpected"] = "not accepted"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected schema"):
                build_report([str(audit)], str(state_path))

    def test_output_overwrite_and_symlink_are_refused_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(root / "audit.jsonl", [{"simulation": True, "source": "in_memory_decoy"}])
            existing_zip = root / "exists.zip"
            existing_zip.write_bytes(b"leave alone")
            with self.assertRaises(FileExistsError):
                export_report([str(audit)], None, existing_zip)
            self.assertEqual(existing_zip.read_bytes(), b"leave alone")
            self.assertFalse(existing_zip.with_suffix(".md").exists())

            sidecar = root / "target.md"
            sidecar.write_text("do not replace", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                export_report([str(audit)], None, root / "target.zip")
            self.assertFalse((root / "target.zip").exists())

            target = root / "protected.md"
            target.write_text("protected", encoding="utf-8")
            link = root / "link.md"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                export_report([str(audit)], None, root / "link.zip")
            self.assertEqual(target.read_text(encoding="utf-8"), "protected")

    def test_size_and_combined_record_limits_use_selected_regular_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            big = root / "big.jsonl"
            big.write_bytes(b"x" * (MAX_AUDIT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "configured size"):
                build_report([str(big)])

            records = [{"simulation": True, "source": "in_memory_decoy"}] * (MAX_COMBINED_RECORDS + 1)
            many = _write_jsonl(root / "many.jsonl", records)
            with self.assertRaisesRegex(ValueError, "combined limit"):
                build_report([str(many)])

            oversized_state = root / "state-large.json"
            oversized_state.write_bytes(b" " * (MAX_STATE_BYTES + 1))
            normal = _write_jsonl(root / "normal.jsonl", [{"simulation": True, "source": "in_memory_decoy"}])
            with self.assertRaisesRegex(ValueError, "configured size"):
                build_report([str(normal)], str(oversized_state))

    def test_no_network_or_exec_helpers_are_called(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = _write_jsonl(root / "audit.jsonl", [{"simulation": True, "source": "in_memory_decoy"}])
            with mock.patch("socket.socket", side_effect=AssertionError("network"), create=True), mock.patch(
                "subprocess.run", side_effect=AssertionError("exec"), create=True
            ), mock.patch("os.system", side_effect=AssertionError("exec")):
                report = build_report([str(audit)])
            self.assertEqual(report["counts"]["recognized_record_count"], 1)


if __name__ == "__main__":
    unittest.main()
