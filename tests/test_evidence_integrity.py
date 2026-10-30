import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from reverse_shell_decoy import incident_explainer as explainer
from reverse_shell_decoy.authorization import AuthorizationScope, request_authorization


def sample_audit():
    return (json.dumps({"event_type": "connecting", "timestamp_utc": "2026-10-30T00:00:00Z", "session_id": "integrity-session"}) + "\n" +
            json.dumps({"event_type": "command", "timestamp_utc": "2026-10-30T00:00:01Z", "session_id": "integrity-session", "verb": "whoami", "token_indicators": ["process_api"], "command": "never retained in a report"}) + "\n").encode()


def write_packet(directory, packet):
    scope = AuthorizationScope("explain", output_ref=str(directory))
    grant = request_authorization(scope, consent=True)
    explainer.write_private_packet(str(directory), packet, authorization=grant, scope=scope)


def verify_packet(directory, pin):
    scope = AuthorizationScope("verify_evidence", str(directory), pin)
    grant = request_authorization(scope, consent=True)
    return explainer.verify_packet(str(directory), expected_manifest_sha256=pin, authorization=grant, scope=scope)


class EvidenceIntegrityTests(unittest.TestCase):
    def _packet_directory(self):
        snapshot = explainer.snapshot_from_bytes(sample_audit())
        packet = explainer.explanation_packet(snapshot)
        root = tempfile.TemporaryDirectory()
        directory = Path(root.name) / "packet"
        write_packet(directory, packet)
        pin = hashlib.sha256(packet["evidence-manifest.json"]).hexdigest()
        return root, directory, pin

    def test_reflective_record_mutation_rejected_before_copy_digest_or_render(self):
        snapshot = explainer.snapshot_from_bytes(sample_audit())
        object.__setattr__(snapshot, "_canonical_record", b'{"record_format":"changed"}')
        for consumer in (lambda: snapshot.digest, snapshot.copy,
                         lambda: explainer.behavior_feedback(snapshot),
                         lambda: explainer.customer_markdown(snapshot),
                         lambda: explainer.explanation_packet(snapshot)):
            with self.subTest(consumer=consumer), self.assertRaises(explainer.EvidenceIntegrityError) as raised:
                consumer()
            self.assertEqual(str(raised.exception), "evidence integrity validation failed")

    def test_reflective_binding_stripping_or_replacement_is_rejected(self):
        for field, replacement in (("_expected_digest", "0" * 64), ("_source_input_sha256", "0" * 64),
                                   ("_metadata_digest", "0" * 64), ("_origin", object())):
            snapshot = explainer.snapshot_from_bytes(sample_audit())
            object.__setattr__(snapshot, field, replacement)
            with self.subTest(field=field), self.assertRaises(explainer.EvidenceIntegrityError):
                snapshot.copy()

    def test_separately_trusted_exact_manifest_pin_is_required(self):
        root, directory, pin = self._packet_directory()
        with root:
            verified = verify_packet(directory, pin)
            self.assertTrue(verified["verified"])
            self.assertEqual(verified["source_authenticity"], "unverified")
            self.assertEqual(verified["verification_scope"], "packet_integrity_and_local_format_only")
            self.assertEqual(verified["artifacts"], ["incident-record.json", "behavior-feedback.json", "customer-explanation.json", "customer-explanation.md"])
            with self.assertRaises(explainer.EvidenceIntegrityError):
                verify_packet(directory, "0" * 64)

    def test_bounded_finite_service_budget_floats_are_valid(self):
        budget = {
            "event_type": "service_budget", "timestamp_utc": "2026-10-30T00:00:02Z",
            "source_kind": "decoy_service_control", "interaction_observed": False,
            "phase": "stopped", "stop_reason": "operator_shutdown",
            "limits": {"max_sessions": 8, "max_sessions_total": 100, "max_commands": 100,
                       "max_runtime_seconds": 5.0, "idle_timeout_seconds": 20,
                       "session_timeout_seconds": 120, "max_input_bytes_total": 1048576,
                       "max_output_bytes_total": 1048576, "max_session_input_bytes": 65536,
                       "commands_per_second": 10},
            "usage": {"input_bytes_total": 1, "output_bytes_total": 2,
                      "accepted_connections": 1, "active_sessions": 0,
                      "peak_active_sessions": 1, "elapsed_seconds": 0.5},
        }
        snapshot = explainer.snapshot_from_bytes(sample_audit() + json.dumps(budget).encode() + b"\n")
        packet = explainer.explanation_packet(snapshot)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "packet"
            write_packet(directory, packet)
            self.assertTrue(verify_packet(directory, hashlib.sha256(packet["evidence-manifest.json"]).hexdigest())["verified"])

    def test_cross_artifact_tampering_rejected_even_with_recomputed_manifest(self):
        root, directory, pin = self._packet_directory()
        with root:
            feedback_path = directory / "behavior-feedback.json"
            feedback = json.loads(feedback_path.read_text())
            feedback["source_input_sha256"] = "0" * 64
            tampered = explainer.canonical(feedback) + b"\n"
            feedback_path.write_bytes(tampered)
            manifest_path = directory / "evidence-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["artifact_sha256"]["behavior-feedback.json"] = hashlib.sha256(tampered).hexdigest()
            replacement = explainer.canonical(manifest) + b"\n"
            manifest_path.write_bytes(replacement)
            with self.assertRaises(explainer.EvidenceIntegrityError):
                verify_packet(directory, hashlib.sha256(replacement).hexdigest())
            self.assertNotEqual(pin, hashlib.sha256(replacement).hexdigest())

    def test_directory_and_artifact_symlinks_are_rejected(self):
        root, directory, pin = self._packet_directory()
        with root:
            linked = Path(root.name) / "linked-packet"
            linked.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(explainer.EvidenceIntegrityError):
                verify_packet(linked, pin)
        root, directory, pin = self._packet_directory()
        with root:
            (directory / "customer-explanation.md").unlink()
            (directory / "customer-explanation.md").symlink_to(directory / "customer-explanation.json")
            with self.assertRaises(explainer.EvidenceIntegrityError):
                verify_packet(directory, pin)

    def test_stripped_time_metadata_and_cross_session_report_are_rejected(self):
        for alteration in ("missing_time", "other_session"):
            root, directory, _pin = self._packet_directory()
            with root:
                report_path = directory / "customer-explanation.json"
                report = json.loads(report_path.read_text())
                if alteration == "missing_time":
                    del report["time_range"]
                else:
                    other_raw = sample_audit().replace(b"integrity-session", b"other-session")
                    report = explainer.customer_explanation(explainer.snapshot_from_bytes(other_raw))
                report_bytes = explainer.canonical(report) + b"\n"
                report_path.write_bytes(report_bytes)
                manifest_path = directory / "evidence-manifest.json"
                manifest = json.loads(manifest_path.read_text())
                manifest["artifact_sha256"]["customer-explanation.json"] = hashlib.sha256(report_bytes).hexdigest()
                manifest_bytes = explainer.canonical(manifest) + b"\n"
                manifest_path.write_bytes(manifest_bytes)
                with self.subTest(alteration=alteration), self.assertRaises(explainer.EvidenceIntegrityError):
                    verify_packet(directory, hashlib.sha256(manifest_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
