import hashlib
import json
import unittest
from unittest.mock import patch

from reverse_shell_decoy import customer_forensics as forensic
from reverse_shell_decoy import resource_boundary as resource
from reverse_shell_decoy.authorization import AuthorizationError, request_authorization


class CustomerResourceIntegrityTests(unittest.TestCase):
    def test_library_resource_apply_requires_scope_before_sysfs(self):
        with patch.object(resource, "prepare_cgroup", side_effect=AssertionError("no sysfs")):
            with self.assertRaises(AuthorizationError):
                resource.apply_fixed_echo("/sys/fs/cgroup/customer", "8:0")

    def test_revoked_resource_grant_runs_nothing(self):
        scope = resource.resource_scope("/sys/fs/cgroup/customer", "8:0")
        grant = request_authorization(scope, consent=True)
        grant.revoke()
        with patch.object(resource, "prepare_cgroup", side_effect=AssertionError("no sysfs")):
            with self.assertRaises(AuthorizationError):
                resource.apply_fixed_echo("/sys/fs/cgroup/customer", "8:0", authorization=grant)

    def test_resource_claims_remain_unverified_and_missing_is_unknown(self):
        value = json.dumps({"format": "resource_boundary_v1", "status": {"cpu": "verified_local_readback", "gpu": True}}).encode()
        result = forensic.sanitize_lab_report(value)
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["independent_attestation"])
        self.assertEqual(result["reported_resource_controls"], {"cpu": "verified_local_readback", "mem": "unknown", "io": "unknown", "gpu": "unknown"})

    def test_malformed_format_is_rejected_without_type_exception(self):
        with self.assertRaises(forensic.ForensicInputError):
            forensic.sanitize_lab_report(b'{"format":["resource_boundary_v1"]}')

    def test_duplicate_artifact_cannot_hide_altered_markdown(self):
        report = b"{}"
        manifest = {"format": forensic.MANIFEST_FORMAT, "existing_incident_packet_verifier_compatible": False,
                    "artifacts": [{"name": "customer-forensic-report.json", "sha256": hashlib.sha256(report).hexdigest()}] * 2}
        raw = json.dumps(manifest).encode()
        with self.assertRaises(forensic.ForensicInputError):
            forensic.verify_packet_manifest(raw, expected_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                artifacts={"customer-forensic-report.json": report, "customer-forensic-report.md": b"tampered"})

    def test_programming_tokens_are_not_a_human_language_inference(self):
        metrics = forensic.analyze_text(b"python -c 'print(1)'")
        self.assertIn("programming_language_indicator", metrics)
        self.assertNotIn("language_indicator_english_heuristic_only", metrics)


if __name__ == "__main__":
    unittest.main()
