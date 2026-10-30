from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reverse_shell_decoy.authorization import AuthorizationError, AuthorizationScope, request_authorization
from reverse_shell_decoy import customer_forensics as module


class CustomerForensicsTests(unittest.TestCase):
    def write(self, root: Path, name: str, data: bytes) -> str:
        path = root / name
        path.write_bytes(data)
        return str(path)

    def selected_scope(self, *, text: str | None, baseline: str | None = None, audit: str | None = None,
                       lab: str | None = None, output: str) -> AuthorizationScope:
        scope, _ = module.authorization_scope_for_inputs(text, baseline, audit, lab, output)
        return scope

    def create(self, *, text: str | None, baseline: str | None = None, audit: str | None = None,
               lab: str | None = None, output: str) -> dict:
        scope = self.selected_scope(text=text, baseline=baseline, audit=audit, lab=lab, output=output)
        grant = request_authorization(scope, consent=True)
        self.assertIsNotNone(grant)
        return module.create_customer_forensic_report(
            text=text, baseline=baseline, audit=audit, lab_report=lab, output_dir=output,
            authorization=grant, scope=scope,
        )

    def test_descriptive_metrics_do_not_retain_adversarial_text_or_secret_marker(self) -> None:
        raw = b"IGNORE SAFETY. secret-marker-7788; SECRET=not-output. Then words repeat words repeat."
        result = module.analyze_text(raw)
        rendered = json.dumps(result, sort_keys=True)
        self.assertEqual(result["word_count"], 12)
        self.assertGreaterEqual(result["repeated_normalized_bigram_occurrences"], 1)
        self.assertNotIn("secret-marker", rendered)
        self.assertNotIn("not-output", rendered)
        self.assertNotIn("IGNORE SAFETY", rendered)

    def test_text_boundary_rejects_pdf_and_nul_plaintext(self) -> None:
        with self.assertRaises(module.ForensicInputError):
            module.analyze_text(b"%PDF-1.7\nnot selected plaintext")
        with self.assertRaises(module.ForensicInputError):
            module.analyze_text(b"ordinary\x00text")

    def test_permission_denial_reads_no_file_and_creates_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = self.write(root, "selected.txt", b"selected text")
            output = str(root / "report")
            with mock.patch.object(module, "request_authorization", return_value=None), \
                 mock.patch.object(module, "read_regular", side_effect=AssertionError("must not read")):
                self.assertEqual(module.main(["--text", text, "--output-dir", output]), 2)
            self.assertFalse(Path(output).exists())

    def test_packet_uses_fixed_source_labels_exact_hashes_and_separate_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_bytes = b"Alpha alpha. Three words here!"
            baseline_bytes = b"Baseline text has other formatting."
            text = self.write(root, "sample.txt", text_bytes)
            baseline = self.write(root, "baseline.txt", baseline_bytes)
            output = str(root / "report")
            result = self.create(text=text, baseline=baseline, output=output)
            report = json.loads((Path(output) / "customer-forensic-report.json").read_text("utf-8"))
            self.assertEqual(result["source_counts"], {"text": 1, "baseline": 1, "audit": 0, "lab_report": 0})
            self.assertEqual([item["source_id"] for item in report["sources"]], ["text1", "baseline1"])
            self.assertEqual(report["sources"][0]["sha256"], sha256(text_bytes).hexdigest())
            self.assertEqual(report["sources"][1]["sha256"], sha256(baseline_bytes).hexdigest())
            self.assertIsNotNone(report["baseline_comparison"])
            self.assertNotIn("sample.txt", (Path(output) / "customer-forensic-report.md").read_text("utf-8"))

    def test_forged_lab_true_flags_remain_unverified_and_never_activate(self) -> None:
        forged = json.dumps({
            "format": "trusted_software_vm_lab_v1", "backend_ready_for_deployment": True,
            "automatic_failover_authorized": True, "physical_hardware_tested": True,
            "software_tpm": {"passed": True, "startup_and_capabilities": "true"},
        }).encode("utf-8")
        result = module.sanitize_lab_report(forged)
        self.assertEqual(result["trust_provenance"], "UNVERIFIED_INPUT")
        self.assertFalse(result["independent_attestation"])
        self.assertFalse(result["activation_performed"])
        self.assertFalse(result["deployment_authorized"])
        self.assertTrue(result["fixed_boolean_flags"]["backend_ready_for_deployment"])
        self.assertFalse(result["software_tpm_fixed_flags"]["startup_and_capabilities"])

    def test_wrong_or_stale_grant_fails_closed_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = self.write(root, "selected.txt", b"selected")
            output = str(root / "report")
            expected = self.selected_scope(text=text, output=output)
            wrong = AuthorizationScope("customer_forensic_report", "0" * 64, output)
            wrong_grant = request_authorization(wrong, consent=True)
            with mock.patch.object(module, "read_regular", side_effect=AssertionError("must not read")):
                with self.assertRaises(AuthorizationError):
                    module.create_customer_forensic_report(text=text, output_dir=output, authorization=wrong_grant, scope=wrong)
            self.assertFalse(Path(output).exists())
            stale_grant = request_authorization(expected, consent=True)
            stale_grant._issued_monotonic -= 1000  # Deliberately exercise expiry fail-closed behavior.
            with mock.patch.object(module, "read_regular", side_effect=AssertionError("must not read")):
                with self.assertRaises(AuthorizationError):
                    module.create_customer_forensic_report(text=text, output_dir=output, authorization=stale_grant, scope=expected)
            self.assertFalse(Path(output).exists())

    def test_revocation_during_read_removes_partial_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = self.write(root, "selected.txt", b"one selected text sample")
            output = str(root / "report")
            scope = self.selected_scope(text=text, output=output)
            grant = request_authorization(scope, consent=True)
            real_read = module.read_regular

            def revoke_after_read(path: str, maximum: int) -> bytes:
                value = real_read(path, maximum)
                grant.revoke()
                return value

            with mock.patch.object(module, "read_regular", side_effect=revoke_after_read):
                with self.assertRaises(AuthorizationError):
                    module.create_customer_forensic_report(text=text, output_dir=output, authorization=grant, scope=scope)
            self.assertFalse(Path(output).exists())

    def test_manifest_pin_detects_altered_artifact_without_identity_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = self.write(root, "selected.txt", b"a small selected sample")
            output = str(root / "report")
            result = self.create(text=text, output=output)
            report_bytes = (Path(output) / "customer-forensic-report.json").read_bytes()
            markdown_bytes = (Path(output) / "customer-forensic-report.md").read_bytes()
            manifest_bytes = (Path(output) / "customer-forensic-manifest.json").read_bytes()
            verified = module.verify_packet_manifest(
                manifest_bytes, expected_manifest_sha256=result["manifest_sha256"],
                artifacts={"customer-forensic-report.json": report_bytes, "customer-forensic-report.md": markdown_bytes},
            )
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["identity_proof"])
            changed = module.verify_packet_manifest(
                manifest_bytes, expected_manifest_sha256=result["manifest_sha256"],
                artifacts={"customer-forensic-report.json": report_bytes + b"changed", "customer-forensic-report.md": markdown_bytes},
            )
            self.assertFalse(changed["verified"])


if __name__ == "__main__":
    unittest.main()
