"""Focused regression tests for review 8 evidence findings."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from reverse_shell_decoy import __version__
from reverse_shell_decoy import evidence


class EvidenceVersionMetadataTests(unittest.TestCase):
    def test_evidence_and_build_metadata_share_the_package_version_source(self) -> None:
        metadata = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(evidence.TOOL_VERSION, "0.1.2")
        self.assertEqual(__version__, "0.1.2")
        self.assertIn('dynamic = ["version"]', metadata)
        self.assertIn(
            'version = {attr = "reverse_shell_decoy.__version__"}', metadata
        )
        self.assertNotIn('\nversion = "0.1.0"\n', metadata)

    def test_previous_release_packet_remains_valid_with_version_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "previous-release.zip"
            with mock.patch.object(evidence, "TOOL_VERSION", "0.1.0"):
                evidence.export_bundle(bundle, {})
            report = evidence.verify_bundle(bundle)
        self.assertTrue(report["valid"], report)
        self.assertIn("manifest was produced by a different tool version", report["warnings"])


class VerifyBundleResourceErrorTests(unittest.TestCase):
    def test_zip_resource_exceptions_are_reported_without_propagating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle.zip"
            bundle.write_bytes(b"PK\\x03\\x04")

            for exception_type in (zipfile.LargeZipFile, MemoryError):
                with self.subTest(exception=exception_type.__name__):
                    with mock.patch.object(
                        evidence.zipfile,
                        "ZipFile",
                        side_effect=exception_type("fixture resource failure"),
                    ):
                        report = evidence.verify_bundle(bundle)

                    self.assertEqual(
                        report,
                        {
                            "valid": False,
                            "warnings": [],
                            "errors": ["bundle exceeds safe ZIP resource limits"],
                        },
                    )


if __name__ == "__main__":
    unittest.main()
