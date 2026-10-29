"""Tests for the privacy-conscious evidence bundle contract."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy import evidence
from reverse_shell_decoy.evidence import (
    MAX_AUDIT_BYTES,
    MAX_AUDIT_EVENTS,
    TOOL_VERSION,
    export_bundle,
    os_info,
    verify_bundle,
)


EXPECTED_MEMBERS = {
    "host_os.json",
    "detection.json",
    "simulation_audit.json",
    "custody_template.md",
    "README.md",
    "manifest.json",
}


def _scan_result() -> dict[str, object]:
    return {
        "scan_version": "test-only",
        "findings": [{"kind": "simulated", "pid": 4242}],
    }


def _events() -> list[dict[str, object]]:
    return [
        {
            "simulation": True,
            "event_id": "synthetic-001",
            "event_type": "virtual_resource_event",
        }
    ]


def _rewrite_zip(source: Path, destination: Path, replacements: dict[str, bytes]) -> None:
    """Make a controlled altered archive while retaining the old manifest."""
    with zipfile.ZipFile(source, "r") as original, zipfile.ZipFile(destination, "w") as altered:
        for info in original.infolist():
            altered.writestr(info.filename, replacements.get(info.filename, original.read(info)))


class EvidenceBundleTests(unittest.TestCase):
    def test_export_schema_integrity_provenance_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            bundle = export_bundle(tmp_path / "evidence.zip", _scan_result(), _events())

            self.assertTrue(bundle.exists())
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o600)
            self.assertEqual(
                verify_bundle(bundle),
                {"valid": True, "warnings": [], "errors": []},
            )

            with zipfile.ZipFile(bundle) as archive:
                self.assertEqual(set(archive.namelist()), EXPECTED_MEMBERS)
                host_os = json.loads(archive.read("host_os.json"))
                self.assertEqual(
                    set(host_os),
                    {
                        "system",
                        "release",
                        "version",
                        "machine",
                        "freedesktop_os_release",
                    },
                )
                self.assertNotIn("hostname", host_os)
                self.assertNotIn("username", host_os)
                self.assertEqual(json.loads(archive.read("detection.json")), _scan_result())
                self.assertEqual(json.loads(archive.read("simulation_audit.json")), _events())

                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["tool_version"], TOOL_VERSION)
                self.assertEqual(manifest["schema_version"], "1.0")
                self.assertTrue(manifest["export_started_at"].endswith("Z"))
                self.assertTrue(manifest["export_ended_at"].endswith("Z"))
                for name in EXPECTED_MEMBERS - {"manifest.json"}:
                    data = archive.read(name)
                    self.assertEqual(
                        manifest["files"][name],
                        {"sha256": sha256(data).hexdigest(), "bytes": len(data)},
                    )

                readme = archive.read("README.md").decode("utf-8")
                self.assertIn("read-only host OS context", readme)
                self.assertIn("apparent privileges, terminal", readme)
                self.assertIn("inbound interaction as observed in the supplied log", readme)
                self.assertIn("not proof of attribution or unauthorized host access", readme)
                self.assertIn("does not share, upload, or transmit", readme)
                self.assertIn("do not authenticate", readme)
                custody = archive.read("custody_template.md").decode("utf-8")
                self.assertIn("## Investigator identity\n\n\n## Case", custody)

    def test_os_info_has_only_allowlisted_host_fields(self) -> None:
        info = os_info()

        self.assertEqual(
            set(info),
            {
                "system",
                "release",
                "version",
                "machine",
                "freedesktop_os_release",
            },
        )
        self.assertTrue(
            all(
                isinstance(info[name], str)
                for name in {"system", "release", "version", "machine"}
            )
        )
        self.assertTrue(
            set(info["freedesktop_os_release"]).issubset(
                {"NAME", "ID", "VERSION", "VERSION_ID"}
            )
        )
        self.assertFalse(
            {"hostname", "host", "node", "username", "user", "environment", "home"}
            .intersection(info)
        )

    def test_tampered_payload_fails_hash_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            original = export_bundle(tmp_path / "original.zip", _scan_result(), _events())
            tampered = tmp_path / "tampered.zip"
            _rewrite_zip(original, tampered, {"detection.json": b'{"changed": true}\n'})

            report = verify_bundle(tampered)

            self.assertFalse(report["valid"])
            self.assertTrue(
                any("SHA-256 hash mismatch for detection.json" in error for error in report["errors"])
            )

    def test_export_refuses_existing_and_symlink_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            output = tmp_path / "existing.zip"
            output.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                export_bundle(output, _scan_result())
            self.assertEqual(output.read_bytes(), b"existing")

            target = tmp_path / "target.zip"
            target.write_bytes(b"do not replace")
            link = tmp_path / "link.zip"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                export_bundle(link, _scan_result())
            self.assertEqual(target.read_bytes(), b"do not replace")

    def test_export_rejects_non_simulation_audit_and_preserves_no_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            output = tmp_path / "bad.zip"
            with self.assertRaisesRegex(ValueError, "simulation"):
                export_bundle(output, _scan_result(), [{"simulation": False}])
            self.assertFalse(output.exists())

            with self.assertRaisesRegex(ValueError, "simulation"):
                export_bundle(
                    tmp_path / "missing-marker.zip", _scan_result(), [{"event": "x"}]
                )

    def test_audit_event_and_byte_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            too_many = [{"simulation": True}] * (MAX_AUDIT_EVENTS + 1)
            with self.assertRaisesRegex(ValueError, "event limit"):
                export_bundle(tmp_path / "too-many.zip", _scan_result(), too_many)

            too_large = [{"simulation": True, "detail": "x" * MAX_AUDIT_BYTES}]
            with self.assertRaisesRegex(ValueError, "2 MiB"):
                export_bundle(tmp_path / "too-large.zip", _scan_result(), too_large)

    def test_verifier_rejects_invalid_unsafe_and_oversized_archives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            invalid = tmp_path / "not-a-zip.zip"
            invalid.write_bytes(b"not a zip")
            invalid_report = verify_bundle(invalid)
            self.assertFalse(invalid_report["valid"])
            self.assertTrue(
                any("not a readable ZIP archive" in error for error in invalid_report["errors"])
            )

            unsafe = tmp_path / "unsafe.zip"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../outside.txt", b"nothing")
            unsafe_report = verify_bundle(unsafe)
            self.assertFalse(unsafe_report["valid"])
            self.assertTrue(
                any("unsafe ZIP member" in error for error in unsafe_report["errors"])
            )
            self.assertTrue(
                any("unlisted ZIP entry" in error for error in unsafe_report["errors"])
            )
            self.assertTrue(
                any("missing required entry: manifest.json" in error for error in unsafe_report["errors"])
            )

            valid = export_bundle(tmp_path / "valid.zip", _scan_result())
            with mock.patch.object(evidence, "MAX_ZIP_INPUT_BYTES", 1):
                size_report = verify_bundle(valid)
            self.assertFalse(size_report["valid"])
            self.assertTrue(any("input ZIP exceeds" in error for error in size_report["errors"]))
            with mock.patch.object(evidence, "MAX_ZIP_MEMBER_BYTES", 1):
                member_report = verify_bundle(valid)
            self.assertFalse(member_report["valid"])
            self.assertTrue(
                any("ZIP member exceeds maximum safe size" in error for error in member_report["errors"])
            )

    def test_verifier_detects_duplicate_and_unlisted_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "duplicates.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("README.md", b"first")
                    archive.writestr("README.md", b"second")
                    archive.writestr("extra.json", b"{}")

            report = verify_bundle(archive_path)

            self.assertFalse(report["valid"])
            self.assertTrue(
                any("duplicate archive entry: README.md" in error for error in report["errors"])
            )
            self.assertTrue(any("unlisted ZIP entry" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
