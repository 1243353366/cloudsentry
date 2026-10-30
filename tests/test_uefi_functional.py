"""Mock-only checks for the trusted ARM64 UEFI functional helper."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy import uefi_functional as uefi


class _Process:
    def __init__(self, serial: Path | None = None, marker: bytes = b"") -> None:
        self.returncode: int | None = None
        self.terminated = self.killed = False
        if serial is not None:
            serial.write_bytes(marker)

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class UefiFunctionalTests(unittest.TestCase):
    def test_qemu_command_is_fixed_tcg_networkless_and_readonly_media(self) -> None:
        command = uefi._qemu_command(Path("/firmware.fd"), Path("/vars.fd"),
                                     Path("/private/bundle"), Path("/private/serial"))
        self.assertEqual(command[:14], [
            "/usr/bin/qemu-system-aarch64", "-accel", "tcg", "-machine", "virt", "-cpu",
            "cortex-a57", "-m", "256", "-smp", "1", "-nic", "none", "-display",
        ])
        self.assertIn("none", command)
        self.assertIn("-monitor", command)
        self.assertIn("-serial", command)
        rendered = " ".join(command)
        self.assertIn("readonly=on,file=/firmware.fd", rendered)
        self.assertIn("readonly=on,file=fat:ro:/private/bundle", rendered)
        self.assertNotIn("-enable-kvm", rendered)
        self.assertNotIn("-qmp", rendered)
        self.assertNotIn("usb", rendered.lower())

    def test_serial_end_marker_is_required_for_observed_boot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / "serial"
            process = _Process(serial, b"firmware\n" + uefi._BEGIN + b"\n" + uefi._END + b"\n")
            with patch("reverse_shell_decoy.uefi_functional.subprocess.Popen", return_value=process):
                result = uefi._run_qemu(["fixed-qemu"], serial, lambda: None)
        self.assertTrue(result["probe_begin_observed"])
        self.assertTrue(result["probe_end_observed"])
        self.assertFalse(result["timed_out"])
        self.assertTrue(process.terminated)
        self.assertNotIn("serial_text", result)

    def test_callback_exception_after_launch_terminates_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / "serial"
            process = _Process()
            calls = 0

            def cancelled() -> None:
                nonlocal calls
                calls += 1
                if calls >= 2:  # pre-launch passes; first polling check cancels.
                    raise RuntimeError("cancelled")

            with patch("reverse_shell_decoy.uefi_functional.subprocess.Popen", return_value=process):
                with self.assertRaisesRegex(RuntimeError, "cancelled"):
                    uefi._run_qemu(["fixed-qemu"], serial, cancelled)
        self.assertTrue(process.terminated)
        self.assertIsNotNone(process.returncode)

    def test_api_marks_secure_boot_unknown_without_unsigned_probe_negative(self) -> None:
        plain = {
            "probe_end_observed": True, "probe_begin_observed": True,
            "firmware_security_violation_observed": False,
        }
        secure = {
            "probe_end_observed": False, "probe_begin_observed": False,
            "firmware_security_violation_observed": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            run_dir = workdir / "uefi-functional"
            run_dir.mkdir(mode=0o700)
            probe = run_dir / "efi-bundle" / "EFI" / "BOOT" / "BOOTAA64.EFI"
            probe.parent.mkdir(parents=True)
            probe.write_bytes(b"trusted")
            with patch("reverse_shell_decoy.uefi_functional._require_fixed_files"), \
                 patch("reverse_shell_decoy.uefi_functional._private_directory", return_value=run_dir), \
                 patch("reverse_shell_decoy.uefi_functional._compile_probe", return_value=(probe, "a" * 64)), \
                 patch("reverse_shell_decoy.uefi_functional._variant", side_effect=[plain, secure]):
                report = uefi.run_uefi_probe(workdir)
        self.assertEqual(report["status"], "observed_with_secure_boot_limit")
        self.assertTrue(report["uefi_boot_observed"])
        self.assertFalse(report["negative_unsigned_probe_ran"])
        self.assertEqual(report["secure_boot_enforcement"], "unknown")
        self.assertNotIn("serial", str(report))

    def test_private_directory_rejects_reuse_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(uefi._private_directory(root), root / "uefi-functional")
            with self.assertRaises(ValueError):
                uefi._private_directory(root)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                uefi._private_directory(link)


if __name__ == "__main__":
    unittest.main()
