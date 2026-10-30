"""Focused review-8 tests for launcher and configuration-auditor bridge boundaries.

These tests use static launcher inspection and local temporary regular files only.
They do not start a decoy, invoke the vendored scanner, or read customer inputs.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan-configurations.py"
RUNNER = ROOT / "integrations" / "config-auditor" / "bridge_runner.py"


def _load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan_bridge = _load_module("review8_scan_bridge", SCRIPT)
runner = _load_module("review8_bridge_runner", RUNNER)


class LauncherIsolationTests(unittest.TestCase):
    """Launchers must sanitize before running Python or another shell."""

    _launchers = {
        "backup-echo.sh": "start-backup-echo.py",
        "emergency-tarpit.sh": "reverse_shell_decoy.emergency",
        "mirror.sh": "reverse_shell_decoy.honeypot",
        "shellception.sh": "reverse_shell_decoy.shellception",
        "start-honeypot.sh": "reverse_shell_decoy.honeypot",
        "tarpit.sh": "reverse_shell_decoy.honeypot",
    }

    def test_service_launchers_fix_command_path_and_clear_environment(self) -> None:
        for filename, module in self._launchers.items():
            with self.subTest(launcher=filename):
                contents = (ROOT / "scripts" / filename).read_text(encoding="utf-8")
                self.assertTrue(contents.startswith("#!/bin/sh\n"))
                self.assertIn("PATH=/usr/bin:/bin\nexport PATH\n", contents)
                self.assertIn("exec /usr/bin/env -i ", contents)
                self.assertIn("/usr/bin/python3", contents)
                self.assertIn(module, contents)
                self.assertNotIn("command -v python3", contents)
                self.assertNotIn("exec bash", contents)
                self.assertNotIn("#!/usr/bin/env", contents)

    def test_mode_wrappers_clear_environment_before_starting_honeypot(self) -> None:
        for filename, mode in (("mirror.sh", "mirror"), ("tarpit.sh", "sink")):
            with self.subTest(launcher=filename):
                contents = (ROOT / "scripts" / filename).read_text(encoding="utf-8")
                self.assertIn("exec /usr/bin/env -i ", contents)
                self.assertIn(f"--response-mode {mode}", contents)
                self.assertNotIn("start-honeypot.sh", contents)


class ScanBridgeDescriptorTests(unittest.TestCase):
    def test_scanner_child_inherits_only_selected_descriptor_under_clean_environment(self) -> None:
        process = MagicMock()
        process.poll.return_value = 0
        process.returncode = 0
        launcher = MagicMock()
        launcher.return_value.__enter__.return_value = process
        permission_check = MagicMock()

        with patch.object(scan_bridge.subprocess, "Popen", launcher):
            completed = scan_bridge._run_scanner(
                Path("/selected/Dockerfile"), "json", "info", 47, permission_check=permission_check
            )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        _, kwargs = launcher.call_args
        self.assertEqual(kwargs["pass_fds"], (47,))
        self.assertTrue(kwargs["close_fds"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(
            kwargs["env"],
            {
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "PYTHONNOUSERSITE": "1",
            },
        )
        self.assertEqual(permission_check.call_count, 2)

    def test_selected_target_symlink_is_rejected_before_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "Dockerfile"
            selected.write_text("FROM scratch\n", encoding="utf-8")
            link = Path(directory) / "alternatives-Dockerfile"
            link.symlink_to(selected)
            with patch.object(scan_bridge, "request_authorization") as request, contextlib.redirect_stderr(
                io.StringIO()
            ):
                code = scan_bridge.main(["--target", str(link), "--consent"])

        self.assertEqual(code, 2)
        request.assert_not_called()


class BridgeSnapshotTests(unittest.TestCase):
    def test_snapshot_copies_to_private_regular_file_without_consuming_parent_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"FROM python:3.12-slim\n")
            staged = Path(directory) / "Dockerfile"
            descriptor = os.open(source, os.O_RDONLY)
            try:
                os.lseek(descriptor, 4, os.SEEK_SET)
                runner._snapshot_fd(descriptor, staged)
                self.assertFalse(staged.is_symlink())
                self.assertTrue(staged.is_file())
                self.assertEqual(staged.read_bytes(), b"FROM python:3.12-slim\n")
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 4)
            finally:
                os.close(descriptor)

    def test_snapshot_rejects_a_source_changed_while_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"FROM scratch\n")
            staged = Path(directory) / "Dockerfile"
            descriptor = os.open(source, os.O_RDONLY)
            original_pread = runner.os.pread
            changed = False

            def mutate_after_read(fd: int, length: int, offset: int) -> bytes:
                nonlocal changed
                data = original_pread(fd, length, offset)
                if not changed:
                    changed = True
                    with source.open("ab") as mutable:
                        mutable.write(b"# changed\n")
                return data

            try:
                with patch.object(runner.os, "pread", side_effect=mutate_after_read):
                    with self.assertRaises(ValueError):
                        runner._snapshot_fd(descriptor, staged)
            finally:
                os.close(descriptor)

    def test_snapshot_rejects_file_over_the_reviewed_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            with source.open("wb") as handle:
                handle.truncate(runner.MAX_FILE_BYTES + 1)
            descriptor = os.open(source, os.O_RDONLY)
            try:
                with self.assertRaises(ValueError):
                    runner._snapshot_fd(descriptor, Path(directory) / "Dockerfile")
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
