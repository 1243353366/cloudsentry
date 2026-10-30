"""Dependency-free contract tests for the authorized CloudSentry bridge."""
from __future__ import annotations

from contextlib import contextmanager
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from reverse_shell_decoy import authorization as authorization

SCRIPT = ROOT / "scripts" / "scan-configurations.py"
spec = importlib.util.spec_from_file_location("config_auditor_bridge", SCRIPT)
assert spec is not None and spec.loader is not None
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


@contextmanager
def _no_signal_guard(grant: object):
    yield grant


class ConfigAuditorBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        # The parent integration adds this operation. Keep these bridge-only tests
        # runnable before that independent parent-file change lands.
        self.operation_patch = patch.object(
            authorization,
            "_OPERATIONS",
            authorization._OPERATIONS | {"configuration_audit"},
        )
        self.operation_patch.start()

    def tearDown(self) -> None:
        self.operation_patch.stop()

    def _target(self, directory: str, name: str = "Dockerfile") -> Path:
        target = Path(directory) / name
        target.write_text("FROM python:3.12-slim\nUSER app\n", encoding="utf-8")
        return target

    def _grant(self) -> MagicMock:
        grant = MagicMock()
        grant.begin.return_value = None
        grant.check.return_value = None
        return grant

    def test_symlink_is_rejected_before_authorization_or_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._target(directory)
            link = Path(directory) / "linked.Dockerfile"
            link.symlink_to(target)
            with patch.object(bridge, "request_authorization") as request, patch.object(
                bridge, "_run_scanner"
            ) as run, contextlib.redirect_stderr(io.StringIO()):
                code = bridge.main(["--target", str(link), "--consent"])
        self.assertEqual(code, 2)
        request.assert_not_called()
        run.assert_not_called()

    def test_directory_is_rejected_before_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(bridge, "request_authorization") as request, contextlib.redirect_stderr(
                io.StringIO()
            ):
                code = bridge.main(["--target", directory, "--consent"])
        self.assertEqual(code, 2)
        request.assert_not_called()

    def test_authorized_invocation_uses_only_fixed_args_and_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._target(directory)
            grant = self._grant()
            completed = subprocess.CompletedProcess([], 1, b'{"status":"ok"}\n', b"ignored")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(bridge, "request_authorization", return_value=grant) as request, patch.object(
                bridge, "cancellation_guard", _no_signal_guard
            ), patch.object(bridge, "_run_scanner", return_value=completed) as run, contextlib.redirect_stdout(
                stdout
            ), contextlib.redirect_stderr(stderr):
                code = bridge.main(
                    [
                        "--target",
                        str(target),
                        "--format",
                        "sarif",
                        "--minimum-severity",
                        "high",
                        "--consent",
                    ]
                )

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), '{"status":"ok"}\n')
        self.assertEqual(stderr.getvalue(), "")
        scope = request.call_args.args[0]
        self.assertEqual(scope.operation, "configuration_audit")
        self.assertIn(str(target.resolve()), scope.input_ref)
        self.assertIn('"format":"sarif"', scope.input_ref)
        self.assertIn('"minimum_severity":"high"', scope.input_ref)
        self.assertEqual(scope.output_ref, "stdout")
        grant.begin.assert_called_once_with(scope)
        grant.check.assert_called_once_with(scope)
        invoked_target, invoked_format, invoked_severity, descriptor = run.call_args.args
        self.assertEqual(invoked_target, target.resolve())
        self.assertEqual(invoked_format, "sarif")
        self.assertEqual(invoked_severity, "high")
        self.assertIsInstance(descriptor, int)

    def test_final_grant_check_blocks_captured_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._target(directory)
            grant = self._grant()
            grant.check.side_effect = bridge.AuthorizationError("revoked")
            completed = subprocess.CompletedProcess([], 0, b'{"sensitive":"report"}\n', b"")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(bridge, "request_authorization", return_value=grant), patch.object(
                bridge, "cancellation_guard", _no_signal_guard
            ), patch.object(bridge, "_run_scanner", return_value=completed), contextlib.redirect_stdout(
                stdout
            ), contextlib.redirect_stderr(stderr):
                code = bridge.main(["--target", str(target), "--consent"])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Configuration audit could not be completed.\n")

    def test_declined_authorization_does_not_open_or_scan_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._target(directory)
            with patch.object(bridge, "request_authorization", return_value=None), patch.object(
                bridge, "_open_authorized_target"
            ) as open_target, patch.object(bridge, "_run_scanner") as run:
                code = bridge.main(["--target", str(target)])
        self.assertEqual(code, 2)
        open_target.assert_not_called()
        run.assert_not_called()

    def test_runner_command_has_no_output_or_arbitrary_flag_channel(self) -> None:
        path = Path("/tmp/selected/Dockerfile")
        command = bridge._runner_command(path, "json", "info", 41)
        self.assertEqual(command[:3], [str(bridge._FIXED_VENV_PYTHON), "-I", str(bridge._RUNNER)])
        self.assertEqual(command[3:], [
            "--fd", "41", "--target-name", "Dockerfile", "--display-path", str(path),
            "--format", "json", "--severity", "info",
        ])
        self.assertNotIn("--output", command)

    def test_revocation_while_worker_is_active_terminates_and_reaps(self) -> None:
        process = MagicMock()
        process.poll.return_value = None
        check = MagicMock(side_effect=[None, bridge.AuthorizationError("revoked")])
        launcher = MagicMock()
        launcher.return_value.__enter__.return_value = process
        with patch.object(bridge.subprocess, "Popen", launcher):
            with self.assertRaises(bridge.AuthorizationError):
                bridge._run_scanner(Path("/selected/Dockerfile"), "json", "info", 41,
                                    permission_check=check)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=1)


if __name__ == "__main__":
    unittest.main()
