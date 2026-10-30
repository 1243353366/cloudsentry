#!/usr/bin/env python3
"""Run one authorized, local, non-executing configuration audit.

The bridge accepts one selected Terraform, Dockerfile, or Compose file only. It
never accepts a directory, cloud credential, output path, arbitrary upstream
flag, provider account, remote URL, remediation request, or provisioning action.
Customer bytes are not opened until a fresh exact-scope authorization grant has
been issued and begun. The report is written only to stdout after a final grant
check; no report file is created.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reverse_shell_decoy.authorization import (  # noqa: E402
    AuthorizationError,
    AuthorizationScope,
    cancellation_guard,
    request_authorization,
)

MAX_FILE_BYTES = 2 * 1024 * 1024
FORMATS = ("text", "json", "sarif")
# Values are the reviewed upstream scanner's Severity enum, in its CLI order.
MINIMUM_SEVERITIES = ("critical", "high", "medium", "low", "info")
_FIXED_VENV_PYTHON = ROOT / ".config-auditor-venv" / "bin" / "python"
_RUNNER = ROOT / "integrations" / "config-auditor" / "bridge_runner.py"
_TIMEOUT_SECONDS = 45
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class TargetValidationError(ValueError):
    """The operator-selected pathname is outside this bridge's file boundary."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Authorized local static audit of one explicitly selected Terraform, Dockerfile, "
            "or Compose file. Reports go to stdout only."
        )
    )
    parser.add_argument("--target", required=True, metavar="FILE", help="one explicit regular file")
    parser.add_argument("--format", choices=FORMATS, default="json")
    parser.add_argument(
        "--minimum-severity", choices=MINIMUM_SEVERITIES, default="info", metavar="SEVERITY"
    )
    parser.add_argument(
        "--consent",
        action="store_true",
        help="issue this invocation's fresh local authorization without a TTY prompt",
    )
    return parser


def _canonical_regular_target(value: str) -> tuple[Path, tuple[int, int, int]]:
    """Validate metadata only; this function never opens or reads customer bytes."""
    try:
        selected = Path(value).expanduser()
        before = os.lstat(selected)
        if not stat.S_ISREG(before.st_mode):
            raise TargetValidationError("selected input must be a regular file")
        if before.st_size > MAX_FILE_BYTES:
            raise TargetValidationError("selected input exceeds the reviewed size limit")
        canonical = Path(os.path.realpath(selected))
        after = os.lstat(canonical)
    except (OSError, ValueError) as exc:
        raise TargetValidationError("selected input is unavailable") from exc
    if not stat.S_ISREG(after.st_mode):
        raise TargetValidationError("selected input must be a regular file")
    identity = (before.st_dev, before.st_ino, before.st_size)
    if identity != (after.st_dev, after.st_ino, after.st_size):
        raise TargetValidationError("selected input changed while resolving")
    return canonical, identity


def _open_authorized_target(path: Path, identity: tuple[int, int, int]) -> int:
    """Safely open the already-authorized file without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise TargetValidationError("selected input must be a regular file")
        if (current.st_dev, current.st_ino, current.st_size) != identity:
            raise TargetValidationError("selected input changed after authorization")
        if current.st_size > MAX_FILE_BYTES:
            raise TargetValidationError("selected input exceeds the reviewed size limit")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _scope_for(path: Path, output_format: str, severity: str) -> AuthorizationScope:
    # Structured canonical scope data prevents delimiter ambiguity in literal filenames.
    input_ref = json.dumps(
        {
            "format": output_format,
            "minimum_severity": severity,
            "target": str(path),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return AuthorizationScope("configuration_audit", input_ref, "stdout")


def _runner_command(path: Path, output_format: str, severity: str, descriptor: int) -> list[str]:
    return [
        str(_FIXED_VENV_PYTHON),
        "-I",
        str(_RUNNER),
        "--fd",
        str(descriptor),
        "--target-name",
        path.name,
        "--display-path",
        str(path),
        "--format",
        output_format,
        "--severity",
        severity,
    ]


def _run_scanner(path: Path, output_format: str, severity: str, descriptor: int, *,
                 permission_check: Callable[[], None]) -> subprocess.CompletedProcess[bytes]:
    # No cloud credential or user site package is inherited. All command arguments
    # are fixed by this bridge; only the prevalidated target path and enum values vary.
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
    }
    permission_check()
    command = _runner_command(path, output_format, severity, descriptor)
    with tempfile.TemporaryFile() as output:
        with subprocess.Popen(command, cwd=ROOT / "integrations" / "config-auditor", env=environment,
                              stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                              pass_fds=(descriptor,)) as process:
            try:
                deadline = time.monotonic() + _TIMEOUT_SECONDS
                while process.poll() is None:
                    permission_check()
                    if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > _MAX_OUTPUT_BYTES:
                        raise TargetValidationError("worker deadline or output bound")
                    time.sleep(0.05)
                permission_check()
                output.seek(0)
                content = output.read(_MAX_OUTPUT_BYTES + 1)
                if len(content) > _MAX_OUTPUT_BYTES:
                    raise TargetValidationError("worker output bound")
                return subprocess.CompletedProcess(command, process.returncode, content, b"")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1)


def _write_stdout(data: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(data)
        stream.flush()
    else:  # Allows the dependency-free unit tests to use io.StringIO.
        sys.stdout.write(data.decode("utf-8", errors="replace"))


def _failure() -> int:
    print("Configuration audit could not be completed.", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        target, identity = _canonical_regular_target(args.target)
        scope = _scope_for(target, args.format, args.minimum_severity)
    except (TargetValidationError, TypeError, ValueError):
        return _failure()

    # Authorization is requested after non-content metadata validation but before any
    # open/read of the selected file. A declined/non-interactive request emits no report.
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        return 2

    descriptor = -1
    try:
        with cancellation_guard(grant):
            grant.begin(scope)
            descriptor = _open_authorized_target(target, identity)
            completed = _run_scanner(target, args.format, args.minimum_severity, descriptor,
                                     permission_check=lambda: grant.check(scope))
            os.close(descriptor)
            descriptor = -1
            # Capture before this final permission check; never release a report after
            # expiry, revocation, interruption, or scope mutation.
            grant.check(scope)
        if completed.returncode not in {0, 1, 2} or not completed.stdout:
            return _failure()
        _write_stdout(completed.stdout)
        return completed.returncode
    except (
        AuthorizationError,
        OSError,
        subprocess.SubprocessError,
        TargetValidationError,
        UnicodeError,
    ):
        return _failure()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
