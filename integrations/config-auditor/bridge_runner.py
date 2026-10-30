"""Private worker for scripts/scan-configurations.py.

This module is not a public scanner CLI.  It receives one already-open regular
file descriptor from the authorized parent, copies a bounded snapshot to a
private regular file with the original basename so the upstream scanner
recognizes the file type, and renders one report to stdout.  It imports the
vendored scanner only after process start.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
import tempfile

MAX_FILE_BYTES = 2 * 1024 * 1024
_COPY_CHUNK_BYTES = 64 * 1024
FORMATS = frozenset({"text", "json", "sarif"})
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fd", required=True, type=int)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--display-path", required=True)
    parser.add_argument("--format", required=True, choices=sorted(FORMATS))
    parser.add_argument("--severity", required=True, choices=SEVERITIES)
    return parser


def _load_upstream() -> tuple[object, object, object, tuple[object, object, object]]:
    """Import from this known vendor directory, never from ambient sys.path."""
    vendor_root = str(Path(__file__).resolve().parent)
    if vendor_root not in sys.path:
        sys.path.insert(0, vendor_root)

    from scanner.cli import console
    from scanner.engine import result_json, scan_paths
    from scanner.models import Severity
    from scanner.sarif import result_sarif
    from scanner.scoring import summarize

    return console, result_json, scan_paths, (Severity, result_sarif, summarize)


def _readable_fd(fd: int) -> None:
    descriptor = os.fstat(fd)
    if not stat.S_ISREG(descriptor.st_mode):
        raise ValueError("worker input is not a regular file")
    if descriptor.st_size > MAX_FILE_BYTES:
        raise ValueError("worker input exceeds the reviewed size limit")


def _stable_identity(descriptor: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return metadata that detects ordinary writes during the bounded copy."""
    return (
        descriptor.st_dev,
        descriptor.st_ino,
        descriptor.st_size,
        descriptor.st_mtime_ns,
        descriptor.st_ctime_ns,
    )


def _snapshot_fd(fd: int, staging_path: Path) -> None:
    """Copy one stable, bounded descriptor snapshot to a private regular file.

    ``pread`` leaves the parent descriptor offset untouched. A later pathname
    swap cannot affect this copy, and the scanner cannot follow the caller's
    descriptor through ``/proc``. The before/after metadata check rejects the
    ordinary concurrent-write case rather than scanning a mixed view.
    """
    before = os.fstat(fd)
    _readable_fd(fd)
    expected_size = before.st_size
    identity = _stable_identity(before)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    staging_fd = os.open(staging_path, flags, 0o600)
    try:
        offset = 0
        while offset < expected_size:
            chunk = os.pread(fd, min(_COPY_CHUNK_BYTES, expected_size - offset), offset)
            if not chunk:
                raise ValueError("worker input changed while snapshotting")
            written = 0
            while written < len(chunk):
                count = os.write(staging_fd, chunk[written:])
                if count <= 0:
                    raise OSError("could not write worker snapshot")
                written += count
            offset += len(chunk)
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or _stable_identity(after) != identity:
            raise ValueError("worker input changed while snapshotting")
    finally:
        os.close(staging_fd)


def _safe_name(value: str) -> str:
    candidate = Path(value)
    if candidate.name != value or value in {"", ".", ".."}:
        raise ValueError("invalid target basename")
    return value


def _replace_staging_paths(result: object, staging_path: Path, display_path: str) -> None:
    """Keep private staging paths out of the scanner report."""
    old = str(staging_path)
    for collection in (result.findings, result.errors, result.warnings):
        for item in collection:
            if item.file_path == old:
                item.file_path = display_path


def _render_text(result: object, console: object, severity_type: object, threshold: str) -> tuple[str, bool]:
    severities = list(severity_type)
    limit = severities.index(severity_type(threshold))
    reported = [finding for finding in result.findings if severities.index(finding.severity) <= limit]
    visible = [finding for finding in reported if not finding.suppressed]
    suppressed_count = len(reported) - len(visible)
    result.findings = reported

    # Importing rich through the reviewed upstream CLI has no scanner side effects.
    from rich.markup import escape
    from rich.table import Table

    table = Table(title=f"CloudSentry — {result.files_scanned} file(s) scanned")
    for column in ("Severity", "Rule", "Location", "Finding"):
        table.add_column(column)
    for finding in visible:
        table.add_row(
            finding.severity.value.upper(),
            finding.rule_id,
            f"{finding.file_path}:{finding.line_start or '?'}",
            finding.title,
        )
    with console.capture() as capture:
        console.print(table)
        console.print(f"Risk score: {result.risk_score}/100 (heuristic, not probability)")
        if suppressed_count:
            console.print(
                f"{suppressed_count} suppressed finding(s) not shown; "
                "JSON or SARIF includes their reasons."
            )
        for warning in result.warnings:
            location = f"{warning.file_path}:{warning.line_start or '?'}"
            console.print(f"[yellow]warning: {escape(location)}: {escape(warning.message)}[/yellow]")
        for error in result.errors:
            text = f"{error.kind}: {error.file_path}: {error.message}"
            console.print(f"[red]{escape(text)}[/red]")
    return capture.get(), bool(visible)


def _run(args: argparse.Namespace) -> int:
    _readable_fd(args.fd)
    name = _safe_name(args.target_name)
    console, result_json, scan_paths, support = _load_upstream()
    severity_type, result_sarif, summarize = support

    with tempfile.TemporaryDirectory(prefix="config-auditor-") as temporary:
        staging_path = Path(temporary) / name
        _snapshot_fd(args.fd, staging_path)
        result = scan_paths([staging_path])
        _replace_staging_paths(result, staging_path, args.display_path)

    severities = list(severity_type)
    threshold = severities.index(severity_type(args.severity))
    reported = [finding for finding in result.findings if severities.index(finding.severity) <= threshold]
    visible = [finding for finding in reported if not finding.suppressed]
    result.findings = reported
    result.risk_score, result.severity_counts = summarize(reported)

    if args.format == "json":
        rendered = result_json(result)
    elif args.format == "sarif":
        rendered = result_sarif(result)
    else:
        # _render_text repeats the threshold selection only to render the selected
        # findings; restore pre-filtered findings to avoid broadening results.
        rendered, _ = _render_text(result, console, severity_type, args.severity)

    sys.stdout.write(rendered)
    if not rendered.endswith("\n"):
        sys.stdout.write("\n")
    if result.errors:
        return 2
    return 1 if visible else 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (OSError, ValueError, UnicodeError):
        # The parent deliberately suppresses this process's stderr. Keep this
        # exception path non-verbose if it is invoked during maintenance.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
