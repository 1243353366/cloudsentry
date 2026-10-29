"""Bounded, read-only heuristics for selected Linux persistence locations.

The scanner reads configuration text only.  It never executes a file, changes host
state, follows symlinks, expands home directories, or reads process/user secrets.
Findings identify a fixed indicator class and a hash of the matching line instead
of returning raw command text.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import os
import re
import stat
from typing import Callable, Iterable, List, Tuple

# The defaults are intentionally explicit system locations.  Callers may supply
# other explicitly authorized paths (for example, isolated test fixtures).
DEFAULT_ROOTS: Tuple[str, str] = ("/etc/cron.d", "/etc/systemd/system")

# A root has depth zero.  Files directly in it are depth one and files in one
# child directory are depth two; deeper contents are not entered.
MAX_DEPTH = 2
MAX_FILES_PER_ROOT = 256
MAX_BYTES_PER_FILE = 64 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 4096

LIMITATION_NOTICE = (
    "Heuristic, read-only scan of limited Linux persistence locations. Matching "
    "patterns are not proof of malicious activity and legitimate files can produce "
    "false positives. No finding does not rule out compromise or persistence in "
    "other locations, on Windows, or through rootkits."
)

# These patterns name broad indicator classes rather than attempting to prove a
# command's intent.  They deliberately operate on one active configuration line.
_TEMPORARY_EXECUTION_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:tmp|var/tmp|dev/shm)(?:/|$)")
_SYSTEMD_EXECUTION_RE = re.compile(
    r"^\s*Exec(?:Start(?:Pre|Post)?|Reload|Stop(?:Post)?)\s*=", re.IGNORECASE
)
_CRON_EXECUTION_RE = re.compile(
    r"^\s*(?:@\w+\b|(?:[\d*/,-]+\s+){5})", re.IGNORECASE
)
_DIRECT_TEMP_COMMAND_RE = re.compile(
    r"^\s*(?:(?:/usr/bin/env\s+)?(?:/bin/)?(?:sh|bash|dash|zsh|ksh)\s+)?"
    r"/(?:tmp|var/tmp|dev/shm)(?:/|$)",
    re.IGNORECASE,
)
_NETCAT_EXEC_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:nc|ncat)(?=\s)(?:(?![;|&]).)*?"
    r"(?:\s-e(?:\s|$)|\s--exec(?:=|\s|$))",
    re.IGNORECASE,
)
_SHELL_TCP_REDIRECTION_RE = re.compile(
    r"(?:^|[\s;|&])(?:\d*(?:<>|>>|>&|>|<)|&>)\s*/dev/tcp/",
    re.IGNORECASE,
)
_DOWNLOAD_PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|;\r\n]*\|\s*(?:[A-Za-z0-9_./-]*/)?"
    r"(?:sh|bash|dash|zsh|ksh)\b",
    re.IGNORECASE,
)


def scan_persistence(roots: list[str] | None = None) -> dict:
    """Inspect selected persistence configuration directories without host changes.

    Args:
        roots: Explicit directories to inspect.  When omitted, only
            ``/etc/cron.d`` and ``/etc/systemd/system`` are inspected.  Supplied
            fixture directories are supported for authorized testing.

    Returns:
        A JSON-safe dictionary.  Raw file content, commands, usernames, and
        environment data are never included.  ``skipped_files``,
        ``unreadable_files``, and ``truncated_files`` are counts rather than
        lists, so inaccessible path details are not unnecessarily disclosed.
    """

    requested_roots: Iterable[str] = DEFAULT_ROOTS if roots is None else roots
    observed_at_utc = _utc_now()
    inspected_roots: List[str] = []
    warnings: List[str] = []
    warning_set: set[str] = set()
    findings: List[dict] = []
    counters = {
        "examined_files": 0,
        "skipped_files": 0,
        "unreadable_files": 0,
        "truncated_files": 0,
        "bytes_read": 0,
    }

    def warn(message: str) -> None:
        if message not in warning_set:
            warning_set.add(message)
            warnings.append(message)

    for requested_root in requested_roots:
        # abspath is lexical normalization only: unlike realpath/resolve it does
        # not follow a symlink or access a user's home directory.
        root = os.path.abspath(os.fspath(requested_root))
        inspected_roots.append(root)
        _scan_root(root, findings, counters, warn)
        if len(findings) >= MAX_FINDINGS:
            warn("finding limit reached; results may be incomplete")
            break

    # Stable ordering makes machine comparison and incident review predictable.
    findings.sort(
        key=lambda item: (item["path"], item["line_number"], item["indicator"])
    )
    return {
        "simulation": False,
        "observed_at_utc": observed_at_utc,
        "inspected_roots": inspected_roots,
        "findings": findings,
        "warnings": warnings,
        "examined_files": counters["examined_files"],
        "skipped_files": counters["skipped_files"],
        "unreadable_files": counters["unreadable_files"],
        "truncated_files": counters["truncated_files"],
        "limitation_notice": LIMITATION_NOTICE,
    }


def _scan_root(
    root: str,
    findings: List[dict],
    counters: dict,
    warn: Callable[[str], None],
) -> None:
    """Walk one root to the depth/file-count limits without following links."""

    try:
        root_stat = os.lstat(root)
    except FileNotFoundError:
        warn("persistence root is unavailable: %s" % root)
        return
    except PermissionError:
        warn("permission denied while inspecting persistence root: %s" % root)
        return
    except OSError:
        warn("unable to inspect persistence root: %s" % root)
        return

    if stat.S_ISLNK(root_stat.st_mode):
        counters["skipped_files"] += 1
        warn("persistence root is a symlink and was skipped: %s" % root)
        return
    if stat.S_ISREG(root_stat.st_mode):
        _inspect_regular_file(root, findings, counters, warn)
        return
    if not stat.S_ISDIR(root_stat.st_mode):
        counters["skipped_files"] += 1
        warn("persistence root is not a directory and was skipped: %s" % root)
        return

    # Store directory depth with each path.  Reversing sorted child directories
    # gives deterministic depth-first traversal without resolving any paths.
    directories: List[Tuple[str, int]] = [(root, 0)]
    regular_files_seen = 0
    root_file_limit_reported = False
    root_depth_limit_reported = False

    while directories:
        directory, depth = directories.pop()
        try:
            with os.scandir(directory) as scan_entries:
                entries = sorted(scan_entries, key=lambda entry: entry.name)
        except FileNotFoundError:
            # A file or directory can disappear between lstat/scandir on a live host.
            warn("a persistence directory disappeared during inspection")
            continue
        except PermissionError:
            warn("permission denied while listing a persistence directory")
            continue
        except OSError:
            warn("unable to list a persistence directory")
            continue

        child_directories: List[str] = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    counters["skipped_files"] += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    # A child directory itself has depth + 1.  Enter it only when
                    # files inside it can still be at or below MAX_DEPTH.
                    if depth + 1 < MAX_DEPTH:
                        child_directories.append(entry.path)
                    elif not root_depth_limit_reported:
                        root_depth_limit_reported = True
                        warn("maximum persistence scan depth reached; deeper contents were not inspected")
                    continue
                if not entry.is_file(follow_symlinks=False):
                    counters["skipped_files"] += 1
                    continue
            except OSError:
                counters["skipped_files"] += 1
                warn("a persistence directory entry could not be inspected")
                continue

            if regular_files_seen >= MAX_FILES_PER_ROOT:
                counters["skipped_files"] += 1
                if not root_file_limit_reported:
                    root_file_limit_reported = True
                    warn("per-root persistence file limit reached; results may be incomplete")
                continue

            regular_files_seen += 1
            _inspect_regular_file(entry.path, findings, counters, warn)
            if len(findings) >= MAX_FINDINGS:
                return

        # The list is already name-sorted.  Push reversed so pop() retains that
        # ordering without changing filenames or resolving links.
        directories.extend((path, depth + 1) for path in reversed(child_directories))


def _inspect_regular_file(
    path: str,
    findings: List[dict],
    counters: dict,
    warn: Callable[[str], None],
) -> None:
    """Read at most the per-file and global byte budgets from one regular file."""

    remaining = MAX_TOTAL_BYTES - counters["bytes_read"]
    if remaining <= 0:
        counters["skipped_files"] += 1
        warn("total persistence content-read limit reached; results may be incomplete")
        return

    try:
        descriptor = _open_regular_no_follow(path)
    except FileNotFoundError:
        counters["skipped_files"] += 1
        return
    except _NotRegularFile:
        counters["skipped_files"] += 1
        return
    except PermissionError:
        counters["unreadable_files"] += 1
        warn("permission denied while reading one or more persistence files")
        return
    except OSError:
        counters["unreadable_files"] += 1
        warn("unable to read one or more persistence files")
        return

    try:
        file_stat = os.fstat(descriptor)
        # fstat after O_NOFOLLOW closes the ordinary symlink race before any bytes
        # are read.  It also avoids reading a special file if one replaces a path.
        if not stat.S_ISREG(file_stat.st_mode):
            counters["skipped_files"] += 1
            return

        amount = min(MAX_BYTES_PER_FILE, remaining)
        raw = _read_at_most(descriptor, amount)
    except PermissionError:
        counters["unreadable_files"] += 1
        warn("permission denied while reading one or more persistence files")
        return
    except OSError:
        counters["unreadable_files"] += 1
        warn("unable to read one or more persistence files")
        return
    finally:
        os.close(descriptor)

    counters["examined_files"] += 1
    counters["bytes_read"] += len(raw)
    truncated = file_stat.st_size > len(raw)
    if truncated:
        counters["truncated_files"] += 1
        warn("persistence file content was truncated at the read limit; results may be incomplete")

    # A byte-limited read can end in the middle of a line.  Do not evaluate that
    # partial line: it may become a different command once its unseen bytes exist.
    if truncated and raw and not raw.endswith((b"\n", b"\r")):
        last_newline = raw.rfind(b"\n")
        raw = raw[: last_newline + 1] if last_newline >= 0 else b""

    text = raw.decode("utf-8", errors="replace")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(findings) >= MAX_FINDINGS:
            return
        if not _is_active_line(line):
            continue
        for indicator, confidence in _indicators_for_line(line):
            findings.append(
                {
                    "path": path,
                    "line_number": line_number,
                    "indicator": indicator,
                    "confidence": confidence,
                    "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    "simulation": False,
                }
            )


class _NotRegularFile(Exception):
    """Internal signal used when an opened path is not an ordinary file."""


def _open_regular_no_follow(path: str) -> int:
    """Open a candidate without dereferencing a final-component symlink."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _NotRegularFile()
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_at_most(descriptor: int, amount: int) -> bytes:
    """Read no more than ``amount`` bytes, including on short OS reads."""

    chunks: List[bytes] = []
    remaining = amount
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _is_active_line(line: str) -> bool:
    """Treat blank lines and lines whose first token is a comment as inactive."""

    stripped = line.lstrip()
    return bool(stripped) and not stripped.startswith("#")


def _indicators_for_line(line: str) -> List[Tuple[str, str]]:
    """Return fixed, non-content-bearing indicator labels for one active line."""

    indicators: List[Tuple[str, str]] = []
    if _temporary_execution_on_command_line(line):
        indicators.append(("startup_execution_from_temporary_directory", "low"))
    if _NETCAT_EXEC_RE.search(line):
        indicators.append(("netcat_exec_option", "medium"))
    if _SHELL_TCP_REDIRECTION_RE.search(line):
        indicators.append(("shell_tcp_redirection", "medium"))
    if _DOWNLOAD_PIPE_SHELL_RE.search(line):
        indicators.append(("download_and_execute", "medium"))
    return indicators


def _temporary_execution_on_command_line(line: str) -> bool:
    """Recognize temporary paths only where the line carries a command to run."""

    if not _TEMPORARY_EXECUTION_RE.search(line):
        return False
    return bool(
        _SYSTEMD_EXECUTION_RE.search(line)
        or _CRON_EXECUTION_RE.search(line)
        or _DIRECT_TEMP_COMMAND_RE.search(line)
    )


def _utc_now() -> str:
    """Return an unambiguous, JSON-friendly UTC observation timestamp."""

    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
