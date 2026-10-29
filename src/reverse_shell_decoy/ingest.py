"""Bounded, local-only import of explicitly selected log content.

This module never uploads input, opens network connections, executes input, writes
input to disk, or tries to discover other files.  Imported content is untrusted and
is normalized only for review; it cannot authenticate a source or establish an
attacker identity.
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, BinaryIO, TextIO

MAX_INPUT_BYTES = 8 * 1024 * 1024
"""Maximum complete source content accepted by either ingestion API (8 MiB)."""

MAX_LINE_BYTES = 256 * 1024
"""Maximum raw physical-line size accepted from imported content (256 KiB)."""

MAX_RECORDS = 10_000
"""Maximum physical input lines inspected from one import."""

MAX_TEXT_CHARS = 4_096
"""Maximum normalized text retained for any one textual record field."""

MAX_INVALID_JSON_WARNINGS = 100
"""Maximum individual invalid-JSONL warnings emitted for a single import."""

MAX_MARKER_CHARS = 64
"""Maximum marker length accepted by :func:`ingest_pasted`."""

_ALLOWED_JSONL_FIELDS = (
    "timestamp",
    "time",
    "event",
    "process",
    "pid",
    "domain",
    "package",
    "service",
    "message",
    "source_ip",
    "remote_address",
    "remote_port",
    "local_address",
    "local_port",
    "session_id",
    "input_sha256",
    "event_id",
    "claimed_os",
    "inferred_os",
    "simulation",
)

_STRING_JSONL_FIELDS = frozenset(
    {
        "event",
        "process",
        "domain",
        "package",
        "service",
        "message",
        "source_ip",
        "remote_address",
        "local_address",
        "session_id",
        "input_sha256",
        "event_id",
        "claimed_os",
        "inferred_os",
    }
)
_PORT_JSONL_FIELDS = frozenset({"remote_port", "local_port"})
_TIMESTAMP_JSONL_FIELDS = frozenset({"timestamp", "time"})
_MAX_PID = 2_147_483_647
_MAX_TIMESTAMP_ABS = 9_223_372_036_854_775_807

# The timestamp is retained as source text only.  It is intentionally not parsed,
# converted, ordered, or replaced with the import time.
_ISO_TIMESTAMP = re.compile(
    r"(?<![0-9])"
    r"(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"(?![0-9])"
)

# Redaction is deliberately broad rather than a claim of comprehensive secret
# detection.  It covers common key/value and HTTP-authorization representations.
_AUTHORIZATION_VALUE = re.compile(
    r"(?ix)\b(?P<prefix>authorization\s*(?::|=)\s*)"
    r"(?P<value>(?:(?:bearer|basic|token)\s+)?[^\s,;}\]]+)"
)
_SECRET_VALUE = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key)\b\s*(?:[:=])\s*)"
    r"(?P<value>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s,;}\]]+)"
)
_AUTHORIZATION_WORDS = re.compile(
    r"(?ix)\b(?P<prefix>authorization\s+)"
    r"(?P<value>(?:bearer|basic|token)\s+\S+)"
)
_BEARER_VALUE = re.compile(r"(?ix)\b(?P<prefix>bearer\s+)(?P<value>\S+)")

_NOTICES = [
    "Imported log content has an untrusted origin.",
    "Imported log content cannot establish an authentic attacker identity.",
    "Sensitive-looking values are conservatively redacted; redaction is not guaranteed to remove every secret.",
    "Imported claimed_os and inferred_os values are unverified claims, not observed local host OS facts.",
    "Any per-record simulation value is an untrusted claim; root simulation:false describes this import operation, not a verified real-world effect.",
]
_PASTED_NOTICES = [
    *_NOTICES,
    "Pasted input is a clipboard/text-stream representation; its UTF-8 hash is not a hash of original logfile bytes.",
    "Pasted content cannot authenticate its source, provenance, or identity.",
]


def ingest_logs(path: str | Path, format: str = "text") -> dict[str, Any]:
    """Import one explicitly selected local log file without uploading it.

    Args:
        path: Path to one existing regular file.  A final symlink, directory, FIFO,
            socket, or device is rejected before any stream read.
        format: ``"text"`` for physical text lines or ``"jsonl"`` for JSON-object
            lines.  JSONL keeps only a small allowlist of fields.

    Returns:
        A JSON-safe mapping containing the source basename, SHA-256 of the complete
        raw source file, UTC ingestion time, redacted normalized records, warnings,
        fixed provenance notices, ``source_kind: "imported_real_log"``, and
        ``simulation: false``.

    The function reads incrementally and refuses a file over 8 MiB, a physical line
    over 256 KiB, or more than 10,000 physical lines.  It does not return a partial
    result or partial digest when a limit is exceeded.  ``record_sha256`` values are
    hashes of the exact raw physical line bytes, including its line terminator when
    one was present.
    """
    _validate_format(format)
    stream, filename = _open_regular_input(path)
    try:
        with stream:
            digest, records, warnings = _consume_raw_lines(_read_binary_lines(stream), format)
            # Reject a changed file rather than reporting a digest for a potentially
            # partial snapshot.  The descriptor itself is stable, and the second
            # stat detects ordinary truncate/append races during the stream read.
            final_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(final_stat.st_mode) or final_stat.st_size != digest[1]:
                raise ValueError("input changed while being read")
            if final_stat.st_size > MAX_INPUT_BYTES:
                raise ValueError("input exceeds the 8 MiB limit")
    except OSError as exc:
        raise ValueError("input could not be read safely") from exc

    return _result(filename, digest[0], format, records, warnings, _NOTICES)


def ingest_pasted(stream: TextIO, format: str = "text", marker: str = "ENDLOG") -> dict[str, Any]:
    """Import pasted text from a caller-provided text stream without disk writes.

    ``stream`` is supplied by the caller (for example, an interactive text input),
    so this API never opens a path or reads ``sys.stdin`` itself.  It reads bounded
    physical lines until a line equal to ``marker`` (with only its line ending
    removed) or EOF.  The marker is excluded from records and hashes.  The marker
    must be non-empty, at most 64 characters, and contain no whitespace or newline.

    The returned ``sha256`` is calculated from the exact UTF-8 representation of
    text delivered by the supplied stream, excluding the marker.  Clipboard/text
    stream decoding can differ from original log-file bytes, so this digest is not
    evidence of an original logfile's byte identity or source authenticity.
    """
    _validate_format(format)
    _validate_marker(marker)
    if not hasattr(stream, "readline"):
        raise TypeError("stream must provide a text readline method")

    digest, records, warnings = _consume_raw_lines(_read_pasted_lines(stream, marker), format)
    return _result("pasted-input", digest[0], format, records, warnings, _PASTED_NOTICES)


def _result(
    filename: str,
    digest: str,
    format: str,
    records: list[dict[str, Any]],
    warnings: list[str],
    notices: list[str],
) -> dict[str, Any]:
    return {
        "filename": filename,
        "sha256": digest,
        "ingested_at": _utc_timestamp(),
        "format": format,
        "source_kind": "imported_real_log",
        "simulation": False,
        "record_count": len(records),
        "records": records,
        "warnings": warnings,
        "notices": list(notices),
    }


def _validate_format(format: str) -> None:
    if not isinstance(format, str) or format not in {"text", "jsonl"}:
        raise ValueError("format must be 'text' or 'jsonl'")


def _validate_marker(marker: str) -> None:
    if not isinstance(marker, str):
        raise TypeError("marker must be a string")
    if not marker or len(marker) > MAX_MARKER_CHARS or any(char.isspace() for char in marker):
        raise ValueError("marker must be non-empty, no more than 64 characters, and contain no whitespace")


def _open_regular_input(value: str | Path) -> tuple[BinaryIO, str]:
    """Open a final regular path without following a final symlink."""
    if not isinstance(value, (str, Path)):
        raise TypeError("path must be a string or pathlib.Path")
    path = Path(value)
    try:
        initial_stat = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError("input path could not be inspected safely") from exc

    if stat.S_ISLNK(initial_stat.st_mode):
        raise ValueError("refusing to ingest a symlink path")
    if not stat.S_ISREG(initial_stat.st_mode):
        raise ValueError("input path is not a regular file")
    if initial_stat.st_size > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the 8 MiB limit")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("input path could not be opened safely") from exc

    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ValueError("input path is not a regular file")
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            initial_stat.st_dev,
            initial_stat.st_ino,
        ):
            raise ValueError("input path changed while opening")
        if opened_stat.st_size > MAX_INPUT_BYTES:
            raise ValueError("input exceeds the 8 MiB limit")
        return os.fdopen(descriptor, "rb"), path.name
    except Exception:
        os.close(descriptor)
        raise


def _read_binary_lines(stream: BinaryIO) -> Iterator[bytes]:
    while True:
        # Explicitly bounded so an untrusted physical line cannot cause an
        # unbounded allocation or read.
        raw_line = stream.readline(MAX_LINE_BYTES + 1)
        if not raw_line:
            return
        yield raw_line


def _read_pasted_lines(stream: TextIO, marker: str) -> Iterator[bytes]:
    """Yield pasted UTF-8 bytes through marker/EOF, without any disk operation."""
    while True:
        # This caps decoded characters.  The encoded byte-size limit is enforced in
        # _consume_raw_lines as well, which handles non-ASCII text safely.
        text_line = stream.readline(MAX_LINE_BYTES + 1)
        if not isinstance(text_line, str):
            raise TypeError("stream.readline must return text strings")
        if not text_line:
            return
        if _without_text_line_ending(text_line) == marker:
            return
        try:
            yield text_line.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("pasted input is not UTF-8 encodable") from exc


def _consume_raw_lines(
    raw_lines: Iterator[bytes], format: str
) -> tuple[tuple[str, int], list[dict[str, Any]], list[str]]:
    """Hash and normalize bounded raw lines shared by file and pasted imports."""
    hasher = sha256()
    total_bytes = 0
    physical_lines = 0
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    truncated_text = False
    invalid_json_warnings = 0
    omitted_invalid_warning = False

    for raw_line in raw_lines:
        if not isinstance(raw_line, bytes):
            raise TypeError("input reader must yield bytes")
        total_bytes += len(raw_line)
        if total_bytes > MAX_INPUT_BYTES:
            raise ValueError("input exceeds the 8 MiB limit")
        hasher.update(raw_line)

        physical_lines += 1
        if physical_lines > MAX_RECORDS:
            raise ValueError("input exceeds the 10000-record limit")
        if len(raw_line) > MAX_LINE_BYTES:
            raise ValueError("input contains a line exceeding the 256 KiB limit")

        if format == "text":
            record, did_truncate = _normalise_text_record(raw_line, physical_lines)
            records.append(record)
            truncated_text = truncated_text or did_truncate
            continue

        record, did_truncate, invalid_reason = _normalise_jsonl_record(raw_line, physical_lines)
        truncated_text = truncated_text or did_truncate
        if record is not None:
            records.append(record)
        elif invalid_reason is not None:
            if invalid_json_warnings < MAX_INVALID_JSON_WARNINGS:
                warnings.append(f"JSONL {invalid_reason} at line {physical_lines}; line skipped")
                invalid_json_warnings += 1
            elif not omitted_invalid_warning:
                warnings.append("Additional invalid JSONL lines were skipped; individual warnings are capped")
                omitted_invalid_warning = True

    if truncated_text:
        warnings.append("One or more text values were truncated to 4096 characters")
    return (hasher.hexdigest(), total_bytes), records, warnings


def _normalise_text_record(raw_line: bytes, line_number: int) -> tuple[dict[str, Any], bool]:
    body = _without_line_ending(raw_line)
    decoded = body.decode("utf-8", errors="replace")
    message, did_truncate = _redact_and_trim(decoded)
    record: dict[str, Any] = {
        "line_number": line_number,
        "message": message,
        "record_sha256": sha256(raw_line).hexdigest(),
    }
    timestamp = _extract_iso_timestamp(decoded)
    if timestamp is not None:
        record["timestamp"] = timestamp
    return record, did_truncate


def _normalise_jsonl_record(
    raw_line: bytes, line_number: int
) -> tuple[dict[str, Any] | None, bool, str | None]:
    """Safely filter one JSONL object, returning a bounded parse-warning reason."""
    decoded = _without_line_ending(raw_line).decode("utf-8", errors="replace")
    if not decoded.strip():
        return None, False, None
    try:
        loaded = json.loads(decoded, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None, False, "parse error"
    if not isinstance(loaded, dict):
        return None, False, "non-object record"

    record: dict[str, Any] = {
        "line_number": line_number,
        "record_sha256": sha256(raw_line).hexdigest(),
    }
    did_truncate = False
    for field in _ALLOWED_JSONL_FIELDS:
        if field not in loaded:
            continue
        keep, cleaned, was_trimmed = _normalise_jsonl_scalar(field, loaded[field])
        if keep:
            record[field] = cleaned
            did_truncate = did_truncate or was_trimmed

    return record, did_truncate, None


def _normalise_jsonl_scalar(field: str, value: Any) -> tuple[bool, Any, bool]:
    """Keep only bounded primitive values appropriate for one allowlisted field.

    Endpoint addresses and operating-system labels remain source text, not parsed or
    asserted as facts.  Nested values, command arguments, environment mappings, and
    all non-allowlisted fields never enter the normalized record.
    """
    if field in _TIMESTAMP_JSONL_FIELDS:
        # Preserve timestamp representation without parsing or converting it.
        if isinstance(value, str):
            cleaned, was_trimmed = _redact_and_trim(value)
            return True, cleaned, was_trimmed
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and -_MAX_TIMESTAMP_ABS <= value <= _MAX_TIMESTAMP_ABS
        ):
            return True, value, False
        return False, None, False
    if field in _STRING_JSONL_FIELDS:
        if not isinstance(value, str):
            return False, None, False
        cleaned, was_trimmed = _redact_and_trim(value)
        return True, cleaned, was_trimmed
    if field in _PORT_JSONL_FIELDS:
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65_535:
            return True, value, False
        return False, None, False
    if field == "pid":
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_PID:
            return True, value, False
        return False, None, False
    if field == "simulation":
        # This is retained only as a source claim.  It cannot override the root
        # import marker, which is always simulation:false.
        if isinstance(value, bool):
            return True, value, False
    return False, None, False


def _without_line_ending(raw_line: bytes) -> bytes:
    if raw_line.endswith(b"\n"):
        raw_line = raw_line[:-1]
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
    return raw_line


def _without_text_line_ending(text_line: str) -> str:
    if text_line.endswith("\n"):
        text_line = text_line[:-1]
        if text_line.endswith("\r"):
            text_line = text_line[:-1]
    return text_line


def _redact_and_trim(value: str) -> tuple[str, bool]:
    """Apply conservative display redaction and a per-field text bound."""
    redacted = _AUTHORIZATION_VALUE.sub(
        lambda match: match.group("prefix") + "[REDACTED]", value
    )
    redacted = _SECRET_VALUE.sub(lambda match: match.group("prefix") + "[REDACTED]", redacted)
    redacted = _AUTHORIZATION_WORDS.sub(
        lambda match: match.group("prefix") + "[REDACTED]", redacted
    )
    redacted = _BEARER_VALUE.sub(lambda match: match.group("prefix") + "[REDACTED]", redacted)
    if len(redacted) > MAX_TEXT_CHARS:
        return redacted[:MAX_TEXT_CHARS], True
    return redacted, False


def _extract_iso_timestamp(value: str) -> str | None:
    match = _ISO_TIMESTAMP.search(value)
    return match.group(1) if match is not None else None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_INVALID_JSON_WARNINGS",
    "MAX_LINE_BYTES",
    "MAX_MARKER_CHARS",
    "MAX_RECORDS",
    "MAX_TEXT_CHARS",
    "ingest_logs",
    "ingest_pasted",
]
