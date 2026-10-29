"""Privacy-conscious evidence bundle export and verification.

The exporter deliberately collects only a small, read-only operating-system
context.  It never performs network operations, runs commands, or discovers
host identity data such as host names, users, environment variables, or home
directories.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
from typing import Any
import zipfile


TOOL_VERSION = "0.1.0"
"""Version recorded in newly exported evidence manifests."""

SCHEMA_VERSION = "1.0"
"""Schema version for newly exported evidence manifests."""

MAX_AUDIT_EVENTS = 1_000
"""Maximum number of synthetic events accepted in one session audit."""

MAX_AUDIT_BYTES = 2 * 1024 * 1024
"""Maximum UTF-8 size of ``simulation_audit.json`` (2 MiB)."""

# Verification limits protect callers from malformed or zip-bomb-style input.
# They are intentionally larger than the audit-specific bound so a legitimate
# detection report can contain modest structured evidence while still having a
# firm processing limit.
MAX_ZIP_INPUT_BYTES = 64 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 32 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_ZIP_MEMBERS = 16

_PAYLOAD_NAMES = (
    "host_os.json",
    "detection.json",
    "simulation_audit.json",
    "custody_template.md",
    "README.md",
)
_MANIFEST_NAME = "manifest.json"
_REQUIRED_NAMES = frozenset((*_PAYLOAD_NAMES, _MANIFEST_NAME))
_OS_RELEASE_FIELDS = ("NAME", "ID", "VERSION", "VERSION_ID")
_HOST_OS_FIELDS = frozenset(
    ("system", "release", "version", "machine", "freedesktop_os_release")
)

_CUSTODY_TEMPLATE = """# Evidence chain-of-custody worksheet

Use this worksheet to record handling after the bundle has been received.
Complete each field according to the receiving organization's procedures.

## Investigator identity


## Case or reference identifier


## Evidence source and acquisition context


## Received (UTC)


## Storage location or evidence identifier


## Transfer and handling log

| Date/time (UTC) | From | To | Purpose | Signature or record reference |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

## Integrity verification record

Manifest verification performed (UTC):

Verifier and version:

Result and notes:

"""

# This text is intentionally static.  In particular, it must never interpolate
# scan data or synthetic events, both of which are potentially hostile input.
_README = """# Evidence bundle

## Purpose and provenance

This archive separates read-only host context and detection data from the
synthetic activity used by this decoy.

- `host_os.json` is collected at export time from Python's `platform.system`,
  `platform.release`, `platform.version`, `platform.machine`, and, where
  available, the limited `NAME`, `ID`, `VERSION`, and `VERSION_ID` values from
  `platform.freedesktop_os_release`. It is real, read-only host OS context.
  It does not include a hostname, username, environment variables, credentials,
  home-directory paths, or installed-software inventory.
- `detection.json` is the caller-supplied read-only detection result. The
  exporter serializes it without executing a scan, changing it, or independently
  establishing its origin. Treat it as real detection evidence only when its
  calling scanner and acquisition context establish that provenance.
  The CLI separates local host observations, explicitly imported/pasted real
  logs, and optional offline name checks inside this file. Imported content is
  unverified and may describe a different computer. Redacted/normalized imports
  are derivatives; retain the original logs separately. A paste hash identifies
  the received text representation, not the original logfile's bytes.
- `simulation_audit.json` is synthetic decoy session evidence only. Every
  recorded event is required to state `"simulation": true`; any represented
  commands or resource events are simulated and are not records of real shell
  execution, processes, or network activity.
- `custody_template.md` is a blank chain-of-custody worksheet. It intentionally
  leaves investigator identity for the receiving investigator to complete.

## Integrity and verification

`manifest.json` records the schema version, tool version, UTC export start and
end times, and the SHA-256 digest and byte length for every payload file in the
archive. Run `verify_bundle(path)` before relying on a bundle. The hashes help
detect accidental or subsequent modification; they do not authenticate a source,
prove authorship, establish chain of custody, or otherwise prove provenance.
The manifest cannot hash itself, so it covers every archive member except
`manifest.json`.

## Privacy and handling

IP endpoints and process IDs in detection material can be sensitive. By default,
this component does not share, upload, or transmit this bundle anywhere and makes
no network connections. Store and disclose it only through approved evidence and
privacy procedures.

The synthetic audit is bounded to 1,000 input events and 2 MiB of UTF-8 JSON.
Verification also applies ZIP input, member-size, member-count, and total
uncompressed-size safeguards. Verification reads ZIP members directly; it does
not extract archive contents or evaluate any archive data.
"""


def os_info() -> dict[str, Any]:
    """Return the deliberately limited, read-only host OS context.

    No host name, user identity, environment, credential, home-directory, or
    installed-software information is requested or returned.  A missing or
    unreadable freedesktop ``os-release`` file simply yields an empty filtered
    mapping, which keeps this helper portable beyond Linux.
    """
    try:
        raw_os_release = platform.freedesktop_os_release()
    except (AttributeError, OSError):
        raw_os_release: dict[str, str] = {}

    os_release = {
        key: raw_os_release[key]
        for key in _OS_RELEASE_FIELDS
        if isinstance(raw_os_release.get(key), str)
    }
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "freedesktop_os_release": os_release,
    }


def export_bundle(
    output: str | Path,
    scan_result: dict[str, Any],
    session_events: list[dict[str, Any]] | None = None,
) -> Path:
    """Create a new, private evidence ZIP at *output*.

    The destination must not exist, including as a symlink.  It is created with
    exclusive creation and mode ``0o600`` and removed if writing fails.  The
    function performs no network activity and only reads the small OS context
    returned by :func:`os_info`.

    ``scan_result`` is preserved as structured caller input in
    ``detection.json``.  ``session_events`` must contain only dictionaries that
    explicitly have ``simulation`` set to the boolean value ``True``.
    """
    output_path = _coerce_output_path(output)
    _validate_new_output_path(output_path)

    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary")

    started_at = _utc_timestamp()
    audit_bytes = _audit_bytes(session_events)
    payloads = {
        "host_os.json": _json_bytes(os_info(), "host OS information"),
        "detection.json": _json_bytes(scan_result, "scan_result"),
        "simulation_audit.json": audit_bytes,
        "custody_template.md": _CUSTODY_TEMPLATE.encode("utf-8"),
        "README.md": _README.encode("utf-8"),
    }
    ended_at = _utc_timestamp()

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "export_started_at": started_at,
        "export_ended_at": ended_at,
        "files": {
            name: {
                "sha256": sha256(payloads[name]).hexdigest(),
                "bytes": len(payloads[name]),
            }
            for name in _PAYLOAD_NAMES
        },
    }
    contents = dict(payloads)
    contents[_MANIFEST_NAME] = _json_bytes(manifest, "manifest")
    _write_new_zip(output_path, contents)
    return output_path


def verify_bundle(path: str | Path) -> dict[str, Any]:
    """Safely verify an evidence ZIP without extracting or evaluating it.

    The return value always contains ``valid``, ``warnings``, and ``errors``.
    ``valid`` is true only when the archive has the expected safe members,
    conforms to the supported schema checks, and all manifest file hashes and
    byte lengths match.  Verification establishes integrity consistency, not
    source authenticity or provenance.
    """
    result: dict[str, Any] = {"valid": False, "warnings": [], "errors": []}

    try:
        archive_path = _coerce_output_path(path)
    except (TypeError, ValueError):
        result["errors"].append("bundle path must be a string or pathlib.Path")
        return result

    file_handle = None
    try:
        file_handle = _open_verified_input(archive_path)
    except FileNotFoundError:
        result["errors"].append("bundle path does not exist")
        return result
    except ValueError as exc:
        result["errors"].append(str(exc))
        return result
    except OSError:
        result["errors"].append("bundle path could not be opened safely")
        return result

    try:
        with file_handle:
            try:
                with zipfile.ZipFile(file_handle, mode="r") as archive:
                    _verify_archive(archive, result)
            except (zipfile.BadZipFile, EOFError, RuntimeError, OSError):
                result["errors"].append("bundle is not a readable ZIP archive")
    finally:
        # ``with file_handle`` closes the descriptor in normal circumstances;
        # this branch only matters if entering that context failed unexpectedly.
        if file_handle is not None and not file_handle.closed:
            file_handle.close()

    result["valid"] = not result["errors"]
    return result


def _coerce_output_path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise TypeError("path must be a string or pathlib.Path")
    return Path(value)


def _validate_new_output_path(output_path: Path) -> None:
    """Check the destination before exclusive creation, without following it."""
    try:
        parent_stat = os.lstat(output_path.parent)
    except FileNotFoundError as exc:
        raise FileNotFoundError("output directory does not exist") from exc
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise NotADirectoryError("output parent is not a directory")

    # lexists intentionally catches a dangling symlink as well as a regular
    # existing destination.  O_EXCL below closes the race after this check.
    if os.path.lexists(output_path):
        raise FileExistsError("refusing to overwrite or follow an existing output path")


def _write_new_zip(output_path: Path, contents: dict[str, bytes]) -> None:
    """Write an archive directly to a securely created new destination."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(output_path, flags, 0o600)
        created_stat = os.fstat(fd)
        if not stat.S_ISREG(created_stat.st_mode):
            raise ValueError("new output path is not a regular file")
        created_identity = (created_stat.st_dev, created_stat.st_ino)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)

        stream = os.fdopen(fd, "wb")
        fd = None  # The file object owns the descriptor from this point.
        with stream:
            with zipfile.ZipFile(
                stream,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for name in (*_PAYLOAD_NAMES, _MANIFEST_NAME):
                    archive.writestr(name, contents[name])
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if fd is not None:
            os.close(fd)
        _remove_created_file(output_path, created_identity)
        raise


def _remove_created_file(path: Path, identity: tuple[int, int] | None) -> None:
    """Remove only the exact inode this exporter created after a write failure."""
    if identity is None:
        return
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) == identity and stat.S_ISREG(current.st_mode):
        try:
            os.unlink(path)
        except OSError:
            # Preserve the original export exception; a caller can still see an
            # incomplete path, but we never remove a replacement inode.
            pass


def _audit_bytes(session_events: list[dict[str, Any]] | None) -> bytes:
    if session_events is None:
        events: list[dict[str, Any]] = []
    elif not isinstance(session_events, list):
        raise TypeError("session_events must be a list of dictionaries or None")
    else:
        events = session_events

    if len(events) > MAX_AUDIT_EVENTS:
        raise ValueError(f"session_events exceeds the {MAX_AUDIT_EVENTS}-event limit")
    for event in events:
        if not isinstance(event, dict):
            raise TypeError("every session event must be a dictionary")
        if event.get("simulation") is not True:
            raise ValueError("every session event must explicitly set simulation to true")

    audit = _json_bytes(events, "session_events")
    if len(audit) > MAX_AUDIT_BYTES:
        raise ValueError("session_events exceeds the 2 MiB audit JSON limit")
    return audit


def _json_bytes(value: Any, label: str) -> bytes:
    """Encode JSON strictly, with a safe error that does not echo input data."""
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{label} must contain UTF-8 JSON-compatible values") from exc


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _open_verified_input(path: Path):
    """Open a regular, bounded archive without following a final symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    # lstat gives a useful deterministic error on platforms without O_NOFOLLOW.
    path_stat = os.lstat(path)
    if stat.S_ISLNK(path_stat.st_mode):
        raise ValueError("refusing to verify a symlink path")
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError("bundle path is not a regular file")
    if path_stat.st_size > MAX_ZIP_INPUT_BYTES:
        raise ValueError("bundle input ZIP exceeds the maximum safe size")

    fd = os.open(path, flags)
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ValueError("bundle path is not a regular file")
        if opened_stat.st_size > MAX_ZIP_INPUT_BYTES:
            raise ValueError("bundle input ZIP exceeds the maximum safe size")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def _verify_archive(archive: zipfile.ZipFile, result: dict[str, Any]) -> None:
    try:
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        result["errors"].append("bundle directory cannot be read")
        return

    if len(infos) > MAX_ZIP_MEMBERS:
        result["errors"].append("bundle has too many ZIP members")

    names = [info.filename for info in infos]
    counts = Counter(names)
    for name, count in counts.items():
        if count > 1:
            result["errors"].append(_known_or_generic(name, "duplicate archive entry"))

    total_uncompressed = 0
    usable_infos: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = info.filename
        if _unsafe_member(info):
            result["errors"].append("bundle contains an unsafe ZIP member path or type")
        if name not in _REQUIRED_NAMES:
            result["errors"].append("bundle contains an unlisted ZIP entry")
        if info.flag_bits & 0x1:
            result["errors"].append(_known_or_generic(name, "encrypted ZIP member is unsupported"))
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            result["errors"].append(_known_or_generic(name, "ZIP member exceeds maximum safe size"))
        if name == "simulation_audit.json" and info.file_size > MAX_AUDIT_BYTES:
            result["errors"].append("simulation audit exceeds the 2 MiB limit")
        total_uncompressed += info.file_size
        if counts[name] == 1 and name in _REQUIRED_NAMES and not _unsafe_member(info):
            usable_infos[name] = info

    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
        result["errors"].append("bundle total uncompressed ZIP size exceeds the maximum safe size")

    for name in _REQUIRED_NAMES:
        if name not in counts:
            result["errors"].append(f"bundle is missing required entry: {name}")

    # Never decompress a member advertised above a configured safety limit.
    if any(
        info.file_size > MAX_ZIP_MEMBER_BYTES
        or (info.filename == "simulation_audit.json" and info.file_size > MAX_AUDIT_BYTES)
        for info in infos
    ) or total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
        return

    member_data: dict[str, bytes] = {}
    for name, info in usable_infos.items():
        try:
            member_data[name] = _read_member(archive, info)
        except (zipfile.BadZipFile, EOFError, OSError, RuntimeError):
            result["errors"].append(_known_or_generic(name, "ZIP member could not be read"))

    manifest = _parse_manifest(member_data.get(_MANIFEST_NAME), result)
    if manifest is not None:
        _verify_manifest(manifest, member_data, result)

    _verify_payload_shapes(member_data, result)


def _unsafe_member(info: zipfile.ZipInfo) -> bool:
    """Reject traversal, absolute, directory, and symlink-style ZIP members."""
    name = info.filename
    if not name or "\x00" in name or info.is_dir():
        return True
    if name.startswith(("/", "\\")) or "\\" in name:
        return True
    if len(name) >= 2 and name[1] == ":":
        return True
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return True
    unix_mode = info.external_attr >> 16
    return stat.S_ISLNK(unix_mode)


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read a single already-bounded member directly, never to the filesystem."""
    chunks: list[bytes] = []
    total = 0
    with archive.open(info, mode="r") as member:
        while True:
            chunk = member.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ZIP_MEMBER_BYTES or total > info.file_size:
                raise zipfile.BadZipFile("member expanded beyond its declared safe size")
            chunks.append(chunk)
    if total != info.file_size:
        raise zipfile.BadZipFile("member length does not match its directory entry")
    return b"".join(chunks)


def _parse_manifest(raw: bytes | None, result: dict[str, Any]) -> dict[str, Any] | None:
    if raw is None:
        result["errors"].append("manifest.json is missing or unreadable")
        return None
    value = _parse_json(raw, "manifest.json", result)
    if not isinstance(value, dict):
        result["errors"].append("manifest.json must contain a JSON object")
        return None
    return value


def _verify_manifest(
    manifest: dict[str, Any], member_data: dict[str, bytes], result: dict[str, Any]
) -> None:
    schema_version = manifest.get("schema_version")
    if not isinstance(schema_version, str):
        result["errors"].append("manifest schema_version is missing or invalid")
    elif schema_version != SCHEMA_VERSION:
        result["warnings"].append("manifest uses an unsupported schema version")

    tool_version = manifest.get("tool_version")
    if not isinstance(tool_version, str):
        result["errors"].append("manifest tool_version is missing or invalid")
    elif tool_version != TOOL_VERSION:
        result["warnings"].append("manifest was produced by a different tool version")

    _verify_manifest_timestamps(manifest, result)

    files = manifest.get("files")
    if not isinstance(files, dict):
        result["errors"].append("manifest files section is missing or invalid")
        return

    for name in files:
        if name not in _PAYLOAD_NAMES:
            result["errors"].append("manifest lists an unrecognized payload entry")

    for name in _PAYLOAD_NAMES:
        descriptor = files.get(name)
        if not isinstance(descriptor, dict):
            result["errors"].append(f"manifest is missing metadata for {name}")
            continue
        expected_digest = descriptor.get("sha256")
        expected_length = descriptor.get("bytes")
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            result["errors"].append(f"manifest has an invalid SHA-256 value for {name}")
            continue
        if not isinstance(expected_length, int) or isinstance(expected_length, bool) or expected_length < 0:
            result["errors"].append(f"manifest has an invalid byte length for {name}")
            continue
        payload = member_data.get(name)
        if payload is None:
            result["errors"].append(f"cannot verify missing or unreadable payload: {name}")
            continue
        if expected_length != len(payload):
            result["errors"].append(f"byte length mismatch for {name}")
        if expected_digest.lower() != sha256(payload).hexdigest():
            result["errors"].append(f"SHA-256 hash mismatch for {name}")


def _verify_manifest_timestamps(manifest: dict[str, Any], result: dict[str, Any]) -> None:
    started = manifest.get("export_started_at")
    ended = manifest.get("export_ended_at")
    if not isinstance(started, str) or not isinstance(ended, str):
        result["errors"].append("manifest export timestamps are missing or invalid")
        return
    if not (started.endswith("Z") and ended.endswith("Z")):
        result["errors"].append("manifest export timestamps must be UTC Z timestamps")
        return
    try:
        start_time = datetime.fromisoformat(started[:-1] + "+00:00")
        end_time = datetime.fromisoformat(ended[:-1] + "+00:00")
    except ValueError:
        result["errors"].append("manifest export timestamps are not ISO-8601 timestamps")
        return
    if start_time > end_time:
        result["errors"].append("manifest export end precedes export start")


def _verify_payload_shapes(member_data: dict[str, bytes], result: dict[str, Any]) -> None:
    host = _parse_json(member_data.get("host_os.json"), "host_os.json", result)
    if host is not None:
        if not isinstance(host, dict) or set(host) != _HOST_OS_FIELDS:
            result["errors"].append("host_os.json does not match the limited OS schema")
        elif not all(isinstance(host[field], str) for field in _HOST_OS_FIELDS - {"freedesktop_os_release"}):
            result["errors"].append("host_os.json platform values must be strings")
        else:
            os_release = host["freedesktop_os_release"]
            if (
                not isinstance(os_release, dict)
                or not set(os_release).issubset(_OS_RELEASE_FIELDS)
                or not all(isinstance(value, str) for value in os_release.values())
            ):
                result["errors"].append("host_os.json os-release values are invalid")

    detection = _parse_json(member_data.get("detection.json"), "detection.json", result)
    if detection is not None and not isinstance(detection, dict):
        result["errors"].append("detection.json must contain a JSON object")

    audit = _parse_json(member_data.get("simulation_audit.json"), "simulation_audit.json", result)
    if audit is not None:
        if not isinstance(audit, list):
            result["errors"].append("simulation_audit.json must contain a JSON list")
        elif len(audit) > MAX_AUDIT_EVENTS:
            result["errors"].append("simulation audit exceeds the event limit")
        else:
            for event in audit:
                if not isinstance(event, dict) or event.get("simulation") is not True:
                    result["errors"].append(
                        "simulation audit contains a non-simulation event"
                    )
                    break


def _parse_json(raw: bytes | None, name: str, result: dict[str, Any]) -> Any | None:
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
        return json.loads(text, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        result["errors"].append(f"{name} is not valid UTF-8 JSON")
        return None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _known_or_generic(name: str, prefix: str) -> str:
    """Avoid reflecting untrusted ZIP paths in verifier output."""
    if name in _REQUIRED_NAMES:
        return f"{prefix}: {name}"
    return prefix


__all__ = [
    "MAX_AUDIT_BYTES",
    "MAX_AUDIT_EVENTS",
    "MAX_ZIP_INPUT_BYTES",
    "MAX_ZIP_MEMBER_BYTES",
    "MAX_ZIP_MEMBERS",
    "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
    "SCHEMA_VERSION",
    "TOOL_VERSION",
    "export_bundle",
    "os_info",
    "verify_bundle",
]
