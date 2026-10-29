"""Bounded, local-only investigator export for synthetic decoy records.

This module normalizes explicitly selected JSONL audit files into a neutral
report.  It does not scan a host, contact a service, execute input, or infer
that a real system was accessed without authorization.  The resulting ZIP is
an integrity-consistent private packet, not an authenticity or legal finding.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import math
import os
from pathlib import Path
import stat
import sys
from typing import Any

from .evidence import export_bundle
from .input_files import read_regular


MAX_AUDIT_FILES = 4
MAX_AUDIT_BYTES = 2 * 1024 * 1024
MAX_COMBINED_RECORDS = 1_000
MAX_STATE_BYTES = 512 * 1024
MAX_VIRTUAL_OBJECTS = 128
MAX_VIRTUAL_TEXT_BYTES = 64 * 1024
MAX_SAFE_TEXT_CHARS = 512
MAX_CASE_LABEL_CHARS = 256
MAX_TOKEN_INDICATORS = 6

# These fixed labels describe bounded text-pattern classification only.  They
# do not represent execution, intent, competence, identity, or authorization.
LANGUAGES = frozenset(
    {"php", "python", "perl", "ruby", "node", "bash", "sh", "nc", "powershell", "unknown"}
)
TOKEN_INDICATORS = frozenset(
    {
        "php_network_api",
        "php_stream_api",
        "process_api",
        "python_socket_api",
        "shell_path",
        "encoded_text",
    }
)

# ``in_memory_decoy`` is the source name emitted by the existing terminal
# simulator.  It is normalized to the more explicit historical form below so
# a report never presents it as a real terminal or service source.
_SOURCE_ALIASES = {
    "decoy_service_interaction": "decoy_service_interaction",
    "historical_in_memory_decoy": "historical_in_memory_decoy",
    "in_memory_decoy": "historical_in_memory_decoy",
    "bounded_defensive_state_loop": "bounded_defensive_state_loop",
}

# These are the only values copied out of an audit record.  No raw command,
# arguments, environment, key, credential, or arbitrary unknown field is
# copied into the report.
_SAFE_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp_utc": ("timestamp_utc",),
    "event_id": ("event_id", "eventid"),
    "session_id": ("session_id", "sessionid"),
    "event_type": ("event_type",),
    "verb": ("verb",),
    "blocked": ("blocked",),
    "reason": ("reason",),
    "response_mode": ("response_mode",),
    "input_sha256": ("input_sha256",),
    "command_sha256": ("command_sha256",),
    "output_sha256": ("output_sha256",),
    "byte_count": ("byte_count",),
    "chunk_sha256": ("chunk_sha256",),
    "before_state_hashes": (
        "before_state_hashes",
        "beforestatehashes",
        "baseline_sha256",
    ),
    "after_state_hashes": (
        "after_state_hashes",
        "afterstatehashes",
        "state_sha256",
        "post_mutation_baseline_sha256",
    ),
    "mutation": ("mutation",),
    "peer_ip": ("peer_ip",),
    "scope": ("scope",),
    "language_indicator": ("language_indicator",),
    "token_indicators": ("token_indicators",),
}

_HASH_FIELDS = frozenset(
    {
        "input_sha256",
        "command_sha256",
        "output_sha256",
        "chunk_sha256",
        "before_state_hashes",
        "after_state_hashes",
    }
)


class _RecordProblem(ValueError):
    """An invalid record with a deliberately generic, non-reflective code."""


def build_report(
    audit_paths: list[str], state_path: str | None = None, case_label: str = ""
) -> dict[str, Any]:
    """Build a neutral report from explicitly selected local synthetic inputs.

    Every accepted timeline entry is traceable to an input file hash, physical
    JSONL line hash, and physical line index.  Invalid records are skipped and
    counted; they are never silently promoted to authentic incident evidence.
    """
    _validate_audit_paths(audit_paths)
    label = _validate_case_label(case_label)

    source_manifest: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    skipped_by_reason: Counter[str] = Counter()
    warning_counts: Counter[str] = Counter()
    nonblank_records = 0

    for source_index, audit_path in enumerate(audit_paths, start=1):
        raw = read_regular(audit_path, MAX_AUDIT_BYTES)
        source_sha256 = sha256(raw).hexdigest()
        source_name = Path(audit_path).name
        manifest: dict[str, Any] = {
            "source_index": source_index,
            "source_basename": source_name,
            "source_file_sha256": source_sha256,
            "byte_count": len(raw),
            "physical_line_count": 0,
            "recognized_record_count": 0,
            "skipped_record_count": 0,
            "warning_counts": {},
        }
        source_warnings: Counter[str] = Counter()

        for line_index, physical_line in enumerate(raw.splitlines(), start=1):
            manifest["physical_line_count"] += 1
            # A non-empty physical line is a bounded input record whether or
            # not it parses.  This prevents malformed JSONL from evading the
            # aggregate cap.
            if physical_line.strip():
                nonblank_records += 1
                if nonblank_records > MAX_COMBINED_RECORDS:
                    raise ValueError(
                        f"audit inputs exceed the {MAX_COMBINED_RECORDS}-record combined limit"
                    )
            else:
                manifest["skipped_record_count"] += 1
                skipped_by_reason["blank_line"] += 1
                source_warnings["blank_line"] += 1
                continue

            parsed, problem = _parse_jsonl_object(physical_line)
            if problem is not None:
                manifest["skipped_record_count"] += 1
                skipped_by_reason[problem] += 1
                source_warnings[problem] += 1
                continue

            try:
                entry, entry_warnings = _normalize_record(
                    parsed,
                    source_index=source_index,
                    source_name=source_name,
                    source_sha256=source_sha256,
                    line_index=line_index,
                    line_sha256=sha256(physical_line).hexdigest(),
                )
            except _RecordProblem as exc:
                # Codes are fixed by this module and never include hostile
                # record contents or input paths.
                code = str(exc)
                manifest["skipped_record_count"] += 1
                skipped_by_reason[code] += 1
                source_warnings[code] += 1
                continue

            timeline.append(entry)
            manifest["recognized_record_count"] += 1
            source_warnings.update(entry_warnings)
            warning_counts.update(entry_warnings)

        manifest["warning_counts"] = dict(sorted(source_warnings.items()))
        source_manifest.append(manifest)

    state = _load_synthetic_state(state_path) if state_path is not None else None
    timestamp_summary = _timestamp_summary(timeline)
    classifications = Counter(entry["classification"] for entry in timeline)
    observed = _observed_log_summary(timeline)
    synthetic_effects = _synthetic_effects_summary(timeline, state)

    report: dict[str, Any] = {
        "report_schema_version": "1.0",
        "narrative": (
            "Prepared for investigator review. This is a bounded normalization of "
            "operator-selected synthetic decoy records, not proof of real-host "
            "unauthorized access, criminality, identity, authorization status, or "
            "legal admissibility."
        ),
        "operator_assertions": {
            "case_label": label,
            "case_label_status": "operator-supplied label; unverified and not a real-case assertion",
        },
        "independent_claims": {
            "real_host_unauthorized_access": "not_established",
            "visitor_identity": "unknown",
            "remote_os": "unknown",
            "authorization_status": "not_established",
        },
        "classifications": dict(sorted(classifications.items())),
        "counts": {
            "audit_file_count": len(source_manifest),
            "physical_record_count": nonblank_records,
            "recognized_record_count": len(timeline),
            "skipped_record_count": sum(
                int(source["skipped_record_count"]) for source in source_manifest
            ),
            "missing_or_invalid_timestamp_count": timestamp_summary["missing_or_invalid_count"],
            "warning_counts": dict(sorted(warning_counts.items())),
            "skipped_record_counts": dict(sorted(skipped_by_reason.items())),
        },
        "timeline_timestamp_range_utc": {
            "first": timestamp_summary["first"],
            "last": timestamp_summary["last"],
            "valid_timestamp_count": timestamp_summary["valid_count"],
        },
        "timeline": timeline,
        "source_manifest": source_manifest,
        "evidence_separation": {
            "observed_in_supplied_log": observed,
            "synthetic_state_and_effects": synthetic_effects,
            "operator_assertions": {
                "case_label": label,
                "status": "operator-supplied label only; unverified",
            },
            "unknown": [
                "Whether any real host was accessed without authorization.",
                "Visitor identity, including attribution through a network address.",
                "Remote operating system.",
                "Authorization status for any interaction represented in a supplied log.",
            ],
        },
        "limitations": [
            "Connection timestamps and peer IP values, when present, are values recorded in supplied logs and are not independently verified.",
            "A peer IP is a network address, not a person; NAT, proxy, relay, reassignment, and logging error can affect attribution.",
            "A public decoy or honeypot connection does not by itself establish unauthorized access to a real host.",
            "Synthetic terminal effects, virtual privileges, state changes, and fake credential text are inert simulation data, not real host effects or credentials.",
            "Source SHA-256 values support integrity consistency for the supplied bytes; they do not authenticate a source, prove authorship, or establish provenance.",
            "This packet does not provide jurisdiction-specific legal advice or a guarantee of admissibility.",
        ],
        "recommended_independent_corroboration": [
            "Retain and compare original authentication, cloud, and network logs in their native acquisition context.",
            "Review asset inventory and the applicable authorization policy.",
            "Seek records from an external trusted collector where available.",
            "Review ownership and access records before making attribution or authorization conclusions.",
        ],
    }
    if state is not None:
        report["synthetic_state"] = state
    return report


def export_report(
    audit_paths: list[str],
    state_path: str | None,
    output: str | Path,
    case_label: str = "",
) -> Path:
    """Write a new private ZIP packet and a new private Markdown sidecar.

    Both output paths must be absent before any write begins.  The ZIP is
    created through :func:`evidence.export_bundle`; its ``detection.json`` is
    the report built here, while its separate simulation audit remains empty.
    The sidecar is created with exclusive, no-follow permissions and is removed
    on failure.  If sidecar creation fails after ZIP creation, the ZIP is also
    removed only if it is still the inode created by this call.
    """
    output_path = _coerce_path(output, "output")
    sidecar_path = output_path.with_suffix(".md")
    _validate_new_output_pair(output_path, sidecar_path)

    report = build_report(audit_paths, state_path, case_label)
    markdown = _render_markdown(report)
    packet = export_bundle(output_path, report, session_events=[])
    packet_identity = _regular_identity(packet)
    try:
        _write_new_private_text(sidecar_path, markdown)
    except Exception:
        _remove_if_same_regular_file(packet, packet_identity)
        raise
    return packet


def main(argv: list[str] | None = None) -> int:
    """Run the local investigator-export CLI without network activity."""
    parser = argparse.ArgumentParser(
        description=(
            "Create a private investigator-review packet from selected synthetic "
            "decoy JSONL files; no host scan, account access, network, or execution."
        )
    )
    parser.add_argument(
        "--audit",
        action="append",
        required=True,
        metavar="FILE",
        help="selected JSONL audit file (repeat at most four times)",
    )
    parser.add_argument(
        "--state",
        metavar="FILE",
        help="optional selected synthetic virtual-state JSON file",
    )
    parser.add_argument("--output", required=True, metavar="ZIP", help="new ZIP path")
    parser.add_argument(
        "--case-label",
        default="",
        help="operator label only; unverified and not a real-case assertion",
    )
    args = parser.parse_args(argv)
    try:
        packet = export_report(args.audit, args.state, args.output, args.case_label)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Investigator-review ZIP created: {packet}")
    print(f"Human-readable sidecar created: {packet.with_suffix('.md')}")
    print("Prepared for investigator review; source hashes support integrity consistency, not authenticity.")
    return 0


def _validate_audit_paths(audit_paths: list[str]) -> None:
    if not isinstance(audit_paths, list):
        raise TypeError("audit_paths must be a list of selected file paths")
    if not audit_paths:
        raise ValueError("at least one audit file is required")
    if len(audit_paths) > MAX_AUDIT_FILES:
        raise ValueError(f"at most {MAX_AUDIT_FILES} audit files may be selected")
    if any(not isinstance(path, str) or not path for path in audit_paths):
        raise TypeError("each audit path must be a non-empty string")


def _validate_case_label(case_label: str) -> str:
    if not isinstance(case_label, str):
        raise TypeError("case_label must be a string")
    if len(case_label) > MAX_CASE_LABEL_CHARS:
        raise ValueError(f"case_label exceeds the {MAX_CASE_LABEL_CHARS}-character limit")
    return case_label


def _parse_jsonl_object(physical_line: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(physical_line.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, "invalid_json"
    if not isinstance(value, dict):
        return None, "record_not_object"
    return value, None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _normalize_record(
    record: dict[str, Any],
    *,
    source_index: int,
    source_name: str,
    source_sha256: str,
    line_index: int,
    line_sha256: str,
) -> tuple[dict[str, Any], Counter[str]]:
    if record.get("simulation") is not True:
        raise _RecordProblem("simulation_not_true")
    source_kind = _normalized_source_kind(record)
    if source_kind is None:
        raise _RecordProblem("unrecognized_source")

    warnings: Counter[str] = Counter()
    entry: dict[str, Any] = {
        "source_kind": source_kind,
        "source_index": source_index,
        "source_basename": source_name,
        "source_file_sha256": source_sha256,
        "physical_line_index": line_index,
        "physical_line_sha256": line_sha256,
    }
    copied, copy_warnings = _copy_safe_fields(record)
    warnings.update(copy_warnings)
    entry.update(copied)

    timestamp = copied.get("timestamp_utc")
    if timestamp is None:
        entry["timestamp_status"] = "missing_or_invalid"
        warnings["missing_or_invalid_timestamp"] += 1
    else:
        entry["timestamp_status"] = "valid_utc_as_supplied"

    classification, observed, effects, unknown = _classify_record(record, source_kind, timestamp)
    entry["classification"] = classification
    entry["observed_in_supplied_log"] = observed
    entry["synthetic_state_or_effects"] = effects
    entry["unknown"] = unknown
    return entry, warnings


def _normalized_source_kind(record: dict[str, Any]) -> str | None:
    provided: list[str] = []
    for key in ("source_kind", "source"):
        value = record.get(key)
        if isinstance(value, str) and value in _SOURCE_ALIASES:
            provided.append(_SOURCE_ALIASES[value])
        elif key in record:
            return None
    if not provided or len(set(provided)) != 1:
        return None
    return provided[0]


def _copy_safe_fields(record: dict[str, Any]) -> tuple[dict[str, Any], Counter[str]]:
    copied: dict[str, Any] = {}
    warnings: Counter[str] = Counter()
    for normalized_name, aliases in _SAFE_FIELD_ALIASES.items():
        values = [(alias, record[alias]) for alias in aliases if alias in record]
        if not values:
            continue
        # Conflicting aliases are untrustworthy.  Drop the field rather than
        # choosing an arbitrary representation.
        if len(values) > 1 and any(value != values[0][1] for _, value in values[1:]):
            warnings["conflicting_safe_field_excluded"] += 1
            continue
        value = values[0][1]
        if normalized_name == "timestamp_utc":
            if _valid_utc_timestamp(value) is None:
                warnings["invalid_timestamp_excluded"] += 1
                continue
        elif normalized_name == "peer_ip":
            if not _valid_ip_address(value):
                warnings["invalid_peer_ip_excluded"] += 1
                continue
        elif normalized_name in _HASH_FIELDS:
            if not _valid_sha256(value):
                warnings["invalid_hash_excluded"] += 1
                continue
        elif normalized_name == "byte_count":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                warnings["invalid_byte_count_excluded"] += 1
                continue
        elif normalized_name == "language_indicator":
            if not isinstance(value, str) or value not in LANGUAGES:
                warnings["invalid_language_indicator_excluded"] += 1
                continue
        elif normalized_name == "token_indicators":
            if (
                not isinstance(value, list)
                or len(value) > MAX_TOKEN_INDICATORS
                or any(not isinstance(token, str) or token not in TOKEN_INDICATORS for token in value)
            ):
                warnings["invalid_token_indicators_excluded"] += 1
                continue
        elif not _safe_primitive(value):
            warnings["unsafe_safe_field_value_excluded"] += 1
            continue
        # Copy the bounded list rather than retaining a reference to parsed
        # input.  Other allowed values are immutable primitives.
        copied[normalized_name] = list(value) if normalized_name == "token_indicators" else value

    # Unknown fields, including raw command / argument / environment / key /
    # credential fields, are intentionally ignored.  Count only their number;
    # never repeat names or values that might be hostile or sensitive.
    recognized = {
        "simulation",
        "source_kind",
        "source",
        "interaction_observed",
        "observation_is_real",
        *{alias for aliases in _SAFE_FIELD_ALIASES.values() for alias in aliases},
    }
    excluded = len(set(record) - recognized)
    if excluded:
        warnings["unallowlisted_fields_excluded"] += excluded
    return copied, warnings


def _safe_primitive(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return not isinstance(value, str) or len(value) <= MAX_SAFE_TEXT_CHARS
    return isinstance(value, float) and math.isfinite(value)


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _valid_ip_address(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _valid_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed.astimezone(timezone.utc)


def _classify_record(
    record: dict[str, Any], source_kind: str, timestamp: Any
) -> tuple[str, list[str], list[str], list[str]]:
    if source_kind == "decoy_service_interaction":
        if record.get("interaction_observed") is True:
            observed = ["connection_interaction"]
            if timestamp is not None:
                observed.append("timestamp_utc")
            if _valid_ip_address(record.get("peer_ip")):
                observed.append("peer_ip")
            return (
                "logged_interaction_unverified",
                observed,
                ["terminal responses and virtual session effects are synthetic"],
                [
                    "visitor_identity",
                    "network-address attribution (NAT/proxy/relay status unknown)",
                    "remote_os",
                    "authorization_status",
                ],
            )
        return (
            "synthetic_decoy_service_event",
            [],
            ["terminal responses and virtual session effects are synthetic"],
            ["visitor_identity", "remote_os", "authorization_status"],
        )

    if source_kind == "bounded_defensive_state_loop":
        if record.get("observation_is_real") is True:
            return (
                "claimed_local_digest_observation_unverified",
                ["claimed_local_digest_observation"],
                ["virtual privilege and decoy mutation effects remain synthetic"],
                ["whether a claimed digest observation reflects a real host condition"],
            )
        return (
            "purely_synthetic",
            [],
            ["virtual privilege and decoy mutation effects are synthetic"],
            ["real host state"],
        )

    # The remaining accepted source is the in-memory terminal simulator.  It
    # cannot establish who supplied local input or whether any person accessed
    # an actual host.
    return (
        "local_operator_or_unknown_input",
        [],
        ["in-memory terminal responses and virtual filesystem effects are synthetic"],
        ["who supplied the local terminal input", "real host access", "authorization_status"],
    )


def _timestamp_summary(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    timestamps: list[tuple[datetime, str]] = []
    for entry in timeline:
        value = entry.get("timestamp_utc")
        parsed = _valid_utc_timestamp(value)
        if parsed is not None:
            timestamps.append((parsed, value))
    timestamps.sort(key=lambda item: item[0])
    return {
        "first": timestamps[0][1] if timestamps else None,
        "last": timestamps[-1][1] if timestamps else None,
        "valid_count": len(timestamps),
        "missing_or_invalid_count": len(timeline) - len(timestamps),
    }


def _observed_log_summary(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    for entry in timeline:
        fields = entry.get("observed_in_supplied_log")
        if fields:
            observed.append(
                {
                    "source_kind": entry["source_kind"],
                    "classification": entry["classification"],
                    "source_file_sha256": entry["source_file_sha256"],
                    "physical_line_sha256": entry["physical_line_sha256"],
                    "physical_line_index": entry["physical_line_index"],
                    "recorded_fields": fields,
                    "status": "recorded in supplied log; not independently verified",
                }
            )
    return observed


def _synthetic_effects_summary(
    timeline: list[dict[str, Any]], state: dict[str, Any] | None
) -> dict[str, Any]:
    effects: list[dict[str, Any]] = []
    for entry in timeline:
        effects.append(
            {
                "source_kind": entry["source_kind"],
                "classification": entry["classification"],
                "source_file_sha256": entry["source_file_sha256"],
                "physical_line_sha256": entry["physical_line_sha256"],
                "effects": entry["synthetic_state_or_effects"],
            }
        )
    return {
        "timeline_effects": effects,
        "included_virtual_state": state is not None,
        "status": "synthetic simulation data only; not a real-host effect",
    }


def _load_synthetic_state(state_path: str) -> dict[str, Any]:
    if not isinstance(state_path, str) or not state_path:
        raise TypeError("state_path must be a non-empty string when supplied")
    raw = read_regular(state_path, MAX_STATE_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("synthetic state must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("synthetic state must be a JSON object")

    expected = {
        "schema_version",
        "state_kind",
        "simulation",
        "timestamp_utc",
        "virtual_privilege",
        "state_sha256",
        "files",
        "directories",
        "cwd",
    }
    optional = {"provenance_notice"}
    if not expected.issubset(value) or not set(value).issubset(expected | optional):
        raise ValueError("synthetic state does not match the expected schema")
    if "provenance_notice" in value and (
        not isinstance(value["provenance_notice"], str)
        or len(value["provenance_notice"]) > MAX_SAFE_TEXT_CHARS
    ):
        raise ValueError("synthetic state provenance_notice is invalid")
    if value["schema_version"] != "1.0":
        raise ValueError("synthetic state schema_version must be 1.0")
    if value["state_kind"] != "synthetic_virtual_filesystem":
        raise ValueError("synthetic state_kind must be synthetic_virtual_filesystem")
    if value["simulation"] is not True:
        raise ValueError("synthetic state must explicitly set simulation to true")
    if _valid_utc_timestamp(value["timestamp_utc"]) is None:
        raise ValueError("synthetic state timestamp_utc must be a valid UTC timestamp")
    if not isinstance(value["virtual_privilege"], str) or len(value["virtual_privilege"]) > MAX_SAFE_TEXT_CHARS:
        raise ValueError("synthetic state virtual_privilege is invalid")
    if not _valid_sha256(value["state_sha256"]):
        raise ValueError("synthetic state state_sha256 is invalid")
    files = value["files"]
    directories = value["directories"]
    cwd = value["cwd"]
    if not isinstance(files, dict) or not all(
        isinstance(path, str) and isinstance(text, str) for path, text in files.items()
    ):
        raise ValueError("synthetic state files must be a string-to-string mapping")
    if not isinstance(directories, list) or not all(isinstance(path, str) for path in directories):
        raise ValueError("synthetic state directories must be a list of strings")
    if not isinstance(cwd, str):
        raise ValueError("synthetic state cwd must be a string")
    if len(files) + len(directories) > MAX_VIRTUAL_OBJECTS:
        raise ValueError(
            f"synthetic state exceeds the {MAX_VIRTUAL_OBJECTS}-object virtual-state limit"
        )
    if len(set(directories)) != len(directories):
        raise ValueError("synthetic state directories must not contain duplicates")
    virtual_text_bytes = sum(
        len(item.encode("utf-8"))
        for item in [*files.keys(), *files.values(), *directories, cwd]
    )
    if virtual_text_bytes > MAX_VIRTUAL_TEXT_BYTES:
        raise ValueError(
            f"synthetic state exceeds the {MAX_VIRTUAL_TEXT_BYTES}-byte decoded virtual-text limit"
        )

    canonical = json.dumps(
        {"files": files, "directories": sorted(directories), "cwd": cwd},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    calculated = sha256(canonical.encode("utf-8")).hexdigest()
    if calculated.lower() != value["state_sha256"].lower():
        raise ValueError("synthetic state state_sha256 does not match its virtual filesystem")

    return {
        "provenance": (
            "Operator-selected state file declaring simulation:true. All paths and "
            "contents below are inert synthetic virtual filesystem text, including any "
            "fake credential values; they are not real host files or credentials."
        ),
        "source_basename": Path(state_path).name,
        "source_file_sha256": sha256(raw).hexdigest(),
        "schema_version": value["schema_version"],
        "state_kind": value["state_kind"],
        "simulation": True,
        "timestamp_utc": value["timestamp_utc"],
        "virtual_privilege": value["virtual_privilege"],
        "state_sha256": value["state_sha256"],
        "calculated_state_sha256": calculated,
        "files": files,
        "directories": sorted(directories),
        "cwd": cwd,
    }


def _coerce_path(value: str | Path, label: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise TypeError(f"{label} path must be a string or pathlib.Path")
    return Path(value)


def _validate_new_output_pair(output_path: Path, sidecar_path: Path) -> None:
    if output_path == sidecar_path:
        raise ValueError("ZIP output and Markdown sidecar paths must be different")
    for path in (output_path, sidecar_path):
        try:
            parent = os.lstat(path.parent)
        except FileNotFoundError as exc:
            raise FileNotFoundError("output directory does not exist") from exc
        if not stat.S_ISDIR(parent.st_mode):
            raise NotADirectoryError("output parent is not a directory")
        if os.path.lexists(path):
            raise FileExistsError("refusing to overwrite or follow an existing output path")


def _write_new_private_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode):
            raise ValueError("new sidecar path is not a regular file")
        identity = (created.st_dev, created.st_ino)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        _remove_if_same_regular_file(path, identity)
        raise


def _regular_identity(path: Path) -> tuple[int, int] | None:
    try:
        current = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(current.st_mode):
        return None
    return current.st_dev, current.st_ino


def _remove_if_same_regular_file(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = os.lstat(path)
    except OSError:
        return
    if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
        try:
            os.unlink(path)
        except OSError:
            pass


def _render_markdown(report: dict[str, Any]) -> str:
    """Render a small safe summary without copying raw selected input values."""
    counts = report["counts"]
    lines = [
        "# Investigator export packet",
        "",
        "Prepared for investigator review. This sidecar summarizes selected synthetic decoy records; it is not proof of real-host unauthorized access, criminality, identity, or legal admissibility.",
        "",
        "## Operator label",
        "",
        f"Operator-supplied, unverified label: {_markdown_value(report['operator_assertions']['case_label'])}",
        "",
        "## Summary",
        "",
        f"- Selected audit files: {counts['audit_file_count']}",
        f"- Recognized synthetic records: {counts['recognized_record_count']}",
        f"- Skipped records: {counts['skipped_record_count']}",
        f"- Missing or invalid supplied timestamps: {counts['missing_or_invalid_timestamp_count']}",
        "",
        "## Timeline",
        "",
    ]
    timeline = report["timeline"]
    if timeline:
        lines.extend(
            [
                "| Supplied UTC time | Classification | Source kind | Peer IP |",
                "| --- | --- | --- | --- |",
            ]
        )
        for entry in timeline:
            timestamp = entry.get("timestamp_utc", "not recorded")
            peer_ip = entry.get("peer_ip", "not recorded")
            lines.append(
                "| "
                + " | ".join(
                    _markdown_value(value, 120)
                    for value in (
                        timestamp,
                        entry["classification"],
                        entry["source_kind"],
                        peer_ip,
                    )
                )
                + " |"
            )
    else:
        lines.append("No recognized synthetic audit records were included.")
    lines.extend(
        [
            "",
            "## Selected-source integrity references",
            "",
            "| Source basename | SHA-256 of supplied bytes | Recognized | Skipped |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    for source in report["source_manifest"]:
        lines.append(
            "| "
            + " | ".join(
                _markdown_value(value, 120)
                for value in (
                    source["source_basename"],
                    source["source_file_sha256"],
                    source["recognized_record_count"],
                    source["skipped_record_count"],
                )
            )
            + " |"
        )
    if "synthetic_state" in report:
        state = report["synthetic_state"]
        lines.extend(
            [
                "",
                "## Synthetic virtual state",
                "",
                "An optional state file was included only as inert synthetic virtual filesystem text in the ZIP report. Fake credential values, if present there, are not real credentials.",
                f"- Source basename: {_markdown_value(state['source_basename'])}",
                f"- State SHA-256: {_markdown_value(state['state_sha256'])}",
            ]
        )
    lines.extend(
        [
            "",
            "## Limits and next steps",
            "",
            "Connection timestamps and peer IP values are recorded in supplied logs only and are not independently verified. A network address does not identify a person; NAT, proxies, relays, reassignment, and logging error remain possible. A decoy connection does not establish unauthorized access to a real host.",
            "",
            "Source hashes support integrity consistency for supplied bytes; they do not authenticate a source, prove authorship, establish provenance, or guarantee admissibility. Retain original authentication, cloud, and network logs; asset and authorization policy; external trusted-collector records; and ownership/access records for independent review.",
            "",
        ]
    )
    return "\n".join(lines)


def _markdown_value(value: Any, limit: int = 160) -> str:
    """Render only safe scalar text with no Markdown link/formatted syntax."""
    if value is None:
        text = "not recorded"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = "not recorded"
    text = " ".join(text.split())[:limit]
    # Only alphanumeric characters, spaces, dots, commas, pluses, equal signs,
    # and hyphens survive.  Colons, slashes, brackets, backticks, HTML markers,
    # and controls become visible escapes, preventing generated links or markup.
    return "".join(
        char if (char.isalnum() or char in " .,+-=") else f"\\u{ord(char):04x}"
        for char in text
    ) or "not recorded"


__all__ = [
    "MAX_AUDIT_BYTES",
    "MAX_AUDIT_FILES",
    "MAX_COMBINED_RECORDS",
    "MAX_STATE_BYTES",
    "MAX_TOKEN_INDICATORS",
    "MAX_VIRTUAL_OBJECTS",
    "MAX_VIRTUAL_TEXT_BYTES",
    "LANGUAGES",
    "TOKEN_INDICATORS",
    "build_report",
    "export_report",
    "main",
]
