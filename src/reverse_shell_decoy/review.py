"""Deterministic, local-only post-scan incident review summaries.

This module only summarizes a scan result already present in memory.  It does not
scan, probe, execute, write files, contact a network service, call an LLM, or
perform remediation or retaliation.  Optional decoy audit metadata is read only
when an explicit caller supplies selected audit paths to :func:`make_review`.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
import re
import sys
from typing import Any, TextIO


REVIEW_SCHEMA_VERSION = "1.0"
MAX_REVIEW_LIST_ITEMS = 1_000
MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_NODES = 100_000
MAX_CANONICAL_BYTES = 8 * 1024 * 1024
MAX_CANONICAL_STRING_BYTES = 512 * 1024
MAX_CONSENT_LINE_CHARS = 64

SUPPORTED_COMMANDS = frozenset(
    {
        "scan",
        "os",
        "listeners",
        "persistence",
        "names",
        "audit",
        "cloud",
        "collect-cloud",
    }
)

_PERSISTENCE_INDICATORS = frozenset(
    {
        "startup_execution_from_temporary_directory",
        "netcat_exec_option",
        "shell_tcp_redirection",
        "download_and_execute",
    }
)
_EXPOSURES = frozenset({"loopback", "wildcard", "interface"})
_CLOUD_COVERAGE_FLAGS = (
    "manual_snapshot_unverified",
    "record_completeness_unknown",
    "no_usable_records",
    "records_without_validated_timestamps",
    "records_with_unvalidated_timestamp_text",
    "unparseable_records",
    "input_unparseable",
    "record_limit_reached",
)
_AUDIT_CLASSIFICATIONS = frozenset(
    {
        "logged_interaction_unverified",
        "claimed_local_digest_observation_unverified",
        "synthetic_decoy_service_event",
        "purely_synthetic",
        "local_operator_or_unknown_input",
    }
)
_SAFE_LANGUAGES = frozenset(
    {"php", "python", "perl", "ruby", "node", "bash", "sh", "nc", "powershell", "unknown"}
)
_SAFE_TOKEN_INDICATORS = frozenset(
    {
        "php_network_api",
        "php_stream_api",
        "process_api",
        "python_socket_api",
        "shell_path",
        "encoded_text",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_BASENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class _ReviewSchemaError(ValueError):
    """Internal non-reflective schema error."""


def make_review(
    scan_result: dict,
    command: str,
    audit_paths: list[str] | None = None,
) -> dict:
    """Build one bounded review from an already-created scan result.

    The report is deterministic for the supplied inputs.  It contains aggregate
    counts, fixed caveats, selected source digests, and supplied UTC observation
    timestamps only; it deliberately does not copy raw findings, endpoints,
    payloads, credentials, filenames, paths, warnings, or other free-form input.

    ``audit_paths`` is optional.  If selected audit paths are supplied, the
    investigator module performs its own bounded, local-only normalization.  The
    resulting review retains aggregate metadata and file digests, never audit
    records or raw contents.

    Raises:
        ValueError: for an invalid review input schema.  The message is fixed and
        never includes caller-controlled content.
    """
    _validate_review_inputs(scan_result, command, audit_paths)
    try:
        canonical_hash = _canonical_result_sha256(scan_result)
        state = _ReviewState()
        scan_summary, defensive = _summarize_command(scan_result, command, state)
        supplied_timestamps = _supplied_utc_timestamps(scan_result, command)
        native_digests = _native_source_digests(scan_result, command)
        audit_metadata = _audit_metadata(audit_paths)
        if audit_metadata is not None:
            native_digests.update(audit_metadata["source_sha256"])

        source_warning_count = state.warning_count + (
            audit_metadata["warning_count"] if audit_metadata is not None else 0
        )
        warnings_present = source_warning_count > 0
        review = {
            "review_schema_version": REVIEW_SCHEMA_VERSION,
            "review_purpose": (
                "Deterministic local incident-review summary of an already supplied "
                "scan result. It does not perform a scan, network action, remediation, "
                "retaliation, upload, or legal determination."
            ),
            "scan_command": command,
            "consent_record": {
                "purpose": "explicit local generation of this incident-review summary",
                "authorization_scope": (
                    "review_generation_only; not authorization to scan, visit, access, "
                    "or interact with any system or person"
                ),
                "authenticated_identity": "not_established",
                "persistence": "not recorded or cached",
            },
            "scan_summary": scan_summary,
            "their_capabilities": _capabilities_section(audit_metadata),
            "my_weaknesses": _defensive_section(defensive, state),
            "legally_important_information": {
                "source_and_canonical_sha256": {
                    "canonical_scan_result_sha256": canonical_hash,
                    "canonical_scan_result_sha256_scope": (
                        "SHA-256 of this tool's canonical JSON representation of the "
                        "supplied scan result; it is not a hash of original evidence bytes "
                        "and does not authenticate origin, authorship, or provenance."
                    ),
                    "native_source_sha256": [
                        {
                            "sha256": digest,
                            "scope": (
                                "digest value already supplied by a source report; its "
                                "origin and evidence scope remain unverified here"
                            ),
                        }
                        for digest in sorted(native_digests)[:MAX_REVIEW_LIST_ITEMS]
                    ],
                },
                "report_supplied_utc_timestamps": supplied_timestamps,
                "claims_not_established": {
                    "real_host_unauthorized_access": "not_established",
                    "visitor_identity": "unknown",
                    "remote_os": "unknown",
                    "authorization_status": "not_established",
                },
                "independent_records_needed": [
                    "original records retained in their native acquisition context",
                    "chain-of-custody and handling records",
                    "asset ownership records",
                    "applicable authorization policy",
                    "independent corroboration from trusted sources where available",
                ],
                "legal_limit": (
                    "This summary is not jurisdiction-specific legal advice, a legal proof, "
                    "an admissibility determination, or an all-clear conclusion."
                ),
            },
            "warnings": {
                "source_warnings_present": warnings_present,
                "source_warning_count": source_warning_count,
                "schema_gaps": sorted(state.schema_gaps)[:MAX_REVIEW_LIST_ITEMS],
                "fixed_caveats": [
                    "Raw findings, payloads, credentials, paths, endpoints, and warning text are not copied into this review.",
                    "Missing logs, empty findings, or incomplete coverage are not an all-clear conclusion.",
                    "An exposed binding does not establish Internet reachability or a backdoor.",
                    "A shell-connection heuristic does not establish an outbound connection, intent, or compromise.",
                ],
            },
        }
        return review
    except _ReviewSchemaError as exc:
        raise ValueError("scan result does not match the expected review schema") from None
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        # Never relay an exception that could contain a hostile value or path.
        raise ValueError("scan result could not be safely summarized") from None


def offer_review(scan_result: dict, command: str) -> bool:
    """Offer one review after an explicit CLI scan, returning whether it was made.

    A non-interactive invocation does nothing at all: it neither reads stdin nor
    creates a report.  Every interactive invocation prompts afresh; ``y`` and
    ``yes`` are the only accepted answers.  Review output is written only to
    stderr so an existing scan JSON document on stdout remains untouched.
    """
    if not _request_explicit_consent():
        return False
    try:
        report = make_review(scan_result, command)
        sys.stderr.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
        sys.stderr.write("\n")
        sys.stderr.flush()
        return True
    except (Exception, KeyboardInterrupt):
        # This is deliberately generic.  A review failure must not disclose scan
        # contents or change the success/failure semantics of the completed scan.
        _safe_stderr("Local incident-review summary could not be generated.\n")
        return False


def _request_explicit_consent(description: str | None = None) -> bool:
    """Prompt once only when stdin and stderr are interactive.

    ``description`` is restricted to a safe scan-file basename for the standalone
    script.  It is never derived from scan, audit, or result contents.
    """
    if not _interactive_streams():
        return False
    if description:
        _safe_stderr("Selected scan file: %s.\n" % _safe_basename(description))
    _safe_stderr("Local only: no uploads occur, and this summary is not legal proof.\n")
    _safe_stderr("Generate a local incident-review summary from these scan results? [y/N] ")
    try:
        response = sys.stdin.readline(MAX_CONSENT_LINE_CHARS)
    except (OSError, ValueError, KeyboardInterrupt):
        return False
    except Exception:
        # Some caller-provided stream implementations can fail unusually; decline
        # without exposing their exception text or trying another read.
        return False
    return isinstance(response, str) and response.strip().lower() in {"y", "yes"}


def _interactive_streams() -> bool:
    try:
        return bool(sys.stdin.isatty()) and bool(sys.stderr.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _safe_stderr(text: str) -> None:
    """Best-effort diagnostic output without letting an output failure propagate."""
    try:
        sys.stderr.write(text)
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def _safe_basename(value: str) -> str:
    base = os.path.basename(value)
    if not base:
        return "selected-scan.json"
    cleaned = _SAFE_BASENAME_RE.sub("_", base)[:128]
    return cleaned or "selected-scan.json"


def _validate_review_inputs(scan_result: Any, command: Any, audit_paths: Any) -> None:
    if type(scan_result) is not dict:
        raise ValueError("scan result does not match the expected review schema")
    if not isinstance(command, str) or command not in SUPPORTED_COMMANDS:
        raise ValueError("scan result does not match the expected review schema")
    if audit_paths is not None and (
        type(audit_paths) is not list
        or any(not isinstance(path, str) or not path for path in audit_paths)
    ):
        raise ValueError("scan result does not match the expected review schema")


class _CanonicalState:
    def __init__(self) -> None:
        self.nodes = 0
        self.string_bytes = 0
        self.seen: set[int] = set()


def _canonical_result_sha256(value: dict) -> str:
    """Hash a bounded canonical JSON representation without emitting its contents."""
    state = _CanonicalState()
    normalized = _canonical_value(value, state, 0)
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _ReviewSchemaError() from None
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise _ReviewSchemaError()
    return sha256(encoded).hexdigest()


def _canonical_value(value: Any, state: _CanonicalState, depth: int) -> Any:
    if depth > MAX_CANONICAL_DEPTH:
        raise _ReviewSchemaError()
    state.nodes += 1
    if state.nodes > MAX_CANONICAL_NODES:
        raise _ReviewSchemaError()
    value_type = type(value)
    if value is None or value_type is bool or value_type is int:
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise _ReviewSchemaError()
        return value
    if value_type is str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            raise _ReviewSchemaError() from None
        if len(encoded) > MAX_CANONICAL_STRING_BYTES:
            raise _ReviewSchemaError()
        state.string_bytes += len(encoded)
        if state.string_bytes > MAX_CANONICAL_BYTES:
            raise _ReviewSchemaError()
        return value
    if value_type is list:
        if len(value) > MAX_CANONICAL_NODES or id(value) in state.seen:
            raise _ReviewSchemaError()
        state.seen.add(id(value))
        try:
            return [_canonical_value(item, state, depth + 1) for item in value]
        finally:
            state.seen.remove(id(value))
    if value_type is dict:
        if len(value) > MAX_CANONICAL_NODES or id(value) in state.seen:
            raise _ReviewSchemaError()
        state.seen.add(id(value))
        try:
            copied: dict[str, Any] = {}
            for key in sorted(value):
                if type(key) is not str:
                    raise _ReviewSchemaError()
                copied[key] = _canonical_value(value[key], state, depth + 1)
            return copied
        except TypeError:
            raise _ReviewSchemaError() from None
        finally:
            state.seen.remove(id(value))
    raise _ReviewSchemaError()


class _ReviewState:
    def __init__(self) -> None:
        self.schema_gaps: set[str] = set()
        self.warning_count = 0

    def gap(self, name: str) -> None:
        self.schema_gaps.add(name)


def _list_field(mapping: Any, key: str, state: _ReviewState, gap: str) -> list[Any] | None:
    if type(mapping) is not dict or key not in mapping:
        state.gap(gap)
        return None
    value = mapping[key]
    if type(value) is not list:
        state.gap(gap)
        return None
    return value


def _dict_field(mapping: Any, key: str, state: _ReviewState, gap: str) -> dict[str, Any] | None:
    if type(mapping) is not dict or key not in mapping or type(mapping[key]) is not dict:
        state.gap(gap)
        return None
    return mapping[key]


def _count_field(mapping: Any, key: str, state: _ReviewState, gap: str) -> int | None:
    if type(mapping) is not dict or key not in mapping:
        state.gap(gap)
        return None
    value = mapping[key]
    if type(value) is not int or value < 0:
        state.gap(gap)
        return None
    return value


def _bool_field(mapping: Any, key: str, state: _ReviewState, gap: str) -> bool | None:
    if type(mapping) is not dict or key not in mapping:
        state.gap(gap)
        return None
    value = mapping[key]
    if type(value) is not bool:
        state.gap(gap)
        return None
    return value


def _warning_count(mapping: Any, state: _ReviewState, gap: str) -> int:
    warnings = _list_field(mapping, "warnings", state, gap)
    if warnings is None:
        return 0
    count = len(warnings)
    state.warning_count += count
    if count > MAX_REVIEW_LIST_ITEMS:
        state.gap("warning_list_exceeds_review_limit")
    return count


def _safe_count(value: list[Any] | None) -> int | None:
    return len(value) if value is not None else None


def _bounded_items(values: list[Any], state: _ReviewState, gap: str) -> list[Any]:
    if len(values) > MAX_REVIEW_LIST_ITEMS:
        state.gap(gap)
    return values[:MAX_REVIEW_LIST_ITEMS]


def _summarize_command(
    result: dict[str, Any], command: str, state: _ReviewState
) -> tuple[dict[str, Any], dict[str, Any]]:
    if command == "scan":
        return _summarize_scan(result, state)
    if command == "os":
        return _summarize_os(result, state)
    if command == "listeners":
        return _summarize_listeners(result, state)
    if command == "persistence":
        return _summarize_persistence(result, state)
    if command == "names":
        return _summarize_names(result, state)
    if command == "audit":
        return _summarize_audit(result, state)
    if command == "cloud":
        return _summarize_cloud(result, state)
    return _summarize_collect_cloud(result, state)


def _summarize_scan(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = _list_field(result, "findings", state, "scan_findings_missing_or_invalid")
    warning_count = _warning_count(result, state, "scan_warnings_missing_or_invalid")
    examined = _count_field(result, "examined_connections", state, "scan_examined_connections_missing_or_invalid")
    count = _safe_count(findings)
    summary: dict[str, Any] = {
        "kind": "shell_connection_snapshot",
        "shell_linked_connection_finding_count": count,
        "source_warning_count": warning_count,
    }
    if examined is not None:
        summary["examined_connection_count"] = examined
    defensive = {
        "indicator_counts": {
            "shell_linked_connection_heuristics": count,
        },
        "exposure_flags": {
            "shell_connection_heuristic_observed": bool(count),
            "connection_direction_established": False,
        },
    }
    return summary, defensive


def _summarize_os(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    os_context = _source_os_context(result, state, "os_context_missing_or_invalid")
    _warning_count(result, state, "os_warnings_missing_or_invalid") if "warnings" in result else None
    return (
        {"kind": "limited_local_os_context", "source_os_context": os_context},
        {"indicator_counts": {}, "exposure_flags": {}},
    )


def _summarize_listeners(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    listeners = _list_field(result, "listeners", state, "listeners_missing_or_invalid")
    warning_count = _warning_count(result, state, "listener_warnings_missing_or_invalid")
    exposure_counts = {exposure: 0 for exposure in sorted(_EXPOSURES)}
    unrecognized = 0
    if listeners is not None:
        for listener in _bounded_items(listeners, state, "listener_list_exceeds_review_limit"):
            if type(listener) is not dict:
                unrecognized += 1
                continue
            exposure = listener.get("exposure")
            if type(exposure) is str and exposure in _EXPOSURES:
                exposure_counts[exposure] += 1
            else:
                unrecognized += 1
    listener_count = _safe_count(listeners)
    summary = {
        "kind": "local_listener_inventory",
        "listener_count": listener_count,
        "listener_exposure_counts": exposure_counts,
        "source_warning_count": warning_count,
    }
    if unrecognized:
        summary["unrecognized_listener_schema_count"] = unrecognized
    defensive = {
        "indicator_counts": {"listener_bindings": listener_count},
        "exposure_flags": {
            "wildcard_binding_observed": exposure_counts["wildcard"] > 0,
            "interface_binding_observed": exposure_counts["interface"] > 0,
            "non_loopback_binding_count": exposure_counts["wildcard"] + exposure_counts["interface"],
        },
    }
    return summary, defensive


def _summarize_persistence(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = _list_field(result, "findings", state, "persistence_findings_missing_or_invalid")
    warning_count = _warning_count(result, state, "persistence_warnings_missing_or_invalid")
    indicator_counts = {name: 0 for name in sorted(_PERSISTENCE_INDICATORS)}
    unrecognized = 0
    if findings is not None:
        for finding in _bounded_items(findings, state, "persistence_finding_list_exceeds_review_limit"):
            indicator = finding.get("indicator") if type(finding) is dict else None
            if type(indicator) is str and indicator in _PERSISTENCE_INDICATORS:
                indicator_counts[indicator] += 1
            else:
                unrecognized += 1
    summary: dict[str, Any] = {
        "kind": "selected_persistence_indicator_scan",
        "persistence_indicator_count": _safe_count(findings),
        "persistence_indicator_counts": indicator_counts,
        "source_warning_count": warning_count,
    }
    for name in ("examined_files", "skipped_files", "unreadable_files", "truncated_files"):
        value = _count_field(result, name, state, "persistence_%s_missing_or_invalid" % name)
        if value is not None:
            summary[name] = value
    if unrecognized:
        summary["unrecognized_persistence_finding_schema_count"] = unrecognized
    return (
        summary,
        {"indicator_counts": indicator_counts, "exposure_flags": {}},
    )


def _summarize_names(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = _list_field(result, "findings", state, "name_findings_missing_or_invalid")
    warning_count = _warning_count(result, state, "name_warnings_missing_or_invalid")
    summary: dict[str, Any] = {
        "kind": "offline_name_similarity_check",
        "name_review_finding_count": _safe_count(findings),
        "source_warning_count": warning_count,
    }
    for name in ("checked_count", "compared_pairs"):
        value = _count_field(result, name, state, "names_%s_missing_or_invalid" % name)
        if value is not None:
            summary[name] = value
    complete = _bool_field(result, "complete", state, "names_complete_missing_or_invalid")
    if complete is not None:
        summary["comparison_complete"] = complete
    return (
        summary,
        {"indicator_counts": {"name_similarity_review_cues": _safe_count(findings)}, "exposure_flags": {}},
    )


def _summarize_cloud(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    events = _list_field(result, "events", state, "cloud_events_missing_or_invalid")
    findings = _list_field(result, "findings", state, "cloud_findings_missing_or_invalid")
    warning_count = _warning_count(result, state, "cloud_warnings_missing_or_invalid")
    summary: dict[str, Any] = {
        "kind": "manual_cloud_log_analysis",
        "event_count": _safe_count(events),
        "finding_count": _safe_count(findings),
        "source_warning_count": warning_count,
    }
    nested = _dict_field(result, "summary", state, "cloud_summary_missing_or_invalid")
    if nested is not None:
        coverage = nested.get("coverage_status")
        if type(coverage) is str and coverage in {"unknown", "partial"}:
            summary["coverage_status"] = coverage
        else:
            state.gap("cloud_coverage_status_missing_or_invalid")
        missing = nested.get("missing_coverage")
        if type(missing) is dict:
            flags: dict[str, bool | int] = {}
            for name in _CLOUD_COVERAGE_FLAGS:
                value = missing.get(name)
                if type(value) is bool or (type(value) is int and value >= 0):
                    flags[name] = value
            summary["coverage_flags"] = flags
        else:
            state.gap("cloud_missing_coverage_missing_or_invalid")
    return (
        summary,
        {"indicator_counts": {"cloud_review_findings": _safe_count(findings)}, "exposure_flags": {}},
    )


def _summarize_collect_cloud(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    events = _list_field(result, "events", state, "collected_cloud_events_missing_or_invalid")
    warning_count = _warning_count(result, state, "collected_cloud_warnings_missing_or_invalid")
    coverage = _dict_field(result, "coverage", state, "collected_cloud_coverage_missing_or_invalid")
    summary: dict[str, Any] = {
        "kind": "manual_bounded_cloud_collection",
        "event_count": _safe_count(events),
        "source_warning_count": warning_count,
    }
    if coverage is not None:
        for name in ("pages_fetched", "maximum_pages", "maximum_events", "events_returned"):
            value = _count_field(coverage, name, state, "collected_cloud_%s_missing_or_invalid" % name)
            if value is not None:
                summary[name] = value
        truncated = _bool_field(coverage, "truncated", state, "collected_cloud_truncated_missing_or_invalid")
        if truncated is not None:
            summary["bounded_sample_truncated"] = truncated
    return (
        summary,
        {"indicator_counts": {"collected_cloud_events": _safe_count(events)}, "exposure_flags": {}},
    )


def _summarize_audit(result: dict[str, Any], state: _ReviewState) -> tuple[dict[str, Any], dict[str, Any]]:
    host = _dict_field(result, "host_observations", state, "audit_host_observations_missing_or_invalid")
    _warning_count(result, state, "audit_warnings_missing_or_invalid") if "warnings" in result else None
    if host is None:
        return (
            {"kind": "combined_local_audit", "component_counts": {}},
            {"indicator_counts": {}, "exposure_flags": {}},
        )

    shell = _dict_field(host, "shell_connections", state, "audit_shell_connections_missing_or_invalid")
    listeners = _dict_field(host, "listeners", state, "audit_listeners_missing_or_invalid")
    persistence = _dict_field(host, "persistence_indicators", state, "audit_persistence_missing_or_invalid")
    os_context = _source_os_context(host.get("host_os"), state, "audit_source_os_missing_or_invalid")

    component_counts: dict[str, int | None] = {}
    defensive_indicators: dict[str, int | None] = {}
    exposure_flags: dict[str, bool | int] = {}
    if shell is not None:
        shell_findings = _list_field(shell, "findings", state, "audit_shell_findings_missing_or_invalid")
        _warning_count(shell, state, "audit_shell_warnings_missing_or_invalid")
        shell_count = _safe_count(shell_findings)
        component_counts["shell_linked_connection_heuristics"] = shell_count
        defensive_indicators["shell_linked_connection_heuristics"] = shell_count
        exposure_flags["shell_connection_heuristic_observed"] = bool(shell_count)
        exposure_flags["connection_direction_established"] = False
    if listeners is not None:
        listener_summary, listener_defensive = _summarize_listeners(listeners, state)
        listener_count = listener_summary.get("listener_count")
        component_counts["listener_bindings"] = listener_count if type(listener_count) is int else None
        defensive_indicators["listener_bindings"] = listener_count if type(listener_count) is int else None
        exposure_flags.update(listener_defensive["exposure_flags"])
    if persistence is not None:
        persistence_summary, persistence_defensive = _summarize_persistence(persistence, state)
        persistence_count = persistence_summary.get("persistence_indicator_count")
        component_counts["persistence_indicators"] = (
            persistence_count if type(persistence_count) is int else None
        )
        defensive_indicators.update(persistence_defensive["indicator_counts"])

    imported = result.get("imported_logs")
    if imported is not None and type(imported) is dict:
        record_count = _count_field(imported, "record_count", state, "audit_imported_log_record_count_missing_or_invalid")
        if record_count is not None:
            component_counts["imported_log_records"] = record_count
        _warning_count(imported, state, "audit_imported_log_warnings_missing_or_invalid")
    elif imported is not None:
        state.gap("audit_imported_logs_invalid")

    names = result.get("offline_name_checks")
    if names is not None and type(names) is dict:
        name_findings = _list_field(names, "findings", state, "audit_name_findings_missing_or_invalid")
        component_counts["name_similarity_review_cues"] = _safe_count(name_findings)
        defensive_indicators["name_similarity_review_cues"] = _safe_count(name_findings)
        _warning_count(names, state, "audit_name_warnings_missing_or_invalid")
    elif names is not None:
        state.gap("audit_offline_name_checks_invalid")

    return (
        {
            "kind": "combined_local_audit",
            "source_os_context": os_context,
            "component_counts": component_counts,
        },
        {"indicator_counts": defensive_indicators, "exposure_flags": exposure_flags},
    )


def _source_os_context(value: Any, state: _ReviewState, gap: str) -> dict[str, Any]:
    """Retain only presence of documented OS fields, never values or host identity."""
    if type(value) is not dict:
        state.gap(gap)
        return {"reported": False, "included_field_names": []}
    allowed = ("system", "release", "version", "machine", "freedesktop_os_release")
    fields = [name for name in allowed if name in value]
    os_release = value.get("freedesktop_os_release")
    release_fields: list[str] = []
    if type(os_release) is dict:
        release_fields = [name for name in ("NAME", "ID", "VERSION", "VERSION_ID") if name in os_release]
    elif "freedesktop_os_release" in value:
        state.gap("source_os_release_missing_or_invalid")
    return {
        "reported": bool(fields),
        "included_field_names": fields,
        "freedesktop_os_release_field_names": release_fields,
        "hostname_included": False,
    }


def _capabilities_section(audit_metadata: dict[str, Any] | None) -> dict[str, Any]:
    section: dict[str, Any] = {
        "label": "observed_tooling_and_decoy_actions",
        "not_a_real_attacker_capability_score": True,
        "not_an_attribution_or_identity_finding": True,
    }
    if audit_metadata is None or audit_metadata["recognized_record_count"] == 0:
        section.update(
            {
                "status": "unknown",
                "reason": (
                    "No recognized selected decoy-audit observations were supplied; "
                    "observed tooling and decoy actions are unknown."
                ),
            }
        )
        return section
    section.update(
        {
            "status": "bounded_selected_decoy_audit_observations",
            "recognized_audit_record_count": audit_metadata["recognized_record_count"],
            "audit_classification_counts": audit_metadata["classification_counts"],
            "language_indicator_counts": audit_metadata["language_indicator_counts"],
            "token_indicator_counts": audit_metadata["token_indicator_counts"],
            "statement": (
                "These are fixed labels observed in selected synthetic decoy audit "
                "metadata, not evidence of execution, intent, competence, identity, "
                "or unauthorized access to a real host."
            ),
        }
    )
    return section


def _defensive_section(defensive: dict[str, Any], state: _ReviewState) -> dict[str, Any]:
    indicators = {
        key: value
        for key, value in sorted(defensive.get("indicator_counts", {}).items())
        if type(key) is str and (type(value) is int or value is None)
    }
    flags = {
        key: value
        for key, value in sorted(defensive.get("exposure_flags", {}).items())
        if type(key) is str and (type(value) is bool or type(value) is int)
    }
    return {
        "label": "defensive_review_indicators",
        "indicator_counts": indicators,
        "exposure_flags": flags,
        "not_proven_vulnerabilities_or_backdoors": True,
        "coverage_gaps": sorted(state.schema_gaps)[:MAX_REVIEW_LIST_ITEMS],
        "interpretation_limits": [
            "An exposed local binding is not proof of Internet reachability, maliciousness, or a backdoor.",
            "A shell heuristic is not proof of an outward connection, intent, or compromise.",
            "No finding or missing coverage does not establish that a system is clear.",
        ],
    }


def _audit_metadata(audit_paths: list[str] | None) -> dict[str, Any] | None:
    if not audit_paths:
        return None
    try:
        from . import investigator

        report = investigator.build_report(audit_paths)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise _ReviewSchemaError() from None

    counts = report.get("counts") if type(report) is dict else None
    timeline = report.get("timeline") if type(report) is dict else None
    manifest = report.get("source_manifest") if type(report) is dict else None
    if type(counts) is not dict or type(timeline) is not list or type(manifest) is not list:
        raise _ReviewSchemaError()
    recognized = counts.get("recognized_record_count")
    skipped = counts.get("skipped_record_count")
    if type(recognized) is not int or recognized < 0 or type(skipped) is not int or skipped < 0:
        raise _ReviewSchemaError()

    classifications: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    tokens: Counter[str] = Counter()
    for entry in timeline[:MAX_REVIEW_LIST_ITEMS]:
        if type(entry) is not dict:
            continue
        classification = entry.get("classification")
        if type(classification) is str and classification in _AUDIT_CLASSIFICATIONS:
            classifications[classification] += 1
        language = entry.get("language_indicator")
        if type(language) is str and language in _SAFE_LANGUAGES:
            languages[language] += 1
        indicators = entry.get("token_indicators")
        if type(indicators) is list:
            for indicator in indicators[:MAX_REVIEW_LIST_ITEMS]:
                if type(indicator) is str and indicator in _SAFE_TOKEN_INDICATORS:
                    tokens[indicator] += 1

    source_digests: set[str] = set()
    for item in manifest[:MAX_REVIEW_LIST_ITEMS]:
        if type(item) is dict:
            digest = item.get("source_file_sha256")
            if _valid_sha256(digest):
                source_digests.add(digest.lower())
    warning_counts = counts.get("warning_counts")
    warning_count = 0
    if type(warning_counts) is dict:
        for value in warning_counts.values():
            if type(value) is int and value >= 0:
                warning_count += value
    return {
        "recognized_record_count": recognized,
        "skipped_record_count": skipped,
        "classification_counts": dict(sorted(classifications.items())),
        "language_indicator_counts": dict(sorted(languages.items())),
        "token_indicator_counts": dict(sorted(tokens.items())),
        "source_sha256": source_digests,
        "warning_count": warning_count,
    }


def _native_source_digests(result: dict[str, Any], command: str) -> set[str]:
    """Collect only safe digest strings from documented source-result fields."""
    locations: list[Any] = []
    if command == "cloud":
        locations.append(result.get("source_sha256"))
    elif command == "audit":
        imported = result.get("imported_logs")
        if type(imported) is dict:
            locations.append(imported.get("sha256"))
    elif command == "collect-cloud":
        # Collection output has no native source byte digest to claim.
        pass
    digests = {value.lower() for value in locations if _valid_sha256(value)}
    return set(sorted(digests)[:MAX_REVIEW_LIST_ITEMS])


def _valid_sha256(value: Any) -> bool:
    return type(value) is str and bool(_SHA256_RE.fullmatch(value))


def _supplied_utc_timestamps(result: dict[str, Any], command: str) -> list[dict[str, str]]:
    candidates: list[tuple[str, Any]] = []
    if command in {"listeners", "persistence"}:
        candidates.append(("observed_at_utc", result.get("observed_at_utc")))
    elif command == "audit":
        candidates.extend(
            [
                ("acquisition_started_at_utc", result.get("acquisition_started_at_utc")),
                ("acquisition_ended_at_utc", result.get("acquisition_ended_at_utc")),
            ]
        )
        host = result.get("host_observations")
        if type(host) is dict:
            for component in ("shell_connections", "listeners", "persistence_indicators"):
                value = host.get(component)
                if type(value) is dict:
                    candidates.append((component + ".observed_at_utc", value.get("observed_at_utc")))
    result_items = [
        {"field": field, "timestamp_utc": value}
        for field, value in candidates
        if _valid_utc_timestamp(value)
    ]
    return sorted(result_items, key=lambda item: (item["timestamp_utc"], item["field"]))[:MAX_REVIEW_LIST_ITEMS]


def _valid_utc_timestamp(value: Any) -> bool:
    if type(value) is not str or len(value) > 64:
        return False
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


__all__ = [
    "MAX_CONSENT_LINE_CHARS",
    "MAX_REVIEW_LIST_ITEMS",
    "REVIEW_SCHEMA_VERSION",
    "SUPPORTED_COMMANDS",
    "make_review",
    "offer_review",
]
