"""One selected audit snapshot -> policy feedback + customer explanation.

Evidence is data, never authority. This module cannot execute visitor commands,
control services, provision VMs, change policies or send reports to customers.

The in-process snapshot is deliberately not an authentication mechanism.  It does,
however, detect ordinary accidental or reflective mutation in the reviewed library
path before a snapshot can be rendered or exported.  Code running with arbitrary
Python execution can still monkey-patch this module and is outside that boundary.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
import re
import stat
import sys
from typing import Any
import weakref

from .input_files import read_regular
from .authorization import (
    AuthorizationError, AuthorizationGrant, AuthorizationScope,
    cancellation_guard, request_authorization,
)
from .operations import MAX_AUDIT_BYTES, MAX_PHYSICAL_RECORDS, MAX_SESSIONS, build_operations_summary_bytes
from .signals import TOKEN_INDICATORS
from .simulator import DecoySession


_RECORD_FORMAT = "security_incident_snapshot_v1"
_MANIFEST_FORMAT = "incident_evidence_manifest_v1"
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_FACTORY_TOKEN = object()
_MAX_NORMALIZED_RECORD_BYTES = 1024 * 1024
_MAX_PACKET_FILE_BYTES = 2 * 1024 * 1024
_MAX_PACKET_TOTAL_BYTES = 8 * 1024 * 1024
_PACKET_FILENAMES = (
    "incident-record.json",
    "behavior-feedback.json",
    "customer-explanation.json",
    "customer-explanation.md",
    "evidence-manifest.json",
)
_PACKET_ARTIFACTS = _PACKET_FILENAMES[:-1]
_CLASSIFICATIONS = (
    "connection_only",
    "probe_like",
    "burst_pattern",
    "multi_command_pattern",
    "execution_related_text",
)
_STOP_REASONS = frozenset({
    "not_stopped", "operator_shutdown", "service_runtime_limit", "audit_limit",
    "operator_audit_failure", "active_session_limit", "lifetime_connection_limit",
    "max_sessions_total", "max_commands", "max_runtime_seconds",
    "max_input_bytes_total", "max_output_bytes_total", "max_session_input_bytes",
    "commands_per_second", "global_input_byte_budget", "global_output_byte_budget",
    "session_input_byte_budget", "idle_timeout_seconds", "session_timeout_seconds",
    "input_budget", "output_budget", "session_input_budget", "command_limit",
    "input_limit", "output_limit", "completed", "unknown",
})
_LIMIT_FIELDS = (
    "max_sessions", "max_sessions_total", "max_commands", "max_runtime_seconds",
    "idle_timeout_seconds", "session_timeout_seconds", "max_input_bytes_total",
    "max_output_bytes_total", "max_session_input_bytes", "commands_per_second",
)
_USAGE_FIELDS = (
    "input_bytes_total", "output_bytes_total", "accepted_connections", "active_sessions",
    "peak_active_sessions", "elapsed_seconds",
)
_LIMIT_BOUNDS = {
    "max_sessions": (1, 64, True), "max_sessions_total": (1, 100, True),
    "max_commands": (1, 100, True), "max_runtime_seconds": (0, 3600, False),
    "idle_timeout_seconds": (1, 300, True), "session_timeout_seconds": (1, 3600, True),
    "max_input_bytes_total": (1, 8 * 1024 * 1024, True),
    "max_output_bytes_total": (1, 8 * 1024 * 1024, True),
    "max_session_input_bytes": (1, 256 * 1024, True), "commands_per_second": (1, 10, True),
}
_USAGE_BOUNDS = {
    "input_bytes_total": (0, 8 * 1024 * 1024, True),
    "output_bytes_total": (0, 8 * 1024 * 1024, True), "accepted_connections": (0, 100, True),
    "active_sessions": (0, 64, True), "peak_active_sessions": (0, 64, True),
    "elapsed_seconds": (0, 86400, False),
}
_DISCARDED_FIELDS = (
    "blank_or_empty", "overlong_line", "malformed_or_deep_json",
    "invalid_or_unsupported_record", "session_limit_omitted",
)
_UNCERTAINTY_FIELDS = (
    "discarded_records", "sessions_missing_connecting_event", "sessions_missing_close_event",
    "service_budget_started_records", "service_budget_stopped_records",
    "service_budget_started_record_missing", "service_budget_stopped_record_missing",
)
_ALLOWED_VERBS = frozenset(DecoySession.allowed_verbs)
_ALLOWED_TOKENS = frozenset(TOKEN_INDICATORS)


class EvidenceIntegrityError(ValueError):
    """A record, snapshot, or packet failed a bounded integrity check."""


def _integrity_error() -> None:
    # Keep this text fixed: untrusted bytes must never appear in an error or report.
    raise EvidenceIntegrityError("evidence integrity validation failed")


def canonical(value: Any) -> bytes:
    """Return the stable JSON representation used for local content hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _valid_hash(value: object) -> bool:
    return type(value) is str and bool(_HASH_RE.fullmatch(value))


def _valid_int(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _valid_number_or_unknown(value: object) -> bool:
    if value == "unknown":
        return True
    return type(value) in {int, float} and not isinstance(value, bool) and math.isfinite(float(value))


def _valid_bounded_number(value: object, bounds: tuple[int | float, int | float, bool]) -> bool:
    if not _valid_number_or_unknown(value):
        return False
    if value == "unknown":
        return True
    minimum, maximum, integer_required = bounds
    return minimum <= value <= maximum and (not integer_required or type(value) is int)


def _exact_keys(value: object, keys: tuple[str, ...]) -> bool:
    return type(value) is dict and set(value) == set(keys)


def _utc_or_unknown(value: object, *, allow_seconds: bool = False) -> bool:
    """Accept an explicit unknown/null value or a canonical UTC timestamp only."""
    if value is None or value == "unknown":
        return True
    if type(value) is not str or len(value) > 64 or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return False
    normalized_microseconds = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value == normalized_microseconds:
        return True
    if allow_seconds:
        return value == parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return False


def _validate_time_range(value: object) -> None:
    if not _exact_keys(value, ("first_utc", "last_utc")):
        _integrity_error()
    first, last = value["first_utc"], value["last_utc"]
    if not _utc_or_unknown(first) or not _utc_or_unknown(last):
        _integrity_error()
    if type(first) is str and type(last) is str and first != "unknown" and last != "unknown" and first > last:
        _integrity_error()


def _limited_int(text: str) -> int:
    if len(text) > 24:
        raise ValueError
    return int(text)


def _limited_float(text: str) -> float:
    """Permit only short, finite JSON floats; schema checks impose field bounds."""
    if len(text) > 64:
        raise ValueError
    value = float(text)
    if not math.isfinite(value):
        raise ValueError
    return value


def _reject_constant(_: str) -> object:
    raise ValueError


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _bounded_json_shape(value: object, *, max_nodes: int = 65536, max_depth: int = 32) -> bool:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            return False
        if type(current) is dict:
            if len(current) > max_nodes:
                return False
            for key, item in current.items():
                if type(key) is not str or len(key) > 256:
                    return False
                pending.append((item, depth + 1))
        elif type(current) is list:
            if len(current) > max_nodes:
                return False
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is str:
            if len(current) > 16 * 1024:
                return False
        elif type(current) in {int, bool} or current is None:
            pass
        elif type(current) is float and math.isfinite(current):
            pass
        else:
            return False
    return True


def _strict_json_object(raw: bytes, maximum: int) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > maximum:
        _integrity_error()
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_int=_limited_int,
            parse_float=_limited_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError):
        _integrity_error()
    if type(parsed) is not dict or not _bounded_json_shape(parsed):
        _integrity_error()
    return parsed


def _session_mappings(operations: dict[str, object]) -> list[dict[str, object]]:
    sessions = operations.get("sessions")
    if type(sessions) is not list:
        _integrity_error()
    mappings: list[dict[str, object]] = []
    for session in sessions:
        if type(session) is not dict:
            _integrity_error()
        mappings.append({
            "session_id_sha256": session.get("session_ref_sha256"),
            "first_seen_utc": session.get("first_seen_utc"),
            "last_seen_utc": session.get("last_seen_utc"),
        })
    return mappings


def _binding_material(source_input_sha256: str, time_range: dict[str, object], session_mappings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "source_input_sha256": source_input_sha256,
        "time_range": time_range,
        "session_mappings": session_mappings,
    }


def _metadata_digest(source_input_sha256: str, time_range: dict[str, object], session_mappings: list[dict[str, object]]) -> str:
    return sha256(canonical(_binding_material(source_input_sha256, time_range, session_mappings))).hexdigest()


def _evidence_metadata(record: dict[str, object]) -> dict[str, object]:
    source = record["source_manifest"]
    if type(source) is not dict:
        _integrity_error()
    return {
        "source_input_sha256": source["input_sha256"],
        "time_range": source["time_range"],
        "session_mappings": source["session_mappings"],
        "metadata_sha256": source["metadata_sha256"],
    }


def _validate_record_references(references: object, physical_records: int) -> None:
    if type(references) is not list or len(references) > MAX_PHYSICAL_RECORDS:
        _integrity_error()
    previous = 0
    for reference in references:
        if not _exact_keys(reference, ("physical_line", "line_sha256")):
            _integrity_error()
        line = reference["physical_line"]
        if not _valid_int(line, 1, physical_records) or line <= previous or not _valid_hash(reference["line_sha256"]):
            _integrity_error()
        previous = line


def _validate_classifications(value: object) -> None:
    if type(value) is not list or len(value) > len(_CLASSIFICATIONS):
        _integrity_error()
    seen: set[str] = set()
    allowed_reasons = {
        "connection_only": {"connecting_without_command_or_chunk"},
        "probe_like": {"one_or_two_command_or_chunk_events"},
        "burst_pattern": {"command_rate_limit", "chunk_rate_limit"},
        "multi_command_pattern": {"three_or_more_distinct_known_verbs"},
        "execution_related_text": _ALLOWED_TOKENS,
    }
    for item in value:
        if not _exact_keys(item, ("name", "confidence", "reasons")):
            _integrity_error()
        name, confidence, reasons = item["name"], item["confidence"], item["reasons"]
        if type(name) is not str or name not in _CLASSIFICATIONS or name in seen or confidence != "low":
            _integrity_error()
        if type(reasons) is not list or not reasons or len(reasons) > 32 or any(type(reason) is not str or reason not in allowed_reasons[name] for reason in reasons):
            _integrity_error()
        if reasons != sorted(set(reasons)):
            _integrity_error()
        seen.add(name)


def _validate_session(session: object) -> None:
    expected = (
        "session_ref_sha256", "event_counts", "known_verbs", "token_indicators",
        "first_seen_utc", "last_seen_utc", "missing_coverage", "classifications",
    )
    if not _exact_keys(session, expected):
        _integrity_error()
    if not _valid_hash(session["session_ref_sha256"]):
        _integrity_error()
    counts = session["event_counts"]
    if not _exact_keys(counts, ("close", "command", "connecting", "mirror_chunk")):
        _integrity_error()
    if any(not _valid_int(count, 0, MAX_PHYSICAL_RECORDS) for count in counts.values()):
        _integrity_error()
    verbs = session["known_verbs"]
    tokens = session["token_indicators"]
    missing = session["missing_coverage"]
    if type(verbs) is not list or verbs != sorted(set(verbs)) or any(type(item) is not str or item not in _ALLOWED_VERBS for item in verbs):
        _integrity_error()
    if type(tokens) is not list or tokens != sorted(set(tokens)) or any(type(item) is not str or item not in _ALLOWED_TOKENS for item in tokens):
        _integrity_error()
    if type(missing) is not list or any(type(item) is not str or item not in {"connecting_event_missing", "close_event_missing"} for item in missing):
        _integrity_error()
    if len(missing) != len(set(missing)):
        _integrity_error()
    if not _utc_or_unknown(session["first_seen_utc"]) or not _utc_or_unknown(session["last_seen_utc"]):
        _integrity_error()
    first, last = session["first_seen_utc"], session["last_seen_utc"]
    if type(first) is str and type(last) is str and first != "unknown" and last != "unknown" and first > last:
        _integrity_error()
    _validate_classifications(session["classifications"])


def _validate_budget_event(value: object) -> None:
    if not _exact_keys(value, ("timestamp_utc", "phase", "stop_reason", "limits", "usage")):
        _integrity_error()
    if not _utc_or_unknown(value["timestamp_utc"]) or value["phase"] not in {"started", "stopped"} or value["stop_reason"] not in _STOP_REASONS:
        _integrity_error()
    for section, fields, bounds in ((value["limits"], _LIMIT_FIELDS, _LIMIT_BOUNDS), (value["usage"], _USAGE_FIELDS, _USAGE_BOUNDS)):
        if not _exact_keys(section, fields):
            _integrity_error()
        if any(not _valid_bounded_number(section[field], bounds[field]) for field in fields):
            _integrity_error()


def _validate_operations(operations: object, source: dict[str, object]) -> None:
    expected = (
        "title", "provider", "source_kind", "audit", "sessions", "session_count",
        "classification_counts", "budget_stats", "uncertainty_counts",
        "budget_counter_semantics", "classification_notice", "limitations", "automatic_actions",
    )
    if not _exact_keys(operations, expected):
        _integrity_error()
    if operations["title"] != "Decoy operations summary" or operations["provider"] != "local" or operations["source_kind"] != "decoy_operations_summary" or operations["automatic_actions"] is not False:
        _integrity_error()
    audit = operations["audit"]
    audit_keys = (
        "status", "input_sha256", "input_bytes", "physical_records", "accepted_records",
        "discarded_records", "coverage", "first_valid_timestamp_utc", "last_valid_timestamp_utc",
    )
    if not _exact_keys(audit, audit_keys):
        _integrity_error()
    if audit["status"] != "explicitly_selected_local_jsonl_unverified" or audit["coverage"] != "provided_records_only; completeness_unknown":
        _integrity_error()
    if not _valid_hash(audit["input_sha256"]) or audit["input_sha256"] != source["input_sha256"]:
        _integrity_error()
    if not _valid_int(audit["input_bytes"], 0, MAX_AUDIT_BYTES) or audit["input_bytes"] != source["input_bytes"]:
        _integrity_error()
    if not _valid_int(audit["physical_records"], 0, MAX_PHYSICAL_RECORDS) or not _valid_int(audit["accepted_records"], 0, MAX_PHYSICAL_RECORDS):
        _integrity_error()
    if not _utc_or_unknown(audit["first_valid_timestamp_utc"]) or not _utc_or_unknown(audit["last_valid_timestamp_utc"]):
        _integrity_error()
    if audit["first_valid_timestamp_utc"] != source["time_range"]["first_utc"] or audit["last_valid_timestamp_utc"] != source["time_range"]["last_utc"]:
        _integrity_error()
    discarded = audit["discarded_records"]
    if not _exact_keys(discarded, _DISCARDED_FIELDS) or any(not _valid_int(item, 0, MAX_PHYSICAL_RECORDS) for item in discarded.values()):
        _integrity_error()
    _validate_record_references(source["record_references"], audit["physical_records"])

    sessions = operations["sessions"]
    if type(sessions) is not list or len(sessions) > MAX_SESSIONS or operations["session_count"] != len(sessions):
        _integrity_error()
    session_ids: set[str] = set()
    for session in sessions:
        _validate_session(session)
        identifier = session["session_ref_sha256"]
        if identifier in session_ids:
            _integrity_error()
        session_ids.add(identifier)
    if [session["session_ref_sha256"] for session in sessions] != sorted(session_ids):
        _integrity_error()

    classifications = operations["classification_counts"]
    if not _exact_keys(classifications, _CLASSIFICATIONS) or any(not _valid_int(item, 0, MAX_SESSIONS) for item in classifications.values()):
        _integrity_error()
    computed_classifications = {name: 0 for name in _CLASSIFICATIONS}
    for session in sessions:
        for classification in session["classifications"]:
            computed_classifications[classification["name"]] += 1
    if classifications != computed_classifications:
        _integrity_error()

    budget = operations["budget_stats"]
    if not _exact_keys(budget, ("status", "coverage", "events")) or budget["status"] not in {"supplied_unverified", "unknown"} or budget["coverage"] != "provided_records_only; completeness_unknown":
        _integrity_error()
    events = budget["events"]
    if type(events) is not list or len(events) > MAX_PHYSICAL_RECORDS:
        _integrity_error()
    for event in events:
        _validate_budget_event(event)
    if (budget["status"] == "supplied_unverified") != bool(events):
        _integrity_error()
    accepted_from_sessions = sum(sum(session["event_counts"].values()) for session in sessions) + len(events)
    if accepted_from_sessions != audit["accepted_records"]:
        _integrity_error()

    uncertainty = operations["uncertainty_counts"]
    if not _exact_keys(uncertainty, _UNCERTAINTY_FIELDS) or any(not _valid_int(item, 0, MAX_PHYSICAL_RECORDS) for item in uncertainty.values()):
        _integrity_error()
    if uncertainty["discarded_records"] != sum(discarded.values()):
        _integrity_error()
    if uncertainty["sessions_missing_connecting_event"] != sum("connecting_event_missing" in session["missing_coverage"] for session in sessions):
        _integrity_error()
    if uncertainty["sessions_missing_close_event"] != sum("close_event_missing" in session["missing_coverage"] for session in sessions):
        _integrity_error()
    started = sum(event["phase"] == "started" for event in events)
    stopped = sum(event["phase"] == "stopped" for event in events)
    if uncertainty["service_budget_started_records"] != started or uncertainty["service_budget_stopped_records"] != stopped or uncertainty["service_budget_started_record_missing"] != int(not started) or uncertainty["service_budget_stopped_record_missing"] != int(not stopped):
        _integrity_error()

    semantics = operations["budget_counter_semantics"]
    if not _exact_keys(semantics, ("input_bytes_total", "output_bytes_total", "remote_resource_cost")) or semantics != {
        "input_bytes_total": "admitted_application_bytes_not_physical_traffic",
        "output_bytes_total": "reserved_application_output_not_confirmed_delivery",
        "remote_resource_cost": "unknown",
    }:
        _integrity_error()
    if operations["classification_notice"] != (
        "Flags describe limited supplied-record patterns only; they do not prove a human, scanner, "
        "exploitation, host access, execution, identity, remote operating system, or remote resource use."
    ):
        _integrity_error()
    limitations = operations["limitations"]
    expected_limitations = [
        "All imported records, including claimed interaction observations, are unverified.",
        "Synthetic decoy responses do not prove host access or identity.",
        "Missing, malformed, omitted, or unavailable events leave coverage unknown rather than clean.",
        "Missing service-budget start or stop records are unknown coverage, not proof of service failure.",
        "input_bytes_total counts admitted application bytes, not physical traffic or bandwidth.",
        "output_bytes_total counts reserved application output even when delivery is not confirmed.",
        "Supplied service budgets are not a measurement of remote CPU, memory, operating system, money, or cost.",
    ]
    if limitations != expected_limitations:
        _integrity_error()


def _validate_normalized_record(record: object) -> tuple[str, str]:
    """Validate the factory's privacy-preserving normalized-record grammar."""
    root_keys = (
        "record_format", "provider", "synthetic_fixture", "environment_kind",
        "source_authenticity", "source_manifest", "operations",
    )
    if not _exact_keys(record, root_keys):
        _integrity_error()
    if record["record_format"] != _RECORD_FORMAT or record["provider"] != "local" or type(record["synthetic_fixture"]) is not bool:
        _integrity_error()
    if record["environment_kind"] != "synthetic_decoy_environment_not_real_host_access" or record["source_authenticity"] != "unverified_selected_audit":
        _integrity_error()
    source = record["source_manifest"]
    source_keys = (
        "input_sha256", "input_bytes", "record_references", "coverage", "original_payload_retained",
        "time_range", "session_mappings", "metadata_sha256",
    )
    if not _exact_keys(source, source_keys):
        _integrity_error()
    if not _valid_hash(source["input_sha256"]) or not _valid_int(source["input_bytes"], 0, MAX_AUDIT_BYTES):
        _integrity_error()
    if source["coverage"] != "provided_records_only; completeness_unknown" or source["original_payload_retained"] is not False:
        _integrity_error()
    _validate_time_range(source["time_range"])
    mappings = source["session_mappings"]
    if type(mappings) is not list or len(mappings) > MAX_SESSIONS:
        _integrity_error()
    mapping_ids: set[str] = set()
    for mapping in mappings:
        if not _exact_keys(mapping, ("session_id_sha256", "first_seen_utc", "last_seen_utc")):
            _integrity_error()
        identifier = mapping["session_id_sha256"]
        if not _valid_hash(identifier) or identifier in mapping_ids or not _utc_or_unknown(mapping["first_seen_utc"]) or not _utc_or_unknown(mapping["last_seen_utc"]):
            _integrity_error()
        if type(mapping["first_seen_utc"]) is str and type(mapping["last_seen_utc"]) is str and mapping["first_seen_utc"] != "unknown" and mapping["last_seen_utc"] != "unknown" and mapping["first_seen_utc"] > mapping["last_seen_utc"]:
            _integrity_error()
        mapping_ids.add(identifier)
    if [mapping["session_id_sha256"] for mapping in mappings] != sorted(mapping_ids):
        _integrity_error()
    expected_metadata = _metadata_digest(source["input_sha256"], source["time_range"], mappings)
    if source["metadata_sha256"] != expected_metadata:
        _integrity_error()
    _validate_operations(record["operations"], source)
    if mappings != _session_mappings(record["operations"]):
        _integrity_error()
    return source["input_sha256"], expected_metadata


# The registry is deliberately separate from the frozen object.  A caller that uses
# object.__setattr__ can change an instance field, but cannot make that field agree
# with this construction-time binding without arbitrary-code access to this module.
_SNAPSHOT_REGISTRY: dict[int, tuple[weakref.ReferenceType["_IncidentSnapshot"], str, str, str]] = {}


def _register_snapshot(snapshot: "_IncidentSnapshot", digest: str, source_hash: str, metadata_hash: str) -> None:
    identity = id(snapshot)

    def cleanup(reference: weakref.ReferenceType[_IncidentSnapshot]) -> None:
        registered = _SNAPSHOT_REGISTRY.get(identity)
        if registered is not None and registered[0] is reference:
            _SNAPSHOT_REGISTRY.pop(identity, None)

    _SNAPSHOT_REGISTRY[identity] = (weakref.ref(snapshot, cleanup), digest, source_hash, metadata_hash)


@dataclass(frozen=True, init=False, eq=False)
class _IncidentSnapshot:
    """Factory-only, registry-bound in-process normalized record."""
    _canonical_record: bytes
    _origin: object
    _expected_digest: str
    _source_input_sha256: str
    _metadata_digest: str

    def __init__(
        self,
        canonical_record: bytes,
        *,
        source_input_sha256: str = "",
        metadata_digest: str = "",
        _factory_token: object,
    ) -> None:
        if _factory_token is not _FACTORY_TOKEN:
            _integrity_error()
        if type(canonical_record) is not bytes or len(canonical_record) > _MAX_NORMALIZED_RECORD_BYTES:
            _integrity_error()
        if not _valid_hash(source_input_sha256) or not _valid_hash(metadata_digest):
            _integrity_error()
        digest = sha256(canonical_record).hexdigest()
        object.__setattr__(self, "_canonical_record", canonical_record)
        object.__setattr__(self, "_origin", _factory_token)
        object.__setattr__(self, "_expected_digest", digest)
        object.__setattr__(self, "_source_input_sha256", source_input_sha256)
        object.__setattr__(self, "_metadata_digest", metadata_digest)
        _register_snapshot(self, digest, source_input_sha256, metadata_digest)

    @property
    def digest(self) -> str:
        _validated_snapshot_record(self)
        return _snapshot_bindings(self)[0]

    def copy(self) -> dict:
        return _validated_snapshot_record(self)


def _snapshot_bindings(snapshot: object) -> tuple[str, str, str]:
    if type(snapshot) is not _IncidentSnapshot:
        _integrity_error()
    registered = _SNAPSHOT_REGISTRY.get(id(snapshot))
    if registered is None or registered[0]() is not snapshot:
        _integrity_error()
    expected_digest, source_hash, metadata_hash = registered[1:]
    if snapshot._origin is not _FACTORY_TOKEN or snapshot._expected_digest != expected_digest or snapshot._source_input_sha256 != source_hash or snapshot._metadata_digest != metadata_hash:
        _integrity_error()
    if type(snapshot._canonical_record) is not bytes or len(snapshot._canonical_record) > _MAX_NORMALIZED_RECORD_BYTES:
        _integrity_error()
    # This precedes decoding so a changed field is never interpreted as JSON.
    if sha256(snapshot._canonical_record).hexdigest() != expected_digest:
        _integrity_error()
    return expected_digest, source_hash, metadata_hash


def _validated_snapshot_record(snapshot: object) -> dict:
    _, source_hash, metadata_hash = _snapshot_bindings(snapshot)
    record = _strict_json_object(snapshot._canonical_record, _MAX_NORMALIZED_RECORD_BYTES)
    actual_source, actual_metadata = _validate_normalized_record(record)
    if actual_source != source_hash or actual_metadata != metadata_hash:
        _integrity_error()
    return record


def snapshot_from_bytes(raw: bytes, *, synthetic_fixture: bool = False) -> _IncidentSnapshot:
    """Normalize one already-selected bounded audit exactly once."""
    if type(raw) is not bytes or type(synthetic_fixture) is not bool:
        raise ValueError("audit bytes and synthetic fixture flag are invalid")
    # build_operations_summary_bytes owns the input size/line bounds and consumes only
    # the caller's one immutable bytes object.  Do not reread a path here.
    operations = build_operations_summary_bytes(raw)
    line_refs = [
        {"physical_line": number, "line_sha256": sha256(line).hexdigest()}
        for number, line in enumerate(raw.splitlines(), 1) if line.strip()
    ]
    audit = operations["audit"]
    time_range = {
        "first_utc": audit["first_valid_timestamp_utc"],
        "last_utc": audit["last_valid_timestamp_utc"],
    }
    mappings = _session_mappings(operations)
    source_hash = audit["input_sha256"]
    metadata_hash = _metadata_digest(source_hash, time_range, mappings)
    record: dict[str, object] = {
        "record_format": _RECORD_FORMAT,
        "provider": "local",
        "synthetic_fixture": synthetic_fixture,
        "environment_kind": "synthetic_decoy_environment_not_real_host_access",
        "source_authenticity": "unverified_selected_audit",
        "source_manifest": {
            "input_sha256": source_hash,
            "input_bytes": len(raw),
            "record_references": line_refs,
            "coverage": "provided_records_only; completeness_unknown",
            "original_payload_retained": False,
            "time_range": time_range,
            "session_mappings": mappings,
            "metadata_sha256": metadata_hash,
        },
        "operations": operations,
    }
    actual_source, actual_metadata = _validate_normalized_record(record)
    if actual_source != source_hash or actual_metadata != metadata_hash:
        _integrity_error()
    encoded = canonical(record)
    if len(encoded) > _MAX_NORMALIZED_RECORD_BYTES:
        _integrity_error()
    return _IncidentSnapshot(
        encoded,
        source_input_sha256=source_hash,
        metadata_digest=metadata_hash,
        _factory_token=_FACTORY_TOKEN,
    )


def _require_authorization(authorization: AuthorizationGrant | None,
                           scope: AuthorizationScope | None) -> None:
    if type(authorization) is not AuthorizationGrant or type(scope) is not AuthorizationScope:
        raise AuthorizationError("fresh authorization required")
    authorization.check(scope)


def snapshot_from_audit(path: str, *, authorization: AuthorizationGrant | None = None,
                        scope: AuthorizationScope | None = None) -> _IncidentSnapshot:
    _require_authorization(authorization, scope)
    if scope.operation != "explain" or scope.input_ref != path:
        raise AuthorizationError("authorization scope does not match selected input")
    authorization.begin(scope)
    try:
        raw = read_regular(path, MAX_AUDIT_BYTES)
        authorization.check(scope)
        snapshot = snapshot_from_bytes(raw)
        authorization.check(scope)
        return snapshot
    except BaseException:
        authorization.revoke()
        raise


def _events(snapshot: _IncidentSnapshot) -> tuple[dict, dict, list, list]:
    record = _validated_snapshot_record(snapshot)
    operations = record["operations"]
    return record, operations, operations["sessions"], operations["budget_stats"]["events"]


def _budget_stops(events: list) -> list:
    protective_reasons = {
        "global_input_byte_budget", "global_output_byte_budget", "service_runtime_limit",
        "audit_limit", "operator_audit_failure", "max_sessions_total", "lifetime_connection_limit",
        "input_budget", "output_budget", "max_runtime_seconds",
    }
    return [event for event in events if event["phase"] == "stopped" and event["stop_reason"] in protective_reasons]


def _behavior_feedback_from_record(record: dict, creation_digest: str) -> dict:
    from .behavior import BehaviorInput, evaluate, policy_contract

    operations = record["operations"]
    sessions = operations["sessions"]
    budgets = operations["budget_stats"]["events"]
    suspicious = any(session["token_indicators"] for session in sessions)
    inputs = BehaviorInput(
        suspicious_text=suspicious,
        local_budget_stop_reported=bool(_budget_stops(budgets)),
        evidence_count=operations["audit"]["accepted_records"],
    )
    decision = evaluate(inputs)
    metadata = _evidence_metadata(record)
    return {
        "format": "incident_behavior_feedback_v1",
        "provider": "local",
        "incident_record_sha256": creation_digest,
        "source_input_sha256": metadata["source_input_sha256"],
        "evidence_metadata": metadata,
        "policy_contract_sha256": sha256(canonical(policy_contract())).hexdigest(),
        "decision": decision,
        "evidence_references": [
            {"incident_record_sha256": creation_digest, "json_pointer": "/operations/sessions"},
            {"incident_record_sha256": creation_digest, "json_pointer": "/operations/budget_stats/events"},
        ],
        "source_claims_verified": False,
        "independent_corroboration": "not_supplied",
        "baseline_comparison": "not_supplied",
        "approval_derived_from_evidence": False,
        "runtime_modified": False,
        "notice": "Fixed policy guidance from unverified supplied records, not learned weights, live authority, automatic containment or proof of a threat. Review before adapting another script.",
    }


def behavior_feedback(snapshot: _IncidentSnapshot) -> dict:
    record, _, _, _ = _events(snapshot)
    return _behavior_feedback_from_record(record, snapshot.digest)


def _customer_explanation_from_record(record: dict, creation_digest: str, generated_utc: str) -> dict:
    operations = record["operations"]
    sessions = operations["sessions"]
    budgets = operations["budget_stats"]["events"]
    counts = {key: sum(session["event_counts"][key] for session in sessions) for key in ("connecting", "command", "mirror_chunk", "close")}
    audit = operations["audit"]
    patterns = operations["classification_counts"]
    stops = _budget_stops(budgets)
    observations = []
    if counts["connecting"]:
        observations.append({
            "code": "recorded_connection_events",
            "description": f"The selected audit contains {counts['connecting']} connection record(s). Their authenticity, authorization and origin were not verified by this script.",
            "evidence_pointer": "/operations/sessions", "classification": "supplied_unverified_record",
        })
    if counts["command"] or counts["mirror_chunk"]:
        observations.append({
            "code": "recorded_decoy_inputs",
            "description": f"The audit contains {counts['command']} command-shaped event(s) and {counts['mirror_chunk']} mirror-chunk event(s). These records do not establish real command execution or host access.",
            "evidence_pointer": "/operations/sessions", "classification": "supplied_unverified_record",
        })
    for name, count in patterns.items():
        if count:
            observations.append({
                "code": name, "session_count": count,
                "description": "A deterministic, low-confidence pattern was present in the selected records; a benign script, administrator, template, incomplete trace or synthetic test may explain it.",
                "evidence_pointer": "/operations/classification_counts/" + name,
                "classification": "inferred_pattern_not_execution_or_attribution",
            })
    status = "insufficient_evidence" if not audit["accepted_records"] else "selected_records_require_contextual_review"
    metadata = _evidence_metadata(record)
    return {
        "format": "customer_incident_explanation_v1", "provider": "local",
        "title": "What the selected CloudSentry audit shows",
        "generated_utc": generated_utc,
        "status": status,
        "synthetic_fixture": record["synthetic_fixture"],
        "incident_record_sha256": creation_digest,
        "source_input_sha256": metadata["source_input_sha256"],
        "evidence_metadata": metadata,
        "what_happened": (
            f"The selected audit describes {len(sessions)} hash-referenced session(s). "
            "It is a supplied, unverified record of a synthetic decoy environment, not proof that your actual device was accessed or compromised."
        ),
        "what_the_script_observed": observations,
        "what_cloudsentry_did": {
            "this_invocation": "Read one selected audit, normalized it once, evaluated fixed review guidance and generated local reports. It did not scan, block, redirect, execute input, change production rules or send a report.",
            "reported_close_records": counts["close"],
            "reported_budget_stops": [{"reason": event["stop_reason"], "timestamp_utc": event["timestamp_utc"], "evidence_pointer": "/operations/budget_stats/events"} for event in stops],
            "reported_actions_verified": False,
            "containment_activated_by_this_script": False,
            "why_no_automatic_containment": "Detection and imported assertions do not grant enforcement authority. False positives, source authenticity, ownership, isolation and rollback need independent operator review.",
        },
        "what_this_means": "Connection or text patterns can justify review. Attempted activity, simulated privileges, actual execution and successful unauthorized host access are different facts; successful unauthorized host access has not been established here.",
        "uncertainty": {
            "discarded_records": sum(audit["discarded_records"].values()),
            "coverage_gaps": operations["uncertainty_counts"],
            "comparison_baseline": "not_supplied",
            "independent_corroboration": "not_supplied",
            "contradictory_independent_evidence": "not_assessed; only one selected audit supplied",
            "identity_intent_authorization_host_os": "unknown",
        },
        "time_range": metadata["time_range"],
        "recommended_next_steps": [
            "Review the original audit alongside independently preserved authentication, process, network and provider records, keeping clock and coverage gaps explicit.",
            "Confirm whether a benign administrator, authorized scanner or synthetic test explains the pattern before proposing a response.",
            "If an actual resource may be compromised, isolate it through a trusted provider/network control plane, preserve independent evidence and revoke exposed credentials using your incident-response process.",
            "Use only independently approved scopes and actions. Do not treat this summary as legal proof, a psychological dossier or an instruction to deploy a decoy.",
        ],
        "evidence_classification": "selected_record_observations_and_limited_inferences; authenticity_unverified",
        "limitations": "No original payloads, peer addresses or credential values are included. Hashes identify selected representations, not authorship, legal custody or authenticity. This is not model training, a forensic verdict or a guarantee of customer-device safety.",
    }


def customer_explanation(snapshot: _IncidentSnapshot) -> dict:
    record, _, _, _ = _events(snapshot)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return _customer_explanation_from_record(record, snapshot.digest, generated)


def customer_markdown(snapshot: _IncidentSnapshot) -> str:
    """Render only a factory-normalized, registry-bound snapshot."""
    return _render_customer_markdown(customer_explanation(snapshot))


def _render_customer_markdown(report: dict) -> str:
    """Private rendering helper for an internally constructed or verifier-validated report."""
    lines = ["# " + report["title"], "", "**Status:** " + report["status"], ""]
    if report["synthetic_fixture"]:
        lines += ["**Illustrative synthetic fixture—not a customer incident.**", ""]
    lines += ["## What happened", "", report["what_happened"], "", "## What the script observed", ""]
    for observation in report["what_the_script_observed"]:
        lines += ["- " + observation["description"], "  Evidence: `" + observation["evidence_pointer"] + "` in the incident snapshot."]
    if not report["what_the_script_observed"]:
        lines.append("No usable observation was available; this is unknown coverage, not an all-clear.")
    actions = report["what_cloudsentry_did"]
    lines += ["", "## What CloudSentry did—and did not do", "", actions["this_invocation"], "", actions["why_no_automatic_containment"]]
    for stop in actions["reported_budget_stops"]:
        lines.append(f"- The supplied audit reports a local stop: `{stop['reason']}` at `{stop['timestamp_utc']}`. This was not independently verified.")
    lines += ["", "## What this means", "", report["what_this_means"], "", "## Unknowns and limitations", "",
              "The baseline, independent corroboration, identity, intent and authorization are unknown. Missing or discarded records do not prove a clean system.",
              report["limitations"], "", "## Recommended next steps", ""]
    lines += ["- " + step for step in report["recommended_next_steps"]]
    metadata = report["evidence_metadata"]
    lines += ["", "## Evidence trail", "", f"- Selected input SHA-256: `{report['source_input_sha256']}`",
              f"- Shared incident snapshot SHA-256: `{report['incident_record_sha256']}`",
              f"- Supplied time range: `{report['time_range']['first_utc']}` to `{report['time_range']['last_utc']}`",
              f"- Session/time metadata SHA-256: `{metadata['metadata_sha256']}`",
              "- The technical feedback and this explanation use the same immutable in-process snapshot.", ""]
    return "\n".join(lines)


def write_private_packet(directory: str, files: dict[str, bytes], *,
                         authorization: AuthorizationGrant | None = None,
                         scope: AuthorizationScope | None = None) -> None:
    """One consented export; revoke and remove partial artifacts on catchable failure."""
    _require_authorization(authorization, scope)
    if scope.operation not in {"train", "explain"} or scope.output_ref != directory:
        raise AuthorizationError("authorization scope does not match selected output")
    if type(files) is not dict or not files or len(files) > 8:
        raise ValueError("invalid artifact set")
    total = 0
    for name, content in files.items():
        if type(name) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name):
            raise ValueError("artifact name must be fixed and local")
        if type(content) is not bytes or len(content) > _MAX_PACKET_FILE_BYTES:
            raise ValueError("invalid artifact content")
        total += len(content)
    if total > _MAX_PACKET_TOTAL_BYTES:
        raise ValueError("artifact budget exceeded")
    fd = -1
    created = []
    try:
        authorization.check(scope)
        os.mkdir(directory, 0o700)
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        for name, content in files.items():
            authorization.check(scope)
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
            created.append(name)
            with os.fdopen(out, "wb") as stream:
                for offset in range(0, len(content), 65536):
                    authorization.check(scope)
                    stream.write(content[offset:offset + 65536])
                    authorization.check(scope)
            authorization.check(scope)
        authorization.check(scope)
    except BaseException:
        if fd >= 0:
            for name in created:
                os.unlink(name, dir_fd=fd)
            os.close(fd)
            fd = -1
            os.rmdir(directory)
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        authorization.revoke()


def explanation_packet(snapshot: _IncidentSnapshot) -> dict[str, bytes]:
    """Build matching artifacts only after all snapshot bindings validate."""
    record = snapshot.copy()
    creation_digest = snapshot.digest
    report = _customer_explanation_from_record(
        record,
        creation_digest,
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    feedback = _behavior_feedback_from_record(record, creation_digest)
    metadata = _evidence_metadata(record)
    files = {
        "incident-record.json": canonical({"incident_record_sha256": creation_digest, "record": record}) + b"\n",
        "behavior-feedback.json": canonical(feedback) + b"\n",
        "customer-explanation.json": canonical(report) + b"\n",
        "customer-explanation.md": _render_customer_markdown(report).encode("utf-8"),
    }
    files["evidence-manifest.json"] = canonical({
        "format": _MANIFEST_FORMAT,
        "incident_record_sha256": creation_digest,
        "source_input_sha256": metadata["source_input_sha256"],
        "evidence_metadata": metadata,
        "artifact_sha256": {name: sha256(content).hexdigest() for name, content in files.items()},
        "authenticity": "unverified; hashes_do_not_authenticate_source",
        "raw_audit_included": False,
    }) + b"\n"
    return files


def _read_packet_files(directory: str, authorization: AuthorizationGrant,
                       scope: AuthorizationScope) -> dict[str, bytes]:
    if type(directory) is not str:
        _integrity_error()
    try:
        authorization.check(scope)
        before = os.lstat(directory)
        if not stat.S_ISDIR(before.st_mode):
            _integrity_error()
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            after = os.fstat(fd)
            if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                _integrity_error()
            # /proc/self/fd keeps the selected directory inode anchored while
            # read_regular performs its own regular-file/no-symlink checks.
            base = f"/proc/self/fd/{fd}"
            files: dict[str, bytes] = {}
            total = 0
            for name in _PACKET_FILENAMES:
                authorization.check(scope)
                content = read_regular(os.path.join(base, name), _MAX_PACKET_FILE_BYTES)
                authorization.check(scope)
                total += len(content)
                if total > _MAX_PACKET_TOTAL_BYTES:
                    _integrity_error()
                files[name] = content
            return files
        finally:
            os.close(fd)
    except EvidenceIntegrityError:
        raise
    except (OSError, ValueError, UnicodeError):
        _integrity_error()


def _validate_packet_manifest(manifest: dict[str, object], files: dict[str, bytes]) -> tuple[str, str, dict[str, object]]:
    keys = (
        "format", "incident_record_sha256", "source_input_sha256", "evidence_metadata",
        "artifact_sha256", "authenticity", "raw_audit_included",
    )
    if not _exact_keys(manifest, keys) or manifest["format"] != _MANIFEST_FORMAT:
        _integrity_error()
    creation, source, metadata = manifest["incident_record_sha256"], manifest["source_input_sha256"], manifest["evidence_metadata"]
    if not _valid_hash(creation) or not _valid_hash(source) or manifest["authenticity"] != "unverified; hashes_do_not_authenticate_source" or manifest["raw_audit_included"] is not False:
        _integrity_error()
    hashes = manifest["artifact_sha256"]
    if type(hashes) is not dict or set(hashes) != set(_PACKET_ARTIFACTS):
        _integrity_error()
    for name in _PACKET_ARTIFACTS:
        if not _valid_hash(hashes.get(name)) or sha256(files[name]).hexdigest() != hashes[name]:
            _integrity_error()
    return creation, source, metadata


def _validate_incident_envelope(value: dict[str, object]) -> tuple[dict[str, object], str, str, dict[str, object]]:
    if not _exact_keys(value, ("incident_record_sha256", "record")) or not _valid_hash(value["incident_record_sha256"]):
        _integrity_error()
    record = value["record"]
    source_hash, metadata_hash = _validate_normalized_record(record)
    creation = sha256(canonical(record)).hexdigest()
    if creation != value["incident_record_sha256"]:
        _integrity_error()
    return record, creation, source_hash, _evidence_metadata(record)


def _validate_feedback(value: dict[str, object], record: dict[str, object], creation: str) -> None:
    expected = _behavior_feedback_from_record(record, creation)
    # This also pins the policy contract hash and decision policy_version to the
    # local reviewed policy rather than accepting a packet-supplied contract.
    if value != expected:
        _integrity_error()


def _validate_report(value: dict[str, object], record: dict[str, object], creation: str) -> None:
    generated = value.get("generated_utc") if type(value) is dict else None
    if not _utc_or_unknown(generated, allow_seconds=True) or generated in {None, "unknown"}:
        _integrity_error()
    expected = _customer_explanation_from_record(record, creation, generated)
    if value != expected:
        _integrity_error()


def verify_packet(directory: str, *, expected_manifest_sha256: str,
                   authorization: AuthorizationGrant | None = None,
                   scope: AuthorizationScope | None = None) -> dict:
    """Verify one selected private packet against a separately trusted manifest hash.

    ``expected_manifest_sha256`` must be obtained out of band.  The packet's own
    manifest is intentionally not treated as an authenticity claim or trust root.
    """
    _require_authorization(authorization, scope)
    if scope.operation != "verify_evidence" or scope.input_ref != directory or scope.output_ref != expected_manifest_sha256:
        raise AuthorizationError("authorization scope does not match selected verification")
    authorization.begin(scope)
    if type(expected_manifest_sha256) is not str or not _valid_hash(expected_manifest_sha256):
        authorization.revoke()
        _integrity_error()
    try:
        files = _read_packet_files(directory, authorization, scope)
        authorization.check(scope)
        # Hash exact raw manifest bytes before decoding.  A self-shipped digest is
        # never accepted in place of this explicit, separately supplied pin.
        if sha256(files["evidence-manifest.json"]).hexdigest() != expected_manifest_sha256:
            _integrity_error()
        manifest = _strict_json_object(files["evidence-manifest.json"], _MAX_PACKET_FILE_BYTES)
        manifest_creation, manifest_source, manifest_metadata = _validate_packet_manifest(manifest, files)
        envelope = _strict_json_object(files["incident-record.json"], _MAX_PACKET_FILE_BYTES)
        feedback = _strict_json_object(files["behavior-feedback.json"], _MAX_PACKET_FILE_BYTES)
        report = _strict_json_object(files["customer-explanation.json"], _MAX_PACKET_FILE_BYTES)
        record, creation, source, metadata = _validate_incident_envelope(envelope)
        if creation != manifest_creation or source != manifest_source or metadata != manifest_metadata:
            _integrity_error()
        _validate_feedback(feedback, record, creation)
        _validate_report(report, record, creation)
        if feedback["incident_record_sha256"] != creation or report["incident_record_sha256"] != creation:
            _integrity_error()
        if feedback["source_input_sha256"] != source or report["source_input_sha256"] != source:
            _integrity_error()
        if feedback["evidence_metadata"] != metadata or report["evidence_metadata"] != metadata:
            _integrity_error()
        if report["time_range"] != metadata["time_range"]:
            _integrity_error()
        if files["customer-explanation.md"] != _render_customer_markdown(report).encode("utf-8"):
            _integrity_error()
        authorization.check(scope)
        return {
            "verified": True,
            "verification_scope": "packet_integrity_and_local_format_only",
            "source_authenticity": "unverified",
            "incident_record_sha256": creation,
            "source_input_sha256": source,
            "metadata_sha256": metadata["metadata_sha256"],
            "artifacts": list(_PACKET_ARTIFACTS),
        }
    except EvidenceIntegrityError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError, KeyError, TypeError, OverflowError):
        _integrity_error()
    finally:
        authorization.revoke()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline behavior regression feedback and consented customer explanation; no execution, automatic containment or self-modification.", allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    train = modes.add_parser("train", help="evaluate trusted built-in synthetic fixtures; not model weights or live rules")
    train.add_argument("--output", help="new private output directory; otherwise safe training JSON on stdout")
    train.add_argument("--consent", action="store_true", help="fresh permission for this synthetic training run")
    explain = modes.add_parser("explain", help="read one selected decoy JSONL audit and create matching customer/technical reports")
    explain.add_argument("--audit", required=True)
    explain.add_argument("--consent", action="store_true", help="explicit fresh permission to process this selected audit")
    explain.add_argument("--output", required=True, help="new private directory; existing outputs are never overwritten")
    args = parser.parse_args(argv)
    scope = AuthorizationScope(args.mode, getattr(args, "audit", ""), args.output or "")
    authorization = request_authorization(scope, consent=args.consent)
    if authorization is None:
        print("Permission required: no input was read or training performed.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(authorization):
            if args.mode == "train":
                from .behavior import run_training
                authorization.begin(scope)
                result = run_training()
                authorization.check(scope)
                if args.output:
                    write_private_packet(args.output, {
                        "training-feedback.json": canonical(result) + b"\n",
                        "policy-contract.json": canonical({"policy_contract": result["policy_contract"], "policy_contract_sha256": result["policy_contract_sha256"], "automatic_adoption": False}) + b"\n",
                    }, authorization=authorization, scope=scope)
                    print("Created private synthetic training feedback and review-only policy contract. Runtime policies unchanged.")
                else:
                    authorization.check(scope)
                    print(canonical(result).decode("ascii"))
                return 0 if result["passed"] else 1
            snapshot = snapshot_from_audit(args.audit, authorization=authorization, scope=scope)
            authorization.check(scope)
            packet = explanation_packet(snapshot)
            authorization.check(scope)
            pin = sha256(packet["evidence-manifest.json"]).hexdigest()
            write_private_packet(args.output, packet, authorization=authorization, scope=scope)
            print("Created private matching reports. No enforcement or runtime change occurred.")
            print("Preserve this manifest SHA-256 separately for verification: " + pin)
            return 0
    except (AuthorizationError, OSError, ValueError, UnicodeError, RecursionError, KeyboardInterrupt):
        print("Authorization or input/output validation failed; no further analysis/export or enforcement occurred.", file=sys.stderr)
        return 2
    finally:
        authorization.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
