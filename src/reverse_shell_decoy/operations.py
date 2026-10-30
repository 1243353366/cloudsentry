"""Summarize one explicitly selected decoy-service audit without side effects.

This module deliberately performs no service control, network activity, command
execution, account access, or recursive file discovery.  It reads one regular
JSONL file selected by the operator and reports only bounded, privacy-preserving
facts from the supplied records.  Every imported record remains unverified.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import re
import sys
from typing import Any

from .input_files import read_regular
from .signals import TOKEN_INDICATORS
from .simulator import DecoySession


MAX_AUDIT_BYTES = 2 * 1024 * 1024
MAX_PHYSICAL_RECORDS = 1000
MAX_LINE_BYTES = 16 * 1024
MAX_SESSIONS = 100
MAX_SESSION_ID_LENGTH = 128
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 512

_EVENT_TYPES = frozenset({"connecting", "command", "mirror_chunk", "close", "service_budget"})
_SESSION_EVENT_TYPES = frozenset({"connecting", "command", "mirror_chunk", "close"})
_CLASSIFICATIONS = (
    "connection_only",
    "probe_like",
    "burst_pattern",
    "multi_command_pattern",
    "execution_related_text",
)
_KNOWN_VERBS = frozenset(DecoySession.allowed_verbs)
_RATE_REASONS = frozenset({"command_rate_limit", "chunk_rate_limit"})
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")

# These labels are deliberately finite.  Unknown supplied stop text is not
# reproduced, and it is not considered a valid service-budget event.
_STOP_REASONS = frozenset({
    "not_stopped",
    "operator_shutdown",
    "service_runtime_limit",
    "audit_limit",
    "operator_audit_failure",
    "active_session_limit",
    "lifetime_connection_limit",
    "max_sessions_total",
    "max_commands",
    "max_runtime_seconds",
    "max_input_bytes_total",
    "max_output_bytes_total",
    "max_session_input_bytes",
    "commands_per_second",
    "global_input_byte_budget",
    "global_output_byte_budget",
    "session_input_byte_budget",
    "idle_timeout_seconds",
    "session_timeout_seconds",
    "input_budget",
    "output_budget",
    "session_input_budget",
    "command_limit",
    "input_limit",
    "output_limit",
    "completed",
    "unknown",
})

# (minimum, maximum, integer_required).  These bounds describe accepted audit
# values, not measured host usage or a guarantee of infrastructure protection.
_LIMIT_BOUNDS: dict[str, tuple[float, float, bool]] = {
    "max_sessions": (1, 64, True),
    "max_sessions_total": (1, 100, True),
    "max_commands": (1, 100, True),
    "max_runtime_seconds": (0, 3600, False),
    "idle_timeout_seconds": (1, 300, True),
    "session_timeout_seconds": (1, 3600, True),
    "max_input_bytes_total": (1, 8 * 1024 * 1024, True),
    "max_output_bytes_total": (1, 8 * 1024 * 1024, True),
    "max_session_input_bytes": (1, 256 * 1024, True),
    "commands_per_second": (1, 10, True),
}
_USAGE_BOUNDS: dict[str, tuple[float, float, bool]] = {
    "input_bytes_total": (0, 8 * 1024 * 1024, True),
    "output_bytes_total": (0, 8 * 1024 * 1024, True),
    "accepted_connections": (0, 100, True),
    "active_sessions": (0, 64, True),
    "peak_active_sessions": (0, 64, True),
    "elapsed_seconds": (0, 86400, False),
}


def _limited_int(text: str) -> int:
    """Reject unusually large JSON numbers before creating large integers."""
    if len(text) > 24:
        raise ValueError("JSON number is too long")
    return int(text)


def _limited_float(text: str) -> float:
    """Reject unusually large JSON floats before converting them."""
    if len(text) > 64:
        raise ValueError("JSON number is too long")
    return float(text)


def _reject_json_constant(_: str) -> None:
    """Do not permit non-finite JSON extensions such as NaN or Infinity."""
    raise ValueError("non-finite JSON constant")


def _bounded_json_shape(value: object) -> bool:
    """Reject deeply nested or excessively broad JSON before inspecting fields."""
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return False
        if isinstance(current, dict):
            if len(current) > MAX_JSON_NODES:
                return False
            for key, item in current.items():
                # JSON object keys are strings, but retain this check for a
                # conservative boundary if a decoder implementation changes.
                if not isinstance(key, str) or len(key) > 256:
                    return False
                pending.append((item, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_JSON_NODES:
                return False
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, str) and len(current) > MAX_LINE_BYTES:
            return False
    return True


def _parse_record(line: bytes) -> dict[str, Any] | None:
    """Decode one bounded JSON object, returning ``None`` for unsafe input."""
    try:
        value = json.loads(
            line.decode("utf-8"),
            parse_int=_limited_int,
            parse_float=_limited_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError):
        return None
    if not isinstance(value, dict) or not _bounded_json_shape(value):
        return None
    return value


def _timestamp(value: object) -> str | None:
    """Return an ISO-8601 UTC time only when a supplied time has an offset."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    # Python 3.10 accepts three/six fractional digits whereas newer versions
    # also accept shorter fractions. Preserve their value across supported runtimes.
    normalized = re.sub(
        r"\.(\d{1,5})(?=[+-]\d{2}:\d{2}$)",
        lambda match: "." + match.group(1).ljust(6, "0"),
        value.replace("Z", "+00:00"),
    )
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def _valid_session_id(value: object) -> str | None:
    """Accept only a short, identifier-shaped session value for hash referencing."""
    if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
        return None
    return value


def _number(value: object, bounds: tuple[float, float, bool]) -> int | float | None:
    """Validate a finite, bounded number without coercing arbitrary values."""
    minimum, maximum, integer_required = bounds
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(float(value)) or value < minimum or value > maximum:
        return None
    if integer_required and not isinstance(value, int):
        return None
    return value


def _budget_numbers(value: object, bounds: dict[str, tuple[float, float, bool]]) -> dict[str, int | float | str] | None:
    """Copy only supplied, valid allowlisted budget fields; mark absent ones unknown."""
    if value is None:
        supplied: dict[str, object] = {}
    elif isinstance(value, dict):
        supplied = value
    else:
        return None
    cleaned: dict[str, int | float | str] = {}
    for field, field_bounds in bounds.items():
        if field not in supplied:
            cleaned[field] = "unknown"
            continue
        number = _number(supplied[field], field_bounds)
        if number is None or (field == "max_runtime_seconds" and number <= 0):
            return None
        cleaned[field] = number
    return cleaned


def _token_labels(value: object) -> set[str]:
    """Keep only known fixed text-indicator labels, never arbitrary supplied text."""
    if not isinstance(value, list) or len(value) > 32:
        return set()
    return {item for item in value if isinstance(item, str) and item in TOKEN_INDICATORS}


def _new_session(session_id: str) -> dict[str, Any]:
    """Create transient internal state; the original session ID is never output."""
    return {
        "reference": sha256(session_id.encode("utf-8")).hexdigest(),
        "event_counts": Counter(),
        "known_verbs": set(),
        "token_indicators": set(),
        "rate_reasons": set(),
        "first_seen_utc": None,
        "last_seen_utc": None,
    }


def _record_session_event(state: dict[str, Any], event: dict[str, Any], event_type: str, timestamp_utc: str) -> None:
    """Retain a deliberately small subset of a valid session event."""
    state["event_counts"][event_type] += 1
    first = state["first_seen_utc"]
    last = state["last_seen_utc"]
    state["first_seen_utc"] = timestamp_utc if first is None or timestamp_utc < first else first
    state["last_seen_utc"] = timestamp_utc if last is None or timestamp_utc > last else last

    if event_type == "command":
        verb = event.get("verb")
        if isinstance(verb, str) and verb in _KNOWN_VERBS:
            state["known_verbs"].add(verb)
        state["token_indicators"].update(_token_labels(event.get("token_indicators")))
    if event_type in {"command", "mirror_chunk"}:
        reason = event.get("reason")
        if isinstance(reason, str) and reason in _RATE_REASONS:
            state["rate_reasons"].add(reason)


def _classification(name: str, reasons: list[str]) -> dict[str, object]:
    """Use the same low-confidence wording for every deterministic pattern flag."""
    return {"name": name, "confidence": "low", "reasons": reasons}


def _session_output(state: dict[str, Any]) -> dict[str, object]:
    """Convert transient state to a hash-only, fixed-label public session summary."""
    counts = state["event_counts"]
    interactions = counts["command"] + counts["mirror_chunk"]
    known_verbs = sorted(state["known_verbs"])
    indicators = sorted(state["token_indicators"])
    classifications: list[dict[str, object]] = []

    if counts["connecting"] and not interactions:
        classifications.append(_classification("connection_only", ["connecting_without_command_or_chunk"]))
    # A short provided trace may be incomplete.  This flag therefore remains
    # compatible with other flags and does not assert a human or scanner source.
    if 1 <= interactions <= 2:
        classifications.append(_classification("probe_like", ["one_or_two_command_or_chunk_events"]))
    if state["rate_reasons"]:
        classifications.append(_classification("burst_pattern", sorted(state["rate_reasons"])))
    if len(known_verbs) >= 3:
        classifications.append(_classification("multi_command_pattern", ["three_or_more_distinct_known_verbs"]))
    if indicators:
        classifications.append(_classification("execution_related_text", indicators))

    missing_coverage: list[str] = []
    if not counts["connecting"]:
        missing_coverage.append("connecting_event_missing")
    if not counts["close"]:
        missing_coverage.append("close_event_missing")

    return {
        "session_ref_sha256": state["reference"],
        "event_counts": {event_type: counts[event_type] for event_type in sorted(_SESSION_EVENT_TYPES)},
        "known_verbs": known_verbs,
        "token_indicators": indicators,
        "first_seen_utc": state["first_seen_utc"] or "unknown",
        "last_seen_utc": state["last_seen_utc"] or "unknown",
        "missing_coverage": missing_coverage,
        "classifications": classifications,
    }


def _budget_event(event: dict[str, Any], timestamp_utc: str) -> dict[str, object] | None:
    """Validate a service-control budget record without trusting it as authoritative."""
    if event.get("source_kind") != "decoy_service_control" or event.get("interaction_observed") is not False:
        return None
    phase = event.get("phase")
    if not isinstance(phase, str) or phase not in {"started", "stopped"}:
        return None
    raw_stop_reason = event.get("stop_reason")
    if raw_stop_reason is None:
        stop_reason = "unknown"
    elif isinstance(raw_stop_reason, str) and raw_stop_reason in _STOP_REASONS:
        stop_reason = raw_stop_reason
    else:
        return None
    limits = _budget_numbers(event.get("limits"), _LIMIT_BOUNDS)
    usage = _budget_numbers(event.get("usage"), _USAGE_BOUNDS)
    if limits is None or usage is None:
        return None
    return {
        "timestamp_utc": timestamp_utc,
        "phase": phase,
        "stop_reason": stop_reason,
        "limits": limits,
        "usage": usage,
    }


def build_operations_summary(audit_path: str) -> dict:
    """Build a deterministic summary of one manually selected local JSONL audit.

    The file is opened only through :func:`read_regular`, so symlinks, devices,
    FIFO streams, and inputs larger than two MiB are rejected before parsing.
    Malformed, deep, unsupported, and overlong records are counted but do not
    cause any supplied raw text to enter the result.
    """
    content = read_regular(audit_path, MAX_AUDIT_BYTES)
    # ``read_regular`` enforces this too; retain an explicit invariant should the
    # helper ever be replaced.
    if len(content) > MAX_AUDIT_BYTES:
        raise ValueError("audit input exceeds 2 MiB")
    lines = content.splitlines()
    if len(lines) > MAX_PHYSICAL_RECORDS:
        raise ValueError("audit input exceeds 1000 physical records")

    discarded = Counter({
        "blank_or_empty": 0,
        "overlong_line": 0,
        "malformed_or_deep_json": 0,
        "invalid_or_unsupported_record": 0,
        "session_limit_omitted": 0,
    })
    sessions: dict[str, dict[str, Any]] = {}
    budget_events: list[dict[str, object]] = []
    accepted_records = 0
    first_timestamp: str | None = None
    last_timestamp: str | None = None

    for line in lines:
        if not line.strip():
            discarded["blank_or_empty"] += 1
            continue
        if len(line) > MAX_LINE_BYTES:
            discarded["overlong_line"] += 1
            continue
        event = _parse_record(line)
        if event is None:
            discarded["malformed_or_deep_json"] += 1
            continue
        event_type = event.get("event_type")
        timestamp_utc = _timestamp(event.get("timestamp_utc"))
        if not isinstance(event_type, str) or event_type not in _EVENT_TYPES or timestamp_utc is None:
            discarded["invalid_or_unsupported_record"] += 1
            continue

        if event_type == "service_budget":
            budget = _budget_event(event, timestamp_utc)
            if budget is None:
                discarded["invalid_or_unsupported_record"] += 1
                continue
            budget_events.append(budget)
            accepted_records += 1
        else:
            session_id = _valid_session_id(event.get("session_id"))
            if session_id is None:
                discarded["invalid_or_unsupported_record"] += 1
                continue
            if session_id not in sessions:
                if len(sessions) >= MAX_SESSIONS:
                    discarded["session_limit_omitted"] += 1
                    continue
                sessions[session_id] = _new_session(session_id)
            _record_session_event(sessions[session_id], event, event_type, timestamp_utc)
            accepted_records += 1

        first_timestamp = timestamp_utc if first_timestamp is None or timestamp_utc < first_timestamp else first_timestamp
        last_timestamp = timestamp_utc if last_timestamp is None or timestamp_utc > last_timestamp else last_timestamp

    session_results = sorted(
        (_session_output(state) for state in sessions.values()),
        key=lambda item: str(item["session_ref_sha256"]),
    )
    classification_counts = {name: 0 for name in _CLASSIFICATIONS}
    for session in session_results:
        for item in session["classifications"]:
            name = item["name"]
            if name in classification_counts:
                classification_counts[name] += 1

    budget_status = "supplied_unverified" if budget_events else "unknown"
    budget_phase_counts = Counter(
        item["phase"] for item in budget_events if item.get("phase") in {"started", "stopped"}
    )
    uncertainty_counts = {
        "discarded_records": sum(discarded.values()),
        "sessions_missing_connecting_event": sum(
            "connecting_event_missing" in item["missing_coverage"] for item in session_results
        ),
        "sessions_missing_close_event": sum(
            "close_event_missing" in item["missing_coverage"] for item in session_results
        ),
        "service_budget_started_records": budget_phase_counts["started"],
        "service_budget_stopped_records": budget_phase_counts["stopped"],
        "service_budget_started_record_missing": int(not budget_phase_counts["started"]),
        "service_budget_stopped_record_missing": int(not budget_phase_counts["stopped"]),
    }
    return {
        "title": "Decoy operations summary",
        "provider": "local",
        "source_kind": "decoy_operations_summary",
        "audit": {
            "status": "explicitly_selected_local_jsonl_unverified",
            "input_sha256": sha256(content).hexdigest(),
            "input_bytes": len(content),
            "physical_records": len(lines),
            "accepted_records": accepted_records,
            "discarded_records": dict(discarded),
            "coverage": "provided_records_only; completeness_unknown",
            "first_valid_timestamp_utc": first_timestamp or "unknown",
            "last_valid_timestamp_utc": last_timestamp or "unknown",
        },
        "sessions": session_results,
        "session_count": len(session_results),
        "classification_counts": classification_counts,
        "budget_stats": {
            "status": budget_status,
            "coverage": "provided_records_only; completeness_unknown",
            "events": budget_events,
        },
        "uncertainty_counts": uncertainty_counts,
        "budget_counter_semantics": {
            "input_bytes_total": "admitted_application_bytes_not_physical_traffic",
            "output_bytes_total": "reserved_application_output_not_confirmed_delivery",
            "remote_resource_cost": "unknown",
        },
        "classification_notice": (
            "Flags describe limited supplied-record patterns only; they do not prove a human, scanner, "
            "exploitation, host access, execution, identity, remote operating system, or remote resource use."
        ),
        "limitations": [
            "All imported records, including claimed interaction observations, are unverified.",
            "Synthetic decoy responses do not prove host access or identity.",
            "Missing, malformed, omitted, or unavailable events leave coverage unknown rather than clean.",
            "Missing service-budget start or stop records are unknown coverage, not proof of service failure.",
            "input_bytes_total counts admitted application bytes, not physical traffic or bandwidth.",
            "output_bytes_total counts reserved application output even when delivery is not confirmed.",
            "Supplied service budgets are not a measurement of remote CPU, memory, operating system, money, or cost.",
        ],
        "automatic_actions": False,
    }


def _safe_hash(value: object) -> str:
    return value if isinstance(value, str) and _HASH.fullmatch(value) else "unknown"


def _safe_count(value: object, maximum: int = MAX_PHYSICAL_RECORDS) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum else 0


def _safe_timestamp(value: object) -> str:
    return _timestamp(value) or "unknown"


def _safe_category_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name in _CLASSIFICATIONS:
                names.append(name)
    return names


def markdown(result: dict) -> str:
    """Render a safe Markdown view without reproducing untrusted audit values."""
    audit = result.get("audit") if isinstance(result, dict) and isinstance(result.get("audit"), dict) else {}
    sessions = result.get("sessions") if isinstance(result, dict) and isinstance(result.get("sessions"), list) else []
    classifications = result.get("classification_counts") if isinstance(result, dict) and isinstance(result.get("classification_counts"), dict) else {}
    budget_stats = result.get("budget_stats") if isinstance(result, dict) and isinstance(result.get("budget_stats"), dict) else {}

    lines = [
        "# Decoy operations summary",
        "",
        "This is a local summary of one explicitly selected JSONL audit. All supplied records are unverified.",
        "",
        "## Supplied audit coverage",
        "",
        f"- Input SHA-256: `{_safe_hash(audit.get('input_sha256'))}`",
        f"- Input bytes: {_safe_count(audit.get('input_bytes'), MAX_AUDIT_BYTES)}",
        f"- Physical records: {_safe_count(audit.get('physical_records'))}",
        f"- Accepted records: {_safe_count(audit.get('accepted_records'))}",
        f"- Valid supplied time range: {_safe_timestamp(audit.get('first_valid_timestamp_utc'))} to {_safe_timestamp(audit.get('last_valid_timestamp_utc'))}",
        "- Coverage is limited to the provided records; completeness is unknown.",
        "",
        "## Limited observable pattern flags",
        "",
    ]
    for name in _CLASSIFICATIONS:
        lines.append(f"- **{name}**: {_safe_count(classifications.get(name), MAX_SESSIONS)} session(s).")
    lines += [
        "",
        "These low-confidence flags do not prove a human, scanner, exploitation, host access, execution, identity, remote OS, or remote resource use.",
        "",
        "## Hash-referenced sessions",
        "",
    ]
    rendered_sessions = 0
    for session in sessions[:MAX_SESSIONS]:
        if not isinstance(session, dict):
            continue
        reference = _safe_hash(session.get("session_ref_sha256"))
        names = _safe_category_names(session.get("classifications"))
        labels = ", ".join(names) if names else "no_pattern_flag"
        lines.append(f"- `{reference}`: {labels}.")
        rendered_sessions += 1
    if not rendered_sessions:
        lines.append("- No hash-referenced valid session records were supplied.")

    budget_status = budget_stats.get("status")
    if budget_status not in {"supplied_unverified", "unknown"}:
        budget_status = "unknown"
    raw_budget_events = budget_stats.get("events")
    budget_event_count = len(raw_budget_events) if isinstance(raw_budget_events, list) else 0
    lines += [
        "",
        "## Decoy service budget records",
        "",
        f"- Status: {budget_status}.",
        f"- Valid supplied budget records: {_safe_count(budget_event_count)}.",
        "- Budget values are supplied, unverified application-control records. Missing values are unknown.",
        "- They are not measurements of remote CPU, memory, operating system, money, or cost.",
        "",
        "## Interpretation limits",
        "",
        "Synthetic responses never prove host access or identity. Missing, malformed, omitted, or unavailable events are unknown coverage, not a clean result. This command takes no automatic action and starts no service.",
    ]
    return "\n".join(lines) + "\n"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the explicit local-audit arguments to a caller-owned parser."""
    parser.add_argument("--audit", required=True, help="explicit local service-audit JSONL file; no service launch")
    parser.add_argument("--json", action="store_true", help="emit structured JSON rather than Markdown")


def run_args(args: argparse.Namespace) -> int:
    """Run one manually requested summary and print only its local result."""
    result = build_operations_summary(args.audit)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
    else:
        print(markdown(result), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse an explicit audit path; never discover inputs or launch anything."""
    parser = argparse.ArgumentParser(
        description="Summarize one explicitly selected decoy-service audit locally; no service launch or automatic action."
    )
    add_arguments(parser)
    args = parser.parse_args(argv)
    try:
        return run_args(args)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
