"""Offline analysis of manually supplied cloud audit-log exports.

This module is deliberately input-only: it reads no files, environment variables, or
cloud credentials, performs no API calls, and does not discover or connect to an
account.  Reports retain only a hash of each supplied source event and narrowly
normalized safe fields.  They are triage aids, not a finding of compromise.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import csv
import html
import io
import ipaddress
import json
import math
import re
from typing import Any, Iterable


MAX_INPUT_BYTES = 8 * 1024 * 1024
"""Largest accepted UTF-8 input representation (8 MiB)."""
MAX_RECORDS = 10_000
"""Largest number of source records accepted from one manual import."""
MAX_JSON_DEPTH = 64
"""Maximum lexical JSON nesting depth accepted before decoding."""
MAX_ACTION_LENGTH = 160
MAX_TEXT_EXCERPT = 240
MAX_FINDING_REFERENCES = 20

_SUPPORTED_PROVIDERS = frozenset({"cloudflare", "aws", "render", "railway"})
_SUPPORTED_FORMATS = frozenset({"auto", "json", "jsonl", "csv", "text"})

# These are the Render event names documented on Render's audit-logs page.  Keeping
# this list narrow prevents arbitrary runtime text from being represented as a named
# Render API event.
_RENDER_SHELL_EVENTS = frozenset({"StartShellEvent", "EndShellEvent"})
_RENDER_SECRET_VIEW_EVENTS = frozenset({"ViewEnvVarValuesEvent", "ViewConnectionInfoEvent"})
_RENDER_ENV_EVENTS = frozenset({"CreateEnvVarsEvent", "UpdateEnvVarsEvent", "DeleteEnvVarsEvent", "DeleteEnvGroupEvent"})
_RENDER_DEPLOYMENT_EVENTS = frozenset({"UpdateAutoDeployEvent", "UpdateAutoDeployTriggerEvent"})

# These patterns redact likely secret-bearing material before any bounded text
# excerpt is returned.  Hashes are computed before redaction to preserve a stable
# reference without exposing the input.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?key|secret|token|password|authorization|credential)"
    r"\b\s*(?:=|:|\s)\s*)([^\s,;\]\}]+)"
)
_BEARER_VALUE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9])")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class _ParseState:
    """Small mutable state object kept private to this one import."""

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self._warning_set: set[str] = set()
        self.unparseable_records = 0
        self.input_unparseable = False
        self.record_limit_reached = False
        self.records_seen = 0
        self.input_format = "unknown"

    def warn(self, message: str) -> None:
        if message not in self._warning_set:
            self._warning_set.add(message)
            self.warnings.append(message)


def analyze_cloud_logs(provider: str, content: str, format: str = "auto") -> dict:
    """Analyze a manually supplied cloud-log snapshot without contacting a provider.

    Args:
        provider: One of ``cloudflare``, ``aws``, ``render``, or ``railway``.
        content: UTF-8 text copied from an export, JSONL, supported JSON envelope,
            Render CSV export, or limited runtime-message text.
        format: ``auto`` (default), ``json``, ``jsonl``, ``csv``, or ``text``.

    Returns:
        A JSON-safe report containing redacted normalized events, heuristic findings,
        coverage warnings, counts, and SHA-256 references.  Empty or malformed input
        returns a report with unknown/incomplete coverage; it is never an all-clear.

    Raises:
        TypeError: If ``provider``, ``content``, or ``format`` has the wrong type.
        ValueError: If the provider/format is unsupported or input exceeds 8 MiB.
    """

    normalized_provider = _validate_provider(provider)
    normalized_format = _validate_format(format)
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    try:
        input_bytes = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("content must be valid UTF-8 text") from exc
    if len(input_bytes) > MAX_INPUT_BYTES:
        raise ValueError("content exceeds the 8 MiB maximum")

    state = _ParseState()
    source_sha256 = sha256(input_bytes).hexdigest()
    records, is_synthetic = _parse_records(
        normalized_provider, content, normalized_format, state
    )

    events: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            state.unparseable_records += 1
            continue
        try:
            event, detection_data = _normalize_record(
                normalized_provider, record, is_synthetic
            )
        except (RecursionError, TypeError, ValueError, OverflowError):
            # An individual malformed record cannot discard the remaining bounded
            # records.  Never include exception text because it can echo input.
            state.unparseable_records += 1
            continue
        events.append(event)
        internal.append(detection_data)

    if state.unparseable_records:
        state.warn(
            "one or more supplied records could not be normalized; coverage is incomplete"
        )
    if not events:
        state.warn(
            "no usable records were found; coverage is unknown and incomplete, not clean"
        )

    missing_timestamps = sum(
        1 for event in events if "timestamp_utc" not in event
    )
    invalid_timestamps = sum(
        1 for event in events if "timestamp_original" in event
    )
    if missing_timestamps:
        state.warn(
            "one or more normalized records lack a validated timestamp; timing coverage is incomplete"
        )
    if is_synthetic:
        state.warn(
            "synthetic demo input was declared; findings are demonstrations, not observations from an account"
        )

    findings = _make_findings(internal, is_synthetic)
    events_by_category = _count_values(event.get("category", "unknown") for event in events)
    findings_by_category = _count_values(
        finding.get("category", "unknown") for finding in findings
    )

    coverage_status = "unknown" if state.input_unparseable or not events else "partial"
    summary = {
        "event_count": len(events),
        "finding_count": len(findings),
        "events_by_category": events_by_category,
        "findings_by_category": findings_by_category,
        "counts": {
            "events": len(events),
            "findings": len(findings),
            "records_seen": state.records_seen,
        },
        "missing_coverage": {
            "manual_snapshot_unverified": True,
            "record_completeness_unknown": True,
            "no_usable_records": not bool(events),
            "records_without_validated_timestamps": missing_timestamps,
            "records_with_unvalidated_timestamp_text": invalid_timestamps,
            "unparseable_records": state.unparseable_records,
            "input_unparseable": state.input_unparseable,
            "record_limit_reached": state.record_limit_reached,
        },
        "coverage_status": coverage_status,
    }
    return {
        "provider": normalized_provider,
        "source_kind": "manual_cloud_log_import",
        "input_format": state.input_format,
        "source_sha256": source_sha256,
        "source_is_synthetic": is_synthetic,
        "records_seen": state.records_seen,
        "simulation": False,
        "events": events,
        "findings": findings,
        "warnings": state.warnings,
        "summary": summary,
        "limitation_notice": (
            "This is an offline analysis of an unverified manual snapshot. It did not "
            "connect to a cloud account, collect additional records, or establish that "
            "an event was authorized, malicious, or complete. No result is an all-clear."
        ),
    }


def _validate_provider(provider: str) -> str:
    if not isinstance(provider, str):
        raise TypeError("provider must be a string")
    value = provider.strip().lower()
    if value not in _SUPPORTED_PROVIDERS:
        raise ValueError("provider must be one of: aws, cloudflare, railway, render")
    return value


def _validate_format(format: str) -> str:
    if not isinstance(format, str):
        raise TypeError("format must be a string")
    value = format.strip().lower()
    if value not in _SUPPORTED_FORMATS:
        raise ValueError("format must be one of: auto, json, jsonl, csv, text")
    return value


def _parse_records(
    provider: str, content: str, requested_format: str, state: _ParseState
) -> tuple[list[Any], bool]:
    """Decode bounded input and return source records plus explicit demo status."""

    selected = requested_format
    stripped = content.lstrip()
    if selected == "auto":
        if _looks_like_render_csv(content):
            selected = "csv"
        elif stripped.startswith(("{", "[")):
            selected = "json"
        else:
            selected = "text"

    if selected == "json":
        parsed = _decode_json(content, state)
        if parsed is None and requested_format == "auto" and _looks_like_jsonl(content):
            # A line-delimited export can begin with a JSON object, so try JSONL
            # only after bounded regular JSON parsing failed.
            return _parse_jsonl(provider, content, state)
        if parsed is None:
            state.input_format = "json"
            return [], False
        state.input_format = "json"
        return _extract_json_records(provider, parsed, state)
    if selected == "jsonl":
        return _parse_jsonl(provider, content, state)
    if selected == "csv":
        return _parse_csv(provider, content, state)
    return _parse_text(provider, content, state)


def _decode_json(content: str, state: _ParseState) -> Any | None:
    if not _json_depth_is_safe(content):
        state.input_unparseable = True
        state.warn("JSON nesting exceeds the safe depth; coverage is unknown and incomplete")
        return None
    try:
        return json.loads(content, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, RecursionError, ValueError, UnicodeDecodeError):
        state.input_unparseable = True
        state.warn("input JSON could not be parsed; coverage is unknown and incomplete")
        return None


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _json_depth_is_safe(content: str) -> bool:
    """Lexically bound nesting before ``json.loads`` can recurse."""

    depth = 0
    in_string = False
    escaped = False
    for character in content:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif character in "]}":
            depth -= 1
            if depth < 0:
                # Leave structural validation to the JSON parser, which will return
                # a generic non-reflective warning.  This fast check need not parse.
                return True
    return True


def _looks_like_jsonl(content: str) -> bool:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return len(lines) > 1 and all(line.startswith(("{", "[")) for line in lines)


def _parse_jsonl(provider: str, content: str, state: _ParseState) -> tuple[list[Any], bool]:
    state.input_format = "jsonl"
    records: list[Any] = []
    synthetic = False
    nonempty = 0
    for line in content.splitlines():
        if not line.strip():
            continue
        nonempty += 1
        if len(records) >= MAX_RECORDS:
            state.record_limit_reached = True
            state.warn("record limit reached; remaining supplied records were not analyzed")
            break
        if not _json_depth_is_safe(line):
            state.unparseable_records += 1
            continue
        try:
            item = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, RecursionError, ValueError, UnicodeDecodeError):
            state.unparseable_records += 1
            continue
        if isinstance(item, dict) and item.get("demo") is True:
            synthetic = True
        if isinstance(item, list):
            for entry in item:
                if len(records) >= MAX_RECORDS:
                    state.record_limit_reached = True
                    state.warn("record limit reached; remaining supplied records were not analyzed")
                    break
                records.append(entry)
        else:
            records.append(item)
    state.records_seen = len(records)
    if nonempty and not records:
        state.input_unparseable = True
        state.warn("input JSONL could not be parsed; coverage is unknown and incomplete")
    # JSONL commonly contains direct event rows; only unwrap a deliberate provider
    # envelope when a single row supplied one.
    if len(records) == 1 and isinstance(records[0], dict):
        extracted, nested_synthetic = _extract_json_records(provider, records[0], state)
        if extracted:
            return extracted, synthetic or nested_synthetic
    return records, synthetic


def _looks_like_render_csv(content: str) -> bool:
    if content.lstrip().startswith(("{", "[")):
        return False
    first_line = content.splitlines()[0].lower() if content.splitlines() else ""
    return "," in first_line and "timestamp" in first_line and "event" in first_line


def _parse_csv(provider: str, content: str, state: _ParseState) -> tuple[list[Any], bool]:
    state.input_format = "csv"
    if provider != "render":
        state.input_unparseable = True
        state.warn("CSV import is supported only for documented Render audit exports; coverage is unknown")
        return [], False
    try:
        reader = csv.DictReader(io.StringIO(content))
        fieldnames = {field.strip().lower() for field in (reader.fieldnames or []) if field}
        if not {"timestamp", "event", "status"}.issubset(fieldnames):
            state.input_unparseable = True
            state.warn("CSV does not have the expected Render audit columns; coverage is unknown")
            return [], False
        records: list[dict[str, Any]] = []
        for row in reader:
            if len(records) >= MAX_RECORDS:
                state.record_limit_reached = True
                state.warn("record limit reached; remaining supplied records were not analyzed")
                break
            # CSV values are strings.  Decode metadata only for local source-IP and
            # resource-type normalization; the original metadata is never returned.
            metadata: Any = row.get("metadata")
            if isinstance(metadata, str) and metadata.strip():
                if _json_depth_is_safe(metadata):
                    try:
                        candidate = json.loads(metadata, parse_constant=_reject_json_constant)
                        metadata = candidate if isinstance(candidate, dict) else {}
                    except (json.JSONDecodeError, RecursionError, ValueError):
                        metadata = {}
                        state.unparseable_records += 1
                else:
                    metadata = {}
                    state.unparseable_records += 1
            else:
                metadata = {}
            records.append(
                {
                    "timestamp": row.get("timestamp"),
                    "actor": row.get("actor"),
                    "event": row.get("event"),
                    "status": row.get("status"),
                    "metadata": metadata,
                }
            )
        state.records_seen = len(records)
        return records, False
    except (csv.Error, RecursionError, UnicodeError):
        state.input_unparseable = True
        state.warn("CSV import could not be parsed; coverage is unknown and incomplete")
        return [], False


def _parse_text(provider: str, content: str, state: _ParseState) -> tuple[list[Any], bool]:
    """Use a deliberately narrow fallback for supplied runtime messages only."""

    state.input_format = "text"
    records: list[dict[str, Any]] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        if len(records) >= MAX_RECORDS:
            state.record_limit_reached = True
            state.warn("record limit reached; remaining supplied records were not analyzed")
            break
        records.append({"_manual_text": line, "_text_provider": provider})
    state.records_seen = len(records)
    if records:
        state.warn(
            "unstructured runtime-message fallback was used; event coverage is limited and incomplete"
        )
    else:
        state.input_unparseable = True
        state.warn("input contains no readable runtime messages; coverage is unknown and incomplete")
    return records, False


def _extract_json_records(provider: str, parsed: Any, state: _ParseState) -> tuple[list[Any], bool]:
    synthetic = isinstance(parsed, dict) and parsed.get("demo") is True
    records: Any = None
    if isinstance(parsed, list):
        records = parsed
    elif isinstance(parsed, dict):
        if parsed.get("source") == "manual_read_only_cloud_api" and isinstance(parsed.get("events"), list):
            records = parsed["events"]
            state.warn("source declares a bounded API collection; full account coverage is not established")
            coverage = parsed.get("coverage")
            if isinstance(coverage, dict) and coverage.get("truncated") is True:
                state.warn("upstream collection was truncated; additional cloud evidence was not analyzed")
        elif provider == "aws":
            records = parsed.get("Records")
        elif provider == "cloudflare":
            result = parsed.get("result")
            if isinstance(result, list):
                records = result
            elif isinstance(result, dict):
                # Supported as an explicit nested audit-log wrapper, without
                # asserting it is the only Cloudflare export format.
                records = result.get("audit_logs")
        elif provider in {"render", "railway"}:
            for key in ("events", "logs"):
                if isinstance(parsed.get(key), list):
                    records = parsed[key]
                    break
            if records is None and provider == "railway":
                records = _railway_graphql_nodes(parsed)
    if not isinstance(records, list):
        state.input_unparseable = True
        state.warn(
            "no supported record list was found in the supplied export; coverage is unknown and incomplete"
        )
        return [], synthetic
    if len(records) > MAX_RECORDS:
        state.record_limit_reached = True
        state.warn("record limit reached; remaining supplied records were not analyzed")
        records = records[:MAX_RECORDS]
    state.records_seen = len(records)
    return records, synthetic


def _railway_graphql_nodes(parsed: dict[str, Any]) -> list[Any] | None:
    """Extract the documented Railway ``auditLogs.edges.node`` response safely."""

    root: Any = parsed.get("data", parsed)
    if not isinstance(root, dict):
        return None
    audit_logs = root.get("auditLogs")
    if not isinstance(audit_logs, dict):
        return None
    edges = audit_logs.get("edges")
    if not isinstance(edges, list):
        return None
    nodes: list[Any] = []
    for edge in edges:
        if isinstance(edge, dict) and isinstance(edge.get("node"), dict):
            nodes.append(edge["node"])
        else:
            nodes.append(edge)
    return nodes


def _normalize_record(
    provider: str, record: dict[str, Any], is_synthetic: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    if "_manual_text" in record:
        return _normalize_text_record(provider, record, is_synthetic)

    source_event_sha256 = _stable_hash(record)
    action, category, timestamp_value, source_ip, identity_value, resource_type, error_kind = (
        _provider_fields(provider, record)
    )
    event: dict[str, Any] = {
        "event_id": f"{provider}:{source_event_sha256[:24]}",
        "source_event_sha256": source_event_sha256,
        "source_kind": "manual_cloud_log_import",
        "provider": provider,
        "action": _safe_action(action),
        "category": category,
        "observation": "synthetic_demo_record" if is_synthetic else "observed_in_supplied_log",
        "simulation": bool(is_synthetic),
    }
    _add_timestamp(event, timestamp_value)
    safe_ip = _safe_ip(source_ip)
    if safe_ip is not None:
        event["source_ip"] = safe_ip
    if identity_value is not None:
        event["identity_sha256"] = _stable_hash(identity_value)
    if resource_type:
        event["resource_type"] = _safe_resource_type(resource_type)

    detection_data = {
        "event": event,
        "provider": provider,
        "category": category,
        "action_for_detection": _normal_form(action),
        "error_kind": error_kind,
        "is_synthetic": is_synthetic,
    }
    return event, detection_data


def _normalize_text_record(
    provider: str, record: dict[str, Any], is_synthetic: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_line = record.get("_manual_text")
    if not isinstance(raw_line, str):
        raise ValueError("text record is invalid")
    source_event_sha256 = sha256(raw_line.encode("utf-8", "replace")).hexdigest()
    action, category, error_kind = _text_action(provider, raw_line)
    event: dict[str, Any] = {
        "event_id": f"{provider}:{source_event_sha256[:24]}",
        "source_event_sha256": source_event_sha256,
        "source_kind": "manual_cloud_log_import",
        "provider": provider,
        "action": action,
        "category": category,
        "observation": "synthetic_demo_record" if is_synthetic else "observed_in_supplied_log",
        "simulation": bool(is_synthetic),
        # This is bounded, escaped, and redacted; it is not a raw log body.
        "text_excerpt": _safe_excerpt(raw_line),
    }
    _add_timestamp(event, _extract_text_timestamp(raw_line))
    detection_data = {
        "event": event,
        "provider": provider,
        "category": category,
        "action_for_detection": _normal_form(action),
        "error_kind": error_kind,
        "is_synthetic": is_synthetic,
    }
    return event, detection_data


def _provider_fields(
    provider: str, record: dict[str, Any]
) -> tuple[Any, str, Any, Any, Any, Any, str | None]:
    if provider == "aws":
        nested = record.get("CloudTrailEvent")
        if isinstance(nested, str):
            nested = json.loads(nested)
        if isinstance(nested, dict):
            record = nested
        action = record.get("eventName")
        identity = record.get("userIdentity")
        event_source = record.get("eventSource")
        action_normal = _normal_form(action)
        identity_type = _normal_form(identity.get("type") if isinstance(identity, dict) else "")
        mfa = _value_at(record.get("additionalEventData"), "MFAUsed")
        category = "cloud_api_activity"
        if action_normal in {"stoplogging", "deletetrail", "updatetrail"}:
            category = "logging_configuration"
        elif action_normal.startswith("attach") and "policy" in action_normal or action_normal == "createaccesskey":
            category = "iam_configuration"
        elif identity_type == "root" and action_normal == "consolelogin" and _is_explicit_false(mfa):
            category = "authentication"
        error_kind = _error_kind(
            record.get("errorCode"), record.get("errorMessage"), record.get("status"), record.get("statusCode")
        )
        if error_kind is None and (record.get("errorCode") is not None or record.get("errorMessage") is not None):
            # CloudTrail documents these fields as service-error information.  Keep
            # only the generic internal classification; never echo either value.
            error_kind = "server_or_operational"
        return (
            action,
            category,
            record.get("eventTime"),
            record.get("sourceIPAddress"),
            identity,
            _aws_resource_type(event_source),
            error_kind,
        )

    if provider == "cloudflare":
        action_value = record.get("action")
        action = _cloudflare_action(action_value)
        action_type = _normal_form(
            action_value.get("type") if isinstance(action_value, dict) else _action_verb(action)
        )
        resource = record.get("resource")
        resources = record.get("resources")
        product = _first_string(
            _value_at(resource, "product"),
            _value_at(resource, "type"),
            _value_at(resources[0], "resource_type") if isinstance(resources, list) and resources and isinstance(resources[0], dict) else None,
        )
        scope = " ".join(
            value for value in (_normal_form(action), _normal_form(product)) if value
        )
        category = _cloudflare_category(scope, action_type)
        actor = record.get("actor")
        raw = record.get("raw")
        timestamp = _first_value(
            _value_at(action_value, "time"), record.get("timestamp"), record.get("when")
        )
        source_ip = _first_value(
            record.get("ip"), _value_at(actor, "ip_address"), _value_at(actor, "ip")
        )
        status = _first_value(_value_at(raw, "status_code"), _value_at(action_value, "result"))
        return action, category, timestamp, source_ip, actor, product, _error_kind(status)

    if provider == "render":
        native_event = record.get("event")
        if isinstance(native_event, dict):
            record = native_event
            action = _first_value(record.get("type"), record.get("eventType"), record.get("event"))
        else:
            action = _first_value(native_event, record.get("type"))
        normalized_action = _normal_form(action)
        category = _render_category(normalized_action)
        metadata = record.get("metadata")
        source_ip = _value_at(metadata, "source_ip")
        resource_type = "service" if _value_at(metadata, "service") else None
        return (
            action,
            category,
            record.get("timestamp"),
            source_ip,
            record.get("actor"),
            resource_type,
            _error_kind(record.get("status")),
        )

    # Railway's public documentation exposes eventType, createdAt, payload and
    # context.  It intentionally delegates the changing event-type catalog to its
    # API, so the classifier uses scoped words from the supplied event type instead
    # of claiming a fixed exhaustive enum.
    action = _first_value(record.get("eventType"), record.get("event"), record.get("action"))
    normalized_action = _normal_form(action)
    category = _railway_category(normalized_action)
    return (
        action,
        category,
        _first_value(record.get("createdAt"), record.get("timestamp")),
        _first_value(record.get("source_ip"), _value_at(record.get("context"), "source_ip")),
        _first_value(record.get("actor"), _value_at(record.get("context"), "actor")),
        _railway_resource_type(normalized_action),
        _error_kind(record.get("status"), record.get("error"), record.get("statusCode")),
    )


def _cloudflare_action(value: Any) -> str:
    if isinstance(value, dict):
        action_type = _safe_action(value.get("type"))
        description = _safe_action(value.get("description"))
        if description != "unknown_action" and action_type != "unknown_action":
            return f"{action_type}: {description}"
        return description if description != "unknown_action" else action_type
    return _safe_action(value)


def _cloudflare_category(scope: str, action_type: str) -> str:
    if action_type not in {"create", "update", "delete", "change"}:
        return "cloud_account_activity"
    # Cloudflare documents create/update/delete as action types and describes the
    # resource/product fields.  This is a scoped keyword match, not a purported
    # exhaustive list of Cloudflare event names.
    if "firewall" in scope or "security" in scope:
        return "security_configuration"
    if "access" in scope:
        return "access_configuration"
    if "token" in scope:
        return "token_management"
    if "member" in scope:
        return "membership"
    if "dns" in scope or "zone" in scope:
        return "dns_configuration"
    return "cloud_account_activity"


def _render_category(action: str) -> str:
    if action in {_normal_form(value) for value in _RENDER_SHELL_EVENTS}:
        return "shell_access"
    if action in {_normal_form(value) for value in _RENDER_SECRET_VIEW_EVENTS}:
        return "secret_access"
    if action in {_normal_form(value) for value in _RENDER_ENV_EVENTS}:
        return "environment_configuration"
    if action in {_normal_form(value) for value in _RENDER_DEPLOYMENT_EVENTS}:
        return "deployment_configuration"
    return "render_workspace_activity"


def _railway_category(action: str) -> str:
    if any(token in action for token in ("permission", "member", "role")):
        return "workspace_permissions"
    if "visibility" in action or "public" in action:
        return "project_visibility"
    if "variable" in action or "environment" in action or "env" in action:
        return "environment_configuration"
    if "deploy" in action:
        return "deployment"
    return "railway_workspace_activity"


def _railway_resource_type(action: str) -> str | None:
    if "workspace" in action or "permission" in action or "member" in action:
        return "workspace"
    if "project" in action or "visibility" in action or "public" in action:
        return "project"
    if "environment" in action or "env" in action or "variable" in action:
        return "environment"
    if "deploy" in action:
        return "deployment"
    return None


def _aws_resource_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    suffix = ".amazonaws.com"
    service = value[:-len(suffix)] if value.endswith(suffix) else value
    return service if re.fullmatch(r"[a-z0-9-]{1,64}", service) else None


def _make_findings(internal: list[dict[str, Any]], is_synthetic: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in internal:
        event = item["event"]
        category = item["category"]
        action = item["action_for_detection"]
        provider = item["provider"]
        finding = _specific_finding(provider, category, action, event, is_synthetic)
        if finding is not None:
            findings.append(finding)
    findings.extend(_error_burst_findings(internal, is_synthetic))
    return findings


def _specific_finding(
    provider: str, category: str, action: str, event: dict[str, Any], is_synthetic: bool
) -> dict[str, Any] | None:
    event_id = event["event_id"]
    if provider == "aws" and category == "logging_configuration":
        return _finding(
            "logging_configuration",
            "medium",
            "A supplied CloudTrail event names a logging configuration action (StopLogging, DeleteTrail, or UpdateTrail).",
            [event_id],
            "Review the trail change, actor authorization, affected trail configuration, and surrounding audit events.",
            is_synthetic,
        )
    if provider == "aws" and category == "authentication":
        return _finding(
            "authentication",
            "medium",
            "A supplied ConsoleLogin event has userIdentity type Root and explicitly reports MFA as not used.",
            [event_id],
            "Review the root-account login context, authentication controls, and approved access records.",
            is_synthetic,
        )
    if provider == "aws" and category == "iam_configuration":
        return _finding(
            "iam_configuration",
            "low",
            "A supplied IAM policy-attachment or access-key creation event needs authorization review.",
            [event_id],
            "Review the requested IAM change and its approval. This rule does not label the change malicious.",
            is_synthetic,
        )
    if provider == "cloudflare" and category in {
        "security_configuration",
        "access_configuration",
        "token_management",
        "membership",
        "dns_configuration",
    }:
        return _finding(
            category,
            "low",
            "A supplied Cloudflare create, update, or delete action is scoped to a security, access, token, membership, or DNS-related resource label.",
            [event_id],
            "Review the change authorization, affected resource, actor context, and related manual audit records.",
            is_synthetic,
        )
    if provider == "render" and category == "shell_access":
        return _finding(
            "shell_access",
            "medium",
            "A supplied Render audit event records service shell access or shell-session completion.",
            [event_id],
            "Review service access authorization, source context when available in the original export, and relevant deployment activity.",
            is_synthetic,
        )
    if provider == "render" and category == "secret_access":
        return _finding(
            "secret_access",
            "medium",
            "A supplied Render audit event records viewing environment-variable values or datastore connection information.",
            [event_id],
            "Review authorized access, rotate exposed values if policy requires it, and retain the original protected export separately.",
            is_synthetic,
        )
    if provider == "render" and category in {"environment_configuration", "deployment_configuration"}:
        return _finding(
            category,
            "low",
            "A supplied Render audit event records an environment or auto-deploy configuration change.",
            [event_id],
            "Review the requested change, its approver, and the service or deployment history in the original export.",
            is_synthetic,
        )
    if provider == "railway" and category in {
        "workspace_permissions",
        "project_visibility",
        "environment_configuration",
        "deployment",
    }:
        return _finding(
            category,
            "low",
            "A supplied Railway event type indicates a workspace permission, project visibility, environment, or deployment-related change.",
            [event_id],
            "Review the original event data, workspace authorization, and related changes in the manual export.",
            is_synthetic,
        )
    return None


def _error_burst_findings(internal: list[dict[str, Any]], is_synthetic: bool) -> list[dict[str, Any]]:
    """Find same-action operational error bursts in ten-minute timestamp buckets."""

    groups: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for item in internal:
        error_kind = item.get("error_kind")
        event = item["event"]
        timestamp = event.get("timestamp_utc")
        if error_kind is None or not isinstance(timestamp, str):
            continue
        parsed = _parse_timestamp(timestamp)
        if parsed is None:
            continue
        bucket = math.floor(parsed.timestamp() / 600)
        key = (item["provider"], item["action_for_detection"], bucket, error_kind)
        groups[key].append(item)

    findings: list[dict[str, Any]] = []
    for (provider, _action, _bucket, error_kind), items in sorted(groups.items()):
        if len(items) < 5:
            continue
        ordered = sorted(items, key=lambda item: item["event"].get("timestamp_utc", ""))
        references = [item["event"]["event_id"] for item in ordered[:MAX_FINDING_REFERENCES]]
        first = ordered[0]["event"].get("timestamp_utc")
        last = ordered[-1]["event"].get("timestamp_utc")
        indicator = (
            f"{len(items)} supplied {provider} records report {error_kind} failures for the same action "
            f"between {first} and {last}. This is operational evidence, not evidence of compromise."
        )
        findings.append(
            _finding(
                "operational_error_burst",
                "low",
                indicator,
                references,
                "Review service health, authentication configuration, rate limits, and the original time-adjacent records.",
                is_synthetic,
                event_count=len(items),
                first_timestamp_utc=first,
                last_timestamp_utc=last,
            )
        )
    return findings


def _finding(
    category: str,
    confidence: str,
    indicator: str,
    event_references: list[str],
    recommended_review: str,
    is_synthetic: bool,
    **extra: Any,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "category": category,
        "confidence": confidence,
        "indicator": indicator,
        "not_proof": "This is an indicator for review, not proof of unauthorized activity or compromise.",
        "event_references": event_references,
        "event_ids": list(event_references),
        "recommended_review": recommended_review,
        "simulation": bool(is_synthetic),
    }
    finding.update(extra)
    return finding


def _text_action(provider: str, raw_line: str) -> tuple[str, str, str | None]:
    folded = _normal_form(raw_line)
    error_kind = _error_kind(raw_line) if re.search(r"(?i)\b(5\d\d|error|fail|denied|unauthorized|auth)\b", raw_line) else None
    if provider == "aws":
        for action in ("StopLogging", "DeleteTrail", "UpdateTrail", "CreateAccessKey"):
            if _normal_form(action) in folded:
                return action, "logging_configuration" if action != "CreateAccessKey" else "iam_configuration", error_kind
        if "attach" in folded and "policy" in folded:
            return "AttachPolicy", "iam_configuration", error_kind
    elif provider == "cloudflare":
        for word, category in (
            ("firewall", "security_configuration"),
            ("security", "security_configuration"),
            ("access", "access_configuration"),
            ("token", "token_management"),
            ("member", "membership"),
            ("dns", "dns_configuration"),
        ):
            if word in folded and any(verb in folded for verb in ("create", "update", "delete", "change")):
                return f"cloudflare_{word}_change", category, error_kind
    elif provider == "render":
        for known, category in (
            ("StartShellEvent", "shell_access"),
            ("ViewEnvVarValuesEvent", "secret_access"),
            ("ViewConnectionInfoEvent", "secret_access"),
            ("UpdateEnvVarsEvent", "environment_configuration"),
            ("UpdateAutoDeployEvent", "deployment_configuration"),
        ):
            if _normal_form(known) in folded:
                return known, category, error_kind
    else:
        category = _railway_category(folded)
        if category != "railway_workspace_activity":
            return f"railway_{category}", category, error_kind
    return "unstructured_runtime_message", "operational_error" if error_kind else "unstructured_runtime_message", error_kind


def _extract_text_timestamp(raw_line: str) -> str | None:
    match = re.search(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b", raw_line)
    return match.group(0) if match else None


def _add_timestamp(event: dict[str, Any], value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    candidate = value.strip()[:128]
    parsed = _parse_timestamp(candidate)
    if parsed is not None:
        event["timestamp_utc"] = parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    else:
        event["timestamp_original"] = _safe_timestamp_original(candidate)


def _parse_timestamp(value: str) -> datetime | None:
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed.tzinfo is not None else None


def _safe_timestamp_original(value: str) -> str:
    return _redact(value)[:128]


def _safe_action(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown_action"
    compact = _CONTROL_CHARS.sub(" ", value).strip()
    if not compact:
        return "unknown_action"
    return _redact(compact)[:MAX_ACTION_LENGTH]


def _safe_resource_type(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown_resource"
    compact = _CONTROL_CHARS.sub(" ", value).strip().lower()
    if not compact:
        return "unknown_resource"
    # A resource type is a label, never a resource name, ID, URI, or env value.
    if not re.fullmatch(r"[a-z0-9_. -]{1,80}", compact):
        return "unknown_resource"
    return compact


def _safe_ip(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _safe_excerpt(value: str) -> str:
    compact = _CONTROL_CHARS.sub(" ", value).strip()
    redacted = _redact(compact)[:MAX_TEXT_EXCERPT]
    return html.escape(redacted, quote=True)


def _redact(value: str) -> str:
    value = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = _BEARER_VALUE.sub(r"\1[REDACTED]", value)
    return _LONG_TOKEN.sub("[REDACTED]", value)


def _stable_hash(value: Any) -> str:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ValueError("record cannot be safely normalized") from exc
    return sha256(encoded).hexdigest()


def _normal_form(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _action_verb(action: Any) -> str:
    normalized = _normal_form(action)
    for verb in ("create", "update", "delete", "change"):
        if verb in normalized:
            return verb
    return ""


def _is_explicit_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() in {"no", "false"})


def _error_kind(*values: Any) -> str | None:
    text_values = [str(value).lower() for value in values if value is not None]
    if not text_values:
        return None
    combined = " ".join(text_values)
    if re.search(r"\b(401|403|auth|unauthori[sz]ed|accessdenied|forbidden|mfa)\b", combined):
        return "authentication_or_authorization"
    if re.search(r"\b5\d\d\b", combined) or any(value in {"error", "failure", "failed"} for value in text_values):
        return "server_or_operational"
    return None


def _value_at(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None


def _first_value(*values: Any) -> Any:
    return next((value for value in values if value is not None), None)


def _first_string(*values: Any) -> str | None:
    return next((value for value in values if isinstance(value, str) and value), None)


def _count_values(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_RECORDS",
    "analyze_cloud_logs",
]
