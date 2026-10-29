"""Manual, bounded, read-only cloud event collection.

This module has no import-time network activity.  ``collect_cloud`` is called only by
an explicit operator action and it never discovers credentials, accounts, or endpoints.
It intentionally does not create or modify cloud resources.
"""

from __future__ import annotations

import datetime as _datetime
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_FIELD_BYTES = 256 * 1024
MAX_EVENTS = 200
MAX_PAGES = 2
HTTP_TIMEOUT_SECONDS = 15

_CLOUDFLARE_HOST = "api.cloudflare.com"
_RENDER_HOST = "api.render.com"
_RAILWAY_HOST = "backboard.railway.com"

_ACCOUNT_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_AWS_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
# Render documents workspace IDs beginning with tea- or usr-.  These are owner IDs.
_RENDER_OWNER_ID_RE = re.compile(r"^(?:tea|usr)-[a-z0-9]+$", re.IGNORECASE)
_GENERIC_SCOPE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$")
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

# Do not broaden this into a general client: every host, path, and request shape below
# is fixed by the provider-specific collectors.
_RAILWAY_AUDIT_QUERY_PREFIX = """query { auditLogs(workspaceId: """
_RAILWAY_AUDIT_QUERY_SUFFIX = """) { edges { node { id eventType createdAt projectId environmentId payload context } } pageInfo { endCursor hasNextPage hasPreviousPage startCursor } } }"""

_SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "apikey",
    "authorization",
    "credential",
    "privatekey",
    "accesskey",
    "cookie",
    "envvalue",
    "environmentvalue",
)
# These provider event fields can include request bodies, configuration values, or
# values returned by a control-plane action.  They are not needed by the analyzer.
_ALWAYS_DROPPED_KEYS = {
    "requestparameters",
    "responseelements",
    "envvalues",
    "environmentvalues",
    "rawsecretfields",
}


class CloudCollectionError(RuntimeError):
    """A safe-to-display collection failure with no provider response body."""


class MissingCredentialError(CloudCollectionError):
    """The explicit environment credential for the selected provider is absent."""


class UnsupportedProvider(CloudCollectionError):
    """The requested provider has no deliberately supported read-only adapter."""


class ScopeMismatchError(CloudCollectionError):
    """AWS STS identity did not match the caller-supplied account scope."""


class OptionalDependencyError(CloudCollectionError):
    """The requested optional provider SDK is not installed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so credentials are never sent to a redirected host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def collect_cloud(
    provider: str,
    scope_id: str,
    since: str,
    until: str,
    region: str | None = None,
) -> dict[str, Any]:
    """Collect at most two pages of manually requested, read-only cloud events.

    ``scope_id`` is deliberately mandatory; this function never enumerates accounts,
    zones, workspaces, credentials, or configured endpoints.  Credentials are read
    only from the exact environment variables documented for each provider.  Returned
    event objects preserve provider-native fields where safe, but redact secret-bearing
    and oversized fields before they leave this module.

    The result is a bounded sample, never a statement that an account is clear.
    """

    if not isinstance(provider, str):
        raise UnsupportedProvider("provider is not supported; use cloudflare, aws, render, or railway")
    normalized_provider = provider.strip().lower()
    if normalized_provider not in {"cloudflare", "aws", "render", "railway"}:
        # Validate this before any credential lookup or network operation.
        raise UnsupportedProvider(
            "provider is not supported; export logs manually for an unsupported provider"
        )

    _validate_scope_id(scope_id)
    start, end = _validate_time_window(since, until)

    try:
        if normalized_provider == "cloudflare":
            _validate_cloudflare_scope(scope_id)
            return _collect_cloudflare(scope_id, since, until)
        if normalized_provider == "aws":
            _validate_aws_scope(scope_id)
            return _collect_aws(scope_id, start, end, region)
        if normalized_provider == "render":
            _validate_render_scope(scope_id)
            return _collect_render(scope_id, since, until)
        return _collect_railway(scope_id, start, end, since, until)
    except (MissingCredentialError, OptionalDependencyError, ScopeMismatchError):
        # These conditions are actionable and are already message-safe.
        raise
    except CloudCollectionError as exc:
        # Provider error bodies and transport exception strings are intentionally not
        # retained: they can echo request data or authorization material.
        return _empty_result(normalized_provider, since, until, warnings=[str(exc)])


def _validate_scope_id(scope_id: str) -> None:
    if not isinstance(scope_id, str) or not _GENERIC_SCOPE_ID_RE.fullmatch(scope_id):
        raise ValueError("scope_id must be a non-empty, safe provider account or workspace ID")


def _validate_cloudflare_scope(scope_id: str) -> None:
    if not _ACCOUNT_ID_RE.fullmatch(scope_id):
        raise ValueError("Cloudflare scope_id must be a 32-character hexadecimal account ID")


def _validate_aws_scope(scope_id: str) -> None:
    if not _AWS_ACCOUNT_ID_RE.fullmatch(scope_id):
        raise ValueError("AWS scope_id must be the expected 12-digit AWS account ID")


def _validate_render_scope(scope_id: str) -> None:
    if not _RENDER_OWNER_ID_RE.fullmatch(scope_id):
        raise ValueError("Render scope_id must be a documented tea- or usr- workspace owner ID")


def _validate_time_window(since: str, until: str) -> tuple[_datetime.datetime, _datetime.datetime]:
    start = _parse_utc_timestamp(since, "since")
    end = _parse_utc_timestamp(until, "until")
    if start >= end:
        raise ValueError("since must be earlier than until")
    if end - start > _datetime.timedelta(days=7):
        raise ValueError("cloud collection time window must not exceed 7 days")
    return start, end


def _parse_utc_timestamp(value: str, name: str) -> _datetime.datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        return _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid ISO-8601 UTC timestamp") from None


def _collect_cloudflare(scope_id: str, since: str, until: str) -> dict[str, Any]:
    token = _required_env("CLOUDFLARE_API_TOKEN")
    events: list[Any] = []
    warnings: list[str] = []
    cursor: str | None = None
    pages_fetched = 0
    truncated = False

    for page_index in range(MAX_PAGES):
        query = {"since": since, "before": until, "direction": "asc", "limit": "100"}
        if cursor:
            query["cursor"] = cursor
        url = _fixed_url(
            _CLOUDFLARE_HOST,
            f"/client/v4/accounts/{scope_id}/logs/audit",
            query,
        )
        payload = _request_json(url, {"Authorization": f"Bearer {token}"}, method="GET")
        pages_fetched += 1
        if not isinstance(payload, Mapping) or payload.get("success") is False:
            raise CloudCollectionError("Cloudflare did not return a successful audit-log response")
        native_events = payload.get("result", [])
        if not isinstance(native_events, list):
            raise CloudCollectionError("Cloudflare returned an invalid audit-log response")
        remaining = MAX_EVENTS - len(events)
        events.extend(native_events[:remaining])
        result_info = payload.get("result_info")
        next_cursor = result_info.get("cursor") if isinstance(result_info, Mapping) else None
        if len(native_events) > remaining:
            truncated = True
            break
        if not isinstance(next_cursor, str) or not next_cursor:
            break
        if page_index + 1 >= MAX_PAGES:
            truncated = True
            break
        cursor = next_cursor

    return _result(
        "cloudflare",
        since,
        until,
        events,
        pages_fetched,
        truncated,
        warnings,
        extra_coverage={"endpoint": "account_audit_logs_v2", "scope_kind": "account"},
    )


def _collect_aws(
    scope_id: str,
    start: _datetime.datetime,
    end: _datetime.datetime,
    region: str | None,
) -> dict[str, Any]:
    access_key = _required_env("AWS_ACCESS_KEY_ID")
    secret_key = _required_env("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN") or None
    selected_region = region or "us-east-1"
    if not _AWS_REGION_RE.fullmatch(selected_region):
        raise ValueError("AWS region must be a conventional AWS region name")

    try:
        # boto3 is optional and is never imported unless AWS was selected explicitly.
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise OptionalDependencyError(
            "AWS collection requires optional boto3; install it manually before selecting aws"
        ) from None

    # Supplying every credential directly disables boto3's implicit environment,
    # shared-file, container, and instance-metadata credential discovery paths.
    session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=selected_region,
    )
    # Explicit internal endpoints override SDK environment/profile endpoint URLs.
    # The validated region cannot introduce a host delimiter or external domain.
    aws_suffix = "amazonaws.com.cn" if selected_region.startswith("cn-") else "amazonaws.com"
    try:
        sts_client = session.client("sts", region_name=selected_region,
                                    endpoint_url=f"https://sts.{selected_region}.{aws_suffix}")
        identity = sts_client.get_caller_identity()
    except Exception as exc:  # SDK exceptions can include provider diagnostics.
        raise CloudCollectionError("AWS STS identity check failed") from None
    if not isinstance(identity, Mapping) or identity.get("Account") != scope_id:
        raise ScopeMismatchError("AWS STS account did not match the requested account scope")

    try:
        cloudtrail_client = session.client("cloudtrail", region_name=selected_region,
                                           endpoint_url=f"https://cloudtrail.{selected_region}.{aws_suffix}")
        events: list[Any] = []
        warnings: list[str] = []
        next_token: str | None = None
        pages_fetched = 0
        truncated = False
        for page_index in range(MAX_PAGES):
            params: dict[str, Any] = {
                "StartTime": start,
                "EndTime": end,
                # CloudTrail itself caps a page at 50; using 50 stays within our
                # universal 200-event ceiling without asking for a broader response.
                "MaxResults": 50,
            }
            if next_token:
                params["NextToken"] = next_token
            response = cloudtrail_client.lookup_events(**params)
            _ensure_bounded_sdk_response(response)
            pages_fetched += 1
            native_events = response.get("Events", []) if isinstance(response, Mapping) else []
            if not isinstance(native_events, list):
                raise CloudCollectionError("AWS CloudTrail returned an invalid event response")
            remaining = MAX_EVENTS - len(events)
            events.extend(_parse_cloudtrail_event(event) for event in native_events[:remaining])
            candidate = response.get("NextToken") if isinstance(response, Mapping) else None
            if len(native_events) > remaining:
                truncated = True
                break
            if not isinstance(candidate, str) or not candidate:
                break
            if page_index + 1 >= MAX_PAGES:
                truncated = True
                break
            next_token = candidate
    except CloudCollectionError:
        raise
    except Exception as exc:  # Never expose a provider exception or request data.
        raise CloudCollectionError("AWS CloudTrail lookup failed") from None

    if region is None:
        warnings.append("AWS region was not supplied; the fixed region us-east-1 was used.")
    return _result(
        "aws",
        start.isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
        events,
        pages_fetched,
        truncated,
        warnings,
        extra_coverage={"region": selected_region, "endpoint": "CloudTrailLookupEvents", "scope_kind": "account"},
    )


def _parse_cloudtrail_event(event: Any) -> Any:
    if not isinstance(event, Mapping):
        return {"_parse_error": "CloudTrail returned a non-object event"}
    parsed = dict(event)
    raw = parsed.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            parsed["CloudTrailEvent"] = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            # Do not return malformed raw text because it can contain sensitive data.
            parsed["CloudTrailEvent"] = {"_parse_error": "CloudTrailEvent was not valid JSON"}
    elif raw is not None and not isinstance(raw, (dict, list)):
        parsed["CloudTrailEvent"] = {"_parse_error": "CloudTrailEvent had an unsupported format"}
    return parsed


def _collect_render(scope_id: str, since: str, until: str) -> dict[str, Any]:
    token = _required_env("RENDER_API_KEY")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    warnings: list[str] = []

    # The explicit owner filter prevents the API's documented unfiltered default,
    # which would return every service visible to the token.
    services_url = _fixed_url(
        _RENDER_HOST,
        "/v1/services",
        {"ownerId": scope_id, "limit": "100", "includePreviews": "false"},
    )
    service_page = _request_json(services_url, headers, method="GET")
    if not isinstance(service_page, list):
        raise CloudCollectionError("Render returned an invalid service-list response")

    service_ids: list[str] = []
    for wrapped_service in service_page:
        service = wrapped_service.get("service") if isinstance(wrapped_service, Mapping) else None
        if isinstance(service, Mapping) and isinstance(service.get("id"), str):
            service_ids.append(service["id"])
    # At most two service-event pages are requested.  This avoids unbounded fan-out
    # over a large workspace while staying under the 200-event collection ceiling.
    selected_service_ids = service_ids[:MAX_PAGES]
    truncated = len(service_ids) > len(selected_service_ids) or len(service_page) >= 100
    if len(service_ids) > len(selected_service_ids):
        warnings.append("Render workspace has additional services outside this bounded sample.")
    if not service_ids:
        warnings.append("Render returned no inspectable service IDs for the requested owner.")

    events: list[Any] = []
    pages_fetched = 0
    for service_id in selected_service_ids:
        event_url = _fixed_url(
            _RENDER_HOST,
            f"/v1/services/{urllib.parse.quote(service_id, safe='')}/events",
            {"startTime": since, "endTime": until, "limit": "100"},
        )
        page = _request_json(event_url, headers, method="GET")
        pages_fetched += 1
        if not isinstance(page, list):
            raise CloudCollectionError("Render returned an invalid service-event response")
        remaining = MAX_EVENTS - len(events)
        # Preserve Render's cursor wrapper; it is useful native context for a later
        # analyzer, but the event object itself is redacted before return.
        events.extend(page[:remaining])
        if len(page) > remaining or len(page) >= 100:
            truncated = True
        if len(events) >= MAX_EVENTS:
            truncated = True
            break

    return _result(
        "render",
        since,
        until,
        events,
        pages_fetched,
        truncated,
        warnings,
        extra_coverage={
            "endpoint": "services_then_service_events",
            "scope_kind": "workspace_owner",
            "services_listed": len(service_ids),
            "services_sampled": len(selected_service_ids),
        },
    )


def _collect_railway(
    scope_id: str,
    start: _datetime.datetime,
    end: _datetime.datetime,
    since: str,
    until: str,
) -> dict[str, Any]:
    token = _required_env("RAILWAY_API_TOKEN")
    # Railway's documented auditLogs query is a GraphQL query (not a mutation). The
    # safe scope grammar makes this JSON string a valid literal without introducing a
    # caller-controlled field, operation, endpoint, or mutation.
    query = _RAILWAY_AUDIT_QUERY_PREFIX + json.dumps(scope_id) + _RAILWAY_AUDIT_QUERY_SUFFIX
    payload = _request_json(
        _fixed_url(_RAILWAY_HOST, "/graphql/v2"),
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
        body=json.dumps({"query": query}, separators=(",", ":")).encode("utf-8"),
    )
    if not isinstance(payload, Mapping) or payload.get("errors"):
        raise CloudCollectionError("Railway GraphQL audit-log query failed")
    data = payload.get("data")
    connection = data.get("auditLogs") if isinstance(data, Mapping) else None
    if not isinstance(connection, Mapping):
        raise CloudCollectionError("Railway returned an invalid audit-log response")
    raw_edges = connection.get("edges", [])
    if not isinstance(raw_edges, list):
        raise CloudCollectionError("Railway returned invalid audit-log edges")

    events: list[Any] = []
    timestamp_unavailable = False
    for edge in raw_edges:
        node = edge.get("node") if isinstance(edge, Mapping) else None
        if not isinstance(node, Mapping):
            continue
        created_at = node.get("createdAt")
        if not isinstance(created_at, str):
            timestamp_unavailable = True
            continue
        try:
            event_time = _parse_utc_timestamp(_normalise_railway_timestamp(created_at), "createdAt")
        except ValueError:
            timestamp_unavailable = True
            continue
        if start <= event_time <= end:
            events.append(node)
            if len(events) >= MAX_EVENTS:
                break

    page_info = connection.get("pageInfo")
    has_next = isinstance(page_info, Mapping) and page_info.get("hasNextPage") is True
    warnings = [
        "Railway's published auditLogs example has no documented time or page arguments; timestamps were filtered locally from one returned page.",
        "For a complete period, export audit logs manually from Railway or use its documented retention/export workflow.",
    ]
    if timestamp_unavailable:
        warnings.append("Some Railway audit-log entries lacked a usable UTC createdAt timestamp and were excluded.")
    return _result(
        "railway",
        since,
        until,
        events,
        1,
        has_next or len(raw_edges) > MAX_EVENTS,
        warnings,
        extra_coverage={
            "endpoint": "documented_auditLogs_query",
            "scope_kind": "workspace",
            "server_side_time_filter": False,
        },
    )


def _normalise_railway_timestamp(value: str) -> str:
    """Accept a Railway RFC3339 UTC timestamp only; normalize +00:00 to Z."""

    if value.endswith("+00:00"):
        return value[:-6] + "Z"
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise MissingCredentialError(f"{name} must be set for this manual collection")
    return value


def _fixed_url(host: str, path: str, query: Mapping[str, str] | None = None) -> str:
    """Build a URL only for one of the module's fixed trusted HTTPS hosts."""

    if host not in {_CLOUDFLARE_HOST, _RENDER_HOST, _RAILWAY_HOST}:
        raise CloudCollectionError("untrusted provider endpoint was rejected")
    encoded_query = urllib.parse.urlencode(query or {}, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit(("https", host, path, encoded_query, ""))


def _request_json(
    url: str,
    headers: Mapping[str, str],
    *,
    method: str,
    body: bytes | None = None,
) -> Any:
    """Issue a fixed-host GET, or Railway's documented read-only GraphQL POST.

    No redirect is followed.  Error bodies are not read, logged, or returned.
    """

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        _CLOUDFLARE_HOST,
        _RENDER_HOST,
        _RAILWAY_HOST,
    } or parsed.port is not None or parsed.username or parsed.password:
        raise CloudCollectionError("untrusted provider endpoint was rejected")
    if method not in {"GET", "POST"}:
        raise CloudCollectionError("non-read-only HTTP method was rejected")
    if method == "POST" and parsed.hostname != _RAILWAY_HOST:
        raise CloudCollectionError("only Railway's documented read-only GraphQL query may use POST")
    if method == "GET" and body is not None:
        raise CloudCollectionError("GET request body was rejected")

    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise CloudCollectionError(f"cloud HTTP request failed with status {exc.code}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise CloudCollectionError("cloud HTTP request failed") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CloudCollectionError("cloud response exceeded the 8 MiB safety limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CloudCollectionError("cloud response was not valid JSON") from None


def _ensure_bounded_sdk_response(response: Any) -> None:
    """Apply the 8 MiB bound to boto3's already-decoded response object.

    boto3 does not expose a stdlib-style bounded ``read`` hook for this operation.
    This guard rejects an oversized decoded result before its event payload is parsed,
    retained, or returned. It deliberately does not include serialization errors or
    content in the raised message.
    """

    try:
        encoded = json.dumps(response, default=str, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise CloudCollectionError("AWS CloudTrail response could not be safely bounded") from None
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise CloudCollectionError("AWS CloudTrail response exceeded the 8 MiB safety limit")


def _empty_result(provider: str, since: str, until: str, *, warnings: list[str]) -> dict[str, Any]:
    return _result(provider, since, until, [], 0, True, warnings)


def _result(
    provider: str,
    since: str,
    until: str,
    events: list[Any],
    pages_fetched: int,
    truncated: bool,
    warnings: list[str],
    *,
    extra_coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    coverage: dict[str, Any] = {
        "requested_since": since,
        "requested_until": until,
        "pages_fetched": pages_fetched,
        "maximum_pages": MAX_PAGES,
        "maximum_events": MAX_EVENTS,
        "events_returned": len(events),
        "truncated": bool(truncated),
        "assessment": "bounded_sample_not_an_all_clear",
    }
    if extra_coverage:
        coverage.update(extra_coverage)
    return {
        "provider": provider,
        "source": "manual_read_only_cloud_api",
        "events": [_sanitize_event(event) for event in events[:MAX_EVENTS]],
        "coverage": coverage,
        "warnings": list(warnings)
        + [
            "Cloud collection is manually invoked, bounded, and incomplete; empty results are not an all-clear assessment."
        ],
    }


def _sanitize_event(value: Any, depth: int = 0) -> Any:
    """Remove secret-bearing fields and bound field size/depth before output."""

    if depth > 32:
        return "[omitted: maximum nesting depth]"
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                continue
            cleaned[key_text] = _sanitize_event(child, depth + 1)
        return cleaned
    if isinstance(value, list):
        # Response and event-count limits already bound total data.  This guard also
        # avoids retaining a single pathological nested collection.
        return [_sanitize_event(item, depth + 1) for item in value[:MAX_EVENTS]]
    if isinstance(value, tuple):
        return [_sanitize_event(item, depth + 1) for item in value[:MAX_EVENTS]]
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="replace")) > MAX_FIELD_BYTES:
            return "[omitted: oversized field]"
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "[omitted: binary field]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if len(text.encode("utf-8", errors="replace")) > MAX_FIELD_BYTES:
        return "[omitted: oversized field]"
    return text


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in _ALWAYS_DROPPED_KEYS or any(
        sensitive in normalized for sensitive in _SENSITIVE_KEY_PARTS
    )
