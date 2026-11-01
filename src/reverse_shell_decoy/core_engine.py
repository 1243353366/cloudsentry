"""Validated shared LDAE event contract and explicit authorization policy.

This module is a data/decision foundation only. It does not collect host data,
modify the host, or claim durable/tamper-proof evidence by itself.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import enum
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import threading
import math
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class AuthStatus(str, enum.Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, enum.Enum):
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    HYPOTHESIZED = "HYPOTHESIZED"
    UNKNOWN = "UNKNOWN"


class PlatformType(str, enum.Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    OTHER = "other"


class PolicyMode(str, enum.Enum):
    PORT_ONLY = "PORT_ONLY"
    EXECUTABLE_PATH_ONLY = "EXECUTABLE_PATH_ONLY"
    # Compatibility alias; serialized decisions use the explicit path-only name.
    EXECUTABLE = "EXECUTABLE_PATH_ONLY"
    EXECUTABLE_AND_HASH = "EXECUTABLE_AND_HASH"


class Exposure(str, enum.Enum):
    LOOPBACK = "LOOPBACK"
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"
    WILDCARD = "WILDCARD"
    LINK_LOCAL = "LINK_LOCAL"
    UNKNOWN = "UNKNOWN"


class IdentityAssurance(str, enum.Enum):
    STRONG = "STRONG"
    PARTIAL = "PARTIAL"
    WEAK = "WEAK"
    UNKNOWN = "UNKNOWN"


class EvidenceError(Exception):
    """Base error for evidence write or verification failures."""


class EvidenceWriteError(EvidenceError):
    """An evidence event was not durably accepted."""


class EvidenceIntegrityError(EvidenceError):
    """Stored evidence is malformed, incomplete, or fails integrity checks."""


class EventValidationError(ValueError):
    pass


class PolicyConfigurationError(ValueError):
    pass


MAX_TEXT = 512
MAX_JOURNAL_LINE_BYTES = 1024 * 1024
MAX_CHECKPOINT_BYTES = 64 * 1024
MAX_DETAILS_BYTES = 64 * 1024
MAX_DETAILS_DEPTH = 8
MAX_DETAIL_ITEMS = 2048
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _strict_text(value: Any, name: str, *, maximum: int = MAX_TEXT, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value.strip()) or len(value) > maximum:
        raise EventValidationError(f"{name} must be a string of 1..{maximum} characters")
    if "\x00" in value:
        raise EventValidationError(f"{name} must not contain NUL")
    return value


def _freeze_json(value: Any, depth: int = 0, count: Optional[List[int]] = None) -> Any:
    if count is None:
        count = [0]
    if depth > MAX_DETAILS_DEPTH:
        raise EventValidationError("details nesting exceeds maximum depth")
    count[0] += 1
    if count[0] > MAX_DETAIL_ITEMS:
        raise EventValidationError("details contains too many values")
    if value is None or type(value) in (str, bool, int):
        if type(value) is str and len(value) > MAX_TEXT:
            raise EventValidationError("details string exceeds maximum length")
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise EventValidationError("details numbers must be finite")
        return value
    if type(value) is list or type(value) is tuple:
        return tuple(_freeze_json(item, depth + 1, count) for item in value)
    if type(value) is dict:
        frozen = {}
        for key, item in value.items():
            _strict_text(key, "details key", maximum=MAX_TEXT)
            frozen[key] = _freeze_json(item, depth + 1, count)
        return MappingProxyType(frozen)
    raise EventValidationError(f"details contains unsupported type: {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _validate_details(value: Any) -> Mapping[str, Any]:
    if type(value) is not dict and not isinstance(value, MappingProxyType):
        raise EventValidationError("details must be a mapping")
    frozen = _freeze_json(_thaw_json(value))
    encoded = json.dumps(_thaw_json(frozen), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_DETAILS_BYTES:
        raise EventValidationError("details exceeds serialized size limit")
    return frozen


def _timezone_id() -> str:
    configured = os.environ.get("TZ")
    if configured:
        return configured.lstrip(":")
    # Linux commonly exposes the IANA zone through this file or symlink.
    for candidate in ("/etc/timezone", "/etc/localtime"):
        try:
            path = Path(candidate)
            if candidate.endswith("timezone"):
                name = path.read_text(encoding="utf-8").strip()
                if name:
                    ZoneInfo(name)
                    return name
            resolved = str(path.resolve())
            marker = "/zoneinfo/"
            if marker in resolved:
                name = resolved.split(marker, 1)[1]
                ZoneInfo(name)
                return name
        except (OSError, ZoneInfoNotFoundError):
            pass
    system_zone = dt.datetime.now().astimezone().tzname() or "unknown"
    return "system:" + system_zone


def _parse_iso(value: str, field_name: str) -> dt.datetime:
    _strict_text(value, field_name, maximum=64)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventValidationError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventValidationError(f"{field_name} must include a timezone offset")
    return parsed


@dataclass(frozen=True)
class ProcessIdentity:
    pid: Optional[int]
    ppid: Optional[int]
    executable: Optional[str]
    executable_sha256: Optional[str]
    user: Optional[str]
    created_time_utc: Optional[str]
    privilege_level: str = "unknown"
    authenticode_verified: Optional[bool] = None
    container_id: Optional[str] = None
    os_file_identity: Optional[str] = None
    hash_subject: Optional[str] = None  # path_file, running_image, or unknown
    hash_provenance: Optional[str] = None

    def __post_init__(self) -> None:
        if self.pid is not None and (type(self.pid) is not int or self.pid < 0):
            raise EventValidationError("pid must be a non-negative integer or None")
        if self.ppid is not None and (type(self.ppid) is not int or self.ppid < 0):
            raise EventValidationError("ppid must be a non-negative integer or None")
        for name in ("executable", "user", "container_id", "os_file_identity"):
            value = getattr(self, name)
            if value is not None:
                _strict_text(value, name)
        if self.executable_sha256 is not None and (type(self.executable_sha256) is not str or not _SHA256_RE.fullmatch(self.executable_sha256)):
            raise EventValidationError("executable_sha256 must be 64 hexadecimal characters")
        if self.created_time_utc is not None:
            parsed = _parse_iso(self.created_time_utc, "created_time_utc")
            if parsed.utcoffset() != dt.timedelta(0):
                raise EventValidationError("created_time_utc must be UTC")
        if self.hash_subject not in (None, "path_file", "running_image", "unknown"):
            raise EventValidationError("invalid hash_subject")
        if self.hash_subject == "running_image" and (self.executable_sha256 is None or self.hash_provenance is None):
            raise EventValidationError("running-image hash requires digest and collection provenance")
        if self.hash_provenance is not None:
            _strict_text(self.hash_provenance, "hash_provenance", maximum=256)
        if self.hash_subject != "running_image" and self.hash_provenance is not None:
            raise EventValidationError("hash provenance is only valid for a running-image hash")
        _strict_text(self.privilege_level, "privilege_level", maximum=64)
        if self.authenticode_verified is not None and type(self.authenticode_verified) is not bool:
            raise EventValidationError("authenticode_verified must be bool or None")

    @property
    def identity_key(self) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """PID plus creation time and OS file identity distinguishes reuse/replacement."""
        return (self.pid, self.created_time_utc, self.os_file_identity)

    @property
    def identity_assurance(self) -> IdentityAssurance:
        if self.pid is None:
            return IdentityAssurance.UNKNOWN
        present = int(self.created_time_utc is not None) + int(self.os_file_identity is not None)
        return IdentityAssurance.STRONG if present == 2 else IdentityAssurance.PARTIAL if present == 1 else IdentityAssurance.WEAK

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classify_exposure(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Exposure:
    if address.is_unspecified:
        return Exposure.WILDCARD
    if address.is_loopback:
        return Exposure.LOOPBACK
    if address.is_link_local:
        return Exposure.LINK_LOCAL
    if address.is_private:
        return Exposure.PRIVATE
    if address.is_global:
        return Exposure.PUBLIC
    return Exposure.UNKNOWN


@dataclass(frozen=True)
class ListenerIdentity:
    protocol: str
    local_address: str
    local_port: int
    process: Optional[ProcessIdentity]
    first_observed_utc: str
    last_observed_utc: str
    duration_seconds: float
    listening_state: str
    associated_connections: int = 0
    raw_payload: Mapping[str, Any] = field(default_factory=dict)
    interface_identity: Optional[str] = None
    exposure: Optional[Exposure] = None
    network_namespace_id: Optional[str] = None

    def __post_init__(self) -> None:
        if type(self.protocol) is not str or self.protocol.upper() not in {"TCP", "UDP"}:
            raise EventValidationError("protocol must be TCP or UDP")
        object.__setattr__(self, "protocol", self.protocol.upper())
        _strict_text(self.local_address, "local_address", maximum=128)
        try:
            parsed_address = ipaddress.ip_address(self.local_address.split("%", 1)[0])
        except ValueError as exc:
            raise EventValidationError("local_address must be an IP address") from exc
        object.__setattr__(self, "local_address", str(parsed_address))
        if self.interface_identity is not None:
            _strict_text(self.interface_identity, "interface_identity", maximum=128)
        if self.network_namespace_id is not None:
            _strict_text(self.network_namespace_id, "network_namespace_id", maximum=128)
        expected_exposure = classify_exposure(parsed_address)
        if self.exposure is not None and self.exposure is not expected_exposure:
            raise EventValidationError("exposure does not match local_address")
        object.__setattr__(self, "exposure", expected_exposure)
        if type(self.local_port) is not int or not 0 <= self.local_port <= 65535:
            raise EventValidationError("local_port must be in 0..65535")
        first = _parse_iso(self.first_observed_utc, "first_observed_utc")
        last = _parse_iso(self.last_observed_utc, "last_observed_utc")
        if last < first:
            raise EventValidationError("last_observed_utc must not precede first_observed_utc")
        if type(self.duration_seconds) not in (int, float) or not math.isfinite(self.duration_seconds) or self.duration_seconds < 0:
            raise EventValidationError("duration_seconds must be finite and non-negative")
        if type(self.associated_connections) is not int or self.associated_connections < 0:
            raise EventValidationError("associated_connections must be non-negative")
        _strict_text(self.listening_state, "listening_state", maximum=32)
        object.__setattr__(self, "raw_payload", _validate_details(self.raw_payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol, "local_address": self.local_address,
            "local_port": self.local_port,
            "process": None if self.process is None else self.process.to_dict(),
            "first_observed_utc": self.first_observed_utc,
            "last_observed_utc": self.last_observed_utc,
            "duration_seconds": self.duration_seconds,
            "listening_state": self.listening_state,
            "associated_connections": self.associated_connections,
            "raw_payload": _thaw_json(self.raw_payload),
            "interface_identity": self.interface_identity,
            "exposure": self.exposure.value,
            "network_namespace_id": self.network_namespace_id,
        }


def extract_listener_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Safely detach a listener observation as bounded JSON data only.

    This does not execute, deserialize, or collect anything from the host. It
    preserves every supplied field, rejecting unsupported or oversized values
    instead of silently dropping fields. Callers should include their own
    CloudSentry listener in the inventory if it is in the observed source.
    """
    if not isinstance(payload, Mapping):
        raise EventValidationError("listener payload must be a mapping")
    frozen = _validate_details(dict(payload))
    return _thaw_json(frozen)


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    incident_id: str
    event_type: str
    timestamp_utc: str
    timestamp_local: str
    timezone_id: str
    utc_offset: str
    host_identifier: str
    platform: str
    collection_source: str
    confidence: ConfidenceLevel
    authorization: AuthStatus
    details: Mapping[str, Any] = field(default_factory=dict)
    synthetic_decoy: bool = False
    dde_event_id: Optional[str] = None
    schema_version: int = 1
    source_event_ids: Tuple[str, ...] = ()
    parent_event_ids: Tuple[str, ...] = ()
    raw_observations: Mapping[str, Any] = field(default_factory=dict)
    behavioral_assessment: Mapping[str, Any] = field(default_factory=dict)
    containment_status: str = "NOT_APPLIED"
    attribution_assessment: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("event_id", "incident_id"):
            value = getattr(self, field_name)
            try:
                parsed = uuid.UUID(value)
            except (ValueError, TypeError, AttributeError) as exc:
                raise EventValidationError(f"{field_name} must be a full UUID") from exc
            if str(parsed) != value:
                raise EventValidationError(f"{field_name} must use canonical UUID format")
        for name, maximum in (("event_type", 128), ("timezone_id", 128), ("host_identifier", 128), ("platform", 16), ("collection_source", 128), ("containment_status", 64)):
            _strict_text(getattr(self, name), name, maximum=maximum)
        utc = _parse_iso(self.timestamp_utc, "timestamp_utc")
        local = _parse_iso(self.timestamp_local, "timestamp_local")
        if utc.utcoffset() != dt.timedelta(0):
            raise EventValidationError("timestamp_utc must have zero UTC offset")
        if self.timezone_id.startswith("system:"):
            # Windows and some minimal containers expose an OS timezone label,
            # not an IANA database key. Preserve that label and verify its
            # captured offset; do not pretend it supports historical transitions.
            expected_offset = _format_offset(local.utcoffset())
            if self.utc_offset != expected_offset or local.astimezone(dt.timezone.utc) != utc.astimezone(dt.timezone.utc):
                raise EventValidationError("system-local timestamp is inconsistent with UTC and offset")
        else:
            try:
                zone = ZoneInfo(self.timezone_id)
            except (ZoneInfoNotFoundError, ValueError) as exc:
                raise EventValidationError("timezone_id must be a valid IANA timezone or system: label") from exc
            expected = utc.astimezone(zone)
            if local.isoformat() != expected.isoformat():
                raise EventValidationError("timestamp_local must be derived from timestamp_utc and timezone_id")
        if self.utc_offset != _format_offset(local.utcoffset()):
            raise EventValidationError("utc_offset does not match local timestamp")
        if self.platform not in {p.value for p in PlatformType}:
            raise EventValidationError("invalid platform")
        if not isinstance(self.confidence, ConfidenceLevel) or not isinstance(self.authorization, AuthStatus):
            raise EventValidationError("confidence and authorization must be enum values")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise EventValidationError("unsupported schema_version")
        if type(self.synthetic_decoy) is not bool:
            raise EventValidationError("synthetic_decoy must be bool")
        if self.synthetic_decoy != (self.dde_event_id is not None):
            raise EventValidationError("synthetic events require a DDE event ID and genuine events must not have one")
        if self.dde_event_id is not None:
            _strict_text(self.dde_event_id, "dde_event_id", maximum=128)
        for collection_name in ("source_event_ids", "parent_event_ids"):
            values = getattr(self, collection_name)
            if type(values) not in (tuple, list) or len(values) > 128:
                raise EventValidationError(f"{collection_name} must be a sequence of at most 128 UUIDs")
            for value in values:
                try:
                    if str(uuid.UUID(value)) != value:
                        raise ValueError
                except (ValueError, TypeError, AttributeError) as exc:
                    raise EventValidationError(f"{collection_name} entries must be full UUIDs") from exc
            object.__setattr__(self, collection_name, tuple(values))
        for name in ("details", "raw_observations", "behavioral_assessment", "attribution_assessment"):
            object.__setattr__(self, name, _validate_details(getattr(self, name)))

    @classmethod
    def create(
        cls,
        event_type: str,
        collection_source: str,
        confidence: ConfidenceLevel,
        authorization: AuthStatus,
        details: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
        synthetic_decoy: bool = False,
        dde_event_id: Optional[str] = None,
        host_id: Optional[str] = None,
        timezone_id: Optional[str] = None,
        source_event_ids: Tuple[str, ...] = (),
        parent_event_ids: Tuple[str, ...] = (),
        raw_observations: Optional[Dict[str, Any]] = None,
        behavioral_assessment: Optional[Dict[str, Any]] = None,
        containment_status: str = "NOT_APPLIED",
        attribution_assessment: Optional[Dict[str, Any]] = None,
    ) -> "CanonicalEvent":
        # Capture one instant, then derive the local representation from it.
        now_utc = dt.datetime.now(dt.timezone.utc)
        zone_name = timezone_id or _timezone_id()
        try:
            local = now_utc.astimezone() if zone_name.startswith("system:") else now_utc.astimezone(ZoneInfo(zone_name))
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise EventValidationError("invalid timezone_id") from exc
        sys_plat = platform.system().lower()
        plat = PlatformType.LINUX.value if "linux" in sys_plat else PlatformType.WINDOWS.value if "windows" in sys_plat else PlatformType.OTHER.value
        return cls(
            event_id=str(uuid.uuid4()), incident_id=incident_id or str(uuid.uuid4()),
            event_type=event_type, timestamp_utc=now_utc.isoformat(), timestamp_local=local.isoformat(),
            timezone_id=zone_name, utc_offset=_format_offset(local.utcoffset()),
            host_identifier=host_id or "unknown-host", platform=plat, collection_source=collection_source,
            confidence=confidence, authorization=authorization, details={} if details is None else details,
            synthetic_decoy=synthetic_decoy, dde_event_id=dde_event_id, source_event_ids=source_event_ids,
            parent_event_ids=parent_event_ids, raw_observations={} if raw_observations is None else raw_observations,
            behavioral_assessment={} if behavioral_assessment is None else behavioral_assessment,
            containment_status=containment_status,
            attribution_assessment={} if attribution_assessment is None else attribution_assessment,
        )

    def to_dict(self) -> Dict[str, Any]:
        # Revalidate at the serialization boundary, then return detached mutable data.
        self.__post_init__()
        return {
            "event_id": self.event_id, "incident_id": self.incident_id, "event_type": self.event_type,
            "timestamp_utc": self.timestamp_utc, "timestamp_local": self.timestamp_local,
            "timezone_id": self.timezone_id, "utc_offset": self.utc_offset, "host_identifier": self.host_identifier,
            "platform": self.platform, "collection_source": self.collection_source,
            "confidence": self.confidence.value, "authorization": self.authorization.value,
            "details": _thaw_json(self.details), "synthetic_decoy": self.synthetic_decoy,
            "dde_event_id": self.dde_event_id, "schema_version": self.schema_version,
            "source_event_ids": list(self.source_event_ids), "parent_event_ids": list(self.parent_event_ids),
            "raw_observations": _thaw_json(self.raw_observations),
            "behavioral_assessment": _thaw_json(self.behavioral_assessment),
            "containment_status": self.containment_status,
            "attribution_assessment": _thaw_json(self.attribution_assessment),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _format_offset(offset: Optional[dt.timedelta]) -> str:
    if offset is None:
        raise EventValidationError("timezone offset is required")
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    return f"{sign}{total_minutes // 60:02d}:{total_minutes % 60:02d}"


@dataclass(frozen=True)
class AuthorizationDecision:
    status: AuthStatus
    policy_revision: str
    policy_id: Optional[str]
    policy_mode: Optional[PolicyMode]
    matching_attributes: Mapping[str, Any]
    reason: str


class CoreAuthorizationEngine:
    """Explicit, validated listener policy; no implicit port-only allow rules."""

    def __init__(self, allowed_listeners: Optional[List[Dict[str, Any]]] = None, *, policy_revision: str, allow_port_only: bool = False):
        _strict_text(policy_revision, "policy_revision", maximum=128)
        if type(allow_port_only) is not bool:
            raise PolicyConfigurationError("allow_port_only must be bool")
        self.policy_revision = policy_revision
        self.allow_port_only = allow_port_only
        self._allowed_listeners = self._validate_policies(allowed_listeners or [])
        self._sensitive_ports = {21, 22, 23, 25, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}

    def _validate_policies(self, policies: List[Dict[str, Any]]) -> Tuple[Mapping[str, Any], ...]:
        if type(policies) is not list:
            raise PolicyConfigurationError("allowed_listeners must be a list")
        validated = []
        seen = set()
        seen_ids = set()
        for index, raw in enumerate(policies):
            if type(raw) is not dict:
                raise PolicyConfigurationError(f"policy {index} must be an object")
            try:
                allowed_fields = {"policy_id", "port", "protocol", "mode", "executable", "sha256", "operator_approved", "bind_address", "exposure", "interface_identity", "network_namespace_id"}
                unknown_fields = set(raw) - allowed_fields
                if unknown_fields:
                    raise PolicyConfigurationError("unknown policy fields: " + ", ".join(sorted(unknown_fields)))
                port = raw["port"]
                protocol = raw.get("protocol", "TCP")
                mode = PolicyMode(raw["mode"])
                policy_id = _strict_text(raw.get("policy_id"), "policy_id", maximum=128)
                if type(port) is not int or not 1 <= port <= 65535:
                    raise PolicyConfigurationError("port must be an integer in 1..65535")
                if type(protocol) is not str or protocol.upper() not in ("TCP", "UDP"):
                    raise PolicyConfigurationError("protocol must be TCP or UDP")
                executable = raw.get("executable")
                sha256 = raw.get("sha256")
                operator_approved = raw.get("operator_approved", False)
                if type(operator_approved) is not bool:
                    raise PolicyConfigurationError("operator_approved must be bool")
                if mode is PolicyMode.PORT_ONLY:
                    if not self.allow_port_only or not operator_approved:
                        raise PolicyConfigurationError("PORT_ONLY requires engine opt-in and operator_approved=true")
                    if executable is not None or sha256 is not None:
                        raise PolicyConfigurationError("PORT_ONLY cannot specify executable or sha256")
                elif mode is PolicyMode.EXECUTABLE_PATH_ONLY:
                    _strict_text(executable, "executable")
                    if sha256 is not None:
                        raise PolicyConfigurationError("EXECUTABLE_PATH_ONLY policy cannot specify sha256")
                    if not operator_approved:
                        raise PolicyConfigurationError("EXECUTABLE_PATH_ONLY requires operator_approved=true")
                elif mode is PolicyMode.EXECUTABLE_AND_HASH:
                    _strict_text(executable, "executable")
                    if type(sha256) is not str or not _SHA256_RE.fullmatch(sha256):
                        raise PolicyConfigurationError("EXECUTABLE_AND_HASH requires a SHA-256 digest")
                if policy_id in seen_ids:
                    raise PolicyConfigurationError("duplicate policy_id")
                seen_ids.add(policy_id)
                key = (port, protocol.upper(), mode.value, executable, sha256)
                if key in seen:
                    raise PolicyConfigurationError("duplicate authorization policy")
                seen.add(key)
                bind_address = raw.get("bind_address")
                if bind_address is not None:
                    try:
                        bind_address = str(ipaddress.ip_address(bind_address.split("%", 1)[0]))
                    except (ValueError, AttributeError) as exc:
                        raise PolicyConfigurationError("bind_address must be an IP address") from exc
                exposure = raw.get("exposure")
                if exposure is not None:
                    try:
                        exposure = Exposure(exposure).value
                    except ValueError as exc:
                        raise PolicyConfigurationError("invalid exposure") from exc
                if bind_address is not None and exposure is not None and classify_exposure(ipaddress.ip_address(bind_address)).value != exposure:
                    raise PolicyConfigurationError("exposure does not match bind_address")
                if exposure is None and bind_address is not None:
                    exposure = classify_exposure(ipaddress.ip_address(bind_address)).value
                if exposure is None:
                    raise PolicyConfigurationError("every policy must specify exposure or bind_address")
                interface_identity = raw.get("interface_identity")
                namespace_id = raw.get("network_namespace_id")
                for field_name, field_value in (("interface_identity", interface_identity), ("network_namespace_id", namespace_id)):
                    if field_value is not None:
                        _strict_text(field_value, field_name, maximum=128)
                normalized = {"policy_id": policy_id, "port": port, "protocol": protocol.upper(), "mode": mode.value,
                              "executable": executable, "sha256": sha256, "operator_approved": operator_approved,
                              "bind_address": bind_address, "exposure": exposure,
                              "interface_identity": interface_identity, "network_namespace_id": namespace_id}
                validated.append(MappingProxyType(normalized))
            except EventValidationError as exc:
                raise PolicyConfigurationError(f"policy {index}: {exc}") from exc
            except KeyError as exc:
                raise PolicyConfigurationError(f"policy {index} is missing required field {exc.args[0]}") from exc
            except ValueError as exc:
                if isinstance(exc, PolicyConfigurationError):
                    raise
                raise PolicyConfigurationError(f"policy {index} has invalid mode") from exc
        for i, left in enumerate(validated):
            for right in validated[i + 1:]:
                if (left["port"], left["protocol"]) == (right["port"], right["protocol"]):
                    same_identity = left["executable"] == right["executable"] and left["sha256"] == right["sha256"]
                    same_executable = left["executable"] == right["executable"]
                    either_port_only = PolicyMode.PORT_ONLY.value in (left["mode"], right["mode"])
                    conflicting = either_port_only or (same_executable and (
                        left["mode"] != right["mode"]
                        or (left["mode"] == PolicyMode.EXECUTABLE_AND_HASH.value and left["sha256"] != right["sha256"])
                    ))
                    if conflicting:
                        raise PolicyConfigurationError("conflicting authorization policies for same listener identity")
        return tuple(validated)

    def evaluate_listener(self, port: int, protocol: str, executable: Optional[str] = None,
                          executable_sha256: Optional[str] = None, *, hash_subject: Optional[str] = None,
                          local_address: Optional[str] = None, interface_identity: Optional[str] = None,
                          exposure: Optional[Exposure | str] = None, network_namespace_id: Optional[str] = None,
                          hash_provenance: Optional[str] = None) -> AuthorizationDecision:
        if type(port) is not int or not 1 <= port <= 65535 or type(protocol) is not str or protocol.upper() not in {"TCP", "UDP"}:
            raise ValueError("invalid listener port or protocol")
        if local_address is not None:
            try:
                local_address = str(ipaddress.ip_address(local_address.split("%", 1)[0]))
            except (ValueError, AttributeError) as exc:
                raise ValueError("invalid listener local address") from exc
        observed_exposure = classify_exposure(ipaddress.ip_address(local_address)) if local_address is not None else None
        if exposure is not None:
            exposure = Exposure(exposure)
            if observed_exposure is not None and exposure is not observed_exposure:
                return AuthorizationDecision(AuthStatus.UNKNOWN, self.policy_revision, None, None, MappingProxyType({"scope_mismatch": "exposure/address"}), "exposure does not match observed address")
            observed_exposure = exposure
        for field_name, value in (("interface_identity", interface_identity), ("network_namespace_id", network_namespace_id)):
            if value is not None:
                _strict_text(value, field_name, maximum=128)
        matching = [p for p in self._allowed_listeners if p["port"] == port and p["protocol"] == protocol.upper()]
        if not matching:
            return AuthorizationDecision(AuthStatus.UNKNOWN, self.policy_revision, None, None, MappingProxyType({}), "no matching explicit policy")
        unresolved = False
        mismatches: List[Tuple[Mapping[str, Any], Dict[str, Any]]] = []
        for policy in matching:
            scope_mismatch = any(
                policy[field] is not None and observed != policy[field]
                for field, observed in (("bind_address", local_address), ("exposure", None if observed_exposure is None else observed_exposure.value),
                                        ("interface_identity", interface_identity), ("network_namespace_id", network_namespace_id))
            )
            if scope_mismatch:
                mismatches.append((policy, {"port": port, "protocol": protocol.upper(), "scope_mismatch": True}))
                continue
            scope_missing = any(policy[field] is not None and observed is None for field, observed in (
                ("bind_address", local_address), ("exposure", observed_exposure),
                ("interface_identity", interface_identity), ("network_namespace_id", network_namespace_id)))
            if scope_missing:
                unresolved = True
                continue
            mode = PolicyMode(policy["mode"])
            attrs: Dict[str, Any] = {"port": port, "protocol": protocol.upper(), "mode": mode.value,
                                     "local_address": local_address,
                                     "exposure": None if observed_exposure is None else observed_exposure.value,
                                     "interface_identity": interface_identity,
                                     "network_namespace_id": network_namespace_id}
            if mode is PolicyMode.PORT_ONLY:
                attrs["operator_approved"] = True
                return AuthorizationDecision(AuthStatus.AUTHORIZED, self.policy_revision, policy["policy_id"], mode, MappingProxyType(attrs), "explicit operator-approved port-only policy")
            if executable is None:
                unresolved = True
                continue
            # Path match is a configured attribute, not proof of the loaded image.
            attrs["executable_path_match"] = executable == policy["executable"]
            attrs["path_is_image_identity_proof"] = False
            if executable != policy["executable"]:
                mismatches.append((policy, attrs))
                continue
            if mode is PolicyMode.EXECUTABLE_PATH_ONLY:
                attrs["executable"] = executable
                attrs["verified_binary_identity"] = False
                return AuthorizationDecision(AuthStatus.AUTHORIZED, self.policy_revision, policy["policy_id"], mode, MappingProxyType(attrs), "operator-approved path-only match; loaded image identity is not proven")
            if executable_sha256 is None or hash_subject is None or hash_provenance is None:
                unresolved = True
                continue
            if type(executable_sha256) is not str or not _SHA256_RE.fullmatch(executable_sha256):
                unresolved = True
                continue
            attrs["sha256_match"] = executable_sha256.lower() == policy["sha256"].lower()
            attrs["hash_subject"] = hash_subject
            attrs["hash_provenance"] = hash_provenance
            attrs["hash_proves_loaded_image"] = hash_subject == "running_image"
            if hash_subject != "running_image":
                unresolved = True
                continue
            try:
                attrs["hash_provenance"] = _strict_text(hash_provenance, "hash_provenance", maximum=256)
            except (EventValidationError, TypeError):
                unresolved = True
                continue
            if attrs["sha256_match"]:
                return AuthorizationDecision(AuthStatus.AUTHORIZED, self.policy_revision, policy["policy_id"], mode, MappingProxyType(attrs), "configured path and running-image hash matched")
            mismatches.append((policy, attrs))
        if unresolved:
            return AuthorizationDecision(AuthStatus.UNKNOWN, self.policy_revision, None, None, MappingProxyType({"port": port, "protocol": protocol.upper(), "required_evidence_missing": True}), "required identity evidence unavailable or not tied to running image")
        if mismatches:
            policy, attrs = mismatches[0]
            attrs["policy_id"] = policy["policy_id"]
            return AuthorizationDecision(AuthStatus.UNAUTHORIZED, self.policy_revision, policy["policy_id"], PolicyMode(policy["mode"]), MappingProxyType(attrs), "observed identity did not match explicit policy")
        return AuthorizationDecision(AuthStatus.UNKNOWN, self.policy_revision, None, None, MappingProxyType({"port": port, "protocol": protocol.upper()}), "policy could not be evaluated")

    def is_sensitive_port(self, port: int) -> bool:
        return port in self._sensitive_ports


class JsonEventLogger:
    """Structured application logger; not a durable evidence recorder."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("cloudsentry.events")

    def emit(self, event: CanonicalEvent) -> int:
        if not isinstance(event, CanonicalEvent):
            raise TypeError("event must be a CanonicalEvent")
        handlers = []
        current = self.logger
        while current is not None:
            handlers.extend(current.handlers)
            if not current.propagate:
                break
            current = current.parent
        eligible = [handler for handler in handlers if logging.INFO >= handler.level]
        if not eligible:
            raise RuntimeError("no event logger handler configured for INFO; event was not dispatched")
        record = self.logger.makeRecord(self.logger.name, logging.INFO, "", 0, event.to_json(), (), None)
        try:
            self.logger.handle(record)
        except Exception as exc:
            raise RuntimeError("event logger dispatch failed") from exc
        return len(eligible)


@dataclass(frozen=True)
class EvidenceVerification:
    valid: bool
    records: int
    last_sequence: int
    errors: Tuple[str, ...] = ()


class EvidenceRecorder:
    """Bounded append-only JSONL journal with SHA-256 chain verification.

    This is integrity-evident, not tamper-proof. It uses local file permissions,
    fsync, a bounded byte budget, and refuses startup on a damaged journal.
    """

    def __init__(self, path: str, *, max_bytes: int = 10 * 1024 * 1024):
        if type(max_bytes) is not int or max_bytes < 1024:
            raise ValueError("max_bytes must be an integer of at least 1024")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._sequence = 0
        self._previous_digest = "0" * 64
        self._event_ids = set()
        self._lock = threading.Lock()
        self._failed = False
        self._verified_signature: Optional[Tuple[int, int, int]] = None
        self._recover()

    @contextlib.contextmanager
    def _process_lock(self):
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        # The lock path lives in a directory an operator may not control. Opening
        # it with O_NOFOLLOW and 0600 stops a pre-planted symlink from redirecting
        # the lock (and, on some platforms, truncating a foreign file) and keeps
        # the lock from being world-readable.
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise EvidenceError("unable to open evidence lock file") from exc
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(lock_fd, 0o600)
            stream = os.fdopen(lock_fd, "a+b")
        except OSError as exc:
            os.close(lock_fd)
            raise EvidenceError("unable to use evidence lock file") from exc
        try:
            if os.name == "nt":
                import msvcrt
                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()

    def _recover(self) -> None:
        try:
            with self._process_lock():
                self._refresh_state()
        except EvidenceError:
            raise
        except Exception as exc:
            raise EvidenceIntegrityError("unable to recover evidence journal") from exc

    def _journal_signature(self) -> Tuple[int, int, int]:
        """Cheap identity of the journal file, used to skip redundant verification."""
        try:
            stat_result = self.path.stat()
        except OSError:
            return (0, 0, 0)
        return (int(stat_result.st_ino), int(stat_result.st_size), int(stat_result.st_mtime_ns))

    def _refresh_state(self) -> None:
        """Re-read journal state, verifying in full only when the file moved.

        A full re-verification on every append is quadratic in the number of
        records and holds the cross-process lock for the whole read, so it is only
        done when the file's inode, size, or mtime changed since it was last read.
        """
        if self._verified_signature is not None and self._journal_signature() == self._verified_signature:
            return
        self._sequence = 0
        self._previous_digest = "0" * 64
        self._event_ids.clear()
        self._verified_signature = None
        if not self.path.exists():
            self._verified_signature = (0, 0, 0)
            return
        try:
            verification = self.verify_file(self.path)
            if not verification.valid:
                raise EvidenceIntegrityError("existing evidence journal failed verification: " + "; ".join(verification.errors))
            with self.path.open("rb") as stream:
                for raw in stream:
                    record = json.loads(raw)
                    self._event_ids.add(record["event"]["event_id"])
                    self._sequence = record["sequence"]
                    self._previous_digest = record["digest"]
            self._verified_signature = self._journal_signature()
        except EvidenceError:
            raise
        except Exception as exc:
            raise EvidenceIntegrityError("unable to recover evidence journal") from exc

    @staticmethod
    def verify_file(path: str | Path) -> EvidenceVerification:
        previous = "0" * 64
        seq = 0
        ids = set()
        errors = []
        try:
            with Path(path).open("rb") as stream:
                for line_no, raw in enumerate(stream, 1):
                    if len(raw) > MAX_JOURNAL_LINE_BYTES:
                        errors.append(
                            f"line {line_no}: record exceeds {MAX_JOURNAL_LINE_BYTES} bytes"
                        )
                        break
                    if not raw.endswith(b"\n"):
                        errors.append(f"line {line_no}: incomplete record (possible interrupted write)")
                        break
                    try:
                        record = json.loads(raw)
                        event = record["event"]
                        sequence = record["sequence"]
                        prev = record["previous_digest"]
                        digest = record["digest"]
                        if type(sequence) is not int or sequence != seq + 1:
                            raise ValueError("sequence discontinuity")
                        if prev != previous:
                            raise ValueError("previous digest mismatch")
                        if event["event_id"] in ids:
                            raise ValueError("duplicate event ID")
                        unsigned = {"sequence": sequence, "previous_digest": prev, "event": event}
                        calculated = hashlib.sha256(json.dumps(unsigned, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                        if calculated != digest:
                            raise ValueError("record digest mismatch")
                        ids.add(event["event_id"])
                        seq = sequence
                        previous = digest
                    except Exception as exc:
                        errors.append(f"line {line_no}: {exc}")
                        break
        except FileNotFoundError:
            return EvidenceVerification(True, 0, 0)
        except OSError as exc:
            return EvidenceVerification(False, seq, seq, (f"read failure: {exc}",))
        return EvidenceVerification(not errors, seq, seq, tuple(errors))

    @staticmethod
    def write_checkpoint(path: str | Path, *, sequence: int, digest: str, key: bytes, signer_id: str) -> Dict[str, Any]:
        """Write an HMAC-signed anchor; caller must store key and checkpoint separately."""
        if type(sequence) is not int or sequence < 0 or not _SHA256_RE.fullmatch(digest):
            raise EvidenceIntegrityError("invalid checkpoint sequence or digest")
        if not isinstance(key, bytes) or len(key) < 32:
            raise EvidenceIntegrityError("checkpoint key must be at least 32 bytes")
        _strict_text(signer_id, "signer_id", maximum=128)
        body = {"format": "cloudsentry-checkpoint-v1", "sequence": sequence, "digest": digest, "signer_id": signer_id}
        signature = hmac.new(key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        record = {**body, "signature": signature}
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        # O_NOFOLLOW keeps a pre-planted symlink at the temporary path from
        # redirecting the checkpoint write; 0600 keeps the anchor owner-only.
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise EvidenceIntegrityError("unable to open checkpoint temporary file") from exc
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            written = os.write(descriptor, payload)
            if written != len(payload):
                raise EvidenceIntegrityError("short checkpoint write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        return record

    @staticmethod
    def verify_checkpoint(path: str | Path, key: bytes) -> Dict[str, Any]:
        try:
            checkpoint_path = Path(path)
            with checkpoint_path.open("rb") as stream:
                raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
            if len(raw) > MAX_CHECKPOINT_BYTES:
                raise ValueError("checkpoint file exceeds size limit")
            record = json.loads(raw.decode("utf-8"))
            if not isinstance(record, dict):
                raise ValueError("checkpoint must be a JSON object")
            body = {key_name: record[key_name] for key_name in ("format", "sequence", "digest", "signer_id")}
            expected = hmac.new(key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
            if body["format"] != "cloudsentry-checkpoint-v1" or not hmac.compare_digest(expected, record["signature"]):
                raise ValueError("checkpoint signature mismatch")
            if type(body["sequence"]) is not int or body["sequence"] < 0 or not _SHA256_RE.fullmatch(body["digest"]):
                raise ValueError("invalid checkpoint fields")
            return body
        except Exception as exc:
            raise EvidenceIntegrityError("checkpoint verification failed") from exc

    @classmethod
    def verify_anchored_file(cls, journal_path: str | Path, checkpoint_path: str | Path, key: bytes) -> EvidenceVerification:
        checkpoint = cls.verify_checkpoint(checkpoint_path, key)
        verification = cls.verify_file(journal_path)
        if not verification.valid:
            return verification
        previous = "0" * 64
        found = checkpoint["sequence"] == 0 and checkpoint["digest"] == previous
        try:
            with Path(journal_path).open("rb") as stream:
                for raw in stream:
                    item = json.loads(raw)
                    previous = item["digest"]
                    if item["sequence"] == checkpoint["sequence"]:
                        found = previous == checkpoint["digest"]
                        break
            if not found:
                return EvidenceVerification(False, verification.records, verification.last_sequence, ("journal does not contain independently anchored checkpoint",))
        except OSError as exc:
            return EvidenceVerification(False, verification.records, verification.last_sequence, (f"anchor verification read failure: {exc}",))
        return verification

    def append(self, event: CanonicalEvent) -> int:
        if not isinstance(event, CanonicalEvent):
            raise TypeError("event must be a CanonicalEvent")
        with self._lock:
            if self._failed:
                raise EvidenceWriteError("recorder is unhealthy after a prior write failure; reopen after verification")
            with self._process_lock():
                self._refresh_state()
                return self._append_locked(event)

    def _append_locked(self, event: CanonicalEvent) -> int:
        if self._failed:
            raise EvidenceWriteError("recorder is unhealthy after a prior write failure; reopen after verification")
        try:
            serialized = event.to_dict()
            if event.event_id in self._event_ids:
                raise EvidenceWriteError("duplicate event ID; event not recorded")
            sequence = self._sequence + 1
            unsigned = {"sequence": sequence, "previous_digest": self._previous_digest, "event": serialized}
            digest = hashlib.sha256(json.dumps(unsigned, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            line = json.dumps({**unsigned, "digest": digest}, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + len(line) > self.max_bytes:
                raise EvidenceWriteError("evidence storage budget exhausted; event not recorded")
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                written = os.write(fd, line)
                if written != len(line):
                    raise OSError("short evidence write")
                os.fsync(fd)
            finally:
                os.close(fd)
            self._sequence = sequence
            self._previous_digest = digest
            self._event_ids.add(event.event_id)
            self._verified_signature = self._journal_signature()
            return sequence
        except EvidenceWriteError:
            raise
        except EvidenceError:
            raise
        except Exception as exc:
            self._failed = True
            raise EvidenceWriteError(f"evidence write failed; event not confirmed durable: {exc}") from exc
