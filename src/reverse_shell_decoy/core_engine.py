"""Shared Core Engine for CloudSentry Listener Defense & Attribution Engine (LDAE).

Provides canonical event normalization, structured logging, tri-state
authorization (AUTHORIZED, UNAUTHORIZED, UNKNOWN), process identity tracking,
and platform-agnostic abstractions.
"""
from __future__ import annotations

import datetime
import enum
import json
import logging
import os
import platform
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class AuthStatus(str, enum.Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    UNKNOWN = "UNKNOWN"  # Must never automatically become UNAUTHORIZED


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


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    executable: str
    executable_sha256: Optional[str]
    user: str
    created_time_utc: Optional[str]
    privilege_level: str = "standard"  # standard, elevated, system, root
    authenticode_verified: Optional[bool] = None
    container_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ListenerIdentity:
    protocol: str  # TCP, UDP
    local_address: str
    local_port: int
    process: Optional[ProcessIdentity]
    first_observed_utc: str
    last_observed_utc: str
    duration_seconds: float
    listening_state: str  # LISTEN, BOUND
    associated_connections: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalEvent:
    event_id: str
    incident_id: str
    event_type: str
    timestamp_utc: str
    timestamp_local: str
    local_timezone: str
    host_identifier: str
    platform: str
    collection_source: str
    confidence: ConfidenceLevel
    authorization: AuthStatus
    details: Dict[str, Any] = field(default_factory=dict)
    synthetic_decoy: bool = False
    dde_event_id: Optional[str] = None

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
    ) -> CanonicalEvent:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_local = datetime.datetime.now().astimezone()
        tz_name = now_local.tzname() or "UTC"

        sys_plat = platform.system().lower()
        if "linux" in sys_plat:
            plat = PlatformType.LINUX.value
        elif "windows" in sys_plat:
            plat = PlatformType.WINDOWS.value
        else:
            plat = PlatformType.OTHER.value

        # Do not emit the machine hostname by default; callers may provide a
        # configured pseudonymous host identifier when stable correlation is needed.
        host = host_id or "unknown-host"

        return cls(
            event_id=f"evt_{uuid.uuid4().hex[:16]}",
            incident_id=incident_id or f"inc_{uuid.uuid4().hex[:12]}",
            event_type=event_type,
            timestamp_utc=now_utc.isoformat(),
            timestamp_local=now_local.isoformat(),
            local_timezone=tz_name,
            host_identifier=host,
            platform=plat,
            collection_source=collection_source,
            confidence=confidence,
            authorization=authorization,
            details=details or {},
            synthetic_decoy=synthetic_decoy,
            dde_event_id=dde_event_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["confidence"] = self.confidence.value
        data["authorization"] = self.authorization.value
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


class CoreAuthorizationEngine:
    """Manages baseline port and process authorizations.
    
    Guarantees that unknown processes or bindings remain UNKNOWN and
    never automatically transition to UNAUTHORIZED without rule evaluation.
    """

    def __init__(self, allowed_listeners: Optional[List[Dict[str, Any]]] = None):
        # Format: [{"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd", "sha256": "..."}]
        self._allowed_listeners = allowed_listeners or []
        self._sensitive_ports = {21, 22, 23, 25, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}

    def evaluate_listener(
        self,
        port: int,
        protocol: str,
        executable: Optional[str] = None,
        executable_sha256: Optional[str] = None,
    ) -> AuthStatus:
        """Evaluate only explicit policy; missing evidence remains UNKNOWN.

        A sensitive port is never itself proof of unauthorized activity. If at
        least one matching explicit rule fully matches the observed identity,
        the listener is authorized. An identity mismatch is unauthorized only
        when there is a matching port/protocol policy and enough identity data
        to compare it.
        """
        matching_rules = [
            rule for rule in self._allowed_listeners
            if rule.get("port") == port
            and str(rule.get("protocol", "TCP")).upper() == protocol.upper()
        ]
        if not matching_rules:
            return AuthStatus.UNKNOWN

        missing_identity_evidence = False
        for rule in matching_rules:
            rule_exe = rule.get("executable")
            rule_hash = rule.get("sha256")

            if rule_exe:
                if not executable:
                    missing_identity_evidence = True
                    continue
                if os.path.normcase(os.path.normpath(rule_exe)) != os.path.normcase(os.path.normpath(executable)):
                    continue

            if rule_hash:
                if not executable_sha256:
                    missing_identity_evidence = True
                    continue
                if str(rule_hash).lower() != str(executable_sha256).lower():
                    continue

            return AuthStatus.AUTHORIZED

        if missing_identity_evidence:
            return AuthStatus.UNKNOWN
        return AuthStatus.UNAUTHORIZED

    def is_sensitive_port(self, port: int) -> bool:
        return port in self._sensitive_ports


class JsonEventLogger:
    """Emit canonical events as one structured JSON record per line."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("cloudsentry.events")

    def emit(self, event: CanonicalEvent) -> None:
        if not isinstance(event, CanonicalEvent):
            raise TypeError("event must be a CanonicalEvent")
        self.logger.info(event.to_json())
