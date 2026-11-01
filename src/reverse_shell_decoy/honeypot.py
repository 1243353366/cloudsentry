"""Bounded inbound-only transport for the virtual decoy terminal.

This module intentionally depends only on the virtual simulator and the Python
standard library.  It never invokes a host shell, opens an outbound connection,
or writes audit files.  Socket peer metadata and timestamps describe a real
observed inbound interaction; only terminal responses and virtual session
effects are synthetic.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
import sys
import time
from typing import Any, Deque, Optional
import uuid

from .simulator import DecoySession, display_safe
from .signals import inspect_text
from .throttle import InboundThrottle


_READ_LIMIT = 4096
_MIRROR_MAX_BYTES = 64 * 1024
_MIRROR_MAX_CHUNKS_PER_SECOND = 10
_WRITE_TIMEOUT = 1.0
_CONFIG_LIMITS = {
    "max_sessions": (1, 64),
    "max_commands": (1, 100),
    "idle_timeout": (1, 300),
    "session_timeout": (1, 3600),
    "max_sessions_total": (1, 100),
    "audit_limit": (1, 1000),
    "max_input_bytes_total": (1, 8 * 1024 * 1024),
    "max_output_bytes_total": (1, 8 * 1024 * 1024),
    "max_session_input_bytes": (1, 256 * 1024),
    "commands_per_second": (1, 10),
}
_MAX_RUNTIME_SECONDS = 3600.0
_CAPTURE_LIMITS = {
    "max_total_bytes": (1, 8 * 1024 * 1024),
    "max_session_bytes": (1, 8 * 1024 * 1024),
    "max_record_bytes": (16, 65536),
    "greeting_bytes": (0, 4096),
}


@dataclass(frozen=True)
class CapturePolicy:
    """Bounded, opt-in evidence capture for one decoy service instance.

    Only bytes the peer sent to this operator's own listener are captured, and
    only up to a fixed byte budget.  The default service configuration does not
    capture payloads at all; an operator opts in explicitly.

    ``max_record_bytes`` bounds one audit record so a single inbound line or
    chunk is always captured whole (the read limit is 4096 bytes) and never
    produces an unbounded audit line.  ``greeting_bytes`` bounds the peer's
    opening bytes, which is where transport and client banners appear.
    """

    max_total_bytes: int = 1024 * 1024
    max_session_bytes: int = 64 * 1024
    max_record_bytes: int = 4096
    greeting_bytes: int = 512
    greeting_grace_seconds: float = 0.25

    def __post_init__(self) -> None:
        for name in ("max_total_bytes", "max_session_bytes", "max_record_bytes", "greeting_bytes"):
            value = getattr(self, name)
            minimum, maximum = _CAPTURE_LIMITS[name]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("%s must be an integer" % name)
            if not minimum <= value <= maximum:
                raise ValueError("%s must be between %d and %d" % (name, minimum, maximum))
        grace = self.greeting_grace_seconds
        if isinstance(grace, bool) or not isinstance(grace, (int, float)):
            raise ValueError("greeting_grace_seconds must be a number")
        if not 0.0 <= float(grace) <= 5.0:
            raise ValueError("greeting_grace_seconds must be between 0 and 5")


class _GreetingReplayReader:
    """Replay already-read greeting bytes, then continue on the real transport.

    Reading the peer's opening bytes before any protocol handling must not
    change how later input is parsed, so this shim preserves the exact byte
    order and the original line semantics.  A partial line held here is joined
    with the next transport line so a command is never split.
    """

    __slots__ = ("_reader", "_pending")

    def __init__(self, reader: asyncio.StreamReader, pending: bytes) -> None:
        self._reader = reader
        self._pending = pending

    async def readline(self) -> bytes:
        if not self._pending:
            return await self._reader.readline()
        index = self._pending.find(b"\n")
        if index >= 0:
            line = self._pending[: index + 1]
            self._pending = self._pending[index + 1 :]
            return line
        head, self._pending = self._pending, b""
        return head + await self._reader.readline()

    async def read(self, count: int = -1) -> bytes:
        if not self._pending:
            return await self._reader.read(count)
        if count is None or count < 0:
            data, self._pending = self._pending, b""
            return data
        data, self._pending = self._pending[:count], self._pending[count:]
        return data


def _utc_timestamp() -> str:
    """Return an explicitly UTC timestamp suitable for a machine audit record."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_int(name: str, value: int) -> int:
    """Validate a deliberately small, finite configuration range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    minimum, maximum = _CONFIG_LIMITS[name]
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_runtime(value: float) -> float:
    """Accept a finite service lifetime; tests may use a sub-second value."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("max_runtime must be a number of seconds")
    runtime = float(value)
    if not 0.0 < runtime <= _MAX_RUNTIME_SECONDS:
        raise ValueError("max_runtime must be greater than 0 and at most 3600")
    return runtime


def _loopback_host(host: str) -> bool:
    """Accept only literal loopback addresses (plus the conventional localhost)."""
    if not isinstance(host, str) or not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Do not resolve arbitrary names merely to decide whether public binding
        # was requested.  That keeps the safe default deterministic.
        return False


class DecoyServer:
    """Serve bounded inbound console, sink, or opaque mirror sessions over TCP.

    Every accepted TCP connection is counted against ``max_sessions_total``;
    capacity-rejected connections count as well.  Audit entries contain only
    observed connection metadata and hash-only interaction details.  The
    observed peer is not identified as an attacker and no remote operating
    system is inferred from the selected presentation persona.  Records are
    emitted as one JSON object per line on stderr, never to a disk file.
    """

    def __init__(
        self,
        max_sessions: int = 8,
        max_commands: int = 100,
        idle_timeout: int = 20,
        session_timeout: int = 120,
        max_sessions_total: int = 100,
        audit_limit: int = 1000,
        persona: str = "linux",
        max_runtime: float = 600,
        response_mode: str = "console",
        max_input_bytes_total: int = 1024 * 1024,
        max_output_bytes_total: int = 1024 * 1024,
        max_session_input_bytes: int = 64 * 1024,
        commands_per_second: int = 10,
        throttle: Optional[InboundThrottle] = None,
        capture: Optional[CapturePolicy] = None,
    ) -> None:
        self.max_sessions = _require_int("max_sessions", max_sessions)
        self.max_commands = _require_int("max_commands", max_commands)
        self.idle_timeout = _require_int("idle_timeout", idle_timeout)
        self.session_timeout = _require_int("session_timeout", session_timeout)
        self.max_sessions_total = _require_int("max_sessions_total", max_sessions_total)
        self.audit_limit = _require_int("audit_limit", audit_limit)
        self.max_runtime = _require_runtime(max_runtime)
        self.max_input_bytes_total = _require_int("max_input_bytes_total", max_input_bytes_total)
        self.max_output_bytes_total = _require_int("max_output_bytes_total", max_output_bytes_total)
        self.max_session_input_bytes = _require_int("max_session_input_bytes", max_session_input_bytes)
        self.commands_per_second = _require_int("commands_per_second", commands_per_second)
        if persona not in {"linux", "windows"}:
            raise ValueError("persona must be linux or windows")
        self.persona = persona
        if response_mode not in {"console", "sink", "mirror"}:
            raise ValueError("response_mode must be console, sink, or mirror")
        self.response_mode = response_mode
        if throttle is not None and not isinstance(throttle, InboundThrottle):
            raise ValueError("throttle must be an InboundThrottle or None")
        if capture is not None and not isinstance(capture, CapturePolicy):
            raise ValueError("capture must be a CapturePolicy or None")
        # ``None`` keeps the library default unpaced and uncaptured; the service
        # entry point supplies both so every listener it opens is throttled.
        self.throttle = throttle
        self.capture = capture

        # This public deque is bounded even if callers retain the server object.
        self.audit: Deque[dict[str, Any]] = deque(maxlen=self.audit_limit)
        self._server: Optional[asyncio.Server] = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._active_sessions: dict[str, asyncio.StreamWriter] = {}
        self._connection_count = 0
        self._audit_exhausted = False
        self._shutdown_requested = False
        self._shutdown_reason = ""
        self._runtime_expired = False
        self._runtime_task: Optional[asyncio.Task[None]] = None
        self._input_bytes_total = 0
        self._output_bytes_total = 0
        self._session_input_bytes: dict[str, int] = {}
        self._peak_active_sessions = 0
        self._started_at: Optional[float] = None
        self._stopped_at: Optional[float] = None
        self._budget_stopped = False
        self._throttle_denials = 0
        self._throttled_units = 0
        self._capture_total_bytes = 0
        self._capture_session_bytes: dict[str, int] = {}
        self._capture_stream_bytes: dict[str, int] = {}
        self._capture_hashers: dict[str, Any] = {}
        self._capture_truncated: set[str] = set()
        self._capture_records = 0

    @property
    def server(self) -> Optional[asyncio.Server]:
        """The current listening server, or ``None`` before :meth:`start`."""
        return self._server

    @property
    def active_sessions(self) -> int:
        """Number of active virtual sessions, excluding immediately rejected peers."""
        return len(self._active_sessions)

    @property
    def connection_count(self) -> int:
        """Lifetime TCP connection attempts observed by this server instance."""
        return self._connection_count

    def budget_snapshot(self) -> dict[str, Any]:
        """Local admission/reservation counters, not wire delivery or remote costs."""
        elapsed = 0.0 if self._started_at is None else max(
            0.0, (self._stopped_at if self._stopped_at is not None else time.monotonic()) - self._started_at
        )
        return {
            "limits": {
                "max_sessions": self.max_sessions,
                "max_sessions_total": self.max_sessions_total,
                "max_commands": self.max_commands,
                "max_runtime_seconds": self.max_runtime,
                "idle_timeout_seconds": self.idle_timeout,
                "session_timeout_seconds": self.session_timeout,
                "max_input_bytes_total": self.max_input_bytes_total,
                "max_output_bytes_total": self.max_output_bytes_total,
                "max_session_input_bytes": self.max_session_input_bytes,
                "commands_per_second": self.commands_per_second,
            },
            "usage": {
                "input_bytes_total": self._input_bytes_total,
                "output_bytes_total": self._output_bytes_total,
                "accepted_connections": self._connection_count,
                "active_sessions": self.active_sessions,
                "peak_active_sessions": self._peak_active_sessions,
                "elapsed_seconds": round(elapsed, 6),
            },
        }

    def pacing_snapshot(self) -> dict[str, Any]:
        """Throttle and capture counters; separate from the byte/time budget."""
        return {
            "throttle": None if self.throttle is None else self.throttle.snapshot(),
            "throttle_denied_connections": self._throttle_denials,
            "throttle_denied_units": self._throttled_units,
            "capture": None if self.capture is None else {
                "enabled": True,
                "max_total_bytes": self.capture.max_total_bytes,
                "max_session_bytes": self.capture.max_session_bytes,
                "max_record_bytes": self.capture.max_record_bytes,
                "greeting_bytes": self.capture.greeting_bytes,
                "captured_bytes_total": self._capture_total_bytes,
                "captured_records": self._capture_records,
                "truncated_sessions": len(self._capture_truncated),
            },
        }

    def _budget_event(self, phase: str) -> None:
        self._audit_event(
            "service_budget", "service", "unknown",
            source_kind="decoy_service_control", interaction_observed=False,
            peer_ip_source="not_applicable_local_control",
            simulation_scope="local_configuration_and_budget_counters",
            phase=phase, stop_reason=self._shutdown_reason or "not_stopped",
            pacing=self.pacing_snapshot(),
            **self.budget_snapshot(),
        )

    async def _read_greeting(self, reader: asyncio.StreamReader) -> tuple[bytes, bool]:
        """Read the peer's opening bytes, bounded by the capture greeting cap.

        This is ordinary inbound telemetry on the operator's own listener: only
        bytes the peer sent are read, nothing is sent back, and no protocol
        answer is generated here.  ``True`` means the cap was reached, so more
        bytes may have followed in the same burst.
        """
        if self.capture is None or self.capture.greeting_bytes == 0:
            return b"", False
        try:
            data = await asyncio.wait_for(
                reader.read(self.capture.greeting_bytes),
                timeout=self.capture.greeting_grace_seconds,
            )
        except (asyncio.TimeoutError, ValueError, asyncio.LimitOverrunError,
                ConnectionError, OSError):
            return b"", False
        if not data:
            return b"", False
        return data, len(data) >= self.capture.greeting_bytes

    @staticmethod
    def _greeting_fields(greeting: bytes, truncated: bool) -> dict[str, Any]:
        """Describe the peer's complete opening bytes as printable evidence."""
        if not greeting:
            return {"peer_greeting_observed": False}
        try:
            text = display_safe(greeting.decode("utf-8"))
        except UnicodeDecodeError:
            text = ""
        return {
            "peer_greeting_observed": True,
            "peer_greeting_b64": base64.b64encode(greeting).decode("ascii"),
            "peer_greeting_sha256": hashlib.sha256(greeting).hexdigest(),
            "peer_greeting_byte_count": len(greeting),
            "peer_greeting_truncated": truncated,
            "peer_greeting_utf8": text[:1024],
        }

    def _capture_fields(self, session_id: str, payload: bytes) -> dict[str, Any]:
        """Return bounded full-payload evidence fields for one inbound record.

        With capture disabled this returns an empty mapping, so the default
        audit record keeps its hash-only shape.  With capture enabled the full
        inbound record is preserved (base64) while it fits the per-record and
        per-session budgets; a cut record is labelled so a reader never mistakes
        a prefix for the whole payload.
        """
        if self.capture is None:
            return {}
        session_used = self._capture_session_bytes.get(session_id, 0)
        available = min(
            self.capture.max_record_bytes,
            max(0, self.capture.max_session_bytes - session_used),
            max(0, self.capture.max_total_bytes - self._capture_total_bytes),
        )
        captured = payload[:available]
        complete = len(captured) == len(payload)
        if captured:
            self._capture_total_bytes += len(captured)
            self._capture_session_bytes[session_id] = session_used + len(captured)
            self._capture_stream_bytes[session_id] = (
                self._capture_stream_bytes.get(session_id, 0) + len(captured)
            )
            self._capture_hashers.setdefault(session_id, hashlib.sha256()).update(captured)
            self._capture_records += 1
        if not complete:
            self._capture_truncated.add(session_id)
        return {
            "payload_b64": base64.b64encode(captured).decode("ascii"),
            "payload_captured_bytes": len(captured),
            "payload_omitted_bytes": len(payload) - len(captured),
            "payload_complete": complete,
        }

    def _account_greeting_capture(self, session_id: str, greeting: bytes) -> None:
        """Debit the capture budget for greeting bytes without double hashing."""
        if self.capture is None or not greeting:
            return
        session_used = self._capture_session_bytes.get(session_id, 0)
        available = min(
            max(0, self.capture.max_session_bytes - session_used),
            max(0, self.capture.max_total_bytes - self._capture_total_bytes),
        )
        captured = min(len(greeting), available)
        if captured:
            self._capture_total_bytes += captured
            self._capture_session_bytes[session_id] = session_used + captured
            self._capture_records += 1
        if captured < len(greeting):
            self._capture_truncated.add(session_id)

    def _capture_close_fields(self, session_id: str) -> dict[str, Any]:
        """Summarize the captured stream for the closing audit record."""
        if self.capture is None:
            return {}
        hasher = self._capture_hashers.pop(session_id, None)
        # Budgeted bytes include the greeting; the reported count and digest
        # describe only the hashed session stream, so the pair always matches.
        self._capture_session_bytes.pop(session_id, None)
        captured = self._capture_stream_bytes.pop(session_id, 0)
        truncated = session_id in self._capture_truncated
        self._capture_truncated.discard(session_id)
        return {
            "capture_enabled": True,
            "capture_sha256": None if hasher is None else hasher.hexdigest(),
            "capture_byte_count": captured,
            "capture_truncated": truncated,
        }

    def _peer_throttle_reason(self, peer_ip: str, *, connection: bool) -> Optional[str]:
        """Ask the shared throttle for one admission decision."""
        if self.throttle is None:
            return None
        reason = (
            self.throttle.admit_connection(peer_ip)
            if connection
            else self.throttle.admit_unit(peer_ip)
        )
        if reason is not None:
            if connection:
                self._throttle_denials += 1
            else:
                self._throttled_units += 1
        return reason

    def _consume_input(self, size: int, session_id: str) -> Optional[str]:
        """Reserve admission before processing; never count rejected bytes as admitted."""
        if self._shutdown_requested:
            return self._shutdown_reason or "server_shutdown"
        if self._input_bytes_total + size > self.max_input_bytes_total:
            self._begin_shutdown("global_input_byte_budget")
            return "global_input_byte_budget"
        consumed = self._session_input_bytes.get(session_id, 0)
        if consumed + size > self.max_session_input_bytes:
            return "session_input_byte_budget"
        self._input_bytes_total += size
        self._session_input_bytes[session_id] = consumed + size
        return None

    def _reserve_output(self, size: int) -> bool:
        """Reserve before an await; drain failure does not refund the conservative budget."""
        if self._shutdown_requested:
            return False
        if self._output_bytes_total + size > self.max_output_bytes_total:
            self._begin_shutdown("global_output_byte_budget")
            return False
        self._output_bytes_total += size
        return True

    async def start(
        self,
        host: str = "127.0.0.1",
        port: int = 8022,
        allow_public: bool = False,
    ) -> asyncio.Server:
        """Begin listening, refusing non-loopback binding without explicit opt-in."""
        if not isinstance(allow_public, bool):
            raise ValueError("allow_public must be a boolean")
        if not allow_public and not _loopback_host(host):
            raise ValueError("non-loopback binding requires allow_public=True")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("port must be an integer between 0 and 65535")
        if self._server is not None and self._server.is_serving():
            raise RuntimeError("server is already listening")
        if self._connection_count >= self.max_sessions_total:
            raise RuntimeError("lifetime connection quota has already been exhausted")
        if self._runtime_expired:
            raise RuntimeError("service runtime has already expired; create a new server")
        if self._started_at is not None or self._audit_exhausted:
            raise RuntimeError("service instance cannot restart; create a new server")

        self._shutdown_requested = False
        self._shutdown_reason = ""
        self._server = await asyncio.start_server(
            self._client_connected,
            host=host,
            port=port,
            limit=_READ_LIMIT,
            backlog=self.max_sessions,
        )
        self._started_at = time.monotonic()
        self._budget_event("started")
        if not self._shutdown_requested:
            self._runtime_task = asyncio.create_task(self._runtime_guard())
        return self._server

    async def shutdown(self) -> None:
        """Stop accepting peers and cancel remaining handlers for deterministic cleanup."""
        self._begin_shutdown("operator_shutdown")
        if self._server is not None:
            await self._server.wait_closed()

        current = asyncio.current_task()
        runtime_task = self._runtime_task
        if runtime_task is not None and runtime_task is not current and not runtime_task.done():
            runtime_task.cancel()
            await asyncio.gather(runtime_task, return_exceptions=True)
        if runtime_task is not current:
            self._runtime_task = None

        tasks = [
            task for task in tuple(self._client_tasks)
            if task is not current and not task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._active_sessions.clear()
        self._session_input_bytes.clear()
        if self._started_at is not None and not self._budget_stopped:
            self._stopped_at = time.monotonic()
            self._budget_stopped = True
            self._budget_event("stopped")

    async def close(self) -> None:
        """Alias for :meth:`shutdown` for callers using server-style cleanup."""
        await self.shutdown()

    def _close_listener(self) -> None:
        """Immediately make the listening socket unavailable without waiting on peers."""
        if self._server is not None:
            self._server.close()

    def _begin_shutdown(self, reason: str) -> None:
        """Stop the service without leaving active virtual sessions resident."""
        if self._shutdown_requested:
            return
        self._shutdown_requested = True
        self._shutdown_reason = reason
        self._close_listener()
        for writer in tuple(self._active_sessions.values()):
            writer.close()

    async def _runtime_guard(self) -> None:
        """End this server instance after its finite, non-restarting service lifetime."""
        try:
            await asyncio.sleep(self.max_runtime)
        except asyncio.CancelledError:
            return
        self._runtime_expired = True
        self._begin_shutdown("service_runtime_limit")

    def _begin_audit_shutdown(self) -> None:
        """Close listener and active transports as soon as the audit budget is full."""
        if self._audit_exhausted:
            return
        self._audit_exhausted = True
        self._begin_shutdown("audit_limit")
        runtime_task = self._runtime_task
        if runtime_task is not None and not runtime_task.done():
            runtime_task.cancel()

    def _audit_event(
        self,
        event_type: str,
        session_id: str,
        peer_ip: str,
        **details: Any,
    ) -> bool:
        """Append and emit one bounded, non-sensitive audit record.

        ``False`` means the final audit record has been emitted and no further
        session work should be performed.  No event is emitted after the cap.
        """
        if self._audit_exhausted:
            return False
        event: dict[str, Any] = {
            "timestamp_utc": _utc_timestamp(),
            "simulation": True,
            "simulation_scope": (
                "bounded_echo_service_not_real_command_execution"
                if self.response_mode == "mirror"
                else "terminal_response_and_virtual_session_effects"
            ),
            "source_kind": "decoy_service_interaction",
            "interaction_observed": True,
            "response_mode": self.response_mode,
            "event_type": event_type,
            "session_id": session_id,
            "peer_ip": peer_ip,
            "peer_ip_source": "socket_peer_observed",
            "peer_ip_verified": False,
            "attacker_identity": "unknown",
            "attacker_identity_inferred": False,
            "remote_os": "unknown",
            "os_inferred": False,
        }
        event.update(details)
        self.audit.append(event)
        # Compact JSON ensures each audit event remains one machine-readable line
        # on stderr.  There is intentionally no file output option.
        try:
            sys.stderr.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            # Preserve visibility: stop accepting work if the operator sink fails.
            self._audit_exhausted = True
            self._begin_shutdown("operator_audit_failure")
            return False
        if len(self.audit) >= self.audit_limit:
            self._begin_audit_shutdown()
            return False
        return True

    @staticmethod
    def _observed_peer_ip(writer: asyncio.StreamWriter) -> str:
        """Get only the socket-provided address, without DNS or identity inference."""
        peer = writer.get_extra_info("peername")
        if isinstance(peer, tuple) and peer:
            return display_safe(str(peer[0]))
        if isinstance(peer, str):
            return display_safe(peer)
        return "unknown"

    @staticmethod
    def _audit_verb(command: str) -> str:
        """Record an allowed verb or a neutral category, never a caller-supplied token."""
        token = command.strip().split(None, 1)[0].lower() if command.strip() else "empty"
        return token if token in DecoySession.allowed_verbs else "unsupported"

    async def _safe_write(self, writer: asyncio.StreamWriter, text: str) -> bool:
        """Write bounded, control-safe terminal text without an unbounded drain wait."""
        if writer.is_closing():
            return False
        encoded = display_safe(text).encode("utf-8", errors="replace")
        if not self._reserve_output(len(encoded)):
            return False
        try:
            writer.write(encoded)
            await asyncio.wait_for(writer.drain(), timeout=_WRITE_TIMEOUT)
            return True
        except (ConnectionError, OSError, asyncio.TimeoutError):
            return False

    @staticmethod
    async def _finish_writer(writer: asyncio.StreamWriter) -> None:
        """Close a peer transport, bounding cleanup in case its peer disappears."""
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=_WRITE_TIMEOUT)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass

    async def _reject(
        self,
        writer: asyncio.StreamWriter,
        session_id: str,
        peer_ip: str,
        reason: str,
        *,
        notify: bool = True,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Reject an over-quota connection before creating a virtual terminal.

        ``notify=False`` closes a throttled peer without writing anything, so a
        flood never earns a response byte or an extra write budget charge.
        """
        if notify and self.response_mode == "console":
            await self._safe_write(writer, "Maintenance console unavailable.\n")
        captured = self._capture_close_fields(session_id)
        if captured:
            details = {**(details or {}), **captured}
        self._audit_event("close", session_id, peer_ip, reason=reason, **(details or {}))
        await self._finish_writer(writer)

    async def _client_connected(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Account for an inbound TCP peer and contain it to one finite session."""
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        session_id = str(uuid.uuid4())
        peer_ip = self._observed_peer_ip(writer)
        try:
            # Pacing happens before any accounting or response: a throttled peer
            # costs one audit record and one transport close, nothing more.
            throttle_reason = self._peer_throttle_reason(peer_ip, connection=True)
            if throttle_reason is not None:
                await self._reject(
                    writer,
                    session_id,
                    peer_ip,
                    throttle_reason,
                    notify=False,
                    details={"throttled": True, "admission": "refused_before_session"},
                )
                return

            self._connection_count += 1
            session: Optional[DecoySession] = None
            connecting_details: dict[str, Any] = {}
            if self.response_mode == "console":
                # Build and send the complete banner before reading anything, so
                # the peer is never made to wait on capture work.
                session = DecoySession(persona=self.persona, presentation="realistic")
                banner_text = session.banner + session.prompt
                connecting_details.update({
                    "banner_sha256": hashlib.sha256(banner_text.encode()).hexdigest(),
                    "banner_byte_count": len(banner_text.encode()),
                    "banner_text": display_safe(banner_text)[:2048],
                })
                if not await self._safe_write(writer, banner_text):
                    connecting_details["banner_delivered"] = False
                    await self._reject(
                        writer, session_id, peer_ip, "banner_write_failure",
                        notify=False, details=connecting_details,
                    )
                    return
                connecting_details["banner_delivered"] = True

            greeting_reader: Any = reader
            if self.capture is not None:
                greeting, greeting_truncated = await self._read_greeting(reader)
                if greeting:
                    greeting_reader = _GreetingReplayReader(reader, greeting)
                connecting_details.update(
                    self._greeting_fields(greeting, greeting_truncated)
                )
                if greeting:
                    # The greeting is captured evidence in its own right (it is
                    # hashed and encoded above), and it spends the capture
                    # budget, but it is deliberately kept out of the session
                    # stream hash: those bytes are replayed into the session and
                    # would otherwise be hashed twice.
                    self._account_greeting_capture(session_id, greeting)

            if not self._audit_event("connecting", session_id, peer_ip, **connecting_details):
                self._capture_close_fields(session_id)
                await self._finish_writer(writer)
                return

            # The connection that reaches the total cap can complete; close the
            # listening socket immediately so no later session is intentionally
            # admitted.  Rejected capacity peers count toward this same quota.
            if self._connection_count >= self.max_sessions_total:
                self._close_listener()
            if self._connection_count > self.max_sessions_total:
                await self._reject(writer, session_id, peer_ip, "lifetime_connection_limit")
                return
            if self._shutdown_requested:
                await self._reject(writer, session_id, peer_ip, "server_shutdown")
                return
            if self.active_sessions >= self.max_sessions:
                await self._reject(writer, session_id, peer_ip, "active_session_limit")
                return

            self._active_sessions[session_id] = writer
            self._session_input_bytes[session_id] = 0
            self._peak_active_sessions = max(self._peak_active_sessions, self.active_sessions)
            close_reason = "completed"
            try:
                close_reason = await asyncio.wait_for(
                    self._serve_session(
                        greeting_reader, writer, session_id, peer_ip,
                        session=session, banner_sent=session is not None,
                    ),
                    timeout=self.session_timeout,
                )
            except asyncio.TimeoutError:
                close_reason = "session_timeout"
                if self.response_mode == "console":
                    await self._safe_write(writer, "Session time limit reached.\n")
            except asyncio.CancelledError:
                close_reason = "server_shutdown"
                raise
            finally:
                if self._shutdown_requested and self._shutdown_reason:
                    close_reason = self._shutdown_reason
                self._active_sessions.pop(session_id, None)
                self._session_input_bytes.pop(session_id, None)
                self._audit_event(
                    "close", session_id, peer_ip, reason=close_reason,
                    **self._capture_close_fields(session_id),
                )
                await self._finish_writer(writer)
        finally:
            if task is not None:
                self._client_tasks.discard(task)

    async def _serve_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        peer_ip: str,
        *,
        session: Optional[DecoySession] = None,
        banner_sent: bool = False,
    ) -> str:
        """Run a finite virtual session under its caller's fixed lifetime deadline."""
        if self.response_mode == "mirror":
            return await self._serve_mirror(reader, writer, session_id, peer_ip)
        if self.response_mode == "sink":
            return await self._serve_sink(reader, session_id, peer_ip)
        if session is None:
            session = DecoySession(persona=self.persona, presentation="realistic")
        if not banner_sent and not await self._safe_write(writer, session.banner + session.prompt):
            return "write_failure"

        command_times: Deque[float] = deque()
        command_count = 0
        loop = asyncio.get_running_loop()
        while not self._shutdown_requested:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=self.idle_timeout)
            except asyncio.TimeoutError:
                await self._safe_write(writer, "Session idle timeout.\n")
                return "idle_timeout"
            except (ValueError, asyncio.LimitOverrunError):
                # StreamReader has already discarded/limited the overlong line.
                # Do not retain or hash any portion of it.
                await self._safe_write(writer, "Input too long.\n")
                return "input_limit"

            if not line:
                return "client_disconnect"
            if len(line) > _READ_LIMIT:
                await self._safe_write(writer, "Input too long.\n")
                return "input_limit"

            budget_reason = self._consume_input(len(line), session_id)
            if budget_reason:
                self._audit_event("command", session_id, peer_ip, blocked=True,
                                  reason=budget_reason, verb="unsupported",
                                  input_sha256=hashlib.sha256(line).hexdigest(),
                                  input_byte_count=len(line),
                                  **self._capture_fields(session_id, line))
                return budget_reason
            # Preserve exact command bytes for the hash while removing only the
            # terminal line separator before virtual execution.
            raw_bytes = line[:-1] if line.endswith(b"\n") else line
            if raw_bytes.endswith(b"\r"):
                raw_bytes = raw_bytes[:-1]
            command = raw_bytes.decode("utf-8", errors="replace")
            unit_reason = self._peer_throttle_reason(peer_ip, connection=False)
            if unit_reason is not None:
                self._audit_event(
                    "command", session_id, peer_ip,
                    command_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                    verb=self._audit_verb(command),
                    blocked=True, reason=unit_reason,
                    input_byte_count=len(line),
                    throttled=True,
                    **inspect_text(command),
                    **self._capture_fields(session_id, line),
                )
                return unit_reason
            now = loop.time()
            while command_times and now - command_times[0] >= 1.0:
                command_times.popleft()
            if len(command_times) >= self.commands_per_second:
                self._audit_event(
                    "command",
                    session_id,
                    peer_ip,
                    command_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                    verb=self._audit_verb(command),
                    blocked=True,
                    reason="command_rate_limit",
                    input_byte_count=len(line),
                    **inspect_text(command),
                    **self._capture_fields(session_id, line),
                )
                await self._safe_write(writer, "Command rate limit reached.\n")
                return "command_rate_limit"
            command_times.append(now)
            command_count += 1

            output, virtual_event = session.execute_with_event(command)
            if virtual_event is not None:
                virtual_details = {
                    "blocked": virtual_event["blocked"],
                    "reason": virtual_event["reason"],
                    "output_sha256": virtual_event["output_sha256"],
                }
            else:
                # When the simulator hits MAX_COMMANDS or is closed, no event is returned.
                virtual_details = {
                    "blocked": True,
                    "reason": "virtual_command_limit" if session.closed else "virtual_audit_unavailable",
                    "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                }
            if not self._audit_event(
                "command",
                session_id,
                peer_ip,
                command_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                verb=self._audit_verb(command),
                input_byte_count=len(line),
                **inspect_text(command),
                **virtual_details,
                **self._capture_fields(session_id, line),
            ):
                return "audit_limit"
            if not await self._safe_write(writer, output):
                return "write_failure"
            if session.closed:
                return "visitor_exit"
            if command_count >= self.max_commands:
                await self._safe_write(writer, "Command quota reached.\n")
                return "command_limit"
            if not await self._safe_write(writer, session.prompt):
                return "write_failure"
        return "server_shutdown"


    async def _serve_mirror(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        peer_ip: str,
    ) -> str:
        """Echo bounded raw inbound chunks on this connection only.

        Mirror mode deliberately treats the input solely as opaque bytes.  It
        does not decode, evaluate, parse, retain, or replay the payload, and it
        never creates another connection.  A limit violation simply closes the
        accepted connection without adding a protocol message.
        """
        chunk_times: Deque[float] = deque()
        chunk_count = 0
        mirrored_bytes = 0
        loop = asyncio.get_running_loop()

        while not self._shutdown_requested:
            if chunk_count >= self.max_commands:
                return "chunk_limit"
            try:
                payload = await asyncio.wait_for(
                    reader.read(_READ_LIMIT), timeout=self.idle_timeout
                )
            except asyncio.TimeoutError:
                return "idle_timeout"
            except (ValueError, asyncio.LimitOverrunError):
                # ``read`` is explicitly bounded, but never turn malformed or
                # overlong inbound data into a response payload.
                return "input_limit"

            if not payload:
                return "client_disconnect"

            now = loop.time()
            while chunk_times and now - chunk_times[0] >= 1.0:
                chunk_times.popleft()
            payload_details = {
                "byte_count": len(payload),
                "input_byte_count": len(payload),
                "chunk_sha256": hashlib.sha256(payload).hexdigest(),
                "execution": False,
                **self._capture_fields(session_id, payload),
            }
            unit_reason = self._peer_throttle_reason(peer_ip, connection=False)
            if unit_reason is not None:
                self._audit_event("mirror_chunk", session_id, peer_ip,
                                  **payload_details, blocked=True, throttled=True,
                                  reason=unit_reason)
                return unit_reason
            budget_reason = self._consume_input(len(payload), session_id)
            if budget_reason:
                self._audit_event("mirror_chunk", session_id, peer_ip,
                                  **payload_details, blocked=True, reason=budget_reason)
                return budget_reason
            if len(chunk_times) >= min(self.commands_per_second, _MIRROR_MAX_CHUNKS_PER_SECOND):
                self._audit_event(
                    "mirror_chunk",
                    session_id,
                    peer_ip,
                    **payload_details,
                    blocked=True,
                    reason="chunk_rate_limit",
                )
                return "chunk_rate_limit"
            if mirrored_bytes + len(payload) > _MIRROR_MAX_BYTES:
                self._audit_event(
                    "mirror_chunk",
                    session_id,
                    peer_ip,
                    **payload_details,
                    blocked=True,
                    reason="byte_budget",
                )
                return "byte_budget"

            if not self._reserve_output(len(payload)):
                self._audit_event("mirror_chunk", session_id, peer_ip,
                                  **payload_details, blocked=True, reason="global_output_byte_budget")
                return "global_output_byte_budget"
            if not self._audit_event(
                "mirror_chunk",
                session_id,
                peer_ip,
                **payload_details,
                blocked=False,
                reason="mirrored",
            ):
                return "audit_limit"
            if writer.is_closing():
                return "write_failure"
            try:
                # Payload is written unmodified to the same accepted transport;
                # this is intentionally a 1:1 echo, including arbitrary binary.
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=_WRITE_TIMEOUT)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                return "write_failure"

            mirrored_bytes += len(payload)
            chunk_count += 1
            chunk_times.append(now)
        return "server_shutdown"


    async def _serve_sink(self, reader: asyncio.StreamReader, session_id: str, peer_ip: str) -> str:
        """Bounded silent input: hashes/known verbs only; no interpreter or replay."""
        command_times: Deque[float] = deque()
        loop = asyncio.get_running_loop()
        for _ in range(self.max_commands):
            if self._shutdown_requested:
                return "server_shutdown"
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=self.idle_timeout)
            except asyncio.TimeoutError:
                return "idle_timeout"
            except (ValueError, asyncio.LimitOverrunError):
                return "input_limit"
            if not line:
                return "client_disconnect"
            if len(line) > _READ_LIMIT:
                return "input_limit"
            budget_reason = self._consume_input(len(line), session_id)
            if budget_reason:
                self._audit_event("command", session_id, peer_ip, blocked=True,
                                  reason=budget_reason, verb="unsupported",
                                  input_sha256=hashlib.sha256(line).hexdigest(),
                                  input_byte_count=len(line),
                                  **self._capture_fields(session_id, line))
                return budget_reason
            raw_bytes = line.rstrip(b"\r\n")
            command = raw_bytes.decode("utf-8", errors="replace")
            unit_reason = self._peer_throttle_reason(peer_ip, connection=False)
            if unit_reason is not None:
                self._audit_event("command", session_id, peer_ip,
                                  command_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                                  input_byte_count=len(line), blocked=True,
                                  throttled=True, verb=self._audit_verb(command),
                                  **inspect_text(command), reason=unit_reason,
                                  **self._capture_fields(session_id, line))
                return unit_reason
            current = loop.time()
            while command_times and current - command_times[0] >= 1.0:
                command_times.popleft()
            rate_exceeded = len(command_times) >= self.commands_per_second
            command_times.append(current)
            if not self._audit_event("command", session_id, peer_ip,
                                     command_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                                     input_byte_count=len(line),
                                     verb=self._audit_verb(command), blocked=True,
                                     **inspect_text(command),
                                     **self._capture_fields(session_id, line),
                                     reason="command_rate_limit" if rate_exceeded else "inbound_sink_no_execution"):
                return "audit_limit"
            if rate_exceeded:
                return "command_rate_limit"
        return "command_limit"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the bounded virtual maintenance-console decoy."
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (loopback by default)")
    parser.add_argument("--port", type=int, default=8022, help="TCP port (0 permits an ephemeral port)")
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="explicitly permit a non-loopback bind",
    )
    parser.add_argument("--persona", choices=("linux", "windows"), default="linux")
    parser.add_argument(
        "--response-mode",
        choices=("console", "sink", "mirror"),
        default="console",
        help=("console is virtual-only; sink is silent hash-only input; mirror is "
              "bounded same-connection binary echo without execution or dial-out"),
    )
    parser.add_argument("--max-sessions", type=int, default=8)
    parser.add_argument("--max-commands", type=int, default=100)
    parser.add_argument("--idle-timeout", type=int, default=20)
    parser.add_argument("--session-timeout", type=int, default=120)
    parser.add_argument("--max-sessions-total", type=int, default=100)
    parser.add_argument("--audit-limit", type=int, default=1000)
    parser.add_argument("--max-input-bytes-total", type=int, default=1024 * 1024)
    parser.add_argument("--max-output-bytes-total", type=int, default=1024 * 1024)
    parser.add_argument("--max-session-input-bytes", type=int, default=64 * 1024)
    parser.add_argument("--commands-per-second", type=int, default=10)
    parser.add_argument(
        "--max-runtime",
        type=int,
        default=600,
        help="whole-service lifetime in seconds (1 through 3600)",
    )
    parser.add_argument(
        "--no-throttle",
        action="store_true",
        help="disable the shared inbound per-source pacing (not recommended)",
    )
    parser.add_argument(
        "--max-connects-per-second",
        type=int,
        default=32,
        help="listener-wide accepted connections per second across all peers",
    )
    parser.add_argument(
        "--max-connects-per-second-per-peer",
        type=int,
        default=8,
        help="accepted connections per second from one source (IPv6 grouped by /64)",
    )
    parser.add_argument(
        "--max-units-per-second",
        type=int,
        default=64,
        help="listener-wide admitted commands/chunks per second",
    )
    parser.add_argument(
        "--max-units-per-second-per-peer",
        type=int,
        default=16,
        help="admitted commands/chunks per second from one source",
    )
    parser.add_argument(
        "--capture-payloads",
        action="store_true",
        help=(
            "opt in to bounded full-payload evidence: base64 inbound records and the "
            "peer's complete greeting banner, on this listener only"
        ),
    )
    parser.add_argument(
        "--capture-bytes-total",
        type=int,
        default=1024 * 1024,
        help="maximum payload bytes captured across the service lifetime",
    )
    parser.add_argument(
        "--capture-session-bytes",
        type=int,
        default=64 * 1024,
        help="maximum payload bytes captured per session",
    )
    parser.add_argument(
        "--capture-record-bytes",
        type=int,
        default=4096,
        help="maximum bytes captured from one inbound record",
    )
    parser.add_argument(
        "--capture-greeting-bytes",
        type=int,
        default=512,
        help="bytes read from a peer's opening burst for the greeting banner (0 disables)",
    )
    parser.add_argument(
        "--capture-greeting-grace",
        type=float,
        default=0.25,
        help="seconds to wait for a peer's opening burst before continuing",
    )
    return parser


def _build_pacing(args: argparse.Namespace) -> tuple[Optional[InboundThrottle], Optional[CapturePolicy]]:
    """Build the shared throttle and optional capture policy from CLI settings."""
    throttle = None
    if not args.no_throttle:
        throttle = InboundThrottle(
            connects_per_second=args.max_connects_per_second,
            connects_per_second_per_peer=args.max_connects_per_second_per_peer,
            units_per_second=args.max_units_per_second,
            units_per_second_per_peer=args.max_units_per_second_per_peer,
        )
    capture = None
    if args.capture_payloads:
        capture = CapturePolicy(
            max_total_bytes=args.capture_bytes_total,
            max_session_bytes=args.capture_session_bytes,
            max_record_bytes=args.capture_record_bytes,
            greeting_bytes=args.capture_greeting_bytes,
            greeting_grace_seconds=args.capture_greeting_grace,
        )
    return throttle, capture


async def _run_from_args(args: argparse.Namespace) -> int:
    throttle, capture = _build_pacing(args)
    service = DecoyServer(
        max_sessions=args.max_sessions,
        max_commands=args.max_commands,
        idle_timeout=args.idle_timeout,
        session_timeout=args.session_timeout,
        max_sessions_total=args.max_sessions_total,
        audit_limit=args.audit_limit,
        persona=args.persona,
        max_runtime=args.max_runtime,
        response_mode=args.response_mode,
        max_input_bytes_total=args.max_input_bytes_total,
        max_output_bytes_total=args.max_output_bytes_total,
        max_session_input_bytes=args.max_session_input_bytes,
        commands_per_second=args.commands_per_second,
        throttle=throttle,
        capture=capture,
    )
    server = await service.start(
        host=args.host,
        port=args.port,
        allow_public=args.allow_public,
    )
    if not server.is_serving():
        await service.shutdown()
        return 2 if service._shutdown_reason in {"audit_limit", "operator_audit_failure"} else 0
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        # Closing a server from a bounded quota can cancel serve_forever().
        if not service._shutdown_requested and not service._audit_exhausted:
            raise
    finally:
        await service.shutdown()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Parse CLI arguments and run until shutdown or a configured finite quota closes."""
    parser = _parser()
    args = parser.parse_args(argv)
    credential_names = {"CLOUDFLARE_API_TOKEN", "RENDER_API_KEY", "RAILWAY_API_TOKEN",
                        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                        "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY"}
    if credential_names.intersection(os.environ):
        parser.error("credential-bearing environment refused; use the clean-environment scripts/start-honeypot.sh launcher")
    try:
        return asyncio.run(_run_from_args(args))
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130
    return 2  # pragma: no cover - parser.error always exits


if __name__ == "__main__":
    raise SystemExit(main())
