"""Listener watchdog: bounded, repeated inventory diffing with recurrence links.

The one-shot inventory answers "what is bound right now". A watchdog answers the
question that actually matters for continuity: did a binding *return*, and is it
still the same one. It does this by taking bounded snapshots, diffing them, and
linking a reappearance of the same binding to the observation in which it was
first seen.

Three properties are deliberate, and each has a test:

* **It never acts.** The watchdog records ``action: "none"`` and
  ``requires_authorization: True`` on every event. It does not signal, kill,
  block, firewall or restart anything. Replacing a listener is an operator
  decision that needs fresh authorization, so the tool cannot make it for them.
  A reappearing listener is evidence, not a verdict.
* **It is bounded.** Snapshots, interval, total deadline and retained history all
  have limits, and a run that hits its deadline reports why it stopped instead of
  presenting a short run as continuous monitoring.
* **It distinguishes continuity from identity.** A reappearance is matched on the
  binding (protocol, family, address, port, state) plus the observed owners. A
  different PID on the same binding is reported as a replacement with its own
  assurance level, never silently treated as the original process coming back.

See ``docs/listener-watchdog.md``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .listeners import scan_listeners
from .observation import (
    COVERAGE_COMPLETE,
    COVERAGE_DEGRADED,
    COVERAGE_NO_DATA,
    COVERAGE_PARTIAL,
)

KIND_APPEARED = "BINDING_APPEARED"
KIND_DISAPPEARED = "BINDING_DISAPPEARED"
KIND_CHANGED = "BINDING_CHANGED"
KIND_REAPPEARED = "BINDING_REAPPEARED"

ACTION_NONE = "none"

ASSURANCE_UNKNOWN = "UNKNOWN"
ASSURANCE_PARTIAL = "PARTIAL"
ASSURANCE_MULTIPLE = "MULTIPLE_OWNERS"

MAX_OBSERVATIONS = 240
MAX_INTERVAL_SECONDS = 3600.0
MAX_DEADLINE_SECONDS = 86400.0
MAX_HISTORY = 2048

LIMITATION_NOTICE = (
    "A watchdog run sees only the moments it looked. A binding that appeared and "
    "disappeared between two snapshots is invisible here, and a run stopped by its "
    "deadline or observation limit is not continuous monitoring. Reappearance links "
    "are based on the binding and the observed owners; a replaced process on the same "
    "binding is reported as a replacement, not as continuity."
)


def _utc_now_text() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_int(name: str, value: object, *, maximum: int, minimum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_seconds(name: str, value: object, *, maximum: float, allow_zero: bool) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    lower_ok = number >= 0.0 if allow_zero else number > 0.0
    if not lower_ok or number > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return number


def binding_key(record: Dict[str, Any]) -> str:
    """Return a stable textual key for one binding record."""

    protocol = str(record.get("protocol", "?"))
    family = str(record.get("family", "?"))
    address = str(record.get("address", "?"))
    port = record.get("port", "?")
    state = str(record.get("state", "?"))
    return f"{protocol}/{family}/{address}:{port}/{state}"


def _owners(record: Dict[str, Any]) -> Tuple[Tuple[int, str], ...]:
    owners: List[Tuple[int, str]] = []
    for owner in record.get("owners") or []:
        if not isinstance(owner, dict):
            continue
        pid = owner.get("pid")
        comm = owner.get("comm")
        if isinstance(pid, int) and not isinstance(pid, bool):
            owners.append((pid, str(comm or "")))
    return tuple(sorted(owners))


def _assurance(owners: Sequence[Tuple[int, str]]) -> str:
    if not owners:
        return ASSURANCE_UNKNOWN
    if len(owners) > 1:
        return ASSURANCE_MULTIPLE
    return ASSURANCE_PARTIAL


@dataclass
class WatchdogEvent:
    """One observed change to one binding. Never an instruction to act."""

    kind: str
    observation_index: int
    observed_at_utc: str
    key: str
    protocol: str = ""
    family: str = ""
    address: str = ""
    port: Optional[int] = None
    exposure: str = ""
    owners: List[Dict[str, Any]] = field(default_factory=list)
    identity_assurance: str = ASSURANCE_UNKNOWN
    detail: str = ""
    recurrence_of_first_seen_utc: Optional[str] = None
    prior_disappearances: int = 0
    action: str = ACTION_NONE
    requires_authorization: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "observation_index": self.observation_index,
            "observed_at_utc": self.observed_at_utc,
            "binding": self.key,
            "protocol": self.protocol,
            "family": self.family,
            "address": self.address,
            "port": self.port,
            "exposure": self.exposure,
            "owners": [dict(owner) for owner in self.owners],
            "identity_assurance": self.identity_assurance,
            "detail": self.detail,
            "recurrence_of_first_seen_utc": self.recurrence_of_first_seen_utc,
            "prior_disappearances": self.prior_disappearances,
            "action": self.action,
            "requires_authorization": self.requires_authorization,
            "watchdog_generated": True,
        }


@dataclass
class _BindingHistory:
    first_seen_utc: str
    last_seen_utc: str
    observations: int = 1
    disappearances: int = 0


class ListenerWatchdog:
    """Repeated bounded snapshots of the listener inventory, diffed over time."""

    def __init__(
        self,
        snapshot: Callable[[], Dict[str, Any]] = scan_listeners,
        *,
        min_interval_seconds: float = 1.0,
        max_observations: int = 60,
        deadline_seconds: float = 300.0,
        history_limit: int = MAX_HISTORY,
    ) -> None:
        if not callable(snapshot):
            raise ValueError("snapshot must be callable")
        self.snapshot = snapshot
        self.min_interval_seconds = _require_seconds(
            "min_interval_seconds", min_interval_seconds, maximum=MAX_INTERVAL_SECONDS, allow_zero=True
        )
        self.max_observations = _require_int(
            "max_observations", max_observations, maximum=MAX_OBSERVATIONS, minimum=1
        )
        self.deadline_seconds = _require_seconds(
            "deadline_seconds", deadline_seconds, maximum=MAX_DEADLINE_SECONDS, allow_zero=False
        )
        self.history_limit = _require_int("history_limit", history_limit, maximum=MAX_HISTORY, minimum=1)

        self._current: Dict[str, Dict[str, Any]] = {}
        self._history: Dict[str, _BindingHistory] = {}
        self._events: List[WatchdogEvent] = []
        self._observations = 0
        self._started_at: Optional[float] = None
        self._stopped_reason = ""
        self._completeness = COVERAGE_NO_DATA
        self._warnings: List[str] = []

    # -- observation -----------------------------------------------------
    def observe(self) -> List[WatchdogEvent]:
        """Take one snapshot, append diff events, and return the new events."""

        if self._started_at is None:
            self._started_at = time.monotonic()
        if self._observations >= self.max_observations:
            self._stopped_reason = "observation limit reached"
            return []
        if time.monotonic() - self._started_at >= self.deadline_seconds:
            self._stopped_reason = "deadline reached"
            return []

        inventory = self.snapshot()
        if not isinstance(inventory, dict):
            raise ValueError("snapshot must return a mapping")
        self._observations += 1
        index = self._observations
        observed_at = str(inventory.get("observed_at_utc") or _utc_now_text())
        warnings = inventory.get("warnings") or []
        if warnings:
            for warning in warnings[:8]:
                text = str(warning)
                if text not in self._warnings:
                    self._warnings.append(text)

        current: Dict[str, Dict[str, Any]] = {}
        for record in inventory.get("listeners") or []:
            if isinstance(record, dict):
                current[binding_key(record)] = record

        events: List[WatchdogEvent] = []
        previous = self._current

        for key in sorted(current):
            record = current[key]
            owners = _owners(record)
            if key in previous:
                before = _owners(previous[key])
                if before != owners:
                    events.append(
                        self._event(
                            KIND_CHANGED,
                            index,
                            observed_at,
                            key,
                            record,
                            _assurance(owners),
                            detail=self._describe_change(before, owners),
                        )
                    )
                history = self._history.get(key)
                if history is not None:
                    history.observations += 1
                    history.last_seen_utc = observed_at
                continue

            history = self._history.get(key)
            if history is not None and history.disappearances > 0:
                events.append(
                    self._event(
                        KIND_REAPPEARED,
                        index,
                        observed_at,
                        key,
                        record,
                        _assurance(owners),
                        detail=(
                            "this binding was observed before, disappeared, and is now present again; "
                            "it is reported as a recurrence and no action was taken"
                        ),
                        recurrence_of=history.first_seen_utc,
                        prior_disappearances=history.disappearances,
                    )
                )
                history.last_seen_utc = observed_at
                history.observations += 1
            else:
                events.append(
                    self._event(
                        KIND_APPEARED,
                        index,
                        observed_at,
                        key,
                        record,
                        _assurance(owners),
                        detail="binding is present in this snapshot and was not present in the previous one",
                    )
                )
                self._history[key] = _BindingHistory(
                    first_seen_utc=observed_at, last_seen_utc=observed_at
                )

        for key in sorted(previous):
            if key in current:
                continue
            record = previous[key]
            owners = _owners(record)
            events.append(
                self._event(
                    KIND_DISAPPEARED,
                    index,
                    observed_at,
                    key,
                    record,
                    _assurance(owners),
                    detail="binding was present in the previous snapshot and is absent from this one",
                )
            )
            history = self._history.get(key)
            if history is not None:
                history.disappearances += 1
                history.last_seen_utc = observed_at

        self._current = current
        self._trim_history()
        self._events.extend(events)
        self._completeness = self._coverage(current, warnings)
        return events

    def run(self, iterations: int) -> Dict[str, Any]:
        """Take up to ``iterations`` snapshots, sleeping the minimum interval."""

        count = _require_int("iterations", iterations, maximum=self.max_observations, minimum=1)
        for attempt in range(count):
            if attempt and self.min_interval_seconds:
                time.sleep(self.min_interval_seconds)
            before = len(self._events)
            produced = self.observe()
            if not produced and len(self._events) == before and self._stopped_reason:
                break
        return self.as_dict()

    # -- reporting -------------------------------------------------------
    def as_dict(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for event in self._events:
            counts[event.kind] = counts.get(event.kind, 0) + 1
        recurrences = [event for event in self._events if event.kind == KIND_REAPPEARED]
        stopped = self._stopped_reason or (
            "observation limit reached" if self._observations >= self.max_observations else ""
        )
        running = not stopped
        statement_parts = [
            f"{self._observations} snapshot(s) of the listener inventory, {len(self._events)} change event(s)."
        ]
        if recurrences:
            statement_parts.append(
                f"{len(recurrences)} binding(s) returned after disappearing; each is reported as a "
                "recurrence with its first-seen time and no action was taken."
            )
        if not running:
            phrase = {
                "deadline reached": "the deadline was reached",
                "observation limit reached": "the observation limit was reached",
            }.get(stopped, stopped)
            statement_parts.append(f"Watching stopped because {phrase}.")
        return {
            "kind": "listener_watchdog",
            "observations": self._observations,
            "max_observations": self.max_observations,
            "min_interval_seconds": self.min_interval_seconds,
            "deadline_seconds": self.deadline_seconds,
            "still_running": running,
            "stopped_reason": stopped,
            "current_bindings": sorted(self._current),
            "event_counts": counts,
            "events": [event.as_dict() for event in self._events],
            "coverage": self._completeness,
            "warnings": list(self._warnings),
            "statement": " ".join(statement_parts),
            "action": ACTION_NONE,
            "terminates_processes": False,
            "limitation_notice": LIMITATION_NOTICE,
        }

    # -- internals -------------------------------------------------------
    def _event(
        self,
        kind: str,
        index: int,
        observed_at: str,
        key: str,
        record: Dict[str, Any],
        assurance: str,
        *,
        detail: str,
        recurrence_of: Optional[str] = None,
        prior_disappearances: int = 0,
    ) -> WatchdogEvent:
        port = record.get("port")
        return WatchdogEvent(
            kind=kind,
            observation_index=index,
            observed_at_utc=observed_at,
            key=key,
            protocol=str(record.get("protocol", "")),
            family=str(record.get("family", "")),
            address=str(record.get("address", "")),
            port=port if isinstance(port, int) and not isinstance(port, bool) else None,
            exposure=str(record.get("exposure", "")),
            owners=[dict(owner) for owner in record.get("owners") or [] if isinstance(owner, dict)],
            identity_assurance=assurance,
            detail=detail,
            recurrence_of_first_seen_utc=recurrence_of,
            prior_disappearances=prior_disappearances,
        )

    @staticmethod
    def _describe_change(
        before: Sequence[Tuple[int, str]], after: Sequence[Tuple[int, str]]
    ) -> str:
        added = [pid for pid, _ in after if pid not in {pid for pid, _ in before}]
        removed = [pid for pid, _ in before if pid not in {pid for pid, _ in after}]
        parts = []
        if added:
            parts.append(f"new owner pid(s) {added}")
        if removed:
            parts.append(f"owner pid(s) {removed} no longer hold this binding")
        if not parts:
            parts.append("owner list changed but no pid difference was resolvable")
        return "; ".join(parts)

    def _trim_history(self) -> None:
        while len(self._history) > self.history_limit:
            oldest = next(iter(self._history))
            self._history.pop(oldest, None)

    def _coverage(self, current: Dict[str, Any], warnings: Sequence[Any]) -> str:
        if self._observations == 0:
            return COVERAGE_NO_DATA
        if warnings:
            return COVERAGE_PARTIAL
        if not current and self._observations >= 2:
            # Two consecutive empty snapshots are a real observation, not a gap.
            return COVERAGE_COMPLETE
        return COVERAGE_COMPLETE
