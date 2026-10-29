"""Safe, deterministic synthetic experiment scenarios.

This module models only JSON-compatible data in memory.  It does not create
processes, use the network, or alter host or security tooling state.
"""

from __future__ import annotations

from random import Random
from typing import Any


SCENARIO_NAMES = (
    "process-limit",
    "network-loss",
    "telemetry-gap",
    "baseline",
)
"""Scenario names supported by :func:`run_scenario`."""

_VIRTUAL_STEP_COUNT = 30
_PROCESS_LIMIT = 3
_TELEMETRY_GAP_STEPS = frozenset(range(10, 16))
_LIMITATIONS = "Does not generate or suppress real OS/EDR events."


def _observer_event(
    step: int,
    event_type: str,
    **fields: str | int | bool | None,
) -> dict[str, str | int | bool | None]:
    """Create one authoritative, in-memory observer event.

    Event values deliberately remain JSON primitives; there are no nested
    payloads, credentials, host identifiers, or network addresses.
    """
    event: dict[str, str | int | bool | None] = {
        "simulation": True,
        "event_id": f"observer-{step:03d}",
        "stream": "observer",
        "step": step,
        "event_type": event_type,
    }
    event.update(fields)
    return event


def _sensor_event(
    observer_event: dict[str, str | int | bool | None]) -> dict[str, str | int | bool | None]:
    """Create a sensor-view event corresponding to an observer event."""
    sensor_event = dict(observer_event)
    step = sensor_event["step"]
    sensor_event["event_id"] = f"sensor-{step:03d}"
    sensor_event["source_event_id"] = observer_event["event_id"]
    sensor_event["stream"] = "sensor"
    return sensor_event


def _process_limit_events() -> tuple[list[dict[str, str | int | bool | None]], int]:
    """Model fork attempts and releases without creating any processes."""
    observer: list[dict[str, str | int | bool | None]] = []
    active_processes = 1
    denied_count = 0
    release_steps = {6, 12, 18, 24, 30}

    for step in range(1, _VIRTUAL_STEP_COUNT + 1):
        if step in release_steps:
            active_processes -= 1
            event = _observer_event(
                step,
                "virtual_process_release",
                action="release",
                result="released",
                virtual_process_count=active_processes,
                virtual_process_limit=_PROCESS_LIMIT,
            )
        elif active_processes < _PROCESS_LIMIT:
            active_processes += 1
            event = _observer_event(
                step,
                "virtual_fork_attempt",
                action="fork",
                result="allowed",
                virtual_process_count=active_processes,
                virtual_process_limit=_PROCESS_LIMIT,
            )
        else:
            denied_count += 1
            event = _observer_event(
                step,
                "virtual_fork_attempt",
                action="fork",
                result="denied",
                virtual_process_count=active_processes,
                virtual_process_limit=_PROCESS_LIMIT,
            )
        observer.append(event)

    return observer, denied_count


def _baseline_events() -> list[dict[str, str | int | bool | None]]:
    """Create normal synthetic activity for every virtual step."""
    return [
        _observer_event(
            step,
            "virtual_heartbeat",
            status="normal",
            virtual_process_count=1,
        )
        for step in range(1, _VIRTUAL_STEP_COUNT + 1)
    ]


def _network_events(rng: Random) -> tuple[list[dict[str, str | int | bool | None]], set[int]]:
    """Create virtual packet events with a deterministic roughly 35% loss set."""
    # Ten of thirty packets is 33.3%, and sampling makes the affected virtual
    # steps deterministic for a supplied seed without sending any packets.
    dropped_steps = set(rng.sample(range(1, _VIRTUAL_STEP_COUNT + 1), 10))
    observer = []
    for step in range(1, _VIRTUAL_STEP_COUNT + 1):
        delivery = "dropped" if step in dropped_steps else "delivered"
        observer.append(
            _observer_event(
                step,
                "virtual_packet",
                packet_id=f"packet-{step:03d}",
                delivery=delivery,
            )
        )
    return observer, dropped_steps


def _telemetry_events() -> list[dict[str, str | int | bool | None]]:
    """Create a complete operator audit before intentionally degrading sensor data."""
    return [
        _observer_event(
            step,
            "virtual_telemetry",
            status="recorded",
        )
        for step in range(1, _VIRTUAL_STEP_COUNT + 1)
    ]


def run_scenario(name: str, seed: int = 0) -> dict[str, Any]:
    """Run one safe, deterministic, entirely in-memory synthetic scenario.

    Parameters:
        name: One of ``process-limit``, ``network-loss``, ``telemetry-gap``,
            or ``baseline``.
        seed: Integer seed used only to select simulated network-loss steps.

    Returns:
        A JSON-serializable dictionary.  ``observer`` always has exactly one
        authoritative event for each of 30 virtual steps.  ``sensor`` is the
        intentionally degraded synthetic view.

    Raises:
        ValueError: If ``name`` is not a supported scenario name.
        TypeError: If ``seed`` is not an integer (booleans are excluded).
    """
    if not isinstance(name, str) or name not in SCENARIO_NAMES:
        allowed = ", ".join(SCENARIO_NAMES)
        raise ValueError(f"unknown synthetic scenario {name!r}; expected one of: {allowed}")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")

    rng = Random(seed)
    denied_count = 0
    dropped_steps: set[int] = set()
    missed_steps: set[int] = set()
    warning = "No synthetic sensor telemetry gap."

    if name == "process-limit":
        observer, denied_count = _process_limit_events()
        sensor = [_sensor_event(event) for event in observer]
    elif name == "network-loss":
        observer, dropped_steps = _network_events(rng)
        sensor = [
            _sensor_event(event)
            for event in observer
            if event["step"] not in dropped_steps
        ]
    elif name == "telemetry-gap":
        observer = _telemetry_events()
        missed_steps = set(_TELEMETRY_GAP_STEPS)
        sensor = [
            _sensor_event(event)
            for event in observer
            if event["step"] not in missed_steps
        ]
        warning = (
            "Synthetic telemetry gap: sensor intentionally omits virtual steps 10..15; "
            "observer remains complete."
        )
    else:  # baseline
        observer = _baseline_events()
        sensor = [_sensor_event(event) for event in observer]

    return {
        "simulation": True,
        "scenario": name,
        "seed": seed,
        "virtual_step_count": _VIRTUAL_STEP_COUNT,
        "observer": observer,
        "sensor": sensor,
        "summary": {
            "simulation": True,
            "delivery_count": len(sensor),
            "drop_count": len(dropped_steps),
            "virtual_process_denied_count": denied_count,
            "fake_telemetry_missed_count": len(missed_steps),
        },
        "metadata": {
            "simulation": True,
            "sensor_warning": warning,
            "telemetry_gap_start_step": 10 if missed_steps else None,
            "telemetry_gap_end_step": 15 if missed_steps else None,
        },
        "limitations": _LIMITATIONS,
    }


__all__ = ["SCENARIO_NAMES", "run_scenario"]
