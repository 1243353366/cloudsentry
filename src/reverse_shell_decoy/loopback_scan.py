"""Bounded loopback-only port scan for corroborating the listener inventory.

An inventory read from procfs answers "what does this kernel say is bound".
A local connection attempt answers a different question: "does something here
actually accept a connection on that port". Neither answer is complete, and
disagreement between them is often more informative than either one alone.

This module therefore only ever connects to loopback addresses on this machine:

* ``127.0.0.0/8`` and ``::1`` are accepted; every other target raises
  :class:`LoopbackOnlyError`. Remote scanning, range sweeps of a network,
  host discovery, service/version probing and OS fingerprinting are refused by
  construction, not by configuration, so no flag or environment variable can
  turn this module into a network scanner.
* Each attempt is a plain TCP connect with a short timeout, immediately closed,
  and no bytes are ever written to the peer.
* Port count, per-port timeout, total deadline and pacing are bounded, and the
  result carries an explicit completeness verdict: a scan stopped by its
  deadline is ``PARTIAL`` and never reported as "everything else is closed".

The tool deliberately does not depend on ``nmap``. Operators who already have
it can run ``nmap -sT -Pn -p1-65535 127.0.0.1`` themselves; the built-in
scanner exists so the audit path has no external binary requirement and no
output format that has to be trusted blindly. See ``docs/loopback-scan.md``.
"""

from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

LOOPBACK_ONLY_NOTICE = (
    "This scanner connects only to loopback addresses on this machine. "
    "Remote hosts, network ranges and service fingerprinting are not supported."
)

MAX_PORTS = 4096
MAX_TIMEOUT_SECONDS = 2.0
MAX_DEADLINE_SECONDS = 120.0
MAX_PACING_DELAY_MS = 1000

STATE_OPEN = "OPEN"
STATE_CLOSED = "CLOSED"
STATE_NO_ANSWER = "NO_ANSWER"
STATE_UNSCANNED = "UNSCANNED"

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_PARTIAL = "PARTIAL"

LIMITATION_NOTICE = (
    "An OPEN result proves that something on this machine accepted a connection "
    "on that port during the scan. A CLOSED or NO_ANSWER result does not prove "
    "that no process is bound: a different network namespace, a firewall rule, a "
    "full accept backlog, or a socket owned by another user all hide a live "
    "listener from this scan. Only the listener inventory read in the same "
    "window is a binding record, and only a COMPLETE scan may be quoted as "
    "full coverage of the scanned port range."
)


class LoopbackOnlyError(ValueError):
    """Raised when a caller asks to scan anything other than loopback."""


def _require_int(name: str, value: object, maximum: int, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_seconds(name: str, value: object, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    if not (0.0 < number <= maximum):
        raise ValueError(f"{name} must be greater than 0 and at most {maximum}")
    return number


def is_loopback_host(host: str) -> bool:
    """Return whether ``host`` is a loopback literal or ``localhost``.

    Hostnames are not resolved: only the literal ``localhost`` and textual
    loopback addresses qualify, so a DNS name can never be redirected to a
    remote address and pass this check.
    """

    if not isinstance(host, str) or not host:
        return False
    candidate = host.strip().lower()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate == "localhost":
        return True
    if candidate == "::1":
        return True
    if candidate.count(":") == 0 and candidate.count(".") == 3:
        first = candidate.split(".", 1)[0]
        return first == "127" and all(part.isdigit() for part in candidate.split("."))
    return False


def parse_port_spec(spec: str, *, max_ports: int = MAX_PORTS) -> Tuple[int, ...]:
    """Parse ``"22,80,1000-1010"`` into a sorted, de-duplicated port tuple.

    Ranges may be written either way round. More than ``max_ports`` distinct
    ports is refused rather than truncated, because a silently truncated scan
    would look complete.
    """

    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("port spec must be a non-empty string")
    ports: set[int] = set()
    for chunk in spec.split(","):
        item = chunk.strip()
        if not item:
            raise ValueError("port spec contains an empty element")
        if "-" in item:
            low_text, _, high_text = item.partition("-")
            low = _require_int("range start", int(low_text), 65535)
            high = _require_int("range end", int(high_text), 65535)
            if low > high:
                low, high = high, low
            if high - low + 1 > max_ports:
                raise ValueError(f"range {item} exceeds the {max_ports} port limit")
            ports.update(range(low, high + 1))
        else:
            ports.add(_require_int("port", int(item), 65535))
        if len(ports) > max_ports:
            raise ValueError(f"port spec exceeds the {max_ports} port limit")
    return tuple(sorted(ports))


@dataclass(frozen=True)
class PortObservation:
    """One bounded connect attempt against one loopback port."""

    port: int
    state: str
    latency_ms: int
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "port": self.port,
            "state": self.state,
            "latency_ms": self.latency_ms,
        }
        if self.error:
            payload["error"] = self.error
        return payload


@dataclass
class LoopbackScanResult:
    """Immutable-in-practice scan result with an explicit completeness verdict."""

    host: str
    ports_scanned: int = 0
    observations: List[PortObservation] = field(default_factory=list)
    completeness: str = COMPLETENESS_PARTIAL
    statement: str = ""
    started_at_utc: str = ""
    duration_ms: int = 0
    deadline_reached: bool = False
    unscanned_ports: int = 0

    @property
    def open_ports(self) -> Tuple[int, ...]:
        return tuple(item.port for item in self.observations if item.state == STATE_OPEN)

    def as_dict(self) -> Dict[str, Any]:
        by_state: Dict[str, int] = {}
        for observation in self.observations:
            by_state[observation.state] = by_state.get(observation.state, 0) + 1
        return {
            "kind": "loopback_scan",
            "scanned_at_utc": self.started_at_utc,
            "host": self.host,
            "ports_scanned": self.ports_scanned,
            "state_counts": by_state,
            "open_ports": list(self.open_ports),
            "observations": [item.as_dict() for item in self.observations],
            "completeness": self.completeness,
            "statement": self.statement,
            "duration_ms": self.duration_ms,
            "deadline_reached": self.deadline_reached,
            "unscanned_ports": self.unscanned_ports,
            "active_network_activity": True,
            "remote_targets": False,
            "limitation_notice": LIMITATION_NOTICE,
        }


def _utc_now_text() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _classify(error_number: int) -> str:
    if error_number == 0:
        return STATE_OPEN
    if error_number in (errno.ECONNREFUSED, errno.ECONNRESET):
        return STATE_CLOSED
    return STATE_NO_ANSWER


def scan_loopback(
    ports: Iterable[int],
    *,
    host: str = "127.0.0.1",
    timeout: float = 0.25,
    deadline_seconds: float = 30.0,
    pacing_delay_ms: int = 0,
    max_ports: int = MAX_PORTS,
) -> LoopbackScanResult:
    """Connect-scan loopback ports and report what answered.

    Args:
        ports: Port numbers to try. At most ``max_ports`` are accepted.
        host: A loopback address or ``localhost``. Anything else raises
            :class:`LoopbackOnlyError`.
        timeout: Per-port connect timeout in seconds.
        deadline_seconds: Total wall-clock budget. Reaching it stops the scan and
            marks the result ``PARTIAL``.
        pacing_delay_ms: Optional sleep between attempts, to keep a scan gentle
            on a host that is already loaded.
        max_ports: Upper bound on how many ports may be requested.

    Returns:
        :class:`LoopbackScanResult` with per-port observations, a completeness
        verdict, and a statement suitable for quoting in a report.
    """

    if not is_loopback_host(host):
        raise LoopbackOnlyError(LOOPBACK_ONLY_NOTICE)
    per_port_timeout = _require_seconds("timeout", timeout, MAX_TIMEOUT_SECONDS)
    deadline = _require_seconds("deadline_seconds", deadline_seconds, MAX_DEADLINE_SECONDS)
    pacing_ms = _require_int("pacing_delay_ms", pacing_delay_ms, MAX_PACING_DELAY_MS, minimum=0)
    limit = _require_int("max_ports", max_ports, MAX_PORTS, minimum=1)

    targets: List[int] = []
    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("ports must be integers between 1 and 65535")
        targets.append(port)
    if not targets:
        raise ValueError("at least one port is required")
    if len(targets) > limit:
        raise ValueError(f"port count exceeds the {limit} port limit")

    started = time.monotonic()
    started_text = _utc_now_text()
    observations: List[PortObservation] = []
    unscanned = 0
    deadline_reached = False
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    target_host = host.strip("[]")

    for index, port in enumerate(targets):
        if time.monotonic() - started >= deadline:
            deadline_reached = True
            unscanned = len(targets) - index
            break
        attempt_started = time.monotonic()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(per_port_timeout)
        try:
            code = sock.connect_ex((target_host, port))
            state = _classify(code)
            error = "" if code == 0 else errno.errorcode.get(code, str(code))
        except OSError as exc:
            state = STATE_NO_ANSWER
            error = type(exc).__name__
        finally:
            sock.close()
        latency_ms = int((time.monotonic() - attempt_started) * 1000)
        observations.append(PortObservation(port=port, state=state, latency_ms=latency_ms, error=error))
        if pacing_ms:
            time.sleep(pacing_ms / 1000.0)

    duration_ms = int((time.monotonic() - started) * 1000)
    no_answer = sum(1 for item in observations if item.state == STATE_NO_ANSWER)
    if deadline_reached or unscanned:
        completeness = COMPLETENESS_PARTIAL
        statement = (
            f"Scanned {len(observations)} of {len(targets)} requested loopback ports before the "
            f"deadline; {unscanned} port(s) were never attempted, so this is not full coverage."
        )
    elif no_answer:
        completeness = COMPLETENESS_PARTIAL
        statement = (
            f"All {len(targets)} loopback ports were attempted, but {no_answer} gave no answer "
            "within the timeout, so their state is unknown rather than closed."
        )
    else:
        completeness = COMPLETENESS_COMPLETE
        statement = (
            f"All {len(targets)} requested loopback ports answered definitively in "
            f"{duration_ms} ms; the scan is complete for that port range only."
        )

    return LoopbackScanResult(
        host=target_host,
        ports_scanned=len(observations),
        observations=observations,
        completeness=completeness,
        statement=statement,
        started_at_utc=started_text,
        duration_ms=duration_ms,
        deadline_reached=deadline_reached,
        unscanned_ports=unscanned,
    )


def cross_check_inventory(
    result: LoopbackScanResult,
    inventory: Dict[str, Any],
) -> Dict[str, Any]:
    """Compare a loopback scan against a listener inventory read in the same window.

    Two kernel-visible views that disagree are reported as such. The function
    never concludes that a port is unauthorized; it reports an unexplained
    difference and leaves attribution to the operator.
    """

    observations = getattr(result, "observations", None)
    open_ports_attr = getattr(result, "open_ports", None)
    if not isinstance(observations, (list, tuple)) or not isinstance(open_ports_attr, (list, tuple)):
        raise ValueError("result must provide observations and open_ports")
    if not isinstance(inventory, dict):
        raise ValueError("inventory must be a mapping")

    inventory_ports: set[int] = set()
    for record in inventory.get("listeners") or []:
        if not isinstance(record, dict):
            continue
        port = record.get("port")
        if isinstance(port, int) and not isinstance(port, bool):
            inventory_ports.add(port)

    scanned_ports = {item.port for item in observations}
    open_ports = set(open_ports_attr)
    overlap = scanned_ports & inventory_ports

    answering_not_bound = sorted(open_ports - inventory_ports)
    bound_but_not_answering = sorted(overlap - open_ports)
    bound_but_not_scanned = sorted(inventory_ports - scanned_ports)
    agreed = sorted(overlap & open_ports)

    if answering_not_bound:
        statement = (
            "Something accepted a connection on ports the inventory did not show as bound; "
            "possible causes include a different network namespace, a socket created after the "
            "inventory read, or an inventory read that was not permitted."
        )
    elif bound_but_not_answering:
        statement = (
            "The inventory shows bindings that did not accept a loopback connection; possible "
            "causes include a full accept backlog, a firewall or netfilter rule, a listener bound "
            "to a non-loopback address only, or a socket in another user's context."
        )
    elif bound_but_not_scanned:
        statement = (
            "The inventory shows bindings outside the port range this scan covered; they were "
            "not probed, so the scan says nothing about them either way."
        )
    else:
        statement = "The scan and the inventory do not contradict each other for the ports both cover."

    return {
        "kind": "loopback_scan_cross_check",
        "scanned_ports": len(scanned_ports),
        "inventory_ports": len(inventory_ports),
        "overlap_ports": len(overlap),
        "agreed_ports": agreed,
        "answering_not_bound": answering_not_bound,
        "bound_but_not_answering": bound_but_not_answering,
        "bound_but_not_scanned": bound_but_not_scanned,
        "statement": statement,
        "attribution": "unresolved",
        "limitation_notice": LIMITATION_NOTICE,
    }


def nmap_equivalent_command(ports: Sequence[int] | str) -> str:
    """Return the operator-runnable nmap command equivalent to this scan.

    Provided for transparency: the built-in scanner and the nmap invocation are
    both loopback connect scans of this machine, and neither justifies probing a
    host the operator does not own.
    """

    if isinstance(ports, str):
        port_argument = ports
    else:
        values = [str(int(port)) for port in ports]
        port_argument = ",".join(values) if values else "1-65535"
    return f"nmap -sT -Pn -n -p{port_argument} 127.0.0.1"
