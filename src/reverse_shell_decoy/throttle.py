"""Shared inbound pacing for decoy listeners.

This module is deliberately inert: it holds token buckets in memory, reads a
caller-supplied monotonic clock, and returns an admission decision.  It opens no
socket, starts no thread, performs no I/O, and never sends, delays, or answers a
peer.  Pacing decisions only decide whether this operator's own listener accepts
another connection or another input unit right now.

One :class:`InboundThrottle` can be shared by several :class:`DecoyServer`
instances so that every listener draws from the same bounded allowance.  Without
a shared object, two listeners each admit their own quota and a single source can
multiply its admitted rate by the number of open ports.

Design constraints kept intentionally small:

* IPv4 peers are grouped by exact address; IPv6 peers are grouped by ``/64`` so a
  single host cannot rotate through its own subnet to reset a bucket.
* The peer table is bounded.  New peer keys are refused once it is full rather
  than evicting an already-throttled peer (eviction would let a spoofed-address
  flood hand a throttled peer a fresh bucket).
* Only counters and a peer-key count are ever exposed; no address is returned by
  :meth:`InboundThrottle.snapshot`.
"""

from __future__ import annotations

import ipaddress
import time
from collections import OrderedDict
from typing import Callable, Optional

MAX_BURST_MULTIPLIER = 10.0
MAX_TRACKED_PEERS_LIMIT = 65536


def peer_bucket_key(peer_ip: str) -> str:
    """Return a stable, non-identifying bucket key for an observed peer address.

    Unknown or non-address values collapse to ``unknown`` so malformed input
    cannot create unbounded distinct buckets.
    """
    if not isinstance(peer_ip, str) or not peer_ip:
        return "unknown"
    text = peer_ip.split("%", 1)[0].strip().strip("[]")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if address.version == 6:
        mapped = address.ipv4_mapped
        if mapped is not None:
            return "v4:" + str(mapped)
        network = ipaddress.ip_network("%s/64" % address, strict=False)
        return "v6:%s/64" % network.network_address
    return "v4:" + str(address)


class _Bucket:
    """One token bucket; refilled lazily from a monotonic clock."""

    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, now: float) -> None:
        self.tokens = tokens
        self.updated = now


class InboundThrottle:
    """Token-bucket admission control shared by every listener that receives it.

    ``connects_per_second`` and ``units_per_second`` are global ceilings across
    the listeners that share this object.  The ``*_per_peer`` values cap what one
    source key may consume from that shared ceiling.  Burst capacity defaults to
    ``burst_multiplier`` times the rate, so short interactive sessions are never
    penalized while sustained floods are still bounded.

    Denials are reported as stable reason labels; they never include the peer
    address and never change the peer's transport beyond the caller closing it.
    """

    def __init__(
        self,
        *,
        connects_per_second: int = 32,
        connects_per_second_per_peer: int = 8,
        units_per_second: int = 64,
        units_per_second_per_peer: int = 16,
        burst_multiplier: float = 2.0,
        max_tracked_peers: int = 2048,
        max_peer_idle_seconds: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.connects_per_second = _positive_int("connects_per_second", connects_per_second)
        self.connects_per_second_per_peer = _positive_int(
            "connects_per_second_per_peer", connects_per_second_per_peer
        )
        self.units_per_second = _positive_int("units_per_second", units_per_second)
        self.units_per_second_per_peer = _positive_int(
            "units_per_second_per_peer", units_per_second_per_peer
        )
        self.burst_multiplier = _bounded_float("burst_multiplier", burst_multiplier)
        self.max_tracked_peers = _bounded_int("max_tracked_peers", max_tracked_peers)
        self.max_peer_idle_seconds = _bounded_float("max_peer_idle_seconds", max_peer_idle_seconds)
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock

        now = self._now()
        self._global_connects = _Bucket(self._burst(self.connects_per_second), now)
        self._global_units = _Bucket(self._burst(self.units_per_second), now)
        self._peers: "OrderedDict[str, dict[str, _Bucket]]" = OrderedDict()
        self._accepted_connections = 0
        self._denied_connections = 0
        self._accepted_units = 0
        self._denied_units = 0

    # -- public admission API -------------------------------------------------

    def admit_connection(self, peer_ip: str) -> Optional[str]:
        """Admit or refuse one inbound connection; return a reason label or None."""
        return self._admit(peer_ip, "connects", self.connects_per_second,
                           self.connects_per_second_per_peer, self._global_connects)

    def admit_unit(self, peer_ip: str) -> Optional[str]:
        """Admit or refuse one inbound command/chunk; return a reason label or None."""
        return self._admit(peer_ip, "units", self.units_per_second,
                           self.units_per_second_per_peer, self._global_units)

    def snapshot(self) -> dict[str, object]:
        """Return bounded counters only; no peer address or key is included."""
        return {
            "limits": {
                "connects_per_second": self.connects_per_second,
                "connects_per_second_per_peer": self.connects_per_second_per_peer,
                "units_per_second": self.units_per_second,
                "units_per_second_per_peer": self.units_per_second_per_peer,
                "max_tracked_peers": self.max_tracked_peers,
            },
            "counters": {
                "accepted_connections": self._accepted_connections,
                "denied_connections": self._denied_connections,
                "accepted_units": self._accepted_units,
                "denied_units": self._denied_units,
            },
            "tracked_peer_buckets": len(self._peers),
        }

    # -- internals ------------------------------------------------------------

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("clock must return a number")
        return float(value)

    def _burst(self, rate: int) -> float:
        return float(rate) * self.burst_multiplier

    def _admit(
        self,
        peer_ip: str,
        family: str,
        rate: int,
        per_peer_rate: int,
        global_bucket: _Bucket,
    ) -> Optional[str]:
        now = self._now()
        key = peer_bucket_key(peer_ip)
        peer = self._peer_buckets(key, per_peer_rate, now)
        if peer is None:
            self._count(family, accepted=False)
            return "peer_tracking_capacity"
        bucket = peer[family]
        if not _take(bucket, per_peer_rate, self._burst(per_peer_rate), now):
            self._count(family, accepted=False)
            return "peer_%s_rate" % ("connect" if family == "connects" else "unit")
        if not _take(global_bucket, rate, self._burst(rate), now):
            # Refund the per-peer token so a global ceiling does not silently
            # starve one peer's allowance for the rest of the window.
            bucket.tokens = min(self._burst(per_peer_rate), bucket.tokens + 1.0)
            self._count(family, accepted=False)
            return "global_%s_rate" % ("connect" if family == "connects" else "unit")
        self._count(family, accepted=True)
        return None

    def _count(self, family: str, *, accepted: bool) -> None:
        if family == "connects":
            if accepted:
                self._accepted_connections += 1
            else:
                self._denied_connections += 1
        else:
            if accepted:
                self._accepted_units += 1
            else:
                self._denied_units += 1

    def _peer_buckets(self, key: str, per_peer_rate: int, now: float) -> Optional[dict[str, _Bucket]]:
        existing = self._peers.get(key)
        if existing is not None:
            self._peers.move_to_end(key)
            return existing
        self._reap(now)
        if len(self._peers) >= self.max_tracked_peers:
            # Fail closed rather than evicting a peer that is already being
            # throttled.  A new source is refused until older buckets age out.
            return None
        created = {
            "connects": _Bucket(self._burst(per_peer_rate), now),
            "units": _Bucket(self._burst(self.units_per_second_per_peer), now),
        }
        self._peers[key] = created
        return created

    def _reap(self, now: float) -> None:
        """Drop only fully refilled, long-idle buckets so the table stays bounded."""
        if not self._peers:
            return
        for key in list(self._peers)[:64]:
            buckets = self._peers[key]
            # Measure idleness before refilling, because refilling stamps a new
            # update time and would otherwise make an idle peer look busy.
            idle = now - max(bucket.updated for bucket in buckets.values())
            for name, rate in (
                ("connects", self.connects_per_second_per_peer),
                ("units", self.units_per_second_per_peer),
            ):
                _refill(buckets[name], rate, self._burst(rate), now)
            refilled = all(
                bucket.tokens >= self._burst(rate) - 1e-9
                for bucket, rate in (
                    (buckets["connects"], self.connects_per_second_per_peer),
                    (buckets["units"], self.units_per_second_per_peer),
                )
            )
            if refilled and idle >= self.max_peer_idle_seconds:
                del self._peers[key]
            else:
                break


def _refill(bucket: _Bucket, rate: int, burst: float, now: float) -> None:
    """Top a bucket up from elapsed monotonic time; never overfill it."""
    if now > bucket.updated:
        bucket.tokens = min(burst, bucket.tokens + (now - bucket.updated) * float(rate))
        bucket.updated = now


def _take(bucket: _Bucket, rate: int, burst: float, now: float) -> bool:
    """Refill then consume one token, or report that the bucket is empty."""
    _refill(bucket, rate, burst, now)
    if bucket.tokens >= 1.0:
        bucket.tokens -= 1.0
        return True
    return False


def _positive_int(name: str, value: object) -> int:
    minimum, maximum = _INT_LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % name)
    if not minimum <= value <= maximum:
        raise ValueError("%s must be between %d and %d" % (name, minimum, maximum))
    return value


_INT_LIMITS = {
    "connects_per_second": (1, 1000),
    "connects_per_second_per_peer": (1, 1000),
    "units_per_second": (1, 1000),
    "units_per_second_per_peer": (1, 1000),
    "max_tracked_peers": (1, MAX_TRACKED_PEERS_LIMIT),
}


def _bounded_int(name: str, value: object) -> int:
    return _positive_int(name, value)


def _bounded_float(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("%s must be a number" % name)
    number = float(value)
    if name == "burst_multiplier":
        if not 1.0 <= number <= MAX_BURST_MULTIPLIER:
            raise ValueError("burst_multiplier must be between 1 and %g" % MAX_BURST_MULTIPLIER)
        return number
    if not 1.0 <= number <= 86400.0:
        raise ValueError("max_peer_idle_seconds must be between 1 and 86400")
    return number
