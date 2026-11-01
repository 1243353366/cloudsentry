"""Loopback and fake-clock coverage for shared inbound pacing.

These tests never leave the loopback interface: they measure how many
connections or input units this operator's own listener admits under a fixed
budget, not anything about a remote peer.
"""
from __future__ import annotations

import asyncio
import contextlib
import unittest

from reverse_shell_decoy.honeypot import DecoyServer
from reverse_shell_decoy.throttle import InboundThrottle, peer_bucket_key


class _Clock:
    """A monotonic clock the test controls explicitly."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ThrottleMathTests(unittest.TestCase):
    def test_burst_then_refill_bounds_one_peer(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second=2, connects_per_second_per_peer=1,
                                   burst_multiplier=2.0, clock=clock)
        # Burst is rate * multiplier, so two connections fit immediately.
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertEqual(throttle.admit_connection("203.0.113.9"), "peer_connect_rate")
        clock.advance(1.0)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))

    def test_distinct_peers_have_separate_allowances(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, connects_per_second=100,
                                   burst_multiplier=1.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertEqual(throttle.admit_connection("203.0.113.9"), "peer_connect_rate")
        self.assertIsNone(throttle.admit_connection("203.0.113.10"))

    def test_global_ceiling_applies_across_peers(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second=1, connects_per_second_per_peer=10,
                                   burst_multiplier=1.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertEqual(throttle.admit_connection("203.0.113.10"), "global_connect_rate")
        clock.advance(1.0)
        self.assertIsNone(throttle.admit_connection("203.0.113.10"))

    def test_unit_admission_is_independent_of_connection_admission(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, units_per_second_per_peer=1,
                                   burst_multiplier=1.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertIsNone(throttle.admit_unit("203.0.113.9"))
        self.assertEqual(throttle.admit_unit("203.0.113.9"), "peer_unit_rate")
        clock.advance(1.0)
        self.assertIsNone(throttle.admit_unit("203.0.113.9"))

    def test_ipv6_peers_are_grouped_by_sixty_four(self) -> None:
        self.assertEqual(peer_bucket_key("2001:db8:1:2::1"), peer_bucket_key("2001:db8:1:2:ffff::9"))
        self.assertNotEqual(peer_bucket_key("2001:db8:1:2::1"), peer_bucket_key("2001:db8:1:3::1"))
        self.assertEqual(peer_bucket_key("::ffff:203.0.113.9"), peer_bucket_key("203.0.113.9"))
        self.assertEqual(peer_bucket_key("fe80::1%eth0"), peer_bucket_key("fe80::1"))

        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, connects_per_second=100,
                                   burst_multiplier=1.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("2001:db8:1:2::1"))
        self.assertEqual(throttle.admit_connection("2001:db8:1:2:ffff::9"), "peer_connect_rate")
        self.assertIsNone(throttle.admit_connection("2001:db8:1:3::1"))

    def test_malformed_peer_values_collapse_to_one_bucket(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, connects_per_second=100,
                                   burst_multiplier=1.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("not-an-address"))
        self.assertEqual(throttle.admit_connection("also-not-an-address"), "peer_connect_rate")
        self.assertEqual(peer_bucket_key(""), "unknown")

    def test_full_peer_table_refuses_new_sources_instead_of_evicting(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, connects_per_second=100,
                                   burst_multiplier=1.0, max_tracked_peers=1, clock=clock)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        self.assertEqual(throttle.admit_connection("203.0.113.10"), "peer_tracking_capacity")
        # The tracked, already-throttled peer keeps its drained bucket.
        self.assertEqual(throttle.admit_connection("203.0.113.9"), "peer_connect_rate")

    def test_idle_fully_refilled_buckets_are_reaped(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, connects_per_second=100,
                                   burst_multiplier=1.0, max_tracked_peers=1,
                                   max_peer_idle_seconds=5.0, clock=clock)
        self.assertIsNone(throttle.admit_connection("203.0.113.9"))
        clock.advance(6.0)
        self.assertIsNone(throttle.admit_connection("203.0.113.10"))

    def test_snapshot_reports_counters_without_addresses(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second_per_peer=1, burst_multiplier=1.0, clock=clock)
        throttle.admit_connection("203.0.113.9")
        throttle.admit_connection("203.0.113.9")
        snapshot = throttle.snapshot()
        self.assertEqual(snapshot["counters"]["accepted_connections"], 1)
        self.assertEqual(snapshot["counters"]["denied_connections"], 1)
        self.assertEqual(snapshot["tracked_peer_buckets"], 1)
        self.assertNotIn("203.0.113.9", repr(snapshot))

    def test_invalid_configuration_is_rejected(self) -> None:
        for kwargs in (
            {"connects_per_second": 0},
            {"connects_per_second": True},
            {"connects_per_second": 5000},
            {"units_per_second_per_peer": -1},
            {"burst_multiplier": 0.5},
            {"max_tracked_peers": 0},
            {"max_peer_idle_seconds": 0},
            {"clock": "not-callable"},
        ):
            with self.assertRaises(ValueError):
                InboundThrottle(**kwargs)


class ListenerPacingTests(unittest.IsolatedAsyncioTestCase):
    """Exercise pacing against real loopback sockets only."""

    async def asyncSetUp(self) -> None:
        self.services: list[DecoyServer] = []
        self.writers: list[asyncio.StreamWriter] = []

    async def asyncTearDown(self) -> None:
        for writer in self.writers:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
        for service in reversed(self.services):
            await service.shutdown()

    async def _start(self, **kwargs: object) -> tuple[DecoyServer, int]:
        kwargs.setdefault("max_runtime", 5)
        service = DecoyServer(**kwargs)
        self.services.append(service)
        server = await service.start(port=0)
        return service, server.sockets[0].getsockname()[1]

    async def _connect(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    def _reasons(self, service: DecoyServer) -> list[str]:
        return [event.get("reason") for event in service.audit if event["event_type"] == "close"]

    async def _wait_until(self, predicate, message: str, timeout: float = 2.0) -> None:
        """Poll the event loop instead of assuming a handler already ran.

        An accepted-then-refused connection is handled by its own task, so a fixed
        sleep is a race under load; waiting on the observable condition is not.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if predicate():
                return
            await asyncio.sleep(0.01)
        raise AssertionError(message)

    async def test_one_listener_refuses_a_fast_connection_burst(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second=10, connects_per_second_per_peer=1,
                                   burst_multiplier=1.0, clock=clock)
        service, port = await self._start(max_sessions_total=10, throttle=throttle)

        first_reader, _ = await self._connect(port)
        banner = await asyncio.wait_for(first_reader.readuntil(b"# "), timeout=1)
        self.assertIn(b"Maintenance console", banner)

        for _ in range(3):
            await self._connect(port)
        await self._wait_until(
            lambda: service._throttle_denials == 3,
            "expected three refusals, saw %d" % service._throttle_denials,
        )
        self.assertEqual(self._reasons(service).count("peer_connect_rate"), 3)
        # Throttled peers never consume the lifetime connection allowance.
        self.assertEqual(service.connection_count, 1)
        self.assertEqual(service.budget_snapshot()["usage"]["accepted_connections"], 1)

    async def test_two_listeners_share_one_pacing_budget(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second=1, connects_per_second_per_peer=10,
                                   burst_multiplier=1.0, clock=clock)
        first_service, first_port = await self._start(throttle=throttle)
        second_service, second_port = await self._start(throttle=throttle)

        reader, _ = await self._connect(first_port)
        self.assertIn(b"Maintenance console", await asyncio.wait_for(reader.readuntil(b"# "), timeout=1))
        await self._connect(second_port)

        await self._wait_until(
            lambda: second_service._throttle_denials == 1,
            "second listener did not refuse the shared-budget peer",
        )
        self.assertEqual(first_service._throttle_denials, 0)
        self.assertEqual(self._reasons(second_service), ["global_connect_rate"])

    async def test_command_units_are_paced_per_source(self) -> None:
        clock = _Clock()
        throttle = InboundThrottle(connects_per_second=10, units_per_second=10,
                                   units_per_second_per_peer=1, burst_multiplier=1.0, clock=clock)
        service, port = await self._start(throttle=throttle)
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        writer.write(b"help\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)
        # The second command is refused by the shared allowance and the session
        # is closed without another response.
        writer.write(b"help\n")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")

        await self._wait_until(
            lambda: any(event.get("throttled") is True for event in service.audit),
            "throttled command record was not written",
        )
        throttled = [event for event in service.audit if event.get("throttled") is True]
        self.assertEqual(len(throttled), 1)
        self.assertEqual(throttled[0]["event_type"], "command")
        self.assertEqual(throttled[0]["reason"], "peer_unit_rate")
        self.assertEqual(service._throttled_units, 1)

    async def test_default_service_instance_stays_unpaced(self) -> None:
        service, _ = await self._start()
        self.assertIsNone(service.throttle)
        self.assertIsNone(service.capture)
        self.assertIsNone(service.pacing_snapshot()["throttle"])

    async def test_pacing_rejects_non_throttle_objects(self) -> None:
        with self.assertRaises(ValueError):
            DecoyServer(throttle="unlimited")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
