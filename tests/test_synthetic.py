"""Synthetic decoy coverage: obvious fakery, no execution, pattern records, separation."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import unittest

from reverse_shell_decoy.synthetic import (
    DEFAULT_SERVICES,
    PATTERN_COMMAND,
    PATTERN_CREDENTIAL,
    PATTERN_EMPTY,
    PATTERN_EXPLOIT,
    PATTERN_FINGERPRINT,
    PATTERN_PROBE,
    SOURCE_SYNTHETIC,
    SYNTHETIC_MARKER,
    SyntheticDecoyError,
    SyntheticFleet,
    SyntheticService,
    classify_line,
    exclude_synthetic,
    summarize_patterns,
)
from reverse_shell_decoy.throttle import InboundThrottle


def _service(**overrides) -> SyntheticService:
    defaults = dict(
        name="test service",
        port=0,
        banner=f"{SYNTHETIC_MARKER}: test banner, nothing real here\r\n",
        default_reply=f"{SYNTHETIC_MARKER}: canned reply, nothing executed\r\n",
        catalogue=(( "help", f"{SYNTHETIC_MARKER}: help is canned text\r\n"),),
    )
    defaults.update(overrides)
    return SyntheticService(**defaults)


class ServiceDefinitionTests(unittest.TestCase):
    def test_every_default_service_advertises_that_it_is_synthetic(self) -> None:
        for service in DEFAULT_SERVICES:
            self.assertIn(SYNTHETIC_MARKER, service.banner, service.name)
            self.assertIn(SYNTHETIC_MARKER, service.default_reply, service.name)
            for _, reply in service.catalogue:
                self.assertIn(SYNTHETIC_MARKER, reply, service.name)

    def test_default_services_claim_no_real_product_version(self) -> None:
        for service in DEFAULT_SERVICES:
            lowered = service.banner.lower()
            for real_product in ("openssh", "apache", "nginx", "redis-server", "mysql", "postgres"):
                self.assertNotIn(real_product, lowered, service.name)

    def test_a_banner_without_the_marker_is_refused(self) -> None:
        with self.assertRaises(SyntheticDecoyError):
            _service(banner="Welcome to a real service\r\n")
        with self.assertRaises(SyntheticDecoyError):
            _service(default_reply="ok\r\n")
        with self.assertRaises(SyntheticDecoyError):
            _service(catalogue=(("help", "no marker here"),))

    def test_invalid_ports_and_names_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            _service(port=70000)
        with self.assertRaises(SyntheticDecoyError):
            _service(name="")

    def test_fleet_refuses_duplicate_names_and_ports(self) -> None:
        with self.assertRaises(SyntheticDecoyError):
            SyntheticFleet([_service(name="a"), _service(name="a")], allow_ephemeral_ports=True)
        with self.assertRaises(SyntheticDecoyError):
            SyntheticFleet(
                [_service(name="a", port=1234), _service(name="b", port=1234)]
            )

    def test_fixed_ephemeral_port_is_refused_outside_tests(self) -> None:
        with self.assertRaises(SyntheticDecoyError):
            SyntheticFleet([_service(port=0)])

    def test_public_bind_needs_an_explicit_opt_in(self) -> None:
        with self.assertRaises(SyntheticDecoyError):
            SyntheticFleet([_service()], host="0.0.0.0", allow_ephemeral_ports=True)
        fleet = SyntheticFleet(
            [_service()], host="0.0.0.0", allow_public=True, allow_ephemeral_ports=True
        )
        self.assertTrue(fleet.allow_public)
        self.assertFalse(fleet.as_dict()["loopback_only"])


class PatternClassificationTests(unittest.TestCase):
    def test_categories_are_shape_labels(self) -> None:
        self.assertEqual(classify_line(""), PATTERN_EMPTY)
        self.assertEqual(classify_line("hello there"), PATTERN_PROBE)
        self.assertEqual(classify_line("USER admin"), PATTERN_CREDENTIAL)
        self.assertEqual(classify_line("cat notes.txt"), PATTERN_COMMAND)
        self.assertEqual(classify_line("cat /etc/passwd"), PATTERN_EXPLOIT)
        self.assertEqual(classify_line("../../../etc/passwd"), PATTERN_EXPLOIT)
        self.assertEqual(classify_line("GET / HTTP/1.1 nmap"), PATTERN_FINGERPRINT)

    def test_exploit_shapes_win_over_generic_command_shapes(self) -> None:
        self.assertEqual(classify_line("; cat ../etc/passwd"), PATTERN_EXPLOIT)

    def test_fingerprint_shapes_win_over_command_shapes(self) -> None:
        self.assertEqual(classify_line("curl/8.0 id"), PATTERN_FINGERPRINT)

    def test_labels_never_describe_intent(self) -> None:
        for word in ("malicious", "attacker", "hacker", "skilled"):
            self.assertNotIn(word, classify_line("nmap").lower())


class FleetSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fleets: list[SyntheticFleet] = []
        self.writers: list[asyncio.StreamWriter] = []

    async def asyncTearDown(self) -> None:
        for writer in self.writers:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
        for fleet in reversed(self.fleets):
            await fleet.stop()

    async def _start(self, services=None, **kwargs) -> tuple[SyntheticFleet, int]:
        kwargs.setdefault("max_runtime", 5)
        fleet = SyntheticFleet(
            services or [_service()], allow_ephemeral_ports=True, **kwargs
        )
        self.fleets.append(fleet)
        await fleet.start()
        return fleet, fleet.bound_ports[0]

    async def _connect(self, port: int):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    def _records(self, fleet: SyntheticFleet, kind: str) -> list[dict]:
        return [record for record in fleet.audit if record["kind"] == kind]

    async def test_visitor_is_told_immediately_that_the_service_is_synthetic(self) -> None:
        fleet, port = await self._start()
        reader, _ = await self._connect(port)
        banner = await asyncio.wait_for(reader.readline(), timeout=1)
        self.assertIn(SYNTHETIC_MARKER.encode(), banner)

    async def test_replies_come_from_the_canned_catalogue(self) -> None:
        fleet, port = await self._start()
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.write(b"help\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readline(), timeout=1)
        self.assertIn(b"help is canned text", reply)
        self.assertIn(SYNTHETIC_MARKER.encode(), reply)

    async def test_session_record_is_derived_facts_only_by_default(self) -> None:
        fleet, port = await self._start()
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.write(b"LOGIN root\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.close()
        for _ in range(100):
            if self._records(fleet, "synthetic_session"):
                break
            await asyncio.sleep(0.01)
        record = self._records(fleet, "synthetic_session")[0]
        self.assertEqual(record["patterns"], {PATTERN_CREDENTIAL: 1})
        self.assertNotIn("payload_b64", record)
        self.assertEqual(len(record["first_line_sha256"]), 64)
        self.assertFalse(record["executed_anything"])
        self.assertFalse(record["authenticated_anything"])
        self.assertFalse(record["stored_anything"])
        self.assertNotIn("root", json.dumps(record))

    async def test_capture_records_the_bytes_only_when_asked(self) -> None:
        fleet, port = await self._start(capture_payloads=True)
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.write(b"probe-bytes\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.close()
        for _ in range(100):
            if self._records(fleet, "synthetic_session"):
                break
            await asyncio.sleep(0.01)
        record = self._records(fleet, "synthetic_session")[0]
        self.assertEqual(base64.b64decode(record["payload_b64"]), b"probe-bytes\n")
        self.assertEqual(record["captured_bytes"], len(b"probe-bytes\n"))

    async def test_session_input_budget_closes_the_session(self) -> None:
        fleet, port = await self._start(max_session_input_bytes=8)
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.write(b"x" * 64 + b"\n")
        with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
            await writer.drain()
        for _ in range(100):
            if self._records(fleet, "synthetic_session"):
                break
            await asyncio.sleep(0.01)
        record = self._records(fleet, "synthetic_session")[0]
        self.assertEqual(record["closed_reason"], "session input budget exhausted")

    async def test_throttled_peer_is_refused_without_a_banner(self) -> None:
        throttle = InboundThrottle(connects_per_second=1, connects_per_second_per_peer=1, burst_multiplier=1.0)
        fleet, port = await self._start(throttle=throttle)
        first, _ = await self._connect(port)
        await asyncio.wait_for(first.readline(), timeout=1)
        second, second_writer = await self._connect(port)
        data = await asyncio.wait_for(second.read(16), timeout=1)
        self.assertEqual(data, b"")
        for _ in range(100):
            if self._records(fleet, "synthetic_throttled"):
                break
            await asyncio.sleep(0.01)
        record = self._records(fleet, "synthetic_throttled")[0]
        self.assertIn("reason", record)
        self.assertEqual(fleet.as_dict()["throttle_denials"], 1)

    async def test_concurrent_session_limit_is_reported(self) -> None:
        fleet, port = await self._start(max_sessions=1)
        first, _ = await self._connect(port)
        await asyncio.wait_for(first.readline(), timeout=1)
        second, _ = await self._connect(port)
        data = await asyncio.wait_for(second.read(16), timeout=1)
        self.assertEqual(data, b"")
        for _ in range(100):
            if self._records(fleet, "synthetic_rejected"):
                break
            await asyncio.sleep(0.01)
        self.assertIn("concurrent session limit reached", json.dumps(fleet.audit))

    async def test_every_record_is_marked_as_synthetic_activity(self) -> None:
        fleet, port = await self._start()
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.close()
        await asyncio.sleep(0.05)
        self.assertTrue(fleet.audit)
        for record in fleet.audit:
            self.assertTrue(record["synthetic"])
            self.assertTrue(record["not_host_activity"])
            self.assertEqual(record["source"], SOURCE_SYNTHETIC)

    async def test_runtime_limit_stops_the_fleet_by_itself(self) -> None:
        fleet, _ = await self._start(max_runtime=0.05)
        await asyncio.sleep(0.15)
        kinds = [record["kind"] for record in fleet.audit]
        self.assertIn("synthetic_fleet_stopped", kinds)

    async def test_summary_separates_synthetic_from_real_activity(self) -> None:
        fleet, port = await self._start()
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.write(b"id\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=1)
        writer.close()
        await asyncio.sleep(0.05)
        report = fleet.as_dict()
        self.assertTrue(report["synthetic"])
        self.assertTrue(report["not_host_activity"])
        self.assertFalse(report["executed_anything"])
        self.assertEqual(report["pattern_counts"][PATTERN_COMMAND], 1)
        self.assertIn("synthetic interactions, not host activity", report["notice"])


class SeparationTests(unittest.TestCase):
    def test_exclude_synthetic_keeps_real_records_only(self) -> None:
        records = [
            {"kind": "process", "pid": 1},
            {"kind": "synthetic_session", "synthetic": True},
            {"kind": "listener", "source": SOURCE_SYNTHETIC},
            {"kind": "listener", "port": 22},
        ]
        kept = exclude_synthetic(records)
        self.assertEqual([record.get("port", record["kind"]) for record in kept], ["process", 22])

    def test_summary_only_counts_synthetic_sessions(self) -> None:
        records = [
            {"kind": "synthetic_session", "peer": "127.0.0.1", "patterns": {PATTERN_CREDENTIAL: 2}},
            {"kind": "synthetic_session", "peer": "127.0.0.2", "patterns": {PATTERN_EXPLOIT: 1}},
            {"kind": "process", "patterns": {PATTERN_EXPLOIT: 99}},
        ]
        summary = summarize_patterns(records)
        self.assertEqual(summary["sessions"], 2)
        self.assertEqual(summary["distinct_peers"], 2)
        self.assertEqual(summary["pattern_counts"][PATTERN_CREDENTIAL], 2)
        self.assertEqual(summary["pattern_counts"][PATTERN_EXPLOIT], 1)
        self.assertTrue(summary["shape_only"])
        self.assertTrue(summary["not_host_activity"])


if __name__ == "__main__":
    unittest.main()
