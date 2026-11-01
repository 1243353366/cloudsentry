"""Relay coverage: rotation, banner bounce, passive fingerprinting, loopback-only targets."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import unittest

from reverse_shell_decoy.relay import (
    FP_HTTP,
    FP_SHELL,
    FP_SSH,
    FP_TLS,
    FP_UNKNOWN,
    NO_THIRD_PARTY_TRANSIT,
    Presentation,
    RelayError,
    RelayFleet,
    RelayTarget,
    fingerprint_opening,
)
from reverse_shell_decoy.synthetic import SYNTHETIC_MARKER, SyntheticFleet, SyntheticService
from reverse_shell_decoy.throttle import InboundThrottle


def _backend_service(port: int = 0) -> SyntheticService:
    return SyntheticService(
        name="relay backend",
        port=port,
        banner=f"{SYNTHETIC_MARKER}: relay backend banner, nothing real here\r\n",
        default_reply=f"{SYNTHETIC_MARKER}: backend canned reply\r\n",
    )


class DefinitionTests(unittest.TestCase):
    def test_presentation_must_state_it_is_synthetic(self) -> None:
        with self.assertRaises(RelayError):
            Presentation("front", "welcome to a real service\r\n")
        with self.assertRaises(RelayError):
            Presentation("", f"{SYNTHETIC_MARKER} hello\r\n")
        Presentation("front", f"{SYNTHETIC_MARKER} hello\r\n")

    def test_target_validation_and_loopback_flag(self) -> None:
        self.assertTrue(RelayTarget("a", "127.0.0.1", 22022).loopback)
        self.assertFalse(RelayTarget("b", "10.1.2.3", 22).loopback)
        with self.assertRaises(ValueError):
            RelayTarget("c", "127.0.0.1", 0)
        with self.assertRaises(RelayError):
            RelayTarget("", "127.0.0.1", 22)

    def test_remote_targets_are_refused_by_default(self) -> None:
        with self.assertRaises(RelayError) as caught:
            RelayFleet([RelayTarget("remote", "192.0.2.5", 22)])
        self.assertIn("third party", str(caught.exception))

    def test_remote_target_can_only_be_enabled_explicitly(self) -> None:
        fleet = RelayFleet([RelayTarget("remote", "192.0.2.5", 22)], allow_non_loopback_target=True)
        self.assertEqual(fleet.as_dict()["target_scope"], "explicit_remote")

    def test_limits_are_validated(self) -> None:
        target = RelayTarget("a", "127.0.0.1", 22022)
        with self.assertRaises(RelayError):
            RelayFleet([])
        with self.assertRaises(RelayError):
            RelayFleet([target], presentations=[])
        with self.assertRaises(ValueError):
            RelayFleet([target], rotate_every_connections=0)
        with self.assertRaises(ValueError):
            RelayFleet([target], banner_bytes=2)
        with self.assertRaises(RelayError):
            RelayFleet([target], throttle="nope")


class FingerprintTests(unittest.TestCase):
    def test_ssh_identification_is_recognised_without_inferring_an_os(self) -> None:
        record = fingerprint_opening(b"SSH-2.0-OpenSSH_9.6\r\n")
        self.assertEqual(record["category"], FP_SSH)
        self.assertEqual(record["detail"], "SSH-2.0-OpenSSH_9.6")
        self.assertIsNone(record["inferred_operating_system"])

    def test_tls_client_hello_is_recognised(self) -> None:
        record = fingerprint_opening(b"\x16\x03\x01\x00\xa5")
        self.assertEqual(record["category"], FP_TLS)

    def test_http_request_and_client_software_are_extracted(self) -> None:
        record = fingerprint_opening(b"GET /admin HTTP/1.1\r\nUser-Agent: curl/8.4.0\r\n\r\n")
        self.assertEqual(record["category"], FP_HTTP)
        self.assertEqual(record["client_software"], "curl/8.4.0")

    def test_interactive_text_is_labelled_as_such(self) -> None:
        self.assertEqual(fingerprint_opening(b"whoami\n")["category"], FP_SHELL)

    def test_binary_of_unknown_shape_stays_unknown(self) -> None:
        self.assertEqual(fingerprint_opening(b"\x00\x01\x02\x03")["category"], FP_UNKNOWN)

    def test_empty_and_untyped_inputs(self) -> None:
        self.assertEqual(fingerprint_opening(b"")["length"], 0)
        with self.assertRaises(ValueError):
            fingerprint_opening("not bytes")

    def test_hash_is_recorded_and_detail_is_bound(self) -> None:
        record = fingerprint_opening(b"SSH-2.0-" + b"A" * 400 + b"\r\n")
        self.assertEqual(len(record["sha256"]), 64)
        self.assertLessEqual(len(record["detail"]), 48)


class RelaySessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fleets: list[RelayFleet] = []
        self.backends: list[SyntheticFleet] = []
        self.writers: list[asyncio.StreamWriter] = []

    async def asyncTearDown(self) -> None:
        for writer in self.writers:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
        for fleet in reversed(self.fleets):
            await fleet.stop()
        for backend in reversed(self.backends):
            await backend.stop()

    async def _start(self, backend_services=None, **kwargs):
        backend = SyntheticFleet(
            backend_services or [_backend_service()], allow_ephemeral_ports=True, max_runtime=10
        )
        await backend.start()
        self.backends.append(backend)
        targets = [
            RelayTarget(f"backend-{index}", "127.0.0.1", port)
            for index, port in enumerate(backend.bound_ports)
        ]
        kwargs.setdefault("max_runtime", 10)
        fleet = RelayFleet(targets, **kwargs)
        self.fleets.append(fleet)
        await fleet.start()
        return fleet, backend

    async def _connect(self, port: int):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    def _records(self, fleet: RelayFleet, kind: str) -> list[dict]:
        return [record for record in fleet.records if record["kind"] == kind]

    async def _wait(self, fleet: RelayFleet, kind: str, count: int = 1) -> list[dict]:
        for _ in range(200):
            records = self._records(fleet, kind)
            if len(records) >= count:
                return records
            await asyncio.sleep(0.01)
        raise AssertionError(f"expected {count} {kind} record(s)")

    async def test_front_greeting_says_synthetic_and_backend_banner_is_bounced(self) -> None:
        fleet, backend = await self._start()
        reader, writer = await self._connect(fleet.bound_port)
        greeting = await asyncio.wait_for(reader.read(200), timeout=1)
        self.assertIn(SYNTHETIC_MARKER.encode(), greeting)
        writer.write(b"hello\n")
        await writer.drain()
        bounced = await asyncio.wait_for(reader.read(400), timeout=1)
        combined = greeting + bounced
        self.assertIn(b"relay backend banner", combined)
        banners = self._records(fleet, "relay_banner")
        self.assertTrue(banners[0]["backend_banner_synthetic"])
        self.assertEqual(len(banners[0]["backend_banner_sha256"]), 64)

    async def test_peer_opening_is_fingerprinted_passively(self) -> None:
        fleet, _ = await self._start()
        reader, writer = await self._connect(fleet.bound_port)
        await asyncio.wait_for(reader.read(200), timeout=1)
        writer.write(b"POST /probe HTTP/1.1\r\nUser-Agent: zgrab/0.x\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        fingerprints = await self._wait(fleet, "relay_fingerprint")
        self.assertEqual(fingerprints[0]["category"], FP_HTTP)
        self.assertIsNone(fingerprints[0]["inferred_operating_system"])
        self.assertEqual(len(fingerprints[0]["sha256"]), 64)

    async def test_rotation_changes_the_front_presentation_and_is_recorded(self) -> None:
        fleet, _ = await self._start(rotate_every_connections=1)
        first, first_writer = await self._connect(fleet.bound_port)
        await asyncio.wait_for(first.read(200), timeout=1)
        second, second_writer = await self._connect(fleet.bound_port)
        greeting = await asyncio.wait_for(second.read(200), timeout=1)
        rotations = await self._wait(fleet, "relay_rotated")
        self.assertEqual(rotations[0]["from_presentation"], "front-a")
        self.assertEqual(rotations[0]["to_presentation"], "front-b")
        self.assertIn(b"front proxy B", greeting)

    async def test_time_based_rotation_also_applies(self) -> None:
        fleet, _ = await self._start(rotate_every_connections=100, rotate_every_seconds=0.05)
        first, _ = await self._connect(fleet.bound_port)
        await asyncio.wait_for(first.read(200), timeout=1)
        await asyncio.sleep(0.08)
        second, _ = await self._connect(fleet.bound_port)
        await asyncio.wait_for(second.read(200), timeout=1)
        rotations = await self._wait(fleet, "relay_rotated")
        self.assertEqual(rotations[0]["reason"], "time budget")

    async def test_payload_capture_is_opt_in(self) -> None:
        fleet, _ = await self._start(capture_payloads=True)
        reader, writer = await self._connect(fleet.bound_port)
        await asyncio.wait_for(reader.read(200), timeout=1)
        writer.write(b"capture-me\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
        sessions = await self._wait(fleet, "relay_session")
        self.assertEqual(base64.b64decode(sessions[0]["payload_b64"]), b"capture-me\n")
        self.assertEqual(sessions[0]["captured_bytes"], len(b"capture-me\n"))

    async def test_session_record_states_no_third_party_transit(self) -> None:
        fleet, _ = await self._start()
        reader, writer = await self._connect(fleet.bound_port)
        await asyncio.wait_for(reader.read(200), timeout=1)
        writer.close()
        sessions = await self._wait(fleet, "relay_session")
        record = sessions[0]
        self.assertFalse(record["third_party_transit"])
        self.assertFalse(record["executed_anything"])
        self.assertTrue(record["no_third_party_transit"])
        self.assertNotIn("payload_b64", record)
        self.assertTrue(all(record_item["relay"] for record_item in fleet.records))

    async def test_unreachable_target_is_reported_not_hidden(self) -> None:
        fleet = RelayFleet(
            [RelayTarget("dead", "127.0.0.1", 9)], max_runtime=10
        )
        self.fleets.append(fleet)
        await fleet.start()
        reader, writer = await self._connect(fleet.bound_port)
        await asyncio.sleep(0.2)
        records = await self._wait(fleet, "relay_target_unreachable")
        self.assertEqual(records[0]["target"], "dead")

    async def test_throttled_peer_gets_no_banner(self) -> None:
        throttle = InboundThrottle(connects_per_second=1, connects_per_second_per_peer=1, burst_multiplier=1.0)
        fleet, _ = await self._start(throttle=throttle)
        first, _ = await self._connect(fleet.bound_port)
        await asyncio.wait_for(first.read(200), timeout=1)
        second, _ = await self._connect(fleet.bound_port)
        data = await asyncio.wait_for(second.read(16), timeout=1)
        self.assertEqual(data, b"")
        records = await self._wait(fleet, "relay_throttled")
        self.assertFalse(records[0]["banner_sent"])
        self.assertEqual(fleet.as_dict()["throttle_denials"], 1)

    async def test_concurrent_session_limit_is_reported(self) -> None:
        fleet, _ = await self._start(max_sessions=1)
        first, _ = await self._connect(fleet.bound_port)
        await asyncio.wait_for(first.read(200), timeout=1)
        second, _ = await self._connect(fleet.bound_port)
        data = await asyncio.wait_for(second.read(16), timeout=1)
        self.assertEqual(data, b"")
        await self._wait(fleet, "relay_rejected")

    async def test_summary_is_json_safe_and_carries_the_transit_footer(self) -> None:
        fleet, _ = await self._start()
        report = fleet.as_dict()
        json.dumps(report)
        self.assertTrue(report["no_third_party_transit"])
        self.assertEqual(report["footer"], NO_THIRD_PARTY_TRANSIT)
        self.assertEqual(report["target_scope"], "loopback")

    async def test_runtime_limit_stops_the_relay(self) -> None:
        fleet, _ = await self._start(max_runtime=0.05)
        await asyncio.sleep(0.15)
        kinds = [record["kind"] for record in fleet.records]
        self.assertIn("relay_stopped", kinds)


if __name__ == "__main__":
    unittest.main()
