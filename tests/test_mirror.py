"""Loopback coverage for the bounded, inbound-only binary mirror mode."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import unittest
from unittest.mock import patch

from reverse_shell_decoy.honeypot import DecoyServer, _parser


class MirrorModeTests(unittest.IsolatedAsyncioTestCase):
    """Exercise mirror mode without using any external service or host process."""

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
        kwargs.setdefault("response_mode", "mirror")
        kwargs.setdefault("max_runtime", 5)
        service = DecoyServer(**kwargs)
        self.services.append(service)
        server = await service.start(port=0)
        return service, server.sockets[0].getsockname()[1]

    async def _connect(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def test_mirrors_exact_binary_bytes_without_banner_execution_or_dial_out(self) -> None:
        service, port = await self._start()
        reader, writer = await self._connect(port)

        # Mirror mode emits nothing until it receives opaque bytes.
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(reader.read(1), timeout=0.05)

        payload = b"\x00not-a-command\xff\r\nmirror-secret-7F3A\n"
        with patch(
            "reverse_shell_decoy.honeypot.DecoySession.execute",
            side_effect=AssertionError("mirror input must never execute"),
        ), patch(
            "asyncio.open_connection",
            side_effect=AssertionError("the server must never dial out"),
        ) as outbound_open:
            writer.write(payload)
            await writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1),
                payload,
            )
        outbound_open.assert_not_called()

        mirror_events = [event for event in service.audit if event["event_type"] == "mirror_chunk"]
        self.assertEqual(len(mirror_events), 1)
        event = mirror_events[0]
        self.assertEqual(event["byte_count"], len(payload))
        self.assertEqual(event["chunk_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertFalse(event["execution"])
        self.assertTrue(event["simulation"])
        self.assertEqual(event["source_kind"], "decoy_service_interaction")
        self.assertTrue(event["interaction_observed"])
        self.assertEqual(event["simulation_scope"], "bounded_echo_service_not_real_command_execution")
        serialised_audit = json.dumps(list(service.audit))
        self.assertNotIn("mirror-secret-7F3A", serialised_audit)
        self.assertNotIn("not-a-command", serialised_audit)
        self.assertNotIn("Maintenance console", serialised_audit)

    async def test_chunk_count_cap_echoes_only_accepted_chunks(self) -> None:
        service, port = await self._start(max_commands=2)
        reader, writer = await self._connect(port)

        for payload in (b"first", b"second\n"):
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1), payload)
        self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")

        mirror_events = [event for event in service.audit if event["event_type"] == "mirror_chunk"]
        self.assertEqual(len(mirror_events), 2)
        self.assertEqual(sum(event["byte_count"] for event in mirror_events), len(b"firstsecond\n"))
        close_events = [event for event in service.audit if event["event_type"] == "close"]
        self.assertEqual(close_events[-1]["reason"], "chunk_limit")

    async def test_byte_budget_does_not_echo_the_over_budget_chunk(self) -> None:
        service, port = await self._start(max_commands=10)
        reader, writer = await self._connect(port)

        with patch("reverse_shell_decoy.honeypot._MIRROR_MAX_BYTES", 8):
            accepted = b"12345678"
            writer.write(accepted)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(accepted)), timeout=1), accepted)

            writer.write(b"X")
            with contextlib.suppress(ConnectionError, OSError):
                await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")

        mirror_events = [event for event in service.audit if event["event_type"] == "mirror_chunk"]
        self.assertEqual([event["byte_count"] for event in mirror_events], [8, 1])
        self.assertFalse(mirror_events[0]["blocked"])
        self.assertTrue(mirror_events[1]["blocked"])
        self.assertEqual(mirror_events[1]["reason"], "byte_budget")

    async def test_chunk_rate_limit_closes_silently_after_ten_chunks_per_second(self) -> None:
        service, port = await self._start(max_commands=100)
        reader, writer = await self._connect(port)

        # Waiting for each echo ensures one server read per sent chunk rather
        # than depending on incidental TCP packet boundaries.
        for _ in range(10):
            writer.write(b"r")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(1), timeout=1), b"r")
        writer.write(b"x")
        with contextlib.suppress(ConnectionError, OSError):
            await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")

        mirror_events = [event for event in service.audit if event["event_type"] == "mirror_chunk"]
        self.assertEqual(len(mirror_events), 11)
        self.assertTrue(mirror_events[-1]["blocked"])
        self.assertEqual(mirror_events[-1]["reason"], "chunk_rate_limit")

    async def test_idle_and_session_deadlines_close_without_timeout_payloads(self) -> None:
        idle_service, idle_port = await self._start(idle_timeout=1, session_timeout=3)
        idle_reader, _ = await self._connect(idle_port)
        self.assertEqual(await asyncio.wait_for(idle_reader.read(), timeout=2), b"")
        idle_close = [event for event in idle_service.audit if event["event_type"] == "close"][-1]
        self.assertEqual(idle_close["reason"], "idle_timeout")

        session_service, session_port = await self._start(idle_timeout=3, session_timeout=1)
        session_reader, _ = await self._connect(session_port)
        self.assertEqual(await asyncio.wait_for(session_reader.read(), timeout=2), b"")
        session_close = [event for event in session_service.audit if event["event_type"] == "close"][-1]
        self.assertEqual(session_close["reason"], "session_timeout")

    async def test_capacity_rejection_is_silent_in_mirror_mode(self) -> None:
        _, port = await self._start(max_sessions=1)
        _, first_writer = await self._connect(port)
        second_reader, _ = await self._connect(port)
        self.assertFalse(first_writer.is_closing())
        self.assertEqual(await asyncio.wait_for(second_reader.read(), timeout=1), b"")


class MirrorModeConfigurationTests(unittest.TestCase):
    def test_response_mode_rejects_unknown_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "response_mode"):
            DecoyServer(response_mode="callback")

    def test_cli_exposes_mirror_mode(self) -> None:
        self.assertEqual(_parser().parse_args(["--response-mode", "mirror"]).response_mode, "mirror")


if __name__ == "__main__":
    unittest.main()
