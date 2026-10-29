"""Tests for the bounded, inbound-only virtual terminal service."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import unittest

from reverse_shell_decoy.honeypot import DecoyServer, main


class HoneypotServerTests(unittest.IsolatedAsyncioTestCase):
    """Exercise only loopback sockets and ensure every test cleans up handlers."""

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

    async def _start(self, **kwargs: object) -> tuple[DecoyServer, asyncio.Server, int]:
        kwargs.setdefault("max_runtime", 5)
        service = DecoyServer(**kwargs)
        self.services.append(service)
        server = await service.start(port=0)
        port = server.sockets[0].getsockname()[1]
        return service, server, port

    async def _connect(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def _read_prompt(self, reader: asyncio.StreamReader) -> bytes:
        return await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

    async def test_loopback_startup_uses_neutral_realistic_banner_and_synthetic_root_id(self) -> None:
        _, _, port = await self._start()
        reader, writer = await self._connect(port)

        banner = await self._read_prompt(reader)
        self.assertIn(b"Maintenance console", banner)
        self.assertIn(b"ROOT ACCESS GRANTED", banner)
        self.assertNotIn(b"honeypot", banner.lower())
        self.assertNotIn(b"reverse-shell decoy", banner.lower())

        writer.write(b"id\n")
        await writer.drain()
        reply = await self._read_prompt(reader)
        self.assertIn(b"uid=0(root)", reply)
        self.assertNotIn(b"[SIMULATED]", reply)

    async def test_shell_operators_are_blocked_and_audit_never_records_raw_arguments(self) -> None:
        service, _, port = await self._start()
        reader, writer = await self._connect(port)
        await self._read_prompt(reader)

        supplied = b"id; uname very-secret-value\n"
        writer.write(supplied)
        await writer.drain()
        response = await self._read_prompt(reader)
        self.assertIn(b"blocked", response.lower())

        command_events = [event for event in service.audit if event["event_type"] == "command"]
        self.assertEqual(len(command_events), 1)
        command_event = command_events[0]
        self.assertEqual(command_event["verb"], "unsupported")
        self.assertEqual(
            command_event["command_sha256"],
            hashlib.sha256(supplied.rstrip(b"\n")).hexdigest(),
        )
        self.assertNotIn("very-secret-value", json.dumps(command_event))
        self.assertNotIn("command", command_event)

    async def test_oversize_line_is_controlled_and_disconnected(self) -> None:
        _, _, port = await self._start()
        reader, writer = await self._connect(port)
        await self._read_prompt(reader)

        writer.write(b"x" * 4097 + b"\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=1)
        self.assertIn(b"Input too long.", response)

    async def test_nonloopback_bind_requires_opt_in_without_attempting_a_connection(self) -> None:
        service = DecoyServer(max_runtime=5)
        self.services.append(service)
        with self.assertRaisesRegex(ValueError, "allow_public"):
            await service.start(host="203.0.113.9", port=0)
        self.assertIsNone(service.server)
        self.assertEqual(service.connection_count, 0)

    async def test_concurrent_session_cap_rejects_second_peer_immediately(self) -> None:
        service, _, port = await self._start(max_sessions=1)
        first_reader, _ = await self._connect(port)
        await self._read_prompt(first_reader)
        self.assertEqual(service.active_sessions, 1)

        second_reader, _ = await self._connect(port)
        rejected = await asyncio.wait_for(second_reader.read(), timeout=1)
        self.assertIn(b"Maintenance console unavailable.", rejected)
        self.assertEqual(service.active_sessions, 1)

    async def test_command_quota_and_idle_timer_end_sessions(self) -> None:
        _, _, quota_port = await self._start(max_commands=1)
        quota_reader, quota_writer = await self._connect(quota_port)
        await self._read_prompt(quota_reader)
        quota_writer.write(b"id\n")
        await quota_writer.drain()
        quota_output = await asyncio.wait_for(quota_reader.read(), timeout=1)
        self.assertIn(b"uid=0(root)", quota_output)
        self.assertIn(b"Command quota reached.", quota_output)

        _, _, idle_port = await self._start(idle_timeout=1, session_timeout=3)
        idle_reader, _ = await self._connect(idle_port)
        await self._read_prompt(idle_reader)
        idle_output = await asyncio.wait_for(idle_reader.read(), timeout=2)
        self.assertIn(b"Session idle timeout.", idle_output)

    async def test_rate_limit_closes_after_more_than_ten_commands_per_second(self) -> None:
        _, _, port = await self._start()
        reader, writer = await self._connect(port)
        await self._read_prompt(reader)

        writer.write(b"pwd\n" * 11)
        await writer.drain()
        output = await asyncio.wait_for(reader.read(), timeout=1)
        self.assertIn(b"Command rate limit reached.", output)

    async def test_lifetime_connection_quota_closes_listener_but_allows_final_session(self) -> None:
        service, server, port = await self._start(max_sessions_total=1)
        reader, writer = await self._connect(port)
        await self._read_prompt(reader)
        # asyncio.Server.wait_closed() also waits for the active final peer;
        # is_serving() verifies that the listening socket is already closed.
        await asyncio.sleep(0)
        self.assertFalse(server.is_serving())
        self.assertEqual(service.connection_count, 1)

        writer.write(b"id\n")
        await writer.drain()
        response = await self._read_prompt(reader)
        self.assertIn(b"uid=0(root)", response)

    async def test_audit_is_bounded_machine_json_schema_and_stops_the_service_at_cap(self) -> None:
        service, server, port = await self._start(audit_limit=3, max_commands=1)
        reader, writer = await self._connect(port)
        await self._read_prompt(reader)
        writer.write(b"echo very-secret-value\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=1)
        await asyncio.wait_for(server.wait_closed(), timeout=1)

        self.assertEqual(len(service.audit), 3)
        self.assertFalse(server.is_serving())
        serialised = json.dumps(list(service.audit))
        self.assertNotIn("very-secret-value", serialised)
        for event in service.audit:
            self.assertTrue(event["simulation"])
            self.assertEqual(event["source_kind"], "decoy_service_interaction")
            self.assertTrue(event["interaction_observed"])
            self.assertEqual(event["attacker_identity"], "unknown")
            self.assertEqual(event["remote_os"], "unknown")
            self.assertIn("timestamp_utc", event)
            self.assertIn("session_id", event)
            self.assertNotIn("command", event)

    async def test_global_runtime_stops_listener_and_active_session_without_restart(self) -> None:
        service, server, port = await self._start(max_runtime=0.05)
        reader, _ = await self._connect(port)
        await self._read_prompt(reader)
        await asyncio.wait_for(reader.read(), timeout=1)
        await asyncio.wait_for(server.wait_closed(), timeout=1)

        self.assertTrue(service._runtime_expired)
        close_events = [event for event in service.audit if event["event_type"] == "close"]
        self.assertEqual(close_events[-1]["reason"], "service_runtime_limit")
        with self.assertRaisesRegex(RuntimeError, "runtime"):
            await service.start(port=0)


class HoneypotCliTests(unittest.TestCase):
    def test_cli_rejects_runtime_outside_its_one_to_3600_second_range(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["--max-runtime", "0"])
        self.assertEqual(raised.exception.code, 2)
