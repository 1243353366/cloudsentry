"""Loopback coverage for opt-in full-payload and full-banner evidence capture.

Every connection here is to this operator's own loopback listener.  The tests
check what the listener records about the bytes a peer sent to it; nothing is
sent anywhere else.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import unittest

from reverse_shell_decoy.honeypot import CapturePolicy, DecoyServer, _build_pacing, _parser


class CaptureTests(unittest.IsolatedAsyncioTestCase):
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

    @staticmethod
    def _events(service: DecoyServer, event_type: str) -> list[dict]:
        return [event for event in service.audit if event["event_type"] == event_type]

    async def _await_events(self, service: DecoyServer, event_type: str, count: int) -> list[dict]:
        for _ in range(200):
            events = self._events(service, event_type)
            if len(events) >= count:
                return events
            await asyncio.sleep(0.01)
        raise AssertionError("expected %d %s events" % (count, event_type))

    async def test_capture_is_off_by_default_and_records_stay_hash_only(self) -> None:
        service, port = await self._start()
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)
        writer.write(b"id\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        events = await self._await_events(service, "command", 1)
        for event in events:
            self.assertNotIn("payload_b64", event)
        self.assertNotIn("peer_greeting_b64", self._events(service, "connecting")[0])
        self.assertIsNone(service.capture)
        self.assertIsNone(service.pacing_snapshot()["capture"])

    async def test_console_command_payload_is_captured_complete(self) -> None:
        policy = CapturePolicy(greeting_grace_seconds=0.05)
        service, port = await self._start(capture=policy)
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)
        command = b"cat /root/credentials.txt\n"
        writer.write(command)
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        event = (await self._await_events(service, "command", 1))[0]
        self.assertTrue(event["payload_complete"])
        self.assertEqual(base64.b64decode(event["payload_b64"]), command)
        self.assertEqual(event["payload_captured_bytes"], len(command))
        self.assertEqual(event["payload_omitted_bytes"], 0)

        writer.close()
        close = (await self._await_events(service, "close", 1))[0]
        self.assertTrue(close["capture_enabled"])
        self.assertFalse(close["capture_truncated"])
        self.assertEqual(close["capture_byte_count"], len(command))
        # The stream hash covers exactly the admitted inbound bytes.
        self.assertEqual(close["capture_sha256"], hashlib.sha256(command).hexdigest())

    async def test_mirror_payload_is_captured_byte_for_byte(self) -> None:
        policy = CapturePolicy(greeting_grace_seconds=0.05)
        service, port = await self._start(response_mode="mirror", capture=policy)
        reader, writer = await self._connect(port)
        payload = b"\x00binary\xff\r\nsecret-token-9f1c\n"
        writer.write(payload)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(len(payload)), timeout=1), payload)

        event = (await self._await_events(service, "mirror_chunk", 1))[0]
        self.assertEqual(base64.b64decode(event["payload_b64"]), payload)
        self.assertTrue(event["payload_complete"])
        self.assertEqual(event["chunk_sha256"], hashlib.sha256(payload).hexdigest())

    async def test_peer_greeting_banner_is_captured_before_any_command(self) -> None:
        policy = CapturePolicy(greeting_bytes=64, greeting_grace_seconds=0.25)
        service, port = await self._start(capture=policy)
        reader, writer = await self._connect(port)
        greeting = b"SSH-2.0-libssh2_1.11.0\r\n"
        writer.write(greeting)
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        connecting = (await self._await_events(service, "connecting", 1))[0]
        self.assertTrue(connecting["peer_greeting_observed"])
        self.assertEqual(base64.b64decode(connecting["peer_greeting_b64"]), greeting)
        self.assertEqual(
            connecting["peer_greeting_sha256"], hashlib.sha256(greeting).hexdigest()
        )
        self.assertEqual(connecting["peer_greeting_byte_count"], len(greeting))
        self.assertFalse(connecting["peer_greeting_truncated"])
        self.assertIn("SSH-2.0-libssh2", connecting["peer_greeting_utf8"])

    async def test_replayed_greeting_does_not_split_a_command(self) -> None:
        policy = CapturePolicy(greeting_bytes=4, greeting_grace_seconds=0.25)
        service, port = await self._start(capture=policy)
        reader, writer = await self._connect(port)
        writer.write(b"id")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(b"\nwhoami\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        connecting = (await self._await_events(service, "connecting", 1))[0]
        self.assertFalse(connecting["peer_greeting_truncated"])
        self.assertEqual(base64.b64decode(connecting["peer_greeting_b64"]), b"id")
        # The greeting bytes are replayed, so the first command is still "id".
        first = (await self._await_events(service, "command", 1))[0]
        self.assertEqual(base64.b64decode(first["payload_b64"]), b"id\n")
        self.assertEqual(first["verb"], "id")

    async def test_complete_server_banner_is_recorded_with_the_session(self) -> None:
        service, port = await self._start(capture=CapturePolicy(greeting_grace_seconds=0.05))
        reader, _ = await self._connect(port)
        banner = await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        connecting = (await self._await_events(service, "connecting", 1))[0]
        self.assertTrue(connecting["banner_delivered"])
        self.assertEqual(connecting["banner_byte_count"], len(banner))
        self.assertEqual(connecting["banner_sha256"], hashlib.sha256(banner).hexdigest())
        self.assertEqual(connecting["banner_text"].encode(), banner)

    async def test_record_budget_marks_a_partial_payload_instead_of_hiding_it(self) -> None:
        policy = CapturePolicy(
            max_record_bytes=16, max_total_bytes=1024, greeting_grace_seconds=0.05
        )
        service, port = await self._start(response_mode="mirror", capture=policy)
        reader, writer = await self._connect(port)
        payload = b"0123456789abcdefghijklmnopqrstuvwxyz"
        writer.write(payload)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(len(payload)), timeout=1), payload)

        event = (await self._await_events(service, "mirror_chunk", 1))[0]
        self.assertEqual(base64.b64decode(event["payload_b64"]), payload[:16])
        self.assertFalse(event["payload_complete"])
        self.assertEqual(event["payload_captured_bytes"], 16)
        self.assertEqual(event["payload_omitted_bytes"], len(payload) - 16)

        writer.close()
        close = (await self._await_events(service, "close", 1))[0]
        self.assertTrue(close["capture_truncated"])

    async def test_total_budget_stops_capture_without_stopping_the_session(self) -> None:
        policy = CapturePolicy(
            max_total_bytes=4, max_session_bytes=4, greeting_bytes=0,
            greeting_grace_seconds=0.05,
        )
        service, port = await self._start(response_mode="mirror", capture=policy)
        reader, writer = await self._connect(port)
        writer.write(b"abcd")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(4), timeout=1), b"abcd")
        writer.write(b"efgh")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(4), timeout=1), b"efgh")

        first, second = await self._await_events(service, "mirror_chunk", 2)
        self.assertTrue(first["payload_complete"])
        self.assertFalse(second["payload_complete"])
        self.assertEqual(second["payload_captured_bytes"], 0)
        self.assertEqual(second["payload_omitted_bytes"], 4)
        self.assertEqual(service.pacing_snapshot()["capture"]["captured_bytes_total"], 4)

    async def test_captured_payloads_stay_escaped_in_printable_fields(self) -> None:
        policy = CapturePolicy(greeting_grace_seconds=0.05)
        service, port = await self._start(capture=policy)
        reader, writer = await self._connect(port)
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)
        writer.write(b"\x1b[31mescape\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

        event = (await self._await_events(service, "command", 1))[0]
        self.assertEqual(base64.b64decode(event["payload_b64"]), b"\x1b[31mescape\n")
        for record in service.audit:
            self.assertNotIn("\x1b", json.dumps(record))

    async def test_invalid_capture_policy_is_rejected(self) -> None:
        for kwargs in (
            {"max_total_bytes": 0},
            {"max_record_bytes": 8},
            {"greeting_bytes": -1},
            {"greeting_bytes": True},
            {"max_session_bytes": 9 * 1024 * 1024},
            {"greeting_grace_seconds": 9.0},
        ):
            with self.assertRaises(ValueError):
                CapturePolicy(**kwargs)
        with self.assertRaises(ValueError):
            DecoyServer(capture={"enabled": True})


class CaptureCliTests(unittest.TestCase):
    def test_capture_and_pacing_are_opt_in_from_the_cli(self) -> None:
        args = _parser().parse_args([])
        throttle, capture = _build_pacing(args)
        self.assertIsNotNone(throttle)
        self.assertIsNone(capture)

        args = _parser().parse_args(
            ["--capture-payloads", "--capture-record-bytes", "512",
             "--capture-greeting-bytes", "128"]
        )
        throttle, capture = _build_pacing(args)
        self.assertIsNotNone(throttle)
        self.assertEqual(capture.max_record_bytes, 512)
        self.assertEqual(capture.greeting_bytes, 128)

        args = _parser().parse_args(["--no-throttle"])
        throttle, _ = _build_pacing(args)
        self.assertIsNone(throttle)


if __name__ == "__main__":
    unittest.main()
