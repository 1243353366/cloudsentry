"""Contract tests for bounded DecoyServer service budgets.

These tests use only short-lived loopback listeners and tiny byte payloads.  They
exercise accounting through the public server API rather than attempting any
host resource exhaustion.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import unittest
from collections.abc import Callable
from unittest.mock import patch

from reverse_shell_decoy.honeypot import DecoyServer


class BudgetConfigurationTests(unittest.TestCase):
    """Validate the finite, integer-only budget configuration surface."""

    def test_budget_values_reject_out_of_range_noninteger_and_boolean_values(self) -> None:
        baseline = {
            "max_input_bytes_total": 1024,
            "max_output_bytes_total": 1024,
            "max_session_input_bytes": 256,
            "commands_per_second": 2,
        }
        invalid_values = {
            "max_input_bytes_total": (0, 8_388_609, 1.5, "1", True, False),
            "max_output_bytes_total": (0, 8_388_609, 1.5, "1", True, False),
            "max_session_input_bytes": (0, 262_145, 1.5, "1", True, False),
            "commands_per_second": (0, 11, 1.5, "1", True, False),
        }

        for name, values in invalid_values.items():
            for value in values:
                with self.subTest(parameter=name, value=repr(value)):
                    options = dict(baseline)
                    options[name] = value
                    with self.assertRaisesRegex(ValueError, name):
                        DecoyServer(**options)

    def test_budget_snapshot_is_complete_before_starting_a_loop(self) -> None:
        service = DecoyServer(
            max_input_bytes_total=17,
            max_output_bytes_total=19,
            max_session_input_bytes=7,
            commands_per_second=3,
        )

        snapshot = service.budget_snapshot()

        self.assertEqual(set(snapshot), {"limits", "usage"})
        self.assertEqual(
            {
                name: snapshot["limits"][name]
                for name in (
                    "max_input_bytes_total",
                    "max_output_bytes_total",
                    "max_session_input_bytes",
                    "commands_per_second",
                )
            },
            {
                "max_input_bytes_total": 17,
                "max_output_bytes_total": 19,
                "max_session_input_bytes": 7,
                "commands_per_second": 3,
            },
        )
        self.assertEqual(
            set(snapshot["usage"]),
            {
                "input_bytes_total",
                "output_bytes_total",
                "accepted_connections",
                "active_sessions",
                "peak_active_sessions",
                "elapsed_seconds",
            },
        )
        self.assertEqual(snapshot["usage"]["input_bytes_total"], 0)
        self.assertEqual(snapshot["usage"]["output_bytes_total"], 0)
        self.assertEqual(snapshot["usage"]["accepted_connections"], 0)
        self.assertEqual(snapshot["usage"]["active_sessions"], 0)
        self.assertEqual(snapshot["usage"]["peak_active_sessions"], 0)
        self.assertEqual(snapshot["usage"]["elapsed_seconds"], 0)


class BudgetEnforcementTests(unittest.IsolatedAsyncioTestCase):
    """Exercise tiny budgets over ephemeral loopback sockets only."""

    async def asyncSetUp(self) -> None:
        self.services: list[DecoyServer] = []
        self.writers: list[asyncio.StreamWriter] = []
        # Audit output is an operator-facing sink, not test output.  Capturing it
        # also lets the privacy assertion ensure a supplied sentinel is never
        # emitted raw.
        self.stderr = io.StringIO()
        self.stderr_patch = patch("sys.stderr", self.stderr)
        self.stderr_patch.start()

    async def asyncTearDown(self) -> None:
        for writer in self.writers:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
        for service in reversed(self.services):
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await service.shutdown()
        self.stderr_patch.stop()

    async def _start(self, **kwargs: object) -> tuple[DecoyServer, asyncio.Server, int]:
        kwargs.setdefault("max_runtime", 5)
        service = DecoyServer(**kwargs)
        self.services.append(service)
        server = await service.start(host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        return service, server, port

    async def _connect(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def _read_prompt(self, reader: asyncio.StreamReader) -> bytes:
        return await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

    async def _eventually(self, condition: Callable[[], bool], timeout: float = 1) -> None:
        """Wait for a short, local state transition without polling indefinitely."""
        deadline = asyncio.get_running_loop().time() + timeout
        while not condition():
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("timed out waiting for bounded loopback service state")
            await asyncio.sleep(0.01)

    @staticmethod
    def _client_input_events(service: DecoyServer) -> list[dict[str, object]]:
        return [
            event
            for event in service.audit
            if event["event_type"] in {"command", "mirror_chunk"}
        ]

    async def test_budget_lifecycle_records_are_control_events_with_exact_metadata(self) -> None:
        service, _, _ = await self._start(
            max_input_bytes_total=32,
            max_output_bytes_total=32,
            max_session_input_bytes=8,
            commands_per_second=2,
        )
        await service.shutdown()

        records = [event for event in service.audit if event["event_type"] == "service_budget"]
        self.assertEqual({event["phase"] for event in records}, {"started", "stopped"})
        for record in records:
            phase = record["phase"]
            self.assertEqual(
                {
                    "event_type": record["event_type"],
                    "phase": phase,
                    "source_kind": record["source_kind"],
                    "interaction_observed": record["interaction_observed"],
                },
                {
                    "event_type": "service_budget",
                    "phase": phase,
                    "source_kind": "decoy_service_control",
                    "interaction_observed": False,
                },
            )

    async def test_session_input_budget_closes_only_that_session_in_every_mode(self) -> None:
        for mode in ("console", "sink", "mirror"):
            with self.subTest(response_mode=mode):
                service, server, port = await self._start(
                    response_mode=mode,
                    max_input_bytes_total=64,
                    max_output_bytes_total=2_048,
                    max_session_input_bytes=1,
                    commands_per_second=2,
                )
                first_reader, first_writer = await self._connect(port)
                if mode == "console":
                    await self._read_prompt(first_reader)

                # Two payload bytes (three in line modes) exceed the one-byte
                # per-session cap without allocating a large test buffer.
                first_writer.write(b"xx\n" if mode != "mirror" else b"xx")
                with contextlib.suppress(ConnectionError, OSError):
                    await first_writer.drain()
                await asyncio.wait_for(first_reader.read(), timeout=1)
                await self._eventually(lambda: service.active_sessions == 0)
                self.assertTrue(server.is_serving())

                second_reader, second_writer = await self._connect(port)
                if mode == "console":
                    await self._read_prompt(second_reader)
                elif mode == "mirror":
                    second_writer.write(b"z")
                    await second_writer.drain()
                    self.assertEqual(
                        await asyncio.wait_for(second_reader.readexactly(1), timeout=1), b"z"
                    )
                self.assertTrue(server.is_serving())
                second_writer.close()

    async def test_global_input_violation_stops_listener_and_all_active_sessions(self) -> None:
        service, server, port = await self._start(
            response_mode="mirror",
            max_input_bytes_total=1,
            max_output_bytes_total=8,
            max_session_input_bytes=8,
            commands_per_second=2,
        )
        first_reader, first_writer = await self._connect(port)
        second_reader, _ = await self._connect(port)
        await self._eventually(lambda: service.active_sessions == 2)

        first_writer.write(b"a")
        await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first_reader.readexactly(1), timeout=1), b"a")
        self.assertEqual(service.budget_snapshot()["usage"]["input_bytes_total"], 1)
        self.assertEqual(service.budget_snapshot()["usage"]["output_bytes_total"], 1)

        # A second one-byte chunk would exceed the global input allocation.  It
        # must not be admitted, and its violation closes the listener plus the
        # otherwise idle second session.
        first_writer.write(b"b")
        with contextlib.suppress(ConnectionError, OSError):
            await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first_reader.read(), timeout=1), b"")
        self.assertEqual(await asyncio.wait_for(second_reader.read(), timeout=1), b"")
        await self._eventually(lambda: not server.is_serving())
        await self._eventually(lambda: service.active_sessions == 0)

        usage = service.budget_snapshot()["usage"]
        self.assertEqual(usage["input_bytes_total"], 1)
        self.assertEqual(usage["output_bytes_total"], 1)
        self.assertEqual(usage["accepted_connections"], 2)
        self.assertEqual(usage["active_sessions"], 0)
        self.assertGreaterEqual(usage["peak_active_sessions"], 2)

    async def test_mirror_output_budget_echoes_only_reserved_bytes_without_amplification(self) -> None:
        service, server, port = await self._start(
            response_mode="mirror",
            max_input_bytes_total=8,
            max_output_bytes_total=1,
            max_session_input_bytes=8,
            commands_per_second=2,
        )
        reader, writer = await self._connect(port)

        writer.write(b"x")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), timeout=1), b"x")
        writer.write(b"y")
        with contextlib.suppress(ConnectionError, OSError):
            await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")
        await self._eventually(lambda: not server.is_serving())

        usage = service.budget_snapshot()["usage"]
        self.assertEqual(usage["input_bytes_total"], 2)
        self.assertEqual(usage["output_bytes_total"], 1)
        self.assertEqual(usage["active_sessions"], 0)
        self.assertEqual(usage["peak_active_sessions"], 1)

    async def test_configured_rate_is_used_in_console_sink_and_mirror_modes(self) -> None:
        for mode in ("console", "sink", "mirror"):
            with self.subTest(response_mode=mode):
                service, _, port = await self._start(
                    response_mode=mode,
                    max_input_bytes_total=64,
                    max_output_bytes_total=2_048,
                    max_session_input_bytes=64,
                    commands_per_second=1,
                )
                reader, writer = await self._connect(port)
                if mode == "console":
                    await self._read_prompt(reader)
                    writer.write(b"id\n")
                    await writer.drain()
                    await self._read_prompt(reader)
                    writer.write(b"pwd\n")
                elif mode == "sink":
                    writer.write(b"id\npwd\n")
                else:
                    writer.write(b"a")
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(1), timeout=1), b"a")
                    writer.write(b"b")
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.drain()
                await asyncio.wait_for(reader.read(), timeout=1)
                await self._eventually(lambda: service.active_sessions == 0)
                self.assertEqual(service.budget_snapshot()["limits"]["commands_per_second"], 1)
                events = self._client_input_events(service)
                self.assertTrue(any(event.get("blocked") is True for event in events))

    async def test_client_input_audits_count_bytes_without_retaining_raw_payloads(self) -> None:
        sentinel = "BUDGET-INPUT-SENTINEL-73C1"
        payloads = {
            "console": f"not_a_command {sentinel}\n".encode(),
            "sink": f"not_a_command {sentinel}\n".encode(),
            "mirror": f"{sentinel}".encode(),
        }
        for mode, payload in payloads.items():
            with self.subTest(response_mode=mode):
                service, _, port = await self._start(
                    response_mode=mode,
                    max_input_bytes_total=2_048,
                    max_output_bytes_total=2_048,
                    max_session_input_bytes=512,
                    commands_per_second=2,
                )
                reader, writer = await self._connect(port)
                if mode == "console":
                    await self._read_prompt(reader)
                writer.write(payload)
                await writer.drain()
                if mode == "console":
                    await self._read_prompt(reader)
                elif mode == "mirror":
                    self.assertEqual(
                        await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1), payload
                    )
                else:
                    await self._eventually(lambda: bool(self._client_input_events(service)))

                events = self._client_input_events(service)
                self.assertTrue(events)
                event = events[-1]
                self.assertEqual(event["input_byte_count"], len(payload))
                self.assertEqual(event["source_kind"], "decoy_service_interaction")
                self.assertTrue(event["interaction_observed"])
                self.assertNotIn(sentinel, json.dumps(events))
                self.assertNotIn(sentinel, self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
