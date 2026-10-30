"""Focused review-8 regressions for the bounded decoy service."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import unittest
from unittest.mock import patch

import reverse_shell_decoy.simulator as simulator
from reverse_shell_decoy.honeypot import DecoyServer, main


class SimulatorAuditBridgeTests(unittest.IsolatedAsyncioTestCase):
    """Use only an ephemeral loopback listener and a temporary simulator cap."""

    async def asyncSetUp(self) -> None:
        self.service: DecoyServer | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def asyncTearDown(self) -> None:
        if self.writer is not None:
            self.writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(self.writer.wait_closed(), timeout=1)
        if self.service is not None:
            await self.service.shutdown()

    async def test_missing_simulator_limit_event_uses_current_command_metadata(self) -> None:
        """A retained prior simulator event must never supply this command's audit data."""
        self.service = DecoyServer(max_commands=2, commands_per_second=2, max_runtime=5)
        server = await self.service.start(port=0)
        port = server.sockets[0].getsockname()[1]
        reader, self.writer = await asyncio.open_connection("127.0.0.1", port)

        # The production simulator cap is higher than the public service range.
        # Patch it only in this finite fixture to exercise the defensive bridge.
        with patch.object(simulator, "MAX_COMMANDS", 1):
            await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)
            self.writer.write(b"pwd\n")
            await self.writer.drain()
            await asyncio.wait_for(reader.readuntil(b"# "), timeout=1)

            self.writer.write(b"id\n")
            await self.writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.read(), timeout=1),
                b"[SIMULATED] maximum command count reached; session closed\n",
            )

        commands = [event for event in self.service.audit if event["event_type"] == "command"]
        self.assertEqual(len(commands), 2)
        overflow = commands[-1]
        self.assertEqual(overflow["command_sha256"], hashlib.sha256(b"id").hexdigest())
        self.assertEqual(overflow["verb"], "id")
        self.assertTrue(overflow["blocked"])
        self.assertEqual(overflow["reason"], "virtual_command_limit")
        self.assertEqual(
            overflow["output_sha256"],
            hashlib.sha256(b"[SIMULATED] maximum command count reached; session closed\n").hexdigest(),
        )


class ServiceBoundaryTests(unittest.TestCase):
    def test_service_command_configuration_stays_below_simulator_event_cap(self) -> None:
        service = DecoyServer(max_commands=100)
        self.assertLess(service.max_commands, simulator.MAX_COMMANDS)
        with self.assertRaisesRegex(ValueError, "max_commands"):
            DecoyServer(max_commands=101)

    def test_inherited_known_credential_refuses_before_async_runtime_starts(self) -> None:
        stderr = io.StringIO()
        with patch.dict("os.environ", {"AWS_SESSION_TOKEN": "test-value-not-emitted"}, clear=True), \
             patch("reverse_shell_decoy.honeypot.asyncio.run") as run, \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as result:
                main([])
        self.assertEqual(result.exception.code, 2)
        run.assert_not_called()
        self.assertIn("credential-bearing environment refused", stderr.getvalue())
        self.assertNotIn("test-value-not-emitted", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
