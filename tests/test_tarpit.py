import asyncio
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from reverse_shell_decoy.honeypot import DecoyServer


class InboundSinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_sink_hashes_input_never_executes_and_closes_at_quota(self):
        service = DecoyServer(response_mode="sink", max_commands=2, max_runtime=2)
        audit = io.StringIO()
        with contextlib.redirect_stderr(audit):
            server = await service.start(port=0)
            port = server.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                with patch("reverse_shell_decoy.honeypot.DecoySession.execute", side_effect=AssertionError("sink must not interpret input")), \
                     patch("asyncio.open_connection", side_effect=AssertionError("service must not dial a peer")):
                    writer.write(b"echo NEVER-STORE-RAW-SECRET\nwhoami\n")
                    await writer.drain()
                    received = await asyncio.wait_for(reader.read(), timeout=1)
                self.assertEqual(received, b"", "sink sends no application payload or echo")
                writer.close()
                await writer.wait_closed()
            finally:
                await service.shutdown()
        events = [json.loads(line) for line in audit.getvalue().splitlines()]
        commands = [e for e in events if e["event_type"] == "command"]
        self.assertEqual(len(commands), 2)
        self.assertTrue(all(e["blocked"] and e["response_mode"] == "sink" for e in commands))
        self.assertNotIn("NEVER-STORE-RAW-SECRET", audit.getvalue())
        self.assertTrue(all(e["remote_os"] == "unknown" for e in events))
        self.assertTrue(any(e.get("reason") == "command_limit" for e in events))

    async def test_sink_rejects_oversize_input_without_execution_or_echo(self):
        service = DecoyServer(response_mode="sink", max_runtime=2)
        with contextlib.redirect_stderr(io.StringIO()):
            server = await service.start(port=0)
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
                writer.write(b"x" * 5000 + b"\n")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
                writer.close()
                await writer.wait_closed()
            finally:
                await service.shutdown()
        self.assertTrue(any(e.get("reason") == "input_limit" for e in service.audit))

    def test_response_modes_are_allowlisted(self):
        with self.assertRaises(ValueError):
            DecoyServer(response_mode="echo-back-to-c2")


if __name__ == "__main__":
    unittest.main()
