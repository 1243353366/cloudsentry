"""Independent loopback checks for the bounded, inward-only backup echo service."""
from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import io
import os
import socket
import unittest
from unittest.mock import AsyncMock, patch

from reverse_shell_decoy import backup_echo
from reverse_shell_decoy.authorization import AuthorizationError, request_authorization
from reverse_shell_decoy.honeypot import DecoyServer
from reverse_shell_decoy.simulator import DecoySession


class BackupEchoConfigurationTests(unittest.TestCase):
    def test_fixed_limits_and_binding_validation_include_v4_v6_and_mutation(self) -> None:
        self.assertEqual(
            backup_echo._SERVICE_LIMITS,
            {
                "max_sessions": 1,
                "max_sessions_total": 2,
                "max_commands": 5,
                "idle_timeout": 2,
                "session_timeout": 5,
                "audit_limit": 32,
                "max_runtime": 30,
                "max_input_bytes_total": 4096,
                "max_output_bytes_total": 4096,
                "max_session_input_bytes": 2048,
                "commands_per_second": 1,
            },
        )
        self.assertEqual(backup_echo.EchoBindings("127.0.0.1", 18021, 18022).host, "127.0.0.1")
        self.assertEqual(backup_echo.EchoBindings("::1", 18023, 18024).host, "::1")
        self.assertTrue(backup_echo.EchoBindings("192.0.2.10", 18025, 18026, True).allow_public)

        invalid = (
            ("127.0.0.1", 0, 18022, False),
            ("127.0.0.1", 18022, 18022, False),
            ("localhost", 18021, 18022, False),
            ("127.0.0.1%lo", 18021, 18022, False),
            ("192.0.2.10", 18021, 18022, False),
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                backup_echo.EchoBindings(*values)

        bindings = backup_echo.EchoBindings("127.0.0.1", 18027, 18028)
        object.__setattr__(bindings, "operator_port", 0)
        with self.assertRaises(ValueError):
            _ = bindings.digest
        with self.assertRaises(ValueError):
            backup_echo.authorization_scope(bindings)

    def test_module_ast_has_no_dial_out_or_process_launch_and_mirror_only_server(self) -> None:
        tree = ast.parse(inspect.getsource(backup_echo))
        called_names: set[str] = set()
        called_attributes: set[str] = set()
        server_calls: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
                if node.func.id == "DecoyServer":
                    server_calls.append(node)
            elif isinstance(node.func, ast.Attribute):
                called_attributes.add(node.func.attr)

        forbidden = {
            "open_connection",
            "create_connection",
            "create_subprocess_exec",
            "create_subprocess_shell",
            "Popen",
            "connect",
            "sendto",
            "urlopen",
            "request",
        }
        self.assertFalse(forbidden.intersection(called_names | called_attributes))
        self.assertEqual(len(server_calls), 1)
        response_modes = [
            keyword.value.value
            for keyword in server_calls[0].keywords
            if keyword.arg == "response_mode" and isinstance(keyword.value, ast.Constant)
        ]
        self.assertEqual(response_modes, ["mirror"])
        self.assertNotIn("DecoySession", called_names)

    def test_cli_rejects_callback_style_options_before_any_network_work(self) -> None:
        for option in ("--target", "--c2", "--callback"):
            with self.subTest(option=option), patch.object(
                backup_echo.asyncio, "run", side_effect=AssertionError("parser must reject first")
            ) as run, patch.object(
                DecoyServer, "start", new_callable=AsyncMock,
                side_effect=AssertionError("no listener may start"),
            ) as start, patch(
                "reverse_shell_decoy.honeypot.asyncio.start_server",
                new_callable=AsyncMock,
                side_effect=AssertionError("no socket may open"),
            ) as start_server:
                with self.assertRaises(SystemExit) as result:
                    backup_echo.main([option, "127.0.0.1"])
                self.assertEqual(result.exception.code, 2)
                run.assert_not_called()
                start.assert_not_called()
                start_server.assert_not_called()


class BackupEchoLoopbackTests(unittest.IsolatedAsyncioTestCase):
    """Use real, short-lived 127.0.0.1 listeners without any external network."""

    async def asyncSetUp(self) -> None:
        self._raw_clients: list[socket.socket] = []

    async def asyncTearDown(self) -> None:
        for client in self._raw_clients:
            client.close()
        await asyncio.sleep(0)

    @staticmethod
    def _ephemeral_ports() -> tuple[int, int]:
        """Reserve then release two concrete ports; EchoBindings intentionally rejects 0."""
        holders: list[socket.socket] = []
        try:
            for _ in range(2):
                holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                holder.bind(("127.0.0.1", 0))
                holders.append(holder)
            ports = tuple(holder.getsockname()[1] for holder in holders)
            assert ports[0] != ports[1]
            return ports[0], ports[1]
        finally:
            for holder in holders:
                holder.close()

    async def _raw_connect(self, port: int) -> socket.socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setblocking(False)
        try:
            await asyncio.get_running_loop().sock_connect(client, ("127.0.0.1", port))
        except BaseException:
            client.close()
            raise
        self._raw_clients.append(client)
        return client

    @staticmethod
    async def _receive_exact(client: socket.socket, size: int) -> bytes:
        loop = asyncio.get_running_loop()
        received = bytearray()
        while len(received) < size:
            chunk = await loop.sock_recv(client, size - len(received))
            if not chunk:
                raise AssertionError(f"unexpected EOF after {len(received)} of {size} bytes")
            received.extend(chunk)
        return bytes(received)

    async def _wait_for(self, predicate: object, timeout: float = 0.75) -> None:
        check = predicate  # keep call sites readable while avoiding a helper dependency
        deadline = asyncio.get_running_loop().time() + timeout
        while not check():  # type: ignore[operator]
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("timed out waiting for expected local server state")
            await asyncio.sleep(0.005)

    async def _assert_refused(self, port: int) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setblocking(False)
        try:
            with self.assertRaises(ConnectionRefusedError):
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_connect(client, ("127.0.0.1", port)),
                    timeout=0.25,
                )
        finally:
            client.close()

    @staticmethod
    def _grant_for(bindings: backup_echo.EchoBindings):
        scope = backup_echo.authorization_scope(bindings)
        grant = request_authorization(scope, consent=True)
        assert grant is not None
        return scope, grant

    async def test_default_deny_and_wrong_scope_precede_listener_or_socket_calls(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        good_scope, grant = self._grant_for(bindings)
        wrong_scope = backup_echo.authorization_scope(
            backup_echo.EchoBindings("127.0.0.1", operator + 2, visitor + 2)
        )

        with patch.object(DecoyServer, "start", new_callable=AsyncMock) as start, patch(
            "reverse_shell_decoy.honeypot.asyncio.start_server", new_callable=AsyncMock
        ) as start_server:
            with self.assertRaises(AuthorizationError):
                await backup_echo.run_backup_echo(bindings)
            with self.assertRaises(AuthorizationError):
                await backup_echo.run_backup_echo(bindings, authorization=grant, scope=wrong_scope)
            start.assert_not_called()
            start_server.assert_not_called()
        grant.revoke()
        # Keep this check explicit: a correctly scoped grant itself is valid, only the supplied scope was wrong.
        with self.assertRaises(AuthorizationError):
            grant.check(good_scope)

    async def test_credential_environment_refuses_without_printing_the_value(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        secret = "fake-cloud-key-MUST-NOT-APPEAR"
        stderr = io.StringIO()
        with patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": secret}, clear=True), contextlib.redirect_stderr(stderr), patch.object(
            DecoyServer, "start", new_callable=AsyncMock,
            side_effect=AssertionError("credential refusal occurs before start"),
        ) as start:
            with self.assertRaisesRegex(ValueError, "credential-bearing environment refused"):
                await backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope)
            start.assert_not_called()
        self.assertNotIn(secret, stderr.getvalue())

    async def test_two_slots_echo_only_their_own_opaque_bytes_then_revoke_closes_all(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        services: list[DecoyServer] = []
        addresses: list[tuple[str, int]] = []
        both_started = asyncio.Event()
        stderr = io.StringIO()
        real_start = DecoyServer.start

        async def observing_start(service: DecoyServer, *args: object, **kwargs: object):
            server = await real_start(service, *args, **kwargs)
            services.append(service)
            addresses.extend((str(item.getsockname()[0]), int(item.getsockname()[1])) for item in (server.sockets or ()))
            if len(services) == 2:
                both_started.set()
            return server

        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(stderr), patch.object(
            DecoyServer, "start", new=observing_start
        ), patch.object(
            DecoySession, "execute", side_effect=AssertionError("mirror bytes must never execute")
        ), patch.object(
            asyncio, "open_connection", side_effect=AssertionError("the service must never dial out")
        ) as outbound_open:
            job = asyncio.create_task(backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope))
            await asyncio.wait_for(both_started.wait(), timeout=0.75)
            self.assertEqual(addresses, [("127.0.0.1", operator), ("127.0.0.1", visitor)])

            operator_client, visitor_client = await asyncio.gather(
                self._raw_connect(operator), self._raw_connect(visitor)
            )
            # Mirror mode has neither banner nor prompt and writes nothing before input.
            for client in (operator_client, visitor_client):
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.get_running_loop().sock_recv(client, 1), timeout=0.05)

            operator_payload = b"\x00prompt-injection-operator;PS1=$'x'\xff"
            visitor_payload = b"\x00prompt-injection-visitor$(id)\x00\xfe"
            await asyncio.gather(
                asyncio.get_running_loop().sock_sendall(operator_client, operator_payload),
                asyncio.get_running_loop().sock_sendall(visitor_client, visitor_payload),
            )
            returned_operator, returned_visitor = await asyncio.gather(
                self._receive_exact(operator_client, len(operator_payload)),
                self._receive_exact(visitor_client, len(visitor_payload)),
            )
            self.assertEqual(returned_operator, operator_payload)
            self.assertEqual(returned_visitor, visitor_payload)
            # A peer receives no other slot's payload after its own complete echo.
            for client in (operator_client, visitor_client):
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.get_running_loop().sock_recv(client, 1), timeout=0.05)

            await self._wait_for(lambda: all(service.connection_count == 1 for service in services))
            self.assertEqual(len(services), 2)
            self.assertEqual(sum(service.connection_count for service in services), 2)
            outbound_open.assert_not_called()
            self.assertNotIn("prompt-injection-operator", stderr.getvalue())
            self.assertNotIn("prompt-injection-visitor", stderr.getvalue())

            grant.revoke()
            with self.assertRaises(AuthorizationError):
                await asyncio.wait_for(job, timeout=1)

        self.assertTrue(all(service.server is not None and not service.server.is_serving() for service in services))
        self.assertTrue(all(not service._client_tasks and service.active_sessions == 0 for service in services))
        await self._assert_refused(operator)
        await self._assert_refused(visitor)

    async def test_2049_byte_connection_input_is_silent_and_not_logged_raw(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        services: list[DecoyServer] = []
        both_started = asyncio.Event()
        stderr = io.StringIO()
        real_start = DecoyServer.start

        async def observing_start(service: DecoyServer, *args: object, **kwargs: object):
            server = await real_start(service, *args, **kwargs)
            services.append(service)
            if len(services) == 2:
                both_started.set()
            return server

        marker = b"raw-payload-must-not-be-logged-73A9"
        payload = marker + b"Q" * (2049 - len(marker))
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(stderr), patch.object(
            DecoyServer, "start", new=observing_start
        ):
            job = asyncio.create_task(backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope))
            await asyncio.wait_for(both_started.wait(), timeout=0.75)
            client = await self._raw_connect(operator)
            await asyncio.get_running_loop().sock_sendall(client, payload)
            self.assertEqual(await asyncio.wait_for(asyncio.get_running_loop().sock_recv(client, 1), timeout=1), b"")
            self.assertNotIn(marker.decode(), stderr.getvalue())
            self.assertEqual(services[0].max_input_bytes_total, 4096)
            self.assertEqual(services[0].max_session_input_bytes, 2048)
            grant.revoke()
            with self.assertRaises(AuthorizationError):
                await asyncio.wait_for(job, timeout=1)

    async def test_short_runtime_budget_poll_shuts_both_slots_without_waiting_30_seconds(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        services: list[DecoyServer] = []
        addresses: list[tuple[str, int]] = []
        both_started = asyncio.Event()
        real_start = DecoyServer.start

        async def short_lived_start(service: DecoyServer, *args: object, **kwargs: object):
            # Test-only wrapper: retain production's fixed 30-second constant while
            # causing the actual DecoyServer runtime guard to exercise poll cleanup.
            service.max_runtime = 0.01
            server = await real_start(service, *args, **kwargs)
            services.append(service)
            addresses.extend((str(item.getsockname()[0]), int(item.getsockname()[1])) for item in (server.sockets or ()))
            if len(services) == 2:
                both_started.set()
            return server

        with patch.dict(os.environ, {}, clear=True), patch.object(DecoyServer, "start", new=short_lived_start):
            job = asyncio.create_task(backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope))
            await asyncio.wait_for(both_started.wait(), timeout=0.75)
            result = await asyncio.wait_for(job, timeout=1)

        self.assertEqual(result["slots"], 2)
        self.assertEqual(addresses, [("127.0.0.1", operator), ("127.0.0.1", visitor)])
        self.assertTrue(all(service._shutdown_requested for service in services))
        self.assertTrue(all(service.server is not None and not service.server.is_serving() for service in services))
        await self._assert_refused(operator)
        await self._assert_refused(visitor)

    async def test_second_real_bind_failure_closes_the_first_listener(self) -> None:
        operator, visitor = self._ephemeral_ports()
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("127.0.0.1", visitor))
        occupied.listen()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        started: list[DecoyServer] = []
        real_start = DecoyServer.start

        async def observing_start(service: DecoyServer, *args: object, **kwargs: object):
            server = await real_start(service, *args, **kwargs)
            started.append(service)
            return server

        try:
            with patch.dict(os.environ, {}, clear=True), patch.object(DecoyServer, "start", new=observing_start):
                with self.assertRaises(OSError):
                    await backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope)
            self.assertEqual(len(started), 1)
            self.assertFalse(started[0].server.is_serving())  # type: ignore[union-attr]
            await self._assert_refused(operator)
        finally:
            occupied.close()

    async def test_revocation_after_first_real_start_prevents_second_and_closes_first(self) -> None:
        operator, visitor = self._ephemeral_ports()
        bindings = backup_echo.EchoBindings("127.0.0.1", operator, visitor)
        scope, grant = self._grant_for(bindings)
        started: list[DecoyServer] = []
        real_start = DecoyServer.start

        async def revoke_during_start(service: DecoyServer, *args: object, **kwargs: object):
            server = await real_start(service, *args, **kwargs)
            started.append(service)
            if len(started) == 1:
                grant.revoke()
            return server

        with patch.dict(os.environ, {}, clear=True), patch.object(DecoyServer, "start", new=revoke_during_start):
            with self.assertRaises(AuthorizationError):
                await asyncio.wait_for(
                    backup_echo.run_backup_echo(bindings, authorization=grant, scope=scope), timeout=1
                )
        self.assertEqual(len(started), 1)
        self.assertFalse(started[0].server.is_serving())  # type: ignore[union-attr]
        await self._assert_refused(operator)


if __name__ == "__main__":
    unittest.main()
