"""Protection regressions for selected-file analysis and loopback mirror checks."""
from __future__ import annotations

import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from reverse_shell_decoy.authorization import (
    AuthorizationError,
    AuthorizationScope,
    request_authorization,
)
from reverse_shell_decoy.mirror_regression import run_regression
from reverse_shell_decoy.virtual_analysis import VirtualAnalysisComputer, main as virtual_main


class _InterruptingTTY(io.StringIO):
    def isatty(self) -> bool:
        return True

    def readline(self, _limit: int = -1) -> str:
        raise KeyboardInterrupt


class ProtectedVirtualAnalysisTests(unittest.TestCase):
    def test_revocation_during_read_refuses_before_analysis_or_success_output(self) -> None:
        path = "/selected/analysis-input.txt"
        scope = AuthorizationScope("static_analysis", path)
        grant = request_authorization(scope, consent=True)
        assert grant is not None
        output = io.StringIO()

        def revoke_during_read(*_args: object, **_kwargs: object) -> bytes:
            grant.revoke()
            return b"echo inert-data"

        with patch("reverse_shell_decoy.virtual_analysis.request_authorization", return_value=grant), \
                patch("reverse_shell_decoy.virtual_analysis.read_regular", side_effect=revoke_during_read), \
                patch("reverse_shell_decoy.virtual_analysis.static_inspect", side_effect=AssertionError("analyzed")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(virtual_main(["--consent", "--sample", path]), 2)

        self.assertEqual(
            json.loads(output.getvalue()),
            {"reason": "permission_or_input_unavailable", "status": "error"},
        )
        self.assertNotIn("inert-data", output.getvalue())

    def test_interrupted_tty_refuses_without_opening_selected_file(self) -> None:
        output = io.StringIO()
        with patch("sys.stdin", _InterruptingTTY()), \
                patch("reverse_shell_decoy.virtual_analysis.read_regular", side_effect=AssertionError("opened")) as reader, \
                contextlib.redirect_stdout(output):
            self.assertEqual(virtual_main(["--sample", "/private/selected.txt"]), 2)
        reader.assert_not_called()
        self.assertEqual(
            json.loads(output.getvalue()),
            {"reason": "permission_or_input_unavailable", "status": "error"},
        )

    def test_each_virtual_analysis_instance_and_reset_have_distinct_opaque_sessions(self) -> None:
        first, second = VirtualAnalysisComputer(), VirtualAnalysisComputer()
        first.submit("echo private-fixture-name")
        second.submit("echo private-fixture-name")
        first_session = first.audit_events[-1]["session_id"]
        second_session = second.audit_events[-1]["session_id"]
        reset = first.reset()
        reset.submit("echo private-fixture-name")
        reset_session = reset.audit_events[-1]["session_id"]

        self.assertEqual(len({first_session, second_session, reset_session}), 3)
        for session_id in (first_session, second_session, reset_session):
            self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{32}", session_id))
            self.assertNotEqual(session_id, "virtual-analysis-1")
        rendered = json.dumps(first.audit_events + second.audit_events + reset.audit_events)
        self.assertNotIn("/selected", rendered)
        self.assertNotIn("private-fixture-name", rendered)
        self.assertNotIn('"command":', rendered)

    def test_require_vm_refuses_before_authorization_or_selected_file_io_even_with_consent(self) -> None:
        output = io.StringIO()
        with patch("reverse_shell_decoy.virtual_analysis.request_authorization") as authorize, \
                patch("reverse_shell_decoy.virtual_analysis.read_regular", side_effect=AssertionError("opened")) as reader, \
                contextlib.redirect_stdout(output):
            self.assertEqual(
                virtual_main(["--require-vm", "--consent", "--sample", "/private/selected.txt"]),
                2,
            )
        authorize.assert_not_called()
        reader.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {"reason": "remote_vm_unavailable", "status": "error"})


class ProtectedMirrorRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_runner_default_denies_before_corpus_read_or_socket(self) -> None:
        with patch("reverse_shell_decoy.mirror_regression.load_corpus", side_effect=AssertionError("read")) as reader, \
                patch("reverse_shell_decoy.mirror_regression.DecoyServer.start", new=AsyncMock()) as start:
            with self.assertRaises(AuthorizationError):
                await run_regression("/selected/corpus.jsonl")
        reader.assert_not_called()
        start.assert_not_awaited()

    async def test_revocation_mid_reader_denies_before_listener_connect(self) -> None:
        path = "/selected/corpus.jsonl"
        scope = AuthorizationScope("mirror_regression", path)
        grant = request_authorization(scope, consent=True)
        assert grant is not None

        def revoke_during_read(*_args: object, **_kwargs: object) -> bytes:
            grant.revoke()
            return b'{"text":"inert"}\n'

        with patch("reverse_shell_decoy.mirror_regression.read_regular", side_effect=revoke_during_read), \
                patch("reverse_shell_decoy.mirror_regression.DecoyServer.start", new=AsyncMock()) as start:
            with self.assertRaises(AuthorizationError):
                await run_regression(path, authorization=grant, scope=scope)
        start.assert_not_awaited()

    async def test_revocation_after_listener_start_stops_it_before_any_callback(self) -> None:
        class _Socket:
            def getsockname(self) -> tuple[str, int]:
                return ("127.0.0.1", 43210)

        class _Server:
            sockets = (_Socket(),)

        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus.jsonl"
            corpus.write_text('{"text":"inert"}\n', encoding="utf-8")
            scope = AuthorizationScope("mirror_regression", str(corpus))
            grant = request_authorization(scope, consent=True)
            assert grant is not None

            async def start_then_revoke(*_args: object, **_kwargs: object) -> _Server:
                grant.revoke()
                return _Server()

            with patch("reverse_shell_decoy.mirror_regression.DecoyServer.start", new=AsyncMock(
                side_effect=start_then_revoke
            )) as start, patch("reverse_shell_decoy.mirror_regression.DecoyServer.shutdown", new=AsyncMock()) as shutdown, \
                    patch("reverse_shell_decoy.mirror_regression._echo_once", new=AsyncMock()) as echo:
                with self.assertRaises(AuthorizationError):
                    await run_regression(corpus, authorization=grant, scope=scope)

        start.assert_awaited_once()
        shutdown.assert_awaited_once()
        echo.assert_not_awaited()

    async def test_grant_cannot_launch_a_second_pipeline_after_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus.jsonl"
            corpus.write_text('{"text":"inert"}\n', encoding="utf-8")
            scope = AuthorizationScope("mirror_regression", str(corpus))
            grant = request_authorization(scope, consent=True)
            assert grant is not None

            result = await run_regression(corpus, authorization=grant, scope=scope)
            self.assertTrue(result["passed"])
            with patch("reverse_shell_decoy.mirror_regression.load_corpus", side_effect=AssertionError("read")) as reader:
                with self.assertRaises(AuthorizationError):
                    await run_regression(corpus, authorization=grant, scope=scope)
            reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
