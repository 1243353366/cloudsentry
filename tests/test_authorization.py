"""Tests for the fresh per-invocation authorization gate."""
from __future__ import annotations

import io
import pickle
import signal
import threading
import unittest
from unittest.mock import patch

from reverse_shell_decoy import authorization as auth


class _TTY(io.StringIO):
    def __init__(self, value: str = "", *, interactive: bool = True) -> None:
        super().__init__(value)
        self._interactive = interactive

    def isatty(self) -> bool:
        return self._interactive


class _InterruptingTTY(_TTY):
    def readline(self, _limit: int = -1) -> str:
        raise KeyboardInterrupt


class AuthorizationScopeTests(unittest.TestCase):
    def test_scope_is_frozen_validated_and_redacts_references(self) -> None:
        scope = auth.AuthorizationScope("train", "/private/input", "/private/output")
        self.assertEqual(scope.operation, "train")
        self.assertNotIn("/private/input", repr(scope))
        self.assertNotIn("/private/output", repr(scope))
        with self.assertRaises((AttributeError, TypeError)):
            scope.input_ref = "changed"  # type: ignore[misc]

        for operation in ("", "access", "TRAIN"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                auth.AuthorizationScope(operation)
        for operation in (None, 1, True):
            with self.subTest(operation=operation), self.assertRaises(TypeError):
                auth.AuthorizationScope(operation)  # type: ignore[arg-type]
        for reference in ("x\x00y", "x" * 4097):
            with self.subTest(reference=reference[:1]), self.assertRaises(ValueError):
                auth.AuthorizationScope("train", reference)
        with self.assertRaises(TypeError):
            auth.AuthorizationScope("train", input_ref=1)  # type: ignore[arg-type]


class RequestAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = auth.AuthorizationScope("static_analysis", "/selected/input", "/selected/output")

    def test_explicit_boolean_consent_issues_fresh_opaque_grants(self) -> None:
        first = auth.request_authorization(self.scope, consent=True)
        second = auth.request_authorization(self.scope, consent=True)
        self.assertIsInstance(first, auth.AuthorizationGrant)
        self.assertIsNot(first, second)
        first.check(self.scope)  # type: ignore[union-attr]
        self.assertFalse(hasattr(auth.AuthorizationGrant, "from_json"))
        with self.assertRaises(TypeError):
            pickle.dumps(first)

    def test_truthy_non_booleans_are_rejected(self) -> None:
        for value in (1, {"consent": True}, "true", [True]):
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                auth.request_authorization(self.scope, consent=value)  # type: ignore[arg-type]

    def test_interactive_prompt_accepts_only_fresh_affirmation_without_paths(self) -> None:
        stderr = io.StringIO()
        with patch.object(auth.sys, "stdin", _TTY("y\n")), patch.object(auth.sys, "stderr", stderr):
            grant = auth.request_authorization(self.scope)
        self.assertIsInstance(grant, auth.AuthorizationGrant)
        self.assertIn("[y/N]", stderr.getvalue())
        self.assertNotIn(self.scope.input_ref, stderr.getvalue())
        self.assertNotIn(self.scope.output_ref, stderr.getvalue())

    def test_decline_eof_interrupt_and_noninteractive_never_issue(self) -> None:
        cases = (
            ("decline", _TTY("no\n")),
            ("eof", _TTY("")),
            ("interrupt", _InterruptingTTY()),
            ("noninteractive", _TTY("y\n", interactive=False)),
        )
        for label, stdin in cases:
            with self.subTest(label=label), patch.object(auth, "_issue") as issue, patch.object(
                auth.sys, "stdin", stdin
            ), patch.object(auth.sys, "stderr", io.StringIO()):
                self.assertIsNone(auth.request_authorization(self.scope))
                issue.assert_not_called()


class GrantEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = auth.AuthorizationScope("synthetic_analysis", "input-a", "output-a")

    def test_revocation_is_permanent(self) -> None:
        grant = auth.request_authorization(self.scope, consent=True)
        assert grant is not None
        grant.check(self.scope)
        grant.revoke()
        for _ in range(2):
            with self.assertRaises(auth.AuthorizationError):
                grant.check(self.scope)

    def test_scope_binding_and_expiry_are_exact(self) -> None:
        with patch.object(auth.time, "monotonic", side_effect=(100.0, 400.0)):
            grant = auth.request_authorization(self.scope, consent=True)
            assert grant is not None
            with self.assertRaises(auth.AuthorizationError):
                grant.check(self.scope)

        grant = auth.request_authorization(self.scope, consent=True)
        assert grant is not None
        for other in (
            auth.AuthorizationScope("synthetic_analysis", "input-b", "output-a"),
            auth.AuthorizationScope("synthetic_analysis", "input-a", "output-b"),
            auth.AuthorizationScope("static_analysis", "input-a", "output-a"),
        ):
            with self.subTest(other=other.operation), self.assertRaises(auth.AuthorizationError):
                grant.check(other)

    def test_snapshot_detects_low_level_scope_mutation(self) -> None:
        grant = auth.request_authorization(self.scope, consent=True)
        assert grant is not None
        object.__setattr__(self.scope, "input_ref", "rebound")
        with self.assertRaises(auth.AuthorizationError):
            grant.check(self.scope)

    def test_forged_values_and_direct_construction_are_rejected(self) -> None:
        grant = auth.request_authorization(self.scope, consent=True)
        assert grant is not None
        with self.assertRaises(TypeError):
            grant.check({"operation": "synthetic_analysis"})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            auth.AuthorizationGrant(self.scope)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            auth.AuthorizationGrant(self.scope, _token=object())

    def test_concurrent_revoke_has_deterministic_post_revoke_rejection(self) -> None:
        grant = auth.request_authorization(self.scope, consent=True)
        assert grant is not None
        first_check = threading.Barrier(2)
        revoked = threading.Barrier(2)
        outcome: list[str] = []

        def worker() -> None:
            grant.check(self.scope)
            first_check.wait()
            revoked.wait()
            try:
                grant.check(self.scope)
            except auth.AuthorizationError:
                outcome.append("rejected")

        thread = threading.Thread(target=worker)
        thread.start()
        first_check.wait()
        grant.revoke()
        revoked.wait()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome, ["rejected"])


class CancellationGuardTests(unittest.TestCase):
    def test_signal_handler_revokes_and_prior_handlers_are_restored(self) -> None:
        scope = auth.AuthorizationScope("mirror_regression")
        grant = auth.request_authorization(scope, consent=True)
        assert grant is not None
        previous = {signal.SIGINT: object(), signal.SIGTERM: object()}
        calls: list[tuple[int, object]] = []

        def get_signal(signum: int) -> object:
            return previous[signum]

        def set_signal(signum: int, handler: object) -> object:
            calls.append((signum, handler))
            return previous[signum]

        with patch.object(auth.signal, "getsignal", side_effect=get_signal), patch.object(
            auth.signal, "signal", side_effect=set_signal
        ):
            with self.assertRaisesRegex(auth.AuthorizationError, "authorization interrupted"):
                with auth.cancellation_guard(grant):
                    handler = dict(calls)[signal.SIGINT]
                    handler(signal.SIGINT, None)  # type: ignore[operator]

        with self.assertRaises(auth.AuthorizationError):
            grant.check(scope)
        self.assertEqual(calls[-2:], [(signal.SIGINT, previous[signal.SIGINT]), (signal.SIGTERM, previous[signal.SIGTERM])])

    def test_worker_thread_does_not_install_signal_handlers(self) -> None:
        scope = auth.AuthorizationScope("explain")
        grant = auth.request_authorization(scope, consent=True)
        assert grant is not None
        signal_calls: list[object] = []

        with patch.object(auth.signal, "signal", side_effect=signal_calls.append):
            thread = threading.Thread(target=lambda: self._use_guard(grant, scope))
            thread.start()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(signal_calls, [])

    @staticmethod
    def _use_guard(grant: auth.AuthorizationGrant, scope: auth.AuthorizationScope) -> None:
        with auth.cancellation_guard(grant):
            grant.check(scope)


if __name__ == "__main__":
    unittest.main()
