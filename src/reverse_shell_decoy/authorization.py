"""Fresh local operator authorization for bounded trusted-caller operations.

This is an in-process safety gate, not a host-security boundary. Arbitrary code
already running in this Python process can patch it. No grant is parsed from
customer data. Each invocation needs a new exact-scope, short-lived grant.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import secrets
import signal
import sys
import threading
import time
from typing import Iterator

__all__ = ["AuthorizationError", "AuthorizationGrant", "AuthorizationScope",
           "cancellation_guard", "request_authorization"]
_OPERATIONS = frozenset({"train", "explain", "static_analysis", "synthetic_analysis",
                         "mirror_regression", "verify_evidence", "backup_echo"})
_MAX_REF_LENGTH = 4096
_GRANT_TTL_SECONDS = 300.0
_ISSUANCE_TOKEN = object()


class AuthorizationError(RuntimeError):
    """The protected operation lacks a current exact-scope authorization."""


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationScope:
    operation: str
    input_ref: str = ""
    output_ref: str = ""

    def __post_init__(self) -> None:
        if type(self) is not AuthorizationScope:
            raise TypeError("authorization scopes cannot be subclassed")
        _validate_scope_fields(self.operation, self.input_ref, self.output_ref)

    def __repr__(self) -> str:
        return f"AuthorizationScope(operation={self.operation!r}, refs=<redacted>)"


def _validate_scope_fields(operation: object, input_ref: object, output_ref: object) -> None:
    if type(operation) is not str:
        raise TypeError("authorization operation must be a string")
    if operation not in _OPERATIONS:
        raise ValueError("unsupported authorization operation")
    for reference in (input_ref, output_ref):
        if type(reference) is not str:
            raise TypeError("authorization references must be strings")
        if len(reference) > _MAX_REF_LENGTH or "\x00" in reference:
            raise ValueError("invalid authorization reference")


def _validate_scope(scope: AuthorizationScope) -> None:
    if type(scope) is not AuthorizationScope:
        raise TypeError("authorization scope is required")
    _validate_scope_fields(scope.operation, scope.input_ref, scope.output_ref)


class AuthorizationGrant:
    """Opaque, non-serializable and revocable; admits one pipeline only."""
    __slots__ = ("_grant_id", "_issued_monotonic", "_lock", "_revoked", "_scope", "_started")

    def __init__(self, scope: AuthorizationScope, *, _token: object) -> None:
        if _token is not _ISSUANCE_TOKEN:
            raise TypeError("authorization grants are issued only by the authorization gate")
        _validate_scope(scope)
        self._scope = AuthorizationScope(scope.operation, scope.input_ref, scope.output_ref)
        self._issued_monotonic = time.monotonic()
        self._grant_id = secrets.token_hex(16)
        self._lock = threading.RLock()
        self._revoked = False
        self._started = False

    def __reduce__(self) -> object:
        raise TypeError("authorization grants cannot be serialized")

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True

    def check(self, scope: AuthorizationScope) -> None:
        _validate_scope(scope)
        with self._lock:
            expired = time.monotonic() - self._issued_monotonic >= _GRANT_TTL_SECONDS
            if self._revoked or expired or scope != self._scope:
                raise AuthorizationError("authorization grant is not valid")

    def begin(self, scope: AuthorizationScope) -> None:
        """Atomic admission; a grant cannot start a second or concurrent pipeline."""
        with self._lock:
            self.check(scope)
            if self._started:
                raise AuthorizationError("authorization grant already used")
            self._started = True


def _issue(scope: AuthorizationScope) -> AuthorizationGrant:
    _validate_scope(scope)
    return AuthorizationGrant(scope, _token=_ISSUANCE_TOKEN)


def _interactive_input() -> str | None:
    try:
        if not sys.stdin.isatty():
            return None
        sys.stderr.write("Authorize this operation? [y/N] ")
        sys.stderr.flush()
        return sys.stdin.readline(16)
    except (KeyboardInterrupt, EOFError, OSError):
        return None


def request_authorization(scope: AuthorizationScope, *, consent: bool = False) -> AuthorizationGrant | None:
    _validate_scope(scope)
    if type(consent) is not bool:
        raise TypeError("consent must be a bool")
    if consent:
        return _issue(scope)
    response = _interactive_input()
    if response is not None and response.strip().casefold() in {"y", "yes"}:
        return _issue(scope)
    return None


@contextmanager
def cancellation_guard(grant: AuthorizationGrant) -> Iterator[AuthorizationGrant]:
    """Revoke on CLI SIGINT/SIGTERM and restore previous handlers on exit.

    Worker threads do not install process signal handlers; they retain explicit
    thread-safe checks and revocation. SIGKILL/power loss cannot be caught.
    """
    if type(grant) is not AuthorizationGrant:
        raise TypeError("authorization grant is required")
    if threading.current_thread() is not threading.main_thread():
        yield grant
        return
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def interrupted(_number: int, _frame: object) -> None:
        grant.revoke()
        raise AuthorizationError("authorization interrupted")

    installed: list[int] = []
    try:
        for number in previous:
            signal.signal(number, interrupted)
            installed.append(number)
        yield grant
    finally:
        for number in installed:
            signal.signal(number, previous[number])
