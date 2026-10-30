"""Bounded subprocess checks for the authorization review findings.

Signals are sent only to short-lived child interpreters so this test never alters
or interrupts the parent test runner's signal handlers.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


_ROOT = Path(__file__).resolve().parents[1]
_CHILD = r"""
import json
import os
import signal
import socket
import sys
import threading
import time

from reverse_shell_decoy.authorization import (
    AuthorizationError,
    AuthorizationScope,
    cancellation_guard,
    request_authorization,
)

mode = sys.argv[1]
scope = AuthorizationScope("static_analysis", "synthetic-input", "synthetic-output")
grant = request_authorization(scope, consent=True)
assert grant is not None
previous_sigint = signal.getsignal(signal.SIGINT)

if mode == "pipe":
    read_fd, write_fd = os.pipe()
    resource = os.fdopen(read_fd, "rb", buffering=0)
    peer = None
else:
    resource, peer = socket.socketpair()
    write_fd = None


def interrupt() -> None:
    time.sleep(0.15)
    os.kill(os.getpid(), signal.SIGINT)

threading.Thread(target=interrupt, daemon=True).start()
started = time.monotonic()
try:
    with cancellation_guard(grant):
        if mode == "pipe":
            resource.read(1)
        else:
            resource.recv(1)
except AuthorizationError:
    try:
        grant.check(scope)
    except AuthorizationError:
        revoked = True
    else:
        revoked = False
    result = {
        "exception": "AuthorizationError",
        "elapsed": time.monotonic() - started,
        "revoked": revoked,
        "handler_restored": signal.getsignal(signal.SIGINT) == previous_sigint,
    }
else:
    result = {"exception": None, "elapsed": time.monotonic() - started}
finally:
    resource.close()
    if write_fd is not None:
        os.close(write_fd)
    if peer is not None:
        peer.close()

print(json.dumps(result))
sys.exit(0 if result["exception"] == "AuthorizationError" else 1)
"""


class CancellationGuardBlockingIOTests(unittest.TestCase):
    """PEP 475 retries only syscalls whose signal handlers return normally."""

    def test_sigint_interrupts_blocked_pipe_read_and_socket_receive(self) -> None:
        environment = dict(os.environ)
        source_root = str(_ROOT / "src")
        environment["PYTHONPATH"] = source_root + os.pathsep + environment.get("PYTHONPATH", "")

        for mode in ("pipe", "socket"):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [sys.executable, "-c", textwrap.dedent(_CHILD), mode],
                    cwd=_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual(result["exception"], "AuthorizationError")
                self.assertTrue(result["revoked"])
                self.assertTrue(result["handler_restored"])
                self.assertLess(result["elapsed"], 1.5)


if __name__ == "__main__":
    unittest.main()
