"""Synthetic-only analysis: no VM, host execution, network, or provider actions."""
from __future__ import annotations
import argparse
from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import sys
from typing import Any, Deque, Optional
from .input_files import read_regular
from .signals import inspect_text
from .simulator import DecoySession, MAX_INPUT, MAX_VIRTUAL_BYTES
_SESSION_ID, _MAX_REQUESTS, _MAX_AUDIT_EVENTS = "virtual-analysis-1", 16, 32
_REMOTE_VM_MESSAGE = "Remote VM backend is not configured; real execution is unavailable."
_CAPABILITY_MARKERS = ("/proc", "/sys", "/dev", "mount", "callback", "reverse shell",
                       "fsockopen", "stream_socket_client", "socket.socket", "unshare",
                       "nsenter", "chroot", "--privileged", "--no-sandbox", "disable isolation")
_INTERPRETERS = frozenset({"python", "python2", "python3", "bash", "sh", "perl", "ruby",
                           "node", "nodejs", "nc", "ncat", "powershell", "pwsh"})
class IsolationUnavailableError(RuntimeError):
    """The requested real-isolation backend is unavailable by design."""
def require_remote_vm_backend() -> None:
    """Always fail closed rather than falling back to a local executor or container."""
    raise IsolationUnavailableError(_REMOTE_VM_MESSAGE)
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def static_inspect(text: str) -> dict[str, Any]:
    """Bounded labels only; it neither simulates a command nor names a source."""
    if not isinstance(text, str):
        raise ValueError("input must be text")
    if len(text) > MAX_INPUT:
        raise ValueError("input exceeds the 4096-character limit")
    labels = inspect_text(text)
    return {"language_indicator": labels["language_indicator"],
            "token_indicators": labels["token_indicators"]}
class VirtualAnalysisComputer:
    """A transparent, dictionary-backed DecoySession—not a virtual machine.
    Python callers can alter Python state; this denies capabilities in this
    component and makes no impossible hypervisor-isolation guarantee.
    """
    def __init__(self, persona: str = "linux") -> None:
        self._persona = persona
        self._session = DecoySession(persona=persona, presentation="transparent")
        self._requests = self._input_bytes_total = 0
        self._destroyed = False
        self._audit: Deque[dict[str, Any]] = deque(maxlen=_MAX_AUDIT_EVENTS)
    @property
    def audit_events(self) -> tuple[dict[str, Any], ...]:
        """Deep-copied bounded audit records, suitable for JSONL serialization."""
        return tuple(deepcopy(event) for event in self._audit)
    @property
    def state_fingerprint(self) -> str:
        """Hash-only fingerprint of synthetic dictionaries, never a guest snapshot."""
        return self._state_sha()
    @staticmethod
    def static_inspect(text: str) -> dict[str, Any]:
        return static_inspect(text)
    def _state(self) -> dict[str, Any]:
        return {"closed": self._session.closed, "cwd": self._session.cwd,
                "directories": sorted(self._session.directories),
                "files": sorted(self._session.files.items())}
    def _state_sha(self) -> str:
        return _sha(json.dumps(self._state(), sort_keys=True, separators=(",", ":")).encode())
    @staticmethod
    def _capability_requested(text: str) -> bool:
        value, words = text.strip().lower(), text.strip().lower().split()
        if any(marker in value for marker in _CAPABILITY_MARKERS):
            return True
        if not words:
            return False
        return (words[0].strip("'\"") in _INTERPRETERS or
                (words[0] == "php" and len(words) > 1 and words[1] not in {"-v", "--version", "-m"}))
    @staticmethod
    def _verb(text: str, capability: bool) -> str:
        words = text.strip().split(None, 1)
        verb = words[0].lower() if words else "unsupported"
        return verb if not capability and verb in DecoySession.allowed_verbs else "unsupported"
    def _audit_command(self, input_sha256: Optional[str], labels: dict[str, Any], verb: str,
                       blocked: bool, reason: str, output_sha256: str, before: str,
                       before_files: int) -> None:
        after, after_files = self._state_sha(), len(self._session.files)
        self._audit.append({
            "event_type": "command", "timestamp_utc": _utc(), "session_id": _SESSION_ID,
            "source_kind": "in_memory_decoy", "interaction_observed": False,
            "synthetic_not_connection": True, "simulation": True, "response_mode": "console",
            "verb": verb, "blocked": blocked, "reason": reason, "input_sha256": input_sha256,
            "synthetic_output_sha256": output_sha256, "virtual_state_before_sha256": before,
            "virtual_state_after_sha256": after, "virtual_files_added": max(0, after_files - before_files),
            "virtual_files_removed": max(0, before_files - after_files), "host_execution": False,
            "network_access": False, "credential_access": False, "network_visitor": "none",
            "remote_os": "none", "language_indicator": labels["language_indicator"],
            "token_indicators": list(labels["token_indicators"]),
        })
    def _report(self, status: str, input_sha256: Optional[str], output: str,
                labels: dict[str, Any], before: str, before_files: int) -> dict[str, Any]:
        after, after_files = self._state_sha(), len(self._session.files)
        return {"simulation": True, "real_vm": False, "status": status,
                "input_sha256": input_sha256,
                "synthetic_output_sha256": _sha(output.encode("utf-8", errors="replace")),
                "virtual_state_sha256": after, "virtual_state_before_sha256": before,
                "virtual_state_after_sha256": after,
                "virtual_files_added": max(0, after_files - before_files),
                "virtual_files_removed": max(0, before_files - after_files),
                "host_execution": False, "network_access": False, "credential_access": False,
                "language_indicator": labels["language_indicator"],
                "token_indicators": list(labels["token_indicators"])}
    def _finish(self, status: str, input_sha256: Optional[str], output: str,
                labels: dict[str, Any], verb: str, blocked: bool, reason: str,
                before: str, before_files: int) -> dict[str, Any]:
        output_sha256 = _sha(output.encode("utf-8", errors="replace"))
        self._audit_command(input_sha256, labels, verb, blocked, reason, output_sha256, before, before_files)
        return self._report(status, input_sha256, output, labels, before, before_files)
    def submit(self, text: str) -> dict[str, Any]:
        """Perform one bounded synthetic request and retain no raw request or output."""
        before, before_files = self._state_sha(), len(self._session.files)
        if not isinstance(text, str):
            labels = {"language_indicator": "unknown", "token_indicators": []}
            return self._finish("blocked", None, "[SIMULATED] invalid text input; blocked\n", labels,
                                "unsupported", True, "input_type", before, before_files)
        if len(text) > MAX_INPUT:  # Never hash the full over-limit string.
            return self._finish("blocked", None, "[SIMULATED] input too long; blocked\n",
                                static_inspect(text[:MAX_INPUT]), "unsupported", True, "input_limit",
                                before, before_files)
        encoded, labels = text.encode("utf-8", errors="replace"), static_inspect(text)
        input_sha256, capability = _sha(encoded), self._capability_requested(text)
        verb = self._verb(text, capability)
        if self._destroyed or self._session.closed:
            return self._finish("closed", input_sha256, "[SIMULATED] session closed\n", labels,
                                verb, True, "synthetic_session_closed", before, before_files)
        if self._requests >= _MAX_REQUESTS:
            self._session.closed = True
            return self._finish("closed", input_sha256, "[SIMULATED] request limit reached; session closed\n",
                                labels, verb, True, "request_limit", before, before_files)
        if self._input_bytes_total + len(encoded) > MAX_VIRTUAL_BYTES:
            self._session.closed = True
            return self._finish("closed", input_sha256, "[SIMULATED] virtual byte limit reached; session closed\n",
                                labels, verb, True, "virtual_byte_limit", before, before_files)
        self._requests += 1
        self._input_bytes_total += len(encoded)
        if capability:
            return self._finish("blocked", input_sha256, "[SIMULATED] requested capability unavailable; blocked\n",
                                labels, verb, True, "capability_unavailable", before, before_files)
        output = self._session.execute(text)
        event = self._session.events[-1]
        status = "closed" if self._session.closed else ("blocked" if event["blocked"] else "simulated")
        return self._finish(status, input_sha256, output, labels, verb, bool(event["blocked"]),
                            event["reason"], before, before_files)
    def destroy(self) -> None:
        """Destroy only this object's synthetic dictionaries; no guest or OS operation occurs."""
        if self._destroyed:
            return
        self._destroyed, self._session.closed = True, True
        self._session.files.clear()
        self._session.directories.clear()
        self._session.events.clear()
        self._audit.append({"event_type": "close", "timestamp_utc": _utc(), "session_id": _SESSION_ID,
                            "source_kind": "in_memory_decoy", "interaction_observed": False,
                            "synthetic_not_connection": True, "simulation": True,
                            "response_mode": "console", "reason": "trusted_controller_destroy",
                            "host_execution": False, "network_access": False,
                            "credential_access": False, "network_visitor": "none", "remote_os": "none"})
    def reset(self) -> "VirtualAnalysisComputer":
        """Return a new clean synthetic instance after fail-closing this instance."""
        self.destroy()
        return type(self)(persona=self._persona)
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static labels or synthetic-only virtual analysis.")
    parser.add_argument("--sample", help="explicit regular UTF-8 text file (maximum 4096 bytes)")
    parser.add_argument("--consent", action="store_true", help="fresh noninteractive permission for this invocation")
    parser.add_argument("--require-vm", action="store_true", help="fail unless a remote VM backend is configured")
    parser.add_argument("--simulate", action="store_true", help="exercise only synthetic dictionary state")
    return parser
def _fresh_permission(consent_flag: bool) -> bool:
    if consent_flag:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        sys.stderr.write("Permission to read and process the selected sample? [y/N] ")
        sys.stderr.flush()
        return sys.stdin.readline().strip().lower() == "y"
    except (OSError, EOFError):
        return False
def main(argv: Optional[list[str]] = None) -> int:
    """Print one hash/label-only JSON result; never echo a path, sample, or output."""
    args = _parser().parse_args(argv)
    try:
        if args.require_vm:
            require_remote_vm_backend()  # Deliberately before a prompt, read, or analysis.
        if not args.sample or not _fresh_permission(args.consent):
            raise ValueError("permission_or_sample")
        raw = read_regular(args.sample, MAX_INPUT)
        text, source_sha256 = raw.decode("utf-8"), _sha(raw)
        result: dict[str, Any] = (VirtualAnalysisComputer().submit(text) if args.simulate else
                                  {"status": "static", "analysis_mode": "static_non_executing",
                                   "real_vm": False, "host_execution": False,
                                   "network_access": False, "credential_access": False,
                                   **static_inspect(text)})
        result["source_sha256"] = source_sha256
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except IsolationUnavailableError:
        print('{"reason":"remote_vm_unavailable","status":"error"}')
    except (OSError, UnicodeError, ValueError):
        print('{"reason":"permission_or_input_unavailable","status":"error"}')
    return 2
if __name__ == "__main__":
    raise SystemExit(main())
