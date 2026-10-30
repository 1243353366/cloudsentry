"""Fail-closed, customer-delegated cgroup-v2 boundary for the fixed echo workload.

This module is deliberately *not* a general process runner.  Its only launch
vector is ``scripts/start-backup-echo.py --consent``.  Review mode performs no
sysfs access or writes.  Application requires an explicit, pre-delegated v2
parent and an external, trusted GPU-deny-policy verification integration; the
standalone CLI intentionally has no such integration and therefore fails
closed before creating a cgroup or starting a service.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import glob
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Iterator, Mapping

from .authorization import AuthorizationError, AuthorizationGrant, AuthorizationScope, request_authorization

__all__ = [
    "CAPS", "POLICY_HASH", "ResourceBoundaryError", "apply_fixed_echo",
    "build_review_report", "counter_delta", "main", "parse_counters",
    "parse_io_stat", "prepare_cgroup", "validate_cgroup_parent",
]

CGROUP_ROOT = Path("/sys/fs/cgroup")
_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids", "io"})
_MAX_TELEMETRY_BYTES = 16 * 1024
_MAX_COUNTER_LINES = 128
_MAX_GPU_PATHS = 50
_MAX_SUPERVISION_SECONDS = 35.0
_POLL_SECONDS = 0.1

# These values are intentionally constants, rather than customer-provided
# parameters.  The application's separate 4 KiB/two-slot/30-second limits are
# enforced by backup_echo itself.
CAPS: dict[str, str] = {
    "cpu.max": "25000 100000",
    "memory.max": "268435456",
    "memory.swap.max": "0",
    "pids.max": "32",
}
_IO_CAP_VALUES: dict[str, str] = {
    "rbps": "1048576", "wbps": "1048576", "riops": "128", "wiops": "128",
}
_POLICY = {
    "format": "resource_boundary_v1",
    "fixed_workload": "scripts/start-backup-echo.py --consent",
    "loopback_defaults_only": True,
    "application_limits": {"slots": 2, "max_runtime_seconds": 30, "input_bytes_per_slot": 4096},
    "caps": {**CAPS, "io.max": _IO_CAP_VALUES},
    "gpu": "external_deny_policy_required; no CLI attestation accepted",
    "supervision": {"max_seconds": 35, "poll_seconds": _POLL_SECONDS},
}
POLICY_HASH = hashlib.sha256(json.dumps(_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class ResourceBoundaryError(RuntimeError):
    """A requested boundary could not be established and was not deployed."""


@dataclass(frozen=True, slots=True)
class CgroupPlan:
    """Validated, customer-delegated parent and explicit block-device selector."""

    parent: Path
    io_device: str
    root: Path


def _fixed_error(message: str) -> ResourceBoundaryError:
    # Callers must not include paths, environment values, workload output, or
    # supplied text in a report.  Keep failures categorical and non-sensitive.
    return ResourceBoundaryError(message)


def _validate_io_device(value: object) -> str:
    if type(value) is not str or len(value) > 16:
        raise _fixed_error("invalid_io_device")
    pieces = value.split(":")
    if len(pieces) != 2 or not all(piece.isascii() and piece.isdecimal() for piece in pieces):
        raise _fixed_error("invalid_io_device")
    major, minor = (int(piece) for piece in pieces)
    if major > 1_048_575 or minor > 1_048_575:
        raise _fixed_error("invalid_io_device")
    return f"{major}:{minor}"


def _lexical_child(parent: Path, root: Path) -> None:
    """Reject root, escapes, missing segments, and every symlink in the chain."""
    if not parent.is_absolute() or not root.is_absolute() or parent == root:
        raise _fixed_error("invalid_cgroup_parent")
    try:
        relative = parent.relative_to(root)
    except ValueError:
        raise _fixed_error("invalid_cgroup_parent") from None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise _fixed_error("invalid_cgroup_parent")
    current = root
    for part in (".", *relative.parts):
        if part != ".":
            current = current / part
        try:
            mode = os.lstat(current).st_mode
        except OSError:
            raise _fixed_error("cgroup_parent_unavailable") from None
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise _fixed_error("cgroup_parent_not_real_directory")


def _read_small(path: Path, *, limit: int = _MAX_TELEMETRY_BYTES) -> str:
    try:
        with path.open("rb") as handle:
            value = handle.read(limit + 1)
    except OSError:
        raise _fixed_error("cgroup_read_unavailable") from None
    if len(value) > limit:
        raise _fixed_error("cgroup_read_invalid")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        raise _fixed_error("cgroup_read_invalid") from None


def validate_cgroup_parent(parent: str | Path, io_device: str) -> CgroupPlan:
    """Validate only a delegated, enabled v2 parent; never enable controllers.

    The production root is the module constant ``/sys/fs/cgroup``.  Tests may
    patch that private module constant to an owned temporary mock tree; callers
    cannot select another root through this API.
    """
    if not isinstance(parent, (str, Path)):
        raise _fixed_error("invalid_cgroup_parent")
    root = CGROUP_ROOT
    chosen = Path(parent)
    # Do not resolve: resolving would follow a symlink before we reject it.
    _lexical_child(chosen, root)
    controllers = _read_small(root / "cgroup.controllers", limit=1024).split()
    if not _REQUIRED_CONTROLLERS.issubset(set(controllers)):
        raise _fixed_error("cgroup_v2_controllers_unavailable")
    enabled = _read_small(chosen / "cgroup.subtree_control", limit=1024).split()
    if not _REQUIRED_CONTROLLERS.issubset(set(enabled)):
        raise _fixed_error("delegated_controllers_not_enabled")
    return CgroupPlan(parent=chosen, io_device=_validate_io_device(io_device), root=root)


def _gpu_nodes_present() -> bool:
    """Bounded local discovery; existence alone prevents standalone deployment."""
    examined = 0
    for pattern in ("/dev/dri", "/dev/dri/*", "/dev/nvidia*", "/dev/kfd"):
        for path in glob.iglob(pattern):
            examined += 1
            if examined > _MAX_GPU_PATHS:
                return True
            if os.path.exists(path):
                return True
    return False


def _require_external_gpu_deny_policy(verifier: Callable[[], bool] | None) -> None:
    """Accept only a trusted in-process integration, never a CLI/file assertion.

    Absence of currently visible device nodes cannot prove denial after hotplug.
    The standalone CLI passes no verifier and is therefore intentionally unable
    to deploy.  An integrating, authorized controller must perform its own
    external device/eBPF policy verification immediately before this call.
    """
    if _gpu_nodes_present() or verifier is None:
        raise _fixed_error("gpu_policy_not_verified")
    try:
        verified = verifier()
    except BaseException:
        raise _fixed_error("gpu_policy_not_verified") from None
    if verified is not True:
        raise _fixed_error("gpu_policy_not_verified")


def _write_exact(path: Path, value: str) -> None:
    try:
        with path.open("w", encoding="ascii", newline="") as handle:
            handle.write(value + "\n")
    except OSError:
        raise _fixed_error("cgroup_write_failed") from None


def _normalized_tokens(value: str) -> tuple[str, ...]:
    tokens = tuple(value.split())
    if not tokens or any(any(ord(char) < 0x21 or ord(char) > 0x7E for char in token) for token in tokens):
        raise _fixed_error("cgroup_readback_invalid")
    return tokens


def _verify_scalar(child: Path, name: str, expected: str) -> None:
    received = _normalized_tokens(_read_small(child / name, limit=256))
    if received != tuple(expected.split()):
        raise _fixed_error("cgroup_readback_mismatch")


def _parse_io_max(value: str, device: str) -> Mapping[str, str]:
    found: Mapping[str, str] | None = None
    for line in value.splitlines():
        tokens = _normalized_tokens(line)
        if len(tokens) < 2 or tokens[0] != device:
            continue
        fields: dict[str, str] = {}
        for token in tokens[1:]:
            if token.count("=") != 1:
                raise _fixed_error("cgroup_readback_invalid")
            key, number = token.split("=", 1)
            if key not in _IO_CAP_VALUES or not number.isdecimal() or key in fields:
                raise _fixed_error("cgroup_readback_invalid")
            fields[key] = number
        if found is not None:
            raise _fixed_error("cgroup_readback_invalid")
        found = fields
    if found is None:
        raise _fixed_error("cgroup_readback_mismatch")
    return found


def _verify_io_max(child: Path, device: str) -> None:
    observed = _parse_io_max(_read_small(child / "io.max", limit=2048), device)
    if dict(observed) != _IO_CAP_VALUES:
        raise _fixed_error("cgroup_readback_mismatch")


def _new_child(plan: CgroupPlan) -> Path:
    """Create one private random direct child; no parent configuration changes."""
    for _ in range(4):
        child = plan.parent / f"resource-boundary-{secrets.token_hex(16)}"
        try:
            child.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError:
            raise _fixed_error("cgroup_child_create_failed") from None
        try:
            mode = os.lstat(child).st_mode
        except OSError:
            raise _fixed_error("cgroup_child_create_failed") from None
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise _fixed_error("cgroup_child_create_failed")
        return child
    raise _fixed_error("cgroup_child_create_failed")


def prepare_cgroup(parent: str | Path, io_device: str, *,
                    gpu_policy_verifier: Callable[[], bool] | None = None) -> Path:
    """Create and exactly verify a new delegated child, or raise without launch.

    This is intentionally separate from process launch for unit testing.  It
    has writes only after v2/delegation/GPU checks have all succeeded.
    """
    plan = validate_cgroup_parent(parent, io_device)
    _require_external_gpu_deny_policy(gpu_policy_verifier)
    child: Path | None = None
    try:
        child = _new_child(plan)
        for name, value in CAPS.items():
            _write_exact(child / name, value)
            _verify_scalar(child, name, value)
        io_value = " ".join([plan.io_device, *(f"{key}={value}" for key, value in _IO_CAP_VALUES.items())])
        _write_exact(child / "io.max", io_value)
        _verify_io_max(child, plan.io_device)
        return child
    except BaseException:
        if child is not None:
            _remove_empty_child(child)
        raise


def parse_counters(value: str) -> dict[str, int]:
    """Parse bounded ``key integer`` telemetry without treating missing as zero."""
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > _MAX_TELEMETRY_BYTES:
        raise ValueError("invalid bounded telemetry")
    output: dict[str, int] = {}
    lines = value.splitlines()
    if len(lines) > _MAX_COUNTER_LINES:
        raise ValueError("invalid bounded telemetry")
    for line in lines:
        pieces = line.split()
        if len(pieces) != 2 or len(pieces[0]) > 64 or not pieces[0].replace("_", "").isalnum() or not pieces[1].isdecimal():
            raise ValueError("invalid bounded telemetry")
        if pieces[0] in output:
            raise ValueError("invalid bounded telemetry")
        number = int(pieces[1])
        if number > (2 ** 63 - 1):
            raise ValueError("invalid bounded telemetry")
        output[pieces[0]] = number
    return output


def parse_io_stat(value: str, io_device: str) -> dict[str, int]:
    """Return bounded numeric counters for the explicit device only."""
    device = _validate_io_device(io_device)
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > _MAX_TELEMETRY_BYTES:
        raise ValueError("invalid bounded telemetry")
    result: dict[str, int] = {}
    lines = value.splitlines()
    if len(lines) > _MAX_COUNTER_LINES:
        raise ValueError("invalid bounded telemetry")
    matching = 0
    for line in lines:
        fields = line.split()
        if not fields or fields[0] != device:
            continue
        matching += 1
        if matching > 1:
            raise ValueError("invalid bounded telemetry")
        for field in fields[1:]:
            if field.count("=") != 1:
                raise ValueError("invalid bounded telemetry")
            key, number = field.split("=", 1)
            if len(key) > 64 or not key.replace("_", "").isalnum() or not number.isdecimal() or key in result:
                raise ValueError("invalid bounded telemetry")
            parsed = int(number)
            if parsed > (2 ** 63 - 1):
                raise ValueError("invalid bounded telemetry")
            result[key] = parsed
    return result


def counter_delta(before: Mapping[str, int] | None, after: Mapping[str, int] | None,
                  keys: tuple[str, ...]) -> dict[str, int | str]:
    """Counter reset/missing values are ``unknown``, never deceptively zero."""
    answer: dict[str, int | str] = {}
    for key in keys:
        left = before.get(key) if before is not None else None
        right = after.get(key) if after is not None else None
        if type(left) is not int or type(right) is not int or left < 0 or right < left:
            answer[key] = "unknown"
        else:
            answer[key] = right - left
    return answer


def _telemetry(child: Path, io_device: str) -> dict[str, Mapping[str, int] | None]:
    """Read only numeric owned-child counters; a failed read remains unknown."""
    output: dict[str, Mapping[str, int] | None] = {}
    readers: tuple[tuple[str, str, Callable[[str], dict[str, int]]], ...] = (
        ("cpu", "cpu.stat", parse_counters),
        ("memory", "memory.events", parse_counters),
        ("pids", "pids.events", parse_counters),
        ("io", "io.stat", lambda text: parse_io_stat(text, io_device)),
    )
    for output_name, filename, parser in readers:
        try:
            output[output_name] = parser(_read_small(child / filename))
        except (ResourceBoundaryError, ValueError):
            output[output_name] = None
    return output


def _report_from_telemetry(before: Mapping[str, Mapping[str, int] | None],
                           after: Mapping[str, Mapping[str, int] | None], io_device: str) -> dict[str, Any]:
    return {
        "format": "resource_boundary_v1",
        "source_policy_hash": POLICY_HASH,
        "ready": False,
        "status": {"cpu": "verified_local_readback", "mem": "verified_local_readback",
                   "io": "verified_local_readback", "gpu": "not_verified"},
        "telemetry": {
            "cpu": {"usage_usec": counter_delta(before["cpu"], after["cpu"], ("usage_usec",)),
                    "pressure_label": "CPU throttled counters are observations, not cause attribution",
                    "throttled": counter_delta(before["cpu"], after["cpu"], ("nr_throttled", "throttled_usec"))},
            "mem": {"events": counter_delta(before["memory"], after["memory"], ("low", "high", "max", "oom", "oom_kill")),
                    "pressure_label": "memory event counters are observations, not cause attribution"},
            "io": {"device": io_device, "counters": counter_delta(before["io"], after["io"], ("rbytes", "wbytes", "rios", "wios")),
                   "observation": "IO counters can miss buffered writes and are not a delivery or attribution claim"},
            "pids": {"events": counter_delta(before["pids"], after["pids"], ("max",)),
                     "pressure_label": "PID max counters are observations, not cause attribution"},
        },
        "gpu_note": "not verified: absence of visible GPU nodes cannot guarantee denial after hotplug",
        "private_audit": {"workload": "fixed_loopback_echo", "raw_workload_output_recorded": False},
    }


def _join_preexec(child: str) -> Callable[[], None]:
    """Return the single-thread-only pre-exec hook that moves the child itself."""
    def join() -> None:
        descriptor = os.open(os.path.join(child, "cgroup.procs"), os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.write(descriptor, b"0\n")  # Linux moves the writing process itself.
        finally:
            os.close(descriptor)
    return join


def _child_present(child: Path, pid: int) -> bool:
    try:
        values = _read_small(child / "cgroup.procs", limit=4096).split()
    except ResourceBoundaryError:
        return False
    if len(values) > _MAX_COUNTER_LINES or any(not value.isdecimal() for value in values):
        return False
    return str(pid) in values


def _kill_created_child(child: Path) -> None:
    """Only affect the fresh child.  There is deliberately no parent fallback."""
    kill_file = child / "cgroup.kill"
    if kill_file.is_file():
        try:
            _write_exact(kill_file, "1")
        except ResourceBoundaryError:
            pass


def _remove_empty_child(child: Path) -> None:
    try:
        child.rmdir()
    except OSError:
        pass


def _fixed_environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONUNBUFFERED": "1"}


def _fixed_workload_path() -> Path:
    path = Path(__file__).resolve().parents[2] / "scripts" / "start-backup-echo.py"
    if not path.is_file() or path.is_symlink():
        raise _fixed_error("fixed_workload_unavailable")
    return path


@contextmanager
def _interrupt_cleanup() -> Iterator[None]:
    """Convert terminal signals into cleanup while in the CLI/main thread."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    def interrupted(_number: int, _frame: object) -> None:
        raise InterruptedError("resource boundary interrupted")
    try:
        for number in previous:
            signal.signal(number, interrupted)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def apply_fixed_echo(parent: str | Path, io_device: str, *,
                     gpu_policy_verifier: Callable[[], bool] | None = None,
                     continue_check: Callable[[], bool] | None = None,
                     authorization: AuthorizationGrant | None = None) -> dict[str, Any]:
    """Launch only the fixed echo script after exact local cgroup verification.

    ``continue_check`` is an authorized controller hook; a false/error result
    stops the fresh child.  The module itself does not invent authorization.
    It rejects multithreaded callers because ``preexec_fn`` is safe here only
    for the standalone single-threaded CLI path.
    """
    scope = resource_scope(parent, io_device)
    if type(authorization) is not AuthorizationGrant:
        raise AuthorizationError("fresh resource-boundary authorization required")
    authorization.begin(scope)
    child: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        authorization.check(scope)
        if threading.active_count() != 1:
            raise _fixed_error("threaded_caller_refused")
        with _interrupt_cleanup():
            child = prepare_cgroup(parent, io_device, gpu_policy_verifier=gpu_policy_verifier)
            authorization.check(scope)
            before = _telemetry(child, _validate_io_device(io_device))
            authorization.check(scope)
            process = subprocess.Popen(
                [sys.executable, str(_fixed_workload_path()), "--consent"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, env=_fixed_environment(), start_new_session=True,
                preexec_fn=_join_preexec(str(child)),
            )
            if not _child_present(child, process.pid):
                raise _fixed_error("child_membership_not_verified")
            deadline = time.monotonic() + _MAX_SUPERVISION_SECONDS
            while process.poll() is None:
                authorization.check(scope)
                if time.monotonic() >= deadline:
                    raise _fixed_error("workload_deadline_exceeded")
                if continue_check is not None:
                    try:
                        permitted = continue_check()
                    except BaseException:
                        permitted = False
                    if permitted is not True:
                        raise _fixed_error("authorization_no_longer_valid")
                time.sleep(_POLL_SECONDS)
            authorization.check(scope)
            after = _telemetry(child, _validate_io_device(io_device))
            report = _report_from_telemetry(before, after, _validate_io_device(io_device))
            report["workload_exit_code"] = process.returncode
            report["ready"] = process.returncode == 0
            # GPU approval is supplied by a separate trusted integration, not
            # by local cgroup readback.  Do not upgrade this report's GPU status.
            authorization.check(scope)
            return report
    except BaseException:
        if child is not None:
            _kill_created_child(child)
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        raise
    finally:
        if child is not None:
            _remove_empty_child(child)
        authorization.revoke()


def resource_scope(parent: str | Path, io_device: str) -> AuthorizationScope:
    """Bind approval to the selected parent, block device and fixed policy."""
    selected = json.dumps({"parent": os.path.abspath(str(parent)),
                           "io_device": _validate_io_device(io_device), "policy": POLICY_HASH},
                          sort_keys=True, separators=(",", ":"))
    return AuthorizationScope("resource_boundary", hashlib.sha256(selected.encode()).hexdigest())


def build_review_report() -> dict[str, Any]:
    """Return the no-write/no-service report without reading host cgroup state."""
    return {
        "format": "resource_boundary_v1",
        "source_policy_hash": POLICY_HASH,
        "ready": False,
        "review_only": True,
        "service_launched": False,
        "status": {"cpu": "declared", "mem": "declared", "io": "declared", "gpu": "not_verified"},
        "fixed_workload": "scripts/start-backup-echo.py --consent",
        "caps": {**CAPS, "io.max": dict(_IO_CAP_VALUES)},
        "application_limits": {"slots": 2, "max_runtime_seconds": 30, "input_bytes_per_slot": 4096},
        "gpu_note": "no GPU access or global future-hotplug guarantee is claimed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review or fail-closed apply the fixed echo cgroup boundary.", allow_abbrev=False)
    parser.add_argument("--consent", action="store_true", help="manual operator consent; required with --apply")
    parser.add_argument("--apply", action="store_true", help="attempt the fixed workload only (standalone CLI fails closed on GPU policy)")
    parser.add_argument("--review", action="store_true", help="explicit no-write review (the default)")
    parser.add_argument("--cgroup-parent", metavar="ABSOLUTE_PATH")
    parser.add_argument("--io-device", metavar="MAJOR:MINOR")
    try:
        args = parser.parse_args(argv)
        if not args.apply:
            if args.cgroup_parent is not None or args.io_device is not None:
                raise _fixed_error("apply_options_require_apply")
            print(json.dumps(build_review_report(), sort_keys=True))
            return 0
        if args.review or not args.consent or args.cgroup_parent is None or args.io_device is None:
            raise _fixed_error("explicit_consent_parent_and_io_device_required")
        # No --gpu-* flag exists.  A direct CLI cannot prove an external device
        # policy and so _require_external_gpu_deny_policy rejects before writes.
        scope = resource_scope(args.cgroup_parent, args.io_device)
        grant = request_authorization(scope, consent=args.consent)
        if grant is None:
            raise AuthorizationError("resource approval required")
        try:
            apply_fixed_echo(args.cgroup_parent, args.io_device, authorization=grant)
        finally:
            grant.revoke()
        return 0
    except (AuthorizationError, ResourceBoundaryError, OSError, ValueError, InterruptedError, KeyboardInterrupt):
        print("Resource boundary not deployed; no service was launched or retained.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
