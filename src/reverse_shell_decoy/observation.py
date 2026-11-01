"""Observation-completeness layer over the read-only listener inventory.

The base inventory in :mod:`reverse_shell_decoy.listeners` answers "which
bindings can I see right now".  This module answers the harder question a
security review actually needs: *how much of that answer is trustworthy, and
what did I fail to see*.

It adds, without any active network activity and without executing anything:

* a measured collection window plus a second independent snapshot, so a socket
  that disappears or changes owner mid-collection is reported as ``UNKNOWN``
  rather than attributed to whichever owner was seen first;
* every discovered owner of a binding, including forked children that share a
  listening descriptor, with parent/child relationships preserved;
* executable identity taken from the opened ``/proc/<pid>/exe`` object and
  checked before and after hashing, so a path is never treated as proof of an
  image;
* network-namespace coverage, so partial visibility is never presented as a
  clean host;
* explicit permission and coverage accounting with a ``COMPLETE`` / ``PARTIAL``
  / ``DEGRADED`` verdict;
* an optional independent ``NETLINK_SOCK_DIAG`` cross-check that reports
  disagreement between two kernel views instead of silently trusting one.

Nothing here decides that a binding is malicious.  A state of ``UNKNOWN`` means
the observation was incomplete, not that behaviour was unauthorized.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .listeners import MAX_COMM_LENGTH, _socket_inode, scan_listeners
from .sockdiag import collect_diag_bindings, compare_bindings

MAX_EXE_BYTES = 8 * 1024 * 1024
EXE_CHUNK = 65536
MAX_OWNER_PIDS = 4096

OWNERSHIP_CONFIRMED = "CONFIRMED"
OWNERSHIP_MULTIPLE = "MULTIPLE_OWNERS"
OWNERSHIP_UNKNOWN = "UNKNOWN"
OWNERSHIP_DEGRADED = "DEGRADED"

COVERAGE_NO_DATA = "NO_DATA"
COVERAGE_COMPLETE = "COMPLETE"
COVERAGE_PARTIAL = "PARTIAL"
COVERAGE_DEGRADED = "DEGRADED"

_LIMITATION_NOTICE = (
    "Observation completeness is measured, not assumed. UNKNOWN ownership means the "
    "binding could not be attributed, not that it is unauthorized. Namespace counts "
    "describe only processes this process could inspect. Exposure is a binding-scope "
    "description, not proof of reachability, and no external probing was performed."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def socket_reference(protocol: str, family: str, address: str, port: int, state: str) -> str:
    """Stable reference for one binding; keeps raw inode values internal."""
    material = "%s|%s|%s|%s|%s" % (protocol, family, address, port, state)
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _read_text(path: str, limit: int = 4096) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.readline(limit + 1)[:limit]
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _readlink(path: str, limit: int = 4096) -> Optional[str]:
    try:
        return os.readlink(path)[:limit]
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _parent_pid(proc_root: str, pid: int) -> Optional[int]:
    """Read only the parent PID field of ``/proc/<pid>/stat``.

    Field 4 is ``ppid``; the comm field may contain spaces and parentheses, so
    parsing starts after the final ``)`` rather than splitting the whole line.
    """
    text = _read_text(os.path.join(proc_root, str(pid), "stat"))
    if not text or ")" not in text:
        return None
    tail = text[text.rfind(")") + 1 :].split()
    if len(tail) < 2:
        return None
    try:
        return int(tail[1])
    except ValueError:
        return None


def _namespace_reference(proc_root: str, pid: int) -> Optional[str]:
    """Return a non-reversible reference for a process network namespace."""
    target = _readlink(os.path.join(proc_root, str(pid), "ns", "net"))
    if not target:
        return None
    return hashlib.sha256(target.encode()).hexdigest()[:24]


def _executable_identity(proc_root: str, pid: int, max_bytes: int) -> Dict[str, Any]:
    """Hash the opened executable object, not the path it was reached through.

    The file descriptor is opened once, hashed from that descriptor, and
    re-``fstat``-ed afterwards.  Any change in device, inode, size, or mtime
    across the hash, or an unlinked path name, is reported so the caller can
    refuse to treat the result as a verified image identity.
    """
    link_target = _readlink(os.path.join(proc_root, str(pid), "exe"))
    record: Dict[str, Any] = {
        "path_state": "unavailable",
        "deleted_in_path": bool(link_target and link_target.endswith(" (deleted)")),
        "image_sha256": None,
        "image_bytes_hashed": 0,
        "image_complete": False,
        "changed_during_hash": False,
        "identity_verified": False,
        "device_inode": None,
        "path_is_basename_only": True,
    }
    if link_target is None:
        return record
    descriptor = None
    try:
        descriptor = os.open(os.path.join(proc_root, str(pid), "exe"), os.O_RDONLY)
    except FileNotFoundError:
        record["path_state"] = "unlinked"
        return record
    except (PermissionError, OSError):
        record["path_state"] = "unreadable"
        return record
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            record["path_state"] = "not_a_regular_file"
            return record
        hasher = hashlib.sha256()
        hashed = 0
        complete = True
        while True:
            chunk = os.read(descriptor, EXE_CHUNK)
            if not chunk:
                break
            if hashed + len(chunk) > max_bytes:
                chunk = chunk[: max_bytes - hashed]
                complete = False
            hasher.update(chunk)
            hashed += len(chunk)
            if not complete:
                break
        after = os.fstat(descriptor)
        record.update({
            "path_state": "verified" if complete and not record["deleted_in_path"] else "partial",
            "image_sha256": hasher.hexdigest(),
            "image_bytes_hashed": hashed,
            "image_complete": complete,
            "changed_during_hash": (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
            ) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ),
            "device_inode": "%d:%d" % (before.st_dev, before.st_ino),
        })
        record["identity_verified"] = bool(
            complete and not record["changed_during_hash"] and not record["deleted_in_path"]
        )
        return record
    except OSError:
        record["path_state"] = "unreadable"
        return record
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _owner_detail(
    proc_root: str,
    pid: int,
    comm: str,
    exe_cache: Dict[Tuple[int, int], Dict[str, Any]],
    max_exe_bytes: int,
) -> Dict[str, Any]:
    """Describe one owner: lineage and namespace only, never credentials."""
    executable = _executable_identity(proc_root, pid, max_exe_bytes)
    cache_key = None
    identity = executable.get("device_inode")
    if isinstance(identity, str) and executable.get("identity_verified"):
        device, _, inode = identity.partition(":")
        try:
            cache_key = (int(device), int(inode))
        except ValueError:
            cache_key = None
    if cache_key is not None:
        cached = exe_cache.get(cache_key)
        if cached is not None:
            executable = dict(cached)
        else:
            exe_cache[cache_key] = dict(executable)
    return {
        "pid": pid,
        "comm": comm,
        "parent_pid": _parent_pid(proc_root, pid),
        "namespace_ref": _namespace_reference(proc_root, pid),
        "executable": executable,
    }


def _merge_owners(first: Dict[str, Any], second: Dict[str, Any]) -> Dict[str, Any]:
    """Record both snapshots' owners, keeping the union and any disagreement."""
    owners: Dict[int, Dict[str, Any]] = {}
    for listener in (first, second):
        for owner in listener.get("owners") or []:
            pid = owner.get("pid")
            if not isinstance(pid, int):
                continue
            owners.setdefault(pid, dict(owner))
    return owners


def collect_snapshot(
    proc_root: str = "/proc",
    *,
    recheck: bool = True,
    cross_verify: bool = True,
    max_exe_bytes: int = MAX_EXE_BYTES,
) -> Dict[str, Any]:
    """Collect one listener inventory with measured observation completeness.

    Two independent procfs snapshots are taken (unless ``recheck`` is false), so
    a binding that vanishes or changes owner between them is reported instead of
    silently attributed.  Cross-verification is read-only and degrades to an
    explicit ``not_verified`` result when the kernel does not offer it.
    """
    if isinstance(max_exe_bytes, bool) or not isinstance(max_exe_bytes, int):
        raise ValueError("max_exe_bytes must be an integer")
    if not 0 <= max_exe_bytes <= MAX_EXE_BYTES:
        raise ValueError("max_exe_bytes must be between 0 and %d" % MAX_EXE_BYTES)

    started_utc = _utc_now()
    started_monotonic = time.monotonic()
    first = scan_listeners(proc_root)
    first_finished_utc = _utc_now()
    second = scan_listeners(proc_root) if recheck else None
    second_finished_utc = _utc_now() if second is not None else None
    finished_monotonic = time.monotonic()

    warnings: List[str] = list(dict.fromkeys(first.get("warnings") or []))
    if second is not None:
        for warning in second.get("warnings") or []:
            if warning not in warnings:
                warnings.append(warning)

    def index(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {
            socket_reference(
                str(listener["protocol"]), str(listener["family"]),
                str(listener["address"]), int(listener["port"]), str(listener["state"]),
            ): listener
            for listener in snapshot.get("listeners") or []
        }

    second_index = index(second) if second is not None else None
    exe_cache: Dict[Tuple[int, int], Dict[str, Any]] = {}
    listeners: List[Dict[str, Any]] = []
    namespaces: Dict[str, int] = {}
    unresolved = 0
    inaccessible_namespaces = 0
    verified_owners = 0
    unverified_owners = 0

    for reference, listener in index(first).items():
        rechecked = None if second_index is None else second_index.get(reference)
        merged = _merge_owners(listener, rechecked or {}) if rechecked is not None else {
            owner["pid"]: dict(owner) for owner in listener.get("owners") or []
        }
        owners = [
            _owner_detail(proc_root, pid, str(owner.get("comm") or "unknown"), exe_cache, max_exe_bytes)
            for pid, owner in sorted(merged.items())
        ]
        for owner in owners:
            if owner["namespace_ref"] is not None:
                namespaces[owner["namespace_ref"]] = namespaces.get(owner["namespace_ref"], 0) + 1
            elif os.path.isdir(os.path.join(proc_root, str(owner["pid"]))):
                # The process is still present but its namespace link could not
                # be read, so coverage really is reduced for a live process.
                inaccessible_namespaces += 1
            if (owner["executable"] or {}).get("identity_verified"):
                verified_owners += 1
            else:
                unverified_owners += 1

        reasons: List[str] = []
        if not owners:
            state = OWNERSHIP_UNKNOWN
            reasons.append("no_owner_descriptor_observed")
            unresolved += 1
        elif rechecked is None:
            state = OWNERSHIP_MULTIPLE if len(owners) > 1 else OWNERSHIP_CONFIRMED
            reasons.append("single_snapshot_no_recheck")
        elif len(owners) > 1:
            state = OWNERSHIP_MULTIPLE
            reasons.append("multiple_processes_hold_this_binding")
        else:
            state = OWNERSHIP_CONFIRMED
        if rechecked is None and second is not None:
            state = OWNERSHIP_UNKNOWN
            reasons.append("binding_disappeared_before_recheck")
        elif rechecked is not None:
            previous = {owner.get("pid") for owner in listener.get("owners") or []}
            current = {owner.get("pid") for owner in rechecked.get("owners") or []}
            if previous and current and previous != current:
                state = OWNERSHIP_UNKNOWN
                reasons.append("owner_changed_between_snapshots")
        if any(reason.startswith("permission") for reason in warnings):
            if state == OWNERSHIP_CONFIRMED:
                state = OWNERSHIP_DEGRADED
            reasons.append("collector_permission_incomplete")

        owner_pids = {owner["pid"] for owner in owners}
        # A parent that is itself an owner of the same binding is the signature of
        # a listening descriptor inherited across fork.
        shared_parent = sorted(
            {owner["parent_pid"] for owner in owners
             if isinstance(owner["parent_pid"], int) and owner["parent_pid"] in owner_pids}
        )

        listeners.append({
            "binding_ref_sha256": reference,
            "protocol": listener["protocol"],
            "family": listener["family"],
            "address": listener["address"],
            "port": listener["port"],
            "state": listener["state"],
            "exposure": listener["exposure"],
            "direction": listener["direction"],
            "ownership": {
                "state": state,
                "reasons": reasons,
                "owner_count": len(owners),
                "shared_descriptor": len(owners) > 1,
                "fork_related_parent_pids": sorted(shared_parent),
                "recheck_observed": rechecked is not None,
            },
            "owners": owners,
        })

    listeners.sort(key=lambda item: (item["protocol"], item["family"], item["port"], item["address"]))
    total = len(listeners)
    with_owner = total - unresolved
    diag = collect_diag_bindings() if cross_verify else {
        "available": False, "reason": "cross_verification_not_requested", "observations": [],
    }
    comparison = compare_bindings(listeners, diag)

    permission_warnings = [warning for warning in warnings if warning.startswith("permission")]
    if total == 0:
        # Nothing visible is not the same as nothing present, and it must never
        # read as a clean host.
        coverage_state = COVERAGE_NO_DATA
    elif permission_warnings or inaccessible_namespaces:
        coverage_state = COVERAGE_DEGRADED
    elif unresolved or (second is not None and any(
        "disappeared" in reason or "changed" in reason
        for listener in listeners for reason in listener["ownership"]["reasons"]
    )):
        coverage_state = COVERAGE_PARTIAL
    else:
        coverage_state = COVERAGE_COMPLETE

    return {
        "listeners": listeners,
        "coverage": {
            "state": coverage_state,
            "bindings_observed": total,
            "bindings_with_owner": with_owner,
            "bindings_without_owner": unresolved,
            "ownership_ratio": round(with_owner / total, 4) if total else None,
            "owners_identity_verified": verified_owners,
            "owners_identity_unverified": unverified_owners,
            "permission_denials": len(permission_warnings),
            "permission_warning_labels": permission_warnings,
            "namespaces_observed": len(namespaces),
            "namespace_owner_counts": dict(sorted(namespaces.items())),
            "namespaces_inaccessible": inaccessible_namespaces,
            "namespace_scope": (
                "single_namespace" if len(namespaces) <= 1 else "multiple_namespaces"
            ),
            "collector_namespace_ref": _namespace_reference(proc_root, os.getpid()),
            "recheck_performed": second is not None,
            "statement": _coverage_statement(
                coverage_state, total, with_owner, unresolved, len(namespaces), len(permission_warnings)
            ),
        },
        "collection": {
            "started_utc": started_utc,
            "first_snapshot_utc": first_finished_utc,
            "second_snapshot_utc": second_finished_utc,
            "finished_utc": _utc_now(),
            "duration_seconds": round(finished_monotonic - started_monotonic, 6),
            "recheck_performed": second is not None,
            "snapshots": 2 if second is not None else 1,
        },
        "cross_verification": comparison,
        "warnings": warnings,
        "observed_at_utc": first_finished_utc,
        "simulation": False,
        "limitation_notice": _LIMITATION_NOTICE,
    }


def _coverage_statement(
    state: str,
    total: int,
    with_owner: int,
    unresolved: int,
    namespaces: int,
    permission_denials: int,
) -> str:
    """Human-readable completeness statement; never a clean/all-clear claim."""
    if total == 0:
        return "No bindings were visible in the namespaces this collector could inspect."
    parts = [
        "%d of %d visible bindings had an identified owner" % (with_owner, total),
        "%d could not be attributed" % unresolved,
        "%d network namespace(s) inspected" % max(namespaces, 0),
    ]
    if permission_denials:
        parts.append("%d permission denial(s) limited coverage" % permission_denials)
    return "%s: %s." % (state, "; ".join(parts))
