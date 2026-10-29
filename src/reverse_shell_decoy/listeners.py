"""Read-only Linux procfs listener inventory.

This module observes existing local procfs socket tables only.  It does not open
network sockets, send traffic, execute commands, or modify the host.  In
particular, a UDP entry in state ``07`` is an unconnected bound socket; it is
reported as ``UDP-bound`` rather than treated as proof that an application is
listening.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .detector import _decode_endpoint

# Keep both socket-table and /proc process traversal finite when procfs is
# unusually large, hostile, or represented by a deliberately broad fixture.
MAX_PROCESSES = 4096
MAX_FDS_PER_PROCESS = 1024
MAX_SOCKET_ROWS = 65536
MAX_SOCKET_LINE = 4096
MAX_LISTENERS = 65536
MAX_COMM_LENGTH = 64

LIMITATION_NOTICE = (
    "Read-only local procfs snapshot only. TCP LISTEN entries identify passive "
    "bindings; UDP state 07 entries are reported as UDP-bound and do not prove "
    "that an application is listening. Visibility limits, races, namespaces, "
    "and scan bounds can omit bindings or owners; network exposure alone is not "
    "malicious."
)


@dataclass(frozen=True)
class _SocketBinding:
    """A parsed binding kept internal so socket inode values are not emitted."""

    inode: str
    protocol: str
    family: str
    address: str
    port: int
    state: str


def scan_listeners(proc_root: str = "/proc") -> dict:
    """Return a bounded, passive inventory of locally observed socket bindings.

    The function reads only Linux procfs files.  It recognizes TCP/TCP6 rows in
    state ``0A`` and UDP/UDP6 rows in state ``07``.  Socket inode symlinks in
    ``/proc/<pid>/fd`` are correlated to a PID and the bounded ``comm`` value;
    command lines, environments, usernames, credentials, and process paths are
    intentionally never read or returned.

    Args:
        proc_root: Linux ``/proc`` directory, or a test fixture with equivalent
            ``net`` and PID/fd layout.

    Returns:
        A JSON-safe mapping containing ``listeners`` and a compatibility
        ``findings`` list (both neutral binding observations), warnings,
        ``observed_at_utc``, ``simulation`` (always ``False``), and a fixed
        limitation notice.
    """

    warnings: List[str] = []
    warning_set: Set[str] = set()

    def warn(message: str) -> None:
        # Static messages deliberately contain no proc-root paths or exception
        # text, which avoids leaking host-specific filesystem details.
        if message not in warning_set:
            warning_set.add(message)
            warnings.append(message)

    observed_at_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    result = {
        "listeners": [],
        "findings": [],
        "warnings": warnings,
        "observed_at_utc": observed_at_utc,
        "simulation": False,
        "limitation_notice": LIMITATION_NOTICE,
    }

    if not sys.platform.startswith("linux"):
        warn("listener scanning is supported only on Linux procfs")
        return result
    try:
        if not os.path.isdir(proc_root):
            warn("procfs is unavailable; listener snapshot was not collected")
            return result
    except PermissionError:
        warn("permission denied while accessing procfs snapshot")
        return result
    except OSError:
        warn("unable to access procfs snapshot")
        return result

    # A logical binding combines duplicate table rows and SO_REUSEPORT-style
    # socket inodes for the same endpoint, while retaining all discoverable
    # owners below.
    bindings: Dict[Tuple[str, str, str, int, str], dict] = {}
    inodes_by_binding: Dict[Tuple[str, str, str, int, str], Set[str]] = {}
    truncated = False
    table_specs = (
        ("tcp", "tcp", False, "0A", "LISTEN"),
        ("tcp6", "tcp", True, "0A", "LISTEN"),
        ("udp", "udp", False, "07", "UDP-bound"),
        ("udp6", "udp", True, "07", "UDP-bound"),
    )
    for table_name, protocol, ipv6, wanted_state, label in table_specs:
        for binding in _iter_socket_table(
            os.path.join(proc_root, "net", table_name),
            table_name,
            protocol,
            ipv6,
            wanted_state,
            label,
            warn,
        ):
            key = (
                binding.protocol,
                binding.family,
                binding.address,
                binding.port,
                binding.state,
            )
            if key not in bindings:
                if len(bindings) >= MAX_LISTENERS:
                    if not truncated:
                        warn("listener output limit reached; results may be incomplete")
                        truncated = True
                    continue
                bindings[key] = {
                    "protocol": binding.protocol,
                    "family": binding.family,
                    "address": binding.address,
                    "port": binding.port,
                    "exposure": _exposure(binding.address),
                    "owners": [],
                    "direction": "passive",
                    "state": binding.state,
                }
                inodes_by_binding[key] = set()
            inodes_by_binding[key].add(binding.inode)

    if not bindings:
        return result

    binding_keys_by_inode: Dict[str, Set[Tuple[str, str, str, int, str]]] = {}
    for key, inodes in inodes_by_binding.items():
        for inode in inodes:
            binding_keys_by_inode.setdefault(inode, set()).add(key)

    owners_by_inode = _correlate_owners(proc_root, set(binding_keys_by_inode), warn)
    for inode, owners in owners_by_inode.items():
        for key in binding_keys_by_inode.get(inode, set()):
            # Multiple descriptors for one socket and multiple socket inodes for
            # one logical binding are collapsed into one PID/comm owner record.
            existing = {owner["pid"] for owner in bindings[key]["owners"]}
            for owner in owners:
                if owner["pid"] not in existing:
                    bindings[key]["owners"].append(dict(owner))
                    existing.add(owner["pid"])

    listeners = list(bindings.values())
    for listener in listeners:
        listener["owners"].sort(key=lambda owner: (owner["pid"], owner["comm"]))
    listeners.sort(
        key=lambda listener: (
            listener["protocol"],
            listener["family"],
            listener["address"],
            listener["port"],
            listener["state"],
        )
    )

    # Keep the compatibility collection independently allocated so callers cannot
    # mutate one list and silently change the other.
    result["listeners"] = listeners
    result["findings"] = [_copy_listener(listener) for listener in listeners]
    return result


def _iter_socket_table(
    path: str,
    table_name: str,
    protocol: str,
    ipv6: bool,
    wanted_state: str,
    state_label: str,
    warn,
) -> Iterator[_SocketBinding]:
    """Yield selected rows from one procfs socket table, with bounded reads."""

    table_description = _table_description(table_name)
    try:
        with open(path, "r", encoding="ascii", errors="replace") as table:
            header = table.readline(MAX_SOCKET_LINE + 1)
            if len(header) > MAX_SOCKET_LINE:
                warn("socket table line limit reached; results may be incomplete")
                return
            for row_index in range(MAX_SOCKET_ROWS + 1):
                line = table.readline(MAX_SOCKET_LINE + 1)
                if not line:
                    break
                if row_index == MAX_SOCKET_ROWS or len(line) > MAX_SOCKET_LINE:
                    warn("socket table scan limit reached; results may be incomplete")
                    break
                parsed, malformed = _parse_socket_row(
                    line, protocol, ipv6, wanted_state, state_label
                )
                if malformed:
                    warn("malformed socket entry skipped")
                elif parsed is not None:
                    yield parsed
    except FileNotFoundError:
        warn("%s socket table is unavailable" % table_description)
    except PermissionError:
        warn("permission denied while reading %s socket table" % table_description)
    except OSError:
        warn("unable to read %s socket table" % table_description)


def _parse_socket_row(
    line: str,
    protocol: str,
    ipv6: bool,
    wanted_state: str,
    state_label: str,
) -> Tuple[Optional[_SocketBinding], bool]:
    """Return a selected binding plus a malformed-row indicator.

    Non-selected socket states (for example established TCP) are normal and do
    not generate warnings.  Linux puts the inode at field index 9, while later
    columns are kernel-specific and intentionally ignored.
    """

    fields = line.split()
    if not fields:
        return None, False
    if len(fields) >= 4 and fields[3].upper() != wanted_state:
        return None, False
    if len(fields) < 10:
        return None, True
    try:
        address, port = _decode_endpoint(fields[1], ipv6)
        inode = str(int(fields[9], 10))
    except (OSError, ValueError):
        return None, True
    return (
        _SocketBinding(
            inode=inode,
            protocol=protocol,
            family="IPv6" if ipv6 else "IPv4",
            address=address,
            port=port,
            state=state_label,
        ),
        False,
    )


def _table_description(table_name: str) -> str:
    """Return a static, path-free description for a known procfs table."""

    descriptions = {
        "tcp": "IPv4 TCP",
        "tcp6": "IPv6 TCP",
        "udp": "IPv4 UDP",
        "udp6": "IPv6 UDP",
    }
    return descriptions[table_name]


def _exposure(address: str) -> str:
    """Classify only the bind-address scope; do not inspect network interfaces."""

    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_unspecified:
        return "wildcard"
    return "interface"


def _correlate_owners(proc_root: str, socket_inodes: Set[str], warn) -> Dict[str, List[dict]]:
    """Map tracked socket inodes to bounded PID/comm owner observations."""

    try:
        proc_entries = os.scandir(proc_root)
    except FileNotFoundError:
        warn("process snapshot is unavailable")
        return {}
    except PermissionError:
        warn("permission denied while listing process snapshot")
        return {}
    except OSError:
        warn("unable to list process snapshot")
        return {}

    pid_names: List[str] = []
    try:
        for entry in proc_entries:
            # Accept only ordinary ASCII decimal PID names, not look-alikes.
            if not (entry.name.isascii() and entry.name.isdecimal()):
                continue
            if len(pid_names) >= MAX_PROCESSES:
                warn("process scan limit reached; results may be incomplete")
                break
            pid_names.append(entry.name)
    except PermissionError:
        warn("permission denied while listing process snapshot")
    except OSError:
        warn("unable to list process snapshot")
    finally:
        proc_entries.close()

    owners: Dict[str, Dict[int, str]] = {}
    comm_cache: Dict[str, Optional[str]] = {}
    for pid_text in sorted(pid_names, key=int):
        fd_directory = os.path.join(proc_root, pid_text, "fd")
        try:
            fd_entries = os.scandir(fd_directory)
        except FileNotFoundError:
            # Expected for processes that exit between directory scans.
            continue
        except PermissionError:
            warn("permission denied while reading process file descriptors")
            continue
        except OSError:
            warn("unable to read process file descriptors")
            continue

        try:
            for fd_index, entry in enumerate(fd_entries):
                if fd_index >= MAX_FDS_PER_PROCESS:
                    warn("file descriptor scan limit reached; results may be incomplete")
                    break
                try:
                    target = os.readlink(entry.path)
                except FileNotFoundError:
                    continue
                except PermissionError:
                    warn("permission denied while reading process file descriptors")
                    continue
                except OSError:
                    # A descriptor may disappear during a procfs snapshot race.
                    continue
                inode = _socket_inode(target)
                if inode is None or inode not in socket_inodes:
                    continue
                comm = _read_comm(proc_root, pid_text, comm_cache, warn)
                if comm is None:
                    continue
                owners.setdefault(inode, {})[int(pid_text)] = comm
        except PermissionError:
            warn("permission denied while reading process file descriptors")
        except OSError:
            warn("unable to read process file descriptors")
        finally:
            fd_entries.close()

    return {
        inode: [
            {"pid": pid, "comm": comm}
            for pid, comm in sorted(pid_to_comm.items(), key=lambda item: (item[0], item[1]))
        ]
        for inode, pid_to_comm in owners.items()
    }


def _socket_inode(target: str) -> Optional[str]:
    """Extract a normalized inode from a procfs ``socket:[inode]`` symlink."""

    if not target.startswith("socket:[") or not target.endswith("]"):
        return None
    value = target[8:-1]
    if not value.isdecimal():
        return None
    return str(int(value, 10))


def _read_comm(proc_root: str, pid_text: str, cache: Dict[str, Optional[str]], warn) -> Optional[str]:
    """Read only a bounded process name; never inspect cmdline, env, or identity."""

    if pid_text in cache:
        return cache[pid_text]
    try:
        with open(
            os.path.join(proc_root, pid_text, "comm"),
            "r",
            encoding="utf-8",
            errors="replace",
        ) as comm_file:
            # One extra character lets us preserve the full 64-character bound
            # while avoiding an unbounded line read from a malformed fixture.
            comm = comm_file.readline(MAX_COMM_LENGTH + 1).strip()[:MAX_COMM_LENGTH]
    except FileNotFoundError:
        cache[pid_text] = None
        return None
    except PermissionError:
        warn("permission denied while reading process names")
        cache[pid_text] = None
        return None
    except OSError:
        warn("unable to read process names")
        cache[pid_text] = None
        return None

    cache[pid_text] = comm or None
    return cache[pid_text]


def _copy_listener(listener: dict) -> dict:
    """Make a shallow JSON-safe listener copy with independent owner records."""

    copied = dict(listener)
    copied["owners"] = [dict(owner) for owner in listener["owners"]]
    return copied
