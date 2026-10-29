"""Read-only, heuristic procfs correlation for possible shell-linked TCP sockets.

This module intentionally does not execute commands, inspect command-line arguments,
send network traffic, signal processes, or alter the host.  Its output is a snapshot
heuristic only: an established TCP entry cannot establish which endpoint initiated it.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# Bounds avoid an untrusted or unusually large procfs causing unlimited work.
MAX_PROCESSES = 4096
MAX_FDS_PER_PROCESS = 1024
MAX_ANCESTRY_DEPTH = 16
MAX_TCP_ROWS = 65536
MAX_TCP_LINE = 4096

# These are process *names* from /proc/<pid>/comm, not command-line arguments.
SHELL_NAMES = frozenset(
    {
        "ash",
        "bash",
        "csh",
        "dash",
        "elvish",
        "fish",
        "ksh",
        "mksh",
        "nu",
        "pwsh",
        "rbash",
        "sh",
        "tcsh",
        "xonsh",
        "yash",
        "zsh",
    }
)

LIMITATION_NOTICE = (
    "Heuristic, read-only procfs snapshot only. An established TCP socket and its "
    "local/remote fields do not prove connection direction, intent, or compromise; "
    "limited visibility, races, namespaces, and short-lived processes can omit data."
)


@dataclass(frozen=True)
class _Connection:
    """Internal representation; socket inode is never emitted in scan results."""

    inode: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int


def scan(proc_root: str = "/proc") -> dict:
    """Inspect an existing procfs snapshot without changing the host.

    Only established IPv4/IPv6 TCP sockets whose peer address is non-loopback are
    eligible for correlation. Findings deliberately say ``direction: unknown``:
    procfs alone does not show whether the observed process initiated a connection.

    Args:
        proc_root: A procfs directory, or a test fixture shaped like one.

    Returns:
        A JSON-safe mapping with these keys:
        ``findings`` (list), ``warnings`` (list of visibility/completeness notices),
        ``examined_connections`` (number of successfully parsed established TCP
        rows), and ``limitation_notice`` (a fixed caveat).
    """

    warnings: List[str] = []
    warning_set: Set[str] = set()

    def warn(message: str) -> None:
        if message not in warning_set:
            warning_set.add(message)
            warnings.append(message)

    connections: List[_Connection] = []
    connections.extend(_read_tcp_table(os.path.join(proc_root, "net", "tcp"), False, warn))
    connections.extend(_read_tcp_table(os.path.join(proc_root, "net", "tcp6"), True, warn))

    # Count all successfully decoded established rows, including loopback peers, so
    # callers can distinguish no TCP activity from connections filtered as local.
    examined_connections = len(connections)
    relevant_by_inode: Dict[str, List[_Connection]] = {}
    for connection in connections:
        if not _is_loopback(connection.remote_address):
            relevant_by_inode.setdefault(connection.inode, []).append(connection)

    findings: List[dict] = []
    if relevant_by_inode:
        _correlate_processes(proc_root, relevant_by_inode, findings, warn)

    # Deterministic ordering makes snapshot comparisons and tests straightforward.
    findings.sort(
        key=lambda finding: (
            finding["pid"],
            finding["local_address"],
            finding["local_port"],
            finding["remote_address"],
            finding["remote_port"],
            finding["reason"],
        )
    )
    return {
        "findings": findings,
        "warnings": warnings,
        "examined_connections": examined_connections,
        "limitation_notice": LIMITATION_NOTICE,
    }


def _read_tcp_table(path: str, ipv6: bool, warn) -> List[_Connection]:
    """Parse established rows in one /proc/net/tcp* table, tolerating bad rows."""

    table_name = "IPv6" if ipv6 else "IPv4"
    connections: List[_Connection] = []
    try:
        with open(path, "r", encoding="ascii", errors="replace") as table:
            table.readline(MAX_TCP_LINE + 1)  # conventional table header
            for index in range(MAX_TCP_ROWS + 1):
                line = table.readline(MAX_TCP_LINE + 1)
                if not line:
                    break
                if index == MAX_TCP_ROWS or len(line) > MAX_TCP_LINE:
                    warn("TCP snapshot scan limit reached; results may be incomplete")
                    break
                fields = line.split()
                # Well-formed non-established states are not parse failures.
                if len(fields) >= 10 and fields[3].upper() in {"02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C"}:
                    continue
                parsed = _parse_tcp_row(line, ipv6)
                if parsed is None:
                    if line.strip():
                        warn("malformed TCP socket entry skipped")
                    continue
                connections.append(parsed)
    except FileNotFoundError:
        warn("%s TCP snapshot is unavailable" % table_name)
        return []
    except PermissionError:
        warn("permission denied while reading %s TCP snapshot" % table_name)
        return []
    except OSError:
        warn("unable to read %s TCP snapshot" % table_name)
        return []

    return connections


def _parse_tcp_row(line: str, ipv6: bool) -> Optional[_Connection]:
    fields = line.split()
    # /proc/net/tcp has local and remote endpoints at indexes 1/2, state at 3,
    # and inode at 9. Kernels may append fields, so only require this minimum.
    if len(fields) < 10 or fields[3].upper() != "01":
        return None
    try:
        local_address, local_port = _decode_endpoint(fields[1], ipv6)
        remote_address, remote_port = _decode_endpoint(fields[2], ipv6)
        inode = str(int(fields[9], 10))
    except (ValueError, OSError):
        return None
    return _Connection(inode, local_address, local_port, remote_address, remote_port)


def _decode_endpoint(endpoint: str, ipv6: bool) -> Tuple[str, int]:
    encoded_address, encoded_port = endpoint.split(":", 1)
    port = int(encoded_port, 16)
    if not 0 <= port <= 65535:
        raise ValueError("invalid port")
    if ipv6:
        return _decode_tcp6_address(encoded_address), port
    if len(encoded_address) != 8:
        raise ValueError("invalid IPv4 address width")
    raw = bytes.fromhex(encoded_address)
    return socket.inet_ntop(socket.AF_INET, raw[::-1]), port


def _decode_tcp6_address(encoded_address: str) -> str:
    """Decode Linux /proc/net/tcp6's four little-endian 32-bit address words."""

    if len(encoded_address) != 32:
        raise ValueError("invalid IPv6 address width")
    raw = bytes.fromhex(encoded_address)
    # tcp6 exposes each native-endian u32 separately. Reversing all 16 bytes would
    # incorrectly reverse word order; reverse each four-byte word instead.
    network_order = b"".join(raw[offset : offset + 4][::-1] for offset in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, network_order)


def _is_loopback(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        # Addresses originate from our decoder, but fail closed if a future change
        # hands this helper something unparsable.
        return True
    if parsed.is_loopback:
        return True
    # ipaddress does not classify every IPv4-mapped loopback IPv6 form uniformly.
    return bool(getattr(parsed, "ipv4_mapped", None) and parsed.ipv4_mapped.is_loopback)


def _correlate_processes(
    proc_root: str,
    relevant_by_inode: Dict[str, List[_Connection]],
    findings: List[dict],
    warn,
) -> None:
    try:
        entries = os.scandir(proc_root)
    except FileNotFoundError:
        warn("process snapshot is unavailable")
        return
    except PermissionError:
        warn("permission denied while listing process snapshot")
        return
    except OSError:
        warn("unable to list process snapshot")
        return

    pid_names: List[str] = []
    try:
        for entry in entries:
            # Restrict this to ordinary ASCII decimal PID directory names. This
            # avoids accepting look-alike names in an arbitrary test fixture.
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
        entries.close()
    pid_names.sort(key=lambda value: int(value))

    process_cache: Dict[str, Optional[Tuple[str, int]]] = {}
    emitted: Set[Tuple[int, str]] = set()
    for pid_text in pid_names:
        fd_path = os.path.join(proc_root, pid_text, "fd")
        try:
            fd_entries = os.scandir(fd_path)
        except FileNotFoundError:
            # Expected process exit or a deliberately partial fixture.
            continue
        except PermissionError:
            warn("permission denied while reading process file descriptors")
            continue
        except OSError:
            # Treat arbitrary fd-dir errors as a race/visibility gap, without
            # surfacing host-specific error text.
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
                    continue
                inode = _socket_inode(target)
                if inode is None or inode not in relevant_by_inode:
                    continue

                key = (int(pid_text), inode)
                if key in emitted:
                    continue
                emitted.add(key)
                process_info = _read_process_info(proc_root, pid_text, process_cache, warn)
                if process_info is None:
                    continue
                comm, parent_pid = process_info
                parent_names = _ancestor_names(
                    proc_root, parent_pid, process_cache, warn
                )
                direct_shell = _is_shell(comm)
                shell_in_ancestors = any(_is_shell(name) for name in parent_names)
                if not direct_shell and not shell_in_ancestors:
                    continue

                for connection in relevant_by_inode[inode]:
                    findings.append(
                        _make_finding(
                            int(pid_text),
                            comm,
                            parent_names,
                            connection,
                            direct_shell,
                        )
                    )
        except PermissionError:
            warn("permission denied while reading process file descriptors")
        except OSError:
            warn("unable to read process file descriptors")
        finally:
            fd_entries.close()


def _socket_inode(target: str) -> Optional[str]:
    if not target.startswith("socket:[") or not target.endswith("]"):
        return None
    inode = target[8:-1]
    if not inode.isdecimal():
        return None
    return str(int(inode, 10))


def _read_process_info(
    proc_root: str,
    pid_text: str,
    cache: Dict[str, Optional[Tuple[str, int]]],
    warn,
) -> Optional[Tuple[str, int]]:
    """Read only comm and PPid. Deliberately never open cmdline or environ."""

    if pid_text in cache:
        return cache[pid_text]
    comm_path = os.path.join(proc_root, pid_text, "comm")
    status_path = os.path.join(proc_root, pid_text, "status")
    try:
        with open(comm_path, "r", encoding="utf-8", errors="replace") as comm_file:
            comm = comm_file.readline(256).strip()
        parent_pid = _read_parent_pid(status_path)
    except FileNotFoundError:
        cache[pid_text] = None
        return None
    except PermissionError:
        warn("permission denied while reading process metadata")
        cache[pid_text] = None
        return None
    except ValueError:
        warn("malformed process metadata skipped")
        cache[pid_text] = None
        return None
    except OSError:
        warn("unable to read process metadata")
        cache[pid_text] = None
        return None
    if not comm or parent_pid < 0:
        cache[pid_text] = None
        return None
    # comm is normally <= 15 bytes, but trim a malicious fixture to retain a
    # bounded JSON value without reading richer process data.
    cache[pid_text] = (comm[:64], parent_pid)
    return cache[pid_text]


def _read_parent_pid(status_path: str) -> int:
    with open(status_path, "r", encoding="utf-8", errors="replace") as status_file:
        for _ in range(128):
            line = status_file.readline(4096)
            if not line:
                break
            if line.startswith("PPid:"):
                value = line.split(":", 1)[1].strip()
                return int(value, 10)
    raise ValueError("PPid missing")


def _ancestor_names(
    proc_root: str,
    parent_pid: int,
    cache: Dict[str, Optional[Tuple[str, int]]],
    warn,
) -> List[str]:
    """Return at most 16 ancestor comm values, stopping safely on loops/races."""

    names: List[str] = []
    seen: Set[int] = set()
    current = parent_pid
    while current > 0 and len(names) < MAX_ANCESTRY_DEPTH and current not in seen:
        seen.add(current)
        info = _read_process_info(proc_root, str(current), cache, warn)
        if info is None:
            break
        name, current = info
        names.append(name)
    return names


def _is_shell(comm: str) -> bool:
    return comm.lower() in SHELL_NAMES


def _make_finding(
    pid: int,
    comm: str,
    parent_names: List[str],
    connection: _Connection,
    direct_shell: bool,
) -> dict:
    if direct_shell:
        reason = (
            "shell process owns an established TCP socket with a non-loopback peer; "
            "connection direction is not inferable from this snapshot"
        )
        severity = "medium"
        confidence = "medium"
    else:
        reason = (
            "process with an established TCP socket has a shell in its ancestor chain; "
            "connection direction is not inferable from this snapshot"
        )
        severity = "low"
        confidence = "low"
    # Keep the public finding deliberately narrow: no command lines, usernames,
    # environment, socket inode, process path, or host-specific metadata.
    return {
        "pid": pid,
        "parent_names": list(parent_names),
        "comm": comm,
        "local_address": connection.local_address,
        "local_port": connection.local_port,
        "remote_address": connection.remote_address,
        "remote_port": connection.remote_port,
        "reason": reason,
        "severity": severity,
        "confidence": confidence,
        "direction": "unknown",
    }
