"""Optional independent socket observation through ``NETLINK_SOCK_DIAG``.

This is a second, read-only view of the kernel's own socket table, used only to
cross-check the procfs inventory.  It requests a dump; it never opens, probes,
connects, or sends anything to a peer, and it holds no state beyond one bounded
reply read per family.

Where the kernel, container policy, or permissions do not provide the generic
netlink socket family, the caller receives an explicit ``unavailable`` result
with a reason label.  An unavailable cross-check is never reported as an
agreement, and a disagreement is never resolved silently in favour of one
source.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Dict, List, Optional, Tuple

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20

TCP_LISTEN = 0x0A
UDP_UNCONNECTED = 0x07
ALL_STATES = 0xFF

INET_DIAG_MSG_BYTES = 72

NLM_F_REQUEST = 0x01
NLM_F_DUMP = 0x300

NLMSG_ERROR = 2
NLMSG_DONE = 3

MAX_REPLY_BYTES = 1024 * 1024
MAX_MESSAGES = 65536
RECV_CHUNK = 65536

_UNAVAILABLE_REASONS = {
    "netlink_sock_diag_not_supported",
    "netlink_permission_denied",
    "netlink_query_failed",
    "netlink_reply_truncated",
}


def socket_reference(identifier: str) -> str:
    """Return a stable, non-reversible reference for a kernel socket identity."""
    return hashlib.sha256(("sockdiag:%s" % identifier).encode()).hexdigest()[:32]


def describe_state(protocol: str, state: int) -> Optional[str]:
    """Map a diag state to the same labels the procfs inventory uses."""
    if protocol == "tcp" and state == TCP_LISTEN:
        return "LISTEN"
    if protocol == "udp" and state == UDP_UNCONNECTED:
        return "UDP-bound"
    return None


def _request(family: int, protocol: int, states: int) -> bytes:
    """Build one INET_DIAG dump request for a family and state mask."""
    payload = struct.pack(
        "=BBBBI", family, protocol, 0, 0, states
    ) + struct.pack("=IIII", 0, 0, 0, 0)
    header = struct.pack("=IHHII", 16 + len(payload), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 1, 0)
    return header + payload


def _decode_address(raw: bytes, family: int) -> str:
    """Render an address in the same textual form the procfs decoder produces."""
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    return socket.inet_ntop(socket.AF_INET6, raw[:16])


def _parse_messages(
    data: bytes,
    family: int,
    protocol: str,
) -> Tuple[List[Dict[str, object]], bool, Optional[str]]:
    """Parse diag replies into neutral binding observations.

    Returns ``(observations, done, error_reason)``.  The reply layouts are
    kernel ABI, not guesses: ``inet_diag_msg`` is a fixed 72-byte structure with
    network-order ports and 16-byte addresses.  A malformed or short message
    stops the parse and is reported instead of being reinterpreted.
    """
    observations: List[Dict[str, object]] = []
    offset = 0
    done = False
    while offset + 16 <= len(data):
        length, message_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, offset)
        if length < 16 or offset + length > len(data):
            return observations, done, "netlink_reply_truncated"
        body = data[offset + 16 : offset + length]
        offset += (length + 3) & ~3
        if message_type == NLMSG_DONE:
            done = True
            break
        if message_type == NLMSG_ERROR:
            return observations, done, "netlink_query_failed"
        if message_type != SOCK_DIAG_BY_FAMILY:
            continue
        if len(body) < INET_DIAG_MSG_BYTES:
            return observations, done, "netlink_reply_truncated"
        (msg_family, state, _timer, _retrans, _sport_raw, _dport_raw,
         source, destination, _iface, _cookie_low, _cookie_high,
         _expires, _rqueue, _wqueue, _uid, inode) = struct.unpack_from(
            "=BBBBHH16s16sIIIIIIII", body, 0
        )
        sport, dport = struct.unpack_from("!HH", body, 4)
        if msg_family not in (socket.AF_INET, socket.AF_INET6):
            continue
        label = describe_state(protocol, state)
        if label is None:
            continue
        try:
            address = _decode_address(source, msg_family)
        except (OSError, ValueError):
            return observations, done, "netlink_query_failed"
        observations.append({
            "protocol": protocol,
            "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
            "address": address,
            "port": int(sport),
            "state": label,
            "socket_ref_sha256": socket_reference("%s:%s" % (protocol, inode)),
            "inode_present": inode != 0,
            "destination_port": int(dport),
        })
    return observations, done, None


def collect_diag_bindings() -> Dict[str, object]:
    """Return a bounded diag view of TCP listeners and bound UDP sockets.

    The result is always a mapping with ``available`` and ``reason`` so a caller
    can state exactly what it did and did not observe.
    """
    result: Dict[str, object] = {
        "available": False,
        "reason": "netlink_sock_diag_not_supported",
        "source": "netlink_sock_diag",
        "observations": [],
        "messages_complete": False,
    }
    try:
        probe = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    except OSError as exc:
        result["reason"] = (
            "netlink_permission_denied" if exc.errno in {1, 13} else "netlink_sock_diag_not_supported"
        )
        return result
    observations: List[Dict[str, object]] = []
    complete = True
    try:
        probe.settimeout(1.0)
        for family in (socket.AF_INET, socket.AF_INET6):
            for protocol, protocol_number in (("tcp", socket.IPPROTO_TCP), ("udp", socket.IPPROTO_UDP)):
                probe.send(_request(family, protocol_number, ALL_STATES))
                total = 0
                done = False
                while not done:
                    chunk = probe.recv(RECV_CHUNK)
                    total += len(chunk)
                    if total > MAX_REPLY_BYTES:
                        complete = False
                        result["reason"] = "netlink_reply_truncated"
                        break
                    parsed, done, error = _parse_messages(chunk, family, protocol)
                    observations.extend(parsed)
                    if error is not None:
                        complete = False
                        result["reason"] = error
                        break
                    if len(observations) > MAX_MESSAGES:
                        complete = False
                        result["reason"] = "netlink_reply_truncated"
                        break
                if not complete:
                    break
            if not complete:
                break
    except PermissionError:
        result["reason"] = "netlink_permission_denied"
        return result
    except (OSError, socket.timeout):
        result["reason"] = "netlink_query_failed"
        return result
    finally:
        probe.close()

    result["available"] = True
    result["reason"] = "ok" if complete else result["reason"]
    result["observations"] = observations
    result["messages_complete"] = complete
    return result


def compare_bindings(
    procfs_bindings: List[Dict[str, object]],
    diag: Dict[str, object],
) -> Dict[str, object]:
    """Compare two independent observations without preferring either one."""
    if not diag.get("available"):
        return {
            "available": False,
            "reason": diag.get("reason", "unavailable"),
            "agreement": "not_verified",
            "agreed": 0,
            "procfs_only": 0,
            "diag_only": 0,
            "state_disagreements": 0,
            "detail": "cross-verification unavailable; procfs observations stand alone",
        }

    def key(item: Dict[str, object]) -> Tuple[object, object, object, object]:
        return (item.get("protocol"), item.get("family"), item.get("address"), item.get("port"))

    procfs_index: Dict[Tuple[object, object, object, object], List[str]] = {}
    for binding in procfs_bindings:
        current = procfs_index.setdefault(key(binding), [])
        state = binding.get("state")
        if isinstance(state, str):
            current.append(state)
    diag_index: Dict[Tuple[object, object, object, object], List[str]] = {}
    for observation in diag.get("observations", []):  # type: ignore[union-attr]
        current = diag_index.setdefault(key(observation), [])
        state = observation.get("state")
        if isinstance(state, str):
            current.append(state)

    agreed = [item for item in procfs_index if item in diag_index]
    disagreements = [
        item for item in agreed if sorted(procfs_index[item]) != sorted(diag_index[item])
    ]
    return {
        "available": True,
        "reason": diag.get("reason", "ok"),
        "agreement": "consistent" if not disagreements else "state_disagreement",
        "agreed": len(agreed),
        "procfs_only": len([item for item in procfs_index if item not in diag_index]),
        "diag_only": len([item for item in diag_index if item not in procfs_index]),
        "state_disagreements": len(disagreements),
        "detail": (
            "both sources describe the same endpoints and states"
            if not disagreements
            else "endpoint states differ between procfs and netlink diag; both observations are preserved"
        ),
    }
