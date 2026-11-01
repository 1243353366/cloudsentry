"""Loopback-only scan coverage: bounds, refusal of remote targets, completeness."""
from __future__ import annotations

import json
import socket
import unittest

from reverse_shell_decoy.loopback_scan import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PARTIAL,
    LOOPBACK_ONLY_NOTICE,
    MAX_PORTS,
    STATE_CLOSED,
    STATE_OPEN,
    LoopbackOnlyError,
    cross_check_inventory,
    is_loopback_host,
    nmap_equivalent_command,
    parse_port_spec,
    scan_loopback,
)


class LoopbackGuardTests(unittest.TestCase):
    def test_loopback_literals_and_localhost_are_accepted(self) -> None:
        for host in ("127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "[::1]", "localhost", "LOCALHOST"):
            self.assertTrue(is_loopback_host(host), host)

    def test_remote_and_ambiguous_hosts_are_refused(self) -> None:
        for host in (
            "10.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "128.0.0.1",
            "example.com",
            "localhost.example.com",
            "::",
            "8.8.8.8",
            "",
        ):
            self.assertFalse(is_loopback_host(host), host)

    def test_scanning_a_remote_host_raises_instead_of_probing(self) -> None:
        with self.assertRaises(LoopbackOnlyError) as caught:
            scan_loopback([80], host="192.0.2.10")
        self.assertEqual(str(caught.exception), LOOPBACK_ONLY_NOTICE)

    def test_hostname_is_not_resolved_into_a_permitted_target(self) -> None:
        # A name that resolves to loopback must not pass, or DNS could redirect the scan.
        with self.assertRaises(LoopbackOnlyError):
            scan_loopback([80], host="localtest.me")


class PortSpecTests(unittest.TestCase):
    def test_single_list_and_range_forms(self) -> None:
        self.assertEqual(parse_port_spec("22"), (22,))
        self.assertEqual(parse_port_spec("443,22"), (22, 443))
        self.assertEqual(parse_port_spec("80,22-24"), (22, 23, 24, 80))
        self.assertEqual(parse_port_spec("1000-999").__len__(), 2)

    def test_duplicates_collapse(self) -> None:
        self.assertEqual(parse_port_spec("22,22,20-23"), (20, 21, 22, 23))

    def test_malformed_specs_are_rejected(self) -> None:
        for spec in ("", " ", "0", "65536", "abc", "22,,80", "1-", "-5", "1-999999"):
            with self.assertRaises(ValueError, msg=spec):
                parse_port_spec(spec)

    def test_port_count_limit_is_enforced_rather_than_truncated(self) -> None:
        with self.assertRaises(ValueError):
            parse_port_spec("1-5000", max_ports=MAX_PORTS)


class ScanBehaviourTests(unittest.TestCase):
    def _closed_port(self) -> int:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def test_open_listener_is_detected(self) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        port = server.getsockname()[1]
        try:
            result = scan_loopback([port], timeout=0.5, deadline_seconds=5)
        finally:
            server.close()
        self.assertEqual(result.open_ports, (port,))
        self.assertEqual(result.completeness, COMPLETENESS_COMPLETE)
        self.assertIn("complete", result.statement.lower())

    def test_closed_port_does_not_answer_on_a_loopback_listener(self) -> None:
        port = self._closed_port()
        result = scan_loopback([port], timeout=0.5, deadline_seconds=5)
        states = [item.state for item in result.observations]
        self.assertNotIn(STATE_OPEN, states)
        self.assertIn(states[0], (STATE_CLOSED, "NO_ANSWER"))

    def test_deadline_marks_the_result_partial_and_counts_unscanned_ports(self) -> None:
        result = scan_loopback(
            [self._closed_port() for _ in range(5)],
            timeout=0.2,
            deadline_seconds=1.0,
            pacing_delay_ms=600,
        )
        self.assertTrue(result.deadline_reached)
        self.assertEqual(result.completeness, COMPLETENESS_PARTIAL)
        self.assertGreater(result.unscanned_ports, 0)
        self.assertIn("never attempted", result.statement)

    def test_no_answer_is_reported_as_partial_not_clean(self) -> None:
        # 9/9 is the discard port in most containers; either refused or unanswered.
        result = scan_loopback([9], timeout=0.2, deadline_seconds=5)
        if any(item.state == "NO_ANSWER" for item in result.observations):
            self.assertEqual(result.completeness, COMPLETENESS_PARTIAL)
            self.assertIn("unknown rather than closed", result.statement)

    def test_invalid_parameters_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scan_loopback([], )
        with self.assertRaises(ValueError):
            scan_loopback([0])
        with self.assertRaises(ValueError):
            scan_loopback([22], timeout=0)
        with self.assertRaises(ValueError):
            scan_loopback([22], timeout=99)
        with self.assertRaises(ValueError):
            scan_loopback([22], deadline_seconds=0)
        with self.assertRaises(ValueError):
            scan_loopback([22], pacing_delay_ms=-1)
        with self.assertRaises(ValueError):
            scan_loopback(list(range(1, 12)), max_ports=10)

    def test_result_is_json_safe_and_scoped_to_local_activity(self) -> None:
        result = scan_loopback([self._closed_port()], timeout=0.3, deadline_seconds=5)
        payload = result.as_dict()
        json.dumps(payload)
        self.assertFalse(payload["remote_targets"])
        self.assertTrue(payload["active_network_activity"])
        self.assertIn("does not prove", payload["limitation_notice"])
        self.assertEqual(payload["kind"], "loopback_scan")


class CrossCheckTests(unittest.TestCase):
    def test_answering_but_not_bound_is_flagged(self) -> None:
        report = cross_check_inventory(
            _FakeResult([1000, 2000]),
            {"listeners": [{"port": 2000}, {"port": 3000}]},
        )
        self.assertEqual(report["answering_not_bound"], [1000])
        self.assertEqual(report["bound_but_not_answering"], [])
        self.assertEqual(report["bound_but_not_scanned"], [3000])
        self.assertIn("different network namespace", report["statement"])
        self.assertEqual(report["attribution"], "unresolved")

    def test_bound_but_not_answering_is_flagged(self) -> None:
        report = cross_check_inventory(
            _FakeResult([1000], scanned_ports=[1000, 4000]),
            {"listeners": [{"port": 1000}, {"port": 4000}]},
        )
        self.assertEqual(report["bound_but_not_answering"], [4000])
        self.assertEqual(report["bound_but_not_scanned"], [])
        self.assertIn("accept backlog", report["statement"])

    def test_bindings_outside_the_scanned_range_are_not_called_clean(self) -> None:
        report = cross_check_inventory(_FakeResult([1000]), {"listeners": [{"port": 1000}, {"port": 4000}]})
        self.assertEqual(report["bound_but_not_scanned"], [4000])
        self.assertIn("not probed", report["statement"])

    def test_agreement_is_reported_without_a_verdict(self) -> None:
        report = cross_check_inventory(_FakeResult([1234]), {"listeners": [{"port": 1234}]})
        self.assertEqual(report["agreed_ports"], [1234])
        self.assertIn("do not contradict", report["statement"])
        self.assertNotIn("malicious", json.dumps(report))

    def test_arguments_are_typed(self) -> None:
        with self.assertRaises(ValueError):
            cross_check_inventory("not a result", {})
        with self.assertRaises(ValueError):
            cross_check_inventory(_FakeResult([]), "not a mapping")


class _FakeObservation:
    def __init__(self, port: int, state: str = STATE_OPEN) -> None:
        self.port = port
        self.state = state

    def as_dict(self):
        return {"port": self.port, "state": self.state, "latency_ms": 0}


class _FakeResult:
    """Minimal stand-in so cross-check logic can be tested without real sockets."""

    def __init__(self, open_ports, scanned_ports=None) -> None:
        scanned = list(scanned_ports if scanned_ports is not None else open_ports)
        self.observations = [
            _FakeObservation(port, STATE_OPEN if port in open_ports else STATE_CLOSED)
            for port in scanned
        ]
        self.open_ports = tuple(open_ports)

    def as_dict(self):
        return {}


class NmapEquivalenceTests(unittest.TestCase):
    def test_command_is_loopback_and_connect_scan_only(self) -> None:
        command = nmap_equivalent_command([22, 80])
        self.assertEqual(command, "nmap -sT -Pn -n -p22,80 127.0.0.1")
        self.assertIn("127.0.0.1", command)
        self.assertNotIn("-sS", command)  # no raw-socket scan
        self.assertEqual(nmap_equivalent_command("1-1024"), "nmap -sT -Pn -n -p1-1024 127.0.0.1")


if __name__ == "__main__":
    unittest.main()
