"""Policy-divergence coverage: parsers, comparison verdicts, and the trust caveat."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from reverse_shell_decoy.policy import (
    FINDING_DECOY_PORT_REACHABLE,
    FINDING_DEFAULT_INBOUND_ACCEPT,
    FINDING_FILTER_UNREADABLE,
    FINDING_NAMESPACE_SPLIT,
    FINDING_PARTIAL_VISIBILITY,
    FINDING_UNEXPECTED_INBOUND_ALLOW,
    STATUS_COMPLETE,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    TRUST_LIMITATION,
    VERDICT_DIVERGENT,
    VERDICT_MATCH,
    VERDICT_PARTIAL,
    VERDICT_UNKNOWN,
    InboundRule,
    PolicyIntent,
    PolicyObservation,
    PolicyObservationError,
    collect_linux_policy,
    collect_windows_policy,
    compare_policy,
    count_network_namespaces,
    parse_iptables_save,
    parse_net_firewall_profile_json,
    parse_netsh_firewall_profiles,
    parse_nftables_json,
)

NFT_FIXTURE = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {
                "chain": {
                    "family": "inet",
                    "table": "filter",
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": 22022,
                            }
                        },
                        {"accept": None},
                    ],
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": {"range": [2000, 2002]},
                            }
                        },
                        {"accept": None},
                    ],
                }
            },
        ]
    }
)

IPTABLES_FIXTURE = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 9000 -j DROP
COMMIT
"""

NETSH_FIXTURE = """Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       AllowInbound,AllowOutbound
"""


class NftablesParsingTests(unittest.TestCase):
    def test_input_chain_policy_and_accept_rules_are_extracted(self) -> None:
        default_inbound, rules, notes = parse_nftables_json(NFT_FIXTURE)
        self.assertEqual(default_inbound, "drop")
        self.assertEqual(sorted(rule.port for rule in rules), [2000, 2001, 2002, 22022])
        self.assertEqual(notes, [])

    def test_output_chain_is_ignored(self) -> None:
        payload = json.dumps(
            {
                "nftables": [
                    {
                        "chain": {
                            "family": "inet",
                            "table": "filter",
                            "name": "out",
                            "hook": "output",
                            "policy": "accept",
                        }
                    }
                ]
            }
        )
        default_inbound, rules, notes = parse_nftables_json(payload)
        self.assertEqual(default_inbound, "unknown")
        self.assertEqual(rules, [])
        self.assertTrue(notes)

    def test_malformed_json_and_missing_key_raise(self) -> None:
        with self.assertRaises(PolicyObservationError):
            parse_nftables_json("not json")
        with self.assertRaises(PolicyObservationError):
            parse_nftables_json(json.dumps({"something": []}))


class IptablesParsingTests(unittest.TestCase):
    def test_policy_and_allow_rules_are_extracted(self) -> None:
        default_inbound, rules, notes = parse_iptables_save(IPTABLES_FIXTURE)
        self.assertEqual(default_inbound, "drop")
        self.assertEqual([rule.port for rule in rules], [22])
        self.assertEqual(notes, [])

    def test_accept_policy_is_reported_as_accept(self) -> None:
        default_inbound, _, _ = parse_iptables_save("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
        self.assertEqual(default_inbound, "accept")

    def test_loopback_only_rule_without_a_port_is_not_counted(self) -> None:
        _, rules, _ = parse_iptables_save("-A INPUT -i lo -j ACCEPT\n")
        self.assertEqual(rules, [])

    def test_missing_policy_line_is_noted(self) -> None:
        default_inbound, _, notes = parse_iptables_save("*filter\nCOMMIT\n")
        self.assertEqual(default_inbound, "unknown")
        self.assertIn("unreadable", notes[0])


class WindowsParsingTests(unittest.TestCase):
    def test_netsh_profiles_are_parsed_with_whitespace_alignment(self) -> None:
        profiles, notes = parse_netsh_firewall_profiles(NETSH_FIXTURE)
        self.assertEqual(profiles["domain"]["state"], "ON")
        self.assertEqual(profiles["domain"]["firewall_policy"], "BlockInbound,AllowOutbound")
        self.assertEqual(profiles["private"]["state"], "OFF")
        self.assertEqual(notes, [])

    def test_unrecognised_netsh_output_yields_a_note(self) -> None:
        profiles, notes = parse_netsh_firewall_profiles("nothing useful here\n")
        self.assertEqual(profiles, {})
        self.assertTrue(notes)

    def test_powershell_json_profiles_are_normalised(self) -> None:
        payload = json.dumps(
            [
                {"Name": "Domain", "Enabled": 1, "DefaultInboundAction": 1},
                {"Name": "Private", "Enabled": False, "DefaultInboundAction": 2},
            ]
        )
        profiles, notes = parse_net_firewall_profile_json(payload)
        self.assertEqual(profiles["domain"]["state"], "ON")
        self.assertEqual(profiles["private"]["state"], "OFF")
        self.assertIn("blockinbound", profiles["domain"]["firewall_policy"].lower())
        self.assertIn("allowinbound", profiles["private"]["firewall_policy"].lower())
        self.assertEqual(notes, [])


class NamespaceTests(unittest.TestCase):
    def test_distinct_network_namespaces_are_counted_from_procfs(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            for pid, inode in (("1", "net:[1]"), ("2", "net:[1]"), ("3", "net:[2]")):
                directory = os.path.join(root, pid, "ns")
                os.makedirs(directory)
                os.symlink(inode, os.path.join(directory, "net"))
            self.assertEqual(count_network_namespaces(root), 2)

    def test_missing_procfs_reports_zero(self) -> None:
        self.assertEqual(count_network_namespaces("/nonexistent-proc"), 0)


class IntentTests(unittest.TestCase):
    def test_decoy_ports_stay_local_unless_reviewed(self) -> None:
        intent = PolicyIntent(decoy_ports=(22022, 22080), reviewed_public_ports=(22080,))
        self.assertEqual(intent.must_stay_local, (22022,))

    def test_invalid_ports_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PolicyIntent(decoy_ports=(0,))
        with self.assertRaises(ValueError):
            PolicyIntent(decoy_ports=(70000,))


def _observation(**overrides) -> PolicyObservation:
    base = dict(
        platform="linux",
        mechanism="iptables-save",
        status=STATUS_COMPLETE,
        default_inbound="drop",
        rules=[],
        namespaces=1,
        privileged=True,
    )
    base.update(overrides)
    return PolicyObservation(**base)


class ComparisonTests(unittest.TestCase):
    def test_default_deny_with_no_rules_matches_intent(self) -> None:
        report = compare_policy(_observation(), PolicyIntent())
        self.assertEqual(report["verdict"], VERDICT_MATCH)
        self.assertEqual(report["findings"], [])
        self.assertFalse(report["all_clear"])
        self.assertFalse(report["changes_applied"])
        self.assertIn("not proof that the host is clean", report["statement"])

    def test_accept_default_is_a_divergence(self) -> None:
        report = compare_policy(_observation(default_inbound="accept"), PolicyIntent())
        self.assertEqual(report["verdict"], VERDICT_DIVERGENT)
        self.assertIn(FINDING_DEFAULT_INBOUND_ACCEPT, [f["code"] for f in report["findings"]])
        self.assertTrue(report["rotation_recommended"])

    def test_decoy_port_open_off_host_is_a_divergence(self) -> None:
        observation = _observation(rules=[InboundRule(port=22022)])
        report = compare_policy(observation, PolicyIntent())
        self.assertIn(FINDING_DECOY_PORT_REACHABLE, [f["code"] for f in report["findings"]])

    def test_reviewed_public_decoy_port_is_not_a_divergence(self) -> None:
        observation = _observation(rules=[InboundRule(port=22022)])
        report = compare_policy(observation, PolicyIntent(reviewed_public_ports=(22022,)))
        codes = [f["code"] for f in report["findings"]]
        self.assertNotIn(FINDING_DECOY_PORT_REACHABLE, codes)
        self.assertNotIn(FINDING_UNEXPECTED_INBOUND_ALLOW, codes)

    def test_unexpected_allow_port_is_flagged_without_a_verdict(self) -> None:
        observation = _observation(rules=[InboundRule(port=8080)])
        report = compare_policy(observation, PolicyIntent(expected_inbound_ports=(22,)))
        findings = [f for f in report["findings"] if f["code"] == FINDING_UNEXPECTED_INBOUND_ALLOW]
        self.assertEqual(findings[0]["ports"], [8080])
        self.assertIn("unexplained", findings[0]["detail"])
        self.assertNotIn("unauthorized", json.dumps(report).replace("not necessarily unauthorized", ""))

    def test_expected_port_is_accepted(self) -> None:
        observation = _observation(rules=[InboundRule(port=22)])
        report = compare_policy(observation, PolicyIntent(expected_inbound_ports=(22,)))
        self.assertEqual(report["verdict"], VERDICT_MATCH)

    def test_unreadable_filter_is_unknown_not_clean(self) -> None:
        report = compare_policy(_observation(status=STATUS_UNAVAILABLE), PolicyIntent())
        self.assertEqual(report["verdict"], VERDICT_UNKNOWN)
        self.assertIn(FINDING_FILTER_UNREADABLE, [f["code"] for f in report["findings"]])
        self.assertIn("observation gap", report["statement"])

    def test_partial_visibility_is_not_a_match(self) -> None:
        report = compare_policy(_observation(status=STATUS_PARTIAL), PolicyIntent())
        self.assertEqual(report["verdict"], VERDICT_PARTIAL)
        self.assertIn(FINDING_PARTIAL_VISIBILITY, [f["code"] for f in report["findings"]])
        self.assertIn("not a clean result", report["statement"])

    def test_namespace_split_is_reported_as_a_gap(self) -> None:
        report = compare_policy(_observation(namespaces=3), PolicyIntent())
        codes = [f["code"] for f in report["findings"]]
        self.assertIn(FINDING_NAMESPACE_SPLIT, codes)
        self.assertTrue(any("namespace" in line for line in report["rotation_guidance"]))

    def test_report_carries_the_trust_limitation_and_is_json_safe(self) -> None:
        report = compare_policy(_observation(), PolicyIntent())
        self.assertEqual(report["trust_limitation"], TRUST_LIMITATION)
        self.assertIn("cannot guarantee trustworthy visibility", report["trust_limitation"])
        json.dumps(report)
        self.assertFalse(report["changes_applied"])

    def test_arguments_are_typed(self) -> None:
        with self.assertRaises(PolicyObservationError):
            compare_policy({"status": "COMPLETE"}, PolicyIntent())
        with self.assertRaises(PolicyObservationError):
            compare_policy(_observation(), {"decoy_ports": ()})


class CollectorTests(unittest.TestCase):
    def test_linux_collector_never_reports_an_applied_change(self) -> None:
        observation = collect_linux_policy()
        self.assertIn(
            observation.status, {STATUS_COMPLETE, STATUS_PARTIAL, STATUS_UNAVAILABLE}
        )
        self.assertFalse(observation.as_dict()["changes_applied"])
        self.assertIn("trust_limitation", observation.as_dict())

    def test_windows_collector_is_not_applicable_elsewhere(self) -> None:
        if os.name == "nt":
            self.skipTest("this assertion is for non-Windows hosts")
        observation = collect_windows_policy()
        self.assertEqual(observation.status, STATUS_NOT_APPLICABLE)
        self.assertEqual(observation.platform, "windows")


class CliVersionTests(unittest.TestCase):
    def test_cli_reports_the_package_version(self) -> None:
        import subprocess
        import sys

        from reverse_shell_decoy import __version__

        completed = subprocess.run(
            [sys.executable, "-m", "reverse_shell_decoy", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn(__version__, completed.stdout)
        self.assertNotIn("0.1.0", completed.stdout)


if __name__ == "__main__":
    unittest.main()
