"""Effective host policy versus CloudSentry's own intent, with an honest trust caveat.

CloudSentry states what it is allowed to do: decoy services stay on loopback, the
scanner only connects to loopback, nothing calls back, and nothing transits a
third party. The kernel's packet filter is a *separate* statement of what is
actually reachable. When the two disagree, either the configuration was changed
or something is filtering reachability without our knowledge. This module reads
the filter state and reports the disagreement.

Read-only, and nothing here changes a rule:

* **Linux.** ``nft -j list ruleset`` when nftables answers, otherwise
  ``iptables-save``/``ip6tables-save``; plus network-namespace and permission
  coverage, because a filter in another namespace is invisible from this one.
* **Windows.** Firewall profile state and inbound defaults from
  ``netsh advfirewall`` when PowerShell is unavailable, otherwise
  ``Get-NetFirewallProfile -PolicyStore ActiveStore``. Windows Filtering
  Platform per-rule state needs administrator rights; without them the report
  says ``PARTIAL`` rather than implying a clean policy.

**Trust limitation, stated once and repeated in every report.** A sufficiently
privileged attacker can change the packet filter *and* the tools used to observe
it. A host-based check cannot produce trustworthy visibility after complete host
compromise: it can only describe the kernel's own answers at the moment it asked.
That is why the report carries a rotation recommendation and never claims that a
matching policy proves the host is clean. Independent observers (another host, a
network tap, a second namespace) are the only way to check an answer that might
itself be manipulated.

Parsers are pure functions over text so they can be tested without root, without
nftables installed, and without changing this machine's firewall.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 8.0
MAX_RULES = 4096

STATUS_COMPLETE = "COMPLETE"
STATUS_PARTIAL = "PARTIAL"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

VERDICT_MATCH = "MATCH"
VERDICT_DIVERGENT = "DIVERGENT"
VERDICT_UNKNOWN = "UNKNOWN"
VERDICT_PARTIAL = "PARTIAL"

SEVERITY_DIVERGENCE = "divergence"
SEVERITY_GAP = "observation_gap"

FINDING_DEFAULT_INBOUND_ACCEPT = "DEFAULT_INBOUND_ACCEPT"
FINDING_DECOY_PORT_REACHABLE = "DECOY_PORT_REACHABLE"
FINDING_UNEXPECTED_INBOUND_ALLOW = "UNEXPECTED_INBOUND_ALLOW"
FINDING_FILTER_UNREADABLE = "FILTER_UNREADABLE"
FINDING_NAMESPACE_SPLIT = "NAMESPACE_SPLIT"
FINDING_PARTIAL_VISIBILITY = "PARTIAL_VISIBILITY"
FINDING_BACKEND_UNFILTERED = "BACKEND_UNFILTERED"

TRUST_LIMITATION = (
    "A sufficiently privileged attacker can change both the packet filter and the tools that "
    "observe it. After complete host compromise, a host-based watchdog cannot guarantee "
    "trustworthy visibility: this report describes what the kernel answered at the moment it "
    "was asked, and a matching policy is not proof that the host is clean. Rotate observations "
    "from an independent vantage point (another host, a network tap, a separate namespace) "
    "before treating any result here as settled."
)

ROTATION_GUIDANCE = (
    "Re-take this reading after any privileged change, on a schedule you control, and from at "
    "least one independent observer. Rotating who observes is the only control that survives a "
    "compromised observer."
)


class PolicyObservationError(ValueError):
    """Raised when a caller passes something that is not a policy observation."""


def _bounded_int(name: str, value: object, maximum: int, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class PolicyIntent:
    """What CloudSentry has told operators it is allowed to do.

    This is CloudSentry's own authorization rule set, not a generic policy wish
    list: decoys stay on loopback unless a public bind was explicitly reviewed,
    the scan is loopback-only, and nothing is relayed to a third party.
    """

    decoy_ports: Tuple[int, ...] = (22022, 22080, 26379)
    expected_inbound_ports: Tuple[int, ...] = ()
    reviewed_public_ports: Tuple[int, ...] = ()
    require_default_deny_inbound: bool = True
    forbid_third_party_transit: bool = True

    def __post_init__(self) -> None:
        for name in ("decoy_ports", "expected_inbound_ports", "reviewed_public_ports"):
            values = getattr(self, name)
            for port in values:
                _bounded_int(name, port, 65535, minimum=1)

    @property
    def must_stay_local(self) -> Tuple[int, ...]:
        """Decoy ports that are not individually approved for public exposure."""

        approved = set(self.reviewed_public_ports)
        return tuple(port for port in self.decoy_ports if port not in approved)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decoy_ports": list(self.decoy_ports),
            "expected_inbound_ports": list(self.expected_inbound_ports),
            "reviewed_public_ports": list(self.reviewed_public_ports),
            "require_default_deny_inbound": self.require_default_deny_inbound,
            "forbid_third_party_transit": self.forbid_third_party_transit,
            "must_stay_local": list(self.must_stay_local),
        }


@dataclass
class InboundRule:
    """One observed inbound allow rule, reduced to what the comparison needs."""

    port: Optional[int]
    protocol: str = "tcp"
    interface: str = ""
    source: str = ""
    table: str = ""
    chain: str = ""

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "port": self.port,
            "protocol": self.protocol,
            "interface": self.interface,
            "source": self.source,
            "table": self.table,
            "chain": self.chain,
        }
        return payload


@dataclass
class PolicyObservation:
    """Read-only snapshot of the effective packet filter and its coverage."""

    platform: str = "linux"
    mechanism: str = "unknown"
    status: str = STATUS_UNAVAILABLE
    default_inbound: str = "unknown"
    rules: List[InboundRule] = field(default_factory=list)
    namespaces: int = 1
    privileged: bool = False
    notes: List[str] = field(default_factory=list)
    observed_at_utc: str = ""

    def __post_init__(self) -> None:
        for note in self.notes:
            if not isinstance(note, str):
                raise PolicyObservationError("notes must be strings")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "effective_policy_observation",
            "platform": self.platform,
            "mechanism": self.mechanism,
            "status": self.status,
            "default_inbound": self.default_inbound,
            "rule_count": len(self.rules),
            "rules": [rule.as_dict() for rule in self.rules[:MAX_RULES]],
            "namespaces": self.namespaces,
            "privileged": self.privileged,
            "observed_at_utc": self.observed_at_utc,
            "notes": list(self.notes),
            "changes_applied": False,
            "trust_limitation": TRUST_LIMITATION,
        }


# ---------------------------------------------------------------------------
# Parsers: pure functions over captured text
# ---------------------------------------------------------------------------
def parse_nftables_json(text: str) -> Tuple[str, List[InboundRule], List[str]]:
    """Parse ``nft -j list ruleset`` output into (default inbound, rules, notes)."""

    notes: List[str] = []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        raise PolicyObservationError("nftables output is not valid JSON")

    if not isinstance(payload, dict) or "nftables" not in payload:
        raise PolicyObservationError("nftables JSON has no 'nftables' key")

    chains: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    rules: List[InboundRule] = []
    for entry in payload.get("nftables") or []:
        if not isinstance(entry, dict):
            continue
        chain = entry.get("chain")
        if isinstance(chain, dict) and chain.get("hook") == "input":
            chains[(str(chain.get("family")), str(chain.get("table")), str(chain.get("name")))] = chain
            continue
        rule = entry.get("rule")
        if not isinstance(rule, dict):
            continue
        key = (str(rule.get("family")), str(rule.get("table")), str(rule.get("chain")))
        if key not in chains:
            continue
        ports, protocol, interface, source, verdict = _nft_rule_shape(rule.get("expr") or [])
        if verdict != "accept" or ports is None:
            continue
        for port in ports:
            rules.append(
                InboundRule(
                    port=port,
                    protocol=protocol,
                    interface=interface,
                    source=source,
                    table=key[1],
                    chain=key[2],
                )
            )
        if len(rules) > MAX_RULES:
            notes.append("rule limit reached; the policy reading is truncated")
            break

    default_inbound = "unknown"
    for chain in chains.values():
        policy = str(chain.get("policy") or "").lower()
        if policy in {"accept", "drop"}:
            default_inbound = "accept" if policy == "accept" else "drop"
            break
    if not chains:
        notes.append("no inet input chain with an explicit policy was found")
    return default_inbound, rules, notes


def _nft_rule_shape(expr: Sequence[Any]) -> Tuple[Optional[Tuple[int, ...]], str, str, str, str]:
    ports: Optional[Tuple[int, ...]] = None
    protocol = "tcp"
    interface = ""
    source = ""
    verdict = ""
    for item in expr:
        if not isinstance(item, dict):
            continue
        match = item.get("match")
        if isinstance(match, dict):
            left = match.get("left") or {}
            right = match.get("right")
            payload_spec = left.get("payload") if isinstance(left, dict) else None
            if isinstance(payload_spec, dict) and payload_spec.get("field") == "dport":
                protocol = str(payload_spec.get("protocol", protocol))
                ports = _nft_ports(right)
            elif isinstance(left, dict) and left.get("meta", {}).get("key") == "iifname":
                if isinstance(right, str):
                    interface = right
                elif isinstance(right, dict) and isinstance(right.get("set"), list):
                    interface = ",".join(str(value) for value in right["set"])
            elif isinstance(left, dict) and left.get("payload", {}).get("field") == "saddr":
                source = str(right)
        for verdict_key in ("accept", "drop", "reject"):
            if verdict_key in item:
                verdict = verdict_key
    return ports, protocol, interface, source, verdict


def _nft_ports(right: Any) -> Optional[Tuple[int, ...]]:
    """Reduce an nftables dport match to the port numbers it can match."""

    if isinstance(right, int) and not isinstance(right, bool):
        return (right,)
    if not isinstance(right, dict):
        return None
    ports = right.get("set")
    if isinstance(ports, list):
        numbers = [value for value in ports if isinstance(value, int) and not isinstance(value, bool)]
        return tuple(numbers) if numbers else None
    span = right.get("range")
    if isinstance(span, list) and len(span) == 2 and all(isinstance(v, int) for v in span):
        low, high = sorted(span)
        if high - low <= 1024:
            return tuple(range(low, high + 1))
    return None


def parse_iptables_save(text: str, table: str = "filter") -> Tuple[str, List[InboundRule], List[str]]:
    """Parse ``iptables-save`` output into (default inbound, allow rules, notes)."""

    notes: List[str] = []
    default_inbound = "unknown"
    rules: List[InboundRule] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(":INPUT"):
            parts = stripped.split()
            if len(parts) >= 2:
                policy = parts[1].upper()
                if policy in {"ACCEPT", "DROP", "REJECT"}:
                    default_inbound = "accept" if policy == "ACCEPT" else "drop"
            continue
        if not stripped.startswith("-A INPUT"):
            continue
        if "-j ACCEPT" not in stripped:
            continue
        port, protocol, interface, source = _iptables_rule_shape(stripped)
        if port is None:
            continue
        rules.append(
            InboundRule(
                port=port,
                protocol=protocol,
                interface=interface,
                source=source,
                table=table,
                chain="INPUT",
            )
        )
        if len(rules) > MAX_RULES:
            notes.append("rule limit reached; the policy reading is truncated")
            break
    if default_inbound == "unknown":
        notes.append("no INPUT policy line was found; the default is unreadable")
    return default_inbound, rules, notes


def _iptables_rule_shape(line: str) -> Tuple[Optional[int], str, str, str]:
    tokens = line.split()
    port: Optional[int] = None
    protocol = "tcp"
    interface = ""
    source = ""
    for index, token in enumerate(tokens):
        nxt = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token == "--dport" and nxt.isdigit():
            port = int(nxt)
        elif token == "-p":
            protocol = nxt
        elif token == "-i":
            interface = nxt
        elif token == "-s":
            source = nxt
    if port is None:
        return None, protocol, interface, source
    return port, protocol, interface, source


def parse_netsh_firewall_profiles(text: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """Parse ``netsh advfirewall show allprofiles`` output into per-profile values."""

    profiles: Dict[str, Dict[str, str]] = {}
    notes: List[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.endswith("profile settings:") or lowered == "allprofiles settings:":
            current = lowered.split(" profile")[0].strip()
            profiles.setdefault(current, {})
            continue
        if not current:
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
        else:
            # netsh aligns key and value with whitespace and no colon.
            fields = re.split(r"\s{2,}", stripped, maxsplit=1)
            if len(fields) != 2:
                continue
            key, value = fields
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key in {"state", "firewall_policy"} and value:
            profiles[current][key] = value
    if not profiles:
        notes.append("no firewall profile block was recognised in netsh output")
    return profiles, notes


def parse_net_firewall_profile_json(text: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """Parse ``Get-NetFirewallProfile`` JSON (single object or list)."""

    notes: List[str] = []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        raise PolicyObservationError("PowerShell profile output is not valid JSON")
    if isinstance(payload, dict):
        entries = [payload]
    elif isinstance(payload, list):
        entries = [item for item in payload if isinstance(item, dict)]
    else:
        raise PolicyObservationError("PowerShell profile output has an unexpected shape")

    profiles: Dict[str, Dict[str, str]] = {}
    for entry in entries:
        name = str(entry.get("Name") or entry.get("name") or "").strip().lower()
        if not name:
            continue
        enabled = entry.get("Enabled")
        inbound = entry.get("DefaultInboundAction")
        profiles[name] = {
            "state": _windows_enabled(enabled),
            "firewall_policy": _windows_inbound(inbound),
        }
    if not profiles:
        notes.append("no firewall profile entries were returned")
    return profiles, notes


def _windows_enabled(value: Any) -> str:
    if value in (True, 1, "True", "true", 1.0):
        return "ON"
    if value in (False, 0, "False", "false", 0.0):
        return "OFF"
    return str(value or "unknown")


def _windows_inbound(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"block", "blockinbound", "1"}:
        return "BlockInbound,AllowOutbound"
    if text in {"allow", "allowinbound", "2"}:
        return "AllowInbound,AllowOutbound"
    return str(value or "unknown")


def count_network_namespaces(proc_root: str = "/proc") -> int:
    """Count distinct network namespaces visible in procfs, bounded and read-only."""

    inodes = set()
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return 0
    for entry in entries:
        if not entry.isdigit():
            continue
        if len(inodes) > 4096:
            break
        try:
            inodes.add(os.readlink(os.path.join(proc_root, entry, "ns", "net")))
        except OSError:
            continue
    return max(1, len(inodes))


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
def _run(argv: Sequence[str]) -> Tuple[Optional[str], str]:
    """Run one bounded, read-only command; return (output, note)."""

    executable = shutil.which(argv[0])
    if executable is None:
        return None, f"{argv[0]} is not installed"
    try:
        completed = subprocess.run(
            [executable, *argv[1:]],
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{argv[0]} could not be run ({type(exc).__name__})"
    output = (completed.stdout or b"")[:MAX_COMMAND_OUTPUT].decode("utf-8", "replace")
    if completed.returncode != 0 and not output.strip():
        return None, f"{argv[0]} exited with status {completed.returncode}"
    return output, ""


def collect_linux_policy(proc_root: str = "/proc") -> PolicyObservation:
    """Read nftables/iptables state and namespace coverage. Applies no changes."""

    observation = PolicyObservation(
        platform="linux",
        mechanism="none",
        status=STATUS_UNAVAILABLE,
        namespaces=count_network_namespaces(proc_root),
        privileged=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        observed_at_utc=_utc_now(),
    )

    output, note = _run(["nft", "-j", "list", "ruleset"])
    if output is not None:
        try:
            default_inbound, rules, notes = parse_nftables_json(output)
        except PolicyObservationError as exc:
            observation.notes.append(f"nftables output was not usable: {exc}")
        else:
            observation.mechanism = "nftables"
            observation.status = STATUS_COMPLETE
            observation.default_inbound = default_inbound
            observation.rules = rules
            observation.notes.extend(notes)
    elif note:
        observation.notes.append(note)

    if observation.mechanism == "none":
        for command in (["iptables-save"], ["ip6tables-save"]):
            output, note = _run(command)
            if output is None:
                if note:
                    observation.notes.append(note)
                continue
            default_inbound, rules, notes = parse_iptables_save(output)
            observation.mechanism = command[0]
            observation.status = STATUS_COMPLETE if default_inbound != "unknown" else STATUS_PARTIAL
            observation.default_inbound = default_inbound
            observation.rules.extend(rules)
            observation.notes.extend(notes)
            break

    if observation.mechanism == "none":
        observation.status = STATUS_UNAVAILABLE
        observation.notes.append(
            "no nftables or iptables state could be read; this may be a permission limit rather "
            "than an absence of filtering"
        )
    elif observation.namespaces > 1:
        observation.status = STATUS_PARTIAL
        observation.notes.append(
            "more than one network namespace is visible, so this reading covers only the "
            "namespace the collector ran in"
        )
    return observation


def collect_windows_policy() -> PolicyObservation:
    """Read firewall profile state on Windows. Applies no changes."""

    if sys.platform != "win32":
        return PolicyObservation(
            platform="windows",
            mechanism="none",
            status=STATUS_NOT_APPLICABLE,
            observed_at_utc=_utc_now(),
            notes=["this collector is only meaningful on Windows"],
        )

    observation = PolicyObservation(
        platform="windows", mechanism="none", status=STATUS_UNAVAILABLE, observed_at_utc=_utc_now()
    )
    output, note = _run(["netsh", "advfirewall", "show", "allprofiles"])
    if output is not None:
        profiles, notes = parse_netsh_firewall_profiles(output)
        observation.notes.extend(notes)
        if profiles:
            observation.mechanism = "netsh advfirewall"
            observation.status = STATUS_PARTIAL
            observation.default_inbound = _profile_summary_default(profiles)
            for name, values in profiles.items():
                observation.notes.append(f"profile {name}: state={values.get('state', 'unknown')}")
            if any(values.get("state", "").upper() == "ON" for values in profiles.values()):
                observation.status = STATUS_COMPLETE
    elif note:
        observation.notes.append(note)

    powershell, note = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress",
        ]
    )
    if powershell is not None:
        try:
            profiles, notes = parse_net_firewall_profile_json(powershell)
        except PolicyObservationError as exc:
            observation.notes.append(f"PowerShell profile output was not usable: {exc}")
        else:
            observation.mechanism = (
                f"{observation.mechanism}+PowerShell" if observation.mechanism != "none" else "PowerShell"
            )
            observation.status = STATUS_PARTIAL
            observation.default_inbound = _profile_summary_default(profiles)
            observation.notes.extend(notes)
    elif note:
        observation.notes.append(note)

    if observation.mechanism == "none":
        observation.notes.append(
            "Windows Filtering Platform per-rule state needs administrator rights; without them "
            "this report is limited to profile defaults and must not be read as a clean policy"
        )
    return observation


def _profile_summary_default(profiles: Dict[str, Dict[str, str]]) -> str:
    values = {str(entry.get("firewall_policy", "")).lower() for entry in profiles.values() if entry}
    if any("allowinbound" in value for value in values):
        return "accept"
    if values and all("blockinbound" in value for value in values if value):
        return "drop"
    return "unknown"


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
@dataclass
class PolicyFinding:
    code: str
    severity: str
    detail: str
    ports: Tuple[int, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
            "ports": list(self.ports),
        }


def compare_policy(observation: PolicyObservation, intent: PolicyIntent) -> Dict[str, Any]:
    """Compare an observed filter state against CloudSentry's stated intent.

    The comparison reports divergence and observation gaps. It never reports a
    host as compromised, and a matching result is explicitly not an all-clear.
    """

    if not isinstance(observation, PolicyObservation):
        raise PolicyObservationError("observation must be a PolicyObservation")
    if not isinstance(intent, PolicyIntent):
        raise PolicyObservationError("intent must be a PolicyIntent")

    findings: List[PolicyFinding] = []
    if observation.status in (STATUS_UNAVAILABLE, STATUS_NOT_APPLICABLE):
        findings.append(
            PolicyFinding(
                FINDING_FILTER_UNREADABLE,
                SEVERITY_GAP,
                "the effective packet filter could not be read, so no comparison is possible",
            )
        )
    else:
        if intent.require_default_deny_inbound and observation.default_inbound == "accept":
            findings.append(
                PolicyFinding(
                    FINDING_DEFAULT_INBOUND_ACCEPT,
                    SEVERITY_DIVERGENCE,
                    "the inbound default is accept, so listeners beyond CloudSentry's reviewed set "
                    "are reachable without an explicit rule; the intent was default deny",
                )
            )
        reachable_tcp_ports = {rule.port for rule in observation.rules if rule.port is not None}
        wide_rules = tuple(
            sorted(
                port
                for port in reachable_tcp_ports
                if port in set(intent.decoy_ports) and port not in set(intent.reviewed_public_ports)
            )
        )
        if wide_rules and observation.default_inbound != "unknown":
            findings.append(
                PolicyFinding(
                    FINDING_DECOY_PORT_REACHABLE,
                    SEVERITY_DIVERGENCE,
                    "an inbound allow rule names a CloudSentry decoy port that the intent keeps on "
                    "loopback; either the exposure was reviewed and the intent is stale, or the "
                    "rule was added without review",
                    wide_rules,
                )
            )
        unexpected = tuple(
            sorted(
                port
                for port in reachable_tcp_ports
                if port not in set(intent.expected_inbound_ports)
                and port not in set(intent.reviewed_public_ports)
                and port not in set(intent.decoy_ports)
            )
        )
        if unexpected:
            findings.append(
                PolicyFinding(
                    FINDING_UNEXPECTED_INBOUND_ALLOW,
                    SEVERITY_DIVERGENCE,
                    "inbound allow rules exist for ports the intent does not name; they are "
                    "unexplained, not necessarily unauthorized",
                    unexpected,
                )
            )
        if observation.namespaces > 1:
            findings.append(
                PolicyFinding(
                    FINDING_NAMESPACE_SPLIT,
                    SEVERITY_GAP,
                    f"{observation.namespaces} network namespaces are visible; this reading covers "
                    "only the namespace the collector ran in",
                )
            )
        if observation.status == STATUS_PARTIAL:
            findings.append(
                PolicyFinding(
                    FINDING_PARTIAL_VISIBILITY,
                    SEVERITY_GAP,
                    "the reading is partial; missing rules may be missing because of permissions "
                    "rather than because they do not exist",
                )
            )

    divergence = [finding for finding in findings if finding.severity == SEVERITY_DIVERGENCE]
    gaps = [finding for finding in findings if finding.severity == SEVERITY_GAP]
    if observation.status in (STATUS_UNAVAILABLE, STATUS_NOT_APPLICABLE):
        verdict = VERDICT_UNKNOWN
    elif divergence:
        verdict = VERDICT_DIVERGENT
    elif gaps:
        verdict = VERDICT_PARTIAL
    else:
        verdict = VERDICT_MATCH

    rotation = [ROTATION_GUIDANCE]
    if observation.namespaces > 1:
        rotation.append(
            "Re-run the collector inside each network namespace, or observe from a host that can "
            "see them all."
        )
    return {
        "kind": "policy_divergence_report",
        "platform": observation.platform,
        "mechanism": observation.mechanism,
        "verdict": verdict,
        "intent": intent.as_dict(),
        "observation": observation.as_dict(),
        "findings": [finding.as_dict() for finding in findings],
        "divergence_count": len(divergence),
        "gap_count": len(gaps),
        "statement": _statement(verdict, divergence, gaps),
        "rotation_recommended": bool(divergence or gaps or verdict != VERDICT_MATCH),
        "rotation_guidance": rotation,
        "all_clear": False,
        "trust_limitation": TRUST_LIMITATION,
        "changes_applied": False,
    }


def _statement(verdict: str, divergence: Sequence[PolicyFinding], gaps: Sequence[PolicyFinding]) -> str:
    if verdict == VERDICT_UNKNOWN:
        return (
            "No comparison was possible: the effective packet filter could not be read, which is "
            "an observation gap and not evidence that the host is unfiltered."
        )
    if verdict == VERDICT_DIVERGENT:
        codes = ", ".join(finding.code for finding in divergence)
        return (
            f"The effective policy disagrees with CloudSentry's stated intent ({codes}). "
            "Divergence means one of the two descriptions is out of date; it does not establish "
            "who changed what."
        )
    if verdict == VERDICT_PARTIAL:
        return (
            "The readable part of the policy does not contradict the stated intent, but coverage "
            "is incomplete, so this is not a clean result."
        )
    return (
        "The effective policy matches CloudSentry's stated intent for what this collector could "
        "see. That is agreement between two descriptions, not proof that the host is clean."
    )


def collect_policy(proc_root: str = "/proc") -> PolicyObservation:
    """Collect from whichever platform this is, applying no changes."""

    if sys.platform == "win32":
        return collect_windows_policy()
    return collect_linux_policy(proc_root=proc_root)


def policy_report(intent: Optional[PolicyIntent] = None, proc_root: str = "/proc") -> Dict[str, Any]:
    """Collect and compare in one call, suitable for the CLI."""

    observation = collect_policy(proc_root=proc_root)
    return compare_policy(observation, intent or PolicyIntent())
