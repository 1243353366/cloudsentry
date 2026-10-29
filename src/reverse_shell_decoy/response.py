"""Review-required containment planning. No DNS writes or traffic interception."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import re


def sinkhole_plan(report: dict, owned_domain: str, decoy_ip: str, confirm_owned: bool = False) -> dict:
    if confirm_owned is not True:
        raise ValueError("explicitly confirm that the target domain and decoy endpoint are yours to administer")
    domain = owned_domain.strip().rstrip(".").lower()
    if len(domain) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or "." not in domain or ".." in domain:
        raise ValueError("provide an explicit owned domain; no wildcard or URL")
    ip = ipaddress.ip_address(decoy_ip)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ValueError("provide your isolated decoy's usable endpoint, not wildcard/multicast/loopback")
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False)
    if len(encoded) > 8 * 1024 * 1024:
        raise ValueError("report exceeds planning limit")
    # Count review indicators, not 'proven attackers'. Do not trust a numerical risk score.
    counts = report.get("non_demo_indicator_confidence_counts", {})
    positives = sum(v for v in counts.values() if isinstance(v, int) and not isinstance(v, bool) and v > 0) if isinstance(counts, dict) else 0
    if not positives:
        findings = report.get("findings", [])
        positives = len(findings) if isinstance(findings, list) and report.get("source_is_synthetic") is not True else 0
    return {
        "source_kind": "containment_proposal_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "review_required" if positives else "no_positive_indicators_in_supplied_report",
        "positive_review_indicators": positives,
        "proposal": {"action": "review_dns_sinkhole", "owned_domain": domain, "record_type": "AAAA" if ip.version == 6 else "A", "decoy_ip": str(ip)},
        "approval_required": True,
        "automatic_actions": False,
        "dns_changed": False,
        "traffic_redirected": False,
        "credential_collection": False,
        "preconditions": ["Independently verify the finding and authorized ownership.",
                          "Confirm the destination is an isolated endpoint you control.",
                          "Match the decoy protocol to the traffic; a plaintext terminal is not an HTTP/DNS service.",
                          "Review impact, TTL, DNS record scope, rollback and platform-specific approval.",
                          "Apply any approved change manually through your own provider, not this script."],
        "limitations": "DNS changes do not redirect already established TCP sessions. A positive heuristic is not proof of compromise. This plan does not touch an attacker or a third-party machine.",
    }
