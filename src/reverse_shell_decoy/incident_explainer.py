"""One selected audit snapshot -> policy feedback + customer explanation.

Evidence is data, never authority. This module cannot execute visitor commands,
control services, provision VMs, change policies or send reports to customers.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import sys
from typing import Any

from .input_files import read_regular
from .operations import MAX_AUDIT_BYTES, build_operations_summary_bytes


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


_FACTORY_TOKEN = object()


@dataclass(frozen=True, init=False)
class _IncidentSnapshot:
    """Immutable in-process representation; not signed or authenticated evidence."""
    _canonical_record: bytes
    _origin: object

    def __init__(self, canonical_record: bytes, *, _factory_token: object) -> None:
        if _factory_token is not _FACTORY_TOKEN or not isinstance(canonical_record, bytes):
            raise ValueError("incident snapshots must be built by the normalization factory")
        object.__setattr__(self, "_canonical_record", canonical_record)
        object.__setattr__(self, "_origin", _factory_token)

    @property
    def digest(self) -> str:
        return sha256(self._canonical_record).hexdigest()

    def copy(self) -> dict:
        return json.loads(self._canonical_record)


def snapshot_from_bytes(raw: bytes, *, synthetic_fixture: bool = False) -> _IncidentSnapshot:
    if type(synthetic_fixture) is not bool:
        raise ValueError("synthetic fixture flag must be a boolean")
    operations = build_operations_summary_bytes(raw)
    line_refs = [
        {"physical_line": number, "line_sha256": sha256(line).hexdigest()}
        for number, line in enumerate(raw.splitlines(), 1) if line.strip()
    ]
    return _IncidentSnapshot(canonical({
        "record_format": "security_incident_snapshot_v1",
        "provider": "local",
        "synthetic_fixture": synthetic_fixture,
        "environment_kind": "synthetic_decoy_environment_not_real_host_access",
        "source_authenticity": "unverified_selected_audit",
        "source_manifest": {
            "input_sha256": operations["audit"]["input_sha256"],
            "input_bytes": len(raw),
            "record_references": line_refs,
            "coverage": "provided_records_only; completeness_unknown",
            "original_payload_retained": False,
        },
        "operations": operations,
    }), _factory_token=_FACTORY_TOKEN)


def snapshot_from_audit(path: str) -> _IncidentSnapshot:
    return snapshot_from_bytes(read_regular(path, MAX_AUDIT_BYTES))


def _events(snapshot: _IncidentSnapshot) -> tuple[dict, dict, list, list]:
    if not isinstance(snapshot, _IncidentSnapshot) or snapshot._origin is not _FACTORY_TOKEN:
        raise ValueError("use an incident normalization factory, not serialized or arbitrary report data")
    record = snapshot.copy()
    operations = record["operations"]
    return record, operations, operations["sessions"], operations["budget_stats"]["events"]


def _budget_stops(events: list) -> list:
    protective_reasons = {
        "global_input_byte_budget", "global_output_byte_budget", "service_runtime_limit",
        "audit_limit", "operator_audit_failure", "max_sessions_total", "lifetime_connection_limit",
        "input_budget", "output_budget", "max_runtime_seconds",
    }
    return [event for event in events if event["phase"] == "stopped" and event["stop_reason"] in protective_reasons]


def behavior_feedback(snapshot: _IncidentSnapshot) -> dict:
    from .behavior import BehaviorInput, evaluate, policy_contract
    record, operations, sessions, budgets = _events(snapshot)
    suspicious = any(session["token_indicators"] for session in sessions)
    # Imported assertions cannot become approval, independent verification or authority.
    inputs = BehaviorInput(
        suspicious_text=suspicious,
        local_budget_stop_reported=bool(_budget_stops(budgets)),
        evidence_count=operations["audit"]["accepted_records"],
    )
    decision = evaluate(inputs)
    return {
        "format": "incident_behavior_feedback_v1",
        "provider": "local",
        "incident_record_sha256": snapshot.digest,
        "source_input_sha256": record["source_manifest"]["input_sha256"],
        "policy_contract_sha256": sha256(canonical(policy_contract())).hexdigest(),
        "decision": decision,
        "evidence_references": [
            {"incident_record_sha256": snapshot.digest, "json_pointer": "/operations/sessions"},
            {"incident_record_sha256": snapshot.digest, "json_pointer": "/operations/budget_stats/events"},
        ],
        "source_claims_verified": False,
        "independent_corroboration": "not_supplied",
        "baseline_comparison": "not_supplied",
        "approval_derived_from_evidence": False,
        "runtime_modified": False,
        "notice": "Fixed policy guidance from unverified supplied records, not learned weights, live authority, automatic containment or proof of a threat. Review before adapting another script.",
    }


def customer_explanation(snapshot: _IncidentSnapshot) -> dict:
    record, operations, sessions, budgets = _events(snapshot)
    counts = {key: sum(session["event_counts"][key] for session in sessions)
              for key in ("connecting", "command", "mirror_chunk", "close")}
    audit = operations["audit"]
    patterns = operations["classification_counts"]
    stops = _budget_stops(budgets)
    observations = []
    if counts["connecting"]:
        observations.append({
            "code": "recorded_connection_events",
            "description": f"The selected audit contains {counts['connecting']} connection record(s). Their authenticity, authorization and origin were not verified by this script.",
            "evidence_pointer": "/operations/sessions", "classification": "supplied_unverified_record",
        })
    if counts["command"] or counts["mirror_chunk"]:
        observations.append({
            "code": "recorded_decoy_inputs",
            "description": f"The audit contains {counts['command']} command-shaped event(s) and {counts['mirror_chunk']} mirror-chunk event(s). These records do not establish real command execution or host access.",
            "evidence_pointer": "/operations/sessions", "classification": "supplied_unverified_record",
        })
    for name, count in patterns.items():
        if count:
            observations.append({
                "code": name, "session_count": count,
                "description": "A deterministic, low-confidence pattern was present in the selected records; a benign script, administrator, template, incomplete trace or synthetic test may explain it.",
                "evidence_pointer": "/operations/classification_counts/" + name,
                "classification": "inferred_pattern_not_execution_or_attribution",
            })
    status = "insufficient_evidence" if not audit["accepted_records"] else "selected_records_require_contextual_review"
    return {
        "format": "customer_incident_explanation_v1", "provider": "local",
        "title": "What the selected CloudSentry audit shows",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": status,
        "synthetic_fixture": record["synthetic_fixture"],
        "incident_record_sha256": snapshot.digest,
        "source_input_sha256": record["source_manifest"]["input_sha256"],
        "what_happened": (
            f"The selected audit describes {len(sessions)} hash-referenced session(s). "
            "It is a supplied, unverified record of a synthetic decoy environment, not proof that your actual device was accessed or compromised."
        ),
        "what_the_script_observed": observations,
        "what_cloudsentry_did": {
            "this_invocation": "Read one selected audit, normalized it once, evaluated fixed review guidance and generated local reports. It did not scan, block, redirect, execute input, change production rules or send a report.",
            "reported_close_records": counts["close"],
            "reported_budget_stops": [{"reason": event["stop_reason"], "timestamp_utc": event["timestamp_utc"], "evidence_pointer": "/operations/budget_stats/events"} for event in stops],
            "reported_actions_verified": False,
            "containment_activated_by_this_script": False,
            "why_no_automatic_containment": "Detection and imported assertions do not grant enforcement authority. False positives, source authenticity, ownership, isolation and rollback need independent operator review.",
        },
        "what_this_means": "Connection or text patterns can justify review. Attempted activity, simulated privileges, actual execution and successful unauthorized host access are different facts; successful unauthorized host access has not been established here.",
        "uncertainty": {
            "discarded_records": sum(audit["discarded_records"].values()),
            "coverage_gaps": operations["uncertainty_counts"],
            "comparison_baseline": "not_supplied",
            "independent_corroboration": "not_supplied",
            "contradictory_independent_evidence": "not_assessed; only one selected audit supplied",
            "identity_intent_authorization_host_os": "unknown",
        },
        "time_range": {"first_utc": audit["first_valid_timestamp_utc"], "last_utc": audit["last_valid_timestamp_utc"]},
        "recommended_next_steps": [
            "Review the original audit alongside independently preserved authentication, process, network and provider records, keeping clock and coverage gaps explicit.",
            "Confirm whether a benign administrator, authorized scanner or synthetic test explains the pattern before proposing a response.",
            "If an actual resource may be compromised, isolate it through a trusted provider/network control plane, preserve independent evidence and revoke exposed credentials using your incident-response process.",
            "Use only independently approved scopes and actions. Do not treat this summary as legal proof, a psychological dossier or an instruction to deploy a decoy.",
        ],
        "evidence_classification": "selected_record_observations_and_limited_inferences; authenticity_unverified",
        "limitations": "No original payloads, peer addresses or credential values are included. Hashes identify selected representations, not authorship, legal custody or authenticity. This is not model training, a forensic verdict or a guarantee of customer-device safety.",
    }


def customer_markdown(snapshot: _IncidentSnapshot) -> str:
    """Render only a factory-normalized snapshot; uploaded report mappings are rejected."""
    return _render_customer_markdown(customer_explanation(snapshot))


def _render_customer_markdown(report: dict) -> str:
    """Private rendering helper for the internally constructed report only."""
    lines = ["# " + report["title"], "", "**Status:** " + report["status"], ""]
    if report["synthetic_fixture"]:
        lines += ["**Illustrative synthetic fixture—not a customer incident.**", ""]
    lines += ["## What happened", "", report["what_happened"], "", "## What the script observed", ""]
    for observation in report["what_the_script_observed"]:
        lines += ["- " + observation["description"], "  Evidence: `" + observation["evidence_pointer"] + "` in the incident snapshot."]
    if not report["what_the_script_observed"]:
        lines.append("No usable observation was available; this is unknown coverage, not an all-clear.")
    actions = report["what_cloudsentry_did"]
    lines += ["", "## What CloudSentry did—and did not do", "", actions["this_invocation"], "", actions["why_no_automatic_containment"]]
    for stop in actions["reported_budget_stops"]:
        lines.append(f"- The supplied audit reports a local stop: `{stop['reason']}` at `{stop['timestamp_utc']}`. This was not independently verified.")
    lines += ["", "## What this means", "", report["what_this_means"], "", "## Unknowns and limitations", "",
              "The baseline, independent corroboration, identity, intent and authorization are unknown. Missing or discarded records do not prove a clean system.",
              report["limitations"], "", "## Recommended next steps", ""]
    lines += ["- " + step for step in report["recommended_next_steps"]]
    lines += ["", "## Evidence trail", "", f"- Selected input SHA-256: `{report['source_input_sha256']}`",
              f"- Shared incident snapshot SHA-256: `{report['incident_record_sha256']}`",
              f"- Supplied time range: `{report['time_range']['first_utc']}` to `{report['time_range']['last_utc']}`",
              "- The technical feedback and this explanation use the same immutable in-process snapshot.", ""]
    return "\n".join(lines)


def write_private_packet(directory: str, files: dict[str, bytes]) -> None:
    """Create a new private directory and never overwrite any existing artifact."""
    os.mkdir(directory, 0o700)
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    created = []
    try:
        for name, content in files.items():
            if "/" in name or name in {".", ".."}:
                raise ValueError("artifact name must be fixed and local")
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
            created.append(name)
            with os.fdopen(out, "wb") as stream:
                stream.write(content)
    except BaseException:
        for name in created:
            os.unlink(name, dir_fd=fd)
        os.close(fd)
        fd = -1
        os.rmdir(directory)
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def explanation_packet(snapshot: _IncidentSnapshot) -> dict[str, bytes]:
    report = customer_explanation(snapshot)
    feedback = behavior_feedback(snapshot)
    files = {
        "incident-record.json": canonical({"incident_record_sha256": snapshot.digest, "record": snapshot.copy()}) + b"\n",
        "behavior-feedback.json": canonical(feedback) + b"\n",
        "customer-explanation.json": canonical(report) + b"\n",
        "customer-explanation.md": _render_customer_markdown(report).encode("utf-8"),
    }
    files["evidence-manifest.json"] = canonical({
        "incident_record_sha256": snapshot.digest,
        "source_input_sha256": snapshot.copy()["source_manifest"]["input_sha256"],
        "artifact_sha256": {name: sha256(content).hexdigest() for name, content in files.items()},
        "authenticity": "unverified; hashes_do_not_authenticate_source", "raw_audit_included": False,
    }) + b"\n"
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline behavior regression feedback and consented customer explanation; no execution, automatic containment or self-modification.", allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    train = modes.add_parser("train", help="evaluate trusted built-in synthetic fixtures; not model weights or live rules")
    train.add_argument("--output", help="new private output directory; otherwise safe training JSON on stdout")
    train.add_argument("--consent", action="store_true", help="fresh permission for this synthetic training run")
    explain = modes.add_parser("explain", help="read one selected decoy JSONL audit and create matching customer/technical reports")
    explain.add_argument("--audit", required=True)
    explain.add_argument("--consent", action="store_true", help="explicit fresh permission to process this selected audit")
    explain.add_argument("--output", required=True, help="new private directory; existing outputs are never overwritten")
    args = parser.parse_args(argv)
    if not args.consent:
        approved = False
        if sys.stdin.isatty():
            print("Allow this one local training/review run? No runtime rules or services will change. [y/N] ", end="", file=sys.stderr, flush=True)
            try:
                approved = sys.stdin.readline(16).strip().lower() in {"y", "yes"}
            except (OSError, EOFError):
                pass
        if not approved:
            print("Permission required: use --consent only for a run you explicitly authorize. No input was read or training performed.", file=sys.stderr)
            return 2
    try:
        if args.mode == "train":
            from .behavior import run_training
            result = run_training()
            if args.output:
                write_private_packet(args.output, {
                    "training-feedback.json": canonical(result) + b"\n",
                    "policy-contract.json": canonical({"policy_contract": result["policy_contract"], "policy_contract_sha256": result["policy_contract_sha256"], "automatic_adoption": False}) + b"\n",
                })
                print("Created private synthetic training feedback and review-only policy contract. Runtime policies unchanged.")
            else:
                print(canonical(result).decode("ascii"))
            return 0 if result["passed"] else 1
        snapshot = snapshot_from_audit(args.audit)
        write_private_packet(args.output, explanation_packet(snapshot))
        print("Created private customer explanation, behavior feedback and shared evidence snapshot. No enforcement, runtime change or report sending occurred.")
        return 0
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Selected input or output was unavailable or invalid; no enforcement or policy change occurred.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
