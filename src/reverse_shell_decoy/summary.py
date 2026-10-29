"""Deterministic evidence summaries; no model, account scan or service launch."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from .input_files import read_regular

PROVIDERS = ("cloudflare", "aws", "render", "railway")
MAX_INPUT = 8 * 1024 * 1024


def safe(value: object, length: int = 100) -> str:
    text = str(value)[:length].replace("\n", " ").replace("\r", " ")
    text = "".join(c if c.isprintable() else "?" for c in text)
    return re.sub(r"([\\`*_{}\[\]()<>#!|])", r"\\\1", text)


def _load_json(path: str) -> dict:
    try:
        value = json.loads(read_regular(path, MAX_INPUT).decode("utf-8"))
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("report is not a safely readable JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError("host report must be a JSON object")
    return value


def _decoy(path: str | None) -> dict:
    if not path:
        return {"status": "not_supplied", "sessions": 0, "commands": 0, "blocked": 0, "file_read_attempts": 0}
    lines = read_regular(path, 2 * 1024 * 1024).decode("utf-8").splitlines()
    if len(lines) > 1000:
        raise ValueError("decoy audit exceeds 1000 lines")
    events = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            skipped += 1
            continue
        if not isinstance(event, dict) or event.get("simulation") is not True:
            skipped += 1
            continue
        events.append(event)
    commands = [e for e in events if e.get("event_type") == "command" or "input_sha256" in e]
    sessions = {e["session_id"] for e in events if isinstance(e.get("session_id"), str)}
    return {
        "status": "supplied_unverified_audit",
        "sessions": len(sessions),
        "commands": len(commands),
        "blocked": sum(e.get("blocked") is True for e in commands),
        "file_read_attempts": sum(e.get("verb") in {"cat", "type"} for e in commands),
        "ignored_lines": skipped,
        "simulation": True,
        "notice": "Observed interactions with synthetic responses; no verified attacker identity or remote OS. Raw command arguments are absent.",
    }


def build_summary(provider_files: dict[str, str], host_report: str | None = None, decoy_audit: str | None = None) -> dict:
    # Cloud parsing is lazy and local: no collector, credential or network code is imported here.
    from .cloud import analyze_cloud_logs
    if any(p not in PROVIDERS for p in provider_files):
        raise ValueError("unsupported provider")
    if not provider_files and not host_report and not decoy_audit:
        raise ValueError("supply at least one manual evidence source")
    providers, timeline = {}, []
    counts: Counter[str] = Counter()
    for provider in PROVIDERS:
        path = provider_files.get(provider)
        if not path:
            providers[provider] = {"status": "not_supplied", "events": 0, "indicators": 0,
                                   "coverage": "unknown; not scanned"}
            continue
        content = read_regular(path, MAX_INPUT).decode("utf-8")
        result = analyze_cloud_logs(provider, content, format="auto")
        events, findings = result.get("events", []), result.get("findings", [])
        synthetic = result.get("source_is_synthetic", False) is True
        providers[provider] = {
            "status": "synthetic_demo" if synthetic else "manual_logs_supplied_unverified",
            "events": len(events), "indicators": len(findings),
            "input_filename": Path(path).name,
            "input_sha256": sha256(content.encode("utf-8")).hexdigest(),
            "warnings": result.get("warnings", []),
            "coverage": result.get("coverage", "limited to supplied input"),
        }
        if not synthetic:
            for finding in findings:
                level = finding.get("confidence", "unknown")
                counts[level if level in {"low", "medium", "high"} else "unknown"] += 1
        for event in events[:50]:
            timestamp = event.get("timestamp_utc") or event.get("timestamp_original")
            if not isinstance(timestamp, str):
                continue
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    continue  # Never invent a timezone for imported event times.
                normalized = parsed.astimezone(timezone.utc).isoformat()
            except ValueError:
                continue
            timeline.append({"provider": provider, "timestamp_utc": normalized,
                             "category": str(event.get("category", "unknown"))[:64],
                             "event_id": str(event.get("event_id", "unknown"))[:64],
                             "source_is_synthetic": synthetic,
                             "classification": "observed_in_supplied_log; unverified"})
    host = {"status": "not_supplied", "os": None, "shell_indicators": 0, "listener_bindings": 0, "persistence_indicators": 0}
    if host_report:
        report = _load_json(host_report)
        observed = report.get("host_observations", {})
        if not isinstance(observed, dict):
            raise ValueError("host report has invalid host_observations")
        for section, list_key in [("shell_connections", "findings"), ("listeners", "listeners"), ("persistence_indicators", "findings")]:
            item = observed.get(section, {})
            if not isinstance(item, dict) or not isinstance(item.get(list_key, []), list):
                raise ValueError("host observation section has an invalid schema")
        host = {
            "status": "supplied_snapshot_unverified",
            "os": observed.get("host_os"),
            "shell_indicators": len(observed.get("shell_connections", {}).get("findings", [])),
            "listener_bindings": len(observed.get("listeners", {}).get("listeners", [])),
            "persistence_indicators": len(observed.get("persistence_indicators", {}).get("findings", [])),
            "notice": "Describes the machine that ran the local scanner, not an inferred visitor OS.",
        }
    return {
        "title": "CloudSentry evidence summary",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "providers": providers,
        "host": host,
        "decoy": _decoy(decoy_audit),
        "non_demo_indicator_confidence_counts": dict(counts),
        "timeline": sorted(timeline, key=lambda e: e["timestamp_utc"])[:200],
        "assessment": "Review indicators and acquisition context. No supplied evidence proves compromise or attacker identity; absent logs are missing coverage, not a clean result.",
        "correlation_notice": "Timeline ordering does not prove causation, shared identity, or synchronized source clocks. Synthetic demonstrations are excluded from non-demo indicator counts.",
        "recommended_actions": ["Preserve original logs and hashes.", "Verify administrator and deployment changes against approved work.",
                                "Review exposed listeners and outbound destinations on authorized systems.",
                                "Review logging coverage before declaring normal activity.",
                                "Approve any containment/DNS change separately; never auto-sinkhole a heuristic match."],
        "automatic_actions": False,
    }


def markdown(result: dict) -> str:
    lines = ["# CloudSentry evidence summary", "", f"Generated: {safe(result['generated_at_utc'])}", "", "## Provider coverage", ""]
    for provider in PROVIDERS:
        p = result["providers"][provider]
        lines.append(f"- **{provider.title()}**: {safe(p['status'])}; {p['events']} supplied events; {p['indicators']} review indicators.")
    lines += ["", "Missing input is unknown coverage, not a successful security scan.", "", "## Host observations", ""]
    host = result["host"]
    lines.append(f"Source: {safe(host['status'])}. Shell/socket indicators: {host['shell_indicators']}; listener bindings: {host['listener_bindings']}; startup indicators: {host['persistence_indicators']}.")
    if isinstance(host.get("os"), dict):
        lines.append(f"Reported scanner-host OS: {safe(host['os'].get('system', 'unknown'))} {safe(host['os'].get('release', 'unknown'))}. This is not a visitor OS fingerprint.")
    d = result["decoy"]
    lines += ["", "## Deception interactions", "", f"Source: {safe(d['status'])}. Sessions: {d['sessions']}; attempted commands: {d['commands']}; blocked attempts: {d['blocked']}; virtual-file read attempts: {d['file_read_attempts']}.",
              "", "Privileged responses and file contents are synthetic. Peer identity and remote OS remain unknown.", "", "## Interpretation", "", result["assessment"], "", result["correlation_notice"], "", "## Review actions", ""]
    lines += [f"- {action}" for action in result["recommended_actions"]]
    return "\n".join(lines) + "\n"


def add_arguments(p: argparse.ArgumentParser) -> None:
    for provider in PROVIDERS:
        p.add_argument(f"--{provider}", help=f"explicit {provider} exported JSON/JSONL/text log file")
    p.add_argument("--host-report", help="previously generated local audit JSON; no new scan")
    p.add_argument("--decoy-audit", help="operator-only decoy JSONL; no new service launch")
    p.add_argument("--json", action="store_true", help="emit structured JSON rather than Markdown")


def run_args(args: argparse.Namespace) -> int:
    files = {p: getattr(args, p) for p in PROVIDERS if getattr(args, p, None)}
    result = build_summary(files, args.host_report, args.decoy_audit)
    print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) if args.json else markdown(result), end="\n" if args.json else "")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Summarize explicitly supplied evidence. Does not scan accounts or launch services.")
    add_arguments(p)
    args = p.parse_args(argv)
    try:
        return run_args(args)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
