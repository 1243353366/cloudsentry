"""Explicit, local-only operations; nothing runs on import."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TextIO

from .input_files import read_regular
from .simulator import DecoySession, MAX_COMMANDS, MAX_INPUT

MAX_AUDIT_BYTES = 2 * 1024 * 1024


def new_private_file(path: str) -> TextIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


def read_audit(path: str | None) -> list[dict]:
    if path is None:
        return []
    content = read_regular(path, MAX_AUDIT_BYTES)
    if len(content) > MAX_AUDIT_BYTES:
        raise ValueError("audit input exceeds 2 MiB")
    lines = content.decode("utf-8").splitlines()
    if len(lines) > MAX_COMMANDS:
        raise ValueError("audit input exceeds 1000 records")
    events = [json.loads(line) for line in lines if line.strip()]
    if any(not isinstance(e, dict) or e.get("simulation") is not True for e in events):
        raise ValueError("audit records must be simulation:true objects")
    return events


def read_names(path: str) -> list[str]:
    content = read_regular(path, 256 * 1024)
    if len(content) > 256 * 1024:
        raise ValueError("name input exceeds 256 KiB")
    names = [line.strip() for line in content.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(names) > 1000:
        raise ValueError("name input exceeds 1000 names")
    return names


def simulate(persona: str, audit_path: str | None, presentation: str = "transparent") -> int:
    session = DecoySession(persona, presentation)
    audit = new_private_file(audit_path) if audit_path else None
    try:
        print("Operator notice: in-memory simulation only. No real privileges, execution, or network.\n"
              "Audit retains timestamps and command hashes, not raw commands or arguments.", file=sys.stderr)
        print(session.banner, end="")
        while not session.closed:
            if sys.stdin.isatty():
                print(session.prompt, end="", flush=True)
            raw = sys.stdin.readline(MAX_INPUT + 2)
            if not raw:
                break
            if len(raw.rstrip("\n")) > MAX_INPUT:
                print(session.execute(raw), end="")
                if audit and session.events:
                    audit.write(json.dumps(session.events[-1], ensure_ascii=True) + "\n")
                    audit.flush()
                print("[SIMULATED] oversized input; session stopped safely")
                break
            output = session.execute(raw.rstrip("\n"))
            print(output, end="", flush=True)
            if audit and session.events:
                audit.write(json.dumps(session.events[-1], ensure_ascii=True) + "\n")
                audit.flush()
    finally:
        if audit:
            audit.close()
    return 0


def add_log_input(p: argparse.ArgumentParser, required: bool = False) -> None:
    group = p.add_mutually_exclusive_group(required=required)
    group.add_argument("--logs", help="explicit local text/JSONL log file; no upload")
    group.add_argument("--paste", action="store_true", help="paste real logs into stdin, end with ENDLOG or EOF")
    p.add_argument("--format", choices=["text", "jsonl"], default="text")
    p.add_argument("--marker", default="ENDLOG", help="paste terminator on its own line")


def import_input(args: argparse.Namespace) -> dict | None:
    from .ingest import ingest_logs, ingest_pasted
    if args.paste:
        print(f"Paste logs; end with {args.marker} on its own line (or EOF). Paste stays local.\n"
              "Remove sensitive values first; automated redaction is not guaranteed.", file=sys.stderr)
        return ingest_pasted(sys.stdin, format=args.format, marker=args.marker)
    if args.logs:
        return ingest_logs(args.logs, format=args.format)
    return None


def optional_names(args: argparse.Namespace) -> dict | None:
    if bool(args.observed_names) != bool(args.trusted_names):
        raise ValueError("use --observed-names and --trusted-names together")
    if args.observed_names:
        from .typosquat import check_names
        return check_names(read_names(args.observed_names), read_names(args.trusted_names), kind=args.kind)
    return None


def add_optional_names(p: argparse.ArgumentParser) -> None:
    p.add_argument("--observed-names", help="one observed domain/package name per line")
    p.add_argument("--trusted-names", help="operator-provided trusted baseline, one per line")
    p.add_argument("--kind", choices=["domain", "package"], default="domain")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Local incident-response triage and a networkless decoy lab.")
    p.add_argument("--version", action="version", version="reverse-shell-decoy 0.1.0")
    sub = p.add_subparsers(dest="command", required=True)
    cloud = sub.add_parser("cloud", help="analyze explicitly pasted/exported cloud logs; no credentials or account access")
    cloud.add_argument("--provider", required=True, choices=["cloudflare", "aws", "render", "railway"])
    cg = cloud.add_mutually_exclusive_group(required=True)
    cg.add_argument("--logs")
    cg.add_argument("--paste", action="store_true")
    cloud.add_argument("--format", choices=["auto", "json", "jsonl", "text"], default="auto")
    cloud.add_argument("--marker", default="ENDLOG")
    collect = sub.add_parser("collect-cloud", help="manual opt-in read-only API collection using your own scoped environment credentials")
    collect.add_argument("--provider", required=True, choices=["cloudflare", "aws", "render", "railway"])
    collect.add_argument("--scope-id", required=True)
    collect.add_argument("--since", required=True)
    collect.add_argument("--until", required=True)
    collect.add_argument("--region")
    summary = sub.add_parser("summary", help="summarize supplied files only; never launch or scan anything")
    from .summary import add_arguments
    add_arguments(summary)
    operations = sub.add_parser("operations", help="local decoy budget and activity-pattern summary from explicitly selected audit")
    from .operations import add_arguments as add_operations_arguments
    add_operations_arguments(operations)
    response = sub.add_parser("sinkhole-plan", help="review-only proposal; never changes DNS or redirects traffic")
    response.add_argument("--report", required=True)
    response.add_argument("--owned-domain", required=True)
    response.add_argument("--decoy-ip", required=True)
    response.add_argument("--confirm-owned", action="store_true")
    sub.add_parser("scan", help="read-only Linux shell/socket suspicion snapshot as JSON")
    sub.add_parser("os", help="read-only limited OS details of this computer")
    sub.add_parser("listeners", help="read-only Linux TCP listeners and UDP bindings; no port probes")
    persist = sub.add_parser("persistence", help="read-only startup/backdoor indicators, not a malware verdict")
    persist.add_argument("--root", action="append", help="authorized config directory to inspect; default cron/systemd roots")
    ingest = sub.add_parser("ingest", help="normalize pasted or explicitly selected real logs locally")
    add_log_input(ingest, required=True)
    names = sub.add_parser("names", help="offline domain/package typosquatting indicators relative to your baseline")
    names.add_argument("--observed", required=True)
    names.add_argument("--trusted", required=True)
    names.add_argument("--kind", choices=["domain", "package"], default="domain")
    audit = sub.add_parser("audit", help="combined real OS, shell/socket, listener and startup audit")
    add_log_input(audit)
    add_optional_names(audit)
    sim = sub.add_parser("simulate", help="in-memory terminal; never executes commands or opens sockets")
    sim.add_argument("--persona", choices=["linux", "windows"], default="linux")
    sim.add_argument("--presentation", choices=["transparent", "realistic"], default="transparent",
                     help="realistic neutralizes terminal labels; operator notice and audit remain explicit")
    sim.add_argument("--audit", help="create a new private JSONL file; never overwrite")
    scenario = sub.add_parser("experiment", help="synthetic state effects only; no real OS/EDR events")
    scenario.add_argument("scenario", choices=["baseline", "process-limit", "network-loss", "telemetry-gap"])
    scenario.add_argument("--seed", type=int, default=0)
    evidence = sub.add_parser("evidence", help="export private ZIP with real observations, imports and separate decoy audit")
    evidence.add_argument("--output", required=True, help="new ZIP path; review before sharing")
    evidence.add_argument("--audit", help="optional simulation JSONL; never auto-collect logs")
    evidence.add_argument("--summary-report", help="optional previously generated cloud-summary JSON; no live account scan")
    add_log_input(evidence)
    add_optional_names(evidence)
    verify = sub.add_parser("verify", help="check bundle integrity, not truth or authenticity")
    verify.add_argument("path")
    return p


def emit(result: dict) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))


def emit_scan(result: dict, command: str) -> None:
    """Keep scan JSON on stdout; offer a fresh, local consent-gated review."""
    emit(result)
    try:
        from .review import offer_review
        offer_review(result, command)
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Optional review unavailable; the original scan result is unchanged.", file=sys.stderr)
    except KeyboardInterrupt:
        print("Optional review declined; the original scan result is unchanged.", file=sys.stderr)


def pasted_cloud_content(marker: str) -> str:
    if not marker or len(marker) > 64 or any(c.isspace() for c in marker):
        raise ValueError("paste marker must be 1..64 non-whitespace characters")
    print(f"Paste exported cloud logs; end with {marker} on its own line. Input stays local.\nRemove secrets first; this does not authenticate log origin.", file=sys.stderr)
    chunks, total = [], 0
    for _ in range(10001):
        line = sys.stdin.readline(256 * 1024 + 1)
        if not line or line.rstrip("\r\n") == marker:
            return "".join(chunks)
        if len(line.encode("utf-8")) > 256 * 1024 or len(chunks) >= 10000:
            raise ValueError("paste line/record limit exceeded")
        total += len(line.encode("utf-8"))
        if total > 8 * 1024 * 1024:
            raise ValueError("paste exceeds 8 MiB")
        chunks.append(line)
    raise ValueError("paste record limit exceeded")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "simulate":
            return simulate(args.persona, args.audit, args.presentation)
        if args.command == "cloud":
            from .cloud import analyze_cloud_logs
            content = pasted_cloud_content(args.marker) if args.paste else read_regular(args.logs, 8 * 1024 * 1024).decode("utf-8")
            emit_scan(analyze_cloud_logs(args.provider, content, format=args.format), args.command)
            return 0
        if args.command == "collect-cloud":
            from .collectors import collect_cloud
            emit_scan(collect_cloud(args.provider, args.scope_id, args.since, args.until, args.region), args.command)
            return 0
        if args.command == "summary":
            from .summary import run_args
            return run_args(args)
        if args.command == "operations":
            from .operations import run_args as run_operations_args
            return run_operations_args(args)
        if args.command == "sinkhole-plan":
            from .response import sinkhole_plan
            report = json.loads(read_regular(args.report, 8 * 1024 * 1024).decode("utf-8"))
            if not isinstance(report, dict):
                raise ValueError("report must be a JSON object")
            emit(sinkhole_plan(report, args.owned_domain, args.decoy_ip, args.confirm_owned))
            return 0
        if args.command == "scan":
            from .detector import scan
            emit_scan(scan(), args.command)
        elif args.command == "os":
            from .evidence import os_info
            emit_scan(os_info(), args.command)
        elif args.command == "listeners":
            from .listeners import scan_listeners
            emit_scan(scan_listeners(), args.command)
        elif args.command == "persistence":
            from .persistence import scan_persistence
            emit_scan(scan_persistence(args.root), args.command)
        elif args.command == "ingest":
            emit(import_input(args))
        elif args.command == "names":
            from .typosquat import check_names
            emit_scan(check_names(read_names(args.observed), read_names(args.trusted), kind=args.kind), args.command)
        elif args.command == "audit":
            from .correlation import audit_host
            emit_scan(audit_host(import_input(args), optional_names(args)), args.command)
        elif args.command == "experiment":
            from .experiments import run_scenario
            emit(run_scenario(args.scenario, args.seed))
        elif args.command == "evidence":
            from .correlation import audit_host
            from .evidence import export_bundle
            report = audit_host(import_input(args), optional_names(args))
            if args.summary_report:
                summary_input = json.loads(read_regular(args.summary_report, 8 * 1024 * 1024).decode("utf-8"))
                if not isinstance(summary_input, dict):
                    raise ValueError("supplied summary must be a JSON object")
                report["manual_summary_unverified"] = summary_input
            path = export_bundle(Path(args.output), report, read_audit(args.audit))
            print(f"Evidence ZIP created: {path}\nIncludes host OS, endpoint metadata and selected imports. Review before sharing. Nothing uploaded.")
        elif args.command == "verify":
            from .evidence import verify_bundle
            result = verify_bundle(args.path)
            emit(result)
            return 0 if result.get("valid") else 1
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130
    return 0
