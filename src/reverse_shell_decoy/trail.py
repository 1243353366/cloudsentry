"""Build a bounded, local-only text-pattern trail from selected decoy audits.

The trail consumes the investigator module's already-normalized report rather
than parsing, executing, or replaying audit input itself.  It exposes only
integrity references and fixed classification labels; it never includes raw
commands, arguments, payloads, credentials, visitor identity, operating-system
claims, or competence scores.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import sys
from typing import Any

from . import investigator


TRAIL_SCHEMA_VERSION = "1.0"
TEXT_PATTERN_STATEMENT = (
    "Text pattern only; not execution, intent, competence, attribution or proof "
    "of unauthorized host access."
)


def build_trail(audit_paths: list[str]) -> dict[str, Any]:
    """Return a safe, local aggregation for explicitly selected audit JSONL files.

    ``investigator.build_report`` applies the file, record, simulation-source,
    and timeline-field bounds.  This function projects that report into a
    smaller trail; it does not read a raw audit line, write a file, execute an
    input, or contact a service.
    """
    report = investigator.build_report(audit_paths)
    timeline = report["timeline"]

    classifications: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    tokens: Counter[str] = Counter()
    events: list[dict[str, Any]] = []
    for entry in timeline:
        event = _safe_event(entry)
        events.append(event)

        classification = event["classification"]
        classifications[classification] += 1
        language = event.get("language_indicator")
        if language is not None:
            languages[language] += 1
        tokens.update(event.get("token_indicators", []))

    counts = report["counts"]
    return {
        "trail_schema_version": TRAIL_SCHEMA_VERSION,
        "authorization_status": "not_established",
        "statement": TEXT_PATTERN_STATEMENT,
        "counts": {
            "audit_file_count": counts["audit_file_count"],
            "recognized_record_count": len(events),
            "skipped_record_count": counts["skipped_record_count"],
            "source_classifications": dict(sorted(classifications.items())),
            "language_indicators": dict(sorted(languages.items())),
            "token_indicators": dict(sorted(tokens.items())),
        },
        "source_references": _safe_source_references(report["source_manifest"]),
        "timeline": events,
    }


def main(argv: list[str] | None = None) -> int:
    """Write one trail JSON object to stdout and no output files."""
    parser = argparse.ArgumentParser(
        description=(
            "Summarize selected synthetic decoy JSONL audits as bounded text-pattern "
            "classification evidence; no execution, network, or file output."
        )
    )
    parser.add_argument(
        "--audit",
        action="append",
        required=True,
        metavar="FILE",
        help="selected JSONL audit file (repeat at most four times)",
    )
    args = parser.parse_args(argv)
    try:
        trail = build_trail(args.audit)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(trail, sort_keys=True, separators=(",", ":")))
    return 0


def _safe_event(entry: dict[str, Any]) -> dict[str, Any]:
    """Project one normalized timeline entry into the trail's fixed safe schema."""
    event: dict[str, Any] = {
        "source_kind": entry["source_kind"],
        "classification": entry["classification"],
        "source_file_sha256": entry["source_file_sha256"],
        "physical_line_index": entry["physical_line_index"],
        "physical_line_sha256": entry["physical_line_sha256"],
    }
    if "timestamp_utc" in entry:
        event["timestamp_utc"] = entry["timestamp_utc"]
    for name in ("command_sha256", "input_sha256"):
        if name in entry:
            event[name] = entry[name]
    if isinstance(entry.get("blocked"), bool):
        event["blocked"] = entry["blocked"]
    language = entry.get("language_indicator")
    if isinstance(language, str) and language in investigator.LANGUAGES:
        event["language_indicator"] = language
    token_indicators = entry.get("token_indicators")
    if _safe_token_indicators(token_indicators):
        event["token_indicators"] = list(token_indicators)
    return event


def _safe_source_references(source_manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain source SHA-256 references without paths, record contents, or names."""
    references: list[dict[str, Any]] = []
    for source in source_manifest:
        source_index = source.get("source_index")
        source_hash = source.get("source_file_sha256")
        if (
            isinstance(source_index, int)
            and not isinstance(source_index, bool)
            and source_index > 0
            and _is_sha256(source_hash)
        ):
            references.append(
                {
                    "source_index": source_index,
                    "source_file_sha256": source_hash,
                }
            )
    return references


def _safe_token_indicators(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= investigator.MAX_TOKEN_INDICATORS
        and all(isinstance(token, str) and token in investigator.TOKEN_INDICATORS for token in value)
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


__all__ = [
    "TEXT_PATTERN_STATEMENT",
    "TRAIL_SCHEMA_VERSION",
    "build_trail",
    "main",
]
