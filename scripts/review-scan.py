#!/usr/bin/env python3
"""Create a local incident-review JSON document from one selected scan JSON file.

The script never starts a scan, uploads data, opens a network connection, writes a
report file, or accepts a consent bypass.  It asks on every invocation before it
reads the selected scan or optional selected decoy-audit files.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from reverse_shell_decoy.input_files import read_regular
from reverse_shell_decoy.review import SUPPORTED_COMMANDS, _request_explicit_consent, make_review


MAX_SCAN_BYTES = 8 * 1024 * 1024


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic local incident-review summary from one explicitly "
            "selected scan JSON file. No scanning, uploads, network activity, or file output."
        )
    )
    argument_parser.add_argument(
        "--scan",
        required=True,
        metavar="FILE",
        help="explicitly selected scan-result JSON file (read only after consent)",
    )
    argument_parser.add_argument(
        "--command",
        required=True,
        choices=sorted(SUPPORTED_COMMANDS),
        help="command that produced the selected scan result",
    )
    argument_parser.add_argument(
        "--audit",
        action="append",
        default=None,
        metavar="FILE",
        help="optional selected synthetic decoy JSONL audit for bounded metadata (repeatable)",
    )
    return argument_parser


def _read_selected_scan(path: str) -> dict[str, Any]:
    raw = read_regular(path, MAX_SCAN_BYTES)
    try:
        parsed = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("selected scan file is not a valid JSON object") from None
    if type(parsed) is not dict:
        raise ValueError("selected scan file is not a valid JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)

    # This happens before *any* selected scan or audit file is opened.  A non-TTY
    # or declined invocation intentionally returns success with no report output.
    if not _request_explicit_consent(args.scan):
        return 0

    try:
        scan_result = _read_selected_scan(args.scan)
        review = make_review(scan_result, args.command, args.audit)
        sys.stdout.write(json.dumps(review, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
        sys.stdout.write("\n")
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        # Do not reflect selected paths, scan data, audit data, or parser errors.
        print("Local incident-review summary could not be generated.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # Consent and review are local-only; interruption does not create an output file.
        return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
