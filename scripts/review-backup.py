#!/usr/bin/env python3
"""Static-only review or candidate emission for backup profile configuration.

The command never starts Docker, Compose, libvirt, QEMU, KVM, a VM, an image pull,
a registry request, a host socket, or any provider resource.  It writes no files.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.authorization import (
    AuthorizationError,
    AuthorizationScope,
    cancellation_guard,
    request_authorization,
)
from reverse_shell_decoy.backup_admission import (
    MAX_CONFIG_BYTES,
    make_libvirt_candidate,
    make_pc_free_candidate,
    review_libvirt,
    review_pc_free,
)
from reverse_shell_decoy.input_files import read_regular


def _failure(code: str, expected: str | None = None) -> dict[str, Any]:
    """Return a fixed, source-free status when a selected file cannot be read."""
    return {
        "admission_code": code,
        "api_version": "backup-admission/v2",
        "claim_check": "STATIC_SCHEMA_ONLY",
        "config_sha256": None,
        "expected_config_sha256": expected if type(expected) is str and re.fullmatch(r"[a-f0-9]{64}", expected) else None,
        "machine_actions": [],
        "profile_only": True,
        "ready_for_deployment": False,
        "runtime_checks": "unknown",
        "source_authority": "unverified",
    }


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Static schema review only; this command never deploys, boots, or contacts a backend.",
        allow_abbrev=False,
    )
    argument_parser.add_argument("--backend", choices=("libvirt", "pc-free"), required=True)
    argument_parser.add_argument("--config", metavar="FILE", help="selected candidate XML or JSON file")
    argument_parser.add_argument("--expected-sha256", metavar="HEX", help="external exact SHA-256 pin for --config")
    argument_parser.add_argument("--emit-candidate", action="store_true", help="print a review candidate; no write or launch")
    argument_parser.add_argument("--session-id", metavar="HEX", help="optional 16-hex candidate identity")
    argument_parser.add_argument("--image", metavar="DIGEST_REF", help="required only for pc-free candidate emission")
    argument_parser.add_argument("--consent", action="store_true", help="explicit per-invocation authorization acknowledgement")
    return argument_parser


def _print(value: dict[str, Any] | str) -> None:
    if type(value) is str:
        sys.stdout.write(value)
    else:
        sys.stdout.write(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False))
    sys.stdout.write("\n")


def _review_scope(config: str, expected: str) -> AuthorizationScope:
    return AuthorizationScope("static_analysis", os.fspath(config), expected)


def _candidate_scope(backend: str) -> AuthorizationScope:
    # A built-in grammar is the input; no external image/ref/raw XML is placed in scope.
    return AuthorizationScope("static_analysis", f"builtin:backup:{backend}", "")


def _arguments_are_valid(args: argparse.Namespace) -> bool:
    if args.emit_candidate:
        if args.config is not None or args.expected_sha256 is not None:
            return False
        if args.backend == "pc-free":
            return args.image is not None
        return args.image is None
    return (
        args.config is not None
        and args.expected_sha256 is not None
        and args.image is None
        and args.session_id is None
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not _arguments_are_valid(args):
        _print(_failure("ARGUMENTS_INVALID"))
        return 2

    scope = _candidate_scope(args.backend) if args.emit_candidate else _review_scope(args.config, args.expected_sha256)
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        return 2

    try:
        with cancellation_guard(grant):
            grant.begin(scope)
            grant.check(scope)
            if args.emit_candidate:
                # Identity creation occurs only after a current authorization is begun.
                session_id = args.session_id if args.session_id is not None else secrets.token_hex(8)
                text = (
                    make_libvirt_candidate(session_id)
                    if args.backend == "libvirt"
                    else make_pc_free_candidate(args.image, session_id)
                )
                grant.check(scope)
                _print(text)
                return 0

            raw = read_regular(os.fspath(args.config), MAX_CONFIG_BYTES)
            grant.check(scope)
            result = review_libvirt(raw, args.expected_sha256) if args.backend == "libvirt" else review_pc_free(raw, args.expected_sha256)
            grant.check(scope)
            _print(result)
            return 0 if result["admission_code"] == "STATIC_PROFILE_ACCEPTED" else 2
    except (AuthorizationError, KeyboardInterrupt):
        return 2
    except (OSError, ValueError, TypeError, UnicodeError):
        _print(_failure("INPUT_UNAVAILABLE", args.expected_sha256))
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
