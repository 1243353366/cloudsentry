#!/usr/bin/env python3
"""Verify selected report artifacts; no source-authenticity or VM guarantee."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import argparse
import json
from reverse_shell_decoy.authorization import (
    AuthorizationError, AuthorizationScope, cancellation_guard, request_authorization,
)
from reverse_shell_decoy.incident_explainer import verify_packet


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--packet", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True,
                        help="pin saved separately when the trusted export completed")
    parser.add_argument("--consent", action="store_true")
    args = parser.parse_args(argv)
    scope = AuthorizationScope("verify_evidence", args.packet, args.expected_manifest_sha256)
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        print("Permission required; no packet was read.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(grant):
            result = verify_packet(args.packet, expected_manifest_sha256=args.expected_manifest_sha256,
                                   authorization=grant, scope=scope)
            print(json.dumps(result, sort_keys=True))
        return 0
    except (AuthorizationError, ValueError, OSError, KeyboardInterrupt):
        print("Verification or authorization failed; no verified report was produced.", file=sys.stderr)
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
