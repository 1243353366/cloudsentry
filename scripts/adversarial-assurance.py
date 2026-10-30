#!/usr/bin/env python3
"""Run fixed synthetic assurance checks; not a proof against every attack."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
import unittest

from reverse_shell_decoy.authorization import (
    AuthorizationError, AuthorizationScope, cancellation_guard, request_authorization,
)
from reverse_shell_decoy.behavior import policy_contract
from reverse_shell_decoy.incident_explainer import canonical, write_private_packet

TEST_FILES = (
    "test_adversarial_assurance.py", "test_authorization.py", "test_evidence_integrity.py",
    "test_incident_explainer.py", "test_behavior.py", "test_protected_analysis.py",
    "test_virtual_analysis.py", "test_mirror_regression.py", "test_mirror_corpus_bounds.py",
)
SOURCE_FILES = (
    "authorization.py", "behavior.py", "incident_explainer.py",
    "virtual_analysis.py", "mirror_regression.py",
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--output", help="new private directory; otherwise report JSON on stdout")
    args = parser.parse_args(argv)
    scope = AuthorizationScope("train", "builtin:adversarial-assurance", args.output or "")
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        print("Permission required; no assurance cases ran.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(grant):
            grant.begin(scope)
            before = hashlib.sha256(canonical(policy_contract())).hexdigest()
            loader = unittest.TestLoader()
            suite = unittest.TestSuite()
            for name in TEST_FILES:
                grant.check(scope)
                suite.addTests(loader.discover(str(ROOT / "tests"), pattern=name))
            # Fixtures may emit local test audit events. Never publish captured
            # traces, raw fixture contents, environment values or local paths.
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                result = unittest.TextTestRunner(stream=captured, verbosity=0).run(suite)
            grant.check(scope)
            after = hashlib.sha256(canonical(policy_contract())).hexdigest()
            failed = sorted(test.id() for test, _detail in result.failures + result.errors)
            hashes = {}
            for name in SOURCE_FILES:
                grant.check(scope)
                hashes[name] = hashlib.sha256((ROOT / "src" / "reverse_shell_decoy" / name).read_bytes()).hexdigest()
            report = {
                "format": "adversarial_assurance_report_v1", "provider": "local",
                "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "passed": result.wasSuccessful() and before == after,
                "tests_run": result.testsRun, "failed_test_ids": failed,
                "skipped_tests": len(result.skipped),
                "exhaustive_boolean_combinations": 8192,
                "exhaustive_evidence_count": 2,
                "policy_contract_sha256_before": before,
                "policy_contract_sha256_after": after,
                "policy_unchanged": before == after,
                "local_source_sha256": hashes,
                "scope": "fixed_synthetic_regressions_and_disposable_loopback_only",
                "production_policy_adopted": False, "customer_data_used": False,
                "third_party_target": None, "real_vm_tested": False,
                "pc_free_deployed_or_tested": False,
                "coverage": ["review_policy_no_enforcement", "poisoned_input_remains_unverified",
                             "snapshot_tamper_rejection", "pinned_packet_and_session_binding",
                             "revocation_and_interrupted_consent", "one_grant_one_pipeline",
                             "bounded_nonexecuting_echo", "unavailable_vm_fails_closed"],
                "limitations": [
                    "Finite regression coverage, not formal verification or immunity to all tricks.",
                    "Initial source authenticity and independent corroboration remain unknown.",
                    "Same-process arbitrary code or a compromised host can bypass Python checks.",
                    "Local hashes are not a supply-chain signature or real-VM attestation.",
                    "Revocation stops subsequent protected phases; it cannot undo a completed read.",
                    "SIGKILL or power loss can leave incomplete private artifacts; require pinned verification.",
                    "No VM escape, real Windows backup, cloud permission or live customer attack was tested.",
                ],
            }
            grant.check(scope)
            encoded = canonical(report) + b"\n"
            if args.output:
                write_private_packet(args.output, {"adversarial-assurance.json": encoded},
                                     authorization=grant, scope=scope)
                print("Created private assurance report; production authority unchanged.")
            else:
                print(encoded.decode("ascii"), end="")
            return 0 if report["passed"] else 1
    except (AuthorizationError, OSError, ValueError, KeyboardInterrupt):
        print("Assurance or authorization failed; no trusted result or fallback was activated.", file=sys.stderr)
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
