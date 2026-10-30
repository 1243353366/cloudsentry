#!/usr/bin/env python3
"""Synthetic/configuration and loopback layer smoke checks, not real VM boots."""
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
from reverse_shell_decoy.backup_smoke import negative_control_results, validate_layer_results

LAYER_TESTS = (
    ("primary_vm_configuration", ("test_backup_admission.py",), "LibvirtAdmissionTests"),
    ("pc_free_backup_configuration", ("test_backup_admission.py",), "PcFreeAdmissionTests"),
    ("two_inbound_echo_surfaces", ("test_backup_echo.py",), None),
    ("emergency_sink", ("test_emergency.py", "test_tarpit.py"), None),
    ("opaque_mirror", ("test_mirror.py", "test_mirror_regression.py", "test_protected_analysis.py"), None),
)
SOURCE_FILES = (
    "src/reverse_shell_decoy/backup_admission.py", "src/reverse_shell_decoy/backup_echo.py",
    "src/reverse_shell_decoy/backup_smoke.py", "src/reverse_shell_decoy/authorization.py",
    "src/reverse_shell_decoy/honeypot.py", "scripts/review-backup.py",
    "scripts/start-backup-echo.py", "scripts/backup-echo.sh",
)


def source_hashes(grant, scope):
    hashes = {}
    for name in SOURCE_FILES:
        grant.check(scope)
        hashes[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        grant.check(scope)
    return hashes


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def run_tests(suite):
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        return unittest.TextTestRunner(stream=captured, verbosity=0).run(suite)


def failing_runner_control():
    class DeliberateFailure(unittest.TestCase):
        def runTest(self):
            self.fail("intentional smoke-runner negative control")
    result = run_tests(unittest.TestSuite([DeliberateFailure()]))
    return result.testsRun == 1 and len(result.failures) == 1 and not result.wasSuccessful()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--consent", action="store_true")
    args = parser.parse_args(argv)
    scope = AuthorizationScope("train", "builtin:backup-layer-smoke")
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        print("Permission required; no layer test ran.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(grant):
            grant.begin(scope)
            source_before = source_hashes(grant, scope)
            layers = []
            hashes = {}
            for name, patterns, class_name in LAYER_TESTS:
                grant.check(scope)
                suite = unittest.TestSuite()
                for pattern in patterns:
                    # Exact expected test files must exist; a missing suite is not a pass.
                    path = ROOT / "tests" / pattern
                    hashes[pattern] = hashlib.sha256(path.read_bytes()).hexdigest()
                    discovered = unittest.TestLoader().discover(str(ROOT / "tests"), pattern=pattern)
                    suite.addTests(item for item in flatten(discovered)
                                   if class_name is None or type(item).__name__ == class_name)
                result = run_tests(suite)
                grant.check(scope)
                layers.append({"layer": name, "tests_run": result.testsRun,
                               "failures": len(result.failures), "errors": len(result.errors),
                               "skipped": len(result.skipped), "passed": result.wasSuccessful(),
                               "runtime_vm_boot_tested": False})
            controls = negative_control_results()
            controls["runner_catches_deliberately_failing_test"] = failing_runner_control()
            boot_tests = unittest.TestLoader().discover(str(ROOT / "tests"), pattern="test_backup_boot_boundary.py")
            boot_result = run_tests(boot_tests)
            controls["boot_and_hid_additions_fail_admission"] = (
                boot_result.testsRun >= 3 and boot_result.wasSuccessful() and not boot_result.skipped)
            hashes["test_backup_boot_boundary.py"] = hashlib.sha256(
                (ROOT / "tests" / "test_backup_boot_boundary.py").read_bytes()).hexdigest()
            grant.check(scope)
            source_after = source_hashes(grant, scope)
            report = {
                "format": "backup_layer_smoke_v1", "provider": "local",
                "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "passed": validate_layer_results(layers) and all(controls.values()) and source_before == source_after,
                "layers": layers, "smoke_test_negative_controls": controls,
                "test_file_sha256": hashes,
                "local_source_sha256": source_after,
                "source_files_unchanged_during_checks": source_before == source_after,
                "scope": "static_candidate_and_finite_loopback_regressions_only",
                "runtime_vm_boot_tested": False, "vm_escape_tested": False,
                "openterface_hardware_tested": False, "hid_control_authorized": False,
                "backend_ready_for_deployment": False, "automatic_failover_authorized": False,
                "customer_data_used": False, "remote_target": None,
                "limitations": ["Not a real VM boot or remote-isolation attestation.",
                                "Positive smoke results cannot approve a backend or defeat compromised code/hosts.",
                                "Runtime hypervisor, disk-image, controller, ingress and egress checks remain external."],
            }
            grant.check(scope)
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            return 0 if report["passed"] else 1
    except (AuthorizationError, OSError, ValueError, KeyboardInterrupt):
        print("Layer smoke unavailable or permission revoked; no backend was authorized.", file=sys.stderr)
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
