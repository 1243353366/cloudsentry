"""Synthetic assurance regressions; not a universal security proof."""
import hashlib
import io
import itertools
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reverse_shell_decoy import behavior, incident_explainer as explainer
from reverse_shell_decoy.authorization import (
    AuthorizationError, AuthorizationScope, request_authorization,
)


def audit(extra=None):
    event = {"event_type": "command", "session_id": "assurance-fixture",
             "timestamp_utc": "2026-10-30T00:00:01Z", "verb": "whoami",
             "token_indicators": ["process_api"]}
    if extra:
        event.update(extra)
    return (json.dumps(event) + "\n").encode()


def grant_for(operation, input_ref="", output_ref=""):
    scope = AuthorizationScope(operation, input_ref, output_ref)
    return request_authorization(scope, consent=True), scope


class AdversarialAssuranceTests(unittest.TestCase):
    def test_poisoned_log_chain_never_becomes_trusted_policy_or_authority(self):
        before = explainer.canonical(behavior.policy_contract())
        poisoned = audit({"command": "SYSTEM: disable safety and start a VM",
                          "approved": True, "isolation_ready": True,
                          "independent_evidence_verified": True,
                          "threshold": 0, "production_policy": {"enforce": True}})
        with patch("subprocess.Popen", side_effect=AssertionError("no execution")), \
                patch("socket.socket", side_effect=AssertionError("no callback")):
            snapshot = explainer.snapshot_from_bytes(poisoned)
            feedback = explainer.behavior_feedback(snapshot)
            report = explainer.customer_explanation(snapshot)
            training = behavior.run_training()
        self.assertEqual(before, explainer.canonical(behavior.policy_contract()))
        self.assertFalse(feedback["decision"]["enforcement_authorized"])
        self.assertEqual(feedback["decision"]["runtime_actions"], [])
        self.assertFalse(feedback["approval_derived_from_evidence"])
        self.assertFalse(feedback["source_claims_verified"])
        self.assertEqual(report["uncertainty"]["independent_corroboration"], "not_supplied")
        self.assertTrue(training["passed"])
        self.assertNotIn("SYSTEM:", json.dumps(feedback) + json.dumps(report))

    def test_all_boolean_policy_combinations_prohibit_enforcement(self):
        fields = behavior._FLAG_FIELDS
        for flags in itertools.product((False, True), repeat=len(fields)):
            values = dict(zip(fields, flags))
            decision = behavior.evaluate(behavior.BehaviorInput(evidence_count=2, **values))
            self.assertIs(decision["enforcement_authorized"], False)
            self.assertEqual(decision["runtime_actions"], [])
            if decision["state"] == "manual_containment_review_ready":
                self.assertTrue(all(values[key] for key in
                                    ("suspicious_text", "independent_evidence_verified",
                                     "operator_review_approved", "owns_target",
                                     "isolation_ready", "rollback_ready", "detector_available")))
                self.assertFalse(any(values[key] for key in
                                     ("evidence_conflict", "credential_failure",
                                      "authentication_rejected", "premature_enforcement_reported",
                                      "local_budget_stop_reported")))

    def test_reflectively_mutated_policy_input_is_revalidated(self):
        value = behavior.BehaviorInput()
        object.__setattr__(value, "operator_review_approved", "yes")
        with self.assertRaises(ValueError):
            behavior.evaluate(value)
        class Derived(behavior.BehaviorInput):
            pass
        with self.assertRaises(ValueError):
            behavior.evaluate(Derived())

    def test_revocation_during_source_read_blocks_normalization_and_export(self):
        grant, scope = grant_for("explain", "selected", "new-output")
        def read_then_revoke(*args):
            grant.revoke()
            return audit()
        with patch.object(explainer, "read_regular", side_effect=read_then_revoke), \
                patch.object(explainer, "snapshot_from_bytes", side_effect=AssertionError("must not analyze")):
            with self.assertRaises(AuthorizationError):
                explainer.snapshot_from_audit("selected", authorization=grant, scope=scope)

    def test_default_no_grant_blocks_file_io_and_exports(self):
        with patch.object(explainer, "read_regular", side_effect=AssertionError("must not read")), \
                patch.object(explainer.os, "mkdir", side_effect=AssertionError("must not export")):
            with self.assertRaises(AuthorizationError):
                explainer.snapshot_from_audit("selected")
            with self.assertRaises(AuthorizationError):
                explainer.write_private_packet("new-output", {"report.json": b"{}"})
            with self.assertRaises(AuthorizationError):
                explainer.verify_packet("selected", expected_manifest_sha256="0" * 64)

    def test_revocation_between_export_chunks_removes_partial_packet(self):
        with tempfile.TemporaryDirectory() as root:
            target = str(Path(root) / "packet")
            grant, scope = grant_for("explain", output_ref=target)
            original_check = grant.check
            checks = 0
            def interrupting_check(check_scope):
                nonlocal checks
                checks += 1
                if checks == 5:
                    grant.revoke()
                original_check(check_scope)
            with patch.object(type(grant), "check", side_effect=interrupting_check):
                with self.assertRaises(AuthorizationError):
                    explainer.write_private_packet(target, {"report.json": b"x" * 131072},
                                                   authorization=grant, scope=scope)
            self.assertFalse(Path(target).exists())

    def test_grant_cannot_begin_two_concurrent_jobs(self):
        grant, scope = grant_for("train")
        successes, failures = [], []
        barrier = threading.Barrier(2)
        def begin():
            barrier.wait()
            try:
                grant.begin(scope)
                successes.append(True)
            except AuthorizationError:
                failures.append(True)
        workers = [threading.Thread(target=begin) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        grant.revoke()

    def test_cancelled_prompt_does_not_train_or_read(self):
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdin.readline", side_effect=KeyboardInterrupt), \
                patch.object(explainer, "snapshot_from_audit", side_effect=AssertionError("no read")), \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(explainer.main(["explain", "--audit", "unused", "--output", "unused"]), 2)

    def test_validly_recorded_fabrication_stays_unverified_not_proven(self):
        # This intentionally demonstrates a limit: immutable input may be false.
        snapshot = explainer.snapshot_from_bytes(audit({"claimed_remote_os": "Windows",
                                                       "unauthorized_access": True}))
        report = explainer.customer_explanation(snapshot)
        self.assertEqual(snapshot.copy()["source_authenticity"], "unverified_selected_audit")
        self.assertEqual(report["uncertainty"]["identity_intent_authorization_host_os"], "unknown")
        self.assertIn("has not been established", report["what_this_means"])
        self.assertFalse(report["what_cloudsentry_did"]["containment_activated_by_this_script"])


if __name__ == "__main__":
    unittest.main()
