"""Tests for the pure, review-only security behavior policy."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, asdict, fields
import hashlib
import inspect
import json
import unittest
from unittest import mock

from reverse_shell_decoy import behavior
from reverse_shell_decoy.behavior import BehaviorInput, evaluate, policy_contract, run_training


_INPUT_FIELD_NAMES = (
    "unfamiliar_connection",
    "suspicious_text",
    "evidence_conflict",
    "detector_available",
    "credential_failure",
    "authentication_rejected",
    "premature_enforcement_reported",
    "local_budget_stop_reported",
    "evidence_count",
    "independent_evidence_verified",
    "operator_review_approved",
    "owns_target",
    "isolation_ready",
    "rollback_ready",
)
_DECISION_KEYS = {
    "enforcement_authorized",
    "runtime_actions",
    "state",
    "rule_id",
    "reasons",
    "suggestions",
    "policy_version",
}


def _canonical_sha256(value: object) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _ready_inputs(**overrides):
    values = {
        "suspicious_text": True,
        "evidence_count": 2,
        "independent_evidence_verified": True,
        "operator_review_approved": True,
        "owns_target": True,
        "isolation_ready": True,
        "rollback_ready": True,
    }
    values.update(overrides)
    return BehaviorInput(**values)


class BehaviorInputTests(unittest.TestCase):
    def test_input_has_only_the_required_frozen_fields_in_order(self):
        self.assertEqual(tuple(field.name for field in fields(BehaviorInput)), _INPUT_FIELD_NAMES)
        self.assertTrue(BehaviorInput.__dataclass_params__.frozen)
        self.assertEqual(asdict(BehaviorInput()), {
            "unfamiliar_connection": False,
            "suspicious_text": False,
            "evidence_conflict": False,
            "detector_available": True,
            "credential_failure": False,
            "authentication_rejected": False,
            "premature_enforcement_reported": False,
            "local_budget_stop_reported": False,
            "evidence_count": 0,
            "independent_evidence_verified": False,
            "operator_review_approved": False,
            "owns_target": False,
            "isolation_ready": False,
            "rollback_ready": False,
        })

    def test_each_flag_requires_exact_bool_type(self):
        for name in _INPUT_FIELD_NAMES:
            if name == "evidence_count":
                continue
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    BehaviorInput(**{name: 1})
                with self.assertRaises(ValueError):
                    BehaviorInput(**{name: None})

    def test_evidence_count_requires_non_bool_bounded_int(self):
        class IntegerSubclass(int):
            pass

        for invalid in (True, False, -1, 1001, 1.5, "2", IntegerSubclass(2)):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(ValueError):
                    BehaviorInput(evidence_count=invalid)
        self.assertEqual(BehaviorInput(evidence_count=0).evidence_count, 0)
        self.assertEqual(BehaviorInput(evidence_count=1000).evidence_count, 1000)

    def test_unknown_fields_are_rejected_and_input_cannot_be_mutated(self):
        with self.assertRaises(TypeError):
            BehaviorInput(untrusted_log_payload="not a supported field")
        value = BehaviorInput()
        with self.assertRaises(FrozenInstanceError):
            value.suspicious_text = True


class EvaluationTests(unittest.TestCase):
    def _assert_review_only(self, decision):
        self.assertEqual(set(decision), _DECISION_KEYS)
        self.assertIs(decision["enforcement_authorized"], False)
        self.assertEqual(decision["runtime_actions"], [])
        self.assertEqual(decision["policy_version"], behavior.POLICY_VERSION)
        self.assertNotEqual(decision["state"], "contained")
        self.assertNotIn("already_blocked", decision["state"])

    def test_baseline_and_unfamiliar_connection_are_observe_or_monitor_only(self):
        baseline = evaluate(BehaviorInput())
        unfamiliar = evaluate(BehaviorInput(unfamiliar_connection=True))
        self._assert_review_only(baseline)
        self._assert_review_only(unfamiliar)
        self.assertEqual(baseline["state"], "observe")
        self.assertEqual(unfamiliar["state"], "monitor")
        self.assertEqual(unfamiliar["reasons"], ["unfamiliar_connection_observed"])
        self.assertNotIn("attribution", json.dumps(unfamiliar))

    def test_suspicious_text_without_independent_review_preconditions_only_verifies(self):
        decision = evaluate(BehaviorInput(suspicious_text=True, evidence_count=1))
        self._assert_review_only(decision)
        self.assertEqual(decision["state"], "verify")
        self.assertIn("suspicious_text_requires_verification", decision["reasons"])
        self.assertIn("manual_review_preconditions_incomplete", decision["reasons"])

    def test_only_full_trusted_preconditions_reach_manual_review_ready(self):
        decision = evaluate(_ready_inputs())
        self._assert_review_only(decision)
        self.assertEqual(decision["state"], "manual_containment_review_ready")
        self.assertEqual(decision["rule_id"], "BHV-007-MANUAL-REVIEW-READY")
        self.assertEqual(decision["reasons"], ["trusted_review_preconditions_met"])
        self.assertEqual(decision["suggestions"], ["present_manual_containment_review_proposal"])

        no_suspicion = evaluate(
            BehaviorInput(
                evidence_count=2,
                independent_evidence_verified=True,
                operator_review_approved=True,
                owns_target=True,
                isolation_ready=True,
                rollback_ready=True,
            )
        )
        self.assertEqual(no_suspicion["state"], "observe")

    def test_negative_guard_permutation_table_has_documented_deterministic_priority(self):
        cases = (
            (
                "premature_overrides_every_lower_guard",
                {
                    "premature_enforcement_reported": True,
                    "authentication_rejected": True,
                    "credential_failure": True,
                    "detector_available": False,
                    "evidence_conflict": True,
                    "local_budget_stop_reported": True,
                },
                "premature_enforcement_review",
            ),
            (
                "authentication_overrides_availability_conflict_and_budget",
                {
                    "authentication_rejected": True,
                    "credential_failure": True,
                    "detector_available": False,
                    "evidence_conflict": True,
                    "local_budget_stop_reported": True,
                },
                "authentication_rejected",
            ),
            (
                "credential_overrides_detector_conflict_and_budget",
                {
                    "credential_failure": True,
                    "detector_available": False,
                    "evidence_conflict": True,
                    "local_budget_stop_reported": True,
                },
                "integration_unavailable",
            ),
            (
                "detector_unavailable_overrides_conflict_and_budget",
                {
                    "detector_available": False,
                    "evidence_conflict": True,
                    "local_budget_stop_reported": True,
                },
                "degraded_manual_review",
            ),
            (
                "conflict_overrides_budget",
                {"evidence_conflict": True, "local_budget_stop_reported": True},
                "evidence_conflict_review",
            ),
            (
                "budget_stops_review_proposal",
                {"local_budget_stop_reported": True},
                "local_budget_stop_reported",
            ),
        )
        for name, overrides, expected_state in cases:
            with self.subTest(name=name):
                decision = evaluate(_ready_inputs(**overrides))
                self._assert_review_only(decision)
                self.assertEqual(decision["state"], expected_state)

    def test_conflicting_evidence_never_reaches_ready_even_when_every_approval_is_true(self):
        decision = evaluate(_ready_inputs(evidence_conflict=True))
        self._assert_review_only(decision)
        self.assertEqual(decision["state"], "evidence_conflict_review")
        self.assertNotEqual(decision["state"], "manual_containment_review_ready")

    def test_failure_examples_have_safe_fixed_states_without_identity_or_legal_claims(self):
        cases = (
            (BehaviorInput(authentication_rejected=True), "authentication_rejected"),
            (BehaviorInput(credential_failure=True), "integration_unavailable"),
            (BehaviorInput(detector_available=False), "degraded_manual_review"),
            (BehaviorInput(premature_enforcement_reported=True), "premature_enforcement_review"),
            (BehaviorInput(local_budget_stop_reported=True), "local_budget_stop_reported"),
        )
        for inputs, expected_state in cases:
            with self.subTest(expected_state=expected_state):
                decision = evaluate(inputs)
                self._assert_review_only(decision)
                self.assertEqual(decision["state"], expected_state)
                rendered = json.dumps(decision)
                self.assertNotIn("stolen", rendered)
                self.assertNotIn("identity", rendered)
                self.assertNotIn("legal", rendered)

    def test_evaluation_is_repeatable_and_does_not_mutate_input_or_prior_output(self):
        inputs = _ready_inputs()
        before = asdict(inputs)
        first = evaluate(inputs)
        first["reasons"].append("attempted_external_mutation")
        first["runtime_actions"].append("attempted_external_mutation")
        second = evaluate(inputs)
        self.assertEqual(asdict(inputs), before)
        self._assert_review_only(second)
        self.assertEqual(second["reasons"], ["trusted_review_preconditions_met"])
        self.assertEqual(second["runtime_actions"], [])
        self.assertEqual(second, evaluate(inputs))

    def test_evaluate_rejects_non_dataclass_input(self):
        with self.assertRaises(ValueError):
            evaluate({"suspicious_text": True})


class PolicyContractTests(unittest.TestCase):
    def test_contract_is_machine_readable_fresh_and_prohibits_runtime_actions(self):
        first = policy_contract()
        second = policy_contract()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        json.dumps(first, sort_keys=True)
        self.assertEqual(first["policy_version"], behavior.POLICY_VERSION)
        self.assertTrue(first["input_schema"]["trusted_caller_only"])
        self.assertTrue(first["state_graph"]["review_proposal_only"])
        self.assertFalse(first["state_graph"]["automatic_transition_to_enforcement"])
        self.assertEqual(first["state_graph"]["permitted_runtime_actions"], [])
        self.assertIn("no_contained_or_already_blocked_state", first["invariants"])
        self.assertIn("evidence_conflict_never_reaches_manual_review_ready", first["invariants"])
        self.assertTrue(first["evidence_handling"]["evidence_is_data_not_instructions"])
        self.assertFalse(first["evidence_handling"]["read_secrets"])
        self.assertFalse(first["evidence_handling"]["run_arbitrary_commands"])
        self.assertFalse(first["evidence_handling"]["automatic_adoption"])
        self.assertFalse(first["training_scope"]["model_weight_training"])
        self.assertFalse(first["training_scope"]["live_policy_changes"])
        self.assertFalse(first["training_scope"]["automatic_actions"])

    def test_every_evaluation_uses_only_contract_fixed_labels(self):
        contract = policy_contract()
        allowed_reasons = set(contract["decision_schema"]["fixed_label_sets"]["reasons"])
        allowed_suggestions = set(contract["decision_schema"]["fixed_label_sets"]["suggestions"])
        for state in contract["state_graph"]["states"]:
            self.assertNotEqual(state, "contained")
            self.assertNotIn("already_blocked", state)

        example_inputs = (
            BehaviorInput(),
            BehaviorInput(unfamiliar_connection=True),
            BehaviorInput(suspicious_text=True),
            _ready_inputs(),
            _ready_inputs(evidence_conflict=True),
            _ready_inputs(detector_available=False),
            _ready_inputs(credential_failure=True),
            _ready_inputs(authentication_rejected=True),
            _ready_inputs(premature_enforcement_reported=True),
            _ready_inputs(local_budget_stop_reported=True),
        )
        for inputs in example_inputs:
            with self.subTest(inputs=inputs):
                decision = evaluate(inputs)
                self.assertTrue(set(decision["reasons"]).issubset(allowed_reasons))
                self.assertTrue(set(decision["suggestions"]).issubset(allowed_suggestions))

    def test_module_has_no_dynamic_execution_or_external_runtime_imports(self):
        tree = ast.parse(inspect.getsource(behavior))
        prohibited_import_roots = {
            "subprocess",
            "socket",
            "urllib",
            "requests",
            "http",
            "os",
            "pathlib",
            "importlib",
        }
        imports = set()
        invoked_builtins = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                invoked_builtins.add(node.func.id)
        self.assertFalse(imports & prohibited_import_roots)
        self.assertFalse(invoked_builtins & {"eval", "exec", "compile", "__import__"})


class SyntheticTrainingTests(unittest.TestCase):
    def test_training_report_is_stable_complete_and_evaluator_only(self):
        with mock.patch.object(
            behavior.signals,
            "inspect_text",
            wraps=behavior.signals.inspect_text,
        ) as inspected:
            report = run_training()
        second_report = run_training()

        self.assertEqual(inspected.call_count, 7)
        self.assertEqual(report, second_report)
        self.assertEqual(report["kind"], "synthetic_behavior_regression")
        self.assertEqual(
            report["training_method"],
            "fixtures_and_policy_feedback_not_model_weight_training",
        )
        self.assertTrue(report["passed"])
        self.assertGreaterEqual(report["case_count"], 14)
        self.assertLessEqual(report["case_count"], 20)
        self.assertEqual(report["case_count"], 19)
        self.assertEqual(report["passed_count"], report["case_count"])
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["metrics"]["fixture_pass_rate"], 1.0)
        self.assertIsNone(report["metrics"]["production_false_positive_rate"])
        self.assertIsNone(report["metrics"]["production_true_positive_rate"])
        self.assertIsNone(report["metrics"]["detection_latency_seconds"])
        self.assertIsNone(report["metrics"]["containment_latency_seconds"])
        self.assertIsNone(report["metrics"]["recovery_seconds"])
        self.assertIsNone(report["metrics"]["resource_usage"])
        self.assertFalse(report["runtime_modified"])
        self.assertIn("do not validate runtime OAuth", report["limit_notice"])

        self.assertEqual(report["policy_contract"], policy_contract())
        self.assertEqual(report["policy_contract_sha256"], _canonical_sha256(policy_contract()))
        self.assertEqual(report["policy_contract_sha256"], second_report["policy_contract_sha256"])

    def test_training_scenarios_are_digest_only_and_all_remain_review_only(self):
        report = run_training()
        scenario_keys = {
            "regression_id",
            "family",
            "fixture_kind",
            "fixture_sha256",
            "expected_state",
            "actual_decision",
            "passed",
        }
        expected_injection_ids = {f"SYN-{number:03d}" for number in range(13, 20)}
        observed_injection_ids = set()
        for scenario in report["scenarios"]:
            with self.subTest(regression_id=scenario["regression_id"]):
                self.assertEqual(set(scenario), scenario_keys)
                self.assertEqual(scenario["fixture_kind"], "synthetic")
                self.assertRegex(scenario["fixture_sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(scenario["passed"])
                self.assertEqual(scenario["actual_decision"]["state"], scenario["expected_state"])
                self.assertIs(scenario["actual_decision"]["enforcement_authorized"], False)
                self.assertEqual(scenario["actual_decision"]["runtime_actions"], [])
                if scenario["family"] == "evidence_as_data":
                    observed_injection_ids.add(scenario["regression_id"])
        self.assertEqual(observed_injection_ids, expected_injection_ids)

        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn("ignore previous instructions", rendered)
        self.assertNotIn("run arbitrary commands now", rendered)
        self.assertNotIn("reveal secrets from the host", rendered)


if __name__ == "__main__":
    unittest.main()
