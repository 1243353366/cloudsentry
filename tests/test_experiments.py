"""Tests for the safe in-memory synthetic experiment scenarios."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.experiments import SCENARIO_NAMES, run_scenario


class RunScenarioTests(unittest.TestCase):
    def test_results_are_deterministic_for_a_seed(self) -> None:
        self.assertEqual(
            run_scenario("network-loss", seed=41),
            run_scenario("network-loss", seed=41),
        )
        self.assertNotEqual(
            run_scenario("network-loss", seed=41)["observer"],
            run_scenario("network-loss", seed=42)["observer"],
        )

    def test_all_scenarios_are_bounded_to_thirty_virtual_steps(self) -> None:
        expected_steps = list(range(1, 31))
        for scenario in SCENARIO_NAMES:
            with self.subTest(scenario=scenario):
                result = run_scenario(scenario, seed=3)
                self.assertTrue(result["simulation"])
                self.assertTrue(result["summary"]["simulation"])
                self.assertTrue(result["metadata"]["simulation"])
                self.assertEqual(result["virtual_step_count"], 30)
                self.assertEqual([event["step"] for event in result["observer"]], expected_steps)
                self.assertEqual(len(result["observer"]), 30)
                self.assertTrue(all(event["simulation"] for event in result["observer"]))
                self.assertTrue(all(event["simulation"] for event in result["sensor"]))

    def test_observer_preserves_every_step_when_sensor_is_degraded(self) -> None:
        for scenario in ("network-loss", "telemetry-gap"):
            with self.subTest(scenario=scenario):
                result = run_scenario(scenario, seed=7)
                observer_steps = {event["step"] for event in result["observer"]}
                sensor_source_ids = {event["source_event_id"] for event in result["sensor"]}
                self.assertEqual(observer_steps, set(range(1, 31)))
                self.assertTrue(
                    sensor_source_ids.issubset(
                        {event["event_id"] for event in result["observer"]}
                    )
                )

    def test_telemetry_gap_reports_fake_misses_and_warning(self) -> None:
        result = run_scenario("telemetry-gap")
        sensor_steps = {event["step"] for event in result["sensor"]}

        self.assertEqual(result["summary"]["fake_telemetry_missed_count"], 6)
        self.assertEqual(sensor_steps, set(range(1, 31)) - set(range(10, 16)))
        self.assertEqual(len(result["observer"]), 30)
        self.assertEqual(result["metadata"]["telemetry_gap_start_step"], 10)
        self.assertEqual(result["metadata"]["telemetry_gap_end_step"], 15)
        self.assertIn("intentionally omits virtual steps 10..15", result["metadata"]["sensor_warning"])

    def test_baseline_is_complete_and_has_no_synthetic_loss(self) -> None:
        result = run_scenario("baseline")

        self.assertEqual(len(result["observer"]), 30)
        self.assertEqual(len(result["sensor"]), 30)
        self.assertEqual(result["summary"]["delivery_count"], 30)
        self.assertEqual(result["summary"]["drop_count"], 0)
        self.assertEqual(result["summary"]["virtual_process_denied_count"], 0)
        self.assertEqual(result["summary"]["fake_telemetry_missed_count"], 0)
        self.assertEqual(
            result["limitations"],
            "Does not generate or suppress real OS/EDR events.",
        )

    def test_process_limit_is_virtual_and_never_exceeds_three(self) -> None:
        result = run_scenario("process-limit")
        process_counts = [event["virtual_process_count"] for event in result["observer"]]

        self.assertLessEqual(max(process_counts), 3)
        self.assertGreater(result["summary"]["virtual_process_denied_count"], 0)
        self.assertTrue(
            any(event.get("result") == "denied" for event in result["observer"])
        )

    def test_network_loss_is_a_seeded_roughly_thirty_five_percent_loss(self) -> None:
        result = run_scenario("network-loss", seed=0)

        self.assertEqual(len(result["observer"]), 30)
        self.assertEqual(result["summary"]["drop_count"], 10)
        self.assertEqual(result["summary"]["delivery_count"], 20)
        self.assertEqual(len(result["sensor"]), 20)

    def test_invalid_scenario_name_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            run_scenario("not-a-scenario")
        with self.assertRaises(ValueError):
            run_scenario("")

    def test_result_is_json_serializable(self) -> None:
        serialized = json.dumps(run_scenario("telemetry-gap", seed=9), sort_keys=True)
        self.assertIn('"simulation": true', serialized)


if __name__ == "__main__":
    unittest.main()
