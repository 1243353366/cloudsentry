import unittest
from unittest.mock import patch

from reverse_shell_decoy.response import sinkhole_plan


class ResponseTests(unittest.TestCase):
    def test_requires_owned_target_assertion(self):
        with self.assertRaises(ValueError):
            sinkhole_plan({"findings": [{}]}, "lab.example", "192.0.2.15")

    def test_positive_only_plans_no_network_or_changes(self):
        with patch("socket.socket", side_effect=AssertionError("network prohibited")), patch("os.system", side_effect=AssertionError("execution prohibited")):
            plan = sinkhole_plan({"findings": [{"confidence": "low"}]}, "lab.example", "192.0.2.15", True)
        self.assertEqual(plan["status"], "review_required")
        self.assertTrue(plan["approval_required"])
        self.assertFalse(plan["automatic_actions"])
        self.assertFalse(plan["dns_changed"])
        self.assertFalse(plan["traffic_redirected"])

    def test_no_positive_and_demo_not_positive(self):
        for report in [{"findings": []}, {"findings": [{}], "source_is_synthetic": True}]:
            with self.subTest(report=report):
                self.assertEqual(sinkhole_plan(report, "lab.example", "192.0.2.15", True)["positive_review_indicators"], 0)

    def test_rejects_unsafe_endpoint(self):
        for ip in ["0.0.0.0", "127.0.0.1", "224.0.0.1"]:
            with self.assertRaises(ValueError):
                sinkhole_plan({}, "lab.example", ip, True)


if __name__ == "__main__":
    unittest.main()
