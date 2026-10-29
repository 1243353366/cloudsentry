"""Tests for offline, low-confidence name similarity checks."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.typosquat import check_names


class TyposquatTests(unittest.TestCase):
    def test_exact_and_legitimate_subdomain_are_not_flagged(self) -> None:
        result = check_names(
            ["example.com", "Example.COM", "api.example.com"],
            ["example.com"],
            kind="domain",
        )

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["checked_count"], 3)
        self.assertFalse(result["simulation"])

    def test_adjacent_transposition_is_low_confidence_near_match(self) -> None:
        result = check_names(["exmaple.com"], ["example.com"], kind="domain")

        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["reason"], "near_trusted_name")
        self.assertEqual(finding["distance"], 1)
        self.assertEqual(finding["confidence"], "low")
        self.assertFalse(finding["simulation"])

    def test_unicode_and_punycode_lookalikes_are_cues_not_proof(self) -> None:
        unicode_lookalike = "\u0440\u0430ypal.com"  # Cyrillic p/a followed by "ypal.com"
        result = check_names([unicode_lookalike], ["paypal.com"], kind="domain")

        self.assertEqual(result["findings"][0]["reason"], "unicode_lookalike")
        self.assertEqual(result["findings"][0]["confidence"], "low")
        self.assertTrue(any("not proof" in limitation for limitation in result["limitations"]))
        self.assertTrue(any("IDNA" in limitation for limitation in result["limitations"]))

    def test_deceptive_suffix_uses_true_label_boundary_only(self) -> None:
        result = check_names(
            ["example.com.evil.test", "notexample.com"], ["example.com"], kind="domain"
        )

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["observed"], "example.com.evil.test")
        self.assertEqual(result["findings"][0]["reason"], "brand_boundary_mismatch")

    def test_benign_package_separator_normalization_is_a_warning_not_a_finding(self) -> None:
        result = check_names(["my_package"], ["my.package"], kind="package")

        self.assertEqual(result["findings"], [])
        self.assertTrue(any("normalization collision" in warning for warning in result["warnings"]))

    def test_pair_comparison_budget_marks_result_incomplete(self) -> None:
        # 101 x 100 would otherwise require more than the explicit 10,000-pair
        # budget.  The result must not look exhaustive when it stops early.
        observed = [f"observed-package-{index}" for index in range(101)]
        trusted = [f"trusted-package-{index}" for index in range(100)]

        result = check_names(observed, trusted, kind="package")

        self.assertEqual(result["checked_count"], 101)
        self.assertEqual(result["compared_pairs"], 10_000)
        self.assertFalse(result["complete"])
        self.assertTrue(any("incomplete" in warning.lower() for warning in result["warnings"]))

    def test_bounds_and_input_types_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "1000"):
            check_names(["a"] * 1001, [], kind="domain")
        with self.assertRaisesRegex(ValueError, "maximum"):
            check_names(["a" * 254], [], kind="domain")
        with self.assertRaisesRegex(ValueError, "maximum"):
            check_names(["a" * 129], [], kind="package")
        with self.assertRaisesRegex(TypeError, "list"):
            check_names("example.com", ["example.com"], kind="domain")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
