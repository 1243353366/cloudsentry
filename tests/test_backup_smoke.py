import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from reverse_shell_decoy.backup_smoke import negative_control_results, validate_layer_results


class BackupSmokeTests(unittest.TestCase):
    def test_all_mutated_result_negative_controls_are_rejected(self):
        controls = negative_control_results()
        self.assertGreaterEqual(len(controls), 12)
        self.assertTrue(all(controls.values()))

    def test_no_truthy_string_empty_or_duplicated_result_passes(self):
        for value in (None, {}, "passed", True, [], [{"passed": True}]):
            with self.subTest(value=value):
                self.assertFalse(validate_layer_results(value))

    def test_runner_itself_catches_a_deliberately_failing_case(self):
        path = Path(__file__).resolve().parents[1] / "scripts" / "smoke-backup-layers.py"
        spec = importlib.util.spec_from_file_location("backup_smoke_script_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(module.failing_runner_control())

    def test_no_permission_prevents_any_test_file_read_or_runner(self):
        path = Path(__file__).resolve().parents[1] / "scripts" / "smoke-backup-layers.py"
        spec = importlib.util.spec_from_file_location("backup_smoke_script_test_gate", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, "request_authorization", return_value=None), \
                patch.object(module, "run_tests", side_effect=AssertionError("no test runner")), \
                patch.object(module.Path, "read_bytes", side_effect=AssertionError("no source read")), \
                patch("sys.stderr"):
            self.assertEqual(module.main([]), 2)


if __name__ == "__main__":
    unittest.main()
