import unittest
from unittest.mock import patch

from reverse_shell_decoy.correlation import audit_host


class CorrelationTests(unittest.TestCase):
    def test_host_and_imported_origins_are_separate(self):
        imported = {"source_kind": "imported_real_log", "simulation": False, "records": []}
        name_check = {"findings": [], "simulation": False}
        with patch("reverse_shell_decoy.correlation.scan", return_value={"findings": []}), \
             patch("reverse_shell_decoy.correlation.os_info", return_value={"system": "Linux"}), \
             patch("reverse_shell_decoy.correlation.scan_listeners", return_value={"listeners": []}), \
             patch("reverse_shell_decoy.correlation.scan_persistence", return_value={"findings": []}):
            report = audit_host(imported, name_check)
        self.assertIs(report["imported_logs"], imported)
        self.assertIs(report["offline_name_checks"], name_check)
        self.assertEqual(report["host_observations"]["host_os"]["system"], "Linux")
        self.assertFalse(report["host_observations"]["shell_connections"]["simulation"])
        self.assertIn("not necessarily", report["provenance_notice"])
        self.assertIn("No result establishes compromise", report["assessment"])


if __name__ == "__main__":
    unittest.main()
