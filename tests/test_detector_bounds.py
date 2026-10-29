import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.detector import scan


class DetectorBoundsTests(unittest.TestCase):
    def make_proc(self, td, rows):
        net = Path(td) / "net"
        net.mkdir()
        (net / "tcp").write_text("header\n" + rows)
        (net / "tcp6").write_text("header\n")

    def test_listen_is_not_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_proc(td, "0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42\n")
            result = scan(td)
            self.assertEqual(result["warnings"], [])
            self.assertEqual(result["examined_connections"], 0)

    def test_row_bound_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_proc(td, "\n\n\n")
            with patch("reverse_shell_decoy.detector.MAX_TCP_ROWS", 1):
                result = scan(td)
            self.assertTrue(any("limit" in w for w in result["warnings"]))

    def test_line_bound_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_proc(td, "x" * 5000 + "\n")
            result = scan(td)
            self.assertTrue(any("limit" in w for w in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
