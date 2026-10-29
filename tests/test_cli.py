import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.cli import main, new_private_file, read_audit


class CLITests(unittest.TestCase):
    def test_realistic_still_informs_operator_and_labels_audit(self):
        with tempfile.TemporaryDirectory() as td:
            log = str(Path(td) / "audit.jsonl")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.stdin", io.StringIO("whoami\nexit\n")), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["simulate", "--presentation", "realistic", "--audit", log]), 0)
            self.assertIn("ROOT ACCESS GRANTED", stdout.getvalue())
            self.assertIn("Operator notice", stderr.getvalue())
            events = read_audit(log)
            self.assertEqual(len(events), 2)
            self.assertTrue(all(e["simulation"] for e in events))
            if os.name == "posix":
                self.assertEqual(Path(log).stat().st_mode & 0o777, 0o600)

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "audit.jsonl")
            with new_private_file(path) as f:
                f.write("original")
            with self.assertRaises(FileExistsError):
                new_private_file(path)
            self.assertEqual(Path(path).read_text(), "original")

    def test_refuses_non_simulation_audit(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "input.jsonl"
            path.write_text(json.dumps({"simulation": False}) + "\n")
            with self.assertRaises(ValueError):
                read_audit(str(path))

    def test_no_automatic_audit_collection(self):
        self.assertEqual(read_audit(None), [])

    def test_experiment_cli_json(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["experiment", "telemetry-gap", "--seed", "42"]), 0)
        self.assertTrue(json.loads(out.getvalue())["simulation"])


if __name__ == "__main__":
    unittest.main()
