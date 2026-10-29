import contextlib
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from reverse_shell_decoy.shellception import DefensiveLoop, main


class StateExportTests(unittest.TestCase):
    def test_state_is_explicitly_synthetic_and_digest_verifiable(self):
        loop = DefensiveLoop()
        loop.session.execute("touch /tmp/synthetic-file")
        loop.step()
        state = loop.export_state()
        material = {key: state[key] for key in ("files", "directories", "cwd")}
        expected = sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(state["state_sha256"], expected)
        self.assertTrue(state["simulation"])
        self.assertEqual(state["state_kind"], "synthetic_virtual_filesystem")
        state["files"]["/tmp/changed-copy"] = "synthetic"
        self.assertNotIn("/tmp/changed-copy", loop.session.files)

    def test_no_watched_file_content_or_actual_path_enters_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "real-input.txt"
            path.write_text("DO-NOT-EXPORT-THIS-WATCHED-CONTENT")
            loop = DefensiveLoop(watch_files=[str(path)])
            rendered = json.dumps(loop.export_state())
            self.assertNotIn("DO-NOT-EXPORT-THIS-WATCHED-CONTENT", rendered)
            self.assertNotIn(str(path), rendered)

    def test_explicit_new_output_private_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "synthetic-state.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--demo", "--iterations", "1", "--interval", "0", "--max-runtime", "1", "--state-output", str(path)]), 0)
            state = json.loads(path.read_text())
            self.assertTrue(state["simulation"])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--iterations", "1", "--interval", "0", "--state-output", str(path)]), 2)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
