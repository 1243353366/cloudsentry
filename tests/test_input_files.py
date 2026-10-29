import os
from pathlib import Path
import tempfile
import unittest

from reverse_shell_decoy.input_files import read_regular


class InputFileTests(unittest.TestCase):
    def test_bounded_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "input"
            path.write_bytes(b"abc")
            self.assertEqual(read_regular(str(path), 3), b"abc")
            with self.assertRaises(ValueError):
                read_regular(str(path), 2)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "file"
            file.write_bytes(b"abc")
            link = Path(td) / "link"
            link.symlink_to(file)
            with self.assertRaises(ValueError):
                read_regular(str(link), 100)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fifo"
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                read_regular(str(path), 100)


if __name__ == "__main__":
    unittest.main()
