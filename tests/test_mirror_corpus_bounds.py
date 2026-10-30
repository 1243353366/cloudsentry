import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from reverse_shell_decoy.mirror_regression import CorpusValidationError, load_corpus


class CorpusDepthRegressionTests(unittest.TestCase):
    def test_excessively_nested_json_fails_cleanly_before_network(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "nested.jsonl"
            path.write_text('{"text":' + '[' * 1500 + '0' + ']' * 1500 + '}\n')
            with patch("asyncio.start_server", side_effect=AssertionError("must not bind")):
                with self.assertRaises(CorpusValidationError):
                    load_corpus(path)


if __name__ == "__main__":
    unittest.main()
