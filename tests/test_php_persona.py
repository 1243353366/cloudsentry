import unittest
from unittest.mock import patch

from reverse_shell_decoy.signals import inspect_text
from reverse_shell_decoy.simulator import DecoySession


class PhpPersonaTests(unittest.TestCase):
    def test_php_is_first_in_virtual_catalog_without_host_lookup(self):
        session = DecoySession(presentation="realistic")
        with patch("os.system", side_effect=AssertionError("host execution prohibited")), patch("subprocess.Popen", side_effect=AssertionError("interpreter prohibited")), patch("socket.socket", side_effect=AssertionError("outbound socket prohibited")):
            self.assertIn("Runtime catalog: PHP", session.banner)
            self.assertEqual(session.execute("which nc python3 php").splitlines()[0], "/usr/bin/php")
            self.assertIn("PHP 8.2.13", session.execute("php -v"))
            self.assertIn("Core", session.execute("php -m"))
        self.assertTrue(all(event["simulation"] for event in session.events))
        self.assertTrue(all(not event["blocked"] for event in session.events))

    def test_execution_flags_are_blocked_but_language_is_a_text_indicator(self):
        session = DecoySession()
        for text in ["php -r 'NONEXECUTABLE-TEST-MARKER'", "php synthetic.php", "php -f synthetic.php", "python3 synthetic.py"]:
            with self.subTest(text=text):
                session.execute(text)
                self.assertTrue(session.events[-1]["blocked"])
                self.assertNotIn(text, str(session.events))
                self.assertIn(session.events[-1]["language_indicator"], {"php", "python"})

    def test_tokens_and_aliases_are_fixed_identifiers_not_payloads(self):
        result = inspect_text("php COMMENT-ONLY fsockopen stream_set_blocking proc_open KEEP-THIS-SECRET-OUT")
        self.assertEqual(result["language_indicator"], "php")
        self.assertEqual(set(result["token_indicators"]), {"php_network_api", "php_stream_api", "process_api"})
        self.assertNotIn("KEEP-THIS-SECRET-OUT", str(result))
        self.assertIn("not execution/skill/authorization", result["indicator_scope"])
        self.assertEqual(inspect_text("/usr/bin/python3 COMMENT-ONLY")["language_indicator"], "python")
        self.assertEqual(inspect_text("echo php")["language_indicator"], "unknown")

    def test_signals_ignore_oversize_tail(self):
        text = "x" * 4096 + " fsockopen proc_open"
        self.assertEqual(inspect_text(text)["token_indicators"], [])


if __name__ == "__main__":
    unittest.main()
