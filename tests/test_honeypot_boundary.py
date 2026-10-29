import contextlib
import io
import unittest
from unittest.mock import patch

from reverse_shell_decoy.honeypot import DecoyServer, main


class HoneypotBoundaryTests(unittest.TestCase):
    def test_service_refuses_known_cloud_credentials(self):
        stderr = io.StringIO()
        with patch.dict("os.environ", {"CLOUDFLARE_API_TOKEN": "NEVER-ECHO-THIS"}, clear=True), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as result:
                main([])
        self.assertEqual(result.exception.code, 2)
        self.assertIn("credential-bearing environment refused", stderr.getvalue())
        self.assertNotIn("NEVER-ECHO-THIS", stderr.getvalue())

    def test_operator_audit_loss_stops_session_work(self):
        service = DecoyServer()
        with patch("sys.stderr.write", side_effect=OSError("sink failure")):
            ok = service._audit_event("connecting", "test-session", "127.0.0.1")
        self.assertFalse(ok)
        self.assertTrue(service._shutdown_requested)
        self.assertEqual(service._shutdown_reason, "operator_audit_failure")


if __name__ == "__main__":
    unittest.main()
