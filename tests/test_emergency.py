import contextlib
import io
import unittest
from unittest.mock import patch

from reverse_shell_decoy.emergency import build_emergency_arguments, main
from reverse_shell_decoy.honeypot import _parser


class EmergencyProfileTests(unittest.TestCase):
    def test_profile_is_silent_finite_small_and_loopback_only_by_default(self):
        args = _parser().parse_args(build_emergency_arguments([]))
        self.assertEqual(args.host, "127.0.0.1")
        self.assertFalse(args.allow_public)
        self.assertEqual(args.response_mode, "sink")
        self.assertEqual(args.max_runtime, 30)
        self.assertEqual(args.max_sessions, 1)
        self.assertEqual(args.max_sessions_total, 2)
        self.assertEqual(args.max_commands, 4)
        self.assertEqual(args.idle_timeout, 2)
        self.assertEqual(args.session_timeout, 5)
        self.assertEqual(args.audit_limit, 40)
        self.assertEqual(args.max_input_bytes_total, 1024)
        self.assertEqual(args.max_output_bytes_total, 1)
        self.assertEqual(args.max_session_input_bytes, 256)
        self.assertEqual(args.commands_per_second, 1)

    def test_operator_can_select_port_and_explicit_exposure_without_raising_limits(self):
        args = _parser().parse_args(build_emergency_arguments(["--host", "0.0.0.0", "--port", "8023", "--allow-public"]))
        self.assertEqual(args.port, 8023)
        self.assertTrue(args.allow_public)
        self.assertEqual(args.max_runtime, 30)
        with contextlib.redirect_stderr(io.StringIO()):
            for extra in (["--response-mode", "console"], ["--max-runtime", "3600"], ["--port", "0"]):
                with self.assertRaises(SystemExit):
                    build_emergency_arguments(extra)

    def test_manual_entry_only_delegates_fixed_arguments_without_auto_response(self):
        with patch("reverse_shell_decoy.honeypot.main", return_value=0) as serve:
            self.assertEqual(main(["--port", "8023"]), 0)
        serve.assert_called_once_with(build_emergency_arguments(["--port", "8023"]))


if __name__ == "__main__":
    unittest.main()
