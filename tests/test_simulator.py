import hashlib
import json
import unittest
from unittest.mock import patch

from reverse_shell_decoy.simulator import DecoySession, MAX_COMMANDS, MAX_FILES, MAX_INPUT, display_safe


class SimulatorTests(unittest.TestCase):
    def test_root_is_only_virtual(self):
        s = DecoySession()
        self.assertIn("synthetic persona", s.banner)
        self.assertEqual(s.execute("whoami"), "root\n")
        self.assertTrue(s.events[-1]["simulation"])

    def test_windows_and_realistic_presentation(self):
        s = DecoySession("windows", "realistic")
        self.assertNotIn("DECOY", s.banner)
        self.assertNotIn("SIMULAT", s.banner)
        self.assertIn("ADMINISTRATOR ACCESS GRANTED", s.banner)
        self.assertEqual(s.execute("whoami"), "SRV-MAINT-02\\Administrator\n")
        self.assertEqual(s.events[-1]["presentation"], "realistic")
        self.assertTrue(s.events[-1]["simulation"])

    def test_virtual_files_never_read_host(self):
        s = DecoySession()
        with patch("builtins.open", side_effect=AssertionError("host file access")), \
             patch("os.system", side_effect=AssertionError("execution")), \
             patch("subprocess.Popen", side_effect=AssertionError("execution")), \
             patch("socket.socket", side_effect=AssertionError("network")):
            self.assertIn("SYNTHETIC", s.execute("cat credentials.txt"))
            self.assertIn("not found", s.execute("cat /etc/passwd"))
            s.execute("touch local.txt")
            self.assertIn("local.txt", s.execute("ls"))
            s.execute("rm local.txt")
            self.assertNotIn("/root/local.txt", s.files)

    def test_operators_and_arbitrary_programs_blocked(self):
        s = DecoySession()
        for cmd in ["id; whoami", "echo $(whoami)", "echo `id`", "echo x > /etc/passwd", "python payload.py", "bash payload.sh", "id\nwhoami", "echo \x1b[31m"]:
            with self.subTest(cmd=cmd):
                self.assertIn("blocked", s.execute(cmd))
                self.assertTrue(s.events[-1]["blocked"])

    def test_audit_redacts_input_and_output(self):
        s = DecoySession()
        command = "echo sensitive-placeholder-123"
        s.execute(command)
        serialized = json.dumps(s.events)
        self.assertNotIn("sensitive-placeholder-123", serialized)
        self.assertEqual(s.events[0]["input_sha256"], hashlib.sha256(command.encode()).hexdigest())
        self.assertIn("timestamp_utc", s.events[0])

    def test_virtual_path_normalization(self):
        s = DecoySession()
        s.execute("cd ../../etc")
        self.assertEqual(s.cwd, "/etc")
        self.assertIn("DecoyOS", s.execute("cat /root/../etc/os-release"))

    def test_resource_bounds(self):
        s = DecoySession()
        for i in range(MAX_FILES + 5):
            s.execute(f"touch file-{i}")
        self.assertLessEqual(len(s.files) + len(s.directories), MAX_FILES)
        self.assertIn("blocked", s.execute("a" * (MAX_INPUT + 1)))
        s = DecoySession()
        for _ in range(MAX_COMMANDS + 2):
            s.execute("id")
        self.assertLessEqual(len(s.events), MAX_COMMANDS)
        self.assertTrue(s.closed)

    def test_terminal_control_escaping(self):
        self.assertEqual(display_safe("a\x07b\x1bc\n"), "a\\x07b\\x1bc\n")
        s = DecoySession()
        self.assertNotIn("\x07", s.execute("echo '\x07'"))

    def test_invalid_options(self):
        with self.assertRaises(ValueError):
            DecoySession("real-host")
        with self.assertRaises(ValueError):
            DecoySession(presentation="unbounded")

    def test_exit(self):
        s = DecoySession()
        s.execute("exit")
        self.assertTrue(s.closed)
        count = len(s.events)
        s.execute("whoami")
        self.assertEqual(len(s.events), count)


if __name__ == "__main__":
    unittest.main()
