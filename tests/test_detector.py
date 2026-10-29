"""Fixture tests for reverse_shell_decoy.detector using a fake read-only procfs."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy import detector


TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   "
    "uid  timeout inode\n"
)


def tcp_row(local: str, remote: str, state: str, inode: int) -> str:
    return (
        "   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 "
        "1000 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    ).format(local=local, remote=remote, state=state, inode=inode)


class DetectorFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.proc = Path(self.temporary_directory.name)
        (self.proc / "net").mkdir()
        self.write_tcp4([])
        self.write_tcp6([])

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_tcp4(self, rows) -> None:
        (self.proc / "net" / "tcp").write_text(TCP_HEADER + "".join(rows), encoding="ascii")

    def write_tcp6(self, rows) -> None:
        (self.proc / "net" / "tcp6").write_text(TCP_HEADER + "".join(rows), encoding="ascii")

    def add_process(self, pid: int, comm: str, parent: int, socket_inodes=()) -> None:
        process = self.proc / str(pid)
        fd_directory = process / "fd"
        fd_directory.mkdir(parents=True)
        (process / "comm").write_text(comm + "\n", encoding="utf-8")
        (process / "status").write_text(
            "Name:\t%s\nPPid:\t%d\n" % (comm, parent), encoding="utf-8"
        )
        for descriptor, inode in enumerate(socket_inodes):
            os.symlink("socket:[%d]" % inode, fd_directory / str(descriptor))

    def test_ipv4_established_shell_socket_is_reported_without_cmdline(self) -> None:
        self.write_tcp4(
            [tcp_row("0100000A:9C40", "08080808:01BB", "01", 4242)]
        )
        self.add_process(101, "bash", 1, [4242])
        self.add_process(1, "init", 0)
        # A cmdline fixture exists but the detector must neither read nor emit it.
        (self.proc / "101" / "cmdline").write_text("bash\x00-secret\x00", encoding="utf-8")

        result = detector.scan(str(self.proc))

        self.assertEqual(result["examined_connections"], 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["pid"], 101)
        self.assertEqual(finding["comm"], "bash")
        self.assertEqual(finding["local_address"], "10.0.0.1")
        self.assertEqual(finding["local_port"], 40000)
        self.assertEqual(finding["remote_address"], "8.8.8.8")
        self.assertEqual(finding["remote_port"], 443)
        self.assertEqual(finding["direction"], "unknown")
        self.assertEqual(finding["confidence"], "medium")
        self.assertNotIn("secret", repr(result))
        self.assertEqual(
            set(finding),
            {
                "pid", "parent_names", "comm", "local_address", "local_port",
                "remote_address", "remote_port", "reason", "severity",
                "confidence", "direction",
            },
        )

    def test_ipv6_established_shell_socket_decodes_linux_word_endianness(self) -> None:
        # 2001:db8::1 and 2001:4860:4860::8888 encoded as /proc/net/tcp6 u32 words.
        self.write_tcp6(
            [
                tcp_row(
                    "B80D0120000000000000000001000000:C001",
                    "60480120000060480000000088880000:0050",
                    "01",
                    8080,
                )
            ]
        )
        self.add_process(102, "zsh", 1, [8080])
        self.add_process(1, "init", 0)

        result = detector.scan(str(self.proc))

        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["local_address"], "2001:db8::1")
        self.assertEqual(finding["local_port"], 49153)
        self.assertEqual(finding["remote_address"], "2001:4860:4860::8888")
        self.assertEqual(finding["remote_port"], 80)

    def test_loopback_peer_is_filtered_even_for_shell(self) -> None:
        self.write_tcp4(
            [tcp_row("0100007F:1770", "0100007F:1771", "01", 5050)]
        )
        self.add_process(103, "sh", 1, [5050])
        self.add_process(1, "init", 0)

        result = detector.scan(str(self.proc))

        self.assertEqual(result["examined_connections"], 1)
        self.assertEqual(result["findings"], [])

    def test_intermediary_process_with_shell_ancestor_is_low_confidence(self) -> None:
        self.write_tcp4(
            [tcp_row("0200000A:C350", "09090909:01BB", "01", 6000)]
        )
        self.add_process(201, "curl", 200, [6000])
        self.add_process(200, "bash", 1)
        self.add_process(1, "init", 0)

        result = detector.scan(str(self.proc))

        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["pid"], 201)
        self.assertEqual(finding["comm"], "curl")
        self.assertIn("bash", finding["parent_names"])
        self.assertEqual(finding["confidence"], "low")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["direction"], "unknown")

    def test_unrelated_benign_process_is_not_reported(self) -> None:
        self.write_tcp4(
            [tcp_row("0300000A:9C40", "04040404:0035", "01", 7000)]
        )
        self.add_process(301, "systemd-resolved", 1, [7000])
        self.add_process(1, "init", 0)

        result = detector.scan(str(self.proc))

        self.assertEqual(result["examined_connections"], 1)
        self.assertEqual(result["findings"], [])

    def test_permission_denied_fd_visibility_becomes_warning_not_failure(self) -> None:
        self.write_tcp4(
            [tcp_row("0400000A:9C40", "01010101:01BB", "01", 9000)]
        )
        self.add_process(401, "bash", 1, [9000])
        self.add_process(1, "init", 0)
        denied_path = str(self.proc / "401" / "fd")
        original_scandir = detector.os.scandir

        def guarded_scandir(path):
            if os.fspath(path) == denied_path:
                raise PermissionError("fixture visibility denial")
            return original_scandir(path)

        with mock.patch.object(detector.os, "scandir", side_effect=guarded_scandir):
            result = detector.scan(str(self.proc))

        self.assertEqual(result["findings"], [])
        self.assertIn(
            "permission denied while reading process file descriptors",
            result["warnings"],
        )
        self.assertIn("Heuristic, read-only procfs snapshot", result["limitation_notice"])

    def test_missing_network_files_are_graceful(self) -> None:
        (self.proc / "net" / "tcp").unlink()
        (self.proc / "net" / "tcp6").unlink()

        result = detector.scan(str(self.proc))

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["examined_connections"], 0)
        self.assertIn("IPv4 TCP snapshot is unavailable", result["warnings"])
        self.assertIn("IPv6 TCP snapshot is unavailable", result["warnings"])


if __name__ == "__main__":
    unittest.main()
