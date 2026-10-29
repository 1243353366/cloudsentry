import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.listeners import MAX_COMM_LENGTH, scan_listeners


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def socket_row(local, state, inode, remote="00000000:0000"):
    return (
        "  0: %s %s %s 00000000:00000000 00:00000000 00000000 0 0 %s 1\n"
        % (local, remote, state, inode)
    )


class ListenerTests(unittest.TestCase):
    def make_proc(self, directory, tables=None):
        root = Path(directory)
        net = root / "net"
        net.mkdir(parents=True)
        tables = tables or {}
        for name in ("tcp", "tcp6", "udp", "udp6"):
            (net / name).write_text(HEADER + tables.get(name, ""), encoding="ascii")
        return root

    def add_owner(self, root, pid, comm, *inodes):
        process = root / str(pid)
        fd = process / "fd"
        fd.mkdir(parents=True)
        (process / "comm").write_text(comm + "\n", encoding="utf-8")
        for descriptor, inode in enumerate(inodes):
            # Linux procfs fd entries are symlinks whose link text can be a
            # deliberately dangling socket:[inode] target.
            (fd / str(descriptor)).symlink_to("socket:[%s]" % inode)

    def test_tcp_loopback_wildcard_and_established_are_classified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(
                directory,
                {
                    "tcp": (
                        socket_row("0100007F:1F90", "0A", 41)
                        + socket_row("00000000:0050", "0A", 42)
                        + socket_row("0100007F:2328", "01", 43)
                    )
                },
            )
            result = scan_listeners(str(root))

        self.assertEqual(len(result["listeners"]), 2)
        by_port = {listener["port"]: listener for listener in result["listeners"]}
        self.assertEqual(by_port[8080]["address"], "127.0.0.1")
        self.assertEqual(by_port[8080]["exposure"], "loopback")
        self.assertEqual(by_port[80]["address"], "0.0.0.0")
        self.assertEqual(by_port[80]["exposure"], "wildcard")
        for listener in result["listeners"]:
            self.assertEqual(listener["protocol"], "tcp")
            self.assertEqual(listener["state"], "LISTEN")
            self.assertEqual(listener["direction"], "passive")
            self.assertEqual(listener["owners"], [])
        self.assertEqual(result["findings"], result["listeners"])
        self.assertIsNot(result["findings"], result["listeners"])
        self.assertFalse(result["simulation"])
        self.assertRegex(
            result["observed_at_utc"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$",
        )
        self.assertIn("not malicious", result["limitation_notice"])

    def test_udp_state_07_is_reported_as_bound_not_proven_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(
                directory,
                {
                    "udp": (
                        socket_row("0100000A:0035", "07", 51)
                        + socket_row("00000000:0036", "01", 52)
                    )
                },
            )
            result = scan_listeners(str(root))

        self.assertEqual(len(result["listeners"]), 1)
        listener = result["listeners"][0]
        self.assertEqual(listener["protocol"], "udp")
        self.assertEqual(listener["address"], "10.0.0.1")
        self.assertEqual(listener["port"], 53)
        self.assertEqual(listener["exposure"], "interface")
        self.assertEqual(listener["state"], "UDP-bound")
        self.assertEqual(listener["direction"], "passive")

    def test_ipv6_endpoint_decoder_is_used_for_tcp6_and_udp6(self):
        # The final 32-bit word is little-endian in Linux /proc/net/*6 output,
        # so this encodes ::1 for the existing detector endpoint decoder.
        ipv6_loopback = "00000000000000000000000001000000"
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(
                directory,
                {
                    "tcp6": socket_row(ipv6_loopback + ":01BB", "0A", 61),
                    "udp6": socket_row("00000000000000000000000000000000:0222", "07", 62),
                },
            )
            result = scan_listeners(str(root))

        by_protocol = {listener["protocol"]: listener for listener in result["listeners"]}
        tcp_listener = by_protocol["tcp"]
        udp_listener = by_protocol["udp"]
        self.assertEqual(tcp_listener["family"], "IPv6")
        self.assertEqual(tcp_listener["address"], "::1")
        self.assertEqual(tcp_listener["port"], 443)
        self.assertEqual(tcp_listener["exposure"], "loopback")
        self.assertEqual(udp_listener["family"], "IPv6")
        self.assertEqual(udp_listener["address"], "::")
        self.assertEqual(udp_listener["exposure"], "wildcard")

    def test_fd_symlink_ownership_deduplicates_fds_and_combines_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("00000000:0050", "0A", 71)})
            self.add_owner(root, 8, "worker", 71)
            self.add_owner(root, 7, "x" * (MAX_COMM_LENGTH + 20), 71, 71)
            result = scan_listeners(str(root))

        listener = result["listeners"][0]
        self.assertEqual(
            listener["owners"],
            [
                {"pid": 7, "comm": "x" * MAX_COMM_LENGTH},
                {"pid": 8, "comm": "worker"},
            ],
        )
        self.assertNotIn("inode", listener)
        self.assertNotIn("cmdline", str(listener).lower())

    def test_missing_tables_and_denied_reads_warn_without_proc_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.mkdir(exist_ok=True)
            (root / "net").mkdir()
            missing = scan_listeners(str(root))
            self.assertEqual(missing["listeners"], [])
            self.assertTrue(any("unavailable" in warning for warning in missing["warnings"]))

            # Keep a valid fixture so a permission failure is distinguished from
            # a missing table. The static warning must not reveal its temp path.
            visible_root = self.make_proc(str(root / "visible"))
            with patch("builtins.open", side_effect=PermissionError):
                denied = scan_listeners(str(visible_root))

        self.assertTrue(any("permission denied" in warning for warning in denied["warnings"]))
        self.assertTrue(all(directory not in warning for warning in denied["warnings"]))
        self.assertTrue(all(directory not in warning for warning in missing["warnings"]))

    def test_malformed_rows_are_skipped_without_hiding_valid_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(
                directory,
                {
                    "tcp": (
                        "not a proc socket row\n"
                        + socket_row("not-an-endpoint", "0A", 81)
                        + socket_row("00000000:1F90", "0A", 82)
                    )
                },
            )
            result = scan_listeners(str(root))

        self.assertEqual(len(result["listeners"]), 1)
        self.assertEqual(result["listeners"][0]["port"], 8080)
        self.assertTrue(any("malformed socket entry" in warning for warning in result["warnings"]))
        self.assertTrue(all(not re.search(r"/tmp|\\\\", warning) for warning in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
