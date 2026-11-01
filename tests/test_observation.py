"""Deterministic tests for the observation-completeness layer.

Fixtures are ordinary temporary directories that mimic the procfs layout the
collector reads; no test inspects the real host or opens a network listener.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.observation import (
    COVERAGE_COMPLETE,
    COVERAGE_DEGRADED,
    COVERAGE_PARTIAL,
    OWNERSHIP_CONFIRMED,
    OWNERSHIP_MULTIPLE,
    OWNERSHIP_UNKNOWN,
    COVERAGE_NO_DATA,
    collect_snapshot,
    socket_reference,
)

HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def socket_row(local, state, inode):
    return (
        "  0: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 0 0 %s 1\n"
        % (local, state, inode)
    )


def listener(port, inode, protocol="tcp", address="127.0.0.1", state="LISTEN", owners=None):
    return {
        "protocol": protocol,
        "family": "IPv4",
        "address": address,
        "port": port,
        "state": state,
        "exposure": "loopback",
        "direction": "passive",
        "owners": owners or [],
    }


def snapshot(listeners, warnings=None):
    return {
        "listeners": listeners,
        "findings": [],
        "warnings": list(warnings or []),
        "observed_at_utc": "2026-11-01T00:00:00Z",
        "simulation": False,
        "limitation_notice": "fixture",
    }


class ObservationFixture(unittest.TestCase):
    def make_proc(self, directory, tables=None):
        root = Path(directory)
        net = root / "net"
        net.mkdir(parents=True)
        for name in ("tcp", "tcp6", "udp", "udp6"):
            (net / name).write_text(HEADER + (tables or {}).get(name, ""), encoding="ascii")
        return root

    def add_process(self, root, pid, comm, inodes=(), ppid=1, namespace="net:[4026531840]",
                    executable=None):
        process = root / str(pid)
        fd = process / "fd"
        fd.mkdir(parents=True)
        (process / "comm").write_text(comm + "\n", encoding="utf-8")
        (process / "stat").write_text(
            "%d (%s) S %d %d %d 0 -1 4194560\n" % (pid, comm, ppid, pid, pid), encoding="utf-8"
        )
        namespace_dir = process / "ns"
        namespace_dir.mkdir()
        (namespace_dir / "net").symlink_to(namespace)
        for index, inode in enumerate(inodes):
            (fd / str(index)).symlink_to("socket:[%s]" % inode)
        if executable is not None:
            (process / "exe").symlink_to(str(executable))
        return process


class OwnershipTests(ObservationFixture):
    def test_multiple_processes_sharing_one_listener_are_all_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            binary = Path(directory) / "server-bin"
            binary.write_bytes(b"\x7fELF fixture image")
            self.add_process(root, 100, "server", [41], ppid=1, executable=binary)
            self.add_process(root, 101, "server", [41], ppid=100, executable=binary)

            result = collect_snapshot(str(root), cross_verify=False)

        self.assertEqual(len(result["listeners"]), 1)
        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_MULTIPLE)
        self.assertTrue(entry["ownership"]["shared_descriptor"])
        self.assertEqual(entry["ownership"]["owner_count"], 2)
        self.assertEqual([owner["pid"] for owner in entry["owners"]], [100, 101])
        # Both descriptors trace back to the same forked parent.
        self.assertEqual(entry["ownership"]["fork_related_parent_pids"], [100])
        self.assertEqual(entry["owners"][1]["parent_pid"], 100)
        self.assertEqual(result["coverage"]["bindings_with_owner"], 1)
        self.assertEqual(result["coverage"]["ownership_ratio"], 1.0)

    def test_single_owner_with_stable_snapshots_is_confirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            binary = Path(directory) / "server-bin"
            binary.write_bytes(b"image")
            self.add_process(root, 200, "server", [41], executable=binary)

            result = collect_snapshot(str(root), cross_verify=False)

        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_CONFIRMED)
        self.assertFalse(entry["ownership"]["shared_descriptor"])
        self.assertTrue(entry["ownership"]["recheck_observed"])
        self.assertEqual(result["coverage"]["state"], COVERAGE_COMPLETE)

    def test_binding_that_disappears_before_recheck_is_unknown_not_unauthorized(self):
        first = snapshot([listener(8080, 41, owners=[{"pid": 100, "comm": "server"}])])
        second = snapshot([])
        with patch("reverse_shell_decoy.observation.scan_listeners", side_effect=[first, second]):
            result = collect_snapshot("/proc", cross_verify=False)

        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_UNKNOWN)
        self.assertIn("binding_disappeared_before_recheck", entry["ownership"]["reasons"])
        self.assertFalse(entry["ownership"]["recheck_observed"])
        self.assertEqual(result["coverage"]["state"], COVERAGE_PARTIAL)
        self.assertIn("UNKNOWN ownership means", result["limitation_notice"])

    def test_owner_change_between_snapshots_is_reported(self):
        first = snapshot([listener(8080, 41, owners=[{"pid": 100, "comm": "server"}])])
        second = snapshot([listener(8080, 41, owners=[{"pid": 555, "comm": "replacement"}])])
        with patch("reverse_shell_decoy.observation.scan_listeners", side_effect=[first, second]):
            result = collect_snapshot("/proc", cross_verify=False)

        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_UNKNOWN)
        self.assertIn("owner_changed_between_snapshots", entry["ownership"]["reasons"])
        # Both snapshots' owners are preserved rather than one being chosen.
        self.assertEqual([owner["pid"] for owner in entry["owners"]], [100, 555])

    def test_no_owner_descriptor_is_unknown_and_counts_against_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("00000000:0050", "0A", 77)})
            result = collect_snapshot(str(root), cross_verify=False)

        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_UNKNOWN)
        self.assertIn("no_owner_descriptor_observed", entry["ownership"]["reasons"])
        self.assertEqual(result["coverage"]["bindings_without_owner"], 1)
        self.assertEqual(result["coverage"]["ownership_ratio"], 0.0)
        self.assertEqual(result["coverage"]["state"], COVERAGE_PARTIAL)

    def test_permission_warnings_degrade_coverage(self):
        first = snapshot(
            [listener(8080, 41, owners=[{"pid": 100, "comm": "server"}])],
            warnings=["permission denied while reading process file descriptors"],
        )
        with patch("reverse_shell_decoy.observation.scan_listeners", side_effect=[first, first]):
            result = collect_snapshot("/proc", cross_verify=False)

        self.assertEqual(result["listeners"][0]["ownership"]["state"], "DEGRADED")
        self.assertEqual(result["coverage"]["state"], COVERAGE_DEGRADED)
        self.assertEqual(result["coverage"]["permission_denials"], 1)
        self.assertIn("permission denial", result["coverage"]["statement"])

    def test_namespaces_are_counted_from_owner_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(
                directory,
                {"tcp": socket_row("0100007F:1F90", "0A", 41) + socket_row("0100007F:1FA0", "0A", 42)},
            )
            self.add_process(root, 300, "svc-a", [41], namespace="net:[4026531840]")
            self.add_process(root, 301, "svc-b", [42], namespace="net:[4026531999]")

            result = collect_snapshot(str(root), cross_verify=False)

        coverage = result["coverage"]
        self.assertEqual(coverage["namespaces_observed"], 2)
        self.assertEqual(coverage["namespace_scope"], "multiple_namespaces")
        self.assertEqual(sum(coverage["namespace_owner_counts"].values()), 2)


class ExecutableIdentityTests(ObservationFixture):
    def test_executable_is_hashed_from_the_opened_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            binary = Path(directory) / "daemon"
            binary.write_bytes(b"\x7fELF real fixture bytes")
            self.add_process(root, 400, "daemon", [41], executable=binary)

            result = collect_snapshot(str(root), cross_verify=False)

        executable = result["listeners"][0]["owners"][0]["executable"]
        self.assertEqual(executable["path_state"], "verified")
        self.assertTrue(executable["identity_verified"])
        self.assertEqual(
            executable["image_sha256"], hashlib.sha256(b"\x7fELF real fixture bytes").hexdigest()
        )
        self.assertFalse(executable["changed_during_hash"])
        self.assertFalse(executable["deleted_in_path"])

    def test_deleted_executable_is_not_treated_as_verified_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            ghost = Path(directory) / "gone (deleted)"
            self.add_process(root, 401, "ghost", [41], executable=ghost)

            result = collect_snapshot(str(root), cross_verify=False)

        executable = result["listeners"][0]["owners"][0]["executable"]
        self.assertTrue(executable["deleted_in_path"])
        self.assertFalse(executable["identity_verified"])
        self.assertIn(executable["path_state"], {"unlinked", "unavailable"})
        self.assertEqual(result["coverage"]["owners_identity_unverified"], 1)

    def test_missing_executable_link_is_unavailable_not_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            self.add_process(root, 402, "bare", [41])

            result = collect_snapshot(str(root), cross_verify=False)

        executable = result["listeners"][0]["owners"][0]["executable"]
        self.assertEqual(executable["path_state"], "unavailable")
        self.assertFalse(executable["identity_verified"])
        self.assertIsNone(executable["image_sha256"])


class CrossVerificationTests(ObservationFixture):
    def test_cross_verification_is_explicit_when_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            self.add_process(root, 500, "svc", [41])
            with patch(
                "reverse_shell_decoy.observation.collect_diag_bindings",
                return_value={
                    "available": False,
                    "reason": "netlink_sock_diag_not_supported",
                    "observations": [],
                },
            ):
                result = collect_snapshot(str(root))

        comparison = result["cross_verification"]
        self.assertFalse(comparison["available"])
        self.assertEqual(comparison["agreement"], "not_verified")
        self.assertEqual(comparison["reason"], "netlink_sock_diag_not_supported")
        self.assertIn("stand alone", comparison["detail"])

    def test_disagreement_between_sources_preserves_both_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            self.add_process(root, 501, "svc", [41])
            with patch(
                "reverse_shell_decoy.observation.collect_diag_bindings",
                return_value={
                    "available": True,
                    "reason": "ok",
                    "observations": [
                        {"protocol": "tcp", "family": "IPv4", "address": "127.0.0.1",
                         "port": 8080, "state": "UDP-bound", "socket_ref_sha256": "x"}
                    ],
                },
            ):
                result = collect_snapshot(str(root))

        comparison = result["cross_verification"]
        self.assertTrue(comparison["available"])
        self.assertEqual(comparison["agreement"], "state_disagreement")
        self.assertEqual(comparison["state_disagreements"], 1)

    def test_cross_verification_is_skipped_when_not_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {})
            result = collect_snapshot(str(root), cross_verify=False)

        self.assertEqual(
            result["cross_verification"]["reason"], "cross_verification_not_requested"
        )
        self.assertEqual(result["coverage"]["bindings_observed"], 0)
        self.assertEqual(result["coverage"]["state"], COVERAGE_NO_DATA)
        self.assertIn("No bindings were visible", result["coverage"]["statement"])


class CollectionWindowTests(ObservationFixture):
    def test_collection_window_and_snapshot_count_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            self.add_process(root, 600, "svc", [41])

            result = collect_snapshot(str(root), cross_verify=False)

        collection = result["collection"]
        self.assertEqual(collection["snapshots"], 2)
        self.assertTrue(collection["recheck_performed"])
        self.assertIsNotNone(collection["second_snapshot_utc"])
        self.assertGreaterEqual(collection["duration_seconds"], 0.0)

    def test_recheck_can_be_disabled_and_is_then_stated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_proc(directory, {"tcp": socket_row("0100007F:1F90", "0A", 41)})
            self.add_process(root, 601, "svc", [41])

            result = collect_snapshot(str(root), recheck=False, cross_verify=False)

        self.assertEqual(result["collection"]["snapshots"], 1)
        self.assertFalse(result["coverage"]["recheck_performed"])
        entry = result["listeners"][0]
        self.assertEqual(entry["ownership"]["state"], OWNERSHIP_CONFIRMED)
        self.assertIn("single_snapshot_no_recheck", entry["ownership"]["reasons"])

    def test_binding_reference_is_stable_and_does_not_expose_inode(self):
        reference = socket_reference("tcp", "IPv4", "127.0.0.1", 8080, "LISTEN")
        self.assertEqual(reference, socket_reference("tcp", "IPv4", "127.0.0.1", 8080, "LISTEN"))
        self.assertNotIn("41", reference)
        self.assertEqual(len(reference), 32)

    def test_invalid_exe_byte_budget_is_rejected(self):
        for value in (-1, True, 9 * 1024 * 1024, "8"):
            with self.assertRaises(ValueError):
                collect_snapshot("/proc", max_exe_bytes=value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
