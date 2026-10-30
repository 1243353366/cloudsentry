"""Private mock-root checks for the fail-closed fixed-workload resource boundary."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverse_shell_decoy import resource_boundary as boundary


class ResourceBoundaryTests(unittest.TestCase):
    def _mock_parent(self, directory: Path) -> tuple[Path, Path]:
        root = directory / "cgroup"
        parent = root / "customer" / "echo"
        parent.mkdir(parents=True)
        (root / "cgroup.controllers").write_text("cpu memory pids io cpuset\n", encoding="ascii")
        (parent / "cgroup.subtree_control").write_text("cpu memory pids io\n", encoding="ascii")
        return root, parent

    def _child_controls(self, child: Path, device: str = "8:0") -> None:
        for name in (*boundary.CAPS, "io.max", "cgroup.procs", "cpu.stat", "memory.events", "pids.events", "io.stat"):
            (child / name).write_text("\n", encoding="ascii")
        # A normal filesystem mock preserves each write, which is the desired
        # kernel-readback model for this isolated unit test.
        (child / "io.max").write_text(
            f"{device} rbps=1048576 wbps=1048576 riops=128 wiops=128\n", encoding="ascii"
        )

    def test_review_is_no_write_no_sysfs_and_has_required_report_shape(self) -> None:
        with patch.object(boundary, "_read_small", side_effect=AssertionError("review must not inspect sysfs")), patch.object(
            boundary, "_gpu_nodes_present", side_effect=AssertionError("review must not inspect GPUs")
        ):
            report = boundary.build_review_report()
        self.assertEqual(report["format"], "resource_boundary_v1")
        self.assertFalse(report["ready"])
        self.assertFalse(report["service_launched"])
        self.assertEqual(report["status"], {"cpu": "declared", "mem": "declared", "io": "declared", "gpu": "not_verified"})
        self.assertEqual(len(report["source_policy_hash"]), 64)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(boundary, "apply_fixed_echo", side_effect=AssertionError("must not apply")):
            self.assertEqual(boundary.main(["--review", "--consent"]), 0)
        self.assertIn('"ready": false', output.getvalue())

    def test_apply_argument_gates_precede_any_cgroup_attempt(self) -> None:
        for argv in ([], ["--apply"], ["--apply", "--consent"], ["--apply", "--consent", "--cgroup-parent", "/sys/fs/cgroup/a"]):
            with self.subTest(argv=argv), patch.object(boundary, "apply_fixed_echo", side_effect=AssertionError("must not apply")):
                self.assertEqual(boundary.main(list(argv)), 0 if not argv else 2)
        with patch.object(boundary, "apply_fixed_echo", side_effect=boundary.ResourceBoundaryError("fail closed")):
            self.assertEqual(boundary.main(["--apply", "--consent", "--cgroup-parent", "/sys/fs/cgroup/a", "--io-device", "8:0"]), 2)

    def test_parent_requires_exact_delegation_no_root_and_no_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, parent = self._mock_parent(Path(raw))
            with patch.object(boundary, "CGROUP_ROOT", root):
                plan = boundary.validate_cgroup_parent(parent, "008:000")
                self.assertEqual(plan.io_device, "8:0")
                with self.assertRaisesRegex(boundary.ResourceBoundaryError, "invalid_cgroup_parent"):
                    boundary.validate_cgroup_parent(root, "8:0")
                (parent / "cgroup.subtree_control").write_text("cpu memory pids\n", encoding="ascii")
                with self.assertRaisesRegex(boundary.ResourceBoundaryError, "delegated_controllers_not_enabled"):
                    boundary.validate_cgroup_parent(parent, "8:0")
                (parent / "cgroup.subtree_control").write_text("cpu memory pids io\n", encoding="ascii")
                link = root / "linked"
                link.symlink_to(parent, target_is_directory=True)
                with self.assertRaises(boundary.ResourceBoundaryError):
                    boundary.validate_cgroup_parent(link, "8:0")

    def test_prepare_writes_fixed_values_and_checks_readback_only_under_mock_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, parent = self._mock_parent(Path(raw))
            created: list[Path] = []
            real_new_child = boundary._new_child
            def setup_child(plan: boundary.CgroupPlan) -> Path:
                child = real_new_child(plan)
                self._child_controls(child)
                created.append(child)
                return child
            with patch.object(boundary, "CGROUP_ROOT", root), patch.object(
                boundary, "_gpu_nodes_present", return_value=False
            ), patch.object(boundary, "_new_child", side_effect=setup_child):
                child = boundary.prepare_cgroup(parent, "8:0", gpu_policy_verifier=lambda: True)
            self.assertEqual(len(created), 1)
            self.assertTrue(child.name.startswith("resource-boundary-"))
            self.assertEqual((child / "cpu.max").read_text(encoding="ascii").strip(), "25000 100000")
            self.assertEqual((child / "memory.max").read_text(encoding="ascii").strip(), "268435456")
            self.assertEqual((child / "memory.swap.max").read_text(encoding="ascii").strip(), "0")
            self.assertEqual((child / "pids.max").read_text(encoding="ascii").strip(), "32")
            self.assertEqual((child / "io.max").read_text(encoding="ascii").strip(), "8:0 rbps=1048576 wbps=1048576 riops=128 wiops=128")
            self.assertEqual((parent / "cgroup.subtree_control").read_text(encoding="ascii"), "cpu memory pids io\n")

    def test_gpu_is_refused_without_external_verifier_or_when_visible(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, parent = self._mock_parent(Path(raw))
            with patch.object(boundary, "CGROUP_ROOT", root), patch.object(boundary, "_gpu_nodes_present", return_value=False), self.assertRaisesRegex(
                boundary.ResourceBoundaryError, "gpu_policy_not_verified"
            ):
                boundary.prepare_cgroup(parent, "8:0")
            with patch.object(boundary, "CGROUP_ROOT", root), patch.object(boundary, "_gpu_nodes_present", return_value=True), self.assertRaisesRegex(
                boundary.ResourceBoundaryError, "gpu_policy_not_verified"
            ):
                boundary.prepare_cgroup(parent, "8:0", gpu_policy_verifier=lambda: True)
            self.assertEqual(list(parent.iterdir()), [parent / "cgroup.subtree_control"])

    def test_counter_deltas_never_turn_missing_or_reset_into_zero(self) -> None:
        before = boundary.parse_counters("usage_usec 10\nnr_throttled 3\n")
        after = boundary.parse_counters("usage_usec 16\nnr_throttled 2\n")
        self.assertEqual(boundary.counter_delta(before, after, ("usage_usec", "nr_throttled", "absent")), {
            "usage_usec": 6, "nr_throttled": "unknown", "absent": "unknown",
        })
        self.assertEqual(boundary.parse_io_stat("8:0 rbytes=11 wbytes=7 rios=2 wios=1\n", "8:0")["rbytes"], 11)
        with self.assertRaises(ValueError):
            boundary.parse_counters("x not-a-number\n")

    def test_no_generic_command_or_gpu_attestation_option_exists(self) -> None:
        parser_source = Path(boundary.__file__).read_text(encoding="utf-8")
        self.assertNotIn("--command", parser_source)
        self.assertNotIn("--gpu-devices-unavailable", parser_source)
        self.assertIn('"--consent"', parser_source)


if __name__ == "__main__":
    unittest.main()
