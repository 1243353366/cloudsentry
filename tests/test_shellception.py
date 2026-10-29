"""Contract tests for the networkless, virtual-only DefensiveLoop.

These tests intentionally exercise only synthetic DecoySession state and explicit,
operator-selected local files.  They must never require a listener, a network
endpoint, or a persistent host change.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from reverse_shell_decoy.shellception import (
    MAX_WATCH_BYTES,
    MAX_WATCH_FILES,
    DefensiveLoop,
    main,
)


EXPECTED_STEP_KEYS = {
    "simulation",
    "changed",
    "mutation",
    "baseline_sha256",
    "state_sha256",
    "observation_scope",
    "integrity_ok",
    "host_changed",
    "outbound_connections",
}


class DefensiveLoopTests(unittest.TestCase):
    def assert_step_contract(self, report: dict, *, scope: str) -> None:
        self.assertTrue(EXPECTED_STEP_KEYS.issubset(report), "required safety fields missing")
        self.assertIs(report["simulation"], True)
        self.assertIsInstance(report["changed"], bool)
        self.assertTrue(report["mutation"] is None or isinstance(report["mutation"], str))
        self.assertRegex(report["baseline_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["state_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(report["observation_scope"], scope)
        self.assertIsInstance(report["integrity_ok"], bool)
        self.assertIs(report["host_changed"], False)
        self.assertEqual(report["outbound_connections"], 0)

    def test_empty_virtual_state_snapshot_is_stable_and_idle_does_not_mutate(self) -> None:
        loop = DefensiveLoop(seed=17)
        before = loop.snapshot()
        original_files = dict(loop.session.files)
        original_directories = set(loop.session.directories)

        report = loop.step()

        self.assert_step_contract(report, scope="virtual_state")
        self.assertEqual(report["changed"], False)
        self.assertIsNone(report["mutation"])
        self.assertEqual(report["baseline_sha256"], before)
        self.assertEqual(report["state_sha256"], before)
        self.assertEqual(loop.snapshot(), before)
        self.assertEqual(loop.session.files, original_files)
        self.assertEqual(loop.session.directories, original_directories)
        self.assertTrue(loop.verify_isolation())

        # A deterministic seed and an otherwise empty loop state must not acquire
        # timestamps, process lists, or other runtime drift in its digest.
        self.assertEqual(DefensiveLoop(seed=17).snapshot(), before)

    def test_virtual_touch_is_detected_then_reanchored_without_oscillation(self) -> None:
        loop = DefensiveLoop(seed=2)
        loop.session.execute("touch history")

        changed = loop.step()
        settled = loop.step()

        self.assert_step_contract(changed, scope="virtual_state")
        self.assertTrue(changed["changed"])
        self.assertIsNotNone(changed["mutation"])
        self.assertNotEqual(changed["baseline_sha256"], changed["state_sha256"])
        self.assert_step_contract(settled, scope="virtual_state")
        self.assertFalse(settled["changed"])
        self.assertIsNone(settled["mutation"])
        self.assertEqual(settled["baseline_sha256"], settled["state_sha256"])
        self.assertEqual(settled["baseline_sha256"], changed["post_mutation_baseline_sha256"])
        self.assertTrue(loop.verify_isolation())

    def test_virtual_events_are_bounded_simulated_and_do_not_retain_file_content(self) -> None:
        loop = DefensiveLoop(seed=4)
        secret_marker = "never-record-this-virtual-file-content"
        loop.session.files["/root/history"] = secret_marker
        loop.step()

        self.assertLessEqual(len(loop.events), 256)
        self.assertTrue(loop.events)
        self.assertTrue(all(event.get("simulation") is True for event in loop.events))
        self.assertNotIn(secret_marker, json.dumps(loop.events, sort_keys=True))

    def test_virtual_mode_performs_no_host_execution_or_network_activity(self) -> None:
        loop = DefensiveLoop(seed=1)
        original_files = dict(loop.session.files)

        with patch("builtins.open", side_effect=AssertionError("unexpected host file access")), \
             patch("os.system", side_effect=AssertionError("unexpected command execution")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected subprocess")), \
             patch.object(socket, "socket", side_effect=AssertionError("unexpected socket")), \
             patch.object(urllib.request, "urlopen", side_effect=AssertionError("unexpected HTTP request")):
            report = loop.step()

        self.assert_step_contract(report, scope="virtual_state")
        self.assertFalse(report["changed"])
        self.assertEqual(loop.session.files, original_files)

    def test_no_explicit_watch_means_no_automatic_host_observation(self) -> None:
        loop = DefensiveLoop(seed=3)
        with patch("os.open", side_effect=AssertionError("automatic host scanning is prohibited")):
            report = loop.step()
        self.assert_step_contract(report, scope="virtual_state")

    def test_explicit_regular_watch_detects_change_without_writing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            watched = Path(temporary_directory) / "operator-selected.txt"
            watched.write_bytes(b"first synthetic observation")
            loop = DefensiveLoop(seed=5, watch_files=[str(watched)])

            idle = loop.step()
            watched.write_bytes(b"operator changed this file")
            bytes_before_step = watched.read_bytes()
            changed = loop.step()
            bytes_after_step = watched.read_bytes()

        self.assert_step_contract(idle, scope="explicit_local_files")
        self.assertFalse(idle["changed"])
        self.assert_step_contract(changed, scope="explicit_local_files")
        self.assertTrue(changed["changed"])
        self.assertEqual(bytes_before_step, bytes_after_step)
        self.assertNotEqual(changed["baseline_sha256"], changed["state_sha256"])
        self.assertEqual(changed["post_mutation_baseline_sha256"], changed["state_sha256"])

    def test_missing_explicit_file_is_reported_generically_without_contents_or_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            watched = Path(temporary_directory) / "do-not-disclose-this-path.txt"
            marker = "do-not-disclose-this-file-content"
            watched.write_text(marker, encoding="utf-8")
            loop = DefensiveLoop(seed=6, watch_files=[str(watched)])
            watched.unlink()

            report = loop.step()
            audit = json.dumps(loop.events, sort_keys=True)

        self.assert_step_contract(report, scope="explicit_local_files")
        self.assertTrue(report["changed"])
        self.assertTrue(loop.events)
        self.assertNotIn(marker, audit)
        self.assertNotIn(str(watched), audit)

    def test_symlink_watch_is_rejected_or_generates_only_a_generic_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "target.txt"
            link = Path(temporary_directory) / "operator-link.txt"
            marker = "symlink-target-content-must-never-be-read"
            target.write_text(marker, encoding="utf-8")
            try:
                os.symlink(target, link)
            except (AttributeError, NotImplementedError, OSError) as exc:  # pragma: no cover - platform guard
                self.skipTest(f"symlinks unavailable: {exc}")

            try:
                loop = DefensiveLoop(seed=7, watch_files=[str(link)])
            except ValueError as exc:
                self.assertNotIn(str(link), str(exc))
                self.assertNotIn(marker, str(exc))
                return

            report = loop.step()
            audit = json.dumps(loop.events, sort_keys=True)

        self.assert_step_contract(report, scope="explicit_local_files")
        self.assertTrue(loop.events, "an accepted unsafe watch must produce an audit warning")
        self.assertNotIn(marker, audit)
        self.assertNotIn(str(link), audit)

    def test_watch_quotas_are_strict(self) -> None:
        self.assertEqual(MAX_WATCH_FILES, 16)
        self.assertEqual(MAX_WATCH_BYTES, 65536)
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            files = []
            for number in range(MAX_WATCH_FILES + 1):
                path = directory / f"watch-{number}.txt"
                path.write_bytes(b"")
                files.append(str(path))
            with self.assertRaises(ValueError):
                DefensiveLoop(watch_files=files)

            oversized = directory / "oversized.txt"
            marker = b"bounded-watch-content-must-not-enter-audit"
            oversized.write_bytes(marker + (b"x" * (MAX_WATCH_BYTES + 1 - len(marker))))
            try:
                oversized_loop = DefensiveLoop(watch_files=[str(oversized)])
            except ValueError:
                return
            report = oversized_loop.step()
            audit = json.dumps(oversized_loop.events, sort_keys=True)
            self.assert_step_contract(report, scope="explicit_local_files")
            self.assertNotIn(marker.decode(), audit)

    def test_overbound_virtual_dictionary_fails_integrity_check(self) -> None:
        loop = DefensiveLoop(seed=8)
        loop.session.files = {f"/root/entry-{index}": "[SIMULATED]" for index in range(129)}

        self.assertFalse(loop.verify_isolation())
        with self.assertRaises(RuntimeError):
            loop.step()
        self.assertFalse(loop.events, "invalid virtual state must stop before doing work")

    def test_step_stops_at_a_bounded_audit_cap(self) -> None:
        loop = DefensiveLoop(seed=9)
        for _ in range(300):
            try:
                loop.step()
            except (ValueError, RuntimeError):
                break
        else:
            self.fail("DefensiveLoop did not stop when its audit/step cap was reached")

        self.assertLessEqual(len(loop.events), 256)


class DefensiveLoopCliTests(unittest.TestCase):
    def assert_cli_rejected(self, arguments: list[str]) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(arguments)
        self.assertEqual(raised.exception.code, 2)

    def test_cli_uses_json_only_for_a_valid_minimum_bounded_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--iterations", "1", "--interval", "0", "--max-runtime", "1", "--seed", "10"])

        self.assertEqual(code, 0)
        rendered = stdout.getvalue().strip()
        self.assertTrue(rendered)
        try:
            payloads = [json.loads(rendered)]
        except json.JSONDecodeError:
            # JSON Lines is also valid audit-only output; every non-empty line
            # must still be a JSON value and no operator prose may be printed.
            payloads = [json.loads(line) for line in rendered.splitlines() if line.strip()]
        self.assertTrue(payloads)

    def test_cli_rejects_counter_shell_positional_arguments_and_invalid_quotas(self) -> None:
        self.assert_cli_rejected(["attacker.example", "4444"])
        self.assert_cli_rejected(["--iterations", "0"])
        self.assert_cli_rejected(["--iterations", "121"])
        self.assert_cli_rejected(["--interval", "-0.1"])
        self.assert_cli_rejected(["--interval", "5.1"])
        self.assert_cli_rejected(["--max-runtime", "0"])
        self.assert_cli_rejected(["--max-runtime", "61"])
        self.assert_cli_rejected(["--c2", "attacker.example"])


if __name__ == "__main__":
    unittest.main()
