"""Watchdog coverage: diffing, recurrence links, bounds, and the no-action guarantee."""
from __future__ import annotations

import json
import time
import unittest

from reverse_shell_decoy.observation import COVERAGE_COMPLETE, COVERAGE_NO_DATA, COVERAGE_PARTIAL
from reverse_shell_decoy.watchdog import (
    ACTION_NONE,
    ASSURANCE_MULTIPLE,
    ASSURANCE_PARTIAL,
    ASSURANCE_UNKNOWN,
    KIND_APPEARED,
    KIND_CHANGED,
    KIND_DISAPPEARED,
    KIND_REAPPEARED,
    ListenerWatchdog,
    binding_key,
)


def _record(port: int, pids=(100,), protocol: str = "tcp") -> dict:
    return {
        "protocol": protocol,
        "family": "ipv4",
        "address": "127.0.0.1",
        "port": port,
        "exposure": "loopback",
        "state": "listen",
        "owners": [{"pid": pid, "comm": "proc%d" % pid} for pid in pids],
        "direction": "passive",
    }


def _inventory(*records, warnings=(), observed_at="2026-11-01T00:00:00Z") -> dict:
    return {
        "listeners": list(records),
        "warnings": list(warnings),
        "observed_at_utc": observed_at,
        "simulation": False,
    }


class ScriptedSnapshots:
    """Returns one prepared inventory per call, then repeats the last one."""

    def __init__(self, inventories) -> None:
        self.inventories = list(inventories)
        self.calls = 0

    def __call__(self) -> dict:
        index = min(self.calls, len(self.inventories) - 1)
        self.calls += 1
        return self.inventories[index]


class WatchdogDiffTests(unittest.TestCase):
    def test_new_binding_is_reported_as_appeared(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory(), _inventory(_record(8080))]))
        first = watchdog.observe()
        second = watchdog.observe()
        self.assertEqual(first, [])
        self.assertEqual([event.kind for event in second], [KIND_APPEARED])
        self.assertEqual(second[0].port, 8080)
        self.assertEqual(second[0].observation_index, 2)

    def test_disappearing_binding_is_reported_once(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots([_inventory(_record(8080)), _inventory(), _inventory()])
        )
        watchdog.observe()
        second = watchdog.observe()
        third = watchdog.observe()
        self.assertEqual([event.kind for event in second], [KIND_DISAPPEARED])
        self.assertEqual(third, [])

    def test_reappearance_links_back_to_the_first_observation(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots(
                [
                    _inventory(_record(8080), observed_at="2026-11-01T00:00:00Z"),
                    _inventory(observed_at="2026-11-01T00:00:10Z"),
                    _inventory(_record(8080), observed_at="2026-11-01T00:00:20Z"),
                ]
            )
        )
        watchdog.observe()
        watchdog.observe()
        third = watchdog.observe()
        self.assertEqual([event.kind for event in third], [KIND_REAPPEARED])
        self.assertEqual(third[0].recurrence_of_first_seen_utc, "2026-11-01T00:00:00Z")
        self.assertEqual(third[0].prior_disappearances, 1)
        self.assertIn("recurrence", third[0].detail)

    def test_owner_change_on_the_same_binding_is_a_change_not_a_recurrence(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots([_inventory(_record(8080, pids=(100,))), _inventory(_record(8080, pids=(200,)))])
        )
        watchdog.observe()
        events = watchdog.observe()
        self.assertEqual([event.kind for event in events], [KIND_CHANGED])
        self.assertIn("200", events[0].detail)
        self.assertIn("100", events[0].detail)

    def test_second_owner_is_reported_as_multiple_owners(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots(
                [_inventory(_record(8080, pids=(100,))), _inventory(_record(8080, pids=(100, 101)))]
            )
        )
        watchdog.observe()
        events = watchdog.observe()
        self.assertEqual(events[0].identity_assurance, ASSURANCE_MULTIPLE)

    def test_no_owner_is_unknown_assurance_and_single_owner_is_partial(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots([_inventory(_record(8080, pids=()), _record(9090, pids=(7,)))])
        )
        events = watchdog.observe()
        assurance = {event.port: event.identity_assurance for event in events}
        self.assertEqual(assurance[8080], ASSURANCE_UNKNOWN)
        self.assertEqual(assurance[9090], ASSURANCE_PARTIAL)

    def test_binding_key_is_stable_and_covers_the_binding_identity(self) -> None:
        record = _record(8080)
        self.assertEqual(binding_key(record), "tcp/ipv4/127.0.0.1:8080/listen")
        self.assertNotEqual(binding_key(record), binding_key(_record(8081)))


class WatchdogSafetyTests(unittest.TestCase):
    def test_every_event_says_no_action_was_taken(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots(
                [_inventory(), _inventory(_record(8080)), _inventory(), _inventory(_record(8080))]
            )
        )
        for _ in range(4):
            watchdog.observe()
        report = watchdog.as_dict()
        self.assertTrue(report["events"])
        for event in report["events"]:
            self.assertEqual(event["action"], ACTION_NONE)
            self.assertTrue(event["requires_authorization"])
        self.assertFalse(report["terminates_processes"])
        self.assertEqual(report["action"], ACTION_NONE)

    def test_report_never_uses_verdict_language(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory(), _inventory(_record(22))]))
        watchdog.observe()
        watchdog.observe()
        text = json.dumps(watchdog.as_dict()).lower()
        for word in ("malicious", "attacker", "compromised", "backdoor"):
            self.assertNotIn(word, text)

    def test_deadline_stops_watching_and_says_so(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots([_inventory()]), deadline_seconds=0.05, min_interval_seconds=0
        )
        watchdog.observe()
        time.sleep(0.06)
        self.assertEqual(watchdog.observe(), [])
        report = watchdog.as_dict()
        self.assertFalse(report["still_running"])
        self.assertEqual(report["stopped_reason"], "deadline reached")
        self.assertIn("Watching stopped because the deadline was reached.", report["statement"])

    def test_observation_limit_stops_watching(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory()]), max_observations=2)
        watchdog.observe()
        watchdog.observe()
        self.assertEqual(watchdog.observe(), [])
        report = watchdog.as_dict()
        self.assertEqual(report["stopped_reason"], "observation limit reached")
        self.assertEqual(report["observations"], 2)

    def test_run_honours_the_iteration_count(self) -> None:
        snapshots = ScriptedSnapshots([_inventory()])
        watchdog = ListenerWatchdog(snapshots, min_interval_seconds=0, max_observations=10)
        report = watchdog.run(3)
        self.assertEqual(report["observations"], 3)
        self.assertEqual(snapshots.calls, 3)

    def test_invalid_configuration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ListenerWatchdog(snapshot="not callable")
        with self.assertRaises(ValueError):
            ListenerWatchdog(max_observations=0)
        with self.assertRaises(ValueError):
            ListenerWatchdog(deadline_seconds=0)
        with self.assertRaises(ValueError):
            ListenerWatchdog(min_interval_seconds=-1)
        with self.assertRaises(ValueError):
            ListenerWatchdog(history_limit=0)

    def test_snapshot_must_return_a_mapping(self) -> None:
        watchdog = ListenerWatchdog(lambda: ["not", "a", "mapping"])
        with self.assertRaises(ValueError):
            watchdog.observe()


class WatchdogCoverageTests(unittest.TestCase):
    def test_no_snapshot_yet_is_no_data(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory()]))
        self.assertEqual(watchdog.as_dict()["coverage"], COVERAGE_NO_DATA)

    def test_clean_snapshot_is_complete(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory(_record(22))]))
        watchdog.observe()
        self.assertEqual(watchdog.as_dict()["coverage"], COVERAGE_COMPLETE)

    def test_inventory_warning_downgrades_coverage(self) -> None:
        watchdog = ListenerWatchdog(
            ScriptedSnapshots([_inventory(_record(22), warnings=("scan limit reached",))])
        )
        watchdog.observe()
        report = watchdog.as_dict()
        self.assertEqual(report["coverage"], COVERAGE_PARTIAL)
        self.assertIn("scan limit reached", report["warnings"])

    def test_report_is_json_safe(self) -> None:
        watchdog = ListenerWatchdog(ScriptedSnapshots([_inventory(), _inventory(_record(443))]))
        watchdog.observe()
        watchdog.observe()
        payload = watchdog.as_dict()
        json.dumps(payload)
        self.assertEqual(payload["kind"], "listener_watchdog")
        self.assertIn("not continuous monitoring", payload["limitation_notice"])


if __name__ == "__main__":
    unittest.main()
