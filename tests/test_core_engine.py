"""Tests for the first LDAE increment: normalized events and authorization states."""
import json
import unittest

from reverse_shell_decoy.core_engine import (
    AuthStatus,
    CanonicalEvent,
    ConfidenceLevel,
    CoreAuthorizationEngine,
)


class CanonicalEventTests(unittest.TestCase):
    def test_event_contains_required_host_and_time_fields(self):
        event = CanonicalEvent.create(
            event_type="listener_snapshot",
            collection_source="unit-test",
            confidence=ConfidenceLevel.OBSERVED,
            authorization=AuthStatus.UNKNOWN,
            host_id="host-test-01",
        )
        record = event.to_dict()
        required = {
            "timestamp_utc", "timestamp_local", "local_timezone", "event_id",
            "incident_id", "host_identifier", "platform", "event_type",
            "collection_source", "confidence", "authorization",
        }
        self.assertTrue(required.issubset(record))
        self.assertEqual("host-test-01", record["host_identifier"])
        self.assertEqual("UNKNOWN", record["authorization"])
        self.assertTrue(event.timestamp_utc.endswith("+00:00"))
        self.assertTrue(event.event_id.startswith("evt_"))
        self.assertTrue(event.incident_id.startswith("inc_"))
        self.assertEqual("linux" if __import__("platform").system().lower() == "linux" else record["platform"], record["platform"])

    def test_host_name_is_not_emitted_by_default(self):
        event = CanonicalEvent.create(
            event_type="test",
            collection_source="unit-test",
            confidence=ConfidenceLevel.UNKNOWN,
            authorization=AuthStatus.UNKNOWN,
        )
        self.assertEqual("unknown-host", event.host_identifier)

    def test_json_serialization_is_structured_and_stable(self):
        event = CanonicalEvent.create(
            event_type="test",
            collection_source="unit-test",
            confidence=ConfidenceLevel.CORROBORATED,
            authorization=AuthStatus.AUTHORIZED,
            details={"port": 8080},
        )
        decoded = json.loads(event.to_json())
        self.assertEqual("AUTHORIZED", decoded["authorization"])
        self.assertEqual(8080, decoded["details"]["port"])


class AuthorizationStateTests(unittest.TestCase):
    def test_empty_inventory_stays_unknown(self):
        engine = CoreAuthorizationEngine()
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd"), AuthStatus.UNKNOWN)

    def test_matching_explicit_rule_is_authorized(self):
        engine = CoreAuthorizationEngine([{"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd"}])
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd"), AuthStatus.AUTHORIZED)

    def test_identity_mismatch_is_unauthorized_only_under_explicit_rule(self):
        engine = CoreAuthorizationEngine([{"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd"}])
        self.assertIs(engine.evaluate_listener(22, "TCP", "/tmp/sshd"), AuthStatus.UNAUTHORIZED)

    def test_unlisted_port_remains_unknown_even_with_an_inventory(self):
        engine = CoreAuthorizationEngine([{"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd"}])
        self.assertIs(engine.evaluate_listener(3389, "TCP", "unknown"), AuthStatus.UNKNOWN)

    def test_missing_identity_for_identity_bound_rule_remains_unknown(self):
        engine = CoreAuthorizationEngine([{"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd"}])
        self.assertIs(engine.evaluate_listener(22, "TCP", None), AuthStatus.UNKNOWN)

    def test_sensitive_port_is_not_malicious_by_itself(self):
        engine = CoreAuthorizationEngine()
        self.assertTrue(engine.is_sensitive_port(22))
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd"), AuthStatus.UNKNOWN)

    def test_matching_rule_can_follow_a_nonmatching_rule(self):
        engine = CoreAuthorizationEngine([
            {"port": 22, "protocol": "TCP", "executable": "/tmp/other"},
            {"port": 22, "protocol": "TCP", "executable": "/usr/sbin/sshd"},
        ])
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd"), AuthStatus.AUTHORIZED)


if __name__ == "__main__":
    unittest.main()
