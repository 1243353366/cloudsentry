"""Tests for the first LDAE increment: normalized events and authorization states."""
import json
import unittest

from reverse_shell_decoy.core_engine import (
    AuthStatus, CanonicalEvent, ConfidenceLevel, CoreAuthorizationEngine,
    PolicyMode, PolicyConfigurationError, EventValidationError,
    JsonEventLogger, EvidenceRecorder, EvidenceWriteError, EvidenceError,
    EvidenceIntegrityError, MAX_JOURNAL_LINE_BYTES,
    ListenerIdentity, ProcessIdentity, extract_listener_payload,
    Exposure, IdentityAssurance,
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
            "timestamp_utc", "timestamp_local", "timezone_id", "event_id",
            "incident_id", "host_identifier", "platform", "event_type",
            "collection_source", "confidence", "authorization",
        }
        self.assertTrue(required.issubset(record))
        self.assertEqual("host-test-01", record["host_identifier"])
        self.assertEqual("UNKNOWN", record["authorization"])
        self.assertTrue(event.timestamp_utc.endswith("+00:00"))
        import uuid
        self.assertEqual(str(uuid.UUID(event.event_id)), event.event_id)
        self.assertEqual(str(uuid.UUID(event.incident_id)), event.incident_id)
        self.assertEqual(1, event.schema_version)
        self.assertIn("timezone_id", record)
        self.assertIn("utc_offset", record)

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
        engine = CoreAuthorizationEngine(policy_revision="rev1")
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd", local_address="127.0.0.1").status, AuthStatus.UNKNOWN)

    def test_matching_explicit_rule_is_authorized(self):
        engine = CoreAuthorizationEngine([{"policy_id": "ssh", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"}], policy_revision="rev1")
        decision = engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd", local_address="127.0.0.1")
        self.assertIs(decision.status, AuthStatus.AUTHORIZED)
        self.assertEqual("rev1", decision.policy_revision)
        self.assertEqual("ssh", decision.policy_id)
        self.assertFalse(decision.matching_attributes["path_is_image_identity_proof"])

    def test_identity_mismatch_is_unauthorized_only_under_explicit_rule(self):
        engine = CoreAuthorizationEngine([{"policy_id": "ssh", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"}], policy_revision="rev1")
        self.assertIs(engine.evaluate_listener(22, "TCP", "/tmp/sshd", local_address="127.0.0.1").status, AuthStatus.UNAUTHORIZED)

    def test_unlisted_port_remains_unknown_even_with_an_inventory(self):
        engine = CoreAuthorizationEngine([{"policy_id": "ssh", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"}], policy_revision="rev1")
        self.assertIs(engine.evaluate_listener(3389, "TCP", "unknown", local_address="127.0.0.1").status, AuthStatus.UNKNOWN)

    def test_missing_identity_for_identity_bound_rule_remains_unknown(self):
        engine = CoreAuthorizationEngine([{"policy_id": "ssh", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"}], policy_revision="rev1")
        self.assertIs(engine.evaluate_listener(22, "TCP", None, local_address="127.0.0.1").status, AuthStatus.UNKNOWN)

    def test_sensitive_port_is_not_malicious_by_itself(self):
        engine = CoreAuthorizationEngine(policy_revision="rev1")
        self.assertTrue(engine.is_sensitive_port(22))
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd", local_address="127.0.0.1").status, AuthStatus.UNKNOWN)

    def test_matching_rule_can_follow_a_nonmatching_rule(self):
        engine = CoreAuthorizationEngine([
            {"policy_id": "other", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/tmp/other"},
            {"policy_id": "ssh", "port": 22, "protocol": "TCP", "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"},
        ], policy_revision="rev1")
        self.assertIs(engine.evaluate_listener(22, "TCP", "/usr/sbin/sshd", local_address="127.0.0.1").status, AuthStatus.AUTHORIZED)



    def test_falsey_invalid_details_are_not_silently_coerced(self):
        with self.assertRaises(EventValidationError):
            CanonicalEvent.create(event_type="test", collection_source="test", confidence=ConfidenceLevel.UNKNOWN,
                                  authorization=AuthStatus.UNKNOWN, details=[])

    def test_invalid_port_only_policy_rejected_without_explicit_opt_in(self):
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([{"policy_id": "p", "port": 80, "exposure": "LOOPBACK", "mode": "PORT_ONLY", "operator_approved": True}], policy_revision="r1")

    def test_port_only_requires_both_explicit_gates(self):
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([{"policy_id": "p", "port": 80, "exposure": "LOOPBACK", "mode": "PORT_ONLY", "operator_approved": False}], policy_revision="r1", allow_port_only=True)

    def test_duplicate_and_conflicting_policies_rejected(self):
        item = {"policy_id": "p", "port": 22, "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/usr/sbin/sshd"}
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([item, item], policy_revision="r1")
        conflict = {"policy_id": "q", "port": 22, "exposure": "LOOPBACK", "mode": "EXECUTABLE_AND_HASH", "executable": "/usr/sbin/sshd", "sha256": "a" * 64}
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([item, conflict], policy_revision="r1")

    def test_hash_policy_requires_hash_and_hash_subject(self):
        engine = CoreAuthorizationEngine([{"policy_id": "h", "port": 443, "exposure": "LOOPBACK", "mode": "EXECUTABLE_AND_HASH", "executable": "/srv/app", "sha256": "a" * 64}], policy_revision="r2")
        self.assertIs(engine.evaluate_listener(443, "TCP", "/srv/app", local_address="127.0.0.1").status, AuthStatus.UNKNOWN)
        decision = engine.evaluate_listener(443, "TCP", "/srv/app", "a" * 64, hash_subject="path_file", local_address="127.0.0.1")
        self.assertIs(decision.status, AuthStatus.UNKNOWN)
        self.assertIs(decision.status, AuthStatus.UNKNOWN)
        confirmed = engine.evaluate_listener(443, "TCP", "/srv/app", "a" * 64, hash_subject="running_image", hash_provenance="Linux /proc/pid/map_files verified by test", local_address="127.0.0.1")
        self.assertIs(confirmed.status, AuthStatus.AUTHORIZED)

    def test_port_only_conflicts_with_identity_policy_on_same_listener(self):
        port_only = {"policy_id": "port", "port": 8080, "exposure": "LOOPBACK", "mode": "PORT_ONLY", "operator_approved": True}
        executable = {"policy_id": "exec", "port": 8080, "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/srv/app"}
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([port_only, executable], policy_revision="r9", allow_port_only=True)

    def test_port_only_policy_reports_revision_and_attributes(self):
        item = {"policy_id": "web", "port": 8080, "exposure": "LOOPBACK", "mode": "PORT_ONLY", "operator_approved": True}
        engine = CoreAuthorizationEngine([item], policy_revision="r9", allow_port_only=True)
        result = engine.evaluate_listener(8080, "TCP", local_address="127.0.0.1")
        self.assertIs(result.status, AuthStatus.AUTHORIZED)
        self.assertEqual("r9", result.policy_revision)
        self.assertTrue(result.matching_attributes["operator_approved"])


class EventHardeningTests(unittest.TestCase):
    def make_event(self, **kwargs):
        args = dict(event_type="test", collection_source="test", confidence=ConfidenceLevel.OBSERVED, authorization=AuthStatus.UNKNOWN)
        args.update(kwargs)
        return CanonicalEvent.create(**args)

    def test_listener_payload_preserves_all_fields_including_self(self):
        payload = {
            "socket_id": "sock-self", "protocol": "TCP", "local_address": "127.0.0.1",
            "local_port": 9443, "pid": 4, "owner": "cloudsentry", "state": "LISTEN",
            "annotations": {"is_cloudsentry_listener": True},
        }
        extracted = extract_listener_payload(payload)
        self.assertEqual(payload, extracted)
        identity = ListenerIdentity(
            protocol="TCP", local_address="127.0.0.1", local_port=9443, process=None,
            first_observed_utc="2026-01-01T00:00:00+00:00", last_observed_utc="2026-01-01T00:00:00+00:00",
            duration_seconds=0.0, listening_state="LISTEN", raw_payload=payload,
        )
        self.assertEqual(payload, identity.to_dict()["raw_payload"])
        payload["annotations"]["is_cloudsentry_listener"] = False
        self.assertTrue(identity.to_dict()["raw_payload"]["annotations"]["is_cloudsentry_listener"])

    def test_listener_payload_extraction_rejects_unsafe_or_oversized_values(self):
        with self.assertRaises(EventValidationError):
            extract_listener_payload({"payload": object()})
        with self.assertRaises(EventValidationError):
            extract_listener_payload({"payload": "x" * 60000})
        with self.assertRaises(EventValidationError):
            extract_listener_payload([{"port": 80}])

    def test_synthetic_consistency_and_full_uuid_source_ids(self):
        with self.assertRaises(EventValidationError):
            self.make_event(synthetic_decoy=True)
        with self.assertRaises(EventValidationError):
            self.make_event(dde_event_id="dde-1")
        synthetic = self.make_event(synthetic_decoy=True, dde_event_id="dde-1")
        self.assertTrue(synthetic.to_dict()["synthetic_decoy"])
        with self.assertRaises(EventValidationError):
            self.make_event(source_event_ids=("short",))

    def test_details_are_immutable_and_bounded(self):
        original = {"nested": {"items": [1, 2]}}
        event = self.make_event(details=original)
        original["nested"]["items"].append(3)
        self.assertEqual([1, 2], event.to_dict()["details"]["nested"]["items"])
        with self.assertRaises(TypeError):
            event.details["new"] = 1
        with self.assertRaises(EventValidationError):
            nested = "deep"
            for _ in range(10):
                nested = [nested]
            self.make_event(details={"x": nested})
        with self.assertRaises(EventValidationError):
            self.make_event(details={"x": "z" * 65536})

    def test_invalid_timestamp_and_schema_rejected(self):
        event = self.make_event()
        with self.assertRaises(EventValidationError):
            CanonicalEvent(**{**event.__dict__, "timestamp_utc": "not-time"})
        with self.assertRaises(EventValidationError):
            CanonicalEvent(**{**event.__dict__, "schema_version": 7})

    def test_timezone_transition_derivation(self):
        winter = self.make_event(timezone_id="America/New_York")
        summer = self.make_event(timezone_id="America/New_York")
        self.assertEqual(winter.timestamp_local, winter.timestamp_utc and winter.to_dict()["timestamp_local"])
        self.assertIn(summer.utc_offset, ("-04:00", "-05:00"))

    def test_duplicate_event_ids_rejected_by_recorder(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            recorder = EvidenceRecorder(str(Path(tmp) / "events.jsonl"))
            event = self.make_event()
            recorder.append(event)
            with self.assertRaises(EvidenceWriteError):
                recorder.append(event)

    def test_evidence_storage_exhaustion_is_visible(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            recorder = EvidenceRecorder(str(Path(tmp) / "events.jsonl"), max_bytes=1024)
            with self.assertRaises(EvidenceWriteError):
                recorder.append(self.make_event(details={"payload": "x" * 500}))

    def test_synthetic_tagging_survives_evidence_recording(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "events.jsonl")
            recorder = EvidenceRecorder(path)
            event = self.make_event(synthetic_decoy=True, dde_event_id="dde-test")
            recorder.append(event)
            record = json.loads(Path(path).read_text().splitlines()[0])
            self.assertTrue(record["event"]["synthetic_decoy"])
            self.assertEqual("dde-test", record["event"]["dde_event_id"])

    def test_interrupted_write_failure_is_visible_and_requires_recovery(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import reverse_shell_decoy.core_engine as core
        with tempfile.TemporaryDirectory() as tmp:
            recorder = EvidenceRecorder(str(Path(tmp) / "events.jsonl"))
            real_write = core.os.write
            def partial_write(fd, data):
                return real_write(fd, data[:max(1, len(data) // 2)])
            with patch.object(core.os, "write", side_effect=partial_write):
                with self.assertRaises(EvidenceWriteError):
                    recorder.append(self.make_event())
            with self.assertRaises(EvidenceWriteError):
                recorder.append(self.make_event())

    def test_serialized_details_are_detached_and_analysis_is_separate(self):
        event = self.make_event(details={"observed": "raw"}, raw_observations={"port": 10})
        serialized = event.to_dict()
        serialized["details"]["observed"] = "changed"
        self.assertEqual("raw", event.to_dict()["details"]["observed"])
        derived = self.make_event(parent_event_ids=(event.event_id,), source_event_ids=(event.event_id,),
                                 raw_observations={"port": 10}, behavioral_assessment={"risk": "low"})
        self.assertEqual(event.event_id, derived.parent_event_ids[0])
        self.assertEqual("raw", event.to_dict()["details"]["observed"])

    def test_serialization_failure_is_visible_from_evidence_recorder(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            recorder = EvidenceRecorder(str(Path(tmp) / "events.jsonl"))
            event = self.make_event()
            with patch("reverse_shell_decoy.core_engine.CanonicalEvent.to_dict", side_effect=ValueError("broken serialization")):
                with self.assertRaises(EvidenceWriteError):
                    recorder.append(event)

    def test_serialization_boundary_revalidates_event(self):
        event = self.make_event()
        object.__setattr__(event, "synthetic_decoy", True)
        with self.assertRaises(EventValidationError):
            event.to_json()

    def test_recovery_after_restart_and_integrity_verification(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "events.jsonl")
            event = self.make_event()
            recorder = EvidenceRecorder(path)
            self.assertEqual(1, recorder.append(event))
            recovered = EvidenceRecorder(path)
            self.assertEqual(2, recovered.append(self.make_event()))
            self.assertTrue(EvidenceRecorder.verify_file(path).valid)

    def test_process_identity_key_prepares_for_pid_reuse(self):
        from reverse_shell_decoy.core_engine import ProcessIdentity
        first = ProcessIdentity(7, 1, "/bin/a", "a" * 64, "user", "2025-01-01T00:00:00+00:00")
        second = ProcessIdentity(7, 1, "/bin/a", "a" * 64, "user", "2025-01-01T00:00:01+00:00")
        self.assertEqual(first.pid, second.pid)
        self.assertNotEqual(first.identity_key, second.identity_key)

    def test_interrupted_write_is_detected_on_recovery(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_bytes(b'{"sequence":')
            with self.assertRaises(Exception):
                EvidenceRecorder(str(path))

    def test_logger_without_handlers_fails_visibly(self):
        import logging
        logger = logging.Logger("bare")
        with self.assertRaises(RuntimeError):
            JsonEventLogger(logger).emit(self.make_event())


class Increment2HardeningTests(unittest.TestCase):
    def test_loopback_policy_does_not_authorize_public_bind(self):
        rule = {"policy_id": "local", "port": 8080, "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True,
                "executable": "/srv/app", "bind_address": "127.0.0.1", "exposure": "LOOPBACK",
                "interface_identity": "lo", "network_namespace_id": "ns-local"}
        engine = CoreAuthorizationEngine([rule], policy_revision="inc2")
        ok = engine.evaluate_listener(8080, "TCP", "/srv/app", local_address="127.0.0.1", interface_identity="lo",
                                     exposure="LOOPBACK", network_namespace_id="ns-local")
        self.assertIs(ok.status, AuthStatus.AUTHORIZED)
        public = engine.evaluate_listener(8080, "TCP", "/srv/app", local_address="8.8.8.8", interface_identity="eth0",
                                          exposure="PUBLIC", network_namespace_id="ns-local")
        self.assertIsNot(public.status, AuthStatus.AUTHORIZED)
        self.assertIn(public.status, (AuthStatus.UNKNOWN, AuthStatus.UNAUTHORIZED))

    def test_exposure_and_address_mismatch_cannot_authorize(self):
        rule = {"policy_id": "local", "port": 8080, "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True,
                "executable": "/srv/app", "exposure": "LOOPBACK"}
        engine = CoreAuthorizationEngine([rule], policy_revision="inc2")
        decision = engine.evaluate_listener(8080, "TCP", "/srv/app", local_address="127.0.0.1", exposure="PUBLIC")
        self.assertIs(decision.status, AuthStatus.UNKNOWN)

    def test_path_only_requires_explicit_operator_approval(self):
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([{"policy_id": "p", "port": 81, "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "executable": "/app"}], policy_revision="r")
        engine = CoreAuthorizationEngine([{"policy_id": "p", "port": 81, "exposure": "LOOPBACK", "mode": "EXECUTABLE_PATH_ONLY", "operator_approved": True, "executable": "/app"}], policy_revision="r")
        decision = engine.evaluate_listener(81, "TCP", "/app", local_address="127.0.0.1")
        self.assertFalse(decision.matching_attributes["verified_binary_identity"])

    def test_unknown_policy_fields_are_rejected(self):
        with self.assertRaises(PolicyConfigurationError):
            CoreAuthorizationEngine([{"policy_id": "p", "port": 81, "exposure": "LOOPBACK", "mode": "PORT_ONLY", "operator_approved": True, "surprise": True}], policy_revision="r", allow_port_only=True)

    def test_listener_validation_rejects_nonfinite_duration_wrong_time_and_bad_protocol(self):
        base = dict(protocol="TCP", local_address="127.0.0.1", local_port=90, process=None,
                    first_observed_utc="2026-01-01T00:00:00+00:00", last_observed_utc="2026-01-01T00:00:01+00:00",
                    duration_seconds=1, listening_state="LISTEN")
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(EventValidationError): ListenerIdentity(**{**base, "duration_seconds": bad})
        with self.assertRaises(EventValidationError): ListenerIdentity(**{**base, "protocol": "ICMP"})
        with self.assertRaises(EventValidationError): ListenerIdentity(**{**base, "local_address": "localhost"})
        with self.assertRaises(EventValidationError): ListenerIdentity(**{**base, "last_observed_utc": "2025-12-31T23:59:59+00:00"})

    def test_identity_assurance_never_treats_pid_only_as_strong(self):
        pid_only = ProcessIdentity(8, None, "/app", None, None, None)
        self.assertIs(pid_only.identity_assurance, IdentityAssurance.WEAK)
        partial = ProcessIdentity(8, None, "/app", None, None, "2026-01-01T00:00:00+00:00")
        self.assertIs(partial.identity_assurance, IdentityAssurance.PARTIAL)
        strong = ProcessIdentity(8, None, "/app", None, None, "2026-01-01T00:00:00+00:00", os_file_identity="dev:ino")
        self.assertIs(strong.identity_assurance, IdentityAssurance.STRONG)
        self.assertIs(ProcessIdentity(None, None, None, None, None, None).identity_assurance, IdentityAssurance.UNKNOWN)

    def test_running_image_hash_requires_provenance(self):
        with self.assertRaises(EventValidationError):
            ProcessIdentity(8, None, "/app", "a"*64, None, None, hash_subject="running_image")

    def test_concurrent_writer_instances_preserve_sequence_and_unique_ids(self):
        import tempfile, threading
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "events.jsonl")
            recorders = [EvidenceRecorder(path) for _ in range(4)]
            errors = []
            def run(index):
                try:
                    for i in range(12):
                        event = CanonicalEvent.create(event_type="writer", collection_source="test", confidence=ConfidenceLevel.OBSERVED,
                                                      authorization=AuthStatus.UNKNOWN, details={"writer": index, "i": i})
                        recorders[index].append(event)
                except Exception as exc: errors.append(exc)
            threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
            for t in threads: t.start()
            for t in threads: t.join()
            self.assertEqual([], errors)
            verified = EvidenceRecorder.verify_file(path)
            self.assertTrue(verified.valid, verified.errors)
            self.assertEqual(48, verified.last_sequence)

    def test_multiprocess_writers_preserve_sequence(self):
        import multiprocessing, tempfile
        from pathlib import Path
        def worker(path, marker):
            rec = EvidenceRecorder(path)
            for n in range(8):
                event = CanonicalEvent.create(event_type="writer", collection_source="test", confidence=ConfidenceLevel.OBSERVED,
                                               authorization=AuthStatus.UNKNOWN, details={"marker": marker, "n": n})
                rec.append(event)
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "events.jsonl")
            procs = [multiprocessing.Process(target=worker, args=(path, i)) for i in range(3)]
            for p in procs: p.start()
            for p in procs: p.join(10)
            self.assertTrue(all(p.exitcode == 0 for p in procs))
            verified = EvidenceRecorder.verify_file(path)
            self.assertTrue(verified.valid, verified.errors)
            self.assertEqual(24, verified.last_sequence)

    def test_signed_checkpoint_detects_rewritten_historical_journal(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            journal, anchor = Path(tmp) / "events.jsonl", Path(tmp) / "anchor.json"
            rec = EvidenceRecorder(str(journal))
            rec.append(CanonicalEvent.create(event_type="one", collection_source="test", confidence=ConfidenceLevel.OBSERVED, authorization=AuthStatus.UNKNOWN))
            lines = journal.read_text().splitlines()
            checkpoint_digest = json.loads(lines[0])["digest"]
            EvidenceRecorder.write_checkpoint(anchor, sequence=1, digest=checkpoint_digest, key=b"k"*32, signer_id="external-audit")
            # Rewrite complete journal as a valid different history, preserving local hash-chain validity.
            journal.unlink()
            fresh = EvidenceRecorder(str(journal))
            fresh.append(CanonicalEvent.create(event_type="rewritten", collection_source="test", confidence=ConfidenceLevel.OBSERVED, authorization=AuthStatus.UNKNOWN))
            result = EvidenceRecorder.verify_anchored_file(journal, anchor, b"k"*32)
            self.assertFalse(result.valid)
            with self.assertRaises(Exception): EvidenceRecorder.verify_checkpoint(anchor, b"x"*32)

    def test_restart_after_process_writer_exit_recovers_next_sequence(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "events.jsonl")
            rec = EvidenceRecorder(path)
            rec.append(CanonicalEvent.create(event_type="before", collection_source="test", confidence=ConfidenceLevel.OBSERVED, authorization=AuthStatus.UNKNOWN))
            reopened = EvidenceRecorder(path)
            self.assertEqual(2, reopened.append(CanonicalEvent.create(event_type="after", collection_source="test", confidence=ConfidenceLevel.OBSERVED, authorization=AuthStatus.UNKNOWN)))




class EvidenceJournalHardeningTests(unittest.TestCase):
    """Regressions for path, budget and cost defects in the evidence journal."""

    def make_event(self, **overrides):
        payload = dict(
            event_type="listener_snapshot",
            collection_source="unit-test",
            confidence=ConfidenceLevel.OBSERVED,
            authorization=AuthStatus.UNKNOWN,
            host_id="host-hardening-01",
        )
        payload.update(overrides)
        return CanonicalEvent.create(**payload)

    def test_lock_file_is_owner_only(self):
        import os
        import stat
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            recorder = EvidenceRecorder(str(path))
            recorder.append(self.make_event())
            lock = Path(str(path) + ".lock")
            self.assertTrue(lock.exists())
            mode = stat.S_IMODE(os.stat(lock).st_mode)
            self.assertEqual(0o600, mode)

    def test_planted_lock_symlink_is_refused_and_target_is_untouched(self):
        import os
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.txt"
            victim.write_text("do not touch", encoding="utf-8")
            path = Path(tmp) / "events.jsonl"
            os.symlink(victim, Path(str(path) + ".lock"))
            with self.assertRaises(EvidenceError):
                EvidenceRecorder(str(path))
            self.assertEqual("do not touch", victim.read_text(encoding="utf-8"))

    def test_repeated_appends_do_not_reverify_the_whole_journal(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            first = EvidenceRecorder(str(path))
            first.append(self.make_event())
            with patch.object(
                EvidenceRecorder, "verify_file", wraps=EvidenceRecorder.verify_file
            ) as spy:
                # Reopening an existing journal verifies it exactly once; further
                # appends by the same recorder must not re-read the whole file.
                recorder = EvidenceRecorder(str(path))
                for _ in range(6):
                    recorder.append(self.make_event())
                self.assertEqual(1, spy.call_count)
                self.assertEqual(7, recorder._sequence)

    def test_external_change_is_still_detected_on_next_append(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            recorder = EvidenceRecorder(str(path))
            recorder.append(self.make_event())
            with path.open("ab") as stream:
                stream.write(b'{"tampered": true}\n')
            # External mutation is detected on the next append and keeps failing,
            # rather than being appended after silently.
            with self.assertRaises(EvidenceError):
                recorder.append(self.make_event())
            with self.assertRaises(EvidenceError):
                recorder.append(self.make_event())

    def test_oversized_journal_line_fails_verification_instead_of_being_read(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_bytes(b"{" + b"x" * (MAX_JOURNAL_LINE_BYTES + 10) + b"}\n")
            verification = EvidenceRecorder.verify_file(path)
            self.assertFalse(verification.valid)
            self.assertIn("exceeds", verification.errors[0])

    def test_checkpoint_write_refuses_a_planted_temporary_symlink(self):
        import os
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.txt"
            victim.write_text("do not touch", encoding="utf-8")
            target = Path(tmp) / "checkpoint.json"
            os.symlink(victim, Path(str(target) + ".tmp"))
            with self.assertRaises(EvidenceIntegrityError):
                EvidenceRecorder.write_checkpoint(
                    target, sequence=1, digest="a" * 64, key=b"k" * 32, signer_id="tester"
                )
            self.assertEqual("do not touch", victim.read_text(encoding="utf-8"))

    def test_checkpoint_round_trip_is_owner_only_and_bounded(self):
        import os
        import stat
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "checkpoint.json"
            written = EvidenceRecorder.write_checkpoint(
                target, sequence=3, digest="b" * 64, key=b"k" * 32, signer_id="tester"
            )
            self.assertEqual(written["sequence"], 3)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(target).st_mode))
            self.assertEqual(
                3, EvidenceRecorder.verify_checkpoint(target, b"k" * 32)["sequence"]
            )
            target.write_bytes(b"{" + b"y" * (70 * 1024))
            with self.assertRaises(EvidenceIntegrityError):
                EvidenceRecorder.verify_checkpoint(target, b"k" * 32)

if __name__ == "__main__":
    unittest.main()
