from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from reverse_shell_decoy.authorization import AuthorizationError, AuthorizationScope, request_authorization
from reverse_shell_decoy.backup_admission import (
    MAX_CONFIG_BYTES,
    make_libvirt_candidate,
    make_pc_free_candidate,
    review_libvirt,
    review_pc_free,
)


IMAGE = "ghcr.io/dockur/windows@sha256:" + "a" * 64
SESSION_ID = "0123456789abcdef"
SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "review-backup.py"


def pin(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_script():
    spec = importlib.util.spec_from_file_location("review_backup_script", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_static_result(test: unittest.TestCase, result: dict[str, object]) -> None:
    test.assertEqual(result["admission_code"], "STATIC_PROFILE_ACCEPTED")
    test.assertEqual(result["api_version"], "backup-admission/v2")
    test.assertTrue(result["profile_only"])
    test.assertFalse(result["ready_for_deployment"])
    test.assertEqual(result["machine_actions"], [])
    test.assertEqual(result["runtime_checks"], "unknown")
    test.assertEqual(result["source_authority"], "unverified")


class LibvirtAdmissionTests(unittest.TestCase):
    def test_generated_candidate_is_staticly_admitted(self) -> None:
        raw = make_libvirt_candidate(SESSION_ID).encode("utf-8")
        assert_static_result(self, review_libvirt(raw, pin(raw)))

    def test_rejects_network_host_and_management_nodes(self) -> None:
        original = make_libvirt_candidate(SESSION_ID)
        mutations = (
            '<interface type="network"/>',
            '<hostdev mode="subsystem" type="usb"/>',
            '<channel type="unix"/>',
            '<graphics type="vnc" port="5900"/>',
            '<filesystem type="mount"/>',
            '<controller type="usb"/>',
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                raw = original.replace("</devices>", mutation + "</devices>").encode("utf-8")
                self.assertEqual(review_libvirt(raw, pin(raw))["admission_code"], "SCHEMA_REJECTED")

    def test_rejects_qemu_arguments_and_wrong_disk_path(self) -> None:
        original = make_libvirt_candidate(SESSION_ID)
        qemu = original.replace(
            "<domain type=\"kvm\">",
            '<domain type="kvm" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0"><qemu:commandline/>',
        ).encode("utf-8")
        disk = original.replace(
            "/var/lib/libvirt/images/cloudsentry-backup-0123456789abcdef.qcow2",
            "/tmp/other.qcow2",
        ).encode("utf-8")
        self.assertEqual(review_libvirt(qemu, pin(qemu))["admission_code"], "XML_FORBIDDEN_CONSTRUCT")
        self.assertEqual(review_libvirt(disk, pin(disk))["admission_code"], "SCHEMA_REJECTED")

    def test_rejects_duplicate_attributes_forbidden_entities_and_nesting(self) -> None:
        duplicate = b'<domain type="kvm" type="qemu"/>'
        entity = b'<!DOCTYPE domain [<!ENTITY x "y">]><domain type="kvm">&x;</domain>'
        nested = (b"<x>" * 13) + (b"</x>" * 13)
        self.assertEqual(review_libvirt(duplicate, pin(duplicate))["admission_code"], "XML_INVALID")
        self.assertEqual(review_libvirt(entity, pin(entity))["admission_code"], "XML_FORBIDDEN_CONSTRUCT")
        self.assertEqual(review_libvirt(nested, pin(nested))["admission_code"], "XML_DEPTH_EXCEEDED")

    def test_pin_precedes_xml_parsing_and_bounded_input(self) -> None:
        raw = b"<not valid xml>password=not-reflected</not valid xml>"
        result = review_libvirt(raw, "0" * 64)
        self.assertEqual(result["admission_code"], "PIN_MISMATCH")
        self.assertEqual(result["config_sha256"], pin(raw))
        self.assertNotIn("password", json.dumps(result))
        oversized = b"x" * (MAX_CONFIG_BYTES + 1)
        self.assertEqual(review_libvirt(oversized, pin(oversized))["admission_code"], "INPUT_TOO_LARGE")


class PcFreeAdmissionTests(unittest.TestCase):
    def test_generated_candidate_is_staticly_admitted(self) -> None:
        raw = make_pc_free_candidate(IMAGE, SESSION_ID).encode("utf-8")
        assert_static_result(self, review_pc_free(raw, pin(raw)))

    def test_rejects_ports_tun_and_credential_environment(self) -> None:
        original = json.loads(make_pc_free_candidate(IMAGE, SESSION_ID))
        mutations = []
        ports = json.loads(json.dumps(original))
        ports["services"]["windows"]["ports"] = ["8006:8006"]
        mutations.append(ports)
        tun = json.loads(json.dumps(original))
        tun["services"]["windows"]["devices"].append("/dev/net/tun:/dev/net/tun")
        mutations.append(tun)
        credential = json.loads(json.dumps(original))
        credential["services"]["windows"]["environment"]["PASSWORD"] = "not-returned"
        mutations.append(credential)
        nested = json.loads(json.dumps(original))
        nested["services"]["windows"]["logging"]["options"]["path"] = "/host/log"
        mutations.append(nested)
        for mutation in mutations:
            raw = json.dumps(mutation, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.assertEqual(review_pc_free(raw, pin(raw))["admission_code"], "SCHEMA_REJECTED")

    def test_rejects_duplicate_json_giant_numbers_and_malformed_profile(self) -> None:
        duplicate = b'{"services":{},"services":{}}'
        giant = b'{"value":' + (b"9" * 32) + b"}"
        malformed = json.loads(make_pc_free_candidate(IMAGE, SESSION_ID))
        malformed["services"]["windows"]["network_mode"] = "bridge"
        malformed_raw = json.dumps(malformed, separators=(",", ":")).encode("utf-8")
        self.assertEqual(review_pc_free(duplicate, pin(duplicate))["admission_code"], "JSON_DUPLICATE_KEY")
        self.assertEqual(review_pc_free(giant, pin(giant))["admission_code"], "JSON_NUMBER_INVALID")
        self.assertEqual(review_pc_free(malformed_raw, pin(malformed_raw))["admission_code"], "SCHEMA_REJECTED")

    def test_invalid_pin_bounded_input_and_candidate_parameters(self) -> None:
        self.assertEqual(review_pc_free(b"{}", "not-a-sha")["admission_code"], "EXPECTED_CONFIG_SHA256_INVALID")
        oversized = b"x" * (MAX_CONFIG_BYTES + 1)
        self.assertEqual(review_pc_free(oversized, pin(oversized))["admission_code"], "INPUT_TOO_LARGE")
        with self.assertRaises(ValueError):
            make_pc_free_candidate("dockurr/windows:latest", SESSION_ID)
        with self.assertRaises(ValueError):
            make_pc_free_candidate(IMAGE, "not-a-session")


class BackupReviewCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = load_script()

    def _run_with_grant(self, argv: list[str], scope: AuthorizationScope) -> tuple[int, dict[str, object], object]:
        grant = request_authorization(scope, consent=True)
        assert grant is not None
        output = io.StringIO()
        with mock.patch.object(self.script, "request_authorization", return_value=grant), redirect_stdout(output):
            code = self.script.main(argv)
        return code, json.loads(output.getvalue()), grant

    def test_cli_libvirt_happy_path_and_mutation_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.xml"
            raw = make_libvirt_candidate(SESSION_ID).encode("utf-8")
            candidate.write_bytes(raw)
            expected = pin(raw)
            scope = AuthorizationScope("static_analysis", os.fspath(candidate), expected)
            code, result, _grant = self._run_with_grant(
                ["--backend", "libvirt", "--config", os.fspath(candidate), "--expected-sha256", expected, "--consent"], scope,
            )
            self.assertEqual(code, 0)
            assert_static_result(self, result)
            mutated = raw.replace(b"</devices>", b'<interface type="network"/></devices>')
            candidate.write_bytes(mutated)
            expected = pin(mutated)
            scope = AuthorizationScope("static_analysis", os.fspath(candidate), expected)
            code, result, _grant = self._run_with_grant(
                ["--backend", "libvirt", "--config", os.fspath(candidate), "--expected-sha256", expected, "--consent"], scope,
            )
            self.assertEqual(code, 2)
            self.assertEqual(result["admission_code"], "SCHEMA_REJECTED")

    def test_cli_pc_free_happy_path_and_mutation_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.json"
            raw = make_pc_free_candidate(IMAGE, SESSION_ID).encode("utf-8")
            candidate.write_bytes(raw)
            expected = pin(raw)
            scope = AuthorizationScope("static_analysis", os.fspath(candidate), expected)
            code, result, _grant = self._run_with_grant(
                ["--backend", "pc-free", "--config", os.fspath(candidate), "--expected-sha256", expected, "--consent"], scope,
            )
            self.assertEqual(code, 0)
            assert_static_result(self, result)
            mutated = json.loads(raw)
            mutated["services"]["windows"]["ports"] = ["3389:3389"]
            altered = json.dumps(mutated, separators=(",", ":")).encode("utf-8")
            candidate.write_bytes(altered)
            expected = pin(altered)
            scope = AuthorizationScope("static_analysis", os.fspath(candidate), expected)
            code, result, _grant = self._run_with_grant(
                ["--backend", "pc-free", "--config", os.fspath(candidate), "--expected-sha256", expected, "--consent"], scope,
            )
            self.assertEqual(code, 2)
            self.assertEqual(result["admission_code"], "SCHEMA_REJECTED")

    def test_cli_rejects_symlink_fifo_and_oversized_selected_input_and_revokes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "valid.xml"
            raw = make_libvirt_candidate(SESSION_ID).encode("utf-8")
            target.write_bytes(raw)
            link = base / "selected-link.xml"
            link.symlink_to(target)
            fifo = base / "selected.fifo"
            os.mkfifo(fifo)
            large = base / "large.xml"
            large.write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))
            for selected in (link, fifo, large):
                with self.subTest(selected=selected.name):
                    expected = pin(raw)
                    scope = AuthorizationScope("static_analysis", os.fspath(selected), expected)
                    code, result, grant = self._run_with_grant(
                        ["--backend", "libvirt", "--config", os.fspath(selected), "--expected-sha256", expected, "--consent"], scope,
                    )
                    self.assertEqual(code, 2)
                    self.assertEqual(result["admission_code"], "INPUT_UNAVAILABLE")
                    with self.assertRaises(AuthorizationError):
                        grant.check(scope)

    def test_cli_default_denial_and_candidate_permission_precedence(self) -> None:
        with mock.patch.object(self.script, "request_authorization", return_value=None), \
                mock.patch.object(self.script, "read_regular", side_effect=AssertionError("opened")), \
                mock.patch.object(self.script, "make_libvirt_candidate", side_effect=AssertionError("built")):
            self.assertEqual(
                self.script.main(["--backend", "libvirt", "--config", "selected.xml", "--expected-sha256", "0" * 64]), 2,
            )
            self.assertEqual(self.script.main(["--backend", "libvirt", "--emit-candidate"]), 2)

        scope = AuthorizationScope("static_analysis", "builtin:backup:libvirt", "")
        grant = request_authorization(scope, consent=True)
        assert grant is not None
        output = io.StringIO()
        with mock.patch.object(self.script, "request_authorization", return_value=grant), redirect_stdout(output):
            code = self.script.main(["--backend", "libvirt", "--emit-candidate", "--session-id", SESSION_ID, "--consent"])
        self.assertEqual(code, 0)
        self.assertIn("cloudsentry-backup-0123456789abcdef", output.getvalue())
        with self.assertRaises(AuthorizationError):
            grant.check(scope)


if __name__ == "__main__":
    unittest.main()
