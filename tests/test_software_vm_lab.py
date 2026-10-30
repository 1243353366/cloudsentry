import sys
import types
import unittest
from unittest.mock import patch

from reverse_shell_decoy.authorization import AuthorizationError, request_authorization
from reverse_shell_decoy import software_vm_lab as lab


class SoftwareVmLabTests(unittest.TestCase):
    def test_missing_authorization_runs_nothing(self):
        with patch.object(lab.subprocess, "Popen", side_effect=AssertionError("no process")):
            with self.assertRaises(AuthorizationError):
                lab.run_lab()

    def test_no_consent_cli_does_not_invoke_lab(self):
        with patch.object(lab, "request_authorization", return_value=None), \
                patch.object(lab, "run_lab", side_effect=AssertionError("no lab")), patch("sys.stderr"):
            self.assertEqual(lab.main([]), 2)

    def test_revoked_grant_cannot_start_a_lab(self):
        grant = request_authorization(lab.SCOPE, consent=True)
        grant.revoke()
        with patch.object(lab.subprocess, "Popen", side_effect=AssertionError("no process")):
            with self.assertRaises(AuthorizationError):
                lab.run_lab(authorization=grant)

    def test_missing_dependencies_revokes_authorization(self):
        grant = request_authorization(lab.SCOPE, consent=True)
        with patch.object(lab, "_TOOLS", ("cloudsentry-absent-tool",)):
            with self.assertRaises(RuntimeError):
                lab.run_lab(authorization=grant)
        with self.assertRaises(AuthorizationError):
            grant.check(lab.SCOPE)

    def test_command_revocation_happens_before_launch(self):
        with patch.object(lab.subprocess, "Popen", side_effect=AssertionError("no process")):
            def denied():
                raise AuthorizationError("revoked")
            with self.assertRaises(AuthorizationError):
                lab._command(["/usr/bin/qemu-img"], lab.Path("/tmp"), denied)

    def test_success_cleans_up_and_never_authorizes_deployment(self):
        grant = request_authorization(lab.SCOPE, consent=True)
        module = types.ModuleType("reverse_shell_decoy.uefi_functional")
        module.run_uefi_probe = lambda _work, check: {"firmware_boot_observed": True}
        with patch.object(lab, "_TOOLS", ()), \
                patch.object(lab, "_software_tpm", return_value={"passed": True}), \
                patch.object(lab, "_disk_snapshot", return_value={"passed": True}), \
                patch.dict(sys.modules, {"reverse_shell_decoy.uefi_functional": module}):
            result = lab.run_lab(authorization=grant)
        self.assertTrue(result["temporary_resources_removed"])
        self.assertFalse(result["backend_ready_for_deployment"])
        self.assertFalse(result["kvm_isolation_tested"])
        with self.assertRaises(AuthorizationError):
            grant.check(lab.SCOPE)

    def test_interrupted_tpm_path_cleans_up_and_revokes(self):
        grant = request_authorization(lab.SCOPE, consent=True)
        module = types.ModuleType("reverse_shell_decoy.uefi_functional")
        module.run_uefi_probe = lambda _work, check: {}
        with patch.object(lab, "_TOOLS", ()), \
                patch.object(lab, "_software_tpm", side_effect=AuthorizationError("interrupted")), \
                patch.object(lab, "_disk_snapshot", side_effect=AssertionError("no next stage")), \
                patch.dict(sys.modules, {"reverse_shell_decoy.uefi_functional": module}):
            with self.assertRaises(AuthorizationError):
                lab.run_lab(authorization=grant)
        with self.assertRaises(AuthorizationError):
            grant.check(lab.SCOPE)


if __name__ == "__main__":
    unittest.main()
