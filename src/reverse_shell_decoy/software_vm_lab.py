"""Trusted-fixture functional tests only: no customer guest or hostile samples.

Software TPM, offline image snapshots and QEMU/TCG firmware behavior can be
exercised without a physical TPM. TCG is not treated as a hostile-guest isolation
boundary; successful output never authorizes deployment or failover.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Callable

from .authorization import (AuthorizationError, AuthorizationGrant, AuthorizationScope,
                            cancellation_guard, request_authorization)

SCOPE = AuthorizationScope("software_vm_lab", "builtin:trusted-functional-vm-lab-v1")
_TOOLS = ("swtpm", "tpm2_startup", "tpm2_getcap", "tpm2_pcrread", "tpm2_pcrextend",
          "tpm2_pcrreset", "qemu-img", "qemu-io", "qemu-system-aarch64", "gcc", "ld", "objcopy")


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def _command(args: list[str], work: Path, check: Callable[[], None], timeout: float = 5) -> str:
    check()
    started = time.monotonic()
    with subprocess.Popen(args, cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(work)}) as child:
        try:
            while True:
                check()
                if time.monotonic() - started > timeout:
                    raise RuntimeError("functional command deadline")
                try:
                    output, _ = child.communicate(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    continue
            check()
            if child.returncode != 0 or len(output) > 65536:
                raise RuntimeError("functional command did not pass")
            return output.decode("utf-8", errors="replace")
        finally:
            _stop(child)


def _software_tpm(work: Path, check: Callable[[], None]) -> dict:
    state = work / "state"
    state.mkdir(mode=0o700)
    socket_path = work / "tpm.sock"
    check()
    with open(work / "tpm.log", "xb") as log:
        process = subprocess.Popen([
            "/usr/bin/swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state},mode=0600",
            "--ctrl", f"type=unixio,path={socket_path}.ctrl,mode=0600",
            "--server", f"type=unixio,path={socket_path},mode=0600", "--flags", "not-need-init",
        ], cwd=work, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        try:
            deadline = time.monotonic() + 2
            while not socket_path.is_socket():
                check()
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("software TPM startup failed")
                time.sleep(0.02)
            transport = ["-T", f"swtpm:path={socket_path}"]
            _command(["/usr/bin/tpm2_startup", "-c", *transport], work, check)
            capabilities = _command(["/usr/bin/tpm2_getcap", "properties-fixed", *transport], work, check)
            if 'value: "2.0"' not in capabilities or "TPM2_PT_FAMILY_INDICATOR" not in capabilities:
                raise RuntimeError("software TPM family not established")
            before = _command(["/usr/bin/tpm2_pcrread", "sha256:16", *transport], work, check)
            fixture_digest = hashlib.sha256(b"CloudSentry trusted synthetic PCR fixture").hexdigest()
            _command(["/usr/bin/tpm2_pcrextend", f"16:sha256={fixture_digest}", *transport], work, check)
            changed = _command(["/usr/bin/tpm2_pcrread", "sha256:16", *transport], work, check)
            _command(["/usr/bin/tpm2_pcrreset", "16", *transport], work, check)
            restored = _command(["/usr/bin/tpm2_pcrread", "sha256:16", *transport], work, check)
            if before == changed or before != restored:
                raise RuntimeError("software TPM PCR control failed")
            return {"passed": True, "kind": "software_tpm_2_0", "startup_and_capabilities": True,
                    "pcr16_extend_changes_value": True, "pcr16_reset_restores_value": True,
                    "physical_tpm_tested": False, "guest_tpm_device_attachment_tested": False,
                    "measured_guest_boot_or_attestation_tested": False,
                    "transport": "private_local_unix_sockets", "state_retained": False}
        finally:
            _stop(process)


def _disk_snapshot(work: Path, check: Callable[[], None]) -> dict:
    image = str(work / "trusted.qcow2")
    commands = (
        ["/usr/bin/qemu-img", "create", "-q", "-f", "qcow2", image, "8M"],
        ["/usr/bin/qemu-io", "-f", "qcow2", "-c", "write -P 0x41 0 4096", image],
        ["/usr/bin/qemu-img", "snapshot", "-c", "baseline", image],
        ["/usr/bin/qemu-io", "-f", "qcow2", "-c", "write -P 0x42 0 4096", image],
        ["/usr/bin/qemu-io", "-f", "qcow2", "-c", "read -P 0x42 0 4096", image],
        ["/usr/bin/qemu-img", "snapshot", "-a", "baseline", image],
        ["/usr/bin/qemu-io", "-f", "qcow2", "-c", "read -P 0x41 0 4096", image],
        ["/usr/bin/qemu-img", "snapshot", "-d", "baseline", image],
        ["/usr/bin/qemu-img", "check", "-q", image],
    )
    for command in commands:
        _command(command, work, check)
    return {"passed": True, "kind": "disposable_offline_qcow2", "snapshot_created": True,
            "changed_data_verified": True, "restored_data_verified": True,
            "snapshot_deleted": True, "image_integrity_check": True,
            "live_guest_checkpoint_tested": False, "tpm_nvram_atomic_recovery_tested": False,
            "customer_disk_accessed": False, "image_retained": False}


def run_lab(*, authorization: AuthorizationGrant | None = None) -> dict:
    if type(authorization) is not AuthorizationGrant:
        raise AuthorizationError("fresh functional-lab authorization required")
    authorization.begin(SCOPE)
    started = time.monotonic()

    def check() -> None:
        authorization.check(SCOPE)
        if time.monotonic() - started > 120:
            raise RuntimeError("functional lab overall deadline")

    try:
        check()
        if any(not (Path("/usr/bin") / tool).is_file() for tool in _TOOLS):
            raise RuntimeError("functional lab dependencies unavailable")
        from .uefi_functional import run_uefi_probe
        # Short private paths keep UNIX socket names within the OS length bound.
        with tempfile.TemporaryDirectory(prefix="cslab-", dir="/tmp") as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            tpm = root / "tpm"
            disk = root / "disk"
            firmware = root / "uefi"
            for selected in (tpm, disk, firmware):
                selected.mkdir(mode=0o700)
            software_tpm = _software_tpm(tpm, check)
            snapshot = _disk_snapshot(disk, check)
            uefi = run_uefi_probe(firmware, check=check)
            uefi.pop("report_path", None)
            check()
            firmware_passed = uefi.get("uefi_boot_observed") is True and uefi.get("secure_boot_enforcement") == "verified"
            result = {"format": "trusted_software_vm_lab_v1", "provider": "local",
                      "status": "complete" if firmware_passed else "partial",
                      "passed": firmware_passed,
                      "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                      "elapsed_seconds": round(time.monotonic() - started, 3),
                      "scope": "trusted_fixture_functional_only", "accelerator": "tcg",
                      "software_tpm": software_tpm, "offline_disk_snapshot": snapshot, "uefi": uefi,
                      "physical_hardware_tested": False, "kvm_isolation_tested": False,
                      "hostile_guest_executed": False, "customer_data_used": False,
                      "backend_ready_for_deployment": False, "automatic_failover_authorized": False}
        check()
        result["temporary_resources_removed"] = not root.exists()
        return result
    finally:
        authorization.revoke()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--consent", action="store_true")
    args = parser.parse_args(argv)
    grant = request_authorization(SCOPE, consent=args.consent)
    if grant is None:
        print("Permission required; functional lab not started.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(grant):
            result = run_lab(authorization=grant)
            print(json.dumps(result, sort_keys=True))
        return 0 if result.get("passed") is True else 2
    except (AuthorizationError, RuntimeError, OSError, ValueError, ImportError, KeyboardInterrupt):
        print("Functional lab unavailable, interrupted or failed; no deployment was authorized.", file=sys.stderr)
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
