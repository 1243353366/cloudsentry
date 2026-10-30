"""Bounded, trusted-only ARM64 UEFI firmware functional probe.

This module has no CLI and intentionally accepts no guest payload, disk, network,
USB device, host path, or QEMU argument from its caller.  Its caller is responsible
for fresh authorization, scope, and a private fresh work directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import time
from typing import Any, Callable

_QEMU = Path("/usr/bin/qemu-system-aarch64")
_GCC = Path("/usr/bin/aarch64-linux-gnu-gcc")
_LD = Path("/usr/bin/aarch64-linux-gnu-ld")
_OBJCOPY = Path("/usr/bin/aarch64-linux-gnu-objcopy")
_CRT = Path("/usr/lib/crt0-efi-aarch64.o")
_LDSCRIPT = Path("/usr/lib/elf_aarch64_efi.lds")
_LIBDIR = Path("/usr/lib")
_INCLUDE = Path("/usr/include/efi")
_AARCH64_INCLUDE = _INCLUDE / "aarch64"
_AAVMF = Path("/usr/share/AAVMF")
_PLAIN_CODE = _AAVMF / "AAVMF_CODE.no-secboot.fd"
_PLAIN_VARS = _AAVMF / "AAVMF_VARS.fd"
_SECURE_CODE = _AAVMF / "AAVMF_CODE.secboot.fd"
_SECURE_VARS = _AAVMF / "AAVMF_VARS.ms.fd"

# Each child is stopped before 14 seconds.  This leaves termination/reap time while
# keeping the two-variant wall-time ceiling below 30 seconds.
_TIMEOUT_SECONDS = 14.0
_POLL_SECONDS = 0.05
_MAX_SERIAL_BYTES = 64 * 1024
_BEGIN = b"CLOUDSENTRY_UEFI_PROBE_BEGIN"
_END = b"CLOUDSENTRY_UEFI_PROBE_END"
_SECURITY_VIOLATION = b"Security Violation"

# This is compiled into an EFI application created under the caller's private workdir.
# It contains no input mechanism and prints only fixed labels and firmware state bytes.
_PROBE_C = r'''/* SPDX-License-Identifier: BSD-2-Clause */
#include <efi.h>
#include <efilib.h>

static EFI_GUID tcg2_protocol_guid = {
    0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}
};

static UINT8 variable_byte(CHAR16 *name, UINT8 fallback) {
    UINT8 value = fallback;
    UINTN size = sizeof(value);
    EFI_STATUS status = RT->GetVariable(name, &gEfiGlobalVariableGuid, NULL, &size, &value);
    return EFI_ERROR(status) ? fallback : value;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table) {
    VOID *tcg2 = NULL;
    EFI_STATUS tpm_status;
    InitializeLib(image, system_table);
    Print(L"CLOUDSENTRY_UEFI_PROBE_BEGIN\r\n");
    Print(L"CLOUDSENTRY_UEFI_SECUREBOOT=%d\r\n", variable_byte(L"SecureBoot", 255));
    Print(L"CLOUDSENTRY_UEFI_SETUPMODE=%d\r\n", variable_byte(L"SetupMode", 255));
    tpm_status = BS->LocateProtocol(&tcg2_protocol_guid, NULL, &tcg2);
    Print(L"CLOUDSENTRY_UEFI_TCG2=%s\r\n", EFI_ERROR(tpm_status) ? L"absent" : L"present");
    Print(L"CLOUDSENTRY_UEFI_PROBE_END\r\n");
    return EFI_SUCCESS;
}
'''


class UefiFunctionalUnavailable(RuntimeError):
    """Raised where a fixed, trusted tool or firmware artifact is unavailable."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_directory(workdir: Path) -> Path:
    """Create one private new child without reading or importing caller files."""
    if not isinstance(workdir, Path) or not workdir.is_absolute():
        raise ValueError("workdir must be an absolute Path")
    if workdir.is_symlink() or not workdir.is_dir():
        raise ValueError("workdir must be a real directory")
    run_dir = workdir / "uefi-functional"
    try:
        run_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ValueError("workdir must be fresh for the UEFI probe") from exc
    return run_dir


def _require_fixed_files(paths: tuple[Path, ...]) -> None:
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise UefiFunctionalUnavailable("fixed UEFI toolchain or AAVMF firmware unavailable")


def _run_tool(args: list[str], check: Callable[[], None]) -> None:
    """Run a fixed, noninteractive build command with no inherited standard streams."""
    check()
    completed = subprocess.run(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, close_fds=True, timeout=_TIMEOUT_SECONDS,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    check()
    if completed.returncode:
        raise UefiFunctionalUnavailable("trusted EFI probe build failed")


def _compile_probe(run_dir: Path, check: Callable[[], None]) -> tuple[Path, str]:
    source = run_dir / "uefi_probe.c"
    obj = run_dir / "uefi_probe.o"
    shared = run_dir / "uefi_probe.so"
    bundle = run_dir / "efi-bundle"
    probe = bundle / "EFI" / "BOOT" / "BOOTAA64.EFI"
    source.write_text(_PROBE_C, encoding="ascii", newline="\n")
    os.chmod(source, 0o600)
    _run_tool([
        os.fspath(_GCC), "-I", os.fspath(_INCLUDE), "-I", os.fspath(_AARCH64_INCLUDE),
        "-fpic", "-fshort-wchar", "-mstrict-align", "-ffreestanding", "-fno-stack-protector",
        "-fno-stack-check", "-fno-merge-constants", "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables", "-c", os.fspath(source), "-o", os.fspath(obj),
    ], check)
    _run_tool([
        os.fspath(_LD), "-nostdlib", "-znocombreloc", "-shared", "-Bsymbolic",
        f"-L{_LIBDIR}", "-T", os.fspath(_LDSCRIPT), os.fspath(_CRT), os.fspath(obj),
        "-o", os.fspath(shared), "-lefi", "-lgnuefi",
    ], check)
    probe.parent.mkdir(parents=True, mode=0o700)
    # ARM64 GNU-EFI's crt0 supplies a PE/COFF header in .text.head already.
    # Emit that binary instead of wrapping it in a second incompatible PE header.
    _run_tool([
        os.fspath(_OBJCOPY), "-j", ".text", "-j", ".sdata", "-j", ".data",
        "-j", ".dynamic", "-j", ".dynsym", "-j", ".rel", "-j", ".rela", "-j", ".rel.*",
        "-j", ".rela.*", "-j", ".reloc", "-O", "binary",
        os.fspath(shared), os.fspath(probe),
    ], check)
    # The embedded shell looks only for this fixed, generated instruction.  It is part
    # of the same directory-backed FAT volume and is exported read-only to the guest.
    (bundle / "startup.nsh").write_bytes(b"fs0:\\EFI\\BOOT\\BOOTAA64.EFI\r\n")
    os.chmod(bundle / "startup.nsh", 0o600)
    return probe, _sha256(probe)


def _qemu_command(code: Path, vars_copy: Path, bundle: Path, serial: Path) -> list[str]:
    """Return the only QEMU invocation this helper permits (TCG is not an isolation boundary)."""
    return [
        os.fspath(_QEMU), "-accel", "tcg", "-machine", "virt", "-cpu", "cortex-a57",
        "-m", "256", "-smp", "1", "-nic", "none", "-display", "none", "-monitor", "none",
        "-serial", f"file:{serial}",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_copy}",
        "-drive", f"if=none,id=trustedefi,format=raw,readonly=on,file=fat:ro:{bundle}",
        "-device", "virtio-blk-device,drive=trustedefi",
    ]


def _child_limits() -> None:
    # QEMU only needs the serial file, firmware files, and the generated FAT directory.
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1.0)


def _serial_snapshot(serial: Path) -> tuple[bytes, bool]:
    try:
        with serial.open("rb") as handle:
            content = handle.read(_MAX_SERIAL_BYTES + 1)
    except FileNotFoundError:
        return b"", False
    return content[:_MAX_SERIAL_BYTES], len(content) > _MAX_SERIAL_BYTES


def _run_qemu(command: list[str], serial: Path, check: Callable[[], None]) -> dict[str, Any]:
    """Poll a fixed serial file, respecting cancellation and always reaping QEMU."""
    check()
    started = time.monotonic()
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, start_new_session=True, preexec_fn=_child_limits,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    snapshot, truncated, observed_end, timed_out = b"", False, False, False
    try:
        deadline = started + _TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            check()
            snapshot, truncated = _serial_snapshot(serial)
            if _END in snapshot:
                observed_end = True
                break
            if process.poll() is not None:
                break
            time.sleep(_POLL_SECONDS)
        else:
            timed_out = True
        check()
    finally:
        # A cancellation callback may raise at any point above; cleanup still happens.
        _stop_process(process)
    check()
    snapshot, final_truncated = _serial_snapshot(serial)
    elapsed = time.monotonic() - started
    return {
        "duration_seconds": round(elapsed, 6),
        "timed_out": timed_out,
        "probe_begin_observed": _BEGIN in snapshot,
        "probe_end_observed": observed_end or _END in snapshot,
        "firmware_security_violation_observed": _SECURITY_VIOLATION in snapshot,
        "serial_sha256": hashlib.sha256(snapshot).hexdigest(),
        "serial_bytes_captured": len(snapshot),
        "serial_truncated": truncated or final_truncated,
        "qemu_returncode": process.returncode,
    }


def _variant(run_dir: Path, name: str, code: Path, vars_template: Path, bundle: Path,
             check: Callable[[], None]) -> dict[str, Any]:
    vars_copy, serial = run_dir / f"{name}.vars.fd", run_dir / f"{name}.serial"
    shutil.copyfile(vars_template, vars_copy)
    os.chmod(vars_copy, 0o600)
    result = _run_qemu(_qemu_command(code, vars_copy, bundle, serial), serial, check)
    result.update({
        "name": name,
        "firmware_code_sha256": _sha256(code),
        "firmware_vars_template_sha256": _sha256(vars_template),
        "probe_marker_required": True,
    })
    return result


def run_uefi_probe(workdir: Path, check: Callable[[], None] = lambda: None) -> dict[str, Any]:
    """Execute at most two 15-second trusted firmware boots and return non-raw evidence.

    ``check`` is the parent authorization/cancellation callback.  It is invoked before
    every tool launch, at <=50 ms while QEMU runs, and after child cleanup.  Exceptions
    are deliberately propagated after the QEMU child has been terminated and reaped.
    TCG acceleration is used solely for compatibility and is not a security boundary.
    """
    if not callable(check):
        raise ValueError("check must be callable")
    started = time.monotonic()
    report: dict[str, Any] = {
        "status": "unavailable",
        "real_firmware_attempted": False,
        "accelerator": "tcg",
        "hardware_isolation": False,
        "network": "disabled (-nic none)",
        "external_sockets": False,
        "guest_media": "generated probe and fixed startup instruction only; exported read-only",
        "secure_boot_enforcement": "unknown",
        "limitation": "TCG is not a hardware-isolation boundary; no signed positive plus unsigned-probe rejection is asserted.",
    }
    run_dir: Path | None = None
    try:
        check()
        _require_fixed_files((_QEMU, _GCC, _LD, _OBJCOPY, _CRT, _LDSCRIPT, _PLAIN_CODE,
                              _PLAIN_VARS, _SECURE_CODE, _SECURE_VARS))
        run_dir = _private_directory(workdir)
        probe, probe_sha = _compile_probe(run_dir, check)
        report["probe_sha256"] = probe_sha
        report["real_firmware_attempted"] = True
        # Plain firmware is the positive boot: the fixed unsigned app must emit its end marker.
        plain = _variant(run_dir, "plain_unsigned_probe", _PLAIN_CODE, _PLAIN_VARS,
                         probe.parents[2], check)
        report["plain"] = plain
        # Key-enrolled firmware is only enforcement evidence if it rejects this app itself.
        # On this AAVMF build its embedded shell may be rejected first; that is explicitly unknown.
        secure = _variant(run_dir, "enrolled_keys_unsigned_probe", _SECURE_CODE, _SECURE_VARS,
                          probe.parents[2], check)
        report["enrolled_keys"] = secure
        report["uefi_boot_observed"] = bool(plain["probe_end_observed"])
        negative_ran = bool(secure["probe_begin_observed"] or secure["probe_end_observed"])
        report["negative_unsigned_probe_ran"] = negative_ran
        report["secure_boot_enforcement"] = "unknown"
        if plain["probe_end_observed"]:
            report["status"] = "observed" if negative_ran else "observed_with_secure_boot_limit"
        else:
            report["status"] = "probe_marker_not_observed"
    except UefiFunctionalUnavailable:
        report["status"] = "unavailable"
    except subprocess.TimeoutExpired:
        report["status"] = "tool_timeout"
    except OSError:
        report["status"] = "unavailable"
    finally:
        report["duration_seconds"] = round(time.monotonic() - started, 6)
        # The report intentionally contains no serial text, private path, prompt, or host identity.
        if run_dir is not None:
            report_path = run_dir / "report.json"
            report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            os.chmod(report_path, stat.S_IRUSR | stat.S_IWUSR)
            report["report_path"] = os.fspath(report_path)
    return report
