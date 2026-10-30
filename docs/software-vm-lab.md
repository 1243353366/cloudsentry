# Software-only functional VM laboratory

You do not need a physical TPM chip to test software TPM behavior. OVMF/AAVMF firmware, QEMU, software TPM 2.0 (`swtpm`) and disposable disk images can exercise virtual firmware and snapshot features. They do **not** automatically reproduce a production host's hardware root of trust, effective guest isolation, firmware measurements, BMC behavior or physical-console recovery.

The `scripts/software-vm-lab.py` entry point is a separate, fresh-consent **trusted-fixture functional lab**, not a malware executor or a fallback controller. It accepts no customer sample, guest image, target host, endpoint, boot command, arbitrary firmware path or provider credential. No uploaded report can enable it.

## Manual invocation

Install reviewed distribution packages manually on a suitable Linux lab. The script does not install dependencies or change services. The current functional probe is ARM64-specific; it is not an automatic architecture compatibility layer.

On the tested Ubuntu ARM64 development sandbox, the prerequisites were installed using the distribution package manager: `qemu-system-arm`, `qemu-system-x86`, `qemu-utils`, `qemu-efi-aarch64`, `ovmf`, `swtpm`, `swtpm-tools`, `tpm2-tools` and `gnu-efi`. The firmware helper may need additional documented compiler/image tooling; use the report's actual version/source records, not a copied package list as assurance.

```sh
python3 scripts/software-vm-lab.py --consent
```

Omit `--consent` for an interactive default-deny prompt. Noninteractive execution without explicit permission starts nothing. Permission is scoped to this one fixed laboratory invocation; it does not approve a backup VM, persistent service, public listener or firmware flash. A one-run latch, expiry, revocation checks and interruption cleanup apply. The implementation uses a private temporary directory and local UNIX sockets; no third-party network target is probed.

## What the script tests

**Software TPM:** creates a disposable TPM 2.0 instance, performs startup and capability query, reads a resettable synthetic PCR, extends it using a fixed original fixture and verifies reset restores the initial value. It does not claim a physical TPM, guest-device attachment, signed remote attestation or an OS measured-boot event log.

**Offline disk snapshots:** creates a new 8 MiB qcow2 image, writes a known marker, snapshots it, changes and verifies data, restores the baseline and verifies the original marker, deletes the snapshot and checks image integrity. This is an actual disposable disk snapshot cycle, **not** a live guest-memory checkpoint, multi-disk consistency guarantee, backup verification or atomic TPM/NVRAM restore.

**Virtual firmware:** boots only the trusted local fixture via the separately bounded firmware helper. Firmware output and policy checks must be recorded exactly as observed. “The firmware ran,” “Secure Boot state was read” and “an unsigned image was rejected while an authorized image booted” are different claims. The runner does not invent a pass where a required check is unobserved.

All child tools use fixed reviewed arguments, clean environments and deadlines. Temporary TPM state, firmware variable copies and image files are private/disposable; cleanup occurs on normal completion and handled failure. SIGKILL, power loss, kernel failure or a compromised host are outside ordinary Python cleanup guarantees. Never run hostile guest content under software emulation as a substitute for a supported security boundary.

## How to interpret results

The sandbox has no `/dev/kvm`, so these firmware experiments use **QEMU TCG software emulation**, not hardware virtualization. QEMU explicitly does not offer the same guest-isolation/security guarantees for its non-virtualization use case. A successful functional test cannot approve adversarial code execution or prove a guest cannot escape.

The JSON output retains the scope, UTC time, measured duration, observed sub-results and explicit false fields for hardware isolation, customer-data use, production readiness and automatic failover. The report is evidence of the selected trusted local experiment only; an imported copy remains an unverified declaration unless independently authenticated.

Further tests still require a properly configured authorized lab: actual guest boot and service ordering; Secure Boot trust-chain controls; virtual TPM attachment and measured-boot logs; effective hypervisor/network/cgroup confinement; real application and memory-state recovery; EDR/SIEM visibility; controller failure; billing limits; and hardware console/firmware behavior where relevant. No defensible “90–95% coverage” estimate follows merely from installing this stack.

## Sources

[1]: https://github.com/stefanberger/swtpm "swtpm software TPM project"
[2]: https://libvirt.org/kbase/secureboot.html "Libvirt Secure Boot firmware and enrolled-key requirements"
[3]: https://www.qemu.org/docs/master/system/security.html "QEMU security requirements and non-virtualization limitations"

swtpm supplies software TPM interfaces [1]. Secure Boot requires both supporting firmware and suitable enrolled trust keys, not merely a firmware filename [2]. The trusted software-emulation experiment must not be represented as hardware-backed hostile-guest isolation [3].
