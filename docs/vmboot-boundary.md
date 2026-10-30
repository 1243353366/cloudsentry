# VMBoot: firmware research candidate, not an approved fallback

The user-selected [9elements/VMBoot project][1] is a proof of concept for booting TianoCore/EDK2 using coreboot, LinuxBoot/u-root and the Go-based `gokvm` hypervisor. Its README describes reaching an EFI shell, experimental u-root integration, block/network VirtIO support and a Supermicro platform marked work in progress. Its setup includes building firmware and **flashing the target's firmware chip**. [1]

That is a different role from Openterface's physical administrator console, QEMU/libvirt VM lifecycle management, the PC-Free-derived Windows runtime or a TCP echo service. Sharing “VM” or “KVM” in a name does not make these interchangeable security boundaries.

## How it fits the merged design

Keep the current conservative QEMU/libvirt profile as the primary VM **configuration candidate**, the separately constrained PC-Free-derived profile as an optional Windows **configuration candidate**, and the bounded echo workload as the only visitor data plane. The [Openterface console](openterface-console.md) remains a privileged, local administrator path outside guests. VMBoot is an additional **disabled firmware research candidate**; it does not supply a production runtime to either echo slot.

No visitor bytes, uploaded configuration, detector result or smoke report may select a firmware image, enumerate host block devices, mount partitions, invoke u-root/gokvm, flash firmware or type commands through physical HID. This repository adds no VMBoot execution adapter, download/build hook, shell command, firmware image or passthrough device. Unrecognized firmware/boot/kernel/command-line additions fail the current exact VM configuration grammar rather than extending it automatically.

## What must be independently established first

Use separate expendable hardware, not a customer workstation or an analysis host holding production keys. A specialist must confirm the supported board and CPU virtualization features, signed or otherwise independently authenticated source/build inputs, firmware image provenance and exact hashes, recovery/rollback hardware, guest device isolation, host privileges, resource limits and controller failure behavior. Keep the privilege to flash or select boot media outside every guest and every content-analysis process. A firmware recovery path must be proven before considering a flash; a USB keyboard/video console is not necessarily a firmware programmer or power cutoff.

A firmware/hash inventory is not attestation of the running system. Reaching EFI or echoing bytes does not prove isolation, secure boot, malware resistance, protected DMA, rollback correctness or absence of a hypervisor escape. None of these VMBoot hardware/runtime properties has been tested in this sandbox, and its presence in a GitHub topic is not validation.

No firmware changes were performed. `--require-vm` remains unavailable until a separately implemented and verified backend exists. The [layer smoke harness](backup-echo.md#smoke-every-implemented-layer-then-test-the-smoke-harness) tests configuration rejection and finite loopback services, **not VMBoot boot/firmware behavior**. A green result cannot enable this candidate.

## References

[1]: https://github.com/9elements/VMBoot "VMBoot concept, experimental status, platform and firmware-flashing prerequisites"
[2]: https://9esec.io/blog/vmboot-poc/ "VMBoot authors' firmware virtualization proof of concept"
