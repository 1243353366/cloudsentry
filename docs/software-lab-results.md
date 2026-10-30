# Software-only laboratory results and release limits

The initial [15-section assessment](backup-lab-assessment.md) recorded the development environment before virtualization packages were installed. The subsequent trusted-fixture experiment narrows that blocker: **a physical TPM is not required for software TPM testing, and software emulation can exercise firmware and disposable image operations.** It does not establish KVM-backed hostile-guest isolation.

The later Ubuntu ARM64 sandbox experiment installed reviewed distribution QEMU 8.2.2, OVMF/AAVMF, swtpm, TPM tools and GNU-EFI. No `/dev/kvm`, customer guest, physical TPM, GPU, BMC or Openterface hardware was used. No uploaded/hostile payload was executed.

## Measured outcomes

- **Software TPM 2.0:** startup and fixed capability query passed over private UNIX sockets. Synthetic PCR 16 changed after a fixed fixture extension and returned to its initial value after reset. This is not a physical-TPM, guest-attachment, measured-OS-boot or remote-attestation result.
- **Offline qcow2 snapshot:** a newly created 8 MiB disposable image passed known-data write, baseline snapshot, changed-data verification, restore, original-data verification, snapshot deletion and image consistency checks. No customer disk, live guest-memory checkpoint or atomic TPM/NVRAM recovery was tested.
- **Firmware fixture:** AAVMF was invoked with fixed TCG arguments, no NIC, no monitor, a read-only generated media directory and private firmware variable copies. The required original probe's completion marker was **not observed** in the measured run. The enrolled-key variant emitted a firmware security-violation indication, but that alone does not prove rejection of an otherwise working probe or a complete Secure Boot trust-chain test. Firmware/probe hashes were recorded. Secure Boot enforcement remains **unknown**, and the current runner reports a **partial** result/non-success exit rather than a green pass.
- **Containment:** temporary software TPM/image resources were removed on the completed run. No hostile-guest escape resistance, customer-host protection, physical console, production EDR, ingress broker, external spend control or automatic failover was established.

## Implementation findings

The native ARM64 GNU-EFI startup object already includes a PE/COFF header. The fixture builder was corrected to emit its linked binary with objcopy's output-only `-O binary` option instead of ambiguously specifying both input/output formats. That code correction is not substituted for successful firmware observation: the result stays partial until the required marker and appropriate negative controls are actually measured.

The customer report separately preserves selected input hashes and labels all supplied lab/resource flags **unverified**. Unknown resource enforcement is not reported as a passing limit. A configuration or source pin is change-detection evidence, not independent authentication or deployment authorization.

Use [the manual software lab guide](software-vm-lab.md) to reproduce the fixed trusted experiment. Additional equipment is needed only where the specific test concerns actual hardware, physical-console behavior or hardware-backed isolation; no percentage of assessment coverage is claimed from merely choosing an open-source stack.
