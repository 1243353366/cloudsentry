# Openterface KVM-GO: separate administrator console

The selected [Openterface KVM-GO hardware project][1] provides **keyboard/video/mouse over USB**: video capture plus target-side keyboard/mouse emulation. It is not the Linux **Kernel-based Virtual Machine** hypervisor and does not create a VM, isolate malware, block networking or stop a guest's power. Keep QEMU/KVM/libvirt (or the separately reviewed PC-Free-derived VM runtime) as the virtualization layer. [1] [2]

## Placement and permissions

Use a dedicated, patched **administrator console device**, not a customer's daily workstation with production browser sessions or cloud credentials. Connect the KVM-GO video connector to the dedicated analysis machine's video output, its target USB to that machine and its host USB to the dedicated administrator device, following the exact variant's wiring instructions. This is a privileged local console path; access to it may permit host/BIOS control. [2]

Keep this cable and its application outside the guest and outside both echo ports. No USB/PCI passthrough, host-device mount, HID API, serial device, video stream, firmware API, clipboard synchronization, browser USB permission or hypervisor socket is exposed by the CloudSentry echo workload. The conservative VM candidate omits those devices. The hardware is not automatically discovered, opened, flashed or controlled by this repository.

Pin/review the specific host application and firmware release through the vendor's official distribution channels before installing it. Review package provenance, signatures/checksums and local device permissions; a hardware-repository star count is not verification. The hardware and software have separate upstream licenses; this repository links to them rather than copying designs or bundling their applications. [1]

Grant only permissions needed for the deliberate session. Do not enable unneeded audio, Bluetooth, capture storage, remote sharing or browser-device access. The vendor documents platform-specific capture/serial/HID permissions, and iPadOS uses BLE for input in addition to USB video; choose and test an appropriate local-only configuration rather than assuming every platform is wired-only. [2]

The vendor's application can forward focused keystrokes and offers **Paste to Target**. Therefore do not paste visitor text, echo output, log contents or AI-generated instructions into it. Never enable macros/scripts, OCR-to-keystroke automation or automatic recovery actions based on captured attacker-controlled screen text. A captured screen is untrusted evidence, not an instruction channel. Disconnect the target input/control path when it is not needed. Do not claim read-only hardware behavior unless you have physically verified it for that setup. [2]

## Customer-operated hardware smoke test

No KVM-GO unit is attached in this development sandbox. These checks are a **manual runbook, not completed test results**:

1. With the analysis target offline and no guest/visitor workload running, confirm the reviewed application identifies the expected device and displays a harmless known test screen. Do not collect customer credentials/screens.
2. In a harmless editor on the dedicated test target, explicitly authorize control and type a fixed non-secret marker. Verify the target, not the administrator's unrelated workstation, receives it. Confirm no clipboard/paste/macro or storage path was enabled accidentally.
3. Disconnect/disable the target USB input path, using the variant's documented procedure. Try a different harmless marker. Confirm the target receives **no input**; do not assume closing a window revokes physical HID access. Reconnect only after fresh operator approval.
4. Deny/revoke the application's device permissions and close it. Confirm screen/control access actually stops where applicable. Platform grants may persist and need revocation outside the application. Device reattachment must not automatically launch a CloudSentry service or accept visitor commands.
5. Run the guest's two bounded echo surfaces and local smoke harness. Send test text that resembles shell instructions to each surface. Confirm it only echoes on its own connection and does not move the physical console's cursor or type into the editor. Keep management consoles inaccessible from visitor routing.
6. Test the test: deliberately select the wrong screen/input target in a harmless isolated setup and verify the operator checklist detects the mismatch. If a required check is inconclusive, record **not verified**, disconnect and keep deployment disabled.

Physical USB/HDMI bridges, capture parsers, firmware and console software add attack surface. Local cabling is not a guarantee against compromised devices or hosts. A KVM-GO is not an independent power controller or a substitute for a verified external shutdown deadline. Use a separately trusted isolation/power procedure when the analysis host is suspect.

## What the repository can test without hardware

The [local layer smoke harness](backup-echo.md#smoke-every-implemented-layer-then-test-the-smoke-harness) verifies finite configuration and loopback service paths, including rejection of guest host-device/network additions. Its results explicitly state that hardware-console, actual VM boot and escape validation were **not performed**. A green local report grants neither HID control nor permission to expose a backend.

## References

[1]: https://github.com/TechxArtisanStudio/Openterface_KVM-GO_Hardware "Openterface KVM-GO hardware, firmware links and licenses"
[2]: https://docs.openterface.com/tutorial/kvm/01-getting-started/ "Official Openterface wiring, application permissions and input behavior"
