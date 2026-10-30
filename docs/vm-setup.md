# Create a disposable analysis VM manually

Use a **separate analysis host**, not a customer's everyday workstation, production server, cloud-key vault or the hosted CloudSentry portal. This is an optional customer-operated setup. CloudSentry does not create a VM, request infrastructure credentials or execute a sample automatically. Permission to create a VM is not permission to run malware or expose a listener.

A real VM reduces shared-runtime exposure but is not an absolute escape-proof boundary. This guide has been checked against hypervisor documentation, **not executed or security-certified on your hardware**. Real dynamic malware analysis, external guest telemetry, a verified VM controller and VM-escape testing are not delivered by the current scripts.

## 1. Prepare a dedicated Linux analysis host

The example uses an Ubuntu analysis host with KVM-capable hardware and a local graphical administration session. If using a remote host, use your existing restricted administrative access; do not expose a hypervisor, VNC console or libvirt daemon publicly. Virtualization must be enabled in firmware and supported by the host/cloud configuration. Do not disable security controls to work around a failed prerequisite. Ubuntu documents `kvm-ok` and libvirt installation [1].

On **that analysis host only**, after approving the installation:

```sh
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager virt-viewer cpu-checker
kvm-ok
```

Use a supported, patched host/hypervisor and leave its security confinement enabled. A libvirt administrator can control guests and advanced host resources; **never** give an analysis agent, guest, upload parser or sample the host's libvirt membership, socket, SSH key or administrative password. Ubuntu documents the additional group/privilege implications [1].

## 2. Create the guest in Virtual Machine Manager

Open `virt-manager` on the dedicated analysis host. Select the system QEMU/KVM connection and create a new virtual machine from **local install media**. Use an official Linux ISO whose checksum/signature you verified separately.

Name the new guest `cloudsentry-analysis`. An example lab allocation is **2 virtual CPUs, 2 GiB guest RAM and a new 20 GiB qcow2 virtual disk**. These values are not a measured safe budget or a guarantee against host exhaustion: hypervisor overhead, snapshots and disk growth need separate host quotas and monitoring. Choose **Customize configuration before install**.

Before the first boot:

- Remove all guest network-interface devices. Do not select default NAT, a LAN bridge, host-only networking, passthrough or port forwarding. The corresponding CLI option is `--network none`; omitting it ordinarily creates a NIC [2].
- Do not add a shared-filesystem device, host directory, raw host disk, USB/PCI passthrough or container socket. `--filesystem` deliberately exports a host directory and must not be used here [2].
- Disable shared clipboard, drag-and-drop, file transfer, USB redirection and guest-agent/SPICE communication channels. Use a locally attached console and do not store important console passwords in installation arguments. Review the effective XML rather than assuming GUI defaults are safe [2].
- Do not inject cloud metadata credentials, SSH keys, browser sessions or customer API keys. Guest accounts must have unrelated lab-only credentials.
- Disable VM autostart; do not install guest or host watchdogs that silently restart analysis. A separate trusted controller must eventually enforce any required deadline—no such controller is installed by this guide.

Install the OS offline from the ISO. Prepare reviewed tools and **benign fixtures** through a read-only ISO, not a shared host folder. Do not mount an untrusted guest disk on the host to inspect it or copy executable payloads back to a customer's device.

If trusted-image preparation needs updates, do it **before** accepting any untrusted samples in a separately controlled build process. Remove the NIC and verify the final offline configuration before taking the baseline. Do not reconnect an analysis guest to the Internet merely because a sample requests it.

## 3. Verify the effective boundary before analysis

On the analysis host:

```sh
virsh --connect qemu:///system dominfo cloudsentry-analysis
virsh --connect qemu:///system domiflist cloudsentry-analysis
virsh --connect qemu:///system dumpxml cloudsentry-analysis
```

`domiflist` must show **no guest network interface**. Review XML for the chosen memory/CPU/disk allocation and absence of host-filesystem, host-device, unsafe channel and network attachments. Keep the management connection outside the guest. Guest claims such as “no network” or “I am clean” are not independent evidence that these controls hold.

CloudSentry application byte/session limits do not enforce real VM CPU, RAM, disk, console, hypervisor or cloud-spending limits. Before any future dynamic analysis, an independently validated controller must enforce those controls and stop a guest when its deadline or integrity checks fail. If such controls are absent, stay with the non-executing options.

## 4. Save a clean, powered-off baseline

Shut down the prepared guest normally. Confirm the reported state is `shut off`:

```sh
virsh --connect qemu:///system domstate cloudsentry-analysis
virsh --connect qemu:///system snapshot-create-as \
  cloudsentry-analysis clean-baseline \
  --description "Reviewed offline guest before untrusted analysis"
virsh --connect qemu:///system snapshot-list cloudsentry-analysis
```

Use only storage/firmware configurations for which your installed hypervisor supports this snapshot. If it refuses, stop and use a separately managed clean-image/rebuild workflow; do not force past compatibility checks. A snapshot is a recovery point, not proof of integrity or an authenticity signature [3]. Keep evidence outside the disposable guest before any rollback.

## 5. Run only the implemented non-executing options

After explicitly choosing the reviewed VM, boot it from the trusted management console:

```sh
virsh --connect qemu:///system start cloudsentry-analysis
```

Inside the guest, from the reviewed CloudSentry source checkout, use a selected **text** sample:

```sh
python3 scripts/analyze-safely.py --sample /path/to/selected-text.txt --consent
python3 scripts/analyze-safely.py --sample /path/to/selected-text.txt --simulate --consent
```

Without `--consent`, a fresh interactive default-deny permission prompt applies. The first command returns bounded static labels and hashes. The second changes only the synthetic dictionary-based computer. Neither runs a real interpreter on the sample, monitors real malware, captures PCAP or proves that a real VM is safe.

**Important:** manually creating this VM does not activate a CloudSentry VM backend. `--require-vm` still refuses because no verified adapter/controller is configured. There is no automatic remote-VM connection or fallback to local execution. Real dynamic analysis remains unavailable; the customer-created VM is an additional place to run the existing static/synthetic options.

## 6. Preserve evidence and revert or retire deliberately

Preserve source digests, outside-guest controller records and available sanitized reports in a separate protected evidence location using a reviewed transfer process. Do not export executable samples as customer reports. Treat guest-produced records as untrusted and keep independent evidence separate.

For an ordinary completed, powered-off lab run, **rollback deletes guest changes**. Confirm the domain and preserve needed records first:

```sh
virsh --connect qemu:///system snapshot-revert cloudsentry-analysis clean-baseline
```

Do not add `--running` or `--force` by default. A powered-off baseline should remain inactive; re-check network/configuration before starting a new explicitly authorized run. A disposable per-run clone is preferable for future production research, but automatic cloning/cleanup is not implemented [3].

If the guest is suspected of violating isolation, an authorized host administrator can stop **that guest** immediately with:

```sh
virsh --connect qemu:///system destroy cloudsentry-analysis
```

This is the equivalent of abruptly cutting guest power; it can lose volatile evidence. It does **not** delete the disk, repair a potentially compromised analysis host or stop cloud charges [3]. Preserve available independent evidence and isolate/escalate through a trusted control plane. Do not trust a suspect host to certify its own recovery. Reprovision from a independently verified environment before further analysis. Review retention before deleting guest storage; this guide does not automatically delete any disk.

## References

[1]: https://documentation.ubuntu.com/server/how-to/virtualisation/libvirt/ "Ubuntu Server libvirt setup and management"
[2]: https://man.archlinux.org/man/virt-install.1 "virt-install networking, storage, console and resource options"
[3]: https://www.libvirt.org/manpages/virsh.html "libvirt virsh management, snapshot and termination semantics"
[4]: https://www.libvirt.org/securityprocess.html "libvirt security process and published security notices"
