# Backup VM hardening: static admission only

This repository retains two **review-only** configuration grammars, not an active backup platform. The libvirt profile is the preferred disconnected minimal-Linux candidate. The PC-Free-derived Docker profile is retained only as a separately reviewed offline candidate because its published defaults were materially broader: an unpinned image, `NET_ADMIN`, KVM and TUN access, published web/RDP ports, writable host-oriented mounts, and automatic restart are not admitted here. The GitHub virtual-machine topic was discovery context only; it is not a configuration, security, image, or operational authority. [1]

Both paths are intentionally incomplete for runtime use. `backup_admission` proves only that a selected document is under 64 KiB, matches a local exact grammar, and has the operator-provided SHA-256 pin. It does not inspect a disk or image, contact a registry, invoke Docker/libvirt/QEMU/KVM, open a host socket, run a guest, obtain credentials, or provision a provider resource. Every accepted result has `profile_only: true`, `ready_for_deployment: false`, `machine_actions: []`, `runtime_checks: "unknown"`, and `source_authority: "unverified"`.

## Static API and review command

The only public builders and reviewers are pure functions:

```python
make_libvirt_candidate(session_id)
review_libvirt(raw, expected_sha256)
make_pc_free_candidate(image_digest, session_id)
review_pc_free(raw, expected_sha256)
```

A session ID is exactly 16 lowercase hexadecimal characters. Candidate builders return XML or JSON text only. A reviewer requires the externally computed exact document SHA-256 before it parses the document; a mismatch returns `PIN_MISMATCH` before decoding XML or JSON. Results contain fixed status fields and hashes only, never raw configuration text, paths, parsed environment values, or error details.

The command line is likewise static and opt-in. It uses the repository authorization gate with operation `static_analysis`; review scopes identify the selected config through `os.fspath(config)` and the expected pin, while built-in candidate scopes are `builtin:backup:libvirt` or `builtin:backup:pc-free` with an empty output reference. `--consent` is a per-invocation acknowledgement, not runtime deployment approval.

```sh
python scripts/review-backup.py --backend libvirt --config candidate.xml \
  --expected-sha256 "EXTERNALLY_COMPUTED_64_LOWERCASE_HEX" --consent

python scripts/review-backup.py --backend libvirt --emit-candidate --session-id 0123456789abcdef --consent
```

The script reads a selected config only through `read_regular`, refuses symlinks, devices, FIFOs, races, and inputs above 64 KiB, writes no files, and revokes its grant in all normal/error paths. Candidate emission requires authorization before identity generation or output. There are deliberately no Docker `up`, `virsh define`, `virsh start`, QEMU, KVM, registry, or cloud-provider commands in this document.

## Libvirt candidate grammar

The libvirt candidate is a fixed `domain type="kvm"` document. It defines a two-vCPU, 2 GiB `q35`/`hvm` guest with a `cputune` period and quota of `100000`. These quota fields apply per vCPU, not as an aggregate one-CPU limit: two vCPUs can consume up to two CPU budgets, and emulator/host overhead needs separate limits. Effective aggregate cgroup enforcement remains an external runtime requirement. `on_poweroff`, `on_reboot`, and `on_crash` are all `destroy`; no configuration enables an automatic restart. Libvirt documents `domain` as the root VM element, supports `kvm` as a domain type, and documents the disk and CPU-tuning constructs used by this narrow grammar. [2]

Its single disk must be `qcow2` at exactly `/var/lib/libvirt/images/cloudsentry-backup-<session-id>.qcow2`, and the same identity is required in the domain name and disk filename. The grammar has no `<interface>`, `<graphics>`, `<hostdev>`, `<channel>`, USB controller, filesystem share, secret, second disk, host block device, serial/console, monitor, or QEMU command line. XML names, attributes, child order, and values must normalize to the generated tree. Namespaces, XInclude, processing instructions, comments, CDATA, DTDs, and entities are rejected before parsing; `ElementTree` construction is capped at 64 nodes and depth 12.

Only strict UTF-8 XML without NUL bytes is admitted. Alternate encodings such as UTF-16 are rejected before tree construction, so they cannot hide DTD/entity tokens from the pre-parse guard. JSON parsing likewise requires UTF-8, rejects duplicate keys and bounds numbers/nesting. Missing permission exits nonzero before reading or generating anything.

No network interface in the domain means the XML defines no published service, RDP/VNC endpoint, or management channel. The separate [shared `backup_echo` workload](backup-echo.md), if used, must be manually run inside an independently reviewed guest baseline for two **guest-loopback-only** echo ports. This XML neither creates nor validates those listeners. Guest credentials, guest setup, and any management access remain a separate offline baseline process.

A qcow2 filename and `driver type="qcow2"` are not proof that the image is self-contained. qcow2 metadata can refer to a backing file, and this checker intentionally does not open or inspect the image. Libvirt documents explicit `backingStore` structures, while a real image can also carry backing metadata outside this XML. [2] Therefore disk-chain state, ownership, SELinux/AppArmor labels, effective QEMU UID, and host cgroup enforcement remain unknown until independently verified.

## PC-Free candidate grammar

The PC-Free candidate accepts only `ghcr.io/dockur/windows` or `docker.io/dockurr/windows` with a full lowercase `@sha256:` digest. It has exactly one `windows` service, `restart: "no"`, `network_mode: "none"`, `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]`, the sole device `/dev/kvm:/dev/kvm`, read-only root storage, two vCPUs, a 3 GiB container memory limit, PID limit 256, and bounded local logs. It forbids all published ports, networks, TUN, extra devices, `cap_add`, privileged mode, host namespace settings, build instructions, entrypoint/command overrides, profiles, external environment files, labels, health checks, bind mounts, secrets, sockets, shared/OEM paths, and credentials.

The only allowed environment map is `NETWORK=N`, `RAM_SIZE=2G`, `CPU_CORES=2`, and `VERSION=11`. The upstream environment reference documents `NETWORK=N` as disabling guest networking and documents the three fixed resource/version names. [4] It does not document a `SHARED` setting, so this profile does not invent one. The sole persistent storage mount is a generated dedicated named volume at `/storage` with `nocopy: true`; `/run`, `/tmp`, and `/var/tmp` are fixed bounded tmpfs mounts.

This is not a claim that the image will boot, is available offline, has no installer/download behavior, honors all desired guest controls, or can run with read-only root storage. The PC-Free candidate remains disabled for operational deployment until a separately controlled, deadline-bounded review proves a preinstalled offline baseline and verifies the relevant runtime behavior. No automatic dependency download is permitted by this review component.

## Preconditions before any independent runtime decision

A successful static result is never enough to launch either candidate. An external controller must record an approval deadline and current authority; no `--consent` flag confers that authority. Independent reviewers must verify host KVM availability, libvirt/QEMU confinement, QEMU/libvirt versions, cgroup/resource policy, image provenance and ownership, qcow2 backing chains, image contents, guest credentials, guest shutdown behavior, actual network absence, host firewall/provider controls, billing limits, and recovery/destruction procedures. They must also decide whether the host and provider policy permit guest code at all.

QEMU’s security guidance treats guests, user-facing interfaces, network protocols, user-supplied disk images, and passthrough devices as untrusted. It also emphasizes least privilege and management-tool confinement, and cautions that QEMU memory use can exceed assigned guest RAM. [3] Those are runtime and host-control concerns, not properties established by this static admission check. In this environment neither Docker nor KVM boot testing has been performed.

**References**

[1]: https://github.com/topics/virtual-machine "GitHub virtual-machine topic page"
[2]: https://libvirt.org/formatdomain.html "Libvirt domain XML format"
[3]: https://www.qemu.org/docs/master/system/security.html "QEMU security guidance"
[4]: https://raw.githubusercontent.com/dockur/windows/master/docs/environment.md "Dockur Windows environment variables"
