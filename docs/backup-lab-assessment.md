# CloudSentry backup containment assessment

**Assessment date:** 2026-10-30 UTC. **Scope:** development-sandbox software/configuration assessment; not a customer-host, running-hypervisor, firmware or hardware penetration test.

**Release posture: keep runtime deployment disabled.** The local software checks passed. A successful VM boot, secure boot, guest/host containment, physical-console safety and real snapshot/recovery behavior have not been established.

## 1. Scope

The customer authorized defensive hardening and finite testing of CloudSentry's manually selected fallback components. Implemented work merges conservative QEMU/KVM/libvirt and PC-Free-derived offline configuration candidates, two independent echo-only guest ports, fresh authorization, the existing silent sink/mirror, and a smoke harness with failure controls. The requested Openterface KVM-GO is a separate physical administrator console. VMBoot is a firmware-research candidate, not an installed backend.

No customer machine, cloud account, remote listener, real guest, USB device, firmware flash, provider resource or third-party website was accessed as a test target. No exploit, guest escape, resource-exhaustion attack, intrusive network probe, disk deletion, snapshot rollback or production security-policy change was performed. The controller does not automatically provision or reroute when a detector fails.

**Evidence classification:** `observed` means recorded locally; `configuration-only` means a generated/parsed intended setting; `not measured` means no runtime evidence. Passing a synthetic/configuration check is never upgraded to runtime containment proof. All findings below refer to this development scope, not to an unseen customer's security posture.

## 2. Environment Inventory

Observed at **2026-10-30 18:04:01 UTC**:

| Component | Recorded state | Evidence class |
|---|---|---|
| Visible sandbox OS/kernel | Ubuntu 24.04.5 LTS; kernel `6.18.38+` | Observed sandbox identity only |
| Visible architecture / CPU | `aarch64`; physical CPU model unavailable | Observed / unknown |
| Python | 3.12.3 | Observed |
| KVM device | `/dev/kvm` unavailable | Observed blocker |
| Docker / libvirt CLI | Neither available | Observed blocker |
| Hypervisor platform/version | No tested runtime; QEMU/libvirt and container image versions not verified | Not measured |
| Host security patch level | Not established by OS/version strings | Not measured |
| Primary guest OS/patch level | Intended minimal Linux baseline; no guest provisioned | Configuration intent / not measured |
| Backup guest OS/patch level | Windows 11 selection in constrained candidate; no Windows guest provisioned | Configuration intent / not measured |
| Primary guest CPU/RAM | 2 vCPU, 2 GiB; quota/period 100000 | Configuration-only; quota is per vCPU, not an aggregate one-CPU guarantee |
| Backup resource caps | 2 CPUs, 3 GiB container memory, PID limit 256, bounded tmpfs/log configuration | Configuration-only |
| Storage | Primary identity-matched qcow2 path; backup dedicated named volume | Contents, disk chain, capacity and quotas not measured |
| Networking | Candidates define no NIC / `network_mode: none` | Configuration-only; no deployed firewall/routing audit |
| Security/monitoring tools | Python unit tests and Gitleaks used locally; no EDR/AV inventory | Observed tools / EDR unknown |
| Logs | Disposable service-test metadata; smoke/source hashes; no raw customer payloads | Observed software behavior only |
| Snapshot/backup strategy | Manual clean-baseline plan; no snapshot, restore or backup executed | Not measured |
| Physical console | Openterface unit not attached/tested | Not measured |
| Firmware boot | VMBoot/coreboot/u-root/gokvm not installed, flashed or booted | Not measured |

The visible sandbox is ARM64, whereas the conservative libvirt grammar currently targets x86_64/q35. Installing a CLI alone would not make this a suitable hardware-accelerated boot-test host. Do not silently substitute software emulation for the required isolation boundary.

## 3. Test Methodology

Only trusted local source, original synthetic fixtures and disposable loopback sockets were used. The complete suite completed **323 tests, zero failures/errors**. A focused `test_backup*.py` run completed **32 tests**, zero failures/errors. Counts overlap and must not be added to imply independent coverage.

The independently reported smoke layers completed:

| Layer | Executed tests | Outcome | Actual VM boot? |
|---|---:|---|---|
| Primary VM configuration admission | 5 | Passed | No |
| PC-Free backup configuration admission | 4 | Passed | No |
| Two real loopback echo surfaces | 10 | Passed | No |
| Emergency sink | 6 | Passed | No |
| Opaque mirror / permission paths | 19 | Passed | No |

The smoke harness also passed **14 controls**, including an intentionally failing test, rejection of absent/skipped/failed/duplicate results and rejection of fabricated VM-attestation flags. Boot/USB admission mutations were additionally rejected; those tests are configuration tests, not physical hardware tests.

Source hashes are recorded for eight relevant runtime/helper files and compared before/after smoke execution. They support local reproducibility and change detection, not authorship, trusted execution, signature verification or independent attestation. Store the report and its hash outside the analysis guest under your incident-evidence procedure.

Reproduce manually, with fresh consent:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -q </dev/null
python3 scripts/smoke-backup-layers.py --consent
```

Working-tree secret scanning passed with redacted findings enabled. Public CI may be queued independently; local success is not represented as a completed remote matrix or a real hypervisor audit.

## 4. System Architecture

```text
Dedicated administrator console -- physical KVM-GO --> dedicated analysis host
  [privileged, manually controlled; not available to guest/visitor]

Reviewed source + externally pinned config
       |
       v
Consent-gated static candidate review -- fixed status/hashes only
       |
       X  no provisioning / no firmware execution / no automatic routing

Independent lab approval and runtime isolation review REQUIRED
       |
       v
Customer-prepared guest: either QEMU/libvirt OR separate PC-Free-derived runtime
       |
       +-- operator-check port 8022 --> echo only to that accepted connection
       +-- visitor port 8023        --> echo only to that accepted connection
                 no forwarding between slots; no outgoing callback

Outside-guest controller/evidence/deadline/egress enforcement: separately required
VMBoot firmware experiment: disabled, separate research boundary
```

This is the intended trust-boundary design, not a map of deployed infrastructure. A no-NIC guest has no remotely reachable visitor path. Remote ingress would require a separately reviewed broker/network design; it is not provided or validated by these profiles.

## 5. Boot Assessment

**Blocked:** no supported KVM runtime, guest image, appropriate host or physical device is attached. No power-on sequence, UEFI/BIOS behavior, Secure Boot, TPM, measured boot, guest authentication, security-service ordering, boot failure, interrupted recovery or reboot persistence was observed.

The following is a **future evidence timeline**, not measured event times:

| Event | Required external record | Current result |
|---|---|---|
| Approval and host baseline | Signed scope, deadline, host/kernel/hypervisor versions | Not measured |
| Power-on/firmware | UTC plus monotonic sequence, firmware provenance | Not measured |
| Secure Boot / TPM | Guest and host evidence; expected policy and keys | Not measured |
| Kernel and service initialization | Boot journal/security service order and startup scripts | Not measured |
| Echo workload admission | Fresh grant, config/source hashes, actual endpoint inventory | Local invocation paths tested only |
| Interrupted boot / reboot | Independent controller logs and security-control persistence | Not measured |
| Shutdown/deadline | External stop evidence, resource release, logging continuity | Local service cleanup tested only |

The primary candidate does not assert Secure Boot or vTPM configuration. Adding unreviewed firmware/kernel/initrd/boot arguments is rejected. Do not enable those features by bypassing admission; extend and re-assess the policy deliberately on the correct lab host.

## 6. Isolation Assessment

| Communication path | Purpose/necessity | Current policy | Risk if enabled / hardening |
|---|---|---|---|
| Shared clipboard / drag-and-drop | Operator convenience; unnecessary for echo | No integration added; runtime unknown | Content/keystroke transfer; disable and test both directions |
| Shared folders / filesystem | File exchange; unnecessary for visitor echo | Rejected by exact profile grammar | Host-data access; no customer mounts |
| USB / HID / host-device passthrough | Local maintenance only | Guest additions rejected | Privileged input/device access; KVM-GO outside guest |
| Printers / GPU / extra disks | Not needed by this workload | Extra device grammar rejected | Expanded driver/device surface; remove unless separately approved |
| Guest agent / serial / monitor | Management convenience | Visitor-accessible additions rejected | Host-management access; isolate trusted controller |
| Time synchronization | Evidence alignment may require it | No added channel; actual behavior unknown | Record skew and separate source times; do not infer correlation from timestamps alone |
| Memory sharing / guest tools | Runtime-dependent | Not verified | Disable unnecessary sharing; verify effective runtime and versions |
| Guest boot media / firmware | OS startup | One constrained disk path; no unreviewed boot hook | Disk contents/backing chain remain unverified; inspect independently |

Configuration rejection establishes only the narrow admitted document grammar. It does not establish effective host/guest isolation, absence of implicit runtime devices, confinement policy or immunity to escape.

## 7. Network Assessment

Actual tests used temporary **127.0.0.1** listeners only. Clients received their own binary bytes, not banners, raw audit data, another client's input or executed output. Revocation/startup-failure checks verified closure of both local surfaces. The default supervisor never initiates a connection to the operator or visitor listener.

NAT, bridges, host-only networks, internal networks, DNS, gateway, address assignments, external firewall rules, management interfaces and monitoring channels of a deployed guest were **not inventoried**. Do not confuse `network_mode: none` in a candidate with measured host/provider segmentation. The echo response is outbound traffic on an already accepted socket; this is not a “zero packets transmitted” claim.

Before any remote exposure, document each interface, addresses/routes/DNS/gateway, permitted sources, the independently reviewed ingress broker, egress-deny enforcement and protected management path. Validate deny behavior without touching third-party systems. Never expose RDP/VNC/QMP/libvirt/Docker sockets through visitor routing.

## 8. Security Control Assessment

| Control | Software evidence | Effective runtime rating |
|---|---|---|
| Fresh permission / exact scope | Missing/wrong/reused/revoked grants tested; denied CLI exits nonzero | In-process guard only; compromised Python/host can bypass |
| Least-privilege candidate grammar | Extra boot/device/network/command/credential fields rejected | Host UID, AppArmor/SELinux/seccomp not measured |
| Fixed service resource budgets | Local byte/session/deadline/cleanup regressions passed | No CPU/memory/storage/cloud-spend guarantee |
| Secret handling | Clean-environment launcher, known credential-name refusal, redacted source scan | Not discovery of every possible secret |
| AV / EDR / host firewall | No production control queried | Not assessed |
| Hypervisor/image supply chain | Externally pinned config; PC-Free image syntax requires digest | Actual image content, provenance and versions unverified |
| Firmware/physical console | No visitor HID/flash adapter; additions rejected | Hardware/device security not assessed |

Numerical 1–5 runtime-control ratings are **not assigned** without measured coverage, reliability, visibility, maintainability and detection evidence. Unknown is not zero and is not a passing score.

## 9. Monitoring Assessment

The local tests exercise audit loss, source hash references, permission boundaries and metadata-only reflection. No production monitoring platform, EDR integration, alert pipeline or independent outside-guest collector was connected. Detection effectiveness, false-positive/false-negative rates and operator response times are unknown.

The visibility scorecard is therefore: local metadata generation **tested**; test/source references **tested**; outside-guest collection **not measured**; alert delivery **not measured**; searchability/retention **not measured**; security-tool startup/reboot persistence **not measured**. No aggregate visibility score is computed from unknown controls.

## 10. Logging Assessment

Local smoke evidence includes UTC generation time, fixed scope labels, test counts, source/test hashes and explicit `runtime_vm_boot_tested: false`, `openterface_hardware_tested: false`, `backend_ready_for_deployment: false`, and `automatic_failover_authorized: false`.

The existing private evidence-packet verifier requires a separately supplied manifest pin. Hashes detect disagreement against that pin; they do not prove original event truth, attacker identity, unauthorized access or a valid legal chain of custody. Guest logs, synthetic state, actual socket observations and customer-provided logs must retain distinct provenance.

Production retention, searchable hypervisor/host/guest/security/authentication logs, trusted time, log access controls and alert correlation remain unmeasured. Preserve originals separately, record collection/transfer actions and do not paste attacker-controlled screen text into a physical console.

## 11. Risk Matrix

Do not manufacture empirical likelihood/exploitability scores for an absent deployment. The following are **release-readiness gates**, not proven vulnerabilities on a customer system:

| Gate | Evidence | Likelihood / impact / detection / exploitability / operational score | Priority |
|---|---|---|---|
| Runtime/host isolation not validated | No KVM, Docker/libvirt CLI, suitable x86 boot host or guest | All unmeasured | P0: block deployment |
| Ingress and external stop authority absent | No routing/proxy/failover adapter implemented | All unmeasured | P0: no visitor exposure |
| Disk/image/backing chain not inspected | Checkers deliberately parse config only | All unmeasured | P0: verify baseline first |
| Boot/security/snapshot/recovery evidence absent | No real guest lifecycle performed | All unmeasured | P1 before operational use |
| Firmware and physical-console paths untested | No hardware or firmware execution performed | All unmeasured | P1 before enabling these paths |
| Production monitoring/retention unverified | Only local synthetic metadata tested | All unmeasured | P1 before operational use |

For a future measured assessment, record each 1–5 rating with evidence and assessor rationale. Detection must have a declared direction: 5 = strongest detection, so use `6 - D` for detection deficit. A proposed transparent raw score is `L + I + E + O + (6 - D)`; a proposed weighted priority index is `0.20L + 0.30I + 0.20E + 0.20O + 0.10(6-D)`. These are proposed prioritization formulas, not validated risk probabilities or scores computed here. Any missing rating leaves both scores unassigned.

## 12. Findings

**Implemented strengths:** independent static reviewers; separate operator/visitor sockets; exact-scope revocable invocation; no callback or cross-slot forwarding; opaque same-connection reflection; local budgets and paired cleanup; explicit static-versus-runtime labels; negative-control smoke tests; source hashes; and no firmware/HID/host-control adapter reachable from customer content.

**Integration defects corrected and regression-tested:** a permission-denied candidate CLI returned a success exit code; Python equality could accept integer `1` for a required Boolean volume control; alternate XML encodings needed rejection before DTD/entity scanning; and direct script execution needed a source-checkout import bootstrap. These are engineering findings about the new implementation, not evidence of an intrusion.

**Unresolved gates:** actual boot/isolation, guest baseline and image supply chain, physical console, firmware, networking, host confinement, recovery, monitoring and external spend controls remain unverified. The strict Windows candidate may refuse to boot with its read-only/offline/capability constraints. Do not relax them silently to produce a green screen.

**Change management:** exact configuration pins and source hashes detect document/file changes, but no organization patch policy, signed release process, hypervisor security update SLA, drift daemon, offline backup or live rollback program was audited. A dependency/digest being pinned is not proof it is supported or patched.

## 13. Recommended Remediations

**P0 — before any operational VM or visitor routing:** supply a documented isolated lab on a suitable hardware-virtualization host; establish independent external controller/deadline/stop authority; review patched runtime and confinement; independently authenticate and inspect each prepared disk/image/backing chain; confirm no production secrets/host mounts; and keep configuration review, administration and guest content as separate authority domains.

**P1 — before production approval:** collect the complete measured boot timeline, effective device/network/resource inventory, real cgroup enforcement and storage quota evidence; test benign workload/service failures, revocation, controller loss and logging failure; verify management/egress deny paths; validate snapshot creation/restore/deletion on disposable data and log the exact baseline; measure RTO/log continuity; and validate EDR/alerts/search/retention. Use simulations or capped harmless loads, not uncontrolled host starvation.

**P1 — physical/firmware options:** execute the positive and negative [Openterface checks](openterface-console.md) only on expendable authorized hardware. Keep [VMBoot](vmboot-boundary.md) disabled until its board-specific firmware/rollback/boot requirements have been independently assessed; do not flash a customer device as an automatic fallback.

**P2 — operational ownership:** assign patch/credential/incident response owners, release review and rollback procedures, evidence retention/access policies and recurring revalidation after every relevant image, firmware, hypervisor or routing change. Test service/controller interruption and stale approvals, not only happy paths.

## 14. Executive Summary

The software-only fallback components are now modular, manually invoked and deny unreviewed configuration/authority. All 323 local tests passed, the five software smoke layers passed and the harness detected its own deliberately failing control. Customer and visitor check ports remain independent echoes; no incoming content becomes a host command, VM selection, firmware flash or administrative input.

The critical limitation is unchanged: **these results do not establish a running safe VM**. The development sandbox cannot perform the requested x86/KVM boot or physical-device validation. Estimated remediation complexity is low-to-moderate for software/runbook controls and high/platform-dependent for trustworthy lifecycle, ingress/controller, firmware and hardware assurance. These are qualitative engineering estimates, not project schedules or cost quotes.

## 15. Final Verdict

**Runtime isolation: not established; deployment remains blocked.** No positive “isolation appears effective” conclusion is justified for an unbooted guest. Within the requested three-category framework, **“Isolation requires improvement” applies only to incomplete release readiness and validation evidence**, not to a proven escape or compromise of any customer VM.

The tested software boundary behaved as specified under the finite cases executed. Absolute claims such as “cannot be tricked,” “no errors are possible,” “cannot escape” or “nothing can ever touch the customer device” remain unsupported. Preserve that distinction in customer-facing summaries, admission decisions and future incident evidence.

### Reproducible evidence and sources

The delivered inventory and smoke JSON are separate development evidence, not incident telemetry. The smoke result generated at **2026-10-30T18:04:16.761039Z** had SHA-256 `40406f49a2eaa3ec8847cdc226180212cbe3b3594f1e796b29001301b81c5b91`; regenerating a report legitimately changes its time and hash. Verify against your separately retained copy, not a hash an untrusted sender supplies alongside modified bytes.

Design references: [QEMU security](https://www.qemu.org/docs/master/system/security.html), [libvirt domain XML](https://libvirt.org/formatdomain.html), [PC-Free defaults](https://github.com/jephersonRD/PC-Free), [Dockur Windows](https://github.com/dockur/windows), [Openterface hardware](https://github.com/TechxArtisanStudio/Openterface_KVM-GO_Hardware), [Openterface wiring/input documentation](https://docs.openterface.com/tutorial/kvm/01-getting-started/), and [VMBoot concept](https://github.com/9elements/VMBoot). Upstream statements describe their projects, not certification of CloudSentry's runtime.
