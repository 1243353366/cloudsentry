# Backup workload: two inward-only echo surfaces

This workload is shared by the reviewed QEMU/libvirt and PC-Free-derived backup candidates. It is **not** a VM installer, traffic router, shell, callback, bridge or remote execution controller. The customer and a visitor can each connect to their own inward-facing port. Each accepted connection receives only its own submitted bytes; nothing is forwarded between ports or sent by initiating a new connection.

The names `operator` and `visitor` identify slots, not trusted identities. The operator slot has **no administrative privileges or VM controls**. Neither port establishes who connected, whether access was authorized, which OS they use or whether a compromise happened.

## Manual opt-in inside the isolated guest

First complete the [VM/PC-Free candidate hardening review](vm-backup-hardening.md) on a separate analysis host. Static profile admission does not approve deployment. A clean, patched guest, a separately trusted controller/deadline, disk-image review, host containment and any approved ingress still need validation. Do not run a backup on a customer workstation because a detector failed.

From the reviewed source checkout **inside the independently approved guest**:

```sh
# POSIX guest: clear inherited cloud/Python settings before running the workload.
sh scripts/backup-echo.sh --consent
```

A fresh interactive default-deny prompt is available by omitting `--consent`. Defaults are literal loopback `127.0.0.1`, operator-check port **8022** and visitor port **8023**. Both bindings are covered by one exact configuration hash and one fresh scoped grant. Noninteractive runs without explicit permission open no port. Successful permission is not a VM attestation.

For an independently hardened Windows guest with reviewed Python 3.10+, use `python scripts/start-backup-echo.py --consent` from a clean lab account with no cloud/provider credentials. That Windows runtime path has not been boot-tested here. The direct entry point rejects known credential-bearing environments rather than storing or forwarding keys; the list is a defense in depth, not discovery of every possible secret.

Public/non-loopback binding needs **both** fresh invocation consent and `--allow-public`, for example `--host 0.0.0.0 --allow-public`. This alone does not create a safe route. A no-NIC guest cannot receive remote traffic. Do not weaken the disconnected VM candidate simply to make it reachable. A separately reviewed guest-ingress design, approved firewall/egress rules and a trusted proxy/broker are prerequisites for remote visitors; that broker is not provisioned by these scripts. Never expose QMP, libvirt, RDP, VNC, SPICE or a Docker socket to visitors.

The two ports must be different and unprivileged. Arbitrary hostnames, target/controller addresses, forwarding commands, response-mode overrides and callback parameters are not supported. No detector, uploaded flag, login, admission report or smoke-test result starts the workload or changes routing automatically.

## Fixed limits, no fallback escalation

Each surface has a 30-second lifetime, one active session, two lifetime connection attempts, five-second sessions, two-second idle timeout, at most five chunks, one chunk per second and 32 audit records. It admits at most 4 KiB input and reserves at most 4 KiB output per surface, with 2 KiB input per session. Combined admission/reservation budgets are therefore at most **8 KiB each**. These application counters are not physical ingress, CPU/memory, wire-delivery or cloud-billing meters.

The first surface failure/stop ends the pair instead of restarting, switching to a console or launching a second environment. A second-port bind failure closes the first. Both services close on permission revocation or expiry; the supervisor rechecks at most every 50 ms while scheduled normally. Reads already completed or bytes already queued cannot be undone. Revocation does not provide a real-time scheduling or hostile-host guarantee.

Audits stay on operator stderr as limited metadata, timestamps and chunk hashes, never raw commands. The service does not echo audit records to visitors. Preserve the stream privately with your reviewed no-overwrite logging procedure and keep original evidence separate from synthetic regression output. Raw echoed bytes can contain terminal-control sequences; do not display untrusted echoes directly in an operator terminal or pass them to another interpreter.

A host/controller compromise, lost hardware isolation or possible hypervisor escape calls for external incident response, not another local permission flag. No workflow promises “nothing can ever reach the customer device.”

## Smoke every implemented layer, then test the smoke harness

```sh
python3 scripts/smoke-backup-layers.py --consent
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_backup*.py' -v </dev/null
```

The harness covers candidate-configuration admission, two real disposable **loopback** echo surfaces, the existing emergency sink and opaque mirror regressions. It additionally runs an intentionally failing test and verifies that empty/skipped/failed/duplicate/fabricated-VM results cannot be labelled successful. The deliberate failure is a negative control, not a hidden passing assertion. A missing test file or incomplete suite is not accepted as success.

Results include fixed scope labels, counts, test-file hashes and explicit unknowns. **Actual QEMU/Windows boot, hypervisor confinement, disk backing-chain validation, ingress policy, failover/controller loss and billing controls are not tested by this local harness.** Its output always says `runtime_vm_boot_tested: false`, `backend_ready_for_deployment: false` and `automatic_failover_authorized: false`. It cannot turn a static candidate into an approved live backend.

See [adversarial assurance](adversarial-assurance.md), [evidence packet verification](security-behavior.md) and [fallback layer ownership](fallback-layers.md).
