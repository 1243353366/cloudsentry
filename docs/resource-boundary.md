# Fixed echo resource boundary

`resource_boundary` is a narrow, customer-delegated Linux cgroup-v2 helper for **only** the repository's fixed loopback workload:

```text
scripts/start-backup-echo.py --consent
```

It is not a generic sandbox, shell runner, command admission API, GPU scheduler, VM boundary, or proof of guest isolation. The echo program retains its own two-slot, 30-second and 4 KiB-per-slot application limits. This helper neither changes those limits nor accepts visitor input as a command.

## Safe default: review only

The default (and `--review`) prints a JSON report in `resource_boundary_v1` format. It does not inspect cgroup files, create a directory, write sysfs, start a process, change a controller, or enable a service. `--consent` can be included in this review invocation but does not change that behavior:

```sh
PYTHONPATH=src python3 scripts/rationed-echo.py --review --consent
```

The report has `ready: false`, declares CPU/memory/IO values rather than claiming enforcement, and reports GPU as `not_verified`. It includes a stable `source_policy_hash`, never raw workload bytes, and makes no GPU access or future-hotplug guarantee.

## Apply prerequisites and fixed caps

Application is deliberately more restrictive than review. It needs all of the following before any child cgroup is created:

1. A manual `--consent --apply` invocation.
2. An explicit absolute `--cgroup-parent` below `/sys/fs/cgroup`, not the root itself. The customer must already have delegated that parent to the service account.
3. An explicit `--io-device MAJOR:MINOR` block-device selector.
4. An existing cgroup-v2 parent whose `cgroup.subtree_control` already contains `cpu`, `memory`, `pids`, and `io`. The helper never enables controllers or modifies the parent.
5. A trusted external verification of the host's GPU deny policy. A flag, a file, an environment value, and absence of currently visible device nodes are **not** accepted as that verification.

The checked caps for the unique direct child are fixed:

| Control | Required value |
| --- | --- |
| `cpu.max` | `25000 100000` |
| `memory.max` | `268435456` |
| `memory.swap.max` | `0` |
| `pids.max` | `32` |
| `io.max` for the explicit device | `rbps=1048576 wbps=1048576 riops=128 wiops=128` |

Each write is read back and token-normalized for an exact expected value. There is no fallback controller, parent modification, looser cap, arbitrary device, or arbitrary command mode. Any unavailable parent, failed write/readback, permission problem, symlink, missing controller, failed membership check, or thread-unsafe caller returns an error and does not deploy.

The standalone command intentionally has no mechanism to supply a GPU attestation; consequently an apply attempt fails closed before cgroup writes or process launch. An authorized parent integration may supply a trusted in-process external GPU-policy verifier immediately before calling the library. That integration must be independent of caller-controlled flags/files and must account for cgroup-v2 device-policy limitations (device eBPF policy is separate from the four resource controllers). This module never claims a GPU timeslice or that cgroup-v2 alone denied a GPU.

## Lifecycle and report scope

When integrated with a verified GPU policy, the helper creates one random local child beneath the delegated parent. In its single-threaded CLI use, the child moves itself into that child cgroup during `preexec_fn` before the fixed Python script executes. The parent verifies the exact child PID in `cgroup.procs`; a failed check kills only the newly created child cgroup when `cgroup.kill` exists, waits, and never kills or falls back to the parent.

The launched process gets a clean fixed bootstrap environment, closed inherited file descriptors, `/dev/null` standard streams, a new session, and a maximum 35-second supervisor. The launcher reads bounded numeric deltas from its own child (`cpu.stat`, `memory.events`, `pids.events`, and the selected device's `io.stat`) before and after. Missing telemetry and counter resets are `unknown`, never zero. CPU-throttle, memory, PID, and IO labels are local observations, not a claim of malicious activity or causal attribution; buffered writes can be absent from IO counters.

SIGINT/SIGTERM and authorization-controller cancellation use the same fresh-child-only cleanup path. No process output or untrusted echo bytes are recorded by this wrapper. Successful local readback cannot establish VM boot success, device isolation, a global GPU guarantee, host trust, billing bounds, or actual network delivery.

## Operator boundary

Do not attempt to use this on a customer workstation merely because another control failed. A customer must arrange and approve cgroup delegation, external GPU policy verification, guest isolation, ingress/egress rules, and any authorization integration separately. The module does not add an authorization operation itself; the authorized caller must bind its own exact-purpose `resource_boundary` grant and pass a revocation check to the library integration.
