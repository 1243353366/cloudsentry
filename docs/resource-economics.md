# Decoy resource economics and local operations summary

This project’s decoy service uses small, local application budgets to make its own work finite. Those budgets are defensive operator controls, not a mechanism to consume a visitor’s resources, identify a visitor, affect a remote system, or estimate a visitor’s cost. The service makes no callbacks and this summary command does not call cloud, DNS, firewall, billing, or other control APIs.

## Customer opt-in: run it manually, on your infrastructure

The customer is the operator. Nothing here starts by default when the website opens, when someone signs in or when a report contains an indicator. After installing the local tool, choose the host, intended exposure, session policy, evidence retention and stop conditions yourself. You may stop the service at any point with Ctrl-C; it also stops at its finite lifetime or global limits and does not automatically restart.

1. Use a disposable isolated environment you own or administer, separate from your production host and operator portal. Keep real files, accounts, tokens and cloud credentials out of the decoy. Apply external ingress/egress and CPU/memory controls; the [service guide](service.md) explains container restrictions. No claim of escape-proof isolation is made.
2. Create a private audit location and explicitly start the loopback-only service. The following example chooses a lower rate of five commands/chunks per second and refuses to overwrite an existing audit file:

   ```sh
   mkdir -m 700 decoy-review
   (
     umask 077
     set -C
     sh scripts/start-honeypot.sh --host 127.0.0.1 --port 8022 \
       --max-runtime 600 --max-sessions 4 --max-sessions-total 20 \
       --max-input-bytes-total 1048576 --max-output-bytes-total 1048576 \
       --max-session-input-bytes 65536 --commands-per-second 5 \
       2> decoy-review/service-audit.jsonl
   )
   ```

3. Public/non-loopback binding is a **separate, deliberate opt-in**, not something a scan enables. Only after reviewing your isolated deployment and logging controls, add the actual bind address and `--allow-public` to your own launcher invocation. This does not configure firewall rules, publish a container port, create TLS/SSH, deny network egress or acquire authorization. Native provider/network configuration and any additional exposure are yours to perform manually. Do not make the operator-login server the decoy.
4. After the chosen run, generate an operating report from that selected private audit using the command below. If saving JSON, use a private directory, restrictive umask and no-overwrite redirection. Review it before sharing. To use the portal, select that JSON result as provider `local`; do not upload raw JSONL or assume that the portal runs the local service.
5. Review indicators against independent source logs and approved activity. Any firewall block, access revocation, owned-domain DNS sinkhole or other containment change is a **separate manual decision** in your own platform's tools. Confirm the finding, ownership, scope, service/protocol compatibility, impact and rollback first. The existing `sinkhole-plan` command produces a review-only proposal; it never applies the change. No arbitrary third-party system is an authorized response target merely because it connected.

The tool is built for these opt-in steps; operational choices and approved native-provider changes remain with the customer. It does not silently expand this permission into cloud access, an endless hold, remote workloads or automatic investigation/remediation.

## Explicit local audit summary

The operations summary is a manual, local-only command. It reads one explicitly selected JSONL audit file and does not discover other files, start a decoy, launch a scanner, execute input, contact a service, or take an automatic action.

```sh
reverse-shell-decoy operations --audit preserved-service-audit.jsonl
python scripts/operations-summary.py --audit preserved-service-audit.jsonl
```

Add `--json` for structured output. Both forms use the same local parser and require `--audit`.

The selected input must be a regular file. Symlinks, devices, FIFOs, and files above 2 MiB are rejected through the shared safe reader. The parser reads at most 1,000 physical JSONL records and ignores individual records above 16 KiB. Malformed, deep, unsupported, or invalid records are counted as uncertainty; their raw contents are never copied into the report.

The summary includes the exact SHA-256 of the selected input, valid normalized UTC times, counts, fixed labels, and hash-only session references. It intentionally does **not** reproduce peer IP addresses, command text, arguments, arbitrary source fields, or free-form strings. Every imported record is unverified, including a record that claims an interaction was observed. The file can be incomplete, modified, truncated, or originate from another program.

## Limited pattern flags

The output may attach one or more low-confidence flags to a hash-referenced session:

| Flag | Limited observable condition | What it does not prove |
| --- | --- | --- |
| `connection_only` | A supplied `connecting` record without a supplied command or mirror chunk. | A successful session, intent, identity, or source type. |
| `probe_like` | One or two supplied command or mirror-chunk records. | A human, scanner, exploit, or attempted compromise. |
| `burst_pattern` | A supplied fixed rate-limit reason: `command_rate_limit` or `chunk_rate_limit`. | Traffic volume beyond the retained record, remote load, or an attack. |
| `multi_command_pattern` | At least three different allowlisted decoy verbs in supplied records. | A person, a tool, skill, intent, or execution on any host. |
| `execution_related_text` | A supplied fixed text-indicator label from the project’s bounded indicator list. | That code executed, could execute, reached a host, or identifies an actor. |

Flags can overlap; they are not exclusive categories. Unknown verb strings and unknown text indicators are not echoed or converted into labels. The labels describe only a limited pattern in the supplied records. They do not prove a human, scanner, exploitation, host access, execution, identity, a remote operating system, or remote resource use.

Missing `connecting` or `close` events, discarded records, and missing service-budget phases are represented as uncertainty counters. They are **unknown coverage**, not a clean result. A missing final `stopped` budget record is not proof that the service failed: budget audit records can be absent when the audit allowance is already exhausted.

## Decoy budgets

The decoy service records local service-control budget snapshots as `service_budget` events. A valid snapshot has `source_kind: decoy_service_control`, `interaction_observed: false`, a `started` or `stopped` phase, and allowlisted numeric `limits` and `usage` fields. Operations output exposes only those validated fields and labels them as **supplied, unverified**. Missing fields are reported as `unknown`.

The service defaults and hard ceilings are local application constraints:

| Limit | Default | Hard maximum | Purpose |
| --- | ---: | ---: | --- |
| `max_sessions` | 8 | 64 | Concurrent accepted virtual sessions. |
| `max_sessions_total` | 100 | 100 | Accepted connections over one service lifetime. |
| `max_commands` | 100 | 100 | Commands or chunks admitted per virtual session. |
| `max_runtime_seconds` | 600 | 3,600 | Whole service lifetime. |
| `idle_timeout_seconds` | 20 | 300 | Idle period per session. |
| `session_timeout_seconds` | 120 | 3,600 | Maximum session duration. |
| `max_input_bytes_total` | 1 MiB | 8 MiB | Total input admitted for application handling. |
| `max_output_bytes_total` | 1 MiB | 8 MiB | Total application output reserved before writes. |
| `max_session_input_bytes` | 64 KiB | 256 KiB | Input admitted for one virtual session. |
| `commands_per_second` | 10 | 10 | Per-session command/chunk rate. |

The `usage` numbers require careful interpretation:

- `input_bytes_total` counts bytes admitted for application handling. Oversized or rejected reads are not admitted and are not added. It is **not** a physical traffic or bandwidth counter.
- `output_bytes_total` counts application output reserved before writing. If a socket drain later fails, the reservation remains counted; the counter is **not** confirmed delivery or physical traffic.
- `accepted_connections`, session counts, and elapsed seconds are supplied local counters. They do not authenticate an origin, reconstruct all activity, or establish remote conditions.

No budget field measures a visitor’s CPU, memory, operating system, bandwidth, money, cloud bill, or other remote resource. This documentation intentionally provides no dollar estimates or cost claims.

## Deployment boundary

These application controls do not replace infrastructure controls. CPU and memory enforcement belong to an external container/runtime policy, such as reviewed Docker limits, and are not host-OS controls performed by this application. The service does not claim to enforce network egress, firewall policy, volumetric denial-of-service protection, or an infrastructure spending ceiling.

Run public-facing decoys only in an authorized, isolated environment with independently reviewed ingress, egress, container, retention, and incident-response controls. Keep audit logs private and preserve the original file if it may be needed for later review. The operations summary is a factual aid for the explicitly supplied audit only; it is never proof of a remote actor or remote impact.

## Optional customer-side compute boundary

The [resource-boundary module](resource-boundary.md) is separate from these application budgets. Its fixed plan uses `cpu.max=25000 100000`, a 256 MiB memory ceiling, zero swap, 32 tasks and explicit-device I/O limits. Review is no-write/no-launch. The low-level apply path requires a fresh exact-scope grant, pre-delegated cgroup-v2 controllers, verified readback and a trusted external GPU-deny-policy integration. The standalone CLI cannot manufacture that device-policy evidence and fails closed on apply. No parent/global controller setting is changed and no arbitrary command or visitor content is run.

GPU time slicing is not implemented or promised. Fewer CPU resources can reduce available work and limit exposure, but CPU allocation is not a port-equivalent isolation proof and does not eliminate shared-cache, timing, device or hypervisor vulnerabilities. Limits can preserve headroom and response time; they do not establish a guaranteed response window, service SLA or cloud-spending cap.

CPU throttling, memory/PID pressure and selected-device I/O deltas are source-bounded observations. Missing/reset counters remain unknown. Compare a separately reviewed customer baseline and independent telemetry before drawing conclusions: ordinary workloads, quotas and noisy neighbors can also cause pressure. No threshold or claimed violation expands the session's authority or automatically changes production policy.

Customer wording: **“The isolated service is intended to run with small, explicitly configured CPU, memory, process and device-I/O budgets. No GPU workload is granted. We report which controls were declared or verified, and which remain unknown. Pressure and limit events prompt review; they are not proof of an attack. Independent infrastructure controls protect production availability.”**
