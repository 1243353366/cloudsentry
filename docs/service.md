# Separate decoy service

The optional service defaults to a small, plaintext, line-oriented TCP maintenance-console decoy. It also supports a bounded silent input sink and a bounded inbound-only byte mirror. It is not SSH, a real shell, an administrative API or a transparent reverse-shell redirect. The local scanner and the service are separate entry points. The service imports only the virtual terminal and standard-library networking support; its minimal image excludes scanner, ingestion, evidence and correlation modules.

## Local smoke test

In an authorized local checkout:

```sh
sh scripts/start-honeypot.sh --host 127.0.0.1 --port 8022
```

From a second local terminal:

```sh
nc 127.0.0.1 8022
```

Do not enter real credentials. The client sees a maintenance banner and apparent privileged identity, but every command reaches only the synthetic state machine. There is no login to a real OS. The server does not initiate outbound connections or run client-supplied scripts.

For silent bounded capture use `bash scripts/tarpit.sh`; for 1:1 byte reflection on the same accepted socket use `bash scripts/mirror.sh`. Neither mode executes input, preserves raw credentials, opens an outbound connection or loops forever. [MIRROR details](mirror.md) explain its byte/chunk limits. These modes do not emulate a real OS; the default console supplies the synthetic computer.

Non-loopback binding requires the explicit `--allow-public` option. It is an implementation capability, not approval to expose a service on an unknown machine. This project does not start a public service for you.

## Bounded interactions

The service limits concurrent sessions, accepted connections over its lifetime, commands per session, input length, command rate, idle duration, whole-session duration, total operator audit events and total service lifetime. Reaching a hard quota stops or closes work; there is no automatic restart. These are application limits, not a guarantee against network-layer denial of service or hosting costs.

Global input/output admission/reservation budgets default to 1 MiB each; per-session input defaults to 64 KiB. Configure them with `--max-input-bytes-total`, `--max-output-bytes-total` and `--max-session-input-bytes`. `--commands-per-second` may lower the default/hard maximum of 10 (also applies to mirror chunks). Global byte violations stop the listener and close active sessions; per-session input/rate violations close the affected session. Counters are not physical traffic/delivery measurements. A bounded read can precede rejection; CPU/memory/egress/billing limits need external enforcement.

When audit allowance remains, `service_budget` records at start/stop contain local limits and conservative application counters. They are `source_kind: decoy_service_control` and `interaction_observed: false`, not visitor events. No final record is guaranteed after audit loss/exhaustion. Summarize one explicitly preserved audit with `reverse-shell-decoy operations --audit preserved-service-audit.jsonl`; [resource-economics details](resource-economics.md) explain the evidence limits. No summary starts a service or reopens a closed session.

The operator audit records connection time, observed peer endpoint and an opaque session identifier, plus allowlisted command verbs and hashes instead of raw command arguments. Peer IP is a network observation with NAT/proxy uncertainty, not verified attacker identity. Remote OS remains unknown. Apparent Linux/Windows OS and root/admin state are simulated persona responses. The audit keeps that distinction explicit; no visitor can modify scanner rules through this service.

Operator notices/audit are written to stderr. If you preserve this stream, choose a private location with external retention and size limits. A local stream or in-memory audit is not an independent, tamper-proof evidence collector. A production deployment needs an external collector the decoy cannot modify. Do not commit service audit logs to Git.

The clean-environment launcher discards inherited variables, including cloud credentials. Direct service CLI startup refuses known credential variable names. Do not supply credentials or mount credential files into the service image. If the operator audit stream fails, the service stops accepting work rather than silently continuing without visibility.

## Shared inbound pacing

Every listener the service CLI starts is throttled by default. One `InboundThrottle`
holds token buckets that decide whether another connection or another command/chunk is
admitted right now. It opens no socket and sends nothing; a refused peer is closed
without receiving a byte.

- `--max-connects-per-second` (default 32) is the listener-wide accept ceiling across all peers.
- `--max-connects-per-second-per-peer` (default 8) caps one source. IPv4 peers are keyed by exact
  address, IPv6 peers by `/64`, so rotating through a subnet does not reset a bucket.
- `--max-units-per-second` (default 64) and `--max-units-per-second-per-peer` (default 16) cap admitted
  commands or mirror chunks.
- `--no-throttle` disables pacing. That is not recommended, and the pacing counters are still reported.

Burst capacity defaults to twice the rate so short interactive sessions are not penalized. A throttled
connection costs one audit record with `reason: peer_connect_rate` or `global_connect_rate` and is
**not** counted against the lifetime connection allowance, so a flood cannot consume the session quota
it is already being refused. The peer table is bounded by `max_tracked_peers`; when it is full, new
sources are refused rather than evicting a peer that is already throttled. `backup-echo` shares a single
throttle across both of its slots for the same reason.

Pacing is application-layer admission control. It does not replace OS-level SYN flood protection,
firewall policy, egress restriction or billing limits, and it does not slow or tarpit a remote host.

## Full payload and banner capture (opt-in)

By default the service keeps hashes only. With `--capture-payloads` it records the inbound record itself
for the operator's own review:

- `payload_b64` holds the complete inbound record, `payload_complete` says whether it fits the budget, and
  `payload_omitted_bytes` states exactly how much was not captured.
- `peer_greeting_*` fields in the `connecting` record hold the peer's opening bytes: base64, SHA-256,
  byte count, whether the cap was reached, and a printable escaped view.
- `banner_sha256`, `banner_byte_count` and `banner_text` record the complete banner the decoy presented.
- The `close` record carries `capture_sha256` and `capture_byte_count` for the captured session stream, so a
  reader can verify the exact bytes they are holding. The greeting is reported separately and excluded from
  that stream digest, because those bytes are replayed into the session.

Budgets: `--capture-bytes-total` (1 MiB), `--capture-session-bytes` (64 KiB), `--capture-record-bytes`
(4096, always at least one full inbound line) and `--capture-greeting-bytes` (512, `0` disables greeting
reads). Exhausting a budget stops further capture and marks the session `capture_truncated`; it does not
stop the session. `--capture-greeting-grace` (default 0.25s) bounds the wait for a peer's opening burst, so
a silent peer delays nothing else.

Capture is inbound-only, same-connection, bounded and opt-in. It is not a packet capture, it proves nothing
about a peer's identity, and captured payloads can contain third-party personal data or credentials that a
visitor typed. Treat a captured payload as sensitive evidence: keep it in private storage with a retention
limit, do not commit it, and check your own jurisdiction's rules before retaining visitor content.

## Minimal container, not an egress firewall

```sh
docker build -f Dockerfile.honeypot -t reverse-shell-decoy-service .
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges=true --pids-limit 32 \
  --memory 128m --memory-swap 128m --cpus 0.5 \
  -p 127.0.0.1:8022:8022 reverse-shell-decoy-service \
  --host 0.0.0.0 --port 8022 --allow-public
```

Here `0.0.0.0` is inside the container. The published host binding is explicitly localhost-only. Use current Docker: versions before 28.0.0 have a documented caveat allowing some same-L2 hosts to reach localhost-published ports. Non-default direct-routing/network configurations also need review. [1]

The container image runs as UID 10001. No host filesystem or evidence directory is mounted. It contains no scanner/admin module, credentials or Docker socket. Keep it separate from the machine being investigated. Do not add privileged mode, host networking, host PID namespaces or host mounts.

**A normal Docker bridge is not outbound-network denial.** This source code makes no outbound connections, but a public deployment needs an independently enforced network policy that denies new outbound flows and access to private/internal systems while allowing replies to legitimate inbound sessions. Review actual IPv4/IPv6/container firewall behavior; do not assume a generic container command creates that policy. No public-facing deployment is supplied or tested here.

## Before deliberate public use

Use a disposable isolated VM or appropriately reviewed container environment, a dedicated unprivileged account, externally enforced egress restrictions, ingress protection, separate trusted log storage and retention controls. Define the authorized exposure, privacy policy and stop conditions. The TCP protocol is plaintext and is not suitable for transmitting secrets. Do not infer visitor identity or OS from the presented persona.

There are no metered API calls or cloud-control APIs in this service. Its runtime/session caps bound application work but cannot guarantee your infrastructure bill or defend against volumetric attacks. No cloud spending ceiling is configured. There is no remote flooding, retaliation, denial-of-wallet mechanism or host-monitoring interference.

## Release integrity

This initial source includes tests and payload checksums for evidence bundles, not cryptographically signed releases. Runtime Python dependencies are absent. CI action tags, the build tool and the example base-image tag are not immutable supply-chain pins. For production, select reviewed commit/image digests, maintain the Python base image, and use your own signing/verifying release process. No signing key has been generated or installed on your behalf.

## References

[1]: https://docs.docker.com/engine/network/port-publishing/ "Docker port publishing and mapping"
