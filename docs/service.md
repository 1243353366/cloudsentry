# Separate decoy service

The optional service is a small, plaintext, line-oriented TCP maintenance-console decoy. It is not SSH, a real shell, an administrative API or a transparent reverse-shell redirect. The local scanner and the service are separate entry points. The service imports only the virtual terminal and standard-library networking support; its minimal image excludes scanner, ingestion, evidence and correlation modules.

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

Non-loopback binding requires the explicit `--allow-public` option. It is an implementation capability, not approval to expose a service on an unknown machine. This project does not start a public service for you.

## Bounded interactions

The service limits concurrent sessions, accepted connections over its lifetime, commands per session, input length, command rate, idle duration, whole-session duration, total operator audit events and total service lifetime. Reaching a hard quota stops or closes work; there is no automatic restart. These are application limits, not a guarantee against network-layer denial of service or hosting costs.

The operator audit records connection time, observed peer endpoint and an opaque session identifier, plus allowlisted command verbs and hashes instead of raw command arguments. Peer IP is a network observation with NAT/proxy uncertainty, not verified attacker identity. Remote OS remains unknown. Apparent Linux/Windows OS and root/admin state are simulated persona responses. The audit keeps that distinction explicit; no visitor can modify scanner rules through this service.

Operator notices/audit are written to stderr. If you preserve this stream, choose a private location with external retention and size limits. A local stream or in-memory audit is not an independent, tamper-proof evidence collector. A production deployment needs an external collector the decoy cannot modify. Do not commit service audit logs to Git.

The clean-environment launcher discards inherited variables, including cloud credentials. Direct service CLI startup refuses known credential variable names. Do not supply credentials or mount credential files into the service image. If the operator audit stream fails, the service stops accepting work rather than silently continuing without visibility.

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
