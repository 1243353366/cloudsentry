# Relay: rotate, fingerprint, bounce banners

`reverse-shell-decoy relay` puts a rotating proxy in front of a loopback decoy.

```
reverse-shell-decoy relay --targets 127.0.0.1:22022,127.0.0.1:22080 --rotate-every 3
```

## The shape, and the shape it refuses

A visitor connects to the front. The front presents a rotating greeting that states it is
synthetic, connects to the target, captures the target's own banner, bounces that banner
back, and then pumps both directions under byte and time budgets.

It never:

- relays to a remote host (every target must be loopback unless `allow_non_loopback_target`
  is set, and the report then says `target_scope: "explicit_remote"`);
- opens an outbound connection to a third party;
- intercepts a connection it did not receive;
- joins two visitors' sessions together.

Every record carries `no_third_party_transit: true` and every session record carries
`third_party_transit: false`. Relaying someone else's connection onward would move this
host's traffic onto a third party, which CloudSentry refuses in `docs/response-boundaries.md`.

## Rotation

The front presentation and the backend target change on a connection count
(`--rotate-every`) or a time budget, and each rotation is recorded with both sides named:

```json
{"kind": "relay_rotated", "from_presentation": "front-a", "to_presentation": "front-b",
 "reason": "connection count", "connections_since_start": 4}
```

Rotation exists because a stable presentation is a stable fingerprint: a visitor who sees
the same greeting and the same banner forever can recognise the decoy. Rotating does not
make the decoy deceptive; the greeting stays honest at every rotation.

## Fingerprinting

Passive and app-layer only: the first bytes the visitor sent, and the timing. Categories:

| Category | Basis |
| --- | --- |
| `tls_client_hello` | record header bytes |
| `ssh_client_identification` | `SSH-` identification line |
| `http_request` | method and path, plus `User-Agent` if present |
| `interactive_text` | line-oriented text |
| `unknown_opening` | anything else |

No raw-socket options are read, no active probing of the peer happens, and
`inferred_operating_system` is always `null`: what a peer sends first is a hint about its
tooling, not proof of its platform.

## Banner capture in both directions

The backend banner is captured and hashed (`backend_banner_sha256`,
`backend_banner_synthetic`) before it is bounced, so the record proves the target said what
we think it said. The visitor's opening bytes are captured as a fingerprint. Both are
bounded and both are opt-in for raw content (`--full-payloads`).

## Bounds

Concurrent sessions, total sessions, per-session and total bytes, banner size, idle timeout
and runtime are bounded, and the shared inbound throttle is consulted before any banner is
sent. A throttled peer receives nothing at all, which makes pacing visible in the record
(`banner_sent: false`).
