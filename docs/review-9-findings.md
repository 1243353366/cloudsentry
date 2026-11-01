# Review 9 findings and Increment 3

Scope: `1243353366/cloudsentry` at `a412d10` (core 0.1.2). Baseline: 393 tests passing.
Result after this change: 436 tests, 203 subtests, all passing.

## Flaws found and fixed

| # | Flaw | Evidence in 0.1.2 | Fix |
| --- | --- | --- | --- |
| 1 | Payloads were unrecoverable | Console, sink and mirror modes recorded only `command_sha256` / `chunk_sha256` / `byte_count`. An operator could prove a payload existed but never read it back, so no downstream analysis was possible. | Opt-in `CapturePolicy` with complete-record base64, explicit `payload_complete` / `payload_omitted_bytes`, and a per-session `capture_sha256` / `capture_byte_count` on close. |
| 2 | Only the server banner was recorded, and only implicitly | `banner` existed only as simulator output; nothing in the audit trail proved what the decoy presented, and the peer's own opening bytes were never captured. | `connecting` now carries the complete presented banner (`banner_text`, `banner_sha256`, `banner_byte_count`, `banner_delivered`) and the peer's full greeting (`peer_greeting_*`), bounded and escaped. |
| 3 | No inbound pacing across listeners | Rate limiting was per session and per second only. Eight concurrent sessions multiplied the admitted rate eightfold, and `backup-echo`'s two slots each had an independent allowance. | One shared `InboundThrottle` token bucket; global and per-source ceilings for accepts and units, IPv6 grouped by `/64`, bounded peer table, shared across slots. Enabled by default in both entry points. |
| 4 | Throttle hot path could be gamed | n/a (new code) | A throttled peer is closed with no response byte, is not counted against the lifetime connection allowance, and the peer table refuses new sources instead of evicting an already-throttled peer (eviction would hand out a fresh bucket). |
| 5 | Double-counted capture digest | Introduced and caught during this work: replayed greeting bytes were hashed into the session stream twice. | Greeting bytes debit the capture budget but are excluded from the stream digest; `capture_byte_count` now always matches the bytes behind `capture_sha256`. |
| 6 | Minimal container would have broken | `Dockerfile.honeypot` copies an explicit module list; `honeypot.py` now imports `throttle.py`. | Module list updated and verified by importing the copied set in an isolated directory. |
| 7 | README claimed telemetry the code cannot produce | "logging incoming connection banners, TCP options, TTLs, and handshake timing" | Claim narrowed to what the application layer can observe; TTL and TCP options are stated as not captured, with the reason (below the socket API). |

## Increment 3 items delivered

Prioritised exactly as recommended: attribution and visibility before behaviour.

1. **Socket ownership race detection.** Two independent snapshots; a binding that disappears or changes owner is `UNKNOWN` with a reason, never attributed to the first owner seen.
2. **Multiple process ownership.** Every discovered PID, `parent_pid`, and `fork_related_parent_pids` for descriptors inherited across `fork`.
3. **Executable replacement detection.** Opened-descriptor hashing with `fstat` before and after, `changed_during_hash`, `deleted_in_path`, `identity_verified`; a path is never proof of an image.
4. **Namespace coverage.** Owner namespaces, collector namespace reference, inaccessible namespaces, `namespace_scope`; single-namespace results are labelled as such.
5. **Permission visibility.** Unresolved bindings, permission warning labels, ownership ratio, and a `NO_DATA` / `COMPLETE` / `PARTIAL` / `DEGRADED` verdict with a one-sentence statement.
6. **Ground-truth cross-verification.** Read-only `NETLINK_SOCK_DIAG` dump compared against procfs, reporting agreement, per-source-only endpoints and state disagreements without preferring either source; explicit `not_verified` with a reason when unavailable.

`NO_DATA` exists because an empty snapshot previously read as success. An empty result and a clean host are different claims.

## Deferred, with reason

7. **Listener behaviour fingerprinting**, 8. **lineage/persistence correlation**, 9. **collection-integrity watchdog**, 10. **exposure/reachability verification.** These classify or schedule. Implementing them before attribution is trustworthy would build conclusions on the exact races and blind spots items 1–6 exist to expose. Item 10 also needs routing and firewall evidence this package does not read, and it must never become probing: current output states binding scope only (`loopback` / `wildcard` / address), which is not reachability.

The watchdog is the strongest candidate next, precisely because it does not infer behaviour: it would report "telemetry unavailable" instead of "clean" when collection stops, and it belongs in its own process so a collector failure cannot suppress the alarm.

## Refused

A forced VPN/tunnel/redirect that makes a third party's tool connect here, and any mechanism whose purpose is to consume a remote party's resources. Both are documented in [response boundaries](response-boundaries.md) with the reasoning, so the boundary is visible to contributors and operators rather than rediscovered.

## Verification notes

- `PYTHONPATH=src python3 -m pytest tests -q` → 436 passed, 203 subtests.
- Live smoke test on this host: `listeners --assure --cross-verify` reports zero visible bindings, `coverage.state = NO_DATA`, and `cross_verification.available = false` (`netlink_sock_diag_not_supported`). That is the intended honest output, not a failure.
- The diag parser is unit-tested against synthetic 72-byte `inet_diag_msg` frames. It was **not** exercised against a live kernel here, because this environment does not provide `NETLINK_SOCK_DIAG`. First run on a host that does is the integration test.
- Capture and pacing tests use loopback sockets only. No test opens an external connection, and no test asserts a remote peer's behaviour.
