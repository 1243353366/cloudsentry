# Synthetic decoy services

`reverse-shell-decoy synthetic` serves deliberately obvious fake services on loopback.

```
reverse-shell-decoy synthetic --runtime 60
reverse-shell-decoy synthetic --services "web endpoint" --full-payloads
```

Default endpoints: a shell-like service (22022), a web endpoint (22080) and a
database-like endpoint (26379).

## Obviously fake, on purpose

Every banner and every reply contains `SYNTHETIC DECOY` and says what it is not:

```
SYNTHETIC DECOY: this is not a real shell. Nothing is executed, stored or authenticated here.
SYNTHETIC-DECOY-0.0 (invented version, no shell attached)
```

Version strings are invented, no real product names appear, and the visitor is told the
truth immediately. The point is not to fool a knowledgeable visitor. It is to measure
interaction patterns on a listener you own while making it impossible to confuse the
resulting records with real host activity.

## Nothing is executed

Replies come from a fixed catalogue matched on lowercase text. There is no interpreter, no
file access, no subprocess, and no state that survives a session. Every session record says
`executed_anything: false`, `authenticated_anything: false`, `stored_anything: false`.

## Patterns, not payloads

Per session the recorder keeps bounded derived facts: bytes each way, line count, arrival
gaps, first-line hash, and shape labels:

| Label | Shape |
| --- | --- |
| `credential_shaped_input` | looks like a username, password, token |
| `command_shaped_input` | looks like a shell command |
| `known_exploit_marker` | a well-known traversal or injection marker |
| `automated_fingerprint` | a scanner or client software string |
| `service_probe` | anything else textual |
| `no_input` | nothing sent |

Labels describe the shape of the text, never the intent, skill or authorization of the
peer. Raw text is recorded only with `--full-payloads`.

## Evidence separation

Every record carries `synthetic: true`, `source: "synthetic_decoy"` and
`not_host_activity: true`. `exclude_synthetic()` drops them, and the summary says why:

> These records describe connections that were invited by a listener on this host and
> answered by canned text. They are synthetic interactions, not host activity.

This matters in practice: a scan of the decoy ports creates sessions too, and those must
never be counted as suspicious activity against the host.

## Bounds

Sessions (concurrent and total), input and output bytes, session duration, idle time and
total runtime are all limited, and the shared inbound throttle is consulted before a
connection is served. A throttled peer is closed without a response byte.
