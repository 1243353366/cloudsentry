# MIRROR: bounded inbound-only data reflection

MIRROR is an ordinary inbound-only echo surface on a decoy you control. A visitor initiates the TCP connection. The service returns received bytes as data only through the same accepted socket. It never opens a callback connection, executes the bytes, tells a remote computer to execute them, or holds someone else's listening endpoint open. It does not create a reverse shell.

```sh
bash scripts/mirror.sh --host 127.0.0.1 --port 8022 --max-runtime 600
```

The clean-environment launcher excludes inherited credentials. Loopback is the default. A deliberate public deployment still requires the external isolation, egress denial, ingress limits and logging controls in [service boundaries](service.md); none is deployed by this source.

## What is reflected

Within the quota, the received byte chunk is returned unchanged, including newlines or binary bytes. This is a 1:1 echo, not a generated command, interpreted shell program, script, base64 stage, or loop. No banner or prompt is sent in mirror mode. With `--capture-payloads` the operator additionally receives each inbound chunk in
`payload_b64` with `payload_complete`/`payload_omitted_bytes`, still on the same connection and still within
the capture byte budget. Input is never passed to Bash, `eval`, `exec`, `nc`, `socat SYSTEM`, a subprocess or a network destination selected by the visitor.

Raw bytes exist transiently in a bounded memory buffer. Operator audit contains session metadata, byte counts and chunk digests, not raw transcripts, credentials, SSH keys or command arguments. There is no raw capture to `/tmp` or another directory. To show a synthetic computer rather than plain data echo, use the default console mode of `scripts/start-honeypot.sh`: it provides allowlisted virtual commands, files, root/admin presentation and processes, all in memory.

These retained values support a limited **content/activity fingerprint**, not identification of a visitor, a psychological profile or proof that a reverse shell succeeded. Echo and payload hashes do not identify a remote operating system. The visitor OS is unknown; local scanner OS fields describe the scanner machine and the virtual console persona is synthetic. Independent authorization and source evidence are needed before making stronger claims.

## Why the original unlimited design is not used

Every connection is a fresh, bounded session—not an unbounded resource reservation. MIRROR reads at most 4,096 bytes per chunk, echoes at most 64 KiB per session, applies a chunk quota through `--max-commands`, and closes for rate, idle, session, whole-service, connection or audit limits. It does not automatically restart.

`/tmp` is a real host directory, not an isolation boundary. `socat -u` controls direction; it does not make a `SYSTEM:` or `EXEC:` endpoint incapable of launching a host process. A capture pipeline using `tee` also creates a process and writes data. The implementation here does neither.

## Investigator reporting

Use [the investigator exporter](investigator-export.md) with a preserved copy of the operator audit. A `mirror_chunk` is a logged inbound data interaction, not proof of a remotely executed command, identified person, criminal conduct or unauthorized access to a real host. A peer address can represent NAT, a proxy or shared infrastructure. Authorization and attribution need independent records.

Synthetic state and apparent privileged access remain labeled synthetic. The packet's hashes check consistency, not authenticity or legal admissibility. It is suitable for factual review, not for turning a simulation into an allegation.
