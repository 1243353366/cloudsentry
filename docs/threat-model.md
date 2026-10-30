# Trust boundaries

## Local observations

Read-only scanners collect limited OS details, established TCP/socket ownership, listening/bound endpoints, and bounded startup configuration indicators. They describe the current computer and its visible namespaces. They do not determine the initiating endpoint from a socket snapshot, authenticate a remote party, or establish that a service is unauthorized.

Process names can be changed. `/proc` can be incomplete, inaccessible or untrustworthy on a compromised system. Startup directories can omit other persistence mechanisms. An encrypted connection, a listener, or an unfamiliar name is not enough to declare a backdoor. Offline name checks require an operator-maintained known-good baseline and do not query external reputation services.

## Imported real logs

Users explicitly choose a local file or paste log text into stdin. There is no cloud upload path. Each import records source/representation, ingestion UTC, input SHA-256, record hashes and preserved event timestamps where available. Normalized/redacted records are derivative evidence, not original forensic acquisitions. Pasted bytes cannot verify the original logfile's bytes or identity.

Logs may contain false statements, terminal escapes, secrets or extreme-size input. Parsing is bounded, messages are not executed, unknown JSON fields are excluded, and redaction is best effort. JSON output escapes terminal control characters. Keep originals separately; sharing a normalized report does not replace evidence custody.

## Deceptive presentation

A local operator starts an in-memory terminal. The realistic option presents a maintenance session and apparent root/administrator identity without saying honeypot in its banner. Submitted commands reach only an allowlisted parser and synthetic filesystem. There is no shell execution, network listener, outbound socket, host mount, real persistence or privilege transition.

The operator sees a separate notice. Every audit event remains `simulation: true`. The simulated `uname`/Windows version is synthetic and must never be used to identify the actual host or a visitor. Commands are represented by known verbs and hashes, not stored raw strings. Virtual files contain no real people, credentials or agency data.

The optional network service separately accepts bounded inbound sessions and feeds only this virtual parser. It imports no scanner/admin interface, and its minimal image excludes scanner/evidence modules. It defaults to loopback binding. Real observed connection time and source endpoint are recorded as interaction metadata, while privileged session effects remain synthetic; remote OS and attacker identity are unknown. Public use requires explicit binding and separately enforced infrastructure isolation, egress denial and trusted external log collection. It is not deployed by this repository.

## Defensive resource budgets and operating summaries

Global input-admission and output-reservation byte limits, per-session input limits, bounded rates and existing connection/time/audit caps apply only to this decoy instance. Exhausting a global byte budget stops its listener and closes active sessions; a per-session input violation closes that session. Reservations occur before asynchronous writes. No visitor can raise a limit through submitted text, restart the instance, request a host interpreter or route bytes to a chosen remote endpoint. A small bounded read may occur before an over-budget input is rejected; application counters are not physical traffic meters.

Budget-control records are local configuration/counter observations, not visitor interactions. They have separate provenance, and their absence from a supplied stream means unknown coverage. CPU/memory restrictions still require externally enforced container/VM controls; network floods, billed platform traffic and overall cloud spending are outside these application counters. No remote battery drain, generated workload, forced investigation, callbacks or denial-of-wallet mechanism is included.

An explicitly invoked operating summary reads one selected, bounded local audit. All input records remain unverified; forged JSON, repeated tokens, missing records or manipulated timestamps cannot establish actor identity, authorization, execution or psychological traits. Classifications describe patterns such as bursts or multiple commands, not proven scanners, human operators or exploitation. The report excludes raw commands and peer identities and does not call a model, inspect customer accounts, change tenant permissions or trigger firewall/DNS enforcement. The hosted customer portal remains a separate authentication and private-import boundary.

## State experiments

Process limits, packet loss and telemetry gaps are modeled in memory for a fixed number of virtual steps. The authoritative observer remains complete when the synthetic sensor loses events. No host monitoring tool is deceived or disabled. No external system is burdened and no real metered API is called.

## Evidence export

A private ZIP contains actual limited host context and a detection report with separately named observation/import/name-check sources. A separate file contains explicitly simulated activity. A manifest hashes payload files but cannot authenticate the machine, operator or log author. The custody worksheet is blank until a receiving investigator completes it.

The public source repository must contain no runtime evidence. The application does not upload evidence or identify law-enforcement personnel. It provides a bounded triage aid, not a legal conclusion or automated incident response.
