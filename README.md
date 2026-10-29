# CloudSentry: Forensics and Deception

**[Launch CloudSentry in your browser](https://csportal-brpeckhv.manus.space)**

The keyless browser portal uses managed Google/Microsoft/passkey sign-in, customer-owned provider profiles and deliberately imported scan results. No cloud API keys are requested or stored. Cloudflare, AWS, Render and Railway profiles are metadata bookmarks, not authenticated cloud connections; customers perform provider login, scanning and export themselves. Every summary asks fresh permission. Direct GitHub sign-in is not included in the approved keyless version.

The browser application source is in [`portal/`](portal/), with [run instructions](portal/README.md). This public repository is an additional source distribution; the live deployment remains separately managed. Source availability and the launch link do not share anyone's reports or credentials.

A local incident-response triage tool with a separate, in-memory deception terminal. It imports pasted or selected real logs, records limited OS details, inventories Linux listeners, flags possible shell-linked TCP connections and persistence indicators, and checks domain/package lookalikes against an operator-provided baseline.

The decoy can display a neutral maintenance console and apparent root/administrator access. This is cosmetic: it never obtains privileges, executes submitted commands, opens an outbound connection, or exposes the actual host. The local terminal opens no sockets; the optional service only accepts bounded inbound sessions. Operator notices, audit events, and evidence exports retain explicit simulation provenance even when the terminal presentation is realistic.

**The scanner and decoy are separate local components. An optional decoy service accepts bounded inbound terminal interactions and does not expose a scanner/admin interface. The browser launch link opens the customer portal, not a public honeypot or shell.** Neither decoy mode redirects an existing reverse shell or grants real remote access. Public repository visibility does not publish your logs or create a decoy listener.

Cloudflare, AWS, Render and Railway exported/pasted logs have separate manual analyzers. Optional supported read-only API collection is an explicitly invoked operation with the owner's scoped credentials; those credentials never belong in the decoy. There is no scan by default. Start only the honeypot with `sh scripts/start-honeypot.sh`, which drops inherited credentials. The [manual workflow](docs/workflow.md) covers cloud evidence, the summary script, and review-only positive-indicator sinkhole proposals. No automatic DNS change, traffic interception or remote credential/file extraction is included.

## Consent-gated review and text indicators

After an explicitly requested scan, the CLI offers a local review by default in an interactive terminal. It asks fresh permission each time and generates nothing when permission is declined, stdin is non-interactive, or input ends. The prompt and optional review use stderr so the original scan JSON remains clean on stdout. No scan is triggered automatically. See the [post-scan review guide](docs/post-scan-review.md).

```sh
python3 scripts/review-scan.py --scan saved-scan.json --command audit \
  --audit preserved-service-audit.jsonl
python3 scripts/trail.py --audit preserved-service-audit.jsonl
```

The standalone review also asks permission before reading the selected files. Its observed-tooling section is unknown without relevant audit observations; defensive indicators are not proven vulnerabilities, and synthetic actions do not establish unauthorized real-host access. Both scripts perform no network action or submission to law enforcement.

The virtual terminal defaults to a PHP metadata catalog: `php -v`, `php -m` and `which` return canned values. No PHP interpreter is installed or run by this feature; script execution and other interpreter attempts remain blocked. The [text-indicator trail](docs/trail.md) retains only bounded, fixed language/token labels, source context and hashes—not raw one-liners, skill scores or allegations. Mirror mode remains an opaque, bounded byte reflector and does not present or interpret this catalog.

## Install

Python 3.10+ is required. The core runtime uses only the Python standard library; optional manual AWS API collection needs the AWS SDK described in the collector guide. Host process/socket/persistence inspection targets Linux; OS context, log parsing, name checks and virtual terminal personas are separate from native Windows endpoint scanning.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --no-deps .
reverse-shell-decoy --help
```

For a source checkout without installation:

```sh
export PYTHONPATH="$PWD/src"
python3 -m reverse_shell_decoy --help
```

Run only on systems and logs you are authorized to inspect. Do not run as root just to start the decoy. Restricted visibility is reported rather than bypassed.

## Bounded mirror and investigator workflows

The additional [MIRROR mode](docs/mirror.md) reflects received data only through the same accepted inbound socket. It does not execute bytes, dial a peer, loop commands on another computer or capture raw credentials to disk. Start it locally with `bash scripts/mirror.sh`. The default console mode still presents a synthetic computer; `bash scripts/tarpit.sh` is a bounded silent sink.

The [defensive state loop](docs/shellception.md) preserves snapshot/change/virtual-mutation logic without altering real history, SSH, cron or shell startup. Its explicit `--state-output` writes only a private, current synthetic-state artifact. It does not reconstruct historical state from hashes.

```sh
python3 scripts/export-for-investigator.py --audit preserved-service-audit.jsonl \
  --state synthetic-state.json --output investigator-review.zip
```

The [investigator exporter](docs/investigator-export.md) preserves source digests and separates logged interactions, synthetic state/effects, operator assertions and unknown facts. It creates a private review ZIP and readable Markdown sidecar, not an allegation or proof of unauthorized real-host access. Original authentication/network/cloud logs and authorization records remain independent corroboration. No evidence is uploaded or sent to an investigator automatically.

## Paste real logs

```sh
reverse-shell-decoy ingest --paste --format text
```

Paste the log lines, then type `ENDLOG` on a line by itself. JSON Lines input is also supported:

```sh
reverse-shell-decoy ingest --paste --format jsonl
```

An individual JSON object per line is supported, not a whole JSON array. This is local stdin input, not a web upload. Text is never evaluated or treated as a shell command. Remove credentials, tokens and unrelated personal information before pasting: automated redaction is conservative and cannot guarantee removal of every secret.

To import a file or combine pasted logs with an actual host audit:

```sh
reverse-shell-decoy ingest --logs /path/to/authorized.log --format text
reverse-shell-decoy audit --paste --format jsonl
```

Imported content is marked as real-log input, but its source is **unverified**. Hashes describe the selected file or pasted representation; pasted data is not a byte-for-byte acquisition of the original logfile. Event timestamps are preserved when present and are not replaced with import time. The tool does not establish that a log is truthful or that a remote address belongs to an attacker.

## Inspect this computer

```sh
reverse-shell-decoy os
reverse-shell-decoy scan
reverse-shell-decoy listeners
reverse-shell-decoy persistence
reverse-shell-decoy audit
```

`os` reports limited real OS and architecture fields for the computer running the tool, without hostname or username. These details do not identify the OS of a remote peer or of a separate machine that produced pasted logs.

`scan` correlates established non-loopback TCP sockets with owning shell processes or shell ancestors. Direct shell ownership is a stronger heuristic than an application launched from a terminal; legitimate activity can still match. A snapshot cannot prove whether a connection was initiated outward, whether it is malicious, or whether the host is compromised.

`listeners` inventories TCP LISTEN sockets and UDP bound endpoints, with visible PID/process ownership and loopback/wildcard/interface exposure. A bound UDP endpoint is not proof of an application actively accepting requests. An exposed listener is not automatically a backdoor. No port probes or remote connections are made.

`persistence` inspects bounded, regular configuration files in `/etc/cron.d` and `/etc/systemd/system`, without following symlinks. It reports narrow startup-command indicators such as execution from temporary directories and risky remote-shell/download-execution patterns, using line hashes rather than full command content. It is not a full service/package inventory, authentication audit, web-shell detector, scheduled-task audit for Windows, antivirus engine, or rootkit scanner. Compare results against approved configurations.

Additional authorized directories can be explicitly inspected:

```sh
reverse-shell-decoy persistence --root /path/to/startup-configs
```

## Check typosquatting indicators offline

Put one domain or package name per line in each input. The trusted file is **your** baseline, not an automatically curated reputation list.

```sh
reverse-shell-decoy names --observed observed-domains.txt --trusted trusted-domains.txt --kind domain
reverse-shell-decoy names --observed observed-packages.txt --trusted trusted-packages.txt --kind package
reverse-shell-decoy audit --observed-names observed-domains.txt --trusted-names trusted-domains.txt
```

Checks cover spelling proximity, adjacent transpositions, selected Unicode/lookalike behavior and deceptive domain boundaries. Exact trusted entries and ordinary trusted subdomains are handled separately. Similarity is an investigative lead, not proof of impersonation. This tool does not query DNS, certificates, registries, domain age, redirect chains, package contents or live threat intelligence. It does not install any observed package.

## Present simulated privileged access

```sh
reverse-shell-decoy simulate --presentation realistic --audit session.jsonl
reverse-shell-decoy simulate --persona windows --presentation realistic --audit windows-session.jsonl
```

For a separately launched inbound service, use `sh scripts/start-honeypot.sh` rather than carrying cloud credential environment variables into the service. It starts on loopback by default and stops at its configured runtime/quotas; see [service boundaries](docs/service.md).

The terminal-facing stream uses a neutral maintenance banner instead of announcing a honeypot. A separate operator notice explains the simulation. Use `--presentation transparent` for a visibly labeled teaching session. Both modes retain `simulation: true` in every audit event.

Commands such as `whoami`, `id`, `uname`, `ls`, `cat`, `ps`, and `ss` return synthetic state. `touch`, `mkdir`, and `rm` mutate only bounded in-memory dictionaries. Unknown programs, scripts, shell operators, pipes and redirection are blocked. Neither persona executes Linux or Windows commands. There are no network connections, real persistence, privilege escalation, backdoors, or real agency records.

For a reproducible local continuation demo:

```sh
sh examples/continue-demo.sh < examples/decoy-commands.txt
```

Audit files are created exclusively rather than overwritten. They record UTC timestamps, known command verbs, blocked decisions, presentation/persona, and command/output SHA-256 hashes. They do not retain raw commands or arguments. Hashes alone cannot recover an unknown command or prove the identity of the person who entered it. See [service deployment boundaries](docs/service.md) for the separate optional inbound service and its operator-only connection telemetry.

## Export evidence for an investigator

```sh
reverse-shell-decoy evidence --paste --format text --audit session.jsonl --output case-bundle.zip
reverse-shell-decoy verify case-bundle.zip
```

The ZIP contains `host_os.json`, `detection.json`, `simulation_audit.json`, a blank custody worksheet, an explanatory README, and a SHA-256 manifest. `detection.json` separately names local host observations, selected imported logs, and optional offline name checks. Decoy activity remains in its own explicitly synthetic file.

Review all contents before giving a bundle to law enforcement or another investigator. Endpoints, process metadata, paths, and imported messages may be sensitive. Keep the original logs separately and follow the receiving organization's evidence-handling procedures. Hash consistency is not a digital signature, provenance attestation, completed chain of custody, or a guarantee of legal admissibility. The program never sends the bundle anywhere.

Runtime logs, evidence ZIPs, secrets and environment files are ignored by Git. Do not bypass the ignore rules or commit real evidence. Shell redirection such as `> report.json` uses your shell's normal file permissions; use a private working directory and restrictive umask when saving sensitive reports.

## Synthetic state experiments

```sh
reverse-shell-decoy experiment baseline
reverse-shell-decoy experiment process-limit
reverse-shell-decoy experiment network-loss --seed 42
reverse-shell-decoy experiment telemetry-gap
```

These run 30 virtual steps and compare an authoritative in-memory observer with a synthetic degraded sensor. They do not consume target resources, send packets, suppress actual telemetry, test an EDR, change OS process limits, or run metered APIs. There is no flooding, remote retaliation, denial-of-wallet mechanism or hidden monitoring interference.

## Optional container isolation for the decoy

```sh
docker build -t reverse-shell-decoy .
docker run --rm -i --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges=true --pids-limit 32 \
  --memory 128m --memory-swap 128m --cpus 0.5 \
  reverse-shell-decoy simulate --presentation realistic
```

The image runs as UID 10001, not root. Do not add host volumes, the Docker socket, privileged mode, host networking, host PID namespaces or published ports. Building the image may download its base image; the example runtime has no network. Runtime limits affect only this disposable container, not a remote system. A scanner inside it sees the container's namespace, not the actual host. The configuration is defense in depth, not a sandbox for executing hostile programs. Docker execution is not required for the CLI.

## Tests and limitations

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests use synthetic proc/config/log fixtures and hostile input strings. CI is configured for Python 3.10, 3.12 and 3.13 on Linux; see [testing notes](docs/testing.md) for what was actually executed locally. See [security policy](SECURITY.md), [trust boundaries](docs/threat-model.md), and [implementation references](docs/references.md).

MIT licensed. A triage tool can miss short-lived activity, hidden processes, namespace-isolated sockets, encrypted application behavior and persistence outside its configured roots. Neither a positive indicator nor an empty report is a definitive compromise verdict.
