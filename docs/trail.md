# Text-pattern trail

`reverse_shell_decoy.trail` emits one JSON object to standard output from explicitly selected synthetic decoy JSONL audit files. It is a local report projection: it does not execute input, scan a host, write any output files, open a network connection, identify a visitor, infer a visitor operating system, or assign a skill score.

```sh
python scripts/trail.py \
  --audit selected-console.jsonl \
  --audit selected-terminal.jsonl > trail.json
```

`--audit FILE` is required and may be supplied at most four times. The same selected-regular-file, 2 MiB-per-file, and 1,000-nonblank-record combined bounds used by the investigator exporter apply. The command writes the resulting JSON only to stdout; shell redirection, if wanted, is an operator decision outside the tool. It never creates trail files itself.

## Output and evidence boundary

The trail calls `investigator.build_report(audit_paths)` and projects only values that the investigator report has already retained under its strict allowlist. Each trail timeline item may include:

- a source-file SHA-256 reference, physical JSONL line index, and line SHA-256;
- a supplied `timestamp_utc`, when present and valid;
- fixed `source_kind` and `classification` labels;
- a retained `command_sha256` or `input_sha256`, when present;
- a retained `blocked` boolean;
- the fixed `language_indicator` and `token_indicators` labels, when present.

The source-reference list contains only an ordinal and a SHA-256 of the selected source bytes. It deliberately does not reveal selected file paths or basenames. Raw commands, arguments, raw mirror payloads, keys, environment values, credentials, peer addresses, visitor identity, visitor OS, arbitrary text, dictionaries, and competence or “skill” scores are not included.

The top-level status is always `authorization_status: "not_established"`. Every output includes this statement:

> Text pattern only; not execution, intent, competence, attribution or proof of unauthorized host access.

Language and token counters are counts of retained fixed labels only. They are not performance, timing, delay, speed, capability, intent, attribution, or competence metrics.

## Fixed classifier labels

The allowed `language_indicator` values are `php`, `python`, `perl`, `ruby`, `node`, `bash`, `sh`, `nc`, `powershell`, and `unknown`. The allowed `token_indicators` values are `php_network_api`, `php_stream_api`, `process_api`, `python_socket_api`, `shell_path`, and `encoded_text`.

A language field must exactly equal one of those labels. Token indicators must be a JSON list of no more than six labels, every one exactly from that fixed token set. Invalid language values, non-list token fields, overlong token lists, unknown tokens, and nested or arbitrary values are excluded by the investigator report and counted there as warnings. No raw text is copied to explain a label.

Classification is limited to bounded text patterns from the first submitted command, at most 4,096 input characters. It does not run, parse as a program, authorize, replay, emulate, or validate that text. In opaque mirror mode, bytes remain opaque: they are not decoded or classified, and no language or token field is added.

## Virtual PHP console persona

The default console presentation has a virtual PHP persona metadata layer. It is inert, bounded decoy text rather than host discovery. The metadata responses for `php -v`, `php -m`, and `which php python3 nc` list the virtual PHP tool first. The simulated `which` response is pre-defined metadata; it never calls the host `which` utility or looks up installed executables.

PHP execution flags and PHP script invocations are blocked immediately. They do not load a script or execute PHP, and they consume the same existing command and audit quotas as any other submitted console input. The service does not introduce random delays, infinite holds, quota changes, or language-specific performance behavior.

## Safety properties

Trail generation has no subprocess, shell, socket, or network code. It relies on the investigator reader, which accepts only explicitly selected regular files and normalizes only synthetic records from recognized decoy sources. SHA-256 values provide integrity-consistency references for supplied bytes; they do not authenticate a source, prove authorship, establish provenance, identify a person, establish intent, or prove access to an unauthorized host.
