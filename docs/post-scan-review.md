# Local post-scan review

`reverse_shell_decoy.review` provides a deterministic, local-only summary of a scan result that has already been produced. It is a review aid, not a scanner. It does not contact a network service, upload data, call an LLM, probe another system, replay content, create a report file, remediate a host, or retaliate.

## CLI behavior

The main CLI offers a review **after** each explicit `scan`, `os`, `listeners`, `persistence`, `names`, `audit`, `cloud`, or `collect-cloud` result is emitted. It does not add automatic scanning or automatic report generation.

The offer appears only when both standard input and standard error are TTYs. The prompt is shown on stderr so JSON emitted by the scan remains unchanged on stdout:

```text
Local only: no uploads occur, and this summary is not legal proof.
Generate a local incident-review summary from these scan results? [y/N]
```

Only a literal `y` or `yes`, ignoring surrounding whitespace and letter case, accepts. EOF, Ctrl-C, an input error, `n`, empty input, and every other answer decline. Consent is never cached, and there is no `--yes`, non-interactive, or other bypass. When stdin or stderr is not interactive, the offer does not read stdin and does not create a review.

If accepted, the JSON review is written only to stderr. The original scan JSON on stdout is not altered.

## Standalone selected-file review

For a scan JSON saved by an authorized operator, use the standalone script:

```sh
PYTHONPATH=src python3 scripts/review-scan.py \
  --scan selected-scan.json --command listeners
```

Optional, explicitly selected synthetic decoy audit files can contribute bounded investigator metadata:

```sh
PYTHONPATH=src python3 scripts/review-scan.py \
  --scan selected-audit.json --command audit \
  --audit selected-decoy-audit.jsonl
```

The standalone script asks each time **before opening the selected scan file or any selected audit file**. Its prompt names only a sanitized scan-file basename, never a path or scan/audit content. It accepts no consent-bypass flag. A declined or non-interactive invocation exits successfully without reading the selected files, writing a file, or writing a JSON review. After accepted consent, it reads only a regular scan JSON file up to 8 MiB; the JSON root must be an object. It writes the requested structured review JSON to stdout and never writes a report file.

Audit metadata, when selected, is processed through the existing bounded local investigator report. The review keeps aggregate classification/tooling counts and source SHA-256 references only. It never copies audit payloads, commands, arguments, credentials, endpoints, raw warnings, or paths.

## What the review says

The report separates three questions.

- **Their capabilities** is labeled `observed_tooling_and_decoy_actions`. It reports only fixed labels observed in selected synthetic decoy audit metadata. With no recognized selected audit observation, it is `unknown`. It is not a real attacker capability score and does not establish execution, intent, competence, identity, attribution, or unauthorized access to a real host.
- **My weaknesses** is labeled `defensive_review_indicators`. It reports actual aggregate indicator counts, listener exposure categories, and coverage gaps from the supplied result. A wildcard or interface binding does not prove Internet reachability, maliciousness, or a backdoor. A shell/socket heuristic does not prove an outward connection, intent, or compromise. Missing logs, empty findings, and incomplete coverage are never an all-clear.
- **Legally important information** preserves a SHA-256 of the tool's canonical JSON representation of the supplied scan result. That digest is a representation hash, not a hash of original evidence bytes and not an authenticity, authorship, provenance, or custody proof. Where the source report already provides a safe source SHA-256, it is listed separately with its limited scope.

The review retains only UTC timestamps already supplied by an underlying report. It does not invent incident times. It explicitly leaves these claims unresolved:

```json
{
  "real_host_unauthorized_access": "not_established",
  "visitor_identity": "unknown",
  "remote_os": "unknown",
  "authorization_status": "not_established"
}
```

Retain original records in their native acquisition context, chain-of-custody/handling records, asset ownership records, the applicable authorization policy, and independent corroboration where available. This review is not jurisdiction-specific legal advice, legal proof, a legal-admissibility determination, or an all-clear conclusion.

## Data minimization and bounds

The summary uses known scan schemas for detector, listener, persistence, correlation/audit, manual cloud-log analysis, manually requested cloud collection, and offline name checks. It aggregates count and exposure fields rather than copying findings. Unknown fields are not replayed. Review processing caps list inspection and emitted references at 1,000 entries; oversized or malformed schema portions are represented as fixed schema-gap indicators rather than reflected text.

The consent record states that consent was for local review generation only. It does not authorize a scan, a visitor interaction, access to another system, or any person, and it is not an authenticated identity record.
