# Customer forensic descriptive report

`customer-forensic-report.py` creates a **new local, private report packet** from files the operator explicitly selects. It is designed to explain aggregate characteristics of submitted suspected adversarial content and optional supplied technical records. It is not a dossier about the customer.

The report is deliberately descriptive. It does not make authorship, identity, attribution, psychological, health, skill, intent, crime-certainty, legal, access, execution, or unauthorized-activity conclusions. It does not execute submitted content, launch a service or VM, call a cloud provider, scan a network, train a model, change policy, or take an automatic action.

## Run

Use the direct script from the repository. Each invocation needs fresh consent, and the output directory must not already exist:

```bash
python3 scripts/customer-forensic-report.py \
  --text /selected/suspected-content.txt \
  --baseline /selected/comparison-sample.txt \
  --audit /selected/decoy-audit.jsonl \
  --lab-report /selected/local-lab-result.json \
  --output-dir /secure/new-customer-report \
  --consent
```

All input flags are optional, but at least one input is required. `--output-dir` and `--consent` are required. If `--consent` is omitted, the command may ask interactively only on a terminal; denial or non-interactive absence of a grant reads no selected file and creates no output.

Available selected inputs are:

| Option | Accepted input | Limit | Treatment |
|---|---|---:|---|
| `--text` | UTF-8 selected plaintext | 256 KiB | Aggregate descriptive metrics for the submitted sample |
| `--baseline` | A distinct UTF-8 selected plaintext file | 256 KiB | Separate aggregate metrics; optional comparison only |
| `--audit` | UTF-8 JSONL selected local audit | 1 MiB | Existing local byte-only audit summary, then fixed aggregate counts only |
| `--lab-report` | UTF-8 JSON local lab result | 64 KiB | Strict allowlist of known report shapes and fixed boolean flags only |

The combined selected-input ceiling is 2 MiB. Every selected path must be a regular file; symlinks, devices, FIFOs, and oversized files are rejected by the safe reader. Inputs are read once as bytes and SHA-256 hashed exactly as read. PDF headers, NUL bytes, and non-UTF-8 plaintext are rejected; the tool does not perform OCR or claim PDF extraction. Manually extract a selected UTF-8 plaintext portion first if that is the appropriate review workflow.

## Fresh authorization and failure behavior

Before it opens any selected input, the tool computes an exact authorization scope:

- Operation: `customer_forensic_report`
- Input reference: SHA-256 of canonical JSON containing the absolute selected paths and their input types
- Output reference: the absolute new output directory

A grant is obtained only through the local authorization gate, begins once, and is checked before and after each read, before every artifact write, and at completion. The grant is revoked on exit and by the cancellation guard for `SIGINT` or `SIGTERM`.

The output directory is created with mode `0700` only when absent. Fixed artifact files are created with `O_EXCL`, no-follow behavior, and mode `0600`; existing output is never overwritten. If a grant becomes invalid or another error occurs, the tool removes only the directory and fixed artifacts it created in this invocation. It does not discover, traverse, or delete other directories.

## Report packet

A successful invocation emits these files in the new directory:

| File | Purpose |
|---|---|
| `customer-forensic-report.json` | Canonical structured report with aggregate results and boundaries |
| `customer-forensic-report.md` | Fixed-label customer-readable summary with no submitted prose, filenames, commands, payloads, secret patterns, or free lexemes |
| `customer-forensic-manifest.json` | Packet and artifact SHA-256 bindings |

The CLI prints the SHA-256 of the raw manifest bytes. Preserve that value separately from the packet. The manifest contains a random 128-bit packet ID, UTC generation time, source IDs (`text1`, `baseline1`, `audit1`, `lab_report1`), source type, exact source SHA-256, byte counts, supplied/unverified provenance labels, fixed source counts, and hashes of the two report artifacts. A supplied source is never treated as an author identity.

The packet records that the model was not trained by the inputs, policy did not change, automatic actions are false, and VM deployment authorization remains false.

## Descriptive style metrics

For selected plaintext, the output provides only aggregate values such as character and whitespace counts, sentence-regex proxies, Unicode word count, unique-word count, type/token ratio, hapax ratio, word-length mean and median, sentence-word and paragraph proxies, fixed ASCII punctuation counts, uppercase and digit fractions, a repeated normalized-bigram count, a fixed function-word distribution labeled as an English heuristic only, and the existing fixed terminology signal labels.

No words, normalized bigrams, quotations, source filenames, raw text, commands, payloads, or secret-looking values are emitted. Sentence and paragraph figures are not syntax or quality measurements. Fixed terminology signals may occur in harmless text and never establish execution, capability, skill, intent, or authorization.

When both `--text` and `--baseline` are supplied, the baseline remains a separate source profile. The optional delta section labels sample-length effects and treats topic, quotation, and language effects as unknown or unmeasured. It has no similarity, authorship, identity, or match score; baseline comparability is explicitly unknown.

## Technical inputs and provenance limits

For a selected audit, the report invokes only the existing byte-only local audit summary path after checking its callable signature. The customer report exposes fixed record/session/classification counts and no raw commands, session identifiers, remote IP addresses, timestamps, or audit text. Remote-IP collection is `none` by default. Any timestamps or remote-address claims in an input are customer-supplied claims, not independent evidence. The counts describe supplied records only; they do not establish a person, access, execution, impact, remote identity, or legal conclusion. Echoes and synthetic responses are not proof of unauthorized access.

A selected lab report must have `format` equal to one of these known shapes:

- `trusted_software_vm_lab_v1`
- `backup_layer_smoke_v1`
- `resource_boundary_v1`

The normalizer copies only fixed, known fields and requires literal JSON booleans; for example, the string `"true"` is not true. Missing or invalid boolean observations remain `null` (unknown), not evidence that a test failed or passed. Even a perfectly shaped report with `true` fields is marked `UNVERIFIED_INPUT`, does not become independent attestation, and cannot activate deployment, failover, or any other action. This protects against an input a customer can forge.

Resource-report CPU, memory, I/O and GPU states are allowlisted as `declared`, `verified_local_readback`, `not_verified` or `unknown`. Those are **supplied claims**; this report did not query a kernel or GPU policy. The customer-readable report explains that CPU/memory/PID and device-specific I/O controls protect the customer's own workload, that the echo grants no GPU workload, and that contention/throttling is an investigation signal rather than proof of mining, cracking, inference, exfiltration or intent. It does not promise side-channel immunity, an SLA or a spending ceiling.

The `programming_language_indicator` is a bounded code-token pattern label, not a determination of the author's natural language. The fixed function-word distribution is separately labeled as an English heuristic. The tool does not infer human-language identity or use a code-language label as baseline authorship evidence.

## Integrity checking

`reverse_shell_decoy.customer_forensics.verify_packet_manifest()` is a pure in-memory helper. Given raw manifest bytes, an externally retained manifest SHA-256 pin, and optionally the two artifact byte strings, it can:

1. Check that the raw manifest matches the separately retained pin.
2. Check supplied artifact bytes against the manifest artifact hashes.

This can detect later alteration when the pin is retained separately. It is not a signature, does not prove identity or source authenticity, and is **not compatible with the existing incident-packet verifier**. The packet's own manifest is never its own trust root.
