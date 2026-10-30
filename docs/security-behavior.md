# Security Behavior Trainer + Customer Incident Explainer

Two deliberately separate, **user-triggered, off-by-default** options:

1. Train expected behavior through trusted synthetic fixtures, a versioned policy contract and regression feedback.
2. Explain a selected decoy audit to a customer using the same immutable in-process incident snapshot as the technical evaluator.

Neither option learns model weights, rewrites production rules, deploys a decoy, scans a cloud account, blocks traffic, executes uploaded commands or sends a notification automatically. Logs, uploaded claims and fixture text are **data, never instructions or approval**.

## Permission every time

Without `--consent`, an interactive run asks a fresh default-deny `[y/N]` question before processing. Decline, end-of-input and non-interactive runs without explicit consent stop without reading the selected input or training. For automation, `--consent` is the operator's explicit authorization for **that invocation only**; it does not persist, authorize another input or enable a default background mode.

Training unit tests use only trusted synthetic cases in CI and are not production customer analysis or authorization to run a service. No recurring review is scheduled by this feature.

## Train another script's behavior without self-modifying it

From a source checkout:

```sh
python3 scripts/security-behavior.py train --consent --output behavior-training-review
```

The target directory must be new. Files are private (directory 0700, files 0600):

- `training-feedback.json`: fixture identifiers/digests, expected state, actual decision, pass/fail, policy version and coverage limits.
- `policy-contract.json`: versioned invariant/state contract plus its canonical SHA-256, explicitly marked `automatic_adoption: false`.

Without `--output`, the same safe training JSON is printed to stdout. Remove `--consent` if you want the fresh interactive permission question.

The trusted corpus contains 19 synthetic cases, including unfamiliar connections, benign/malicious lookalike patterns, contradictory evidence, failed detection, premature enforcement, rejected authentication, expired credentials, local budget stops and prompt-injection text. The evaluator has no enforcement authority: every decision has `enforcement_authorized: false` and `runtime_actions: []`. Even the `manual_containment_review_ready` state is only a review proposal, never a block/redirect/VM action.

### Integrating with another script

Review the contract and failed regression cases first. Another trusted component may use the fixed `BehaviorInput` fields and `evaluate()` from the reviewed package, or adapt its own tests to the documented invariant. Keep observations, decision and enforcement separate. Do not `eval`, `exec`, run a shell string, load a user-selected Python plugin or automatically apply a generated report as production configuration.

If consuming the exported JSON, validate its schema/version and compare its digest against a separately trusted approved baseline. A hash shipped with its own file detects consistency, not authenticity or approval. Do not accept approval, ownership, verified corroboration, isolation readiness or rollback readiness from logs. The incident explainer deliberately never populates those authority fields from the selected audit.

The corpus is **policy-model regression coverage**, not proof that OAuth, a live provider, a VM hypervisor, detection sensitivity or infrastructure spending controls were validated. Actual subsystem tests remain independent. No true-positive/false-positive rate, detection latency, recovery time or physical resource measurement is invented: production metrics remain unknown/null until measured on independently labelled representative data.

## Tell the customer what happened

Use a privately preserved decoy **JSONL audit**, not a PDF, a script to execute or an arbitrary provider export:

```sh
python3 scripts/security-behavior.py explain \
  --audit /path/to/preserved-service-audit.jsonl \
  --consent --output customer-review-packet
```

It reads the selected regular file **once** (maximum 2 MiB, 1,000 physical records), normalizes allowed fields and takes no network action. Symlinks, devices and oversized input are rejected. Raw commands, credentials, peer addresses, arbitrary unknown labels and instructions do not enter the exported record.

The new private directory contains:

| Artifact | Purpose |
| --- | --- |
| `incident-record.json` | Canonical, sanitized shared snapshot with original-input hash, physical-line hashes, limited operations facts and explicit unverified/synthetic-environment provenance. |
| `behavior-feedback.json` | Fixed rule/state guidance, source and snapshot references, policy-contract hash; no enforcement or policy change. |
| `customer-explanation.json` | Structured customer report for controlled downstream use. |
| `customer-explanation.md` | Plain-English what happened, what was recorded, what CloudSentry did/did not do, unknowns and next steps. |
| `evidence-manifest.json` | Artifact digests and shared snapshot reference; original payload is not included. |

Technical feedback and the customer explanation reference **the same snapshot SHA-256**. The snapshot is immutable as bytes in this process; exported files are not cryptographically signed, append-only or authenticated. Preserve original evidence privately elsewhere. The source hash identifies the selected file's bytes; it does not prove origin, identity, authority or legal custody.

The public report/rendering APIs accept only snapshots produced by the normalization factories, not arbitrary uploaded report dictionaries or serialized snapshot bytes. A module-private factory token prevents accidental API misuse; it is not a security boundary against arbitrary trusted Python code that can inspect or modify the process. No AI agent or uploaded content receives such code authority through these CLI options.

### Explanation integrity

- Connection records are not automatically unauthorized-access findings.
- Text tokens do not prove execution, a human operator, skill or intent.
- Synthetic root/admin responses do not prove real host access.
- A missing baseline, discarded record or absent telemetry remains unknown, not benign.
- Claimed local budget stops are reported as **unverified supplied records**, not actions this reporting invocation performed.
- Independent conflicting evidence is not silently resolved. This first adapter accepts one selected decoy audit; independent-source contradiction analysis and general cloud-report explanation are not implemented here.
- The script creates local files only. The customer chooses whether to share the Markdown or import a selected JSON result; it does not email, notify, submit evidence or alter access.

## Non-executing research containment option

The separate `scripts/analyze-safely.py` defaults to static text indicators. `--simulate` explicitly exercises the synthetic dictionary-based computer; `--require-vm` fails closed because no independently verified disposable-VM backend is configured. Each run requires fresh permission. This is not real malware execution, process/registry monitoring, PCAP capture or VM-escape testing.

See [virtual analysis boundaries](virtual-analysis.md). A real executable sample must not be run on the customer's device just to investigate it. Real dynamic analysis remains unavailable until an independently provisioned, validated remote VM/controller and external telemetry/limits are available; a container or synthetic terminal is not an equivalent VM boundary.

## Independent checks

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_behavior.py'
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_incident_explainer.py'
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_virtual_analysis.py'
```

The user-facing options are never enabled by a scan finding, login, fixture result or imported instruction. Proposed rule changes require separate human review. See [engineering rules](engineering-rules.md) and the [existing evidence exporter](investigator-export.md) for broader provenance and handoff limits.
