# Combined release: checks and working demonstrations

This source release adds independent opt-in static configuration auditing, a consent-gated customer forensic-style packet, a fail-closed resource-policy helper, trusted software-lab tests and a central source/creator index. The hosted portal remains keyless and manually operated; it does not execute any local tool, start a VM or run a visitor command.

## Observed checks

| Scope | Observed result | What it establishes |
|---|---|---|
| Core local Python suite | 363 tests passed | Existing and new bounded behavior, evidence, consent and mocked integration regressions on the development interpreter. Not every possible input or deployed kernel. |
| Preserved upstream configuration auditor | 95 tests passed; one upstream dependency deprecation warning | Reviewed pinned scanner behavior in a separate Python 3.12 environment. |
| Customer portal | 33 tests passed; typecheck and production build passed | Existing auth/ownership/consent and pure trust/network interpretation regressions plus a build of the updated instructions. No fabricated login or customer record was inserted. |
| Configuration scan demonstration | `CS-DKR-002` mutable latest tag; `CS-DKR-001` explicit root user | Real static scan of the preserved deliberately vulnerable Dockerfile. Exit 1 correctly represented findings; no Docker/Terraform execution occurred. |
| Customer packet demonstration | Exact artifact hashes verified against the printed manifest pin | Original synthetic text and a declared resource-policy report produced a private customer-readable packet, not evidence of a real incident. Raw selected prose was absent from Markdown. |
| Resource policy review | `ready:false`, `review_only:true`, `service_launched:false` | Fixed limits were described only. This sandbox did not receive writable cgroup delegation, GPU-deny-policy integration or permission to pretend otherwise. |
| Software TPM and qcow2 | Trusted functional checks passed; temporary resources removed | Software TPM startup/capability/PCR fixture and offline disposable snapshot/restore work without physical TPM hardware. |
| Firmware / Secure Boot | Partial; required positive observation absent, enforcement unknown; CLI exit 2 | A bounded attempt, not a passing firmware trust-chain test or hostile-guest isolation certification. |

The publisher separately checks redacted secret scanning and public CI; do not infer a completed GitHub run from this local table. A repository push, saved website checkpoint and successful website deployment are separate events.

**Still unproven:** firmware/Secure Boot enforcement and production VM containment — [see the containment note](../README.md#limitations-and-transparency-echo-is-not-containment).

## Reproduce the useful demonstrations

After following the [auditor setup](config-auditor-integration.md), run:

```sh
python3 scripts/scan-configurations.py \
  --target integrations/config-auditor/examples/docker/Dockerfile.vulnerable \
  --format json --consent
```

Exit 1 is expected for that original upstream vulnerable example. Use `--format sarif` for SARIF or `--format text` for a terminal table. Do not build the vulnerable example.

For a customer-readable packet, choose your own authorized inputs:

```sh
python3 scripts/customer-forensic-report.py --text selected-content.txt \
  --audit selected-audit.jsonl --output-dir new-private-packet --consent
python3 scripts/rationed-echo.py --review --consent
```

The first command requires fresh exact-scope permission, creates a new private directory only, preserves source hashes and prints a manifest pin to preserve through a separate trusted channel. Keep original evidence separately. Selected writing metrics are descriptive, not identity, psychology, skill or legal proof. The second command does not apply limits or launch a service. Unknown resource enforcement stays unknown.

[All guides and referenced creators](../LINKS.md) are indexed from the root README. [Ethical use](../ETHICS.md) and component-specific licenses remain part of the release. No remote resource-exhaustion echo loop, automatic failover/provisioning, GPU workload, direct outreach, public evidence upload or third-party corpus submission is included.
