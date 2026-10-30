# Engineering rules and product boundaries

CloudSentry is a security triage product, not a reason to connect every subsystem to every other subsystem. Modular independence is a security feature. These rules guide changes; they are not a claim of certification, legal immunity, formal isolation or a completed independent penetration test.

## 1. Every subsystem must be independently testable

Use deterministic inputs and small explicit interfaces. Local detectors can consume synthetic procfs/log fixtures, the virtual terminal accepts only its synthetic state, the byte mirror has loopback-only tests, operations reports read a single selected audit, and optional collectors mock provider responses. The portal's trust-label interpreter is a pure function with no database or cloud dependency. Authentication and ownership enforcement stay server-side and are tested with injected repositories rather than shared live data.

From the repository root:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_budget_enforcement.py'
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_operations*.py'
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_integration_states.py'
cd portal
pnpm exec vitest run server/integration-trust.test.ts
```

These commands do not authorize a live scan or create a public decoy. A collector's successful mock test is not evidence that a customer's provider permissions or plan support the feature.

## 2. Every inference must preserve its evidence trail

Retain the selected source/representation hash, source category, available valid timestamps, rule/fixed indicator and uncertainty. Keep synthetic effects separate from observed interaction metadata; imported claims stay unverified. A generated hash proves only which selected representation was processed, not its origin, completeness or authenticity. The operating summary uses hash-referenced sessions and fixed labels rather than raw commands or an identity profile. Keep original logs and any complete custody records separately and privately.

The hosted import boundary preserves canonical original/sanitized representation hashes and source context; it is not a byte-for-byte forensic acquisition. A displayed integration status is a declaration from the selected import with a claimed check time, never a verified live connection. Do not combine an IP, a writing pattern, a token indicator and a synthetic root prompt into supposed identity, intent or unauthorized-access proof. Correlate independent evidence without treating one signal as proof of another.

## 3. Every integration must specify trust boundaries and failure behavior

| Boundary | Allowed input and action | Failure behavior / forbidden inference |
| --- | --- | --- |
| Core local tools | Explicitly selected bounded local input; deterministic analysis. | Malformed/unavailable input is an error or unknown coverage, never an all-clear. No cloud credential dependency. |
| Optional local collectors | Customer-issued, least-privilege credentials in the customer's process; fixed provider-owned endpoints and read-only requests; explicit scope/time window. | Missing credentials, scope mismatch, unsupported SDK/provider, authentication/permission/transport failures stop collection or return a bounded unavailable result. No shared-key fallback, broader scope discovery, mutation or implicit retry service. |
| Hosted customer portal | Validated managed session; owner-scoped metadata and explicitly consented JSON imports/summaries. | Fail closed on invalid session, state/nonce/origin/CSRF or ownership. Profiles are not authorization; the portal accepts no provider API keys and makes no collector calls. |
| Decoy / mirror | Deliberately started inbound service; synthetic parser or same-socket bounded bytes. | Budget/audit/time violations stop local work. No real interpreter, host mount, credential access, chosen-endpoint callback or automatic restart. Infrastructure isolation remains external. |
| Report / response handoff | Selected evidence-derived report and review-only proposals. | Do not submit a case, change DNS/firewalls, impersonate an actor or infer legal conclusions automatically. The customer decides any authorized native-platform response. |

Threat reviews must consider credential theft, request forgery/replay, consent bypass, hostile evidence/data poisoning, instruction injection, privilege escalation, tenant isolation and secret exfiltration. Treat uploaded statements as evidence data, not instructions. Do not add a message bus, cross-subsystem execution, credential vault or shared developer credential pool merely to make modules communicate.

See [integration trust](integration-trust.md), [resource budgets / customer opt-in](resource-economics.md), [trust model](threat-model.md) and [secret scanning](secret-scanning.md) for implementation-specific details. Any new integration must document its inputs, permissions, side effects, retained data, evidence origin, failure states, revocation path and independent tests before being considered ready.
