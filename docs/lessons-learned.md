# CloudSentry: implementation lessons and final handoff

## What this build established

CloudSentry works best as independent tools with explicit handoffs—not as an agent that connects every module to every other module. Its hosted customer portal stays keyless and owner-scoped. Local collectors, scanners, the synthetic decoy, the inbound mirror, operating reports and review-only response proposals remain separate. Optional customer credentials expand available provider evidence without becoming a shared developer credential pool or a hosted token vault.

### 1. Independence is a practical security control

A pure trust-label function needs neither cloud access nor a database to test. A collector can be tested with mocked provider responses. A sink can be tested using tiny loopback inputs; its emergency profile can be tested without opening a port. These boundaries reduce the amount of code and authority involved in a failure. Do not add cross-module execution merely because it is convenient.

### 2. Evidence is not the conclusion

A socket peer, a recurring command pattern, a stylometric footprint, an imported integration status and a synthetic root prompt are different signals. None proves identity, execution, authorization or compromise by itself. Retain source/representation hashes, available timestamps, rule labels and unknowns. Imported assertions remain unverified; synthetic effects remain synthetic. A hash identifies a processed representation but does not authenticate its origin or establish a legal chain of custody.

### 3. Availability must not masquerade as coverage

The portal visibly distinguishes core-only mode from reported customer-authorized collection, reported integration failure and explicit reported credential expiry/revocation. A saved provider profile is only metadata. A generic 401/403, missing log or empty sample does not prove a revoked key, clean account or complete visibility. Core imports and offline rules remain usable without cloud credentials.

### 4. Read-only behavior and least privilege are different

The optional local collectors use fixed provider endpoints and bounded read-only request shapes. That does not reduce an overprivileged key's actual rights. Customers issue least-privilege keys, approve scope/time, revoke them natively and choose any later rerun. Credentials are not intentionally persisted by collectors, but remain in the customer's process environment until cleared; perfect memory erasure is not claimed. Redaction is best effort, including exact active credential values, not protection against every encoded or unknown secret.

### 5. Budgets protect local work, not the whole cloud bill

Global byte budgets, per-session limits, finite rates, timeouts, connection caps and audit limits make the decoy's application work finite. Global byte violations stop its listener and active sessions. Output reservations are conservative, not confirmed delivery. These controls cannot prevent all network floods, provider ingress charges, CPU/memory consumption or ongoing instance billing; independent runtime, network and spending controls are required.

### 6. An emergency decoy is not a recovery boundary

The manual emergency profile starts a new silent, non-executing listener with a fixed 30-second lifetime and small budgets. It does not take over a socket, silently redirect a visitor, interfere with OCR, retaliate, hold indefinitely or repair an exploited host. If actual containment fails, isolate affected resources through a trusted external provider/network control plane and preserve independent evidence.

### 7. Secret scanning should detect problems, not encourage exclusions

Gitleaks is pinned in CI and opt-in pre-commit configuration. Redacted release scans of reachable history and the working tree passed. The initial working-tree scan flagged a synthetic credential-shaped fixture; constructing that dummy value at runtime preserved the test without weakening scanner rules. A passing scan is not proof of no past/future leak. Revoke/rotate exposed credentials first; deleting a file or rewriting history does not revoke a key.

### 8. Cross-version CI adds evidence that local tests cannot

The first public matrix run caught a short-fraction ISO timestamp parsing difference on Python 3.10 that was absent on the sandbox's Python 3.12. The parser now pads fractional seconds before conversion, preserving the same chronological evidence ordering across supported runtimes. Fix the compatibility behavior rather than deleting the regression or narrowing the supported matrix merely to obtain a green badge.

## Actual release validation

- **208 local Python tests passed**; Python compilation and shell syntax checks passed.
- **33 portal tests passed**, including independently tested trust-state interpretation; TypeScript checks and production build passed.
- **Gitleaks 8.30.0 redacted reachable-history and working-tree scans passed** using the verified official CLI.
- The optional pre-commit configuration is supplied; installing hooks remains an explicit developer choice. CI execution after the public push is distinct from these local checks.
- Provider requests in tests were mocked. Tiny loopback interactions and synthetic files were used where needed. No customer cloud account was scanned, no actual incident was proved, no investigator submission occurred, and no public decoy was deployed as part of this work.

These checks are not a penetration test, legal opinion, formal isolation proof, complete credential audit or independent security certification. Reduced credential custody is not immunity from responsibility.

## Customer handoff

Open the hosted portal for managed sign-in, metadata-only profiles and explicit JSON imports. Use the repository's local tools only on authorized systems. Choose the decoy/emergency profile manually in a separate isolated environment, preserve audits privately, generate a selected report, review it and decide whether to import it. Portal summaries require fresh permission. Native provider routing, firewall/DNS changes, key revocation, external logging, infrastructure cost caps and incident-response decisions stay with the customer.

Reference guides: [engineering rules](engineering-rules.md), [integration trust and failure states](integration-trust.md), [secret scanning](secret-scanning.md), [resource budgets and customer opt-in](resource-economics.md), [emergency profile](emergency.md), and [trust model](threat-model.md).
