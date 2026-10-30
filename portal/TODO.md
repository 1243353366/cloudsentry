# CloudSentry — Keyless Customer Portal

Approved design remains Signal Room Amber: graphite #171717, amber #F59E0B, Source Sans 3 and an evidence-led monitoring-room interface. The user explicitly approved: “Publish the keyless version with managed sign-in and manual imports.” This supersedes direct provider OAuth app setup and in-app credential-based cloud scanning.

- [ ] Real managed customer sign-in. Customers choose Google, Microsoft or passkeys on the verified managed sign-in portal. Do not advertise GitHub sign-in, fabricate a Preview user or request builder OAuth app keys. Validate application sessions and project identity server-side.
- [ ] Customer-isolated workspaces, with server-enforced ownership for every provider profile, imported report and summary. Customers—not the builder—select their own provider profiles. No ambient builder cloud credentials or connectors are used.
- [ ] Optional independently removable Cloudflare, AWS, Render and Railway provider profiles containing only labels, account/workspace identifiers and optional region. A profile is not an authenticated cloud connection. No API-key, password or cloud-token fields, capture or storage.
- [ ] Manual cloud workflow only: customers sign in using provider-native dashboards or tools, export their selected results, then deliberately import JSON. Remove in-app cloud collection, child processes and API-scan execution. Local machine scans remain in the separate local tool.
- [ ] An enabled-by-default post-import summary offer that asks fresh permission every time. Skip does not generate a summary. Permission for a summary is not permission for account access, uploads to law enforcement or remediation.
- [ ] Deterministic summaries separating observed tooling or synthetic decoy actions, defensive review indicators and legally relevant evidence context. Label unknown, unverified and synthetic claims; do not infer real attacker skill, identity or unauthorized real-host access.
- [ ] Bounded offline review of customer-supplied network/CIDR configuration from the final attachment, including overlap, broad-prefix review and selected route inconsistencies. No ARP, DHCP or reachability probe, no portal-host inventory claim, no IP/subnet-based authentication and no automatic fixes.
- [ ] Strict separation from the existing decoy, PHP metadata persona, mirror and local scanner. No visitor code execution, outbound callbacks, indefinite holds, hidden persistence, automatic remediation or denial-of-wallet behavior.
- [ ] Private runtime data and clean public source: no incident records, passwords or tokens committed. Platform-managed signing material may derive a distinct private-data encryption key; users supply no keys. Imported evidence is sanitized and marked unverified, with representation-hash scope explained.
- [ ] Read-only end-to-end implementation review of real auth, nonce/state, CSRF, ownership, metadata-only profiles, import consent, summary consent and production readiness. Resolve confirmed defects without a fake login test or fake incident data.
- [ ] Save an accepted Manus checkpoint, deploy the final version, configure the exact production OAuth origin and verify it. Deliver the permanent URL only after successful final publication. Update public source safely without overwriting repository history or including runtime data.

## Existing local tool

The separate local source package includes virtual PHP metadata, bounded text indicators, an investigator exporter and per-invocation consent-gated summaries. Its integrated suite passes 179 tests. No actual incident records were supplied, no case evidence was submitted, and no customer's cloud accounts have been accessed.

## Approved defensive-resource update

- [x] Explain the optional local decoy's finite global input/output budgets, per-session input budget and configurable rate, with no remote workload or guaranteed cloud-bill ceiling.
- [x] Show the customer-run command for generating an operating report from one explicitly selected local audit, then importing that JSON as provider `local`; do not launch a decoy, inspect a portal host, accept raw audit streams or grant cloud access through this website.
- [x] Link to the public resource-economics guide and explain low-confidence pattern flags, unknown coverage, unverified sources and fresh summary consent. Keep the existing exact-origin/CSRF/ownership/authentication protections unchanged.
- [ ] Check the affected portal build, publish an accepted managed checkpoint and verify the final live version. Publish reviewed local source and README updates to the existing public repository without secrets or incident data.

## Customer-requested integration trust and engineering rules

- [ ] Keep the baseline portal keyless and fully available for manual imports. Display core-only mode visibly; saved profiles are metadata, never authenticated cloud connections. Optional BYOK stays an explicitly invoked local read-only collector with no shared developer credential pool or hosted key vault.
- [ ] Show fixed integration states from a selected imported collector report as unverified declarations: customer-authorized integration, integration unavailable, or credential expired/revoked only when explicitly supplied by the local collector. Missing data, imports and profiles must not be treated as verified access or complete coverage. Retain the exact source/representation hashes and unknowns through the existing report boundary.
- [ ] Keep trust-state interpretation independently testable and free of provider calls, account discovery, side effects or raw credential display. Preserve existing ownership, exact-origin, authentication and fresh summary-consent enforcement.
- [ ] Add secret scanning to public CI and opt-in pre-commit checks; document no automatic key retention, least-privilege provider permissions, revocation and fail-closed behavior. No keys enter frontend bundles, Git history or logs by design; scanning reduces risk but cannot guarantee absence of secrets.
- [ ] Document subsystem independence, evidence-preserving inference and explicit integration trust/failure contracts. Do not connect unrelated subsystems or imply legal immunity. Push reviewed public source and publish the tested customer-facing update.

## Final manual emergency layer

- [x] Provide a separately testable local emergency-only silent sink with fixed small budgets and a 30-second whole-service lifetime. Accept only bind/port and explicit non-loopback opt-in, emit no application response and execute no input. It starts a new listener only; it does not take over connections, automatically activate after a finding, deploy from the website, interfere with OCR/security tools or replace trusted external containment of a compromised host.
- [ ] Extract the implementation lessons and verified/unverified boundaries into a concise handoff; push reviewed source and publish the final customer-facing instructions.

## Credited combined toolkit and final demonstration

- [ ] Publish concise manual instructions for the separately permission-gated static configuration auditor, customer forensic-style text/audit report and resource-policy review. The portal must not execute any of them, start a service/VM, take provider credentials or treat imported output as authorization.
- [ ] Credit HuginnsHammer's original MIT configuration-auditor project and link the root creator/source index; preserve licensed source independently in the public repository. Keep descriptive writing metrics distinct from identity, psychology or legal proof, and declared/unknown resource controls distinct from verified enforcement.
- [ ] Finish core, independent upstream and portal checks; publish the accepted checkpoint and public main source, then demonstrate the actual live page without a fabricated customer login or unapproved private-data import.

## Review-8 patch release and walkthrough

- [ ] Publish a visible link to the reviewed 0.1.1 core / 1.0.1 portal changelog, including the previous 0.1.0 source checkpoint, prior deployed portal checkpoint and tested scope. The old version remains in Git history; no reset or history rewriting.
- [ ] Explain confirmed fixes separately from deliberate safety boundaries, unconfirmed review claims and remaining limits. No automatic retry/relisten, provider scan, local service or VM launch is added to the website.
- [ ] Preserve exact-origin, authentication, CSRF and ownership boundaries, check the changed portal, save its checkpoint, publish it and verify the live release-note link.
