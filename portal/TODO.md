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
