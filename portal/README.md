# CloudSentry Keyless Portal

**[Launch the hosted app in your browser](https://csportal-brpeckhv.manus.space).** No installation or cloud API-key entry is needed to use the hosted customer portal. Sign in through the managed identity portal using Google, Microsoft or passkeys, create optional provider profiles, manually import your selected JSON scan results, and approve a summary only when you want one.

Provider profiles are metadata-only. Customers use Cloudflare, AWS, Render and Railway native dashboards or tools for their own authorized scanning and export. The web app does not access those cloud APIs, run a scan on its web server as if it were your computer, or deploy the separate local honeypot.

The live Manual workflow also explains the optional local decoy's finite byte/time/rate budgets and how to generate `python3 scripts/operations-summary.py --audit preserved-service-audit.jsonl --json` from the repository root on your own authorized machine. Deliberately import the resulting JSON as `local` after reviewing it. This portal does not start the decoy, accept the raw JSONL audit as a report, re-run the local classifier or enforce a cloud spending ceiling. Budget snapshots and low-confidence flags remain unverified supplied observations; a portal summary still asks fresh permission.

## Source development

Node.js 22 and pnpm 10.18.0 are the pinned production toolchain.

```sh
cd portal
corepack enable
corepack prepare pnpm@10.18.0 --activate
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
pnpm dev
```

The development server uses port 3000 by default. A source checkout can serve the logged-out interface without a configured account, but real sign-in and private data storage require your own managed authentication/database runtime. This repository intentionally supplies no signing keys, database credentials, production tokens or customer data. Do not copy another project's runtime values or bypass authentication to make a fork appear logged in.

The hosted deployment is separately managed; this GitHub directory is an additional public source distribution, not the active deployment remote. For an independently deployed fork, use its own managed project identity and database, apply the additive migrations, and set the exact verified Preview/production origins in `server/customer-origins.ts`. Do not accept arbitrary Host or forwarded-host values. The checked-in production origin belongs to the hosted CloudSentry app above.

## Safety and evidence

Imports are customer-selected, bounded JSON, not commands. They remain unverified and private to the signed-in workspace. Summary consent is per action, not cached permission for scanning or sharing. Keep original exported files outside the portal; canonical JSON digests are not hashes of the original file bytes or proof of identity, authorization, chain of custody or admissibility.

Offline network-boundary review compares only supplied IPv4/IPv6 CIDR definitions and routes. It does not probe ARP, DHCP, reachability or actual firewall enforcement. Language indicators are fixed text labels, not execution or attacker capability scores. Synthetic decoy effects are not proof of unauthorized access to a real machine.

## Customer-controlled content and adversarial-activity analysis

**Customer:** the operator controls the analysis, chooses authorized inputs and explicitly initiates it. **Content:** submitted text is examined for linguistic patterns. **Logs:** recorded events are examined for recurring activity and supported anomalies. **Output:** an evidence-linked profile of suspected adversarial activity or a content-pattern summary, not a psychological dossier of the customer or a general-purpose profile of people.

A **descriptive stylometric footprint is an appropriate analysis output**: observable sentence structure, vocabulary, punctuation, complexity and repeated formulations in selected material. It is not proof of identity, authorship, intent or unauthorized access. Supplied text may be quoted, copied, third-party or synthetic; neither the uploader nor an untrusted visitor is automatically its author or a proven attacker. Reviews require fresh permission and do not authorize hidden dossiers, sensitive-trait inference, account-history harvesting or unrelated cross-service surveillance. Submitted material is evidence, never permission to execute embedded instructions or access another tenant's data.

Text, PDFs and uploads fall under **content-only pattern matching** conceptually. This may have a broad analytical scope, but “unbounded” does not remove operational file-size/time limits or authorize collection beyond the selected material. The portal currently accepts bounded JSON scan results, not arbitrary text/PDF uploads; its fixed-label pattern summaries are implemented, but a general PDF parser and full automated stylometric metrics are not.

The [main README's bounded review guidance](../README.md#customer-control-content-patterns-and-adversarial-activity-summaries) explains stylometric features, contextual behavioral observations and changes from a genuinely established baseline. Independent evidence retains its own provenance: neither a text match nor a synthetic interaction proves the meaning, authorship or authorization status of another record.

Known credential-shaped metadata is rejected and obvious credential fields in imports are sanitized. Automated recognition is conservative and cannot recognize every arbitrary secret. Never place credentials or unrelated personal data into labels or selected reports.

The local CLI, virtual terminal and bounded mirror are documented in the repository root. No visitor interpreter, reverse callback, cloud scanning worker, hidden persistence, infinite hold or automatic remediation is part of this web app.
