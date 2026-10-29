# CloudSentry Keyless Portal

**[Launch the hosted app in your browser](https://csportal-brpeckhv.manus.space).** No installation or cloud API-key entry is needed to use the hosted customer portal. Sign in through the managed identity portal using Google, Microsoft or passkeys, create optional provider profiles, manually import your selected JSON scan results, and approve a summary only when you want one.

Provider profiles are metadata-only. Customers use Cloudflare, AWS, Render and Railway native dashboards or tools for their own authorized scanning and export. The web app does not access those cloud APIs, run a scan on its web server as if it were your computer, or deploy the separate local honeypot.

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

Known credential-shaped metadata is rejected and obvious credential fields in imports are sanitized. Automated recognition is conservative and cannot recognize every arbitrary secret. Never place credentials or unrelated personal data into labels or selected reports.

The local CLI, virtual terminal and bounded mirror are documented in the repository root. No visitor interpreter, reverse callback, cloud scanning worker, hidden persistence, infinite hold or automatic remediation is part of this web app.
