# CloudSentry changelog

The core Python package and browser portal have separate versions. A public source push, saved portal checkpoint, completed CI run and live publication are different events. Historical results below describe their named source scope, not production containment or every later commit.

## Core 0.1.1 / portal 1.0.1 — 2026-10-30

Patch release following the supplied review of core 0.1.0 at [`4dea59f`](https://github.com/1243353366/cloudsentry/tree/4dea59f2c276d39ac20ed0ec926b6f2548b16389). The portal changes only its release version and visible changelog link; it does not execute local fixes or collect cloud data on its server.

### Walkthrough: what changes for the customer

1. **A later cloud failure no longer erases earlier successful records.** Render now retains completed service-event pages when a later service request fails. The same protection covers bounded Cloudflare and AWS pagination. Results explicitly mark truncated/partial coverage and retain a safe warning. A partial sample is not a clean-account verdict; no live provider access was used to validate these changes.

2. **Redaction preserves more useful evidence while covering known cross-provider credentials.** Local collector output now removes exact credential values from the fixed supported-provider environment-name allowlist, not only the selected provider's names. Explicit token usage/count metrics such as `tokensUsed` and `expirationTokenCount` can survive, while ambiguous secret-bearing fields remain omitted. This does not discover every opaque secret or scan arbitrary environment variables. Review exports before sharing them.

3. **HTTP failure behavior is clearer and more bounded.** Standard urllib HTTPS body reads use a single monotonic deadline rather than a new 15-second window per chunk; the 8 MiB response cap remains. A secure redirect-refusing opener/TLS context is reused without caching credential values or response data. Redirect refusals and HTTP 429 return explicit fixed reasons, without provider bodies or `Location` values. `Retry-After` presence is noted without following it or adding automatic retries. Opaque response wrappers and underlying resolver/custom-I/O behavior do not gain a universal hard cancellation guarantee.

4. **Console audits cannot reuse the previous command's event metadata at the simulator limit.** The service now checks whether the simulator appended a new event before using it. If no event was created, it records the current limit refusal and response hash instead. The normal service limit remains 100 commands, below the simulator's 1,000-event bound; the new regression exercises the otherwise unreachable boundary without raising either production cap. MIRROR stays opaque, same-socket and non-executing.

5. **Launchers and the selected-file bridge have stricter local boundaries.** Six service launchers use a fixed POSIX shell/path, `/usr/bin/env -i` and `/usr/bin/python3` rather than resolving an interpreter through inherited PATH or invoking inherited Bash first. The configuration worker explicitly closes unrelated descriptors. Before the upstream scanner reads its selected input, the host-added bridge creates a bounded private regular-file snapshot from the authorized descriptor and rejects ordinary concurrent mutation. This is not a filesystem lock or forensic guarantee against a privileged local writer.

6. **Evidence versioning has one source, and ZIP resource errors fail safely.** Build metadata and evidence manifests use `reverse_shell_decoy.__version__`. Existing 0.1.0 packets can still verify consistently, with a different-version warning instead of silently becoming invalid. `LargeZipFile` and `MemoryError` become a fixed invalid-bundle result; external OS quotas remain necessary because catching an exception cannot undo prior resource consumption.

7. **CI inputs are immutable.** Reusable GitHub Actions and the local Gitleaks pre-commit hook are pinned to verified full commit SHAs, with version comments retained. Secret scans still fail their job on findings; no rule or failure check was weakened. A failed job blocks merging only when the repository's separate branch-protection/ruleset settings require it; this release does not assert or silently change those settings.

### What deliberately did not change

- `--consent` is the operator's explicit declaration for that invocation, not proof of ownership, legal authority or OS policy enforcement. Exact-scope, expiry, revocation and single-run checks remain in-process safeguards, not a security boundary against arbitrary code already running in that process.
- The review's PEP 475 cancellation allegation did **not reproduce**: bounded isolated child-process tests interrupted blocked pipe reads and socket receives with SIGINT, revoked the grant and restored handlers. That result is scoped to the tested Linux/Python primitives, not every platform or extension.
- Global lifetime/connection/byte budgets remain finite. There is no automatic cooldown, restart or re-listen. Public exposure needs independent ingress fair-share/rate/connection controls; one source can still consume a deliberately finite global allowance.
- Once output budget is exhausted, a bare close remains correct: a friendly rejection message would itself exceed the cap. Direct startup still refuses known inherited credential names; the clean launchers provide the supported path. Symlinks and shell-like operators, even quoted operators, remain deliberately rejected.
- Realistic console presentation is a small synthetic catalog, not a full OS, shell, robust adversary emulation or promise of sustained deception. Cosmetic string substitutions and a helper's misleading name were not rewritten as security fixes.
- A focused read-only portal review found no confirmed XSS, unsafe HTML/execution sink, cross-tenant access or permissive-origin defect in the reviewed paths. Existing mocked portal tests and exact-origin/ownership/CSRF guards remain; this is not a penetration-test certificate or a live OAuth validation.

### Validation and transparency

The attached review's claims were independently triaged by subsystem; confirmed defects received focused regressions, intentional boundaries were preserved and unconfirmed claims were not presented as proven. See the linked [review and test evidence](docs/review-8-findings.md) for the final executed checks and remaining limitations. Original project code remains Apache-2.0; the preserved auditor remains MIT-licensed.

**Still unproven:** firmware/Secure Boot enforcement and production VM containment — [see the containment note](README.md#limitations-and-transparency-echo-is-not-containment). No new VM deployment, remote loop, provider key custody, policy adoption or automatic remediation was added.

## Core 0.1.0 / portal 1.0.0 — previous release, 2026-10-29–30

The old release remains in Git history rather than as a second executable tree mixed into current code:

- [Complete pre-fix source and README at `4dea59f`](https://github.com/1243353366/cloudsentry/tree/4dea59f2c276d39ac20ed0ec926b6f2548b16389).
- [Download that exact previous source snapshot](https://github.com/1243353366/cloudsentry/archive/4dea59f2c276d39ac20ed0ec926b6f2548b16389.zip).
- Core 0.1.0 contained the bounded local scanners, manual optional collectors, synthetic console/mirror, review-only training, evidence/customer packets, manual backup admission and separate MIT static auditor. Prior release checks recorded 363 core, 95 upstream and 33 portal tests; four CI workflows passed for combined-code commit [`4e687ea`](https://github.com/1243353366/cloudsentry/commit/4e687ea).
- The prior deployed portal checkpoint was `d3101a23fdf64bcb66df9dccd8f8427af3b27043`. Later checkpoint `f167a6d` aligned source license metadata before this patch release; a checkpoint alone is not a separate publication claim.
- Commits `f9e72cd` and `acbf02b` added the containment limitation and its cross-reference. Commit `4dea59f` applied Apache-2.0 to original project code while preserving the auditor's MIT license and prior MIT notice/grants. None established production VM containment.

Old code is preserved for reproducibility, not recommended over the corrected release. Keep incident evidence and manifest pins separate from source archives. Upgrading does not authorize collection, deployment, disclosure or remediation.
