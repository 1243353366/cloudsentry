# Testing notes — v0.1.0

On 2026-10-29, the completed source was tested on Ubuntu with Python 3.12.3. The final command `PYTHONPATH=src python3 -m unittest discover -s tests -q` passed **120 tests**. Compilation of `src` and `scripts` also succeeded.

Coverage includes fake Linux procfs snapshots, IPv4/IPv6 socket decoding and listener ownership, startup-file indicators and filesystem bounds, secret-redaction cases, pasted-log markers and limits, offline name-comparison bounds, all four providers' synthetic log formats, collector-to-analyzer round trips, summary provenance, review-only response plans, private ZIP integrity, hostile terminal input, and loopback-only service quotas. Cloud collector requests use mocks; no live cloud account was authenticated or scanned.

The package was built and installed into a fresh virtual environment, and CLI version/help worked. All four provider demo files were analyzed through the CLI and combined with `scripts/summarize.py`. Each remained explicitly synthetic, and demo findings were excluded from non-demo indicator counts.

A read-only host audit was smoke-tested against the Manus sandbox itself, not the user's computer. A private evidence ZIP containing a sandbox snapshot, synthetic session audit and demo cloud summary was generated outside the repository; its manifest verification returned valid with no warnings or errors. These runtime artifacts are not part of the public source archive.

The clean-environment honeypot launcher was smoke-tested on an ephemeral loopback port with a one-second whole-service lifetime. Async unit tests used loopback connections only. No service was exposed publicly or left running, and no cloud resource, DNS record or firewall configuration was changed.

## Not established by these tests

Docker was unavailable in this sandbox, so the provided container images and networking examples were not built or executed here. The cloud APIs were not tested against live credentials, plans or accounts. API behavior and provider schemas can change. GitHub CI is configured for additional Python versions but was not run as part of local testing. Windows and macOS native endpoint collectors are not included; a Windows terminal persona is not native Windows scanning.

This is not an independent penetration test, formal isolation proof, signed release process or guarantee of flawless security. Public exposure requires separately reviewed infrastructure egress/ingress controls and trusted external log storage. Application quotas cannot guarantee defense against volumetric attacks or cloud billing abuse. Positive heuristics remain review indicators, and the sinkhole planner never applies a real change.

## Local defensive add-on validation — 2026-10-29

The local add-on source subsequently passed **157 tests** across the original scanners plus the bounded snapshot loop, private synthetic-state export, silent sink, binary inbound mirror, and investigator-review packet. Shell launcher syntax and Python compilation passed. Mirror tests used loopback only and verified same-connection echo, no interpretation/callback, hash-only audit, byte/chunk/rate/time quotas and silent closures. Investigator tests verified source hashing, synthetic/observed/unknown classifications, no network or execution, private output, overwrite refusal and ZIP integrity.

The add-ons were not pushed to the public repository or deployed. No live incident evidence was supplied, and the tests do not establish unauthorized access, visitor identity, legal liability, provider billing behavior, or escape-proof isolation. There is no indefinite hold, randomized resource-exhaustion behavior or denial-of-wallet feature.

## Resource-budget update — 2026-10-30 UTC

The full local suite now passes **198 tests**. New checks cover validated global input/output budgets, per-session input and rate enforcement in console/sink/mirror modes, concurrent-session shutdown on global violations, conservative byte counters, mirror non-amplification, separate service-control provenance, malformed/deep/oversized audit records, symlink rejection, arbitrary-field privacy, hashed session references and explicitly unknown coverage. Regressions reject unhashable phase fields and overflowing UTC conversion without crashing, preserve chronological ordering within a second, and ensure a local budget record is not counted as a visitor session. Python compilation and source whitespace checks passed.

The customer portal update adds a manual resource-report workflow and documentation links only. Its **27 tests**, TypeScript checks and production build passed; customer authentication, owner checks and fresh summary-consent paths were not replaced. The earlier statement about unpublished add-ons describes that historical test stage: the local source was subsequently published to GitHub. The separate decoy itself has not been deployed publicly.

Tests use tiny, short-lived loopback payloads or synthetic file fixtures, not remote workloads, CPU/memory exhaustion or real attack traffic. No actual case evidence was collected, no cloud scan/firewall/DNS action was taken and no peer cost/battery/billing effect was measured. Container CPU/memory limits and infrastructure spending controls remain operator responsibilities, not claims established by this suite.
