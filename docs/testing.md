# Testing notes — v0.1.0

On 2026-10-29, the completed source was tested on Ubuntu with Python 3.12.3. The final command `PYTHONPATH=src python3 -m unittest discover -s tests -q` passed **120 tests**. Compilation of `src` and `scripts` also succeeded.

Coverage includes fake Linux procfs snapshots, IPv4/IPv6 socket decoding and listener ownership, startup-file indicators and filesystem bounds, secret-redaction cases, pasted-log markers and limits, offline name-comparison bounds, all four providers' synthetic log formats, collector-to-analyzer round trips, summary provenance, review-only response plans, private ZIP integrity, hostile terminal input, and loopback-only service quotas. Cloud collector requests use mocks; no live cloud account was authenticated or scanned.

The package was built and installed into a fresh virtual environment, and CLI version/help worked. All four provider demo files were analyzed through the CLI and combined with `scripts/summarize.py`. Each remained explicitly synthetic, and demo findings were excluded from non-demo indicator counts.

A read-only host audit was smoke-tested against the Manus sandbox itself, not the user's computer. A private evidence ZIP containing a sandbox snapshot, synthetic session audit and demo cloud summary was generated outside the repository; its manifest verification returned valid with no warnings or errors. These runtime artifacts are not part of the public source archive.

The clean-environment honeypot launcher was smoke-tested on an ephemeral loopback port with a one-second whole-service lifetime. Async unit tests used loopback connections only. No service was exposed publicly or left running, and no cloud resource, DNS record or firewall configuration was changed.

## Not established by these tests

Docker was unavailable in this sandbox, so the provided container images and networking examples were not built or executed here. The cloud APIs were not tested against live credentials, plans or accounts. API behavior and provider schemas can change. GitHub CI is configured for additional Python versions but was not run as part of local testing. Windows and macOS native endpoint collectors are not included; a Windows terminal persona is not native Windows scanning.

This is not an independent penetration test, formal isolation proof, signed release process or guarantee of flawless security. Public exposure requires separately reviewed infrastructure egress/ingress controls and trusted external log storage. Application quotas cannot guarantee defense against volumetric attacks or cloud billing abuse. Positive heuristics remain review indicators, and the sinkhole planner never applies a real change.
