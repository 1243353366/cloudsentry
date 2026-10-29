# Security policy

Use this project only with authorization to inspect the selected computer and logs. The scanner is read-only by default. It does not remediate incidents, install persistence, steal credentials, escalate privileges, contact remote targets, or modify security products.

## Reporting a problem

Do not put real evidence, credentials, tokens, personal information or unredacted logs in a public GitHub issue. Report a minimal reproduction with synthetic fixtures. If the repository offers private vulnerability reporting, use that channel for vulnerabilities rather than disclosing sensitive details publicly. No private reporting channel is guaranteed by this source package.

## Trust boundaries

The decoy is an allowlisted state machine, not a real shell. Realistic presentation changes only terminal output. Operator notices and audit provenance remain explicit. Arbitrary executables, command substitution and shell control operators are blocked. Virtual filesystem and command counts are bounded. The optional inbound TCP service is a separate module that imports no scanner or administrative interface and defaults to loopback only; it is not SSH and does not expose a real terminal.

Imported logs and ZIP bundles are untrusted data. Pasted text is normalized, not executed. Redaction is best effort: remove sensitive information before importing and inspect reports before sharing. A log field claiming an OS or identity is not a verified endpoint identity. Real OS metadata describes only the machine running the scanner.

Generated ZIP and decoy audit files use exclusive creation and private POSIX permissions. Verification does not extract files and checks size bounds, member names, duplicate entries, required fields and payload hashes. A compromised host could falsify scanner inputs or rewrite a manifest: hashes provide consistency, not independent authenticity. Store evidence through a separate approved process if you need trusted custody.

The scanner reads a limited set of process/socket/config metadata. It never reads process command lines or environment variables. Host filesystem traversal is bounded and startup inspection avoids symlinks and special files. Permission failures and incomplete visibility are warnings, not permission-bypass attempts.

## Deployment restrictions

The scanner remains a local tool. Do not expose a raw terminal or give network visitors access to the host. Do not use a container as justification to execute submitted malicious code. Public-facing use of the separate decoy service needs separately reviewed isolation, egress denial, retention policy, abuse rate limits and explicit operator authorization. Its minimal container image excludes scanners and evidence modules. Code-level limits do not substitute for network-layer DDoS protection, trusted external evidence storage, or a reviewed deployment.

There is no flooding, cloud-spend abuse, remote counterattack, covert backdoor, or actual telemetry suppression feature. Synthetic process/network/sensor experiments cannot evaluate real EDR detection quality.
