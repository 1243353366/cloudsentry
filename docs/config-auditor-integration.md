# Optional CloudSentry configuration-auditor integration

This integration vendors the reviewed local static scanner from [HuginnsHammer/CloudSentry](https://github.com/HuginnsHammer/CloudSentry) at exact commit [`0e4fd3b55fcb4073db6943e4a2ad802b5e0dba6c`](https://github.com/HuginnsHammer/CloudSentry/commit/0e4fd3b55fcb4073db6943e4a2ad802b5e0dba6c). The vendor source, original MIT license, and source-context record are located under [`integrations/config-auditor`](../integrations/config-auditor/). See its [`NOTICE.md`](../integrations/config-auditor/NOTICE.md).

It is an optional **defensive, local static-analysis** capability for one explicitly selected configuration file. It does not connect to a cloud provider, require credentials, enumerate an account, accept arbitrary commands, start Docker or Terraform, provision infrastructure, or apply remediation. A finding is a review cue, not proof of an exploitable condition or a compliance result.

## Boundary and supported input

The host bridge is [`scripts/scan-configurations.py`](../scripts/scan-configurations.py). It accepts exactly one `--target FILE`, which must be an existing, non-symlink regular file with a canonical absolute path and size at most 2 MiB. It supports a `Dockerfile`/`Dockerfile.*`, `.tf`, `.yaml`, or `.yml` filename as recognized by the upstream scanner. It deliberately **rejects all directories**. The reviewed upstream engine has a per-file limit but recursively walks directories without a total count, depth, byte, canonical-path, or symlink-traversal confinement; directory scanning is therefore not offered by the bridge.

The bridge performs metadata validation without opening the file, then requests a fresh, exact-scope `configuration_audit` authorization. The scope binds the canonical target, requested output format, and requested minimum severity. Only after the grant is issued and begun does the bridge use a no-follow file descriptor. It passes that descriptor to a fixed Python 3.12 worker process; the worker reaches it through a private descriptor symlink, so a later pathname swap cannot redirect the upstream reader. The bridge captures the complete report, checks the grant once more, and only then writes it to stdout. It creates no report file and accepts no output-path argument.

The authorization operation `configuration_audit` must be present in `reverse_shell_decoy.authorization` before this bridge is run. The bridge does not modify the core package’s authorization policy itself.

## Supported report formats and exit codes

```sh
python3 scripts/scan-configurations.py \
  --target /absolute/path/to/Dockerfile \
  --format json \
  --minimum-severity info \
  --consent
```

- `--format text`, `--format json` (default), or `--format sarif`
- `--minimum-severity critical|high|medium|low|info` (default `info`)
- `--consent` asks the authorization module to issue a new grant for this invocation. Without it, a TTY confirmation is required; declined or non-interactive authorization produces no report.
- Exit `0`: no active finding meeting the selected threshold.
- Exit `1`: active findings meeting the selected threshold.
- Exit `2`: incomplete scanner result, rejected input, unavailable fixed environment, authorization expiry/revocation, timeout, or another bridge failure. Exit `2` takes precedence over findings.

The bridge has no `--output`, directory, provider, credentials, cloud-key, API-host, remote URL, remediation, or arbitrary-upstream-flags option. It does not derive commands or operations from scanned content. It neither runs `terraform`, `docker`, nor a configuration interpreter.

## Isolated Python 3.12 environment

The host package remains compatible with Python 3.10 and has no unconditional CloudSentry dependency. The vendor declares Python `>=3.12`; use the separate `.config-auditor-venv` environment in this repository root. The bridge intentionally invokes only that environment's `bin/python` with `-I`, not a sandbox-specific path, an ambient `scanner` import or a user-selected interpreter.

From the repository root, create that environment and install only the reviewed vendor package and its index-resolved dependencies:

```sh
python3.12 -m venv .config-auditor-venv
.config-auditor-venv/bin/python -m pip install -e './integrations/config-auditor[dev]'
.config-auditor-venv/bin/python -m pip check
(cd integrations/config-auditor && ../../.config-auditor-venv/bin/python -m pytest)
```

This uses `pip` to resolve the declared dependencies from the package index; it does not run upstream Makefile targets, frontend tooling, API services, or any repository installer script. Do not create the environment inside the vendor directory and do not add `node_modules`, binaries, real `.env` files, or a git checkout to the vendor tree.

The parent enforces a 45-second deadline and 8 MiB output bound, checks the active grant while the worker runs, stops/reaps the worker on revocation or interruption, and revokes the one-run grant at completion. Declined permission returns exit 2, not a misleading clean-scan status. A separate private temporary output descriptor is discarded after the final permission check and stdout delivery; nothing is uploaded.

## Upstream components retained but not enabled

The vendor snapshot retains the upstream scanner, tests, example fixtures, documentation, FastAPI source, and frontend source to preserve source context and permit upstream tests. They are **not** started, wired into the host portal, or used by the bridge.

The upstream API accepts filesystem paths. If an operator separately experiments with that upstream component, it is local-development-only and must remain bound to `127.0.0.1`; do not expose it on a public interface or tunnel. The retained frontend is also local-development-only, is configured for loopback, and is not a hosted portal deployment. This integration itself has no HTTP listener, public port, network client, background service, auto-cloud scan, or scheduled task.

Do not treat the retained standalone upstream API as equivalent to this bridge: its path-taking endpoint has no host authorization gate and does not impose the bridge's single-file, no-follow descriptor boundary. The retained frontend stylesheet also references a Google Fonts URL, so a browser that an operator separately starts for upstream frontend development may make that external asset request. Neither component is started or invoked by this integration.

## Reporting and privacy review

JSON output can be manually reviewed and, if appropriate, manually supplied to a provider-local portal workflow. The bridge does not upload, post, or synchronize it anywhere. SARIF is intended for a compatible local review workflow.

Treat every report as potentially sensitive. The upstream scanner reports canonical file locations, configuration-derived evidence (truncated in many findings), parser diagnostics, resource names, suppression reasons, and remediation context. A redacted-looking report is **not** a proof that source content, identifiers, comments, or secrets are absent. Review and sanitize the entire report before attaching it to a ticket, portal, CI artifact, or any third-party system. Do not upload source files or reports containing customer secrets, tokens, private endpoints, or sensitive infrastructure names.

## Rule coverage and limitations

At the pinned upstream source, rules include explicit Dockerfile root users and mutable `latest` tags; selected Docker Compose privileged mode, host networking, Docker socket mounts, and wildcard host port bindings; and selected literal Terraform public S3 ACL, world-open security-group ingress, and EBS encryption-disabled cases. See the upstream vendor’s [`docs/detection-rules.md`](../integrations/config-auditor/docs/detection-rules.md) and [`docs/limitations.md`](../integrations/config-auditor/docs/limitations.md).

The scanner performs heuristic static analysis. It does not resolve Terraform variables, modules, dynamic expressions, provider defaults, effective IAM/policy, runtime firewall behavior, Docker build semantics, or orchestrator overrides. A clean result is not proof of security, and findings require contextual review. Suppressions are retained in JSON/SARIF; they are not a remediation mechanism.

## Test boundaries

The independent workflow `.github/workflows/config-auditor-tests.yml` uses Python 3.12, installs the vendor test extra, runs upstream scanner tests from the vendor directory, and separately runs bridge contract tests. Bridge tests use mocks and temporary deliberately vulnerable configuration text only; they never invoke Docker, Terraform, provider APIs, upstream FastAPI, the frontend, cloud accounts, real customer input, or a public listener.
