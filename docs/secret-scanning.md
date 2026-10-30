# Secret scanning

This repository uses Gitleaks 8.30.0[4] to detect likely hard-coded credentials in Git history and checked-out source. It is a preventive control, not proof that a repository has never contained a secret.

## Automated CI

[`.github/workflows/secrets.yml`](../.github/workflows/secrets.yml) runs on every push, pull request, and manual dispatch. It checks out the full history with `fetch-depth: 0`, uses the official `gitleaks/gitleaks-action@v3` with `GITLEAKS_VERSION: "8.30.0"`, then explicitly runs two fail-closed, fully redacted scans:

```sh
gitleaks git --no-banner --redact --exit-code=1 --log-opts="--all" .
gitleaks dir --no-banner --redact --exit-code=1 .
```

The first command covers all reachable Git history. The second covers the clean checkout that GitHub Actions creates. The official action also performs its normal event-range scan. Its result is deferred only long enough for the complete scans to run; a final step fails the job if that action failed. The workflow disables PR comments, result-artifact uploads, and job summaries. It contains no command that prints credentials or environment values, and every Gitleaks invocation uses `--redact`.

No manually configured secret or Gitleaks license is required for this personal repository. GitHub supplies the short-lived `github.token` context used by the official action for pull-request event handling; the workflow grants it read-only `contents` and `pull-requests` permissions and never echoes it. The official action documentation states that a Gitleaks license is required for organizations, not personal accounts.[1]

The release checks passed both a redacted reachable-history scan and a redacted full working-tree scan. An initial scan correctly flagged a synthetic credential-shaped test fixture; it was changed to construct its dummy shape at runtime, preserving the redaction regression without embedding a credential-looking literal in source. No `.gitleaks.toml` exception or broad test-directory, private-key or AWS-pattern exemption was retained. This is evidence of these particular scanner runs, not a guarantee that unknown secret formats or copies outside this repository do not exist.

## Opt-in pre-commit hook

The repository-local [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) uses the official Gitleaks pre-commit hook at the released `v8.30.0` tag. The official hook runs a staged pre-commit scan and already includes `--redact`; this configuration passes `--redact` explicitly as well.[2]

After installing `pre-commit` in your normal developer environment, enable it only for this clone:

```sh
pre-commit install
```

This creates `.git/hooks/pre-commit` in the current repository. It does not modify global Git hooks. To check a full repository manually, use a disposable clean clone that contains no local runtime files or `.env` files, and use the redacted history command shown above. The pre-commit project documents `pre-commit install` as the command that installs the repository hook.[3]

## If a scan detects a secret

Treat every finding as potentially real until reviewed. Do not paste the finding, its surrounding text, or a token into an issue, chat, log, or commit. Immediately rotate or revoke the credential with its provider, remove it from current source and configuration, and assess where it was used. If it is in Git history, coordinate history rewriting separately after rotation; this repository does not rewrite history automatically. Re-run the redacted checks after remediation.

A successful scan does not establish that no secret exists now or ever existed in historical clones, forks, caches, logs, artifacts, or other systems. Detection is pattern- and entropy-based, so it can miss unknown formats and can flag harmless test data. Review and rotation remain necessary when a credible exposure is found.

## References

[1]: https://github.com/gitleaks/gitleaks-action "Gitleaks Action documentation"
[2]: https://github.com/gitleaks/gitleaks "Gitleaks README and pre-commit hook"
[3]: https://pre-commit.com/ "pre-commit installation documentation"
[4]: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0 "Gitleaks v8.30.0 release"
