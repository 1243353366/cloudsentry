# Manual cloud-log review

`reverse_shell_decoy.cloud.analyze_cloud_logs()` is an **offline, opt-in parser** for a log export that an operator already has. It does not read cloud credentials, environment variables, or local cloud configuration. It does not call provider APIs, connect to an account, start a scan, deploy anything, or change provider configuration. It is a limited summary aid for manual review, not a cloud collector or an all-clear check.

```python
from pathlib import Path
import json
from reverse_shell_decoy.cloud import analyze_cloud_logs

# The operator manually exported this file before running the script.
content = Path("manual-cloudtrail-export.json").read_text(encoding="utf-8")
report = analyze_cloud_logs("aws", content, format="auto")
print(json.dumps(report["summary"], indent=2, sort_keys=True))
```

The function signature is:

```python
analyze_cloud_logs(provider: str, content: str, format: str = "auto") -> dict
```

Supported providers are `aws`, `cloudflare`, `render`, and `railway`. Supported format requests are `auto`, `json`, `jsonl`, `csv`, and `text`. `csv` is intentionally limited to the documented Render export columns. The function raises `ValueError` for an unsupported provider/format or content larger than 8 MiB, and `TypeError` for non-string arguments.

## What can be imported

The parser accepts only manually supplied text. It recognizes these provider-specific shapes without treating them as a live account connection:

- AWS JSON exports use a top-level `Records` list. The normalized source fields are `eventTime`, `eventName`, `eventSource`, `sourceIPAddress`, and a hash of `userIdentity`. AWS documents `eventTime` as UTC, `eventName` as the requested service action, and `sourceIPAddress` as the request source; request and response parameter bodies are deliberately not returned. [1]
- Cloudflare JSON accepts `result` as a list and the explicit nested `result.audit_logs` list. The documented v2 example includes action, actor, resource, and timestamp information. The action object can carry a type, description, time, and result, while resource includes type and optionally product. [2]
- Render JSON accepts a direct array or `events`/`logs` wrapper. Render CSV export is also accepted when its header has the documented `timestamp`, `actor`, `event`, `status`, and `metadata` columns. Metadata is read only to normalize a valid source IP and the generic resource type `service`; no metadata body or value is returned. [3]
- Railway JSON accepts a direct array or `events`/`logs` wrapper. It also reads the documented GraphQL `data.auditLogs.edges[].node` export shape. Railway documents `id`, `eventType`, `createdAt`, `projectId`, `environmentId`, `payload`, and `context` in that query. Payload and context bodies are never returned. [4]

JSON Lines is accepted one JSON value per non-empty line. A non-JSON fallback treats each supplied non-empty line only as a runtime message. It never executes the message. It emits a source hash plus a bounded, HTML-escaped and secret-redacted excerpt, so this fallback is intentionally incomplete.

## Report contract

Every result has these top-level fields:

- `provider`, `source_kind: "manual_cloud_log_import"`, `source_sha256`, and `source_is_synthetic` identify the input without returning its raw body.
- `simulation: false` identifies the analyzer itself as non-simulated. It never reports a Connected or scanned status.
- `events` is a list of normalized records; `findings` is a list of review indicators; `warnings` identifies parsing and coverage gaps.
- `summary` contains total counts, counts by category, and `missing_coverage`. The summary calls a usable import `partial`, not clean. An empty, malformed, truncated, or timestamp-poor import is `unknown` or explicitly incomplete.

A normal imported event contains only:

```json
{
  "event_id": "provider:stable-hash-prefix",
  "source_event_sha256": "sha256-of-supplied-event",
  "source_kind": "manual_cloud_log_import",
  "provider": "aws",
  "action": "StopLogging",
  "category": "logging_configuration",
  "timestamp_utc": "2026-01-15T10:30:00Z",
  "source_ip": "192.0.2.42",
  "identity_sha256": "sha256-of-source-identity",
  "resource_type": "cloudtrail",
  "observation": "observed_in_supplied_log",
  "simulation": false
}
```

`timestamp_utc` is present only when an offset-aware ISO timestamp validates. A supplied but unvalidated timestamp is retained as bounded `timestamp_original`; an absent timestamp is not invented. `source_ip`, `identity_sha256`, and `resource_type` are optional. A resource type is a generic label, never an environment-variable value, resource URI, resource ID, request parameter, response body, or secret.

Each finding includes a `category`, `confidence` of `low` or `medium`, an `indicator`, `not_proof`, `event_references` and compatible `event_ids`, and a `recommended_review`. Findings have no severity field and never claim `critical`. They are indicators to review, not evidence that the action was unauthorized or that a compromise occurred.

## Heuristics and limits

The analyzer recognizes these narrow review signals:

- AWS `StopLogging`, `DeleteTrail`, and `UpdateTrail` are logging-configuration review signals. A `ConsoleLogin` is an authentication review signal only when `userIdentity.type` is `Root` and `additionalEventData.MFAUsed` is explicitly `No` or `false`. IAM policy attachment and `CreateAccessKey` are review signals, not automatic malicious-activity labels.
- Cloudflare scope matching is deliberately conservative. It requires a documented action type of `create`, `update`, or `delete` (or a legacy change-style action label) and a supplied action/resource label scoped to security or firewall, access, token, member, DNS, or zone changes. This is not a claim that these are an exhaustive Cloudflare event enum; Cloudflare documents the action type/description and resource fields, not a fixed exhaustive action-name list on the cited page. [2]
- Render recognizes only the exact documented named events for shell access (`StartShellEvent`, `EndShellEvent`), environment-variable or connection-info viewing, environment-variable changes, and auto-deploy configuration changes. The documented `status: error` remains available for error-burst counting. [3]
- Railway uses words in the supplied `eventType` to group workspace permission, project visibility/public, environment, and deployment activity. Railway’s own documentation says the complete, changing event-type list is retrieved through its GraphQL API; this offline parser does not assert a fixed exhaustive Railway enum. [4]
- Generic authentication/authorization or 5xx/operational error activity produces a finding only when at least five same-action error records occur in a ten-minute timestamp bucket. That finding states its event count and first/last normalized timestamps and explicitly says that an operational burst is not evidence of compromise.

Input is capped at 8 MiB and 10,000 source records. JSON nesting is lexically capped at 64 before decoding, parser recursion is caught per record, and malformed records do not stop other bounded records from being reviewed. Any cap, malformed input, unsupported wrapper, unparseable record, missing timestamp, or zero-record result produces a coverage warning. The analyzer cannot determine whether a pasted snapshot is complete, authentic, or current.

The report does not return raw request parameters, response elements, event payloads, contexts, metadata bodies, actor names, emails, account IDs, environment-variable values, tokens, passwords, authorization headers, or copied raw log bodies. Text excerpts are bounded, escaped, and redact common secret assignments, Bearer values, and long token-like strings. Preserve original protected exports separately if your review process requires them.

## Manual export access

Use a least-privilege, human-approved export process under the organization’s access policy. This feature does not ask for, store, or use credentials. Cloudflare’s audit-log documentation states that its history endpoint needs either Account Settings Read or Account Settings Write; use that as a source-specific permission reference rather than giving this tool a token. [2] Render documents workspace-admin export for workspace audit logs and Org Owner export for organization audit logs. [3] Railway documents workspace-admin access to workspace audit logs. [4] For AWS, obtain only the already-authorized CloudTrail export needed for review; this parser does not prescribe an IAM permission set.

## Synthetic examples

The four files under `examples/` are synthetic fixtures, not provider exports:

- `examples/aws-demo.json`
- `examples/cloudflare-demo.json`
- `examples/render-demo.json`
- `examples/railway-demo.json`

Each has top-level `"demo": true` and every record has `"simulation": true`. When a top-level demo flag is present, the report returns `source_is_synthetic: true`; normalized events use `observation: "synthetic_demo_record"` and `simulation: true`, and findings are explicitly demonstrations. Do not remove that marker and later represent these files or their output as a real manual import.

## References

[1]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html "AWS CloudTrail record contents"

[2]: https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/ "Cloudflare Audit Logs version 2"

[3]: https://render.com/docs/audit-logs "Render Audit Logs"

[4]: https://docs.railway.com/enterprise/audit-logs "Railway Audit Logs"
