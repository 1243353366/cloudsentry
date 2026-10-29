# Manual read-only cloud collectors

`reverse_shell_decoy.collectors.collect_cloud(provider, scope_id, since, until, region=None)` is an **operator-invoked** source only. It returns `source: "manual_read_only_cloud_api"` with native provider event objects that have been bounded and redacted for later analysis. Importing the module does nothing. The independent honeypot remains separate and does not call these APIs, inherit their credentials, or start a cloud scan.

The collector never creates or changes a resource, DNS record, sinkhole, log sink, key, deployment, or service. It does not discover accounts, zones, workspaces, credentials, cached configuration, or endpoint URLs. Each request goes only to a fixed HTTPS host, has redirects disabled, and uses `GET` except for Railway's fixed, documented read-only GraphQL query. Provider response bodies are limited to 8 MiB. The returned event sample is limited to 200 events and two pages or two service-event requests; `coverage.assessment` is always `bounded_sample_not_an_all_clear`.

## Required common inputs

Pass an explicit provider, account or workspace identifier, and both UTC timestamps. `since` and `until` must use ISO-8601 UTC `Z` form, such as `2026-10-01T00:00:00Z`; the range must be positive and no longer than seven days. The caller must supply the intended scope. Empty output, a server response without pagination metadata, a short page, or an API error is not evidence that the account is clear.

The output follows this shape:

```python
{
    "provider": "cloudflare",
    "source": "manual_read_only_cloud_api",
    "events": [...],
    "coverage": {
        "requested_since": "...",
        "requested_until": "...",
        "pages_fetched": 0,
        "maximum_pages": 2,
        "maximum_events": 200,
        "events_returned": 0,
        "truncated": True,
        "assessment": "bounded_sample_not_an_all_clear",
    },
    "warnings": [...],
}
```

Before returning event objects, the collector removes `requestParameters`, `responseElements`, environment-value fields, and recursively named secret, password, token, credential, access-key, authorization, cookie, and private-key fields. It omits a field larger than 256 KiB and stops recursion beyond 32 levels. This redaction can remove forensic context, so retain an authorized provider export separately when complete evidence is required. Credentials, raw provider error bodies, request headers, and malformed raw CloudTrail event strings are never returned or logged by this module.

## Cloudflare

Use `provider="cloudflare"`, a 32-character hexadecimal **account** ID, and a manually created token in `CLOUDFLARE_API_TOKEN`. The collector uses the documented account-level Audit Logs v2 request only:

```text
GET https://api.cloudflare.com/client/v4/accounts/{account_id}/logs/audit
```

It sends the requested `since` and `before` timestamps, ascending order, a page limit of 100, and at most one cursor follow-up. It never enumerates zones and never switches to a zone scope. Cloudflare documents `Account Settings Read` (or its broader write alternative) as an accepted permission for this operation; grant only the read capability needed for the selected account. [1]

The result is a bounded Audit Logs v2 sample. Audit-log availability, retention, and token access are controlled by the Cloudflare account, not by this code. If the response advertises another cursor after the second page, `coverage.truncated` is `true`.

## AWS CloudTrail Event history

Use `provider="aws"`, an expected 12-digit AWS account ID, a conventional region such as `us-east-1`, and all of the following explicit environment variables:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN       # optional for temporary credentials
```

AWS support is optional: install `boto3` yourself before selecting this provider. The project does not add it as a dependency. The adapter imports it only for an explicit AWS call and supplies environment credentials and region directly to a new session, instead of discovering credentials from profiles, containers or instance metadata. STS and CloudTrail requests use internally fixed provider-owned region endpoints, overriding SDK endpoint environment/profile settings; no caller-supplied endpoint URL is accepted. SDK configuration unrelated to credential discovery may still be read by the SDK.

The adapter first calls only `sts:GetCallerIdentity`. It compares the returned account to the requested 12-digit account ID and refuses to call CloudTrail if they differ. Only after that match does it call `cloudtrail:LookupEvents`; it uses at most two pages with `MaxResults=50`, because CloudTrail documents 50 as that API's maximum. Grant the credentials only these read actions for the intended account. `LookupEvents` covers management events and Insights events in the specified Region, has a 90-day Event history limit, and is region-scoped; it is not a query of arbitrary archived Trail, S3, or CloudTrail Lake data. [2]

`CloudTrailEvent` is JSON text in the AWS response. The collector parses it into a JSON object. If parsing fails, it returns only a safe parse-error marker instead of returning the malformed raw string.

## Render service events

Use `provider="render"`, a Render workspace owner ID beginning with `tea-` or `usr-`, and `RENDER_API_KEY`. The owner ID is mandatory: the collector does not list every workspace visible to a token. It first makes the documented owner-filtered service-list request:

```text
GET https://api.render.com/v1/services?ownerId={workspace_owner_id}
```

It then requests recent service event history for no more than the first two returned services:

```text
GET https://api.render.com/v1/services/{service_id}/events
```

Each service-event request carries the requested start and end time and a limit of 100. This is a deliberately small sample, not a full workspace audit export. Render documents the service event endpoint as a GET request with `startTime`, `endTime`, cursor, and a maximum limit of 100. [3] A workspace with more than two returned services, a 100-item event page, or a 200-event result is flagged as truncated.

Use a token authorized only to view the named workspace's services and events. The adapter never reads Render environment variables or their values. Render also offers a separate workspace audit-log export endpoint for eligible workspace administrators and retains audit data subject to plan requirements. Use that manual export when you need workspace actions such as access, membership, setting, or environment-variable events; do not represent this bounded service-event sample as that export. [4]

## Railway audit logs

Use `provider="railway"`, an explicit workspace ID, and `RAILWAY_API_TOKEN`. Railway documents a read-only `auditLogs(workspaceId: ...)` GraphQL query with fields for the ID, event type, timestamp, project and environment identifiers, payload, context, and `pageInfo`. The collector sends exactly that fixed field selection to Railway's documented GraphQL endpoint. It does not send a mutation, introspection request, mutation-like helper query, or a caller-provided GraphQL string. [5] [6]

Railway's published `auditLogs` example does not document `since`, `until`, `first`, or `after` arguments. Therefore the collector makes one read-only request, filters returned `createdAt` values locally to the requested period, and flags `hasNextPage` as truncated. It cannot establish complete coverage for the time window. Export audit logs from the Railway workspace or use Railway's documented retention and export process if a complete, reviewable period is needed. Railway describes audit-log availability for workspace admins and plan-specific retention; it does not make an empty bounded API page an all-clear finding. [5]

## Credential handling and manual operation

Set only the credential for the provider selected for this one manual invocation. No provider token is accepted as a function argument, written to a file, cached, printed, included in exception text, or output in the returned dictionary. A missing selected credential raises a safe `MissingCredentialError`. An unsupported provider raises `UnsupportedProvider` before any outbound request; obtain and manually import an authorized export rather than adding an unverified endpoint or schema.

The tests in `tests/test_collectors.py` mock `urllib` and a minimal `boto3` object. They do not open cloud sockets or authenticate to a real account. They verify fixed hosts and methods, mandatory scope/time/credentials, non-followed redirects, sanitized failures, AWS identity mismatch handling, bounded pagination coverage, and the no-outbound unsupported-provider path.

## References

[1]: https://developers.cloudflare.com/api/resources/accounts/subresources/logs/subresources/audit/methods/list/ "Cloudflare Get account audit logs Version 2"

[2]: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html "AWS CloudTrail LookupEvents API Reference"

[3]: https://api-docs.render.com/reference/list-events "Render List service events API Reference"

[4]: https://render.com/docs/audit-logs "Render Audit Logs"

[5]: https://docs.railway.com/enterprise/audit-logs "Railway Audit Logs"

[6]: https://docs.railway.com/integrations/api "Railway Public API"
