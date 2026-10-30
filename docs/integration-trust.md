# Optional integration trust states

Cloud collection is an explicit, local, operator action. It is not a background
connection, credential validator, account-discovery feature, or proof that a person
currently has permission to use a provider account. A successful local request only
means that, **at the time of that request**, a customer-supplied credential was able
to make the collector's fixed, bounded, read-only requests for the supplied provider,
scope, and time window.

The hosted portal remains keyless. It does not accept provider tokens, call provider
APIs, validate a provider connection, or reuse shared developer credentials. Provider
profiles in the portal are labels and scope hints, not authenticated integrations.

## Status envelope

A successful `collect_cloud()` result and a local runtime failure that safely returns
a result include the following fixed envelope:

```json
{
  "state": "customer_authorized_integration",
  "reason": "bounded_read_only_request_completed",
  "source": "local_explicit_collection",
  "read_only_requests": true,
  "coverage": "bounded_sample",
  "credentials_retained": false,
  "checked_at_utc": "2026-10-29T21:11:23Z"
}
```

`checked_at_utc` is the time this local collection status was produced. It is not an
authorization expiry time or an ongoing authentication monitor. `coverage` is either
`bounded_sample` or `unavailable`; neither value makes an all-clear claim.

The supported states and fixed reasons are:

| State | Fixed reason | Meaning and limits |
| --- | --- | --- |
| `customer_authorized_integration` | `bounded_read_only_request_completed` | The explicit local request completed against its supplied provider/account-or-workspace scope and bounded time window. It does not prove continuing authorization, completeness, ownership, or that the credential has no broader rights. |
| `integration_unavailable` | `authentication_failed` | The provider returned HTTP 401. The cause is unknown; this is not labelled revoked. |
| `integration_unavailable` | `permission_denied` | The provider returned HTTP 403. The tool does not infer which permission is absent or whether the account policy is correct. |
| `integration_unavailable` | `unknown_failure` | A safe result could not establish a more specific fixed cause. Provider response text, SDK diagnostic text, and arbitrary error metadata are not exposed. |
| `credential_expired_or_revoked` | `credential_expired` | AWS returned the explicit typed SDK code `ExpiredToken` or `ExpiredTokenException`. This evidence establishes expiry, not whether a key was revoked. The conservative state name leaves external revocation as a possible later condition rather than a claim about the cause. |

The implementation also attaches fixed `integration_state`, `integration_reason`, and
`integration_status` metadata to collection exceptions that preserve compatibility:
missing credentials, unavailable optional dependencies, and AWS scope mismatches
still raise their existing exception types rather than becoming successful-looking
empty results. A caller may report only that fixed metadata and the existing safe
exception message; it must not serialize raw exception objects or provider details.

## Operator-issued credentials and least privilege

Bring your own credential only after the account owner or authorized operator has
approved the local request. Use the exact environment variable for the one provider
being collected, as described in [the collector guide](collectors.md), and use the
least-privilege provider permissions there: Cloudflare account audit-log read access;
AWS `sts:GetCallerIdentity` plus `cloudtrail:LookupEvents` for the intended account
and region; Render read access to the named workspace's services/events; or Railway
workspace audit-log access. The collector sends only the documented fixed read APIs,
with a caller-supplied account/workspace scope and bounded timestamps.

The tool cannot reduce an over-broad token's provider-side permissions. A supplied
credential may have access outside the requested account, workspace, region, or time
window; the local adapter limits its own calls but does not transform that credential
into a narrower one. Do not use shared developer credentials. The status is scoped to
the selected provider, account/workspace, region where applicable, and requested time
window; it is not transferable to another account, provider, or portal user.

Credentials are read from the selected provider's process environment for that
explicit invocation. They are never returned, logged, written to a persistent vault,
or intentionally retained by this module; selected active values are additionally
scrubbed from returned event values, keys, and warning text, including when an
otherwise innocuous field or message contains the exact active value. This redaction
is best effort: it does not promise detection of encoded, encrypted, split,
transformed, or previously unknown secret forms. Environment credentials can still
exist in the process until the operator clears them or exits the process. This design
does not promise perfect memory erasure, protect an already compromised host, or
recognize every possible secret-shaped value. Keep credentials out of reports, labels,
imports, and the decoy environment.

## Graceful degradation and revocation

Optional integrations fail closed: the collector never falls back to a different
provider, credential source, account, endpoint, profile, or broad discovery scan.
No local call occurs until an operator explicitly invokes it. A missing credential,
missing optional AWS SDK, or AWS account-scope mismatch remains an exception so an
existing CLI invocation reports an error and exits non-zero instead of manufacturing
a result. Other safe runtime failures return no events and an
`integration_unavailable` status with `coverage: "unavailable"`; an empty failure is
not a successful zero-event sample.

The tool does not poll authentication state. If an operator revokes or rotates a
provider key outside the portal, they can make another explicit local request to
observe the provider's response. The collector does not infer revocation from HTTP
401, HTTP 403, an arbitrary AWS SDK exception, or a failed network request. It uses
the expiry-or-revocation state only for the two explicit AWS expiry codes above.

## Hosted portal and imported reports

A portal/frontend must treat every imported integration status as customer-supplied,
**unverified** evidence. It should render only the safe allowlisted fields in the
status envelope—`state`, `reason`, `source`, `read_only_requests`, `coverage`,
`credentials_retained`, and `checked_at_utc`—and show the claimed local source as
unverified. It must not present an import as a live provider connection, current
permission proof, ongoing authentication, or a portal-side scan. It must not render
raw provider errors, token values, arbitrary nested fields, or user-controlled status
labels as trusted facts.

Keep original provider exports and authorization records separately when a complete
or independently reviewable account of events is needed. A bounded local sample, an
empty result, an imported status, or a profile label is not evidence that an account
is clear or that any particular person is authorized.
