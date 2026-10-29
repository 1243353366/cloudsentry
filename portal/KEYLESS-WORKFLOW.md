# CloudSentry keyless customer workflow

CloudSentry uses real managed sign-in. Customers select Google, Microsoft or passkeys on the managed identity portal; CloudSentry does not ask for their identity-provider password or for OAuth application keys. Direct GitHub sign-in is not offered in this keyless version. The available managed sign-in methods were checked at https://manus.im/login on October 29, 2026.

After sign-in, each customer has a private workspace. Optional Cloudflare, AWS, Render and Railway provider profiles contain only account/workspace labels, identifiers and an optional region. A saved profile is not an authenticated connection and grants CloudSentry no cloud-account access. Do not paste API keys, passwords, session credentials or tokens into a profile or report.

Customers perform every cloud action themselves through the provider's native dashboard or tools, export their selected scan results, and deliberately import JSON into CloudSentry. The keyless web application does not call the cloud APIs, execute a local scan on the customer's machine, or inventory its own web server as if it were the customer's OS. The separate local CloudSentry tools remain available for explicitly authorized local inspections.

An import is unverified customer-supplied evidence. CloudSentry labels it accordingly, preserves the scope of representation hashes, sanitizes obvious credential fields and keeps the selected result private to its customer workspace. Retain original exported files separately: a canonical JSON hash is not a hash of the original file bytes and does not authenticate the exporter or prove chain of custody.

After each import, the summary offer appears by default. The customer must explicitly approve summary generation each time. Declining leaves the imported report unchanged. Summary consent does not authorize a cloud scan, DNS change, submission to law enforcement or publication of incident information. No automatic remediation or third-party evidence submission is performed.

A summary separates observed tooling or synthetic decoy actions from defensive review indicators and legally relevant evidence context. Language tokens are text patterns, not evidence of competence, identity or execution. Synthetic root/admin effects do not prove unauthorized access to a real host. Missing evidence and unknown authorization remain explicit.

## Offline network-boundary review

Selected JSON may include `networks` with IPv4/IPv6 CIDR definitions and `routes` with CIDR destinations and optional gateway literals. This module compares only the supplied configuration. It does not query ARP, DHCP, routing devices, firewall enforcement or reachability. IPv4 prefixes broader than /24 and IPv6 prefixes broader than /64 are review references, not vulnerability thresholds; legitimate aggregates and nested ranges are common.

A format example, not incident evidence:

```json
{
  "provider": "local",
  "networks": [{"cidr": "192.0.2.0/24"}],
  "routes": []
}
```

The review is bounded to 128 network definitions, 128 routes and 256 reported indicators. It marks input or indicator truncation. IP addresses, subnet masks and network location do not establish identity, integrity or authorization. No indicators does not mean that segmentation is safe.

## Separation and configuration

The web app contains no decoy listener, reverse callback, visitor-code interpreter, indefinite connection hold, hidden persistence or cloud-scanning worker. The existing in-memory decoy and bounded mirror are separate local components. Managed signing material derives a domain-separated private-data encryption key; customers and the builder supply no application key values.

OAuth return origins are exact allowlisted public origins. The application never trusts an arbitrary Host or forwarded-host header to choose a callback. Production sign-in remains fail-closed until the actual deployed origin is recorded. Imported reports, summaries, passwords, tokens and runtime secret values must never enter public source control.

The design follows the managed authentication and database contracts. Publication is not established by a local build or Preview; the final permanent URL is delivered only after a successful production deployment.
