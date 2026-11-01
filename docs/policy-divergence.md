# Effective policy versus stated intent

CloudSentry states what it may do. The kernel's packet filter states what is actually
reachable. `policy` reads the second and compares it with the first.

```
reverse-shell-decoy policy
reverse-shell-decoy policy --expected-ports 22,443 --reviewed-public-ports 22080
```

Nothing here changes a rule, opens a socket, or restarts a service. The command only reads.

## What is collected

| Platform | Source | Notes |
| --- | --- | --- |
| Linux | `nft -j list ruleset` | preferred: chains, hooks, policies and accept rules |
| Linux | `iptables-save`, `ip6tables-save` | fallback when nftables does not answer |
| Linux | `/proc/*/ns/net` | distinct network namespaces, so partial visibility is visible |
| Windows | `netsh advfirewall show allprofiles` | profile state and inbound default |
| Windows | `Get-NetFirewallProfile -PolicyStore ActiveStore` | machine-readable equivalent |

Windows Filtering Platform per-rule state needs administrator rights. Without them the
report says `PARTIAL`, never "clean".

## What the comparison reports

The intent is CloudSentry's own authorization rule set, not a generic wish list: decoy
ports (default 22022, 22080, 26379) stay on loopback unless individually reviewed, the
scanner only connects to loopback, and nothing is relayed to a third party.

| Finding | Severity | Meaning |
| --- | --- | --- |
| `DEFAULT_INBOUND_ACCEPT` | divergence | inbound default is accept, so listeners outside the reviewed set are reachable with no rule |
| `DECOY_PORT_REACHABLE` | divergence | an inbound allow rule names a decoy port the intent keeps local |
| `UNEXPECTED_INBOUND_ALLOW` | divergence | allow rules exist for ports the intent does not name; unexplained, not proven unauthorized |
| `FILTER_UNREADABLE` | observation gap | no filter state could be read, so no comparison was made |
| `PARTIAL_VISIBILITY` | observation gap | part of the reading failed; absence of a rule may be absence of permission |
| `NAMESPACE_SPLIT` | observation gap | more than one namespace is visible and only one was read |

Verdicts: `MATCH`, `DIVERGENT`, `PARTIAL`, `UNKNOWN`. Every report sets `all_clear: false`
and `changes_applied: false`.

## The limitation that matters most

A sufficiently privileged attacker can change the packet filter *and* the tools used to
observe it. After complete host compromise, a host-based check cannot guarantee
trustworthy visibility: it can only repeat what the kernel answered when it was asked,
and the kernel can be lying.

So the report carries a rotation recommendation rather than a reassuring verdict. Rotate
the observer: re-read after any privileged change, on a schedule you control, and from at
least one independent vantage point (another host, a network tap, a second namespace) that
a compromised observer cannot rewrite. `MATCH` means two descriptions agree, which is
worth knowing and is not proof that a host is clean.

## Reading the output

```json
{
  "verdict": "DIVERGENT",
  "findings": [{"code": "DEFAULT_INBOUND_ACCEPT", "severity": "divergence"}],
  "rotation_recommended": true,
  "all_clear": false,
  "trust_limitation": "A sufficiently privileged attacker can change both ..."
}
```

Divergence means one of two descriptions is out of date. It does not establish who changed
what, when, or why, and it is not an attribution.
