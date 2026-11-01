# Loopback scan

`scan-loopback` is the nmap-equivalent the audit path can run with no external binary: a
bounded TCP connect scan of this machine's loopback addresses.

```
reverse-shell-decoy scan-loopback --ports 1-1024
reverse-shell-decoy scan-loopback --ports 22022,22080 --cross-check
```

## Why it is separate from nmap

`nmap` is not a dependency and does not need to be. Operators who have it can run
`nmap -sT -Pn -n -p1-1024 127.0.0.1` themselves; `nmap_equivalent_command()` prints the
exact equivalent. The built-in scanner exists so results have a known shape and a stated
completeness.

## Refusals by construction

- Only `127.0.0.0/8`, `::1` and the literal `localhost` are accepted. Every other target
  raises `LoopbackOnlyError`. There is no flag or environment variable that turns this into
  a network scanner.
- Hostnames are not resolved, so DNS cannot redirect the scan to a remote address.
- No service or version probing, no OS fingerprinting, no raw sockets, no UDP.
- Port count (4096), per-port timeout (2s), total deadline (120s) and pacing are bounded.

## What the result means

`OPEN` proves something accepted a connection during the scan. `CLOSED` and `NO_ANSWER`
prove nothing about absence: another namespace, a firewall rule, a full accept backlog or
another user's socket all hide a live listener.

Completeness is explicit. A scan stopped by its deadline is `PARTIAL` with
`unscanned_ports` counted, because a truncated scan that calls itself complete is worse
than no scan.

## Cross-checking the inventory

`--cross-check` also reads the procfs listener inventory and reports disagreements:

- `answering_not_bound`: something answered on a port the inventory did not show. Possible
  causes: another namespace, a socket created after the inventory read, a permission limit.
- `bound_but_not_answering`: the inventory shows a binding that did not answer. Possible
  causes: accept backlog, netfilter, bound to a non-loopback address only, another user.
- `bound_but_not_scanned`: bindings outside the scanned range, about which the scan says
  nothing.

Two kernel-visible views that disagree are the interesting case, and the report leaves
attribution `unresolved` on purpose.
