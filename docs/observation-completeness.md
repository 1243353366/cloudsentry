# Observation completeness

The listener inventory answers "which bindings can I see". This guide covers the layer
that answers the question a review actually depends on: **how much of that answer is
trustworthy, and what did the collector fail to see**.

Run it with:

```sh
python3 -m reverse_shell_decoy listeners --assure [--cross-verify] [--no-recheck]
```

The plain `listeners` command is unchanged and stays a single read-only procfs snapshot.
`--assure` adds a second independent snapshot, per-owner identity work, namespace and
permission accounting, and an optional independent kernel view.

Everything below is read-only. No port is probed, no packet is sent, no process is
signalled, and no file outside procfs is written.

## Ownership states

| State | Meaning |
| --- | --- |
| `CONFIRMED` | One owner descriptor was observed for the binding in both snapshots and nothing contradicted it. |
| `MULTIPLE_OWNERS` | More than one process holds a descriptor for this binding (inherited across `fork`, shared over `SCM_RIGHTS`, or `SO_REUSEPORT`). Every discovered PID is reported. |
| `UNKNOWN` | The binding disappeared before the recheck, its owner set changed between snapshots, or no owner descriptor was visible. This is an incomplete observation, never an unauthorized one. |
| `DEGRADED` | An owner was found but the collector hit a permission limit, so attribution is incomplete. |

`fork_related_parent_pids` lists owners that are also the parent of another owner of the
same binding, which is the usual signature of a listener inherited across `fork`.

A disappearing socket is common and benign: processes exit during collection. The point
of the second snapshot is that the tool says so instead of asserting the first owner it
happened to see.

## Executable identity

Each owner's executable is opened as a file descriptor and hashed **from that
descriptor**, then `fstat`-ed again:

- `device_inode` and `image_sha256` describe the object that was actually read.
- `changed_during_hash` is true when device, inode, size or mtime moved while hashing.
- `deleted_in_path` is true when `readlink /proc/<pid>/exe` ends in ` (deleted)`.
- `identity_verified` is only true when the hash completed, nothing moved, and the path
  was not unlinked.

A path is never treated as proof of an image, and `path_state` is one of `verified`,
`partial`, `unlinked`, `unreadable`, `not_a_regular_file` or `unavailable`. Hashing is
bounded by `max_exe_bytes` (8 MiB) and cached per device/inode so shared binaries are
hashed once.

## Namespace coverage

`coverage.namespaces_observed`, `namespace_owner_counts` and `namespace_scope` report the
network namespaces of the processes that own visible bindings, plus
`collector_namespace_ref` for the collector itself. `namespaces_inaccessible` counts live
processes whose namespace link could not be read. A single-namespace result means the
collector only saw its own namespace; it is never a claim about the whole host.

## Permission accounting and the coverage verdict

`coverage.state` is one of:

- `NO_DATA`: nothing was visible. This is explicitly not a clean-host result.
- `COMPLETE`: every visible binding had an owner and no permission limit was hit.
- `PARTIAL`: bindings were observed but some could not be attributed, or an observation
  changed between snapshots.
- `DEGRADED`: the collector hit permission limits, so attribution is known to be incomplete.

`coverage.statement` restates this in one sentence, for example
`DEGRADED: 41 of 47 visible bindings had an identified owner; 6 could not be attributed;
1 network namespace(s) inspected; 3 permission denial(s) limited coverage.`
That sentence is the honest summary a report should quote, rather than a green "clean"
indicator.

## Independent cross-verification

`--cross-verify` requests a second, independent observation of the same kernel state
through `NETLINK_SOCK_DIAG` (`inet_diag`). Both views are compared on protocol, family,
address, port and state, and the result reports `agreed`, `procfs_only`, `diag_only` and
`state_disagreements`. A disagreement preserves both observations and sets
`agreement: state_disagreement`; neither source is silently preferred.

When the kernel, container policy or permissions do not provide the generic netlink
socket family, the result is `available: false` with a reason label
(`netlink_sock_diag_not_supported`, `netlink_permission_denied`, `netlink_query_failed`,
`netlink_reply_truncated`) and `agreement: not_verified`. An unavailable check is never
reported as an agreement.

The diag parser follows the fixed 72-byte `inet_diag_msg` ABI with network-order ports.
Its unit tests use synthetic kernel frames. It was **not** exercised against a live
kernel in the environment where this change was prepared, because that sandbox does not
provide `NETLINK_SOCK_DIAG`; treat first run on your own host as the integration test.

## What this layer still cannot tell you

- Reachability. A wildcard bind is not proof of internet exposure. Exposure is reported as
  binding scope (`loopback` / `wildcard` / specific address) only; no external probing is
  performed by design.
- Authorization. Nothing here knows which listeners are intended. A `CONFIRMED` owner is an
  accurate observation, not an approved one.
- Anything in a namespace no readable process exposed.
- Anything in the window between the two snapshots that left no trace in either.

Behavioural baselines, listener lineage/restart detection and a collection-integrity
watchdog are deliberately not implemented yet: they classify behaviour, and behaviour
classification on top of incomplete attribution is how false conclusions get built. See
[response boundaries](response-boundaries.md) for what is permanently out of scope.
