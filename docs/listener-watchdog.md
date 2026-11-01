# Listener watchdog

`watchdog` takes repeated bounded snapshots of the listener inventory and diffs them.

```
reverse-shell-decoy watchdog --observations 5 --interval 2
```

## It never acts

Every event carries `action: "none"` and `requires_authorization: true`, and the report
sets `terminates_processes: false`. The watchdog does not signal, kill, block or restart
anything. Replacing a listener is an operator decision that needs fresh authorization, and
a tool that reaps a replacement process on its own would be doing exactly the thing a
review is supposed to prevent.

A reappearing listener is evidence, not a verdict.

## Diff events

| Event | Meaning |
| --- | --- |
| `BINDING_APPEARED` | present in this snapshot, absent from the previous one |
| `BINDING_DISAPPEARED` | absent now, present before |
| `BINDING_CHANGED` | same binding, different owners (with pids named both ways) |
| `BINDING_REAPPEARED` | seen before, disappeared, and now present again |

`BINDING_REAPPEARED` links back to `recurrence_of_first_seen_utc` and counts
`prior_disappearances`, so "it came back" is one fact with history rather than two
unrelated observations.

## Continuity is not identity

Matching is on the binding (protocol, family, address, port, state) plus the observed
owners. A different PID on the same binding is reported as a change, with its own assurance
level (`UNKNOWN`, `PARTIAL`, `MULTIPLE_OWNERS`), never silently treated as the original
process returning.

## Bounds and honest reporting

Observations (240), interval, total deadline and retained history are all bounded. A run
that hits its deadline or observation limit says so, because a short run presented as
continuous monitoring is a false claim. The report states plainly that a binding which
appeared and disappeared between two snapshots is invisible.

## Example

```
7 snapshot(s) of the listener inventory, 6 change event(s).
  BINDING_APPEARED    tcp/IPv4/127.0.0.1:22022/LISTEN  action: none
  BINDING_DISAPPEARED tcp/IPv4/127.0.0.1:22022/LISTEN  action: none
```
