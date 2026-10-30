# Emergency-only silent decoy profile

This is a **manual, finite, low-budget silent sink** for an isolated decoy environment you administer. It provides no command execution, privileged host access, echo, terminal banner, OCR-targeted visual noise or instructions aimed at another automation system. A visitor receives no application response. Normal transport control packets and deadline closures still occur; the service does not hold peers indefinitely or guarantee that their tooling becomes useless.

## What it does not do

The profile starts a **new listener**. It does not take over an existing connection, switch a running console, migrate an attacker, close another process, redirect third-party traffic, disable real monitoring, repair an exploited host or enforce a cloud bill ceiling. It has no automatic compromise trigger or automatic restart. Nothing in the hosted portal invokes it.

If the actual host or isolation boundary may be compromised, use a trusted provider/network control plane to isolate the affected resource, preserve independent evidence, revoke exposed credentials and follow your incident-response process. Do not trust the suspected host or this decoy as your recovery boundary. A tarpit cannot compensate for failed containment. Only an operator's separately authorized network decision can route an owned service to a replacement isolated destination.

## Explicit opt-in

After choosing your own isolated environment and confirming that the port is free, start it manually from the repository root. The example refuses to overwrite an audit file and uses a restrictive umask:

```sh
mkdir -m 700 emergency-review
(
  umask 077
  set -C
  sh scripts/emergency-tarpit.sh --host 127.0.0.1 --port 8023 \
    2> emergency-review/service-audit.jsonl
)
```

Only `--host`, `--port` and `--allow-public` are accepted. The last is a separate non-loopback opt-in; it does not configure isolation, firewall rules, container port publication or provider routing. Prefer loopback testing first. Ctrl-C stops the selected run. Do not start it on the customer-portal server or supply cloud credentials to the decoy.

## Fixed local policy

| Control | Fixed value |
| --- | ---: |
| Response | Silent sink; no virtual interpreter execution or echo |
| Whole service lifetime | 30 seconds |
| Concurrent sessions / lifetime connections | 1 / 2 |
| Session duration / idle timeout | 5 / 2 seconds |
| Input events per session / per second | 4 / 1 |
| Global admitted input / per-session input | 1,024 / 256 bytes |
| Reserved application output ceiling | 1 byte (sink emits no application output) |
| Audit-event allowance | 40 |

Global byte/audit/runtime violations stop local work; session violations close that session. These limits do not meter all physical traffic or CPU/memory consumption. External runtime/network spending controls are still required. The clean launcher removes inherited variables; known credential-bearing direct launches remain refused by the service.

## Evidence and independent tests

The existing sink audit retains timestamps, fixed indicators, byte counts and hashes instead of raw command payloads. Interactions remain distinct from synthetic effects; remote OS, intent, authorization and identity stay unknown. Budget-control records are separate from visitor events and can be missing after audit exhaustion.

Generate a selected operating report afterward with `python3 scripts/operations-summary.py --audit emergency-review/service-audit.jsonl --json`. Keep the audit private; import only the chosen JSON result if you use the portal. No investigator submission, DNS/firewall action or OCR/counter-tool payload is generated.

`tests/test_emergency.py` tests only the profile's policy/delegation without opening a port. Existing `tests/test_tarpit.py` and `tests/test_budget_enforcement.py` independently test silent non-executing sink behavior and byte/rate/deadline controls with tiny loopback inputs. See [resource budgets and opt-in](resource-economics.md) and [engineering rules](engineering-rules.md).
