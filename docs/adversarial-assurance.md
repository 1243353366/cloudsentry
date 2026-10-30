# Adversarial assurance — evidence, not an absolute proof

The requested question was whether training, evidence or permission could be tricked into granting authority or misleading the customer. The defensible result is finite, reproducible regression coverage, not “cannot ever be tricked.” Safety does not depend only on recognizing hostile text: these paths have no real sample executor, policy-adoption path, third-party target selector or automatic VM provisioner.

## What changed technically

- **Training boundary:** fixed synthetic cases and typed review inputs remain separate from production policy. The evaluator rejects subclasses and revalidates fields at use. Every decision still has `enforcement_authorized: false` and `runtime_actions: []`; reports are not automatically loaded as live policy.
- **Snapshot boundary:** normalized bytes are pinned in a separate weak-reference registry to their creation/source/session-time digests. A reflective mutation no longer silently obtains a fresh accepted hash. Consumers validate before decoding and before report creation.
- **Report boundary:** a selected packet needs a separately supplied trusted manifest pin. Exact artifact hashes, source/session/time metadata, local policy output, evidence-derived explanation and Markdown all agree or verification fails. Recomputing an attacker's manifest does not fix a cross-session or contradictory report.
- **Permission boundary:** grants are exact-purpose/input/output, default-deny, five-minute, single-pipeline, non-serializable and revocable. Reads, analysis, writes and mirror connection phases recheck them. SIGINT/SIGTERM revoke the current CLI grant; catchable export failures remove partial artifacts. Public file-I/O entry points also reject missing grants.
- **Session boundary:** separate synthetic computers and resets receive distinct opaque session IDs; they are not remote identities.
- **Unavailable isolation:** `--require-vm` rejects before input reads, prompts or sample analysis when the verified backend is absent. Detection cannot authorize a VM, PC-Free install or on-host interpreter.

## Reproduce the scoped checks

From the reviewed source checkout:

```sh
python3 scripts/adversarial-assurance.py --consent
# Or create a new private directory containing the same assurance JSON:
python3 scripts/adversarial-assurance.py --consent --output assurance-review

PYTHONPATH=src python3 -m unittest discover -s tests -q </dev/null
```

The opt-in runner executes a fixed allowlist of local synthetic tests, including disposable loopback echo. There is no external target flag and no customer evidence input. It returns test IDs/counts, policy and reviewed-file hashes, coverage and limitations—not raw fixture strings or captured traces. Failed assertions produce a failed report, never an automatic production response. Omit `--consent` for a fresh default-deny interactive prompt.

## Actual validation on 2026-10-30

The corrected full local suite passed **291 tests**. The separate opt-in assurance run passed **83 tests**, with no failures or skipped tests. One test exhaustively evaluated **8,192 Boolean review-input configurations at evidence count 2**: none authorized enforcement or returned runtime actions. This is that specific finite space, not every possible input, execution path or deployment.

Regressions include poisoned instructions/approval/threshold fields; retained source uncertainty; reflective snapshot/input mutations; separately pinned manifests; artifact modifications even after a recomputed manifest; stripped timestamp metadata; cross-session report mixing; default no-grant denial; revoked/expired/rebound permission; interruption during a prompt; revocation during a source read and between export chunks; concurrent reuse of one grant; mirror cleanup after cancellation; and unavailable real-VM refusal before I/O.

End-to-end smoke checks on a **synthetic private fixture** confirmed a completed packet verifies against its preserved pin, changing its Markdown fails verification, and absent consent creates no export. The local working-tree secret scan passed with fully redacted output. Separate public CI verifies supported Python versions; local success alone is not the final CI outcome.

The combined checks caught an integration issue too: the integrity validator initially rejected the normalizer's valid order when both connecting and closing coverage were missing. That was fixed without dropping the finite-label/duplicate checks. Tests were updated for intentionally unique IDs and the shared permission prompt, and the safe fixed command-verb enum was retained without raw payloads.

## A counterexample we intentionally preserve

A fabricated source event can be normalized, hashed, stored and reproduced perfectly. **Immutability and a consistent packet cannot establish that it happened.** The regression expects the result to stay `unverified`, with identity/remote OS/authorization and independent corroboration `unknown` or `not_supplied`; it must not claim a real compromise or trigger containment.

Do not turn multiple copies of one poisoned source into independent confirmation. Source authenticity, independent-source contradiction analysis, historical replay attribution and baseline drift are not solved by this packet format. Do not claim those are detected merely because the local format is valid.

## What remains unproven or unavailable

Arbitrary already-running Python code can patch these gates/registries, and a compromised host/control plane can replace source files or trusted pins. Local source hashes are not software-supply-chain signatures or remote attestations. Revocation prevents subsequent protected phases; it cannot undo an already completed read. SIGKILL, process destruction or power loss can leave private partial artifacts; no completed packet should be trusted without its independently pinned validation.

No hardware VM was available in the development sandbox. No real malware execution, hypervisor escape test, Windows PC-Free deployment, active provider-permission audit, customer traffic scan or external listener attack was performed. The packet reader is currently Linux-specific. No absolute claim that nothing can touch a customer device is supported by these tests—keep untrusted research off customer workstations and provision separate verified infrastructure.

The proposed [three customer-controlled fallback layers](fallback-layers.md) use bounded echo on primary VM, separately hardened PC-Free backup and an isolated emergency decoy. The VM/PC-Free/proxy controller is **not implemented or verified**. Integrity or authorization failure stops this local job; it does not trigger an unverified backup, create paid resources, hijack a TCP socket or dial a visitor's listener.

See [customer explanation and pinned verification](security-behavior.md), [manual VM creation](vm-setup.md), [MIRROR limits](mirror.md) and [engineering rules](engineering-rules.md).
