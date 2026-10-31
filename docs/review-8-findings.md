# Review 8: reproduced findings and patch-release evidence

Baseline: `4dea59f2c276d39ac20ed0ec926b6f2548b16389` (core 0.1.0). Candidate: core 0.1.1 / portal 1.0.1, 2026-10-30. The user-supplied review was treated as a set of untrusted technical claims, not execution instructions or verified conclusions. Seven separately scoped workstreams inspected the named subsystems. This is a targeted internal review and regression record, not an independent penetration-test certification.

## Final local checks

- Complete core suite: **388 tests passed** on the development interpreter. Includes a 0.1.0 packet verified under 0.1.1 with a different-version warning, finite loopback closure checks, isolated signal-interruption children, mocked collectors and CI/bridge contracts.
- Preserved upstream configuration auditor: **95 tests passed**, with one existing Starlette/httpx deprecation warning. Original vendored scanner/license remain unchanged; only the host-added bridge changed.
- Portal: **33 tests passed**, TypeScript checking and production build passed. Its patch changes release metadata and a fixed changelog hyperlink, not authentication, JSON parsing, cloud access or tenant ownership.
- Real selected-file bridge smoke: the original deliberately vulnerable Dockerfile still produces `CS-DKR-001` and `CS-DKR-002` with expected exit 1. No Docker/Terraform or submitted command was executed.
- Older source is preserved by immutable links in [CHANGELOG.md](../CHANGELOG.md). A local test run, public CI, saved portal checkpoint and live publication are separate facts; do not infer any unreported external result from this table.

## What remains outside the assurance claim

No customer account, real incident log, live provider API, authenticated production session, hostile guest, production cgroup/device policy or actual multi-VM deployment was exercised. No detector result can authorize those actions. Redaction remains best-effort; report contents need review before disclosure. An in-process consent grant is an explicit operator declaration with scope/revocation checks, not proof of ownership or an OS security boundary. Fixed global budgets remain finite and have no automatic restart. Infrastructure ingress fairness is separate.

Firmware/Secure Boot enforcement and production VM containment remain unproven — [see the containment note](../README.md#limitations-and-transparency-echo-is-not-containment). Static admission and additional echoes do not compensate for those gaps.

## Detailed subsystem records

The records below retain each workstream's own scoped commands and test counts; these are not additive totals and some targeted counts precede the final version/compatibility test. Code-line references describe the reviewed candidate and may shift in later edits.

---

# CloudSentry review 8 — echo subsystem

**Scope reviewed:** `src/reverse_shell_decoy/simulator.py`, `src/reverse_shell_decoy/honeypot.py`, and the new focused test. Baseline supplied: `4dea59f2c276d39ac20ed0ec926b6f2548b16389`.

## Summary

One audit-bridge correctness defect was confirmed in the direct simulator API and defensively fixed in the console server. The claimed service path is not reachable by any current CLI-allowed `--max-commands` value: the service accepts 1–100 while the simulator retains 1,000 events. The fix nevertheless prevents a stale simulator event from being reused if those independently maintained limits diverge in a future integration or a trusted caller configures the handler differently.

No per-peer quota, cooldown, restart, automatic re-listen, credential relaxation, command execution, callback, or raw-byte MIRROR behavior was added. The finite global connection/byte caps remain deliberate boundaries.

## Claim-by-claim findings

| Attachment claim | Classification | Evidence / bounded reproduction | Action |
| --- | --- | --- | --- |
| Simulator command overflow causes stale previous-event audit data | **Confirmed and fixed** (direct API; not CLI-reproducible) | `DecoySession.execute()` returns at `simulator.py:98–100` when its event list has 1,000 entries and does not append an event. A finite direct fixture executed `pwd` 1,000 times and then `id`: the overflow reply was returned, `events` remained length 1,000, the final record was still `pwd`, and its input hash was not the hash of `id`. The attachment overstates the service effect: pre-fix `honeypot.py` already derived `command_sha256` and `verb` from the current bytes/command; stale fields were `blocked`, `reason`, and `output_sha256`. The service setting is constrained to 1–100 at `honeypot.py:32–42`, so no actual CLI setting can reach the simulator’s 1,000-event cap. | In `honeypot.py:564–592`, the handler records the event count before `execute()`. A fresh event supplies normal virtual metadata; no fresh event produces a current bounded audit record with `blocked=True`, `reason=virtual_command_limit` when closed, and SHA-256 of the returned output. New loopback regression `tests/test_review8_echo.py:30–62` temporarily reduces only the simulator cap to one, sends `pwd` then `id`, and asserts the current hash/verb and non-stale limit metadata. |
| No per-peer-IP quota; a global lifetime connection cap can be exhausted | **Intentional boundary** | The counter is explicitly lifetime-global (`honeypot.py:160–163`) and all accepted/rejected connections increment it at `honeypot.py:447`. The listener closes as soon as the final permitted connection is reached (`honeypot.py:452–459`), and `start()` refuses a used-up instance (`honeypot.py:242–247`). Existing bounded loopback test `tests/test_honeypot.py:137–150` verifies the final session can complete while the listener is closed. | No per-peer state, quota, cooldown, restart, or re-listen was added. This is intentionally fail-closed resource containment, not fair-share admission. Public deployment therefore requires independently operated ingress controls (for example, connection/rate limiting upstream of the service); application-level global limits cannot prevent one source from consuming the finite allowance. |
| Console rejection can be silent after the global output budget is exhausted | **Intentional boundary** | `_reject()` attempts the console text through `_safe_write()` (`honeypot.py:422–433`), which must reserve output before write (`honeypot.py:399–405`). When reservation would exceed the global cap, `_reserve_output()` starts shutdown and refuses bytes (`honeypot.py:217–225`). A response at that point would violate the strict global byte budget. Existing tiny-budget loopback test `tests/test_budget_enforcement.py:246–269` proves the second MIRROR byte is not sent, the listener closes, and only one output byte is charged. | No extra rejection output was added after budget exhaustion. Silent close is retained as the correct fail-closed behavior under the global output limit; audit is attempted without emitting visitor-visible output. |
| Inherited-credential refusal | **Confirmed safeguard** | `main()` checks the known sensitive environment-name set before `asyncio.run()` at `honeypot.py:823–833`, including AWS, cloud-provider, GitHub, and OpenAI variables. The launcher inspected during review uses `env -i`. New test `tests/test_review8_echo.py:72–82` injects only `AWS_SESSION_TOKEN`, proves `SystemExit(2)`, proves `asyncio.run` was never called, and verifies the placeholder value is not printed. | Preserved unchanged. No credential was read, logged, passed to the decoy, or used for an outbound operation. The finite name set is a defensive refusal check; the clean-environment launcher remains required for safer process inheritance handling. |
| Quoted shell operators are blocked before `shlex.split` | **Intentional boundary** | The raw stripped line is checked for shell metacharacters before tokenization at `simulator.py:105–111`. `echo "a;b"` reproduced a blocked response with `blocked=True` and `reason=not_permitted`. | Preserved. This conservative grammar avoids introducing a shell-like quote/operator semantics that could be confused with supported execution. Input is never executed. |
| Realistic-presentation string substitutions are brittle | **Clarification; no concrete boundary failure reproduced** | `_present()` is a narrow cosmetic chain at `simulator.py:130–136`; a future simulated-output wording change could leave a cosmetic marker visible or alter a matching substring. It does not execute input, change host telemetry, or remove the audit’s `simulation=True` provenance (`simulator.py:125–127` and `_event`). Realistic outputs for `id`, `php -m`, and `ss` were checked; corresponding in-memory events remained simulation-labelled. | No broad presentation refactor was made because it would change deliberate persona policy and exceeds the targeted correctness fix. Treat realistic terminal text as cosmetic only; audit provenance, not terminal phrasing, is the authoritative simulation label. |

## Before/after test record

### Before change

* Direct finite reproduction: after 1,000 simulator commands, a further command returned `"[SIMULATED] maximum command count reached; session closed"`; `events[-1]` was unchanged from the preceding `pwd` command.
* CLI range inspection: `--max-commands` is constrained to `(1, 100)` and cannot reproduce the 1,000-event simulator condition through the public service configuration.
* Focused pre-change suites passed: 39 tests across `test_simulator`, `test_honeypot`, `test_honeypot_boundary`, `test_budget_enforcement`, and `test_mirror`. They did not force the cross-limit condition.

### After change

Executed successfully:

```sh
PYTHONPATH=src python3 -m unittest \
  tests.test_review8_echo tests.test_simulator tests.test_honeypot \
  tests.test_honeypot_boundary tests.test_budget_enforcement tests.test_mirror -v
```

Result: **42 tests passed**. The new test uses only an ephemeral loopback listener, a temporary in-process constant patch, time-bounded reads/writes, and deterministic cleanup. Existing MIRROR coverage (`tests/test_mirror.py:42–79`) still asserts exact opaque binary same-socket echo, no `DecoySession.execute`, and no outbound `asyncio.open_connection`.

## Changed files

* `src/reverse_shell_decoy/honeypot.py` — prevents stale simulator-event metadata from entering service command audits.
* `tests/test_review8_echo.py` — focused regression and preserved service-boundary tests.
* `docs/review-8/echo.md` — this report.

`simulator.py` was reviewed but not changed. No README or project documentation was modified.

## Remaining limits and operational requirements

* The server deliberately has a finite, global, non-restartable lifetime connection cap and global input/output budgets. It prioritizes containment over availability/fairness; a single source can consume the allowance.
* Public exposure is not made safe by this process alone. An operator must provide independently reviewed upstream ingress isolation and rate/connection controls; loopback remains the default and non-loopback binding requires explicit opt-in.
* A post-exhaustion connection may receive a bare close because sending a rejection string would exceed the byte cap. This is intentional fail-closed behavior, not an invitation to reserve or emit extra bytes.
* Known inherited credential variables are refused before startup, but environment-name checks cannot establish that a host environment contains no secret of another name. Use the clean-environment launcher and keep credentials outside the decoy process.
* The direct `DecoySession` API still bounds retained events by design. Consumers other than the hardened service should not infer that `events[-1]` describes a call without first confirming the event count advanced.
* No change weakens the no-execution, no-callback, no-auto-restart, no-relisten, synthetic-state, or MIRROR opaque-byte guarantees.

---

# Review 8 — `collectors.py`

**Scope:** `src/reverse_shell_decoy/collectors.py` and the focused test file added for this review. The supplied attachment was treated as untrusted review material only. No live provider requests, credentials, account mutations, redirects, retries, or persistent services were used.

## Test evidence

All tests below use mocked HTTP openers or a finite in-memory response object.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*collectors.py' -v
```

Result after the changes: **15 tests passed** (9 existing collector tests and 6 new focused review tests).

## Classified claims

### 1. Partial failure discards successful Render data

- **Classification:** `confirmed_fixed`
- **Attachment claim:** A Render service-event failure after a prior successful service page was converted by `collect_cloud()` into an unavailable empty result, discarding the earlier page.
- **Before / reproduction:** `_collect_render()` iterated its bounded service IDs at the old request point and allowed a `CloudCollectionError` from service #2 to escape to `collect_cloud()`; the generic handler at `collect_cloud()` then constructed `_empty_result()` with zero events. A mocked service list, success for service #1, and HTTP 500 for service #2 reproduced the loss.
- **Fix / exact references:** `collectors.py:582-604` now catches a safe per-service failure only after at least one valid service-event page. It sets `coverage.truncated`, retains the prior events and page count, and appends a fixed partial-coverage warning. The same bounded-page preservation was also applied to Cloudflare (`collectors.py:360-389`) and AWS CloudTrail (`collectors.py:465-505`), where their second bounded page can otherwise cause the same loss.
- **After test:** `tests/test_review8_collectors.py:99-127`, `test_render_later_service_failure_retains_prior_records_with_partial_warning`, asserts that `evt-first` remains, `pages_fetched == 1`, `truncated` is true, the assessment remains `bounded_sample_not_an_all_clear`, the warning is explicit, no provider body appears, and exactly three fixed requests occurred.

### 2. Credential value redaction was limited to the selected provider

- **Classification:** `confirmed_fixed`
- **Attachment claim:** A supported-provider credential present in the same collector process but not selected for the current collection could appear in an event if it did not match a generic credential pattern.
- **Before / reproduction:** `_result()` called `_active_provider_credential_values(provider)`, which read only the selected provider tuple. With Cloudflare selected and a deliberately opaque `RENDER_API_KEY` in an event field, the opaque Render value was not an exact active-provider match and did not meet a generic pattern.
- **Fix / exact references:** `_result()` now uses `_known_collector_credential_values()` at `collectors.py:949`; that helper at `collectors.py:972-986` reads only the exact credential environment names enumerated in `_PROVIDER_CREDENTIAL_ENV`. It does not enumerate or scan arbitrary environment variables. Values remain transient, are not returned, and are applied only to output sanitization.
- **After test:** `tests/test_review8_collectors.py:129-168`, `test_cross_provider_known_credentials_are_redacted_without_scanning_other_environment`, verifies active Cloudflare and opaque cross-provider Render values are both absent from the returned JSON while an unlisted environment value is not implicitly scanned or redacted.

### 3. Sensitive-key matching removed non-secret token counters

- **Classification:** `confirmed_fixed`
- **Attachment claim:** Substring matching on `token` removed useful non-secret counter fields such as `tokensUsed` and `expirationTokenCount`.
- **Before / reproduction:** `_is_sensitive_key()` considered every normalized key containing the substring `token` sensitive, so both specified fields were omitted despite being numeric usage/count metadata.
- **Fix / exact references:** `collectors.py:1061-1069` separates token handling from the other sensitive substrings and preserves only a narrow suffix list of token usage/count/limit metrics declared near the top of the module. Ambiguous token-bearing fields, such as `sessionToken`, remain omitted.
- **After test:** `tests/test_review8_collectors.py:147-168` asserts that `tokensUsed` and `expirationTokenCount` remain while `sessionToken` does not.

### 4. A fresh HTTPS handler and SSL context were created for each request

- **Classification:** `confirmed_fixed`
- **Attachment claim:** `_request_json()` called `build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))` per request, including Render's bounded two-step collection.
- **Before / reproduction:** Every invocation at the old `_request_json()` opener construction point created a new handler and TLS context, even when collecting successive fixed-host pages in one process.
- **Fix / exact references:** `_get_http_opener()` at `collectors.py:223-245` lazily caches the redirect-refusing HTTPS opener behind a lock. It has no import-time network activity and invalidates its test cache if the opener factory is replaced. It does not cache credentials, URLs, responses, or provider data.
- **After test:** `tests/test_review8_collectors.py:241-260`, `test_https_opener_and_tls_handler_are_reused_within_a_collection_process`, makes two fixed-host calls and asserts one factory invocation, a `_NoRedirect` handler, an HTTPS handler, and two separate request opens.

### 5. The HTTP timeout was per socket operation rather than one overall response-read deadline

- **Classification:** `confirmed_fixed`
- **Attachment claim:** A slow peer could make intermittent progress and hold a connection beyond the advertised 15-second timeout because a socket timeout is normally applied per blocking read.
- **Before / reproduction:** `_request_json()` used one unbounded `response.read(MAX_RESPONSE_BYTES + 1)` after opening with `timeout=15`. This did not reduce the timeout as body bytes arrived.
- **Fix / exact references:** `_read_response_bytes()` at `collectors.py:792-828` uses a monotonic deadline for standard urllib HTTPS responses. It reads in 64 KiB bounded chunks and sets the underlying socket timeout to the remaining deadline before every read. It still enforces the existing 8 MiB response cap and produces a fixed, body-free failure if the deadline expires.
- **After test:** `tests/test_review8_collectors.py:223-239`, `test_streaming_read_uses_one_overall_deadline_not_a_fresh_timeout_per_chunk`, supplies one small first chunk just before the deadline and advances monotonic time beyond 15 seconds. It asserts the second read is refused rather than receiving a fresh 15-second window.

### 6. Redirect refusal was opaque in the status envelope

- **Classification:** `confirmed_fixed`
- **Attachment claim:** `_NoRedirect` converted 3xx responses into a generic unknown request failure, so the caller could not distinguish an intentional credential-protecting refusal.
- **Before / reproduction:** A mocked HTTP 302 reached `_request_json()` as `HTTPError`; the old `_http_failure_reason()` did not classify 3xx codes and returned `unknown_failure`.
- **Fix / exact references:** `_http_failure_reason()` maps 3xx to `redirect_refused` at `collectors.py:719-730`; `_http_failure_message()` provides only the fixed message `cloud HTTP redirect was refused` at `collectors.py:765-780`. `_request_json()` propagates that safe reason at `collectors.py:857-872`. Redirects remain unfollowed.
- **After test:** `tests/test_review8_collectors.py:170-193`, `test_redirect_is_explicitly_refused_without_location_or_provider_message`, asserts `integration_unavailable` with reason `redirect_refused`, one request only, and no mocked provider message or `Location` output.

### 7. HTTP 429 and Retry-After were not explicitly represented

- **Classification:** `confirmed_fixed`
- **Attachment claim:** Rate limiting received only the generic failure treatment; no explicit safe warning explained that retry guidance was deliberately not automatically followed.
- **Before / reproduction:** A mocked HTTP 429 was mapped by `_http_failure_reason()` to `unknown_failure`; `Retry-After` was ignored.
- **Fix / exact references:** `collectors.py:728-729` maps 429 to `rate_limited`. `_has_retry_after()` checks only whether the header exists, never returns its value (`collectors.py:756-762`); `_http_failure_message()` states that `Retry-After` was received and no automatic retry was attempted (`collectors.py:771-777`). There is no sleep, retry, provider-body read, or header-value echo.
- **After test:** `tests/test_review8_collectors.py:195-221`, `test_rate_limit_reports_retry_after_without_echoing_or_retrying`, asserts the `rate_limited` status, one request, no sleep, no provider body, and no `Retry-After` value in output.

## Boundaries and remaining limits

1. The review intentionally did not make live provider requests. Transport behavior is covered with deterministic mocked openers and an in-memory streaming response; provider permission, plan, retention, and actual provider response-shape compatibility remain unverified.
2. The overall read deadline applies to normal stdlib urllib HTTPS responses, which expose `response.fp.raw._sock`. The conservative single-read fallback remains for opaque response wrappers that do not expose a configurable socket; no unsafe background thread or unbounded cancellation mechanism was introduced.
3. A partial multi-page result remains a bounded sample, not a complete collection: `coverage.truncated` is set and warnings state that successful prior records were retained. The existing status envelope continues to describe the explicit integration request, while `coverage.assessment` remains `bounded_sample_not_an_all_clear`.
4. Cross-provider redaction covers only exact values in the collector's declared environment-name allowlist and narrow existing credential patterns. It deliberately does not claim to detect arbitrary secrets that are not present in those named values or that have no recognized shape.
5. `Retry-After` is acknowledged only as a safe presence indicator. Automatic waiting or retrying remains intentionally disabled to preserve the no-retries-by-default bounded-work policy.

## Files changed

- `src/reverse_shell_decoy/collectors.py`
- `tests/test_review8_collectors.py`

No git add, commit, reset, checkout, source push, documentation edit, provider call, or credentials were used.

---

# CloudSentry review 8 — authorization

**Baseline reviewed:** `4dea59f2c276d39ac20ed0ec926b6f2548b16389`
**Scope:** `src/reverse_shell_decoy/authorization.py` and the new focused review test only.
**Production change:** none. No confirmed production defect was found in this subsystem.

## Method

I read `docs/engineering-rules.md`, the authorization implementation, existing authorization tests, and the supplied review attachment as untrusted review material. I traced the local `--consent` call sites only to establish that they pass the explicit Boolean to `request_authorization`; no other subsystem was changed.

The signal claim was tested empirically, not inferred: short-lived Python child processes created a synthetic blocked pipe reader and a loopback-free `socket.socketpair()` receiver. Each child scheduled `SIGINT` after 0.15 seconds, ran the operation inside `cancellation_guard`, and had a three-second parent timeout. No signal was sent to the shared test runner.

## Claims and dispositions

### 1. `--consent` “unconditionally issues a grant”

**Classification:** intentional boundary

**Evidence:** `request_authorization` first validates both the exact scope and that `consent` has the exact type `bool` (`authorization.py:119-122`). A supplied `True` immediately issues a fresh grant (`:123-124`); the alternative path accepts only an affirmative interactive terminal response (`:125-128`). Existing test `test_explicit_boolean_consent_issues_fresh_opaque_grants` (`tests/test_authorization.py:54-62`) verifies two supplied `True` values create distinct opaque grants. `test_truthy_non_booleans_are_rejected` (`:64-67`) verifies that a string, mapping, integer, or list cannot stand in for this declaration.

The unconditional issuance after the caller explicitly supplies `--consent` is deliberate. It preserves noninteractive, per-invocation operator consent; it is not an attempt to validate a statement embedded in a log or customer data. The grant still binds an exact copied scope, expires, is revocable (`authorization.py:69-92`), and permits only one admission through `begin` (`:94-100`).

**Action:** No production change. Explicit CLI consent was preserved exactly; grants were not made dependent on untrusted-log content.

### 2. Operator consent is proof of ownership or operating-system policy

**Classification:** clarification

**Evidence:** The module-level contract already states that this is “an in-process safety gate, not a host-security boundary,” that arbitrary code in the same process can patch it, that no grant is parsed from customer data, and that every invocation requires a new exact-scope, short-lived grant (`authorization.py:1-6`).

An operator’s `--consent` is a declaration to this local process that the operator intends this bounded invocation. It is **not** evidence or proof that the operator owns the input, has authority over the target, meets an organization’s policy, or has any operating-system permission. Those properties must be enforced independently by the operating environment and calling workflow. This report makes the distinction plainly without changing README or project documentation outside the authorized scope.

**Action:** No production change; this is a boundary clarification, not a defect in the explicit-consent mechanism.

### 3. `SIGINT` during blocking `read`/`recv` is retried by PEP 475 and waits for timeout

**Classification:** not reproduced

**Code references:** The installed handler first permanently revokes the grant, then raises `AuthorizationError` (`authorization.py:145-147`); installed signal handlers are restored on exit (`:149-157`).

**Reproduction:** Before adding the regression test, a finite child-process experiment sent `SIGINT` after 0.15 seconds while blocked in each operation. Both results exited zero and reported `AuthorizationError` at `0.150` seconds; a post-signal `grant.check(scope)` also raised `AuthorizationError`.

The added regression test repeats this using only isolated children: `tests/test_review8_authorization.py:17-85` defines the synthetic fixtures and child behavior, and `:91-112` runs both modes with a three-second subprocess timeout. It requires an `AuthorizationError`, permanent revocation, restoration of the prior `SIGINT` handler, and completion in under 1.5 seconds. It passed for both pipe `read(1)` and socket `recv(1)`.

**Result:** The claim is not reproduced. In this Python/Linux environment, the handler raises rather than returns normally, so the blocked calls exit via `AuthorizationError` rather than being transparently retried.

**Action:** No production change. Added bounded regression coverage to prevent this verified behavior from regressing.

### 4. The guard “swallows `KeyboardInterrupt` semantics” over its active block

**Classification:** intentional boundary

**Evidence:** Within an active main-thread guard, the custom signal handler intentionally maps `SIGINT`/`SIGTERM` to `AuthorizationError` after revoking the grant (`authorization.py:143-147`). Existing coverage expects that exception and verifies handler restoration (`tests/test_authorization.py:167-191`).

This is intentionally different from default `KeyboardInterrupt` behavior so protected callers have a single cancellation/failure type while any later authorization check fails closed. Callers enclosing `cancellation_guard` must therefore handle `AuthorizationError` if they need cleanup or a particular CLI exit status.

**Action:** No production change. The behavior provides deterministic revocation and was preserved.

## Tests

### Before review change

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_authorization.py' -v
```

Result: **12 tests passed**.

Additionally, the manual bounded child experiment described above passed for blocked pipe read and blocked socket receive, both at 0.150 seconds. The parent imposed a three-second timeout.

### After review change

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_authorization.py' -v
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_review8_authorization.py' -v
```

Result: **12 existing tests passed; 1 new focused test passed** (two subtests: pipe and socket) in 0.431 seconds.

`git diff --check -- src/reverse_shell_decoy/authorization.py tests/test_review8_authorization.py` also completed cleanly. `authorization.py` has no diff; the only repository change in this scope is the new review test.

## Remaining limits

- This is an in-process safety gate, not a proof of ownership, authority, operating-system permission, or a host-security boundary. Same-process arbitrary code can bypass it.
- A `SIGKILL`, power loss, or other uncatchable termination cannot revoke or run cleanup (`authorization.py:133-136`).
- Signal handlers are installed only in the main thread. Worker-thread guards rely on explicit thread-safe grant checks and do not install process handlers (`authorization.py:140-142`; existing test `tests/test_authorization.py:193-209`).
- The blocking-I/O result is demonstrated on this Linux/Python test environment for the standard pipe and `socketpair` primitives. It is not a guarantee for every platform, custom extension, or operation that suppresses or delays Python signal handling.
- The custom handler intentionally replaces default `KeyboardInterrupt` with `AuthorizationError` only while the guard is active; consumers must account for that documented cancellation contract.

---

# CloudSentry review 8 — evidence subsystem

**Review scope:** `src/reverse_shell_decoy/evidence.py`; package version metadata needed to remove drift; and the focused review test. Baseline reviewed: `4dea59f2c276d39ac20ed0ec926b6f2548b16389`.

## Boundary and compatibility check

The patch does not alter `export_bundle()` or `verify_bundle()` signatures, their return schema, manifest schema, manifest payload hashes, UTC timestamps, session `simulation` validation, source/provenance language, no-overwrite private-output behavior, or input-size/member limits. It adds no I/O bypasses, no networking, and no data collection. Existing manifest hash verification and the separately trusted manifest-pin test remain green.

I read the sibling report interfaces in `operations.py`, `review.py`, and `summary.py` without editing them. They do not consume this evidence module. The actual evidence consumers found were `cli.py` and `investigator.py`; both use the unchanged public functions, so there is no interface compatibility concern to report to the parent.

## Classified attachment claims

### 1. Duplicated `TOOL_VERSION` can drift from package metadata

- **Classification:** `confirmed_fixed`
- **Attachment claim:** “TOOL_VERSION hardcoded `0.1.0` in evidence.py while pyproject.toml versions separately. Drift will break verification's tool_version comparison silently.”
- **Baseline evidence / reproduction:** The baseline had independent `"0.1.0"` literals in `pyproject.toml` `[project].version`, `src/reverse_shell_decoy/evidence.py:22` (`TOOL_VERSION`), and `src/reverse_shell_decoy/__init__.py:2` (`__version__`). A future edit to either packaging metadata or the evidence literal could therefore export a manifest whose `tool_version` did not match the released package version.
- **Fix:** The package initializer remains the sole literal source (`src/reverse_shell_decoy/__init__.py:2`). Evidence imports it and sets `TOOL_VERSION = __version__` at `src/reverse_shell_decoy/evidence.py:21-24`. Packaging now dynamically reads that same attribute at `pyproject.toml:7` and `pyproject.toml:26-27`. The version value remains `0.1.0`.
- **Before/after verification:** `tests/test_review8_evidence.py:18-28` asserts the source configuration and equality of package/evidence versions. A clean temporary wheel build produced `reverse_shell_decoy-0.1.0-py3-none-any.whl` whose `METADATA` has `Version: 0.1.0`.

### 2. `verify_bundle()` did not convert ZIP resource exceptions to a safe result

- **Classification:** `confirmed_fixed`
- **Attachment claim:** “verify_bundle doesn't catch MemoryError/LargeZipFile.”
- **Baseline evidence / reproduction:** In the baseline `verify_bundle()` wrapped ZIP processing only in `(zipfile.BadZipFile, EOFError, RuntimeError, OSError)`. A `zipfile.LargeZipFile` or `MemoryError` raised while opening/processing an untrusted archive could escape instead of returning the documented result dictionary.
- **Fix:** `src/reverse_shell_decoy/evidence.py:264-272` now catches exactly `zipfile.LargeZipFile` and `MemoryError` and returns the fixed non-reflective error `"bundle exceeds safe ZIP resource limits"`. `src/reverse_shell_decoy/evidence.py:429-437` also turns the same exceptions from central-directory enumeration into `"bundle directory exceeds safe ZIP resource limits"`. The change deliberately does not add a broad `BaseException` handler.
- **Before/after verification:** `tests/test_review8_evidence.py:31-53` uses a bounded regular temporary fixture and mocks `ZipFile` to raise each exception. In both cases `verify_bundle()` now returns exactly `{"valid": false, "warnings": [], "errors": ["bundle exceeds safe ZIP resource limits"]}` without propagating the exception. Existing tests continue to exercise malformed, unsafe, and configured oversized archives.

### 3. Path coercion helper rename (`_coerce_output_path` -> `_coerce_path`)

- **Classification:** `code_hygiene`
- **Attachment claim:** “_coerce_output_path is used for input paths too — misleading name.”
- **Evidence:** `export_bundle()` uses the helper for its output at `evidence.py:198`; `verify_bundle()` uses it for its selected input at `evidence.py:245`; its behavior at `evidence.py:283-286` is simply to accept a `str` or `Path` and construct a `Path`.
- **Action:** Renamed helper to `_coerce_path` in `src/reverse_shell_decoy/evidence.py` across all call sites for clarity.

## Tests run

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_review8_evidence.py' -v
# 2 tests passed

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_evidence*.py' -v
# 15 tests passed
```

I also built a wheel from a disposable copy using `python3 -m pip wheel --no-deps --no-build-isolation` and inspected its `.dist-info/METADATA`; it reports `Version: 0.1.0`. `git diff --check` over the assigned tracked files produced no whitespace errors.

## Remaining limits

- Catching `MemoryError` allows the verifier to fail closed with a bounded diagnostic, but cannot reclaim CPU or memory already consumed by Python/`zipfile` while parsing a hostile central directory. The existing 64 MiB input limit, member-size limits, total uncompressed limit, and no-extraction design remain in force; callers needing hard CPU/RSS isolation must provide it externally.
- ZIP member count is checked after the standard library reads the central directory. The verifier reports resource exhaustion safely if raised, but does not provide an operating-system process quota or timeout.
- Integrity consistency and manifest hashes still do not authenticate source, authorship, acquisition completeness, or custody. Imported detection data and observed interaction metadata remain unverified as documented.
- The dynamic version configuration depends on the deliberately side-effect-free package initializer continuing to expose `__version__`; the focused regression test and temporary wheel build enforce the current contract.

## Changed files

- `src/reverse_shell_decoy/evidence.py`
- `pyproject.toml`
- `tests/test_review8_evidence.py`

---

# CloudSentry portal targeted review

**Review scope:** actual portal source at `portal` and public-distribution source at `portal`; client JSON rendering, HTML/execution sinks, summary escaping, prototype handling, `server/customer-origins.ts`, authentication/ownership, and source-copy consistency.

**Baseline supplied:** `4dea59f2c276d39ac20ed0ec926b6f2548b16389`.

**Disposition:** No confirmed vulnerability or code change in this scope. This is a focused source/test review, not a complete penetration test.

## Classified claims

### 1. Attachment claim: portal untrusted JSON may permit XSS

- **Classification:** `not_reproduced`
- **Attachment reference:** `pasted_content_8.txt:35` (the portal is identified as the likely XSS review target; it does not provide a concrete exploit path).
- **Evidence:** Imported reports and summaries are inserted as React children rather than raw markup:
  - `portal/client/src/App.tsx:88-117` recursively bounds/redacts render values and serializes them with `JSON.stringify`.
  - `portal/client/src/App.tsx:564-572` renders each summary value as `<pre>{jsonText(value)}</pre>`.
  - `portal/client/src/App.tsx:606-620` renders a stored report as `<pre className="report-code">{preparedJson}</pre>`.
  - `portal/client/src/App.tsx:143-150` renders trust-label strings as React text nodes; those strings are either constants or constrained timestamp/digest values in `portal/client/src/integration-trust.ts:16-20, 23-59`.
  - A first-party source inventory over `client/src`, `server`, and `shared`, excluding tests and generated output, found no `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, `document.write`, or string-timer sink.
- **Reproduction / expected result:** With a valid managed session, import a JSON object containing a non-sensitive string such as `{"provider":"local","note":"<img src=x onerror=alert(1)>"}`. The server places it in `sanitized_representation` (`server/customer-api.ts:179-222`) and the client serializes it to a React `<pre>` text child. The browser displays literal characters; it does not create an `img` element or execute an event handler. No live session was fabricated for this review; the conclusion is based on the exact server/client flow and the existing mocked suite.
- **Before/after tests:** No fix was required, so there is no before/after patch test. Existing `server/customer-api.test.ts:226-254` verifies server-side sanitized-report handling, and the full mocked suite passed. A browser-renderer regression test for hostile markup is not currently present.
- **Minimal proposed patch:** None. If maintainers later modify these render paths, add a client render test which supplies hostile string values in both `detail.report` and `detail.summary` and asserts escaped text/no created markup.

### 2. Dynamic execution and HTML sink review

- **Classification:** `not_reproduced`
- **Evidence:** The targeted static inventory had zero first-party production matches for HTML sink/dynamic execution APIs. The only `new Function` found during wider searching is in `portal/server/platform.test.ts:18,20`, where it executes the portal's own generated public-config string with a fake document; it is test code, not a customer JSON path. `portal/server/_core/publicConfig.ts:11-14` serializes only selected public environment values with `JSON.stringify` and escapes `<` before returning a fixed assignment string.
- **Reproduction / expected result:** Customer import values flow through `JSON.stringify`, React text children, clipboard text, or a Blob download in `client/src/App.tsx:594-620`; none are used as markup or executable source.
- **Before/after tests:** No confirmed fix; no focused test added. `server/platform.test.ts:11-21` confirms server-only secrets are not emitted by the generated public script.
- **Minimal proposed patch:** None.

### 3. Summary/report escaping and bounded display

- **Classification:** `intentional_boundary`
- **Evidence:** `client/src/App.tsx:88-117` limits nesting, array entries, object entries, and strings before display. `client/src/App.tsx:560-572` uses four fixed section keys and prints values as JSON text. `client/src/App.tsx:606-620` limits a report view to 512 KiB and renders only the prepared JSON string. Downloads use `new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })` in `client/src/App.tsx:594-603`, not an HTML data URL.
- **Reproduction / expected result:** Long strings and deeply nested JSON are truncated by `filteredValue`; sensitive-key values match `SENSITIVE_KEY` and display as `[redacted]`. Markup-looking strings remain text. This is display bounding/redaction, not a claim that arbitrary imported evidence is trustworthy.
- **Before/after tests:** No confirmed fix. Existing `server/customer-api.test.ts:226-254` confirms server redaction of `password` and nested `apiToken` before persistence/response.
- **Remaining limit:** The client-side sensitive-key regex is presentation defense, not a substitute for server validation or a guarantee that every secret-like value under an innocuous key is recognized.

### 4. Prototype handling for customer JSON

- **Classification:** `not_reproduced`
- **Evidence:** The import API accepts one JSON object only and recursively bounds it in `server/customer-api.ts:135-144`. The import sanitizer constructs output objects with a null prototype in `server/customer-api.ts:153-161`; the client display filter does the same in `client/src/App.tsx:95-101`. Neither path merges customer keys into process/global configuration or `Object.prototype`. The summary selector uses `key in summary` at `client/src/App.tsx:560-562`, but `key` is one of four source-code constants at `:565-570`, not a customer-controlled property name. The server-generated summary derives from the sanitized stored report (`server/customer-api.ts:253-292`).
- **Reproduction / expected result:** Importing `{"provider":"local","__proto__":{"polluted":"x"}}` is handled as JSON data. The resulting server/client sanitized objects are null-prototype objects; no assignment to `Object.prototype` or configuration merge occurs. No prototype pollution was reproduced through the reviewed JSON path.
- **Before/after tests:** No confirmed fix and no test added. Existing import bounds/redaction tests pass, but a direct `__proto__` regression fixture is absent.
- **Minimal proposed patch:** None required by this review. A future hardening test could submit a `__proto__` own property and assert `({} as Record<string, unknown>).polluted` remains `undefined` and the response is ordinary JSON text.

### 5. `server/customer-origins.ts` exact allowlist / host validation

- **Classification:** `intentional_boundary`
- **Evidence:** `server/customer-origins.ts:2-19` owns two literal HTTPS origins and tests membership with exact `includes`; it does not derive a trusted origin from request Host, forwarded headers, query content, or environment configuration. `server/customer-security.ts:61-80` rejects non-HTTPS origins, credentials, non-root paths, query strings, fragments, whitespace/control characters, and non-canonical URL representations. `resolveTrustedRequestOrigin` (`:102-129`) requires all supplied query/Origin/Referer candidates to normalize to one identical allowlisted value. Mutation enforcement (`server/customer-api.ts:237-250`) additionally requires the exact external Origin to equal the customer session's origin.
- **Reproduction / expected result:** A profile POST with an otherwise valid session/CSRF header and `Origin: https://attacker.example` reaches `mutationAuthenticated` and returns 403 before repository creation. Existing mocked test: `server/customer-api.test.ts:256-268` exercises this exact case and verifies `createProfile` is not called.
- **Before/after tests:** Existing test passed; no change was needed. No before/after test exists because no defect was confirmed.
- **Remaining limit:** The hard-coded preview and production literals must be deliberately updated by the publisher when deployment topology changes. This review did not validate DNS/TLS ownership or deployment configuration outside the checked-in source.

### 6. Authentication, CSRF, and customer ownership isolation

- **Classification:** `not_reproduced`
- **Evidence:**
  - Customer sessions are server-side revocable records keyed by a hash of an HttpOnly/Secure cookie (`server/customer-auth.ts:179-221`; cookie options in `server/customer-security.ts:43-55`). Authorization headers are intentionally ignored in the managed-session bootstrap (`customer-auth.ts:223-246`).
  - Managed-session verification uses JWT signature verification restricted to HS256, requires `exp`, and checks the app ID (`server/_core/sdk.ts:202-220`; corresponding mocked test `server/customer-api.test.ts:147-155`).
  - OAuth callback processing requires state/cookie nonce equality, consumes the state once, verifies the stored allowlisted origin and exact callback URL before code exchange, and redirects only to the fixed in-app path (`server/customer-auth.ts:307-360`).
  - Every state-changing customer endpoint passes `mutationAuthenticated`, requiring the owner session, exact Origin, and an equality-checked CSRF hash (`server/customer-api.ts:237-250`).
  - Reads/writes use `active.session.user.id`; scan/profile lookup/delete/update methods include `ownerId` predicates (`server/customer-api.ts:295-473`; `server/customer-db.ts:270-311`).
- **Reproduction / expected result:** Requesting a scan whose repository lookup returns no record for the active owner receives 404; the mocked test asserts `findOwnedScan(7, 44)` in `server/customer-api.test.ts:256-268`. A foreign-origin mutation receives 403 as above. No account/session was created or altered during this review.
- **Before/after tests:** Existing mocked tests passed: malformed state rejection (`customer-api.test.ts:165-187`), managed JWT project/expiry validation (`:147-155`), owner predicate behavior (`:256-268`), and cookie-clearing coverage (`server/auth.logout.test.ts:6-18`). No fix/test was added because no defect was confirmed.
- **Remaining limit:** Tests inject repository and identity seams; they do not validate a live managed identity provider, a production database, browser cookie behavior in every deployment topology, or external ingress/CSP configuration.

### 7. Actual portal vs public distribution source-copy consistency

- **Classification:** `intentional_boundary`
- **Evidence:** A read-only SHA-256 comparison of 67 relevant first-party client/server/shared/drizzle/config/test files found no missing files and no content differences between `portal` and `portal`. The key security files also matched pairwise: `client/src/App.tsx`, `client/src/api.ts`, `client/src/integration-trust.ts`, and `server/customer-{api,auth,db,origins,security}.ts`. A broader first-party comparison found only local logs, `RELEASE-CHECKS.md`, and `vite.config.ts.bak` present solely in `portal`; none are public distribution source copies. `git diff --name-status <baseline> -- portal` and `git status --short -- portal` were empty at the time checked.
- **Reproduction / expected result:** Re-running a first-party hash comparison should report 67 compared files, no distribution omissions, and no content differences. The public source therefore contains the same reviewed portal behavior.
- **Before/after tests:** No source-sync fix was necessary. The actual portal test suite was used because its first-party source is byte-identical to the public distribution source.
- **Remaining limit:** This establishes source-tree equality at review time. It does not prove which generated artifact a remote deployment serves, nor inspect any separate deployment pipeline.

## Test evidence

Executed in `portal` with existing finite mocked/loopback fixtures only:

```text
pnpm test && pnpm check
```

Result: **7 test files passed; 33 tests passed; `tsc --noEmit` passed.** The Vitest request helpers bind temporary listeners to `127.0.0.1` and close each listener (`server/customer-api.test.ts:83-94`). No production service was started, no real customer data/session was used, and no database was written.

## Changes

No application code, tests, documentation, repository state, credentials, databases, accounts, or deployment configuration were changed. The sole artifact created is this review report.

## Review limits

- The assessment was restricted to the assigned portal rendering/origin/authentication/ownership/source-copy topics and the attachment's portal XSS lead.
- It is not a complete penetration test and makes no claim about third-party dependencies, browser extensions, CSP/headers/load balancers, deployment configuration, DNS/TLS control, live OAuth provider behavior, live database behavior, or a hosted artifact that may differ from source.
- No browser session was fabricated and no authenticated production request was made. Findings are based on static tracing and existing mocked/loopback tests.
- No confirmed vulnerability means no focused fix test was added; the report identifies narrowly scoped regression-test opportunities without weakening existing tests.

---

# CloudSentry review 8 — launchers and config-auditor bridge

**Baseline:** `4dea59f2c276d39ac20ed0ec926b6f2548b16389`
**Reviewed ownership:** `scripts/scan-configurations.py`, the six shell launchers under `scripts/`, and host-added `integrations/config-auditor/bridge_runner.py`. The vendored `integrations/config-auditor/scanner/` snapshot was not changed.
**Review method:** static inspection plus finite local temporary-file and mocked-subprocess tests. No scanner run, service launch, customer input, provisioning action, or untrusted attachment instruction was executed.

## Test record

A focused test file, `tests/test_review8_launchers_bridge.py`, was added before production changes. Against the pre-fix implementation it produced **9 assertion failures and 3 errors**: all six launcher cases failed the pre-execution isolation expectation; the mirror/tarpit wrappers still chained through inherited Bash; and no bounded snapshot helper existed. The mocked subprocess fixture was then corrected to provide its numerical return code before the final run could reach and verify the explicit descriptor-closure assertion. The existing intentional symlink-rejection case already passed.

After the changes:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  tests/test_review8_launchers_bridge.py tests/test_config_auditor_bridge.py
# Ran 14 tests — OK

python3 -m py_compile scripts/scan-configurations.py \
  integrations/config-auditor/bridge_runner.py \
  tests/test_review8_launchers_bridge.py
for f in scripts/*.sh; do /bin/sh -n "$f"; done
git diff --check -- scripts/scan-configurations.py \
  integrations/config-auditor/bridge_runner.py scripts/*.sh \
  tests/test_review8_launchers_bridge.py
# all succeeded
```

## Claims and findings

### 1. Service launchers need effective `env -i` isolation

**Classification:** `confirmed_fixed`

**Claim:** The attachment asks whether `start-honeypot.sh` actually drops credential-bearing environment variables and raises the related concern that service wrappers can still execute through inherited shell or PATH state before `env -i` takes effect.

**Before / reproduction:** The baseline `scripts/start-honeypot.sh:5-6`, `emergency-tarpit.sh:5-6`, and `shellception.sh:6-8` used `command -v python3` before clearing the environment. Thus the program path itself could be selected through the caller's `PATH`. `scripts/mirror.sh:1,6` and `scripts/tarpit.sh:1,5` used `#!/usr/bin/env bash` and then `exec bash ...`; both decisions happen before `start-honeypot.sh` gets to its own `env -i`. A non-interactive Bash can process `BASH_ENV`, so relying on a later shell script to sanitize is too late. `backup-echo.sh` already used `env -i` for Python but resolved `env` and `dirname` through inherited command lookup before that point.

**Action / exact references:** All six launchers now use `#!/bin/sh`, pin the initial command lookup with `PATH=/usr/bin:/bin` at lines 3-4 (or 4-5 in the longer wrappers), and execute `/usr/bin/env -i` plus fixed `/usr/bin/python3` paths. See `scripts/start-honeypot.sh:1-8`, `scripts/emergency-tarpit.sh:1-8`, `scripts/shellception.sh:1-9`, and `scripts/backup-echo.sh:1-8`. `scripts/mirror.sh:1-9` and `scripts/tarpit.sh:1-8` now directly start the intended honeypot module under their sanitized environment rather than starting another Bash process.

**Tests:** `LauncherIsolationTests.test_service_launchers_fix_command_path_and_clear_environment` checks every service launcher for the fixed POSIX interpreter, fixed initial path, absolute `/usr/bin/env -i`, absolute Python, and absence of `command -v python3`, `exec bash`, and `#!/usr/bin/env`. `test_mode_wrappers_clear_environment_before_starting_honeypot` separately checks mirror and sink mode preservation without the nested-script chain. `/bin/sh -n` passed for every launcher.

**Remaining limits:** The launchers deliberately retain only the listed runtime variables (`PATH`, `PYTHONPATH` where needed, and bytecode/user-site controls). They do not provide a general mechanism to retain locale, proxy, credential, or customer-provided environment values. This is an intentional credential-isolation boundary. The test is static and syntax-based; it does not start a decoy service.

### 2. Configuration-auditor child descriptor inheritance must be narrow and explicit

**Classification:** `clarification`

**Claim:** The bridge must not inherit ambient descriptors into the scanner child.

**Before / reproduction:** Baseline `scripts/scan-configurations.py:156-158` used `pass_fds=(descriptor,)`. On supported POSIX Python, supplying `pass_fds` already forces `close_fds=True`, so an ambient descriptor leak was **not reproduced**. However, that security property was implicit rather than asserted by local tests.

**Action / exact references:** `scripts/scan-configurations.py:146-158` retains the fixed clean environment, `stdin=DEVNULL`, `stderr=DEVNULL`, and the one selected descriptor, and now explicitly sets `close_fds=True` with `pass_fds=(descriptor,)`.

**Tests:** `ScanBridgeDescriptorTests.test_scanner_child_inherits_only_selected_descriptor_under_clean_environment` mocks `Popen` and asserts the exact clean environment, `close_fds is True`, `pass_fds == (47,)`, and `DEVNULL` for standard input/error.

**Remaining limits:** This verifies the host bridge call contract, not the behavior of a nonstandard Python runtime. The fixed scanner virtual environment is still a deployment prerequisite, intentionally outside this review's scope.

### 3. Bridge regular-file race and bound after fd handoff

**Classification:** `confirmed_fixed`

**Claim:** The inherited descriptor must remain a bounded regular-file input even if a local process changes the selected file after authorization or while the bridge runs.

**Before / reproduction:** Baseline `bridge_runner.py:47-52` checked type and size once, then `bridge_runner.py:116-122` created a staging symlink to `/proc/self/fd/<fd>` and passed it to the upstream scanner. A pathname swap could not redirect that fd, but in-place writes or growth after the point-in-time check could change the bytes read by the scanner and defeat the intended size snapshot. There was no private immutable staging file for the scanner.

**Action / exact references:** `bridge_runner.py:68-99` now copies the opened descriptor to a `0600`, `O_CREAT|O_EXCL|O_NOFOLLOW` private regular file. It uses `pread` in 64 KiB chunks so it does not change the parent descriptor offset, copies only the initially bounded size, and compares device, inode, size, mtime, and ctime before and after the copy. A detected ordinary concurrent write fails closed with `ValueError`. `bridge_runner.py:163-167` passes that regular snapshot, not a symlink, to the vendored scanner. The parent already validates with `O_NOFOLLOW` and device/inode/size checks in `scripts/scan-configurations.py:70-103`.

**Tests:** `BridgeSnapshotTests.test_snapshot_copies_to_private_regular_file_without_consuming_parent_offset` asserts a non-symlink regular staged file with identical bytes and preserved parent fd position. `test_snapshot_rejects_a_source_changed_while_copying` deterministically appends during a mocked `pread` and expects rejection. `test_snapshot_rejects_file_over_the_reviewed_bound` rejects a local regular fixture over `MAX_FILE_BYTES`.

**Remaining limits:** No portable userspace copy can prove an adversarial writer with sufficient local privilege has not changed contents while restoring all observed metadata; the before/after metadata comparison rejects the ordinary race but is not a filesystem lock or forensic acquisition guarantee. The private staged bytes, however, are no longer affected by subsequent source-path swaps or writes after copy completion.

### 4. `--target` rejects symlinks, including alternatives-style paths

**Classification:** `intentional_boundary`

**Claim:** The attachment says `/etc/alternatives/...` style targets are unusable because `_canonical_regular_target` rejects a symlink before `realpath`.

**Evidence / reproduction:** This is reproduced by design. `scripts/scan-configurations.py:73-76` uses `lstat` and requires the operator-selected entry itself to be a regular file, so a symlink is rejected before the `realpath` on line 79. `ScanBridgeDescriptorTests.test_selected_target_symlink_is_rejected_before_authorization` creates a local symlink and proves `main()` returns `2` without requesting authorization. The pre-existing `tests/test_config_auditor_bridge.py::test_symlink_is_rejected_before_authorization_or_subprocess` verifies the same no-subprocess behavior.

**Action:** No change. The requested subsystem policy is deliberate strict rejection by default; following alternatives or arbitrary user-selected links would broaden the authorization/path-race boundary. No safe explicit symlink-following design existed, and none was added.

**Remaining limits:** Operators must select the resolved ordinary file rather than a symlink alias. This affects alternatives-style paths intentionally.

### 6. `GH_TOKEN` refusal in direct honeypot startup

**Classification:** `intentional_boundary`

**Claim:** The attachment states that a developer shell with `GH_TOKEN` cannot start the main command and that the error directs users to a shell launcher.

**Evidence:** The guard is outside ownership at `src/reverse_shell_decoy/honeypot.py:826-831`; it explicitly refuses credential-bearing environment variables, including `GH_TOKEN`, and directs users to `scripts/start-honeypot.sh`. The repaired `scripts/start-honeypot.sh:3-8` now clears that variable with `env -i` before invoking the module, so the referenced launcher is a valid clean-environment path.

**Action:** No honeypot-main policy change. The attached concern is a usability trade-off rather than a launcher failure after this fix.

**Remaining limits:** Direct module invocation from a credential-bearing development shell remains intentionally refused. Launchers do not preserve developer credentials.

## Vendor integrity and non-scope notes

`git diff --name-only 4dea59f2c276d39ac20ed0ec926b6f2548b16389 -- integrations/config-auditor` returned only `integrations/config-auditor/bridge_runner.py`. No upstream MIT scanner, license, notice, test, frontend, or documentation file was altered. Other repository changes visible in the shared working tree were left untouched.

---

# CloudSentry CI review 8

## Scope and evidence

Reviewed only `.github/workflows/*.yml`, `.pre-commit-config.yaml`, and the focused regression test added at `tests/test_review8_ci.py`. The attachment’s CI-specific review request was: action pinning, least-privilege token scopes and pull-request/fork behavior, and whether secret scanning is blocking. The attachment’s remaining claims concern other owned subsystems and were not reviewed here.

The starting point was baseline `4dea59f2c276d39ac20ed0ec926b6f2548b16389`. Public GitHub API tag objects were read-only resolved on 2026-10-30 to the commit SHAs retained below. No workflow dispatch or remote workflow run was requested or performed.

## Claims

### 1. Mutable reusable action and pre-commit references — confirmed fixed

**Classification:** `confirmed_fixed`

**Before:** The baseline used mutable major-version tags at `.github/workflows/tests.yml:14-15`, `.github/workflows/portal-tests.yml:20-21`, `.github/workflows/config-auditor-tests.yml:25-26`, and `.github/workflows/secrets.yml:19,28`. The local Gitleaks hook used the mutable release tag `v8.30.0` in `.pre-commit-config.yaml:3`.

**After:** All nine references are full 40-character commits and retain the original requested version as a comment:

- `.github/workflows/tests.yml:14-15`: checkout `v4` and setup-python `v5`.
- `.github/workflows/portal-tests.yml:20-21`: checkout `v4` and setup-node `v4`.
- `.github/workflows/config-auditor-tests.yml:25-26`: checkout `v4` and setup-python `v5`.
- `.github/workflows/secrets.yml:19,28`: checkout `v6` and gitleaks-action `v3`.
- `.pre-commit-config.yaml:3`: Gitleaks `v8.30.0`.

**Verification / reproduction:** The following read-only GitHub API tag refs were resolved, with annotated tags dereferenced when necessary:

```sh
gh api repos/actions/checkout/git/ref/tags/v4
gh api repos/actions/setup-python/git/ref/tags/v5
gh api repos/actions/setup-node/git/ref/tags/v4
gh api repos/actions/checkout/git/ref/tags/v6
gh api repos/gitleaks/gitleaks-action/git/ref/tags/v3
gh api repos/gitleaks/gitleaks/git/ref/tags/v8.30.0
```

They resolved respectively to `11d5960a326750d5838078e36cf38b85af677262`, `a26af69be951a213d495a4c3e4e4022e16d87065`, `49933ea5288caeca8642d1e84afbd3f7d6820020`, `d23441a48e516b6c34aea4fa41551a30e30af803`, `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e`, and `6eaad039603a4de39fddd1cf5f727391efe9974e`. [1] [2] [3] [4] [5] [6]

**Before/after regression test:** `tests/test_review8_ci.py:34-52` now requires every configured action line and the local pre-commit hook revision to equal the verified immutable references. This test would have failed against the baseline tags and passes after the change.

### 2. Least-privilege token scopes and untrusted pull-request behavior — intentional boundary

**Classification:** `intentional_boundary`

**Evidence:** Every workflow uses `pull_request`, not `pull_request_target`: `.github/workflows/tests.yml:2-6`, `.github/workflows/portal-tests.yml:2-12`, `.github/workflows/config-auditor-tests.yml:3-18`, and `.github/workflows/secrets.yml:3-10`. The ordinary test workflows and config-auditor workflow grant only `contents: read`. The secret scanner adds only `pull-requests: read`.

The additional read scope is necessary to the pinned Gitleaks action on pull-request events: its pinned source requires `GITHUB_TOKEN` and calls the PR-commits read endpoint before it reaches the `GITLEAKS_ENABLE_COMMENTS=false` check. Comment creation, artifact upload, and summary publication remain disabled at `.github/workflows/secrets.yml:29-34`. No scope is granted write permission. [7]

**Verification / reproduction:** Inspect the exact pinned action source without executing it:

```sh
gh api repos/gitleaks/gitleaks-action/contents/src/gitleaks.js?ref=e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e
gh api repos/gitleaks/gitleaks-action/contents/src/index.js?ref=e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e
```

**Regression test:** `tests/test_review8_ci.py:54-67` rejects `pull_request_target`, requires `pull_request`, asserts the exact permission blocks, and rejects any `write` scope. It passes after the change.

### 3. Secret scanning is a failing CI check, not advisory — intentional boundary

**Classification:** `intentional_boundary`

**Evidence:** Although the official incremental action is allowed to finish so mandatory scans still run, the workflow executes both a complete reachable-history scan and a checked-out-tree scan with `--redact --exit-code=1` at `.github/workflows/secrets.yml:36-43`. It then explicitly exits 1 if the incremental scan failed at `.github/workflows/secrets.yml:45-49`. Thus a detected secret or incremental action failure fails the workflow job. The 10-minute timeout is unchanged at line 16.

**Verification / reproduction:** This is deterministically inspectable without scanning repository content:

```sh
PYTHONPATH=src python3 -m unittest tests/test_review8_ci.py -v
```

`CIConfigurationSecurityTests.test_secret_scan_remains_blocking_and_redacted` checks both mandatory commands, their nonzero exit behavior, redaction flags, and the final explicit failure. It passes after the review.

**Remaining limit:** A failing workflow check blocks a merge only if repository branch protection or rulesets require that check. Branch protection/ruleset configuration was outside this read-only file scope and was not queried or changed; therefore this review establishes job failure behavior, not GitHub merge-policy enforcement.

### 4. Independent config-auditor CI tests and existing timeout were preserved — intentional boundary

**Classification:** `intentional_boundary`

**Evidence:** `.github/workflows/config-auditor-tests.yml:21-40` still has its original 10-minute timeout, runs the vendored scanner’s `python -m pytest`, and separately runs `python -m unittest tests/test_config_auditor_bridge.py`. No concurrency or timeout setting was added or altered.

**Before/after regression tests:** `tests/test_review8_ci.py:83-88` statically protects the timeout and both test commands. The independent bridge suite also passed locally:

```sh
PYTHONPATH=src python3 -m unittest tests/test_config_auditor_bridge.py -v
```

It completed 7 tests successfully.

## Validation performed

```sh
PYTHONPATH=src python3 -m unittest tests/test_review8_ci.py -v
# 5 tests passed

PYTHONPATH=src python3 -m unittest tests/test_config_auditor_bridge.py -v
# 7 tests passed

git diff --check -- .pre-commit-config.yaml .github/workflows tests/test_review8_ci.py
# passed
```

No workflow dispatch, push, GitHub secret or repository-setting change, Git mutation, live scan, or persistent service was run. Local `pre-commit`, PyYAML, Ruby, and Node YAML parsers were unavailable, so no separate parser-based YAML validation was possible; the static test and whitespace check cover the modified syntax-sensitive invariants.

## References

[1]: https://api.github.com/repos/actions/checkout/git/ref/tags/v4 "GitHub API checkout v4 tag reference"
[2]: https://api.github.com/repos/actions/setup-python/git/ref/tags/v5 "GitHub API setup-python v5 tag reference"
[3]: https://api.github.com/repos/actions/setup-node/git/ref/tags/v4 "GitHub API setup-node v4 tag reference"
[4]: https://api.github.com/repos/actions/checkout/git/ref/tags/v6 "GitHub API checkout v6 tag reference"
[5]: https://api.github.com/repos/gitleaks/gitleaks-action/git/ref/tags/v3 "GitHub API gitleaks action v3 tag reference"
[6]: https://api.github.com/repos/gitleaks/gitleaks/git/ref/tags/v8.30.0 "GitHub API gitleaks v8.30.0 tag reference"
[7]: https://github.com/gitleaks/gitleaks-action/blob/e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e/src/gitleaks.js "Pinned gitleaks action pull request scan source"
