# CloudSentry: Forensics and Deception

**[Launch CloudSentry in your browser](https://csportal-brpeckhv.manus.space)**

The keyless browser portal uses managed Google/Microsoft/passkey sign-in, customer-owned provider profiles and deliberately imported scan results. No cloud API keys are requested or stored. Cloudflare, AWS, Render and Railway profiles are metadata bookmarks, not authenticated cloud connections; customers perform provider login, scanning and export themselves. Every summary asks fresh permission. Direct GitHub sign-in is not included in the approved keyless version.

The browser application source is in [`portal/`](portal/), with [run instructions](portal/README.md). This public repository is an additional source distribution; the live deployment remains separately managed. Source availability and the launch link do not share anyone's reports or credentials.

**Start at the [complete source, guide and public-link index](LINKS.md).** Source is organized on `main`; linked projects are credited below. A reference does not mean its code is installed, copied, security-reviewed, operational or endorsed.

## Creators, upstream work and ethical use

| Creator / community | Original work | How this repository uses or references it |
|---|---|---|
| [@HuginnsHammer](https://github.com/HuginnsHammer) | [CloudSentry static configuration auditor](https://github.com/HuginnsHammer/CloudSentry) | Separately namespaced, pinned MIT-licensed Terraform/Dockerfile/Compose auditor; original source, copyright and license preserved under `integrations/config-auditor/`. See its provenance notice and integration guide. |
| [@jephersonRD](https://github.com/jephersonRD) | [PC-Free](https://github.com/jephersonRD/PC-Free) | Design reference for a separate offline backup candidate; no automatic installation or inheritance of its privileged/default networking choices. |
| [@dockur](https://github.com/dockur) | [Windows runtime](https://github.com/dockur/windows) | Referenced dependency concept for the PC-Free-derived candidate; runtime/image contents are not vendored or authenticated merely by linking. |
| [@TechxArtisanStudio](https://github.com/TechxArtisanStudio) | [Openterface KVM-GO hardware](https://github.com/TechxArtisanStudio/Openterface_KVM-GO_Hardware) | Administrator-only physical-console reference; no visitor HID/device adapter and no hardware test claim. |
| [@9elements](https://github.com/9elements) | [VMBoot](https://github.com/9elements/VMBoot) | Separate firmware-research reference; not flashed, provisioned or enabled by customer content. |
| [@qemu](https://github.com/qemu), QEMU contributors | [QEMU](https://github.com/qemu/qemu) | Distribution-installed trusted functional lab tools; source and firmware licenses remain upstream. TCG results do not establish hostile-guest isolation. |
| Linux KVM community | [KVM](https://www.linux-kvm.org/) | Referenced hardware-virtualization backend; this sandbox does not expose `/dev/kvm`. |
| [@stefanberger](https://github.com/stefanberger), swtpm contributors | [swtpm](https://github.com/stefanberger/swtpm) | Distribution-installed software TPM used only for finite trusted-fixture tests; no physical-TPM assurance. |
| [@tianocore](https://github.com/tianocore), EDK II contributors | [EDK II / OVMF / AAVMF](https://github.com/tianocore/edk2) | Firmware-functional testing reference and distribution firmware; Secure Boot enforcement remains unproven unless the required controls are observed. |
| [@openbmc](https://github.com/openbmc), OpenBMC contributors | [OpenBMC](https://github.com/openbmc/openbmc) | Optional hardware-management research reference only; no BMC deployment or testing included. |
| Prompt Injection Database project | [Public site](https://www.promptinjectiondatabase.com/) | Referenced source/possible contribution destination; no access-gated corpus is copied, and no endorsement or submission is implied. |
| GitHub community | [Virtual-machine topic](https://github.com/topics/virtual-machine) | Discovery index, not an implementation or security certification. |

The original CloudSentry triage, bounded deception, evidence, customer-report and keyless-portal work remains distinguished from upstream modules. Git history and each imported component's own notice preserve attribution; no root license relabels third-party work. Creator profile links and handle text provide public credit and professional discovery, without implying endorsement. README references do not guarantee a notification. Direct issues, pull requests, messages and third-party submissions are separate actions, not automatically sent by the software.

Use only on infrastructure and evidence you are authorized to assess. Never turn resource controls, echo behavior, uploaded content or a detector flag into authority to exhaust a remote endpoint, execute a visitor command, provision a VM or access another person's systems. Preserve original evidence and separate synthetic effects, descriptive patterns and unverified claims from established facts. No authorship, identity, psychology or legal certainty is inferred from a writing-pattern summary.

## Combined static configuration auditing

Your incident-response/deception/report toolkit is now combined with the independently namespaced [MIT configuration auditor by @HuginnsHammer](https://github.com/HuginnsHammer/CloudSentry), pinned at `0e4fd3b55fcb4073db6943e4a2ad802b5e0dba6c`. Its original scanner, tests, frontend, documentation and license are preserved; they do not replace the keyless portal or start an API automatically.

```sh
# Optional isolated dependency environment; core tools do not require it.
python3.12 -m venv .config-auditor-venv
.config-auditor-venv/bin/python -m pip install -e './integrations/config-auditor[dev]'

# Explicitly authorize static inspection of one selected file, not execution.
python3 scripts/scan-configurations.py --target /absolute/path/to/Dockerfile \
  --format json --consent
```

Terraform, Dockerfile and Compose rules retain stable finding IDs, source/evidence locations, severity/confidence, remediation and JSON/SARIF/text output. The host bridge rejects directories and symlinks, limits selected files to 2 MiB, uses an authorized descriptor, bounds runtime/output and checks revocation before releasing results. Exit 0 means no qualifying finding, 1 means findings and 2 means incomplete, denied or failed—not clean. It never executes scanned input, starts a container, applies Terraform, contacts a provider or auto-remediates. Source evidence and paths can be sensitive: review the whole output before manual portal import as `local`. See [setup, upstream limits and source provenance](docs/config-auditor-integration.md).

A local incident-response triage tool with a separate, in-memory deception terminal. It imports pasted or selected real logs, records limited OS details, inventories Linux listeners, flags possible shell-linked TCP connections and persistence indicators, and checks domain/package lookalikes against an operator-provided baseline.

The decoy can display a neutral maintenance console and apparent root/administrator access. This is cosmetic: it never obtains privileges, executes submitted commands, opens an outbound connection, or exposes the actual host. The local terminal opens no sockets; the optional service only accepts bounded inbound sessions. Operator notices, audit events, and evidence exports retain explicit simulation provenance even when the terminal presentation is realistic.

**The scanner and decoy are separate local components. An optional decoy service accepts bounded inbound terminal interactions and does not expose a scanner/admin interface. The browser launch link opens the customer portal, not a public honeypot or shell.** Neither decoy mode redirects an existing reverse shell or grants real remote access. Public repository visibility does not publish your logs or create a decoy listener.

Cloudflare, AWS, Render and Railway exported/pasted logs have separate manual analyzers. Optional supported read-only API collection is an explicitly invoked operation with the owner's scoped credentials; those credentials never belong in the decoy. There is no scan by default. Start only the honeypot with `sh scripts/start-honeypot.sh`, which drops inherited credentials. The [manual workflow](docs/workflow.md) covers cloud evidence, the summary script, and review-only positive-indicator sinkhole proposals. No automatic DNS change, traffic interception or remote credential/file extraction is included.

## Defensive resource economics

**Make suspicious activity unproductive while keeping your own decoy's work finite.** The design objective is to deny useful access through the synthetic environment, preserve evidence-linked indicators and automatically stop at local resource limits—not damage another device, force an investigation, consume remote resources or guarantee an attacker's costs. No command entered into the decoy reaches a real host interpreter. A synthetic environment is not a promise that the whole surrounding infrastructure cannot be compromised.

The service now enforces **global admitted-input and reserved-output budgets** across all sessions, plus a **per-session input budget** and a **configurable command/chunk rate**. Global byte-budget violations close the listener and active sessions; per-session input/rate violations close the affected session. Time, connection, command and audit limits remain in force, with no automatic restart. Example for an authorized isolated local environment:

```sh
sh scripts/start-honeypot.sh --max-runtime 600 \
  --max-input-bytes-total 1048576 --max-output-bytes-total 1048576 \
  --max-session-input-bytes 65536 --commands-per-second 5
```

Default byte budgets are 1 MiB global input, 1 MiB global output and 64 KiB input per session; the default rate is 10 commands/chunks per second. These are application budgets, not physical traffic meters. Reserved output remains counted even if socket delivery fails. CPU/memory restrictions require external container/runtime enforcement; network floods, billed ingress and cloud-spending ceilings require independent infrastructure controls. Closing the decoy does not stop cloud billing by itself.

Generate an **operating summary from one explicitly selected preserved audit**:

```sh
reverse-shell-decoy operations --audit preserved-service-audit.jsonl
python3 scripts/operations-summary.py --audit preserved-service-audit.jsonl --json
```

The local command reports validated supplied budget snapshots, available UTC timestamps, source hashes, hash-referenced sessions, coverage gaps and low-confidence activity flags: `connection_only`, `probe_like`, `burst_pattern`, `multi_command_pattern` and `execution_related_text`. These are overlapping patterns, not reliable classifications of scanners, humans or exploitation. It excludes peer addresses and raw commands; every imported record remains unverified. It performs no network action, host scan or remediation.

Customers may save the resulting JSON privately and deliberately import it into the browser portal as provider `local`. The live **Manual workflow** explains this process; the browser does not execute the local command, re-run its classifier, accept raw JSONL as a report or deploy a honeypot. Portal summaries still require fresh permission.

**Opt in manually:** choose your isolated environment, explicitly start the loopback service, preserve the audit privately, and generate your selected report. Non-loopback binding additionally requires `--allow-public` plus your own reviewed ingress/egress configuration. Login or a positive scan never enables exposure. The [customer opt-in instructions](docs/resource-economics.md#customer-opt-in-run-it-manually-on-your-infrastructure) cover private no-overwrite logging and separately approved manual containment. The customer—not the portal—makes those operational choices.

See [resource budgets and operating-report details](docs/resource-economics.md). Adaptive firewall enforcement, automatic DNS sinkholing, monitored canary credentials and guaranteed attacker-cost estimates are **not** implemented. DNS proposals remain separate, ownership-confirmed and review-only.

### Defensive compute boundary

The optional [rationed echo policy](docs/resource-boundary.md) defines 0.25 CPU quota, 256 MiB memory, no swap, 32 tasks and explicit-device I/O limits. It is an availability/cost-control boundary on the **customer's own workload**, not a way to consume remote resources. No GPU workload or timeslice is granted. Quotas do not eliminate CPU/GPU side channels or replace a hypervisor, device policy, egress controls or an external stop authority.

```sh
# Policy review only: no cgroup changes, GPU access or listener launch.
python3 scripts/rationed-echo.py --review --consent
```

Kernel readback, fresh scoped permission and a separately trusted GPU-deny-policy check are required before the low-level apply path can launch the fixed echo. The standalone CLI has no such device-policy integration and therefore fails closed on apply; it never silently drops a missing limit. Counter deltas describe throttling/pressure, not mining, cracking, inference, exfiltration or malicious intent. Missing/reset telemetry remains unknown. A customer baseline can support an investigation, not replace independent evidence or automatically expand a session's resources.

### Emergency-only manual profile

`sh scripts/emergency-tarpit.sh --port 8023` starts a **new**, loopback-only silent sink with fixed 30-second service lifetime, one concurrent session, two lifetime connection attempts, five-second sessions, two-second idle timeout and small byte/rate/audit budgets. Only bind/port and explicit `--allow-public` exposure are configurable. It emits no application output, executes no visitor input and provides no OCR/counter-tool interference payload. Nothing launches it automatically, takes over an existing socket or repairs failed host containment. If the real host is compromised, isolate it through a trusted external control plane and preserve independent evidence instead of trusting a decoy. See the [emergency profile and private audit instructions](docs/emergency.md).

## Optional BYOK and integration trust

**No cloud-provider key is required for the core tools, offline provider analysis or manual imports.** Customer-supplied credentials are an optional, manually invoked **local** collection path—not a hosted key vault, a shared developer-key pool or automatic cloud authorization. The keyless portal remains usable when an integration is absent or unavailable. Without a key, you may still analyze a native export with the same offline rules; what changes is the available evidence, not an assurance of complete cloud visibility.

| State | Meaning and boundary |
| --- | --- |
| **Core-only mode** | The hosted portal uses no provider keys. Profiles are metadata only; manual imports remain available. |
| **Customer-authorized integration** | A successful explicitly invoked local read-only collector reports a bounded response at a stated time. It is not proof of lawful authority, full coverage, ongoing access or independently audited key permissions. |
| **Integration unavailable** | Collection could not establish usable visibility. Missing credentials/dependencies, permission, network or provider failures do not mean clean accounts; no broader scan or shared-key fallback occurs. |
| **Credential expired/revoked** | A fixed explicit provider credential-failure signal supports this local status. Generic HTTP authentication failures do not by themselves prove expiry/revocation; the cause remains unknown. |

The browser displays supported status declarations from selected imports as **unverified**, alongside their claimed check time and the preserved sanitized-representation hash. It does not check the key, poll the provider, accept a report as authorization or mark a bookmark as connected. Expiry/revocation is not inferred from missing logs. Customers revoke or rotate credentials in provider-native tools and rerun a local collection only when they choose.

Issue least-privilege read-only credentials yourself and pass them only to the local process as described in the [integration trust guide](docs/integration-trust.md). The collectors use fixed provider endpoints and read-only request shapes; they cannot down-scope an overprivileged key. Keys are not persisted by the collector, but environment values remain in the customer's process until cleared. Do not put credentials in command arguments, shell history, browser inputs, reports or Git. Error diagnostics omit provider bodies; output redaction is a best-effort defense, not permission to include secrets in evidence.

Public CI and opt-in pre-commit secret checks are documented in [secret scanning](docs/secret-scanning.md). A passing scan reduces risk; it does not prove that every historic or future secret is absent. If exposed, revoke/rotate first and review retained copies—do not assume deleting a file revokes the key. Reduced credential custody is not legal immunity.

## Engineering requirements

Every subsystem must be independently testable. Every inference must preserve its evidence trail. Every integration must declare its trust boundary and failure behavior. **Modular independence is a security feature**: local collectors, decoys, scanners, reports and the customer portal do not need to execute or authorize one another. See the [engineering rules and subsystem contracts](docs/engineering-rules.md) for concrete tests, evidence rules and the threat-review checklist.

The [implementation lessons and final handoff](docs/lessons-learned.md) summarize what was learned, what the release checks establish, what remains unproven and which operational choices stay with the customer.

## Optional behavior training and customer explanation

The [Security Behavior Trainer + Customer Incident Explainer](docs/security-behavior.md) is **user-triggered and off by default**. Every run asks fresh permission before processing, or requires the operator's explicit `--consent` for that invocation. Training uses trusted synthetic fixtures and a versioned review-only policy contract—not model-weight training, automatic adoption or production rule rewriting.

```sh
python3 scripts/security-behavior.py train --consent --output behavior-training-review
python3 scripts/security-behavior.py explain --audit preserved-service-audit.jsonl \
  --consent --output customer-review-packet
```

The first command compares expected/actual behavior across synthetic regressions and exports a contract another trusted script can review. The second creates private technical feedback and a plain-English customer report from **one shared immutable in-process audit snapshot**, with source/line/artifact hashes and explicit uncertainty. It explains recorded events, inferred patterns and why no automatic containment was authorized. It never treats logs as commands or approval, invents missing evidence, describes synthetic privileges as a real compromise or sends a report automatically. Existing output directories are never overwritten.

### Customer evidence and descriptive writing-pattern report

The [customer forensic-style report](docs/customer-forensic-report.md) combines explicitly selected audit/lab evidence with aggregate characteristics of selected UTF-8 text and an optional separate baseline. It records exact source hashes, UTC generation time, a unique packet ID and a separately preserved manifest pin. Writing metrics cover vocabulary distribution, punctuation, sentence/paragraph proxies and repetition; they are not authorship identification, psychological profiling or proof of access/intent. Imported resource and lab statuses remain unverified, and missing resource enforcement is unknown.

```sh
python3 scripts/customer-forensic-report.py --text selected-content.txt \
  --audit selected-audit.jsonl --lab-report selected-local-result.json \
  --output-dir new-private-customer-packet --consent
```

At least one selected input is required; existing output is never overwritten. PDFs require customer-reviewed text extraction first: this script does not claim OCR. It never executes supplied prose, trains production policy, starts a service or authorizes a VM.

The separately opted-in [software-only functional lab](docs/software-vm-lab.md) uses distribution QEMU/firmware/swtpm and original trusted fixtures, not uploaded samples. Physical TPM hardware is not needed for software TPM checks. Offline qcow2 snapshots and virtual firmware tests are not equivalent to a complete OS boot, live checkpoint, attestation or hardware-isolation audit; missing firmware observations produce an explicit partial result, never deployment approval.

### Test adversarial boundaries and verify a packet

```sh
python3 scripts/adversarial-assurance.py --consent
python3 scripts/verify-evidence.py --consent --packet customer-review-packet \
  --expected-manifest-sha256 TRUSTED_64_CHARACTER_MANIFEST_SHA256
```

The exporter prints the manifest digest for preservation **outside the packet** through a trusted channel. Verification rejects tampered/mismatched artifacts or missing session/time metadata; it confirms packet consistency, **not initial source authenticity**. Optional file-I/O paths use fresh revocable, exact-scope, single-run grants. A failed integrity/permission check stops the operation instead of automatically executing, provisioning or exporting further data. See [adversarial assurance and measured limits](docs/adversarial-assurance.md): 291 local tests and 83 focused checks passed, including 8,192 Boolean policy configurations with no enforcement authority. This is regression evidence, not a proof against every trick, malicious dependency or compromised host.

The [three-layer fallback instructions](docs/fallback-layers.md) describe **bounded echo on each customer-controlled layer**: primary VM, separately hardened PC-Free Windows backup and isolated emergency echo. The real VM/backup/floating-proxy controller is not implemented. PC-Free's published defaults are not automatically trusted or installed; it remains an unverified backup candidate until independently hardened and validated. Detection or uploaded “verified” flags cannot grant permission to provision it.

### Merged manual VM and backup hardening

The [candidate generator/reviewer](docs/vm-backup-hardening.md) now supports **both** conservative QEMU/KVM/libvirt XML and an offline PC-Free-derived Compose JSON profile. It admits only exact bounded grammars plus an externally supplied document pin. No NIC/public management ports, host sharing, arbitrary boot hooks, guest USB/console access, restart loop or imported authorization is added. Static acceptance always leaves `ready_for_deployment: false`; hardware isolation, image provenance, runtime limits and routing require separate validation.

```sh
# Build review text only; no VM, provider resource or firmware is started.
python3 scripts/review-backup.py --backend libvirt --emit-candidate --consent

# Run inside a separately approved isolated guest; both ports are inward-only.
sh scripts/backup-echo.sh --consent

# Test each implemented layer, including deliberate failures of the smoke harness.
python3 scripts/smoke-backup-layers.py --consent
```

The [shared guest workload](docs/backup-echo.md) opens two independent bounded echo surfaces (loopback ports 8022/8023 by default). Each connection receives **only its own bytes**, with no cross-port forwarding, outgoing callback, real interpreter execution or privileged operator shell. Permission loss, startup failure or a stop in one surface closes the pair. Exposure beyond loopback needs separate explicit opt-in and independently reviewed ingress; a disconnected guest has no remote visitor path by itself.

The requested [Openterface KVM-GO hardware](docs/openterface-console.md) belongs only to a dedicated administrator's physical console, never the visitor echo/control plane. Its USB keyboard/video/mouse role is not the Linux KVM hypervisor. The requested [VMBoot project](docs/vmboot-boundary.md) contributes a firmware-research concept, not an automatically enabled boot/flashing workflow. This implementation repurposes the manual isolation/admission ideas without copying privileged firmware execution into customer data paths. Real VM boots, VMBoot firmware and KVM-GO hardware were **not tested or deployed** in this sandbox.

The [15-section defensive lab assessment](docs/backup-lab-assessment.md) records the observed inventory, methodology, architecture, boot/isolation/network/monitoring gaps, risk-scoring limitations and next validation steps. The merged local suite passed **323 tests**, and five software smoke layers plus 14 harness controls passed. These results establish only the tested finite software behavior. No guest boot, Secure Boot/TPM, real snapshot recovery, EDR, external ingress or hardware safety verdict is implied; deployment remains blocked until those prerequisites are independently verified.

The separate optional `scripts/analyze-safely.py` provides static inspection and an explicitly synthetic virtual computer. It does not execute real samples. A real-VM requirement fails closed rather than silently running malware on the customer's device or treating a container/synthetic console as a VM. See the [virtual-analysis boundaries](docs/virtual-analysis.md); real disposable-VM provisioning, guest telemetry and VM-escape validation are not implemented or claimed.

The [optional corpus runner](docs/prompt-injection-corpus.md) can test a customer-authorized local JSONL export or the repository's **original synthetic examples** against an ephemeral, finite loopback-only mirror. It requires fresh consent, retains hashes rather than raw prompts and offers no external target selection. The linked third-party database remains access-gated; this project did not scrape it, redistribute its full dataset, install code on its website or submit a contribution. Exact echo is not proof of LLM injection detection or jailbreak resistance.

**Observation and fingerprinting, not attribution:** the bounded inbound service records limited connection metadata, input/chunk hashes, available timestamps and fixed activity indicators. These are content/activity fingerprints, not a person's identity or a proven attack. MIRROR returns bytes on the visitor-initiated socket; it does not establish a real shell or call a controller. It does **not detect the visitor's OS**. The scanner's OS information belongs to the computer running the scanner; the virtual console's OS is synthetic. A visitor OS remains unknown unless independently supported evidence is supplied and clearly labelled. Observation is not blanket legal immunity: customers still control authorized deployment, collection scope, retention and disclosure.

### Create an analysis VM manually — optional

Use a **separate, patched analysis host**, not the customer's everyday workstation, production server or CloudSentry portal. On an Ubuntu host with hardware virtualization, explicitly approve and run:

```sh
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager virt-viewer cpu-checker
kvm-ok
```

1. Open `virt-manager` on that analysis host; create `cloudsentry-analysis` from a verified official Linux ISO. Choose **Customize configuration before install**, with a new qcow2 disk, for example 2 vCPUs, 2 GiB guest RAM and a 20 GiB virtual disk. These are example allocations, not a complete cost/resource cap.
2. **Remove every guest NIC** before boot; no NAT, bridge or host-only connection. Add no shared host folders, host disks, passthrough devices or sockets. Disable clipboard, file transfer, USB redirection and guest-agent/SPICE channels; keep the management console restricted to the trusted administrator.
3. Use unrelated lab-only credentials and an offline installation. Deliver reviewed tools/benign fixtures through read-only media—not shared directories. Keep customer keys, browser sessions and hypervisor-control privileges outside the guest.
4. Review the effective XML and confirm `virsh --connect qemu:///system domiflist cloudsentry-analysis` shows no NIC. Shut down the clean guest, then create a supported baseline with `virsh --connect qemu:///system snapshot-create-as cloudsentry-analysis clean-baseline`. Preserve evidence separately before any future rollback.
5. Boot the reviewed VM manually and run the existing static/synthetic options **inside it**, with fresh permission. No login, scan or detected pattern starts it automatically. Real interpreter execution of submitted samples remains disabled.
6. After preserving evidence, shut down and deliberately revert to the powered-off baseline, or retire the guest through your reviewed process. If isolation is suspect, use a trusted external control plane to stop/escalate; do not treat a guest snapshot as proof that the host is clean.

See the [full VM creation, verification and rollback instructions](docs/vm-setup.md). **Creating this guest does not enable `--require-vm`**: the verified remote-VM adapter, independent deadline/controller, dynamic malware telemetry and VM-escape validation are not implemented. A container or synthetic computer is not a VM, and no VM guarantees absolute device protection. These instructions were documentation-checked, not executed on customer hardware.

## Consent-gated review and text indicators

After an explicitly requested scan, the CLI offers a local review by default in an interactive terminal. It asks fresh permission each time and generates nothing when permission is declined, stdin is non-interactive, or input ends. The prompt and optional review use stderr so the original scan JSON remains clean on stdout. No scan is triggered automatically. See the [post-scan review guide](docs/post-scan-review.md).

```sh
python3 scripts/review-scan.py --scan saved-scan.json --command audit \
  --audit preserved-service-audit.jsonl
python3 scripts/trail.py --audit preserved-service-audit.jsonl
```

The standalone review also asks permission before reading the selected files. Its observed-tooling section is unknown without relevant audit observations; defensive indicators are not proven vulnerabilities, and synthetic actions do not establish unauthorized real-host access. Both scripts perform no network action or submission to law enforcement.

The virtual terminal defaults to a PHP metadata catalog: `php -v`, `php -m` and `which` return canned values. No PHP interpreter is installed or run by this feature; script execution and other interpreter attempts remain blocked. The [text-indicator trail](docs/trail.md) retains only bounded, fixed language/token labels, source context and hashes—not raw one-liners, skill scores or allegations. Mirror mode remains an opaque, bounded byte reflector and does not present or interpret this catalog.

## Customer control, content patterns and adversarial-activity summaries

**The customer is the operator, not the profiling target.** Analysis concerns supplied content and observed or suspected adversarial activity, not a general-purpose profile of the customer or everyone mentioned in a file.

| Role | Meaning |
| --- | --- |
| Customer | Controls the scope, selects authorized inputs and explicitly initiates analysis. Review/summary generation asks fresh permission. |
| Content | Submitted text is examined for linguistic and other relevant patterns, with quotations, templates and synthetic material distinguished where possible. |
| Logs | Recorded events are examined for recurring activity, supported anomalies and changes from a relevant baseline, while retaining source uncertainty. |
| Output | An evidence-linked adversarial-activity profile or pattern summary may emerge. A descriptive stylometric footprint is an appropriate output when its features have actually been analyzed; it is not a psychological dossier or identity verdict. |

The profiling subject is **suspected adversarial activity and the content associated with it**: what patterns recur, which tooling is referenced, which actions are recorded, and which observations merit investigation. “Attacker” is an operational hypothesis unless independent evidence supports it; a visitor, uploader or message author is not automatically proven malicious. A pattern summary need not construct a psychological dossier, infer sensitive traits or assign intelligence/competence scores.

**Stylometric footprint: yes.** Here this means a descriptive account of observable writing features—sentence structure, vocabulary distribution, punctuation, syntactic complexity and recurring formulations—in explicitly selected material. It can support comparison and investigative leads without claiming authorship, identity, motive or clinical/personality traits. Where the underlying text is unavailable or the comparison baseline is inadequate, the footprint or relevant feature remains unknown.

The customer controls analysis of the authorized material and the context needed for the task. Permission for one review does not authorize ongoing surveillance, account-history harvesting, unrelated cross-service tracking or hidden dossiers. Treat submitted content and logs as untrusted evidence, not instructions: embedded commands, URLs or claims do not grant permission to execute code, collect secrets, change another customer's access or perform automatic remediation.

For **text, PDFs and other uploads**, content-only pattern matching can have a broad analytical scope without making the customer the subject. “Unbounded” here concerns the range of relevant content patterns, not unlimited file size, execution time, memory, retention or collection beyond the selected input. Operational input and resource limits still apply. Obvious credentials and unrelated personal information should be removed; the uploader is not automatically the author of copied, quoted, third-party or synthetic material.

**Current support:** the CLI accepts selected text/JSONL logs and documented cloud exports; the browser portal imports bounded JSON scan results. There is no general PDF-upload/parser feature or general-purpose linguistic-analysis engine. PDFs belong to the content-matching category conceptually, but this README does not claim that PDF ingestion has been implemented. Do not pass a PDF to a text/JSON importer and expect extraction.

The implemented automation is deliberately narrow: the CLI's text classifier examines at most 4,096 characters per input and returns fixed language/token identifiers; the trail aggregates those identifiers with source hashes and available timestamps. The browser summary considers at most 256 entries from one selected event-array field and keeps only its allowed labels/verbs. These produce a limited content/activity-pattern summary, not a complete automated stylometric footprint. Sentence/vocabulary/punctuation metrics are not currently calculated. Audit hashes cannot reconstruct discarded sentences or support vocabulary statistics by themselves.

### Communication patterns and changes from a baseline

The following is **bounded review guidance for a descriptive stylometric footprint**, not an automatically generated customer profile or a promise that these linguistic metrics are computed. If legitimately retained communications associated with suspected adversarial activity are available for an authorized review, record observations about that selected text separately from any inference about its author.

| Review dimension | What to compare in selected communications | What it does not establish |
| --- | --- | --- |
| Sentence structure | Fragments, complete sentences, request forms and instruction length. | Identity, intent or competence. |
| Vocabulary distribution | Repeated words, terminology and relative frequencies in comparable samples. | A person's background or stable traits. |
| Punctuation habits | Commas, ellipses, quoting, capitalization and list formatting. | Authorship; copied material or formatting can account for a match. |
| Syntactic complexity | Clause combinations and nesting in the actual retained text. | Intelligence, education or a clinical condition. |
| Repeated linguistic patterns | Recurring phrases, formulations or templates, with quotations kept separate. | That repeated text comes from one person. |
| Behavioral inference | Observable requests or actions in their stated context, labelled as observations or hypotheses. | Motive, maliciousness or authorization status. |

Ask whether there are meaningful changes in communication patterns only when the baseline and comparison material are sufficiently comparable. Document the source, available event times, language, channel, task and sample limitations. If authorship, context or the baseline is unknown, report **unknown** rather than manufacturing a personal baseline.

Review may note **changes in terminology, unusual requests, changes in writing consistency, repeated behavioral patterns and deviations from an established baseline**. Describe the difference and retain alternative explanations: a new task, quoting, templates, translation, editing, assisted writing or a different contributor. A style change or unusual request is a lead for contextual review, not an automatic compromise verdict. The current tool does not calculate statistical significance or automatically decide whether such a change is meaningful.

### Correlate independent evidence without collapsing it into proof

Keep customer assertions, unverified imported text, local host observations, independently obtained authentication/network/cloud records and synthetic decoy effects in separate provenance categories. Correlate available timestamps and relevant identifiers while preserving clock uncertainty, missing coverage and disagreements. An account or endpoint reference does not by itself identify a person.

Distinguish a genuinely independent source from a second copy, export or summary of the same underlying event. Do not count duplicated evidence as corroboration. A shared word, token, hash or timestamp can connect review items but does not turn a text pattern into proof of execution, or a simulated root prompt into proof of unauthorized real-host access. A hash documents representation consistency; it does not authenticate an author or establish authorization.

For example, a supplied message containing a network-function name is a **text-pattern observation**; a local socket snapshot is a **host observation**; a preserved sign-in event from another source is a **separate authentication record**. Their time and context may justify further investigation. None automatically proves the meaning or attribution of the others. State what each source supports, what it does not support, competing explanations, and what further independent evidence would be needed. Preserve original evidence separately; do not convert these review leads into legal allegations or automatic account/remediation decisions.

## Install

Python 3.10+ is required. The core runtime uses only the Python standard library; optional manual AWS API collection needs the AWS SDK described in the collector guide. Host process/socket/persistence inspection targets Linux; OS context, log parsing, name checks and virtual terminal personas are separate from native Windows endpoint scanning.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --no-deps .
reverse-shell-decoy --help
```

For a source checkout without installation:

```sh
export PYTHONPATH="$PWD/src"
python3 -m reverse_shell_decoy --help
```

Run only on systems and logs you are authorized to inspect. Do not run as root just to start the decoy. Restricted visibility is reported rather than bypassed.

## Bounded mirror and investigator workflows

The additional [MIRROR mode](docs/mirror.md) reflects received data only through the same accepted inbound socket. It does not execute bytes, dial a peer, loop commands on another computer or capture raw credentials to disk. Start it locally with `bash scripts/mirror.sh`. The default console mode still presents a synthetic computer; `bash scripts/tarpit.sh` is a bounded silent sink.

The [defensive state loop](docs/shellception.md) preserves snapshot/change/virtual-mutation logic without altering real history, SSH, cron or shell startup. Its explicit `--state-output` writes only a private, current synthetic-state artifact. It does not reconstruct historical state from hashes.

```sh
python3 scripts/export-for-investigator.py --audit preserved-service-audit.jsonl \
  --state synthetic-state.json --output investigator-review.zip
```

The [investigator exporter](docs/investigator-export.md) preserves source digests and separates logged interactions, synthetic state/effects, operator assertions and unknown facts. It creates a private review ZIP and readable Markdown sidecar, not an allegation or proof of unauthorized real-host access. Original authentication/network/cloud logs and authorization records remain independent corroboration. No evidence is uploaded or sent to an investigator automatically.

## Paste real logs

```sh
reverse-shell-decoy ingest --paste --format text
```

Paste the log lines, then type `ENDLOG` on a line by itself. JSON Lines input is also supported:

```sh
reverse-shell-decoy ingest --paste --format jsonl
```

An individual JSON object per line is supported, not a whole JSON array. This is local stdin input, not a web upload. Text is never evaluated or treated as a shell command. Remove credentials, tokens and unrelated personal information before pasting: automated redaction is conservative and cannot guarantee removal of every secret.

To import a file or combine pasted logs with an actual host audit:

```sh
reverse-shell-decoy ingest --logs /path/to/authorized.log --format text
reverse-shell-decoy audit --paste --format jsonl
```

Imported content is marked as real-log input, but its source is **unverified**. Hashes describe the selected file or pasted representation; pasted data is not a byte-for-byte acquisition of the original logfile. Event timestamps are preserved when present and are not replaced with import time. The tool does not establish that a log is truthful or that a remote address belongs to an attacker.

## Inspect this computer

```sh
reverse-shell-decoy os
reverse-shell-decoy scan
reverse-shell-decoy listeners
reverse-shell-decoy persistence
reverse-shell-decoy audit
```

`os` reports limited real OS and architecture fields for the computer running the tool, without hostname or username. These details do not identify the OS of a remote peer or of a separate machine that produced pasted logs.

`scan` correlates established non-loopback TCP sockets with owning shell processes or shell ancestors. Direct shell ownership is a stronger heuristic than an application launched from a terminal; legitimate activity can still match. A snapshot cannot prove whether a connection was initiated outward, whether it is malicious, or whether the host is compromised.

`listeners` inventories TCP LISTEN sockets and UDP bound endpoints, with visible PID/process ownership and loopback/wildcard/interface exposure. A bound UDP endpoint is not proof of an application actively accepting requests. An exposed listener is not automatically a backdoor. No port probes or remote connections are made.

`persistence` inspects bounded, regular configuration files in `/etc/cron.d` and `/etc/systemd/system`, without following symlinks. It reports narrow startup-command indicators such as execution from temporary directories and risky remote-shell/download-execution patterns, using line hashes rather than full command content. It is not a full service/package inventory, authentication audit, web-shell detector, scheduled-task audit for Windows, antivirus engine, or rootkit scanner. Compare results against approved configurations.

Additional authorized directories can be explicitly inspected:

```sh
reverse-shell-decoy persistence --root /path/to/startup-configs
```

## Check typosquatting indicators offline

Put one domain or package name per line in each input. The trusted file is **your** baseline, not an automatically curated reputation list.

```sh
reverse-shell-decoy names --observed observed-domains.txt --trusted trusted-domains.txt --kind domain
reverse-shell-decoy names --observed observed-packages.txt --trusted trusted-packages.txt --kind package
reverse-shell-decoy audit --observed-names observed-domains.txt --trusted-names trusted-domains.txt
```

Checks cover spelling proximity, adjacent transpositions, selected Unicode/lookalike behavior and deceptive domain boundaries. Exact trusted entries and ordinary trusted subdomains are handled separately. Similarity is an investigative lead, not proof of impersonation. This tool does not query DNS, certificates, registries, domain age, redirect chains, package contents or live threat intelligence. It does not install any observed package.

## Present simulated privileged access

```sh
reverse-shell-decoy simulate --presentation realistic --audit session.jsonl
reverse-shell-decoy simulate --persona windows --presentation realistic --audit windows-session.jsonl
```

For a separately launched inbound service, use `sh scripts/start-honeypot.sh` rather than carrying cloud credential environment variables into the service. It starts on loopback by default and stops at its configured runtime/quotas; see [service boundaries](docs/service.md).

The terminal-facing stream uses a neutral maintenance banner instead of announcing a honeypot. A separate operator notice explains the simulation. Use `--presentation transparent` for a visibly labeled teaching session. Both modes retain `simulation: true` in every audit event.

Commands such as `whoami`, `id`, `uname`, `ls`, `cat`, `ps`, and `ss` return synthetic state. `touch`, `mkdir`, and `rm` mutate only bounded in-memory dictionaries. Unknown programs, scripts, shell operators, pipes and redirection are blocked. Neither persona executes Linux or Windows commands. There are no network connections, real persistence, privilege escalation, backdoors, or real agency records.

For a reproducible local continuation demo:

```sh
sh examples/continue-demo.sh < examples/decoy-commands.txt
```

Audit files are created exclusively rather than overwritten. They record UTC timestamps, known command verbs, blocked decisions, presentation/persona, and command/output SHA-256 hashes. They do not retain raw commands or arguments. Hashes alone cannot recover an unknown command or prove the identity of the person who entered it. See [service deployment boundaries](docs/service.md) for the separate optional inbound service and its operator-only connection telemetry.

## Export evidence for an investigator

```sh
reverse-shell-decoy evidence --paste --format text --audit session.jsonl --output case-bundle.zip
reverse-shell-decoy verify case-bundle.zip
```

The ZIP contains `host_os.json`, `detection.json`, `simulation_audit.json`, a blank custody worksheet, an explanatory README, and a SHA-256 manifest. `detection.json` separately names local host observations, selected imported logs, and optional offline name checks. Decoy activity remains in its own explicitly synthetic file.

Review all contents before giving a bundle to law enforcement or another investigator. Endpoints, process metadata, paths, and imported messages may be sensitive. Keep the original logs separately and follow the receiving organization's evidence-handling procedures. Hash consistency is not a digital signature, provenance attestation, completed chain of custody, or a guarantee of legal admissibility. The program never sends the bundle anywhere.

Runtime logs, evidence ZIPs, secrets and environment files are ignored by Git. Do not bypass the ignore rules or commit real evidence. Shell redirection such as `> report.json` uses your shell's normal file permissions; use a private working directory and restrictive umask when saving sensitive reports.

## Synthetic state experiments

```sh
reverse-shell-decoy experiment baseline
reverse-shell-decoy experiment process-limit
reverse-shell-decoy experiment network-loss --seed 42
reverse-shell-decoy experiment telemetry-gap
```

These run 30 virtual steps and compare an authoritative in-memory observer with a synthetic degraded sensor. They do not consume target resources, send packets, suppress actual telemetry, test an EDR, change OS process limits, or run metered APIs. There is no flooding, remote retaliation, denial-of-wallet mechanism or hidden monitoring interference.

## Optional container isolation for the decoy

```sh
docker build -t reverse-shell-decoy .
docker run --rm -i --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges=true --pids-limit 32 \
  --memory 128m --memory-swap 128m --cpus 0.5 \
  reverse-shell-decoy simulate --presentation realistic
```

The image runs as UID 10001, not root. Do not add host volumes, the Docker socket, privileged mode, host networking, host PID namespaces or published ports. Building the image may download its base image; the example runtime has no network. Runtime limits affect only this disposable container, not a remote system. A scanner inside it sees the container's namespace, not the actual host. The configuration is defense in depth, not a sandbox for executing hostile programs. Docker execution is not required for the CLI.

## Tests and limitations

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests use synthetic proc/config/log fixtures and hostile input strings. CI is configured for Python 3.10, 3.12 and 3.13 on Linux; see [testing notes](docs/testing.md) for what was actually executed locally. See [security policy](SECURITY.md), [trust boundaries](docs/threat-model.md), and [implementation references](docs/references.md).

MIT licensed. A triage tool can miss short-lived activity, hidden processes, namespace-isolated sockets, encrypted application behavior and persistence outside its configured roots. Neither a positive indicator nor an empty report is a definitive compromise verdict.
