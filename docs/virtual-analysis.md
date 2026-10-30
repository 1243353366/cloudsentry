# Virtual analysis is synthetic only

`reverse_shell_decoy.virtual_analysis.VirtualAnalysisComputer` is a bounded, dictionary-backed [`DecoySession`](../src/reverse_shell_decoy/simulator.py). It presents the existing **transparent** synthetic persona for authorized training and safe analysis demonstrations. It is not a virtual machine, hypervisor, container, sandbox escape detector, remote host, malware lab, network listener, or command-execution service.

## Explicit use and fresh permission

Nothing launches this component at scan, login, observer finding, import, or service startup. A parent wrapper may call `main(argv)`, but only after an operator has explicitly chosen that action.

The module CLI accepts a selected regular UTF-8 text file only through `--sample`. Every invocation requires fresh permission **before** reading or processing that file:

```sh
python -m reverse_shell_decoy.virtual_analysis --sample selected.txt
```

On an interactive terminal it asks on stderr, `Permission to read and process the selected sample? [y/N]`. Only `y` proceeds. Decline, EOF, an input error, and a non-interactive invocation without permission fail closed without opening the selected file. Automation must supply the per-invocation, non-interactive acknowledgement explicitly:

```sh
python -m reverse_shell_decoy.virtual_analysis --consent --sample selected.txt
```

The default is **static inspection**: it returns only `language_indicator`, fixed `token_indicators`, status, and a raw-byte `source_sha256`. It does not create a decoy state or process the text as a command. `--simulate` is an additional explicit choice to submit the selected text to a new in-memory synthetic session:

```sh
python -m reverse_shell_decoy.virtual_analysis --consent --simulate --sample selected.txt
```

The one JSON result never includes the selected pathname, source text, command output, virtual path names, file names, or file contents. Errors are generic JSON as well. `--sample` is bounded to 4096 bytes and guarded by `read_regular`, which refuses non-regular files and symlinks.

## No VM fallback

`require_remote_vm_backend()` always raises `IsolationUnavailableError` with the fixed message that the remote VM backend is not configured. `--require-vm` calls that gate before a prompt, file read, or analysis and fails closed. It never falls back to `subprocess`, a local interpreter, Docker, a container, KVM, Firecracker, cloud provisioning, or any provider action.

This repository currently has no remote-VM controller, VM authority, provider integration, or external control plane configured for this capability. Consequently it does **not** create or destroy real VMs; configure an outbound firewall; attach a host mount; allocate CPU, memory, or disk; enforce a hypervisor boundary; collect guest telemetry, PCAPs, syscall traces, or malware-research artifacts; or make any network connection. Real malware execution must remain disabled unless an independently provisioned and verified remote VM controller and its external containment controls are authorized separately.

## Synthetic submission contract

`VirtualAnalysisComputer.submit(text: str) -> dict` accepts at most 4096 characters. It returns hash- and label-only data including:

- `simulation: true`, `real_vm: false`, and status `simulated`, `blocked`, or `closed`;
- `input_sha256` (or `null` when the input limit is rejected before full hashing);
- `synthetic_output_sha256` and no output body;
- `virtual_state_sha256`, plus before/after state hashes;
- `virtual_files_added` and `virtual_files_removed` counts only; and
- fixed language/token labels and `host_execution`, `network_access`, and `credential_access`, all false.

The 16-request and 65,536-byte virtual-input budgets are application limits, not host resource isolation. Requests for a real interpreter, host paths such as `/proc`, `/sys`, or `/dev`, host mounts, callbacks, or isolation-disabling capabilities are denied without dispatch. They do not obtain host or credential access. Input is untrusted data; text markers only select a fixed synthetic denial or fixed labels and never authorize an action.

`audit_events` returns a deep-copied, bounded tuple of JSONL-friendly records. Command records retain hashes, fixed labels, fixed reasons, and state fingerprints only. They use `source_kind: "in_memory_decoy"`, `interaction_observed: false`, `synthetic_not_connection: true`, `network_visitor: "none"`, and `remote_os: "none"`; no `connecting` or `virtual_start` event is emitted because generating synthetic state is not a real visitor connection.

## Safe equivalents for requested VM features

A state fingerprint is a canonical hash of the synthetic dictionaries, not a disk snapshot. Each submission supplies before/after fingerprints and file-count deltas, never names or contents. `state_fingerprint` exposes the current synthetic fingerprint. `destroy()` clears only the object's synthetic dictionaries, emits a safe in-memory close record, and permanently closes that instance. `reset()` first fail-closes the current instance and returns a separate, known-clean `VirtualAnalysisComputer`; it is not guest rollback.

There is no guest-failure replay. Repeating a submission creates a new bounded synthetic request and audit record; it does not replay a process, packet stream, syscall, sample, or VM snapshot. The stable source hash and deterministic synthetic-state fingerprints are the safe equivalents for comparing selected samples and virtual-state changes.

These capability denials reduce accidental local execution in this component. They are not proof of absolute escape prevention: a trusted Python caller that can modify loaded code remains outside this component's boundary.
