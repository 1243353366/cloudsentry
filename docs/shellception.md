# Defensive shellception

This replacement preserves a finite **snapshot → detect change → mutate decoy → re-snapshot → verify → continue** loop. It does not preserve the counter-shell, remote beacon, listener-exhaustion, host persistence, watchdog, immutable-copy or polling-evasion behavior. Connecting back to a suspected attacker's port would expose or burden a remote endpoint; it is not containment.

## Run a virtual-only demonstration

```sh
bash scripts/shellception.sh --demo --iterations 12 --interval 0.5 --max-runtime 15
```

The launcher clears inherited environment variables before starting Python. There is no host/port argument and no network connection. Each demonstration change is an allowlisted virtual `touch`; it changes an in-memory dictionary, not `/tmp` or any real file.

The loop hashes stable virtual file/directory/cwd state. It excludes audit timestamps, live process listings and socket churn, which would otherwise produce routine changes. If state changes, it replaces one bounded synthetic marker representing history, cron, authorized keys, profile or loot. These paths exist only in the decoy dictionary and contain inert text, not real keys or commands. It re-anchors the baseline after its own mutation so the loop cannot repeatedly trigger on itself.

The guard checks virtual state schema/size bounds and stops on failure. The apparent root/admin persona is synthetic. There is no real shell, socket, reverse connection, credential extraction, listener probing or host-monitoring interference.

## Extract the synthetic state for review

Use `--state-output synthetic-state.json` to explicitly create a new private artifact of the current virtual filesystem. The JSON is marked synthetic and includes a reproducible state digest. Real watched-file content and paths are not included. The output is the current state, not a reconstruction of every earlier state or evidence that a real OS was accessed. See [investigator export](investigator-export.md) to combine it with original operator audit logs in a clearly labeled review packet.

## Optional read-only local files

```sh
bash scripts/shellception.sh --watch-file /path/to/authorized-config \
  --iterations 20 --interval 1 --max-runtime 30
```

Only explicitly selected files are read. There is no automatic traversal of `/etc`, home directories, root, SSH, history or cron. At most 16 regular files, 64 KiB each, are hashed per step. Symlinks, devices, FIFOs, oversize files and failed reads are rejected or reported as unavailable. The loop never edits a watched file; any response is confined to its separate virtual filesystem.

Do not watch credentials or unrelated personal files. Hashes can still expose information about low-entropy values; double hashing does not make them authentic or unguessable. Keep originals separately if evidence preservation is required. An availability or content change can be legitimate and is not proof of compromise.

## Hard boundaries

The CLI accepts 1–120 iterations, 0–5 seconds between checks, and a 1–60 second loop budget. The budget is checked between local reads; it is not an operating-system deadline for a stalled filesystem. Use an OS-supervised disposable environment for hard wall-clock enforcement. No restart, daemonization, cron registration, background persistence or jitter is installed.

The retained audit is capped at 256 events. Virtual object/byte limits come from the existing terminal model. Every successful step records observation scope, digests, the synthetic mutation name, guard result and limits—not real file contents or command arguments. `host_changed: false` and `outbound_connections: 0` describe this module's actions, not a forensic claim about every process on the host.

This is not a transparent reverse-shell redirect or proof that a visitor cannot escape an operating-system sandbox. The module simply supplies no shell-execution/network/file-write path for virtual commands. A real inbound service must use the separately reviewed [service isolation](service.md), with externally enforced egress denial and trusted logging. There is no "attacker eating its own listeners" feature or remote counterattack.
