# Investigator-review export

`reverse_shell_decoy.investigator` turns explicitly selected **synthetic** decoy JSONL records into a new private ZIP packet for investigator review. It is a local formatter: it does not scan a host, open a network connection, access a cloud account, execute commands, or identify a person.

The parent wrapper invokes the module's `main` function with this shape:

```sh
python scripts/export-for-investigator.py \
  --audit selected-service.jsonl \
  --audit selected-terminal.jsonl \
  --state selected-virtual-state.json \
  --output investigator-packet.zip \
  --case-label "operator reference only"
```

`--audit` is required and may be repeated up to four times. Each file must be an explicitly selected regular file, not a symlink or device, and is read through the bounded regular-file reader. Each audit file is limited to 2 MiB, and all nonblank JSONL records together are limited to 1,000. `--state` is optional and accepts only the bounded synthetic virtual-filesystem schema described below. The tool never auto-collects incident, cloud, authentication, or network logs.

The ZIP output is created only at a new path with private mode `0600`; a same-stem Markdown sidecar (for example, `investigator-packet.md`) is also created only at a new `0600` path. Existing files and symlinks are refused before either output is written. If the sidecar fails after the ZIP is made, the tool removes only the exact ZIP inode it created when that can be established safely.

## What the packet contains

The ZIP is written through the existing evidence exporter, so it has the standard six members and can be checked with `verify_bundle`:

- `detection.json` contains the investigator report, normalized timeline, source manifest, and optional synthetic virtual state.
- `simulation_audit.json` is intentionally empty for this packet. The selected inputs are represented only in the report's bounded, classified timeline.
- `host_os.json` is the existing exporter's limited OS context collected **at export time**. It is not incident-host evidence.
- `custody_template.md` remains a blank worksheet for a receiving organization.
- `README.md` and `manifest.json` explain and hash the packet members.

The sidecar is a human-readable summary only. It excludes raw audit input, raw commands, arguments, environment values, keys, and credential fields. Its dynamic values are escaped and truncated so selected input cannot create links or Markdown formatting.

## Audit acceptance and classification

Each nonblank JSONL line must be a JSON object that states `"simulation": true` and has a recognized `source_kind` or `source`:

- `decoy_service_interaction`
- `historical_in_memory_decoy` (the existing `in_memory_decoy` name is normalized to this form)
- `bounded_defensive_state_loop`

Invalid JSON, non-object lines, non-simulation lines, conflicting or unknown sources, and other unrecognized records are skipped and counted in the source manifest and report counts. They are never silently treated as authentic incident records.

Only a small primitive allowlist can enter a timeline entry: a valid UTC timestamp, event/session ID, event type, verb, blocked/reason/response metadata, selected SHA-256 values, mirror byte count and chunk SHA-256, mutation, a valid IP address, and scope. All other fields are dropped. In particular, raw commands, arguments, raw mirror payloads, environment fields, keys, credentials, and arbitrary unknown values are not copied.

A service record with `interaction_observed: true` is classified as `logged_interaction_unverified`. Its connection time and peer IP are values **recorded in the supplied log**, not independently verified. A peer IP is a network address, not a person; NAT, proxies, relays, reassignment, and logging error can affect attribution. A connection to a public decoy or honeypot does not, by itself, establish unauthorized access to a real host.

Non-service in-memory terminal data is classified as `local_operator_or_unknown_input`. A state-loop event is `purely_synthetic` unless it has `observation_is_real: true`, in which case it is `claimed_local_digest_observation_unverified`; virtual state effects remain synthetic in either case. Missing or invalid timestamps are counted as warnings and are not replaced with invented incident times. The timestamp range uses only valid supplied UTC timestamps.

## Optional synthetic virtual state

The optional state JSON must contain exactly the following core fields:

```json
{
  "schema_version": "1.0",
  "state_kind": "synthetic_virtual_filesystem",
  "simulation": true,
  "timestamp_utc": "2026-10-29T22:00:00Z",
  "virtual_privilege": "root/admin; synthetic only",
  "state_sha256": "<sha256>",
  "files": {"/virtual/example.txt": "inert synthetic text"},
  "directories": ["/", "/virtual"],
  "cwd": "/virtual"
}
```

The current local synthetic-state exporter may additionally include a bounded string `provenance_notice`. It is accepted solely for compatibility and is not copied into the report; the report supplies its own fixed synthetic provenance statement. No other additional state fields are accepted.

It is limited to 512 KiB of JSON, 128 combined file/directory objects, and 64 KiB of decoded virtual text. `state_sha256` must equal the SHA-256 of exactly this canonical JSON encoding:

```python
json.dumps(
    {"files": files, "directories": sorted(directories), "cwd": cwd},
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
```

The copied state is labeled as inert synthetic virtual filesystem data. Any fake credential values in it are retained only as synthetic text and are not real credentials, host files, or evidence of access.

## Boundaries and appropriate next steps

Every report carries these independent-claim statuses:

```json
{
  "real_host_unauthorized_access": "not_established",
  "visitor_identity": "unknown",
  "remote_os": "unknown",
  "authorization_status": "not_established"
}
```

The `--case-label` value is only an operator-supplied, unverified label; it does not assert that a real case exists. The report separates values observed in supplied logs, synthetic state/effects, the operator label, and unknowns. It is headed “Prepared for investigator review,” not “proof.”

SHA-256 values support integrity consistency for the bytes selected and the archive payloads. They do not authenticate a source, prove authorship, establish provenance, complete a chain of custody, or guarantee legal admissibility. For independent review, retain original authentication, cloud, and network logs in their native context; asset inventory and authorization policy; records from an external trusted collector; and ownership/access records. This tool does not provide jurisdiction-specific legal advice.
