# CloudSentry workflow

CloudSentry combines explicit manual collection, local analysis and an independently launched decoy. No cloud scan, credential lookup, service launch or containment action runs when the package is imported. There is no automatic operation on a positive heuristic.

## Launch only the honeypot

```sh
sh scripts/start-honeypot.sh --host 127.0.0.1 --port 8022 --max-runtime 600
```

The launcher drops the entire inherited environment before starting the service. The service CLI also refuses known cloud/API credential variables. Keep scanner credentials in a separate process/account or private collection environment. The decoy image contains no scanner, collection or evidence modules. Public exposure is deliberate opt-in and still needs the isolation controls in [service boundaries](service.md).

## Analyze manual cloud evidence

```sh
reverse-shell-decoy cloud --provider cloudflare --paste
reverse-shell-decoy cloud --provider aws --logs cloudtrail.json
reverse-shell-decoy cloud --provider render --logs render-events.json
reverse-shell-decoy cloud --provider railway --logs railway-events.json
```

Analysis of exported or pasted logs requires no cloud credential. Read-only API collection, where supported, is a separate optional command with explicit provider, account/workspace scope, UTC start/end and your own environment credentials:

```sh
reverse-shell-decoy collect-cloud --provider cloudflare --scope-id YOUR_ACCOUNT_ID \
  --since 2026-10-29T00:00:00Z --until 2026-10-29T12:00:00Z
```

Do not paste credentials into logs, a chat, the decoy, or the repository. The collector never uses a visitor's credentials. See [collector permissions and availability](collectors.md): providers differ, API availability can be limited, and some evidence must be exported manually. Collection is read-only, opt-in and bounded. Missing or inaccessible evidence is unknown coverage, not a clean scan.

## Summarize supplied evidence

```sh
python3 scripts/summarize.py \
  --cloudflare cloudflare-events.json --aws cloudtrail.json \
  --render render-events.json --railway railway-events.json \
  --host-report host-audit.json --decoy-audit decoy-audit.jsonl
```

The script performs no cloud API request, credential lookup, host scan, sinkhole or honeypot launch. It summarizes only files you supply. The host report comes from a prior, explicitly run `reverse-shell-decoy audit`. Missing providers are marked not supplied. Synthetic demo inputs are excluded from non-demo indicator counts. The decoy section separates actual observed interactions from synthetic privilege/session effects. Use `--json` for a structured summary with a bounded timeline.

Save sensitive output in a private directory with restrictive permissions. Preserve original logs separately. The source ZIP/public repo contains example data only, not your real evidence.

## A positive finding and sinkhole planning

```sh
reverse-shell-decoy sinkhole-plan --report summary.json \
  --owned-domain decoy-lab.example --decoy-ip 192.0.2.15 --confirm-owned
```

The example domain/IP are placeholders. Use only a domain and isolated endpoint you administer. This command generates a review-required proposal; it performs no DNS writes, firewall changes, redirects or network requests. It does not contact or burden a visitor's machine. A positive finding means review indicators exist, not that an attacker has been proven.

Before any real change, independently verify the finding, affected domain ownership, matching traffic protocol, exact DNS record/TTL, rollback and downstream impact. DNS sinkholing does not redirect an already-established reverse-shell TCP session, and the plaintext terminal decoy is not a DNS/HTTP service. Apply an approved provider-specific change separately through your own administrative process. No automatic sinkhole or credential-driven remediation is included.
