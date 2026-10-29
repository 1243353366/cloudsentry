#!/usr/bin/env bash
# Bounded inbound sink. No outbound replay, raw secret capture, or automatic restart.
set -euo pipefail
BASE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$BASE/scripts/start-honeypot.sh" "$@" --response-mode sink
