#!/usr/bin/env bash
# MIRROR: bounded inbound-only data echo on the same accepted connection.
# No interpreter, callback, raw credential logging, persistence, or remote command loop.
set -euo pipefail
BASE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$BASE/scripts/start-honeypot.sh" "$@" --response-mode mirror
