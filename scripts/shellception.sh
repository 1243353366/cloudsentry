#!/usr/bin/env bash
# Defensive shellception: read-only snapshots + synthetic mutation + integrity guard.
# No attacker host/port, counter-shell, cron/watchdog, daemonization, or host changes.
set -euo pipefail
BASE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$(command -v python3)"
exec env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON" -m reverse_shell_decoy.shellception "$@"
