#!/bin/sh
# Defensive shellception: read-only snapshots + synthetic mutation + integrity guard.
# No attacker host/port, counter-shell, cron/watchdog, daemonization, or host changes.
PATH=/usr/bin:/bin
export PATH
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -m reverse_shell_decoy.shellception "$@"
