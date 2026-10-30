#!/bin/sh
# Explicit opt-in only; this does not provision or attest a guest.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec env -i PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 "$BASE/scripts/start-backup-echo.py" "$@"
