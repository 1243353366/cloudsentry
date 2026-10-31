#!/bin/sh
# Explicit opt-in only; this does not provision or attest a guest.
PATH=/usr/bin:/bin
export PATH
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_BIN="${CLOUDSENTRY_PYTHON:-/usr/bin/python3}"
case "$PYTHON_BIN" in
  /*) ;;
  *) echo "CLOUDSENTRY_PYTHON must be an absolute path: $PYTHON_BIN" >&2; exit 1 ;;
esac
if [ ! -x "$PYTHON_BIN" ]; then
  echo "CLOUDSENTRY_PYTHON is not executable: $PYTHON_BIN" >&2
  exit 1
fi
exec /usr/bin/env -i PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON_BIN" "$BASE/scripts/start-backup-echo.py" "$@"
