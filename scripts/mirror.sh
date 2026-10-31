#!/bin/sh
# MIRROR: bounded inbound-only data echo on the same accepted connection.
# No interpreter, callback, raw credential logging, persistence, or remote command loop.
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
exec /usr/bin/env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON_BIN" -m reverse_shell_decoy.honeypot "$@" --response-mode mirror
