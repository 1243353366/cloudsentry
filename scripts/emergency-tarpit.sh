#!/bin/sh
# Manual, finite silent sink. No takeover, callbacks, persistence or OCR payloads.
PATH=/usr/bin:/bin
export PATH
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -m reverse_shell_decoy.emergency "$@"
