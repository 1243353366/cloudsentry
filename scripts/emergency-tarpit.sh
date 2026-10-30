#!/bin/sh
# Manual, finite silent sink. No takeover, callbacks, persistence or OCR payloads.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=$(command -v python3)
exec env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m reverse_shell_decoy.emergency "$@"
