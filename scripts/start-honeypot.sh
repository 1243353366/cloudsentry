#!/bin/sh
# Dedicated launch command. Drop inherited variables, including all cloud credentials.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=$(command -v python3)
exec env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m reverse_shell_decoy.honeypot "$@"
