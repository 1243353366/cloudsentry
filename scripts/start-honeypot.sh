#!/bin/sh
# Dedicated launch command. Drop inherited variables, including all cloud credentials.
PATH=/usr/bin:/bin
export PATH
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/env -i PATH=/usr/bin:/bin PYTHONPATH="$BASE/src" PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -m reverse_shell_decoy.honeypot "$@"
