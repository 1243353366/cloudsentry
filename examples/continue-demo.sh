#!/bin/sh
# Run locally in an authorized lab. This does not install a backdoor or contact any server.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$BASE/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m reverse_shell_decoy simulate --presentation realistic "$@"
