#!/usr/bin/env python3
"""Explicit local audit summary; no service launch, cloud scan or remote actions."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.operations import main

if __name__ == "__main__":
    raise SystemExit(main())
