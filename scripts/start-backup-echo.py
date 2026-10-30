#!/usr/bin/env python3
"""Manually run only inside the independently approved isolated guest."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.backup_echo import main

if __name__ == "__main__":
    raise SystemExit(main())
