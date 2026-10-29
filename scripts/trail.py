#!/usr/bin/env python3
"""Emit a local, JSON-only bounded classification trail for selected decoy audits."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.trail import main


if __name__ == "__main__":
    raise SystemExit(main())
