#!/usr/bin/env python3
"""Run a user-authorized local mirror JSONL regression corpus."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reverse_shell_decoy.mirror_regression import main


if __name__ == "__main__":
    raise SystemExit(main())
