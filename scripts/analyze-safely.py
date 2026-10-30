#!/usr/bin/env python3
"""Non-executing static/synthetic analysis; real VM execution fails closed."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.virtual_analysis import main

if __name__ == "__main__":
    raise SystemExit(main())
