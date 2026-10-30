#!/usr/bin/env python3
"""Create a consented local descriptive packet from selected customer input files."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reverse_shell_decoy.customer_forensics import main


if __name__ == "__main__":
    raise SystemExit(main())
