#!/usr/bin/env python3
"""Export labeled decoy observations and synthetic state for investigator review.

This is not proof of unauthorized real-host access, attacker identity, or legal liability.
Run from the complete source package; no log or state input is executed.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.investigator import main

if __name__ == "__main__":
    raise SystemExit(main())
