#!/usr/bin/env python3
"""Run trusted local software/firmware checks only; no customer image input."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.software_vm_lab import main

if __name__ == "__main__":
    raise SystemExit(main())
