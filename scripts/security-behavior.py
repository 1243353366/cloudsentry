#!/usr/bin/env python3
"""Manual synthetic behavior training or selected-audit customer explanation."""
from pathlib import Path
import sys

# This source-checkout entry point uses only code in its own repository.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.incident_explainer import main

if __name__ == "__main__":
    raise SystemExit(main())
