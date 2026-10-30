#!/usr/bin/env python3
"""Review or fail-closed apply caps to only the fixed loopback backup echo workload."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.resource_boundary import main

if __name__ == "__main__":
    raise SystemExit(main())
