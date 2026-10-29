#!/usr/bin/env python3
"""Summarize manual Cloudflare/AWS/Render/Railway logs and separate decoy evidence."""
from pathlib import Path
import sys

# Prefer this checkout's reviewed source, with no cloud credentials or network calls.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from reverse_shell_decoy.summary import main

if __name__ == "__main__":
    raise SystemExit(main())
