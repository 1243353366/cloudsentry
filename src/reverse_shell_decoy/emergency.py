"""Manual short-lived sink profile, not compromised-host containment or OCR interference."""
from __future__ import annotations

import argparse
from typing import Sequence

# Fixed operator-side limits cannot be raised through this profile's arguments.
LIMIT_ARGUMENTS = (
    "--response-mode", "sink", "--max-runtime", "30",
    "--max-sessions", "1", "--max-sessions-total", "2",
    "--max-commands", "4", "--idle-timeout", "2", "--session-timeout", "5",
    "--audit-limit", "40", "--max-input-bytes-total", "1024",
    "--max-output-bytes-total", "1", "--max-session-input-bytes", "256",
    "--commands-per-second", "1",
)


def build_emergency_arguments(argv: Sequence[str] | None = None) -> list[str]:
    parser = argparse.ArgumentParser(description="Manually start a bounded silent emergency decoy; not a host-isolation command.", allow_abbrev=False)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8022)
    parser.add_argument("--allow-public", action="store_true", help="separate non-loopback bind opt-in; does not configure network isolation")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    result = ["--host", args.host, "--port", str(args.port)]
    if args.allow_public:
        result.append("--allow-public")
    return result + list(LIMIT_ARGUMENTS)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_emergency_arguments(argv)
    from .honeypot import main as serve
    return serve(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
