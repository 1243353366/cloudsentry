"""Separate observations by source; do not inflate indicators into proof."""
from __future__ import annotations

from .detector import scan
from .evidence import os_info
from .listeners import scan_listeners
from .persistence import scan_persistence
from .simulator import now


def audit_host(imported_logs: dict | None = None, name_check: dict | None = None) -> dict:
    started = now()
    shell_connections = scan()
    shell_connections["simulation"] = False
    shell_connections["observed_at_utc"] = now()
    listeners = scan_listeners()
    persistence = scan_persistence()
    return {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "simulation": False,
        "acquisition_started_at_utc": started,
        "acquisition_ended_at_utc": now(),
        "host_observations": {
            "source_kind": "local_read_only_snapshot",
            "host_os": os_info(),
            "shell_connections": shell_connections,
            "listeners": listeners,
            "persistence_indicators": persistence,
        },
        "imported_logs": imported_logs,
        "offline_name_checks": name_check,
        "assessment": "Indicators require investigation. No result establishes compromise, connection direction, or attacker identity.",
        "provenance_notice": (
            "Host observations describe the computer running this tool, not necessarily the computer that produced imported logs. "
            "Imported/pasted content is untrusted evidence and is not authenticated. Decoy audit is stored separately. "
            "This report is not a forensic disk image, rootkit scan, EDR test, or exhaustive backdoor detection."
        ),
    }
