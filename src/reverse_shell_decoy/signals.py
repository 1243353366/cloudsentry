"""Small, deterministic text indicators; never an interpreter or attribution model."""
from __future__ import annotations

import re

LANGUAGES = frozenset({"php", "python", "perl", "ruby", "node", "bash", "sh", "nc", "powershell", "unknown"})
TOKEN_INDICATORS = frozenset({"php_network_api", "php_stream_api", "process_api", "python_socket_api", "shell_path", "encoded_text"})
_ALIASES = {"php": "php", "python": "python", "python3": "python", "python2": "python", "perl": "perl", "ruby": "ruby", "node": "node", "nodejs": "node", "bash": "bash", "sh": "sh", "nc": "nc", "ncat": "nc", "powershell": "powershell", "pwsh": "powershell"}
_PATTERNS = {
    "php_network_api": re.compile(r"\b(?:fsockopen|stream_socket_client)\b", re.IGNORECASE),
    "php_stream_api": re.compile(r"\bstream_set_blocking\b", re.IGNORECASE),
    "process_api": re.compile(r"\b(?:proc_open|subprocess|exec|system)\b", re.IGNORECASE),
    "python_socket_api": re.compile(r"\bsocket\.socket\b", re.IGNORECASE),
    "shell_path": re.compile(r"/bin/(?:bash|sh)\b", re.IGNORECASE),
    "encoded_text": re.compile(r"\b(?:base64|b64decode)\b", re.IGNORECASE),
}


def inspect_text(raw: str) -> dict:
    """Classify at most 4096 characters, returning only fixed identifiers.

    Tokens may occur in comments, ordinary text or harmless metadata queries.
    Their presence proves neither execution, skill, intent nor authorization.
    """
    if not isinstance(raw, str):
        raise ValueError("input must be text")
    text = raw[:4096]
    parts = text.lstrip().split(None, 1)
    first = parts[0][:128].strip("'\"") if parts else ""
    name = first.rsplit("/", 1)[-1].lower()
    language = "php" if text.lstrip().lower().startswith("<?php") else _ALIASES.get(name, "unknown")
    return {
        "language_indicator": language,
        "token_indicators": sorted(key for key, pattern in _PATTERNS.items() if pattern.search(text)),
        "indicator_scope": "bounded_text_patterns_only; not execution/skill/authorization",
    }
