"""A terminal-shaped state machine, never a real shell or network listener."""
from __future__ import annotations

import hashlib
import json
import posixpath
import shlex
from datetime import datetime, timezone
from typing import Any

MAX_INPUT = 4096
MAX_COMMANDS = 1000
MAX_FILES = 128
MAX_VIRTUAL_BYTES = 65536
MAX_OUTPUT = 8192


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def display_safe(text: str) -> str:
    """Preserve newline/tab, but neutralize terminal controls and escape sequences."""
    return "".join(c if (c.isprintable() or c in "\n\t") else f"\\x{ord(c):02x}" for c in text)


class DecoySession:
    """All session state is synthetic and exists only in Python dictionaries."""

    def __init__(self, persona: str = "linux", presentation: str = "transparent") -> None:
        if persona not in {"linux", "windows"}:
            raise ValueError("persona must be linux or windows")
        if presentation not in {"transparent", "realistic"}:
            raise ValueError("presentation must be transparent or realistic")
        self.presentation = presentation
        self.persona = persona
        self.cwd = "/root"
        self.closed = False
        self.directories = {"/", "/root", "/etc", "/cases", "/tmp"}
        self.files = {
            "/etc/os-release": "NAME=DecoyOS\nVERSION=1.0\nSIMULATION=true\n",
            "/root/credentials.txt": "SYNTHETIC ONLY\nuser=training-admin\npassword=NOT-A-REAL-CREDENTIAL\n",
            "/cases/fictional-case.txt": "FICTIONAL TRAINING RECORD\nCASE=DECOY-0001\nNo real people or agency records.\n",
            "/root/persistence.txt": "SIMULATED persistence staging: no host changes made.\n",
        }
        self.events: list[dict[str, Any]] = []

    @property
    def banner(self) -> str:
        privilege = "ROOT ACCESS GRANTED" if self.persona == "linux" else "ADMINISTRATOR ACCESS GRANTED"
        if self.presentation == "realistic":
            return f"Maintenance console\n{privilege}\nSession ready. Type help to continue.\n"
        return (
            "REVERSE-SHELL DECOY — AUTHORIZED SIMULATION\n"
            f"{privilege} [synthetic persona only]\n"
            "[SIMULATED] privilege escalation complete; persistence staged; discovery ready.\n"
            "No real privileges obtained. No commands execute on the host. No network connection.\n"
            "Use help to continue, or exit to end the simulation.\n"
        )

    @property
    def prompt(self) -> str:
        return "root@srv-maint-02:" + self.cwd + "# " if self.persona == "linux" else "PS C:\\Maintenance> "

    def _path(self, value: str) -> str:
        return posixpath.normpath(value if value.startswith("/") else posixpath.join(self.cwd, value))

    def _event(self, raw: str, verb: str, blocked: bool, reason: str, output: str) -> None:
        # Raw input and arguments are deliberately not retained: they could contain secrets.
        self.events.append({
            "event_id": len(self.events) + 1,
            "timestamp_utc": now(),
            "simulation": True,
            "source": "in_memory_decoy",
            "persona": self.persona,
            "presentation": self.presentation,
            "verb": verb if verb in self.allowed_verbs else "unsupported",
            "input_sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
            "input_length": len(raw),
            "blocked": blocked,
            "reason": reason,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        })

    allowed_verbs = frozenset({
        "help", "exit", "quit", "whoami", "id", "uname", "ver", "get-computerinfo",
        "pwd", "ls", "dir", "cat", "type", "cd", "echo", "touch", "mkdir", "rm",
        "ps", "get-process", "ss", "netstat", "status",
    })

    def execute(self, raw: str) -> str:
        if self.closed:
            return "[SIMULATED] session closed\n"
        if len(self.events) >= MAX_COMMANDS:
            self.closed = True
            return "[SIMULATED] maximum command count reached; session closed\n"
        if len(raw) > MAX_INPUT:
            # Never hash/store an unbounded caller-provided value in the audit.
            self._event(raw[:MAX_INPUT], "unsupported", True, "input_limit", "input too long")
            return "[SIMULATED] input too long; blocked\n"
        stripped = raw.strip()
        verb = "unsupported"
        blocked, reason = False, "simulated"
        try:
            if any(c in stripped for c in ";|&><`\n\r") or "$" in stripped or "\x1b" in stripped:
                raise ValueError("shell operators and terminal escapes are blocked")
            tokens = shlex.split(stripped)
            if not tokens:
                output = ""
                reason = "empty_input"
            else:
                verb = tokens[0].lower()
                args = tokens[1:]
                if verb not in self.allowed_verbs:
                    raise ValueError("unsupported command; no host execution")
                output = self._dispatch(verb, args)
        except ValueError as exc:
            output = f"[SIMULATED] blocked: {exc}\n"
            blocked, reason = True, "not_permitted"
        output = display_safe(output)[:MAX_OUTPUT]
        if self.presentation == "realistic":
            output = self._present(output)
        self._event(raw, verb, blocked, reason, output)
        return output

    @staticmethod
    def _present(output: str) -> str:
        # Cosmetic output mapping only: it cannot change audit or host telemetry.
        return (output.replace("[SIMULATED] ", "").replace(" [SIMULATED]", "")
                .replace("[ALL SYNTHETIC]", "").replace("DECOY\\Administrator", "SRV-MAINT-02\\Administrator")
                .replace("synthetic x86_64", "x86_64")
                .replace("; host untouched", "").replace("No real socket exists.\n", ""))

    def _dispatch(self, verb: str, args: list[str]) -> str:
        if verb == "help":
            if self.presentation == "realistic":
                return "Commands: whoami, id, uname, ver, pwd, ls/dir, cat/type, cd, echo, touch, mkdir, rm, ps, ss/netstat, status, exit.\n"
            return (
                "[SIMULATED] Commands: whoami, id, uname, ver, Get-ComputerInfo, pwd, ls/dir,\n"
                "cat/type, cd, echo, touch, mkdir, rm, ps/Get-Process, ss/netstat, status, exit.\n"
                "Virtual paths use / syntax for both personas. No pipes, scripts, shell operators,\n"
                "network commands, persistence, or arbitrary executables. All records are fictional.\n"
            )
        if verb in {"exit", "quit"}:
            self.closed = True
            return "[SIMULATED] session ended\n"
        if verb == "whoami":
            return "root\n" if self.persona == "linux" else "DECOY\\Administrator\n"
        if verb == "id":
            return "uid=0(root) gid=0(root) groups=0(root) [SIMULATED]\n"
        if verb in {"uname", "ver", "get-computerinfo"}:
            if self.presentation == "realistic":
                return "Linux srv-maint-02 6.1.0 x86_64 GNU/Linux\n" if self.persona == "linux" else "Microsoft Windows [Version 10.0.20348.0]\n"
            return "DecoyOS 1.0 / synthetic x86_64 / no real host information [SIMULATED]\n"
        if verb == "pwd":
            return self.cwd + "\n"
        if verb in {"ls", "dir"}:
            if len(args) > 1:
                raise ValueError("use one virtual path, no flags")
            path = self._path(args[0]) if args else self.cwd
            if path in self.files:
                return posixpath.basename(path) + "\n"
            if path not in self.directories:
                return "[SIMULATED] directory not found\n"
            entries = [posixpath.basename(p) for p in self.directories | set(self.files)
                       if p != path and posixpath.dirname(p) == path]
            return "\n".join(sorted(entries)) + "\n"
        if verb in {"cat", "type"}:
            if len(args) != 1:
                raise ValueError("one virtual file required")
            return self.files.get(self._path(args[0]), "[SIMULATED] virtual file not found\n")
        if verb == "cd":
            if len(args) > 1:
                raise ValueError("one virtual directory required")
            path = self._path(args[0]) if args else "/root"
            if path not in self.directories:
                return "[SIMULATED] virtual directory not found\n"
            self.cwd = path
            return ""
        if verb == "echo":
            return " ".join(args) + "\n"
        if verb in {"touch", "mkdir", "rm"}:
            if len(args) != 1 or args[0].startswith("-"):
                raise ValueError("one virtual path required; flags disabled")
            path = self._path(args[0])
            if verb == "rm":
                if path not in self.files:
                    return "[SIMULATED] virtual file not found; directories cannot be removed\n"
                del self.files[path]
            else:
                if posixpath.dirname(path) not in self.directories:
                    raise ValueError("virtual parent directory missing")
                if len(self.files) + len(self.directories) >= MAX_FILES:
                    raise ValueError("virtual object limit reached")
                if sum(len(p) + len(v) for p, v in self.files.items()) + sum(map(len, self.directories)) + len(path) > MAX_VIRTUAL_BYTES:
                    raise ValueError("virtual byte limit reached")
                if verb == "mkdir":
                    if path in self.files:
                        raise ValueError("virtual file already exists")
                    self.directories.add(path)
                else:
                    if path in self.directories:
                        raise ValueError("virtual directory already exists")
                    self.files.setdefault(path, "")
            return "[SIMULATED] virtual state updated; host untouched\n"
        if verb in {"ps", "get-process"}:
            return "PID  USER  COMMAND [ALL SYNTHETIC]\n1    root  decoy-init\n42   root  staged-agent\n"
        if verb in {"ss", "netstat"}:
            return "[SIMULATED] ESTAB 192.0.2.10:40000 -> 198.51.100.20:4444\nNo real socket exists.\n"
        if verb == "status":
            return json.dumps({"simulation": True, "virtual_privilege": "root/admin", "network": "none",
                               "host_execution": False, "virtual_files": len(self.files)}) + "\n"
        raise ValueError("unsupported command")
