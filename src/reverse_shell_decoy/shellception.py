"""Bounded defensive shellception: observe, mutate only a decoy, verify, stop.

There is no counter-shell, C2 connection, real persistence, or listener exhaustion.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
import random
import stat
import sys
import time
from typing import Any

from .input_files import read_regular
from .simulator import DecoySession, MAX_FILES, MAX_VIRTUAL_BYTES, now

MAX_WATCH_FILES = 16
MAX_WATCH_BYTES = 65536
MAX_EVENTS = 256
MUTATIONS = ("history", "cron", "authorized_keys", "profile", "loot")


class DefensiveLoop:
    """Read-only observation and dictionary-only mutations, under fixed bounds."""

    def __init__(self, seed: int = 0, watch_files: list[str] | None = None) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        if watch_files is not None and (not isinstance(watch_files, list) or any(not isinstance(p, str) for p in watch_files)):
            raise ValueError("watch_files must be an explicit list of local file paths")
        if len(watch_files or []) > MAX_WATCH_FILES:
            raise ValueError("at most 16 explicit files may be watched")
        self.watch_files = tuple(watch_files or [])
        self.session = DecoySession(presentation="realistic")
        self.events: list[dict[str, Any]] = []
        self._random = random.Random(seed)
        self._generation = 0
        self._warnings: list[str] = []
        self._closed = False
        self._last = self.snapshot()

    @property
    def observation_scope(self) -> str:
        return "explicit_local_files" if self.watch_files else "virtual_state"

    def verify_isolation(self) -> bool:
        """Validate virtual-state limits, not a claim of OS/VM escape-proofness."""
        if not isinstance(self.session.files, dict) or not isinstance(self.session.directories, set):
            return False
        if len(self.session.files) + len(self.session.directories) > MAX_FILES:
            return False
        if not isinstance(self.session.cwd, str) or len(self.session.cwd) > 4096:
            return False
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.session.files.items()):
            return False
        if any(not isinstance(d, str) for d in self.session.directories):
            return False
        try:
            virtual_bytes = sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) for k, v in self.session.files.items())
            virtual_bytes += sum(len(d.encode("utf-8")) for d in self.session.directories)
        except UnicodeError:
            return False
        return virtual_bytes <= MAX_VIRTUAL_BYTES

    def export_state(self) -> dict[str, Any]:
        """Export only current synthetic state, never real watched-file content."""
        if not self.verify_isolation():
            raise RuntimeError("cannot export invalid virtual state")
        return {
            "schema_version": "1.0",
            "state_kind": "synthetic_virtual_filesystem",
            "simulation": True,
            "timestamp_utc": now(),
            "virtual_privilege": "root/admin; synthetic only",
            "state_sha256": self._virtual_snapshot(),
            "files": dict(self.session.files),
            "directories": sorted(self.session.directories),
            "cwd": self.session.cwd,
            "provenance_notice": "Current synthetic filesystem snapshot, not proof of actual OS access or a reconstruction of every historical state.",
        }

    def _virtual_snapshot(self) -> str:
        if not self.verify_isolation():
            raise RuntimeError("virtual-state integrity/size check failed; loop stopped")
        value = {"files": self.session.files, "directories": sorted(self.session.directories), "cwd": self.session.cwd}
        # Deliberately omit audit timestamps, process lists, and other volatile data.
        return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

    def snapshot(self) -> str:
        self._warnings = []
        if not self.watch_files:
            return self._virtual_snapshot()
        entries = []
        for index, path in enumerate(self.watch_files):
            try:
                content = read_regular(path, MAX_WATCH_BYTES)
                entries.append({"index": index, "sha256": sha256(content).hexdigest()})
            except (OSError, ValueError):
                # No path, file contents, usernames or exception bodies go to audit.
                entries.append({"index": index, "status": "unavailable"})
                self._warnings.append(f"explicit watched file {index + 1} unavailable or rejected by safety bounds")
        return sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _mutate_virtual(self) -> str:
        """Replace bounded synthetic markers; never edit any actual host file."""
        if not self.verify_isolation():
            raise RuntimeError("virtual-state integrity failed before mutation")
        mutation = self._random.choice(MUTATIONS)
        self._generation += 1
        roots = {"/root/.ssh", "/tmp/.shc", "/etc/cron.d"}
        paths = {
            "history": "/root/.bash_history",
            "cron": "/etc/cron.d/shellception",
            "authorized_keys": "/root/.ssh/authorized_keys",
            "profile": "/root/.bashrc",
            "loot": "/tmp/.shc/loot.txt",
        }
        before_files, before_dirs = dict(self.session.files), set(self.session.directories)
        self.session.directories.update(roots)
        self.session.files[paths[mutation]] = (
            f"SYNTHETIC {mutation} marker, generation {self._generation}.\n"
            "No real shell, credentials, scheduled task, host mutation, or outbound connection.\n"
        )
        if not self.verify_isolation():
            self.session.files = before_files
            self.session.directories = before_dirs
            raise RuntimeError("virtual mutation exceeded bounds; reverted and stopped")
        return mutation

    def step(self) -> dict[str, Any]:
        if self._closed or len(self.events) >= MAX_EVENTS:
            self._closed = True
            raise RuntimeError("bounded loop event limit reached; no restart")
        if not self.verify_isolation():
            self._closed = True
            raise RuntimeError("virtual-state integrity failed; loop stopped")
        current = self.snapshot()
        observed_warnings = list(self._warnings)
        previous = self._last
        changed = current != previous
        mutation = self._mutate_virtual() if changed else None
        # Re-anchor after our own decoy mutation, so it cannot feed another mutation.
        # Real watched files were not mutated: don't sample them twice or swallow a race.
        self._last = self._virtual_snapshot() if changed and not self.watch_files else current
        event = {
            "event_id": len(self.events) + 1,
            "timestamp_utc": now(),
            "simulation": True,
            "simulation_scope": "virtual_privilege_and_decoy_mutations_only",
            "source_kind": "bounded_defensive_state_loop",
            "observation_scope": self.observation_scope,
            "observation_is_real": bool(self.watch_files),
            "changed": changed,
            "baseline_sha256": previous,
            "state_sha256": current,
            "post_mutation_baseline_sha256": self._last,
            "mutation": mutation,
            "integrity_ok": self.verify_isolation(),
            "integrity_scope": "virtual_state_schema_and_size_only; not OS escape attestation",
            "host_changed": False,
            "outbound_connections": 0,
            "action_scope": "this_module_only; not a host-wide security claim",
            "virtual_privilege": "root/admin; synthetic only",
            "warnings": observed_warnings,
            "assessment": "A state change is not evidence of an attacker or compromise.",
        }
        self.events.append(event)
        return dict(event)


def _write_state_file(path: str, state: dict[str, Any]) -> None:
    """Write a deliberately requested private artifact; refuse existing paths."""
    content = (json.dumps(state, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            current = os.lstat(path)
            if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(path)
        except OSError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bounded snapshot/change/decoy-mutation loop. No C2 target, counter-shell, or host writes.")
    p.add_argument("--iterations", type=int, default=12)
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--max-runtime", type=float, default=15)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--watch-file", action="append", help="explicit authorized regular file, digest only; never edited")
    p.add_argument("--demo", action="store_true", help="produce harmless synthetic changes; incompatible with real-file watching")
    p.add_argument("--state-output", help="explicit new private JSON artifact containing synthetic state only; never overwrite")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 1 <= args.iterations <= 120:
        _parser().error("iterations must be 1..120")
    if not 0 <= args.interval <= 5:
        _parser().error("interval must be 0..5 seconds")
    if not 1 <= args.max_runtime <= 60:
        _parser().error("max-runtime must be 1..60 seconds")
    if args.demo and args.watch_file:
        _parser().error("demo uses virtual state only; do not combine with real watched files")
    try:
        loop = DefensiveLoop(args.seed, args.watch_file)
        started = time.monotonic()
        for index in range(args.iterations):
            if time.monotonic() - started >= args.max_runtime:
                break
            if args.demo and index % 2 == 0:
                loop.session.execute(f"touch /tmp/demo-change-{index}")
            event = loop.step()
            print(json.dumps(event, sort_keys=True, ensure_ascii=True, allow_nan=False), flush=True)
            remaining = args.max_runtime - (time.monotonic() - started)
            if index + 1 < args.iterations and remaining > 0:
                time.sleep(min(args.interval, remaining))
        if args.state_output:
            _write_state_file(args.state_output, loop.export_state())
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Stopped safely: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
