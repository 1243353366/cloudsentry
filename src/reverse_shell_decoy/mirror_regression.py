"""Bounded local JSONL regression checks for the opaque loopback mirror.

This importer is for user-authorized local exports and original synthetic cases.
It never fetches a corpus, evaluates its contents, or retains payloads in output.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .honeypot import DecoyServer
from .input_files import read_regular

_MAX_FILE_BYTES = 128 * 1024
_MAX_RECORDS = 16
_MAX_PAYLOAD_BYTES = 2048
_MAX_JSON_DEPTH = 8
_MAX_JSON_NODES = 64
_LIMIT_NOTICE = (
    "Exact echo is not LLM prompt-injection detection or jailbreak-resistance. "
    "Output equals supplied bytes; mirror grants no host access. No indefinite "
    "hold/OCR interference/thirdpartytesting."
)


class CorpusValidationError(ValueError):
    """A local export is outside the deliberately small accepted grammar."""


@dataclass(frozen=True)
class CorpusCase:
    physical_line: int
    line_sha256: str
    payload: bytes
    input_sha256: str


@dataclass(frozen=True)
class LocalCorpus:
    source_input_sha256: str
    cases: tuple[CorpusCase, ...]


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _small_int(value: str) -> int:
    if len(value.lstrip("-")) > 24:
        raise ValueError("integer is too large")
    return int(value)


def _small_float(value: str) -> float:
    if len(value) > 24:
        raise ValueError("number is too large")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _check_shape(value: Any, depth: int = 1) -> int:
    """Bound JSON complexity even for fields that the grammar later refuses."""
    if depth > _MAX_JSON_DEPTH:
        raise CorpusValidationError("JSON nesting exceeds limit")
    count = 1
    if isinstance(value, dict):
        for item in value.values():
            count += _check_shape(item, depth + 1)
            if count > _MAX_JSON_NODES:
                raise CorpusValidationError("JSON node count exceeds limit")
    elif isinstance(value, list):
        for item in value:
            count += _check_shape(item, depth + 1)
            if count > _MAX_JSON_NODES:
                raise CorpusValidationError("JSON node count exceeds limit")
    return count


def _read_regular(path: str | os.PathLike[str]) -> bytes:
    """Read one small regular file without following a final symlink."""
    try:
        return read_regular(os.fspath(path), _MAX_FILE_BYTES)
    except (OSError, TypeError, ValueError) as exc:
        raise CorpusValidationError("corpus cannot be opened") from exc


def _parse_record(raw_line: bytes, physical_line: int) -> tuple[bytes, str]:
    """Parse the fixed object grammar without interpreting any text field."""
    try:
        record = json.loads(
            raw_line,
            object_pairs_hook=_unique_object,
            parse_int=_small_int,
            parse_float=_small_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise CorpusValidationError("malformed corpus record") from exc
    _check_shape(record)
    if not isinstance(record, dict) or not set(record).issubset({"id", "text", "prompt", "example"}):
        raise CorpusValidationError("record grammar refused")
    if "id" in record:
        if not isinstance(record["id"], str):
            raise CorpusValidationError("record identifier refused")
        try:
            if len(record["id"].encode("utf-8")) > _MAX_PAYLOAD_BYTES:
                raise CorpusValidationError("record identifier refused")
        except UnicodeEncodeError as exc:
            raise CorpusValidationError("record identifier refused") from exc

    selected = [record[name] for name in ("text", "prompt", "example") if name in record]
    if not selected or any(not isinstance(value, str) for value in selected):
        raise CorpusValidationError("record text field refused")
    if len(set(selected)) != 1:
        raise CorpusValidationError("conflicting text fields refused")
    try:
        payload = selected[0].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CorpusValidationError("record text field refused") from exc
    if not payload or len(payload) > _MAX_PAYLOAD_BYTES:
        raise CorpusValidationError("record payload size refused")
    return payload, hashlib.sha256(payload).hexdigest()


def load_corpus(path: str | os.PathLike[str]) -> LocalCorpus:
    """Load a bounded local JSONL corpus; no listener is created here."""
    source = _read_regular(path)
    cases: list[CorpusCase] = []
    seen_payloads: set[str] = set()
    for physical_line, raw_line in enumerate(source.split(b"\n"), start=1):
        if not raw_line.strip(b" \t\r"):
            continue
        if len(cases) >= _MAX_RECORDS:
            raise CorpusValidationError("record count exceeds limit")
        payload, payload_hash = _parse_record(raw_line, physical_line)
        if payload_hash in seen_payloads:
            raise CorpusValidationError("duplicate payload refused")
        seen_payloads.add(payload_hash)
        cases.append(CorpusCase(physical_line, hashlib.sha256(raw_line).hexdigest(), payload, payload_hash))
    if not cases:
        raise CorpusValidationError("empty corpus refused")
    return LocalCorpus(hashlib.sha256(source).hexdigest(), tuple(cases))


async def _echo_once(endpoint: tuple[str, int], payload: bytes) -> tuple[bytes, bool]:
    """Exercise only the internally obtained loopback endpoint once."""
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    output = b""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*endpoint), timeout=1)
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout=1)
        output = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1)
        return output, output == payload
    except asyncio.IncompleteReadError as exc:
        return exc.partial, False
    except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
        return output, False
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)


async def run_regression(corpus_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Validate first, then run finite opaque echo checks on ephemeral loopback."""
    corpus = load_corpus(corpus_path)
    started = time.monotonic()
    service = DecoyServer(
        response_mode="mirror", max_runtime=10, max_sessions=1,
        max_sessions_total=len(corpus.cases), session_timeout=1, idle_timeout=1,
        max_commands=1, audit_limit=128, max_input_bytes_total=32768,
        max_output_bytes_total=32768, max_session_input_bytes=2048,
        commands_per_second=1,
    )
    audit_sink = io.StringIO()
    results: list[dict[str, Any]] = []
    with contextlib.redirect_stderr(audit_sink):
        try:
            server = await service.start(host="127.0.0.1", port=0, allow_public=False)
            sockets = server.sockets or ()
            address = sockets[0].getsockname() if len(sockets) == 1 else ()
            if not (isinstance(address, tuple) and len(address) >= 2 and address[0] == "127.0.0.1"
                    and isinstance(address[1], int) and 0 < address[1] <= 65535):
                raise RuntimeError("unexpected local listener")
            endpoint = (address[0], address[1])
            for case in corpus.cases:
                output, echoed = await _echo_once(endpoint, case.payload)
                results.append({
                    "physical_line": case.physical_line,
                    "line_sha256": case.line_sha256,
                    "input_sha256": case.input_sha256,
                    "response_sha256": hashlib.sha256(output).hexdigest(),
                    "input_bytes": len(case.payload),
                    "output_bytes": len(output),
                    "echo_matches": echoed,
                    "case_passed": echoed and len(output) == len(case.payload),
                })
        finally:
            await service.shutdown()
    return {
        "format": "mirror_corpus_regression_v1",
        "provider": "local",
        "case_count": len(corpus.cases),
        "passed": bool(results) and all(item["case_passed"] for item in results),
        "case_results": results,
        "source_input_sha256": corpus.source_input_sha256,
        "execution_performed": False,
        "network_scope": "ephemeral_loopback_test_only",
        "runtime_enforcement": False,
        "limit_notice": _LIMIT_NOTICE,
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded local mirror corpus checks.")
    parser.add_argument("--corpus", required=True, help="user-authorized local JSONL export")
    parser.add_argument("--consent", action="store_true", help="confirm this invocation")
    return parser


def _consented(flag: bool) -> bool:
    if flag:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        sys.stderr.write("Run local mirror corpus regression? [y/N] ")
        sys.stderr.flush()
        return sys.stdin.readline().strip().lower() == "y"
    except (OSError, EOFError):
        return False


def main(argv: Optional[list[str]] = None) -> int:
    """CLI with fresh consent before opening the corpus or listener."""
    args = _parser().parse_args(argv)
    if not _consented(args.consent):
        return 2
    try:
        result = asyncio.run(run_regression(Path(args.corpus)))
    except CorpusValidationError:
        sys.stderr.write("corpus rejected\n")
        return 2
    except (OSError, RuntimeError):
        sys.stderr.write("local regression unavailable\n")
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
