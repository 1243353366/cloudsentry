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
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .authorization import (
    AuthorizationError,
    AuthorizationGrant,
    AuthorizationScope,
    cancellation_guard,
    request_authorization,
)
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
    """Trusted library file helper; it grants no authority and opens no listener."""
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
    """Pure trusted-library parser for already-authorized callers; it confers no grant."""
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


def _require_scope(
    corpus_path: str | os.PathLike[str],
    authorization: AuthorizationGrant | None,
    scope: AuthorizationScope | None,
) -> AuthorizationScope:
    """Reject missing or rebound authority without touching the selected path."""
    expected = AuthorizationScope("mirror_regression", os.fspath(corpus_path))
    if type(authorization) is not AuthorizationGrant or type(scope) is not AuthorizationScope or scope != expected:
        raise AuthorizationError("authorization unavailable")
    return expected


async def _echo_once(
    endpoint: tuple[str, int], payload: bytes, authorization: AuthorizationGrant, scope: AuthorizationScope,
) -> tuple[bytes, bool]:
    """Exercise one internally obtained loopback endpoint with checks around every I/O phase."""
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    output = b""
    try:
        authorization.check(scope)  # Before connection.
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*endpoint), timeout=1)
        authorization.check(scope)  # After connection.

        authorization.check(scope)  # Before write.
        writer.write(payload)
        authorization.check(scope)  # After write.
        authorization.check(scope)  # Before write completion.
        await asyncio.wait_for(writer.drain(), timeout=1)
        authorization.check(scope)  # After write completion.

        authorization.check(scope)  # Before response read.
        output = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1)
        authorization.check(scope)  # After response read.
        authorization.check(scope)  # Before returning response output.
        return output, output == payload
    except asyncio.IncompleteReadError as exc:
        authorization.check(scope)
        return exc.partial, False
    except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
        authorization.check(scope)
        return output, False
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)


async def run_regression(
    corpus_path: str | os.PathLike[str], *, authorization: AuthorizationGrant | None = None,
    scope: AuthorizationScope | None = None,
) -> dict[str, Any]:
    """Run one authorized, finite opaque echo check on an ephemeral loopback listener.

    Callers must supply a fresh exact-scope grant.  This public runner consumes it
    atomically before it opens the corpus or starts any socket.
    """
    expected = _require_scope(corpus_path, authorization, scope)
    assert authorization is not None  # Narrowed by _require_scope's exact type check.
    authorization.begin(expected)
    service: DecoyServer | None = None
    try:
        authorization.check(expected)  # Before corpus read and parsing.
        corpus = load_corpus(corpus_path)
        authorization.check(expected)  # After corpus read and parsing.

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
                authorization.check(expected)  # Before listener creation.
                server = await service.start(host="127.0.0.1", port=0, allow_public=False)
                authorization.check(expected)  # After listener creation, before callbacks.
                sockets = server.sockets or ()
                address = sockets[0].getsockname() if len(sockets) == 1 else ()
                if not (isinstance(address, tuple) and len(address) >= 2 and address[0] == "127.0.0.1"
                        and isinstance(address[1], int) and 0 < address[1] <= 65535):
                    raise RuntimeError("unexpected local listener")
                endpoint = (address[0], address[1])
                for case in corpus.cases:
                    authorization.check(expected)  # Before each loopback case.
                    output, echoed = await _echo_once(endpoint, case.payload, authorization, expected)
                    authorization.check(expected)  # After each loopback case.
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
                    authorization.check(expected)  # After result output processing.
            finally:
                await service.shutdown()

        authorization.check(expected)  # Before result construction.
        result = {
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
        authorization.check(expected)  # After result construction.
        return result
    finally:
        authorization.revoke()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded local mirror corpus checks.", allow_abbrev=False)
    parser.add_argument("--corpus", required=True, help="user-authorized local JSONL export")
    parser.add_argument("--consent", action="store_true", help="confirm this invocation")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI with fresh consent and one-time admission before corpus or listener access."""
    grant: AuthorizationGrant | None = None
    try:
        args = _parser().parse_args(argv)
        scope = AuthorizationScope("mirror_regression", os.fspath(args.corpus))
        grant = request_authorization(scope, consent=args.consent)
        if grant is None:
            return 2
        with cancellation_guard(grant):
            grant.check(scope)
            result = asyncio.run(run_regression(args.corpus, authorization=grant, scope=scope))
    except (AuthorizationError, KeyboardInterrupt):
        return 2
    except CorpusValidationError:
        sys.stderr.write("corpus rejected\n")
        return 2
    except (OSError, RuntimeError):
        sys.stderr.write("local regression unavailable\n")
        return 2
    finally:
        if grant is not None:
            grant.revoke()
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
