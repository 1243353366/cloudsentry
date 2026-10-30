"""Consent-gated, local descriptive reporting for explicitly selected inputs.

This module measures text formatting and fixed, bounded record summaries.  It is
not an authorship, identity, psychological, capability, legal, or attribution
system.  It never executes supplied content, invokes a network service, starts
a VM, changes a policy, or retains inputs outside a caller-selected new packet.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import inspect
import json
import math
import os
from pathlib import Path
import re
import secrets
import statistics
import stat
import sys
from typing import Any, Callable, Mapping, Sequence

from .authorization import (
    AuthorizationError,
    AuthorizationGrant,
    AuthorizationScope,
    cancellation_guard,
    request_authorization,
)
from .input_files import read_regular
from . import operations
from .signals import inspect_text

RULESET_VERSION = "customer_forensics_descriptive_v1"
MANIFEST_FORMAT = "customer_forensic_manifest_v1"
REPORT_FORMAT = "customer_forensic_report_v1"
MAX_TEXT_BYTES = 256 * 1024
MAX_AUDIT_BYTES = 1024 * 1024
MAX_LAB_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 1024
_FIXED_PUNCTUATION = (".", ",", ";", ":", "!", "?", "'", '\"', "-", "(", ")", "[", "]", "{", "}")
_FUNCTION_WORDS = ("a", "the", "and", "but", "if", "then", "or", "not", "with", "for", "from", "to", "of", "in", "on", "is", "are", "was", "were")
_WORD_RE = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)?", re.UNICODE)
_SENTENCE_RE = re.compile(r"[^.!?]+[.!?]+|[^.!?]+$", re.UNICODE)
_PDF_HEADER = b"%PDF-"
_ARTIFACTS = ("customer-forensic-report.json", "customer-forensic-report.md")
_OUTPUT_FILES = _ARTIFACTS + ("customer-forensic-manifest.json",)


class ForensicInputError(ValueError):
    """An input does not meet this deliberately narrow local format boundary."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _is_strict_bool(value: object) -> bool:
    return type(value) is bool


def _number(value: object) -> int | float:
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    return 0


def _round(value: float) -> float:
    """Keep deterministic compact decimals; no special values reach JSON."""
    return round(value, 6) if math.isfinite(value) else 0.0


def _validate_plaintext_bytes(content: bytes, maximum: int, source_id: str) -> str:
    if not isinstance(content, bytes):
        raise ForensicInputError(f"{source_id} must be bytes")
    if len(content) > maximum:
        raise ForensicInputError(f"{source_id} exceeds its configured byte limit")
    if content.startswith(_PDF_HEADER):
        raise ForensicInputError(f"{source_id} appears to be a PDF; manually extract selected plaintext first")
    if b"\x00" in content:
        raise ForensicInputError(f"{source_id} contains NUL bytes and is not accepted plaintext")
    try:
        return content.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ForensicInputError(f"{source_id} must be UTF-8 selected plaintext") from exc


def _median(values: Sequence[int]) -> float:
    return _round(float(statistics.median(values))) if values else 0.0


def analyze_text(content: bytes) -> dict[str, object]:
    """Return descriptive aggregate metrics for one UTF-8 plaintext selection.

    The result deliberately has no lexemes, quotations, source filename, identity
    score, authorship score, psychological inference, or claim about intent.
    """
    text = _validate_plaintext_bytes(content, MAX_TEXT_BYTES, "text")
    words = [item.casefold() for item in _WORD_RE.findall(text)]
    frequencies = Counter(words)
    word_lengths = [len(item) for item in words]
    sentences = [item for item in _SENTENCE_RE.findall(text) if item.strip()]
    sentence_words = [len(_WORD_RE.findall(item)) for item in sentences]
    paragraphs = [item for item in re.split(r"\n\s*\n", text) if item.strip()]
    paragraph_words = [len(_WORD_RE.findall(item)) for item in paragraphs]
    bigrams = Counter(zip(words, words[1:]))
    letters = [character for character in text if character.isalpha()]
    total_chars = len(text)
    unique_words = len(frequencies)
    total_words = len(words)
    token_signals = inspect_text(text)
    language = token_signals.get("language_indicator")
    if language not in {"php", "python", "perl", "ruby", "node", "bash", "sh", "nc", "powershell", "unknown"}:
        language = "unknown"
    raw_indicator_values = token_signals.get("token_indicators")
    indicators = [value for value in raw_indicator_values if value in {
        "php_network_api", "php_stream_api", "process_api", "python_socket_api", "shell_path", "encoded_text"
    }] if isinstance(raw_indicator_values, list) else []
    return {
        "analysis_kind": "descriptive_text_format_and_fixed_pattern_counts_only",
        "total_characters": total_chars,
        "whitespace_characters": sum(character.isspace() for character in text),
        "whitespace_fraction": _round(sum(character.isspace() for character in text) / total_chars) if total_chars else 0.0,
        "sentence_proxy_count": len(sentences),
        "word_count": total_words,
        "unique_word_count": unique_words,
        "type_token_ratio": _round(unique_words / total_words) if total_words else 0.0,
        "hapax_ratio": _round(sum(count == 1 for count in frequencies.values()) / total_words) if total_words else 0.0,
        "word_length_mean": _round(statistics.fmean(word_lengths)) if word_lengths else 0.0,
        "word_length_median": _median(word_lengths),
        "sentence_word_mean_proxy": _round(statistics.fmean(sentence_words)) if sentence_words else 0.0,
        "sentence_word_max_proxy": max(sentence_words, default=0),
        "paragraph_proxy_count": len(paragraphs),
        "paragraph_word_mean_proxy": _round(statistics.fmean(paragraph_words)) if paragraph_words else 0.0,
        "paragraph_word_max_proxy": max(paragraph_words, default=0),
        "ascii_punctuation_counts": {character: text.count(character) for character in _FIXED_PUNCTUATION},
        "uppercase_fraction_of_letters": _round(sum(character.isupper() for character in letters) / len(letters)) if letters else 0.0,
        "digit_fraction_of_characters": _round(sum(character.isdigit() for character in text) / total_chars) if total_chars else 0.0,
        "repeated_normalized_bigram_occurrences": sum(count - 1 for count in bigrams.values() if count > 1),
        "function_word_distribution_english_heuristic_only": {word: frequencies[word] for word in _FUNCTION_WORDS},
        "programming_language_indicator": language,
        "known_terminology_signal_labels": sorted(indicators),
        "limitations": [
            "Metrics describe only the submitted selected text and do not identify an author or customer.",
            "Sentence and paragraph values are regex proxies, not syntax or writing-quality measurements.",
            "Fixed terminology signals are bounded pattern labels and do not show execution, skill, intent, or authorization.",
            "No quotation, raw token, phrase, payload, filename, secret pattern, or free lexeme is retained in this result.",
        ],
    }


def _baseline_comparison(sample: dict[str, object], baseline: dict[str, object]) -> dict[str, object]:
    """Describe selected metric deltas without scoring authorship or comparability."""
    def metric(value: dict[str, object], name: str) -> float:
        selected = value.get(name)
        return float(selected) if type(selected) in {int, float} and not isinstance(selected, bool) else 0.0

    return {
        "comparison_kind": "descriptive_selected_sample_delta_only",
        "baseline_comparability": "unknown",
        "sample_length_affect": "present; selected samples can differ in length",
        "sample_length_difference_characters": int(metric(sample, "total_characters") - metric(baseline, "total_characters")),
        "topic_affect": "unknown_not_measured",
        "quotation_affect": "unknown_not_measured",
        "language_affect": "unknown_not_measured",
        "delta_metrics": {
            "type_token_ratio": _round(metric(sample, "type_token_ratio") - metric(baseline, "type_token_ratio")),
            "hapax_ratio": _round(metric(sample, "hapax_ratio") - metric(baseline, "hapax_ratio")),
            "word_length_mean": _round(metric(sample, "word_length_mean") - metric(baseline, "word_length_mean")),
            "sentence_word_mean_proxy": _round(metric(sample, "sentence_word_mean_proxy") - metric(baseline, "sentence_word_mean_proxy")),
            "uppercase_fraction_of_letters": _round(metric(sample, "uppercase_fraction_of_letters") - metric(baseline, "uppercase_fraction_of_letters")),
            "digit_fraction_of_characters": _round(metric(sample, "digit_fraction_of_characters") - metric(baseline, "digit_fraction_of_characters")),
        },
        "prohibited_interpretations": [
            "No authorship, identity, customer profile, psychological trait, health, capability, intent, or crime-certainty inference is made.",
        ],
    }


def _bounded_json_shape(value: object) -> bool:
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            return False
        if type(current) is dict:
            if len(current) > _MAX_JSON_NODES:
                return False
            for key, item in current.items():
                if type(key) is not str or len(key) > 256:
                    return False
                pending.append((item, depth + 1))
        elif type(current) is list:
            if len(current) > _MAX_JSON_NODES:
                return False
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is str and len(current) > 4096:
            return False
    return True


def _strict_json(content: bytes, source_id: str) -> dict[str, object]:
    decoded = _validate_plaintext_bytes(content, MAX_LAB_BYTES, source_id)
    try:
        value = json.loads(decoded, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ForensicInputError(f"{source_id} is not a bounded JSON object") from exc
    if type(value) is not dict or not _bounded_json_shape(value):
        raise ForensicInputError(f"{source_id} is not a bounded JSON object")
    return value


def _fixed_bool(value: object) -> bool | None:
    """Only literal booleans are observations; absent/invalid flags are unknown."""
    return value if type(value) is bool else None


def _nested_flags(value: object, names: Sequence[str]) -> dict[str, bool | None]:
    source = value if type(value) is dict else {}
    return {name: _fixed_bool(source.get(name)) for name in names}


def sanitize_lab_report(content: bytes) -> dict[str, object]:
    """Allowlist fixed flags from known local-lab report shapes.

    A selected file can be forged by any customer.  Its format match and boolean
    values are therefore preserved only as *unverified supplied input*, never as
    an independent attestation or activation signal.
    """
    report = _strict_json(content, "lab_report")
    supplied_format = report.get("format")
    if type(supplied_format) is not str or supplied_format not in {"trusted_software_vm_lab_v1", "backup_layer_smoke_v1", "resource_boundary_v1"}:
        raise ForensicInputError("lab_report format is not an accepted local-lab shape")
    common = {
        "physical_hardware_tested", "kvm_isolation_tested", "hostile_guest_executed", "customer_data_used",
        "backend_ready_for_deployment", "automatic_failover_authorized", "runtime_vm_boot_tested",
        "vm_escape_tested", "openterface_hardware_tested", "hid_control_authorized",
    }
    selected = {name: _fixed_bool(report.get(name)) for name in sorted(common) if name in report or name in {
        "backend_ready_for_deployment", "automatic_failover_authorized"
    }}
    result: dict[str, object] = {
        "format": supplied_format,
        "trust_provenance": "UNVERIFIED_INPUT",
        "independent_attestation": False,
        "reported_status": _fixed_bool(report.get("passed")),
        "fixed_boolean_flags": selected,
        "activation_performed": False,
        "deployment_authorized": False,
    }
    if supplied_format == "trusted_software_vm_lab_v1":
        result["software_tpm_fixed_flags"] = _nested_flags(report.get("software_tpm"), (
            "passed", "startup_and_capabilities", "pcr16_extend_changes_value", "pcr16_reset_restores_value",
            "physical_tpm_tested", "guest_tpm_device_attachment_tested", "measured_guest_boot_or_attestation_tested",
            "state_retained",
        ))
        result["offline_snapshot_fixed_flags"] = _nested_flags(report.get("offline_disk_snapshot"), (
            "passed", "snapshot_created", "changed_data_verified", "restored_data_verified", "snapshot_deleted",
            "image_integrity_check", "live_guest_checkpoint_tested", "tpm_nvram_atomic_recovery_tested",
            "customer_disk_accessed", "image_retained",
        ))
    elif supplied_format == "backup_layer_smoke_v1":
        result["backup_smoke_fixed_flags"] = {
            "source_files_unchanged_during_checks": _fixed_bool(report.get("source_files_unchanged_during_checks")),
            "customer_data_used": _fixed_bool(report.get("customer_data_used")),
            "runtime_vm_boot_tested": _fixed_bool(report.get("runtime_vm_boot_tested")),
        }
    else:
        states = report.get("status") if type(report.get("status")) is dict else {}
        allowed = {"declared", "verified_local_readback", "not_verified"}
        result["reported_resource_controls"] = {
            name: states.get(name) if type(states.get(name)) is str and states.get(name) in allowed else "unknown"
            for name in ("cpu", "mem", "io", "gpu")
        }
        result["resource_control_notice"] = "Supplied declarations only; this report did not verify kernel enforcement or GPU policy. Pressure is a review signal, not evidence of malicious intent."
    return result


def _audit_summary(content: bytes) -> dict[str, object]:
    """Use only the existing pure byte summary API and emit fixed aggregate fields."""
    _validate_plaintext_bytes(content, MAX_AUDIT_BYTES, "audit")
    analyzer: Callable[[bytes], object] = getattr(operations, "analyze_audit_bytes", operations.build_operations_summary_bytes)
    # Bind before invocation so an incompatible future API fails without guessing
    # arguments or falling back to a file-reading function.
    try:
        inspect.signature(analyzer).bind(content)
    except (TypeError, ValueError) as exc:
        raise ForensicInputError("local audit byte-summary API has an incompatible signature") from exc
    raw = analyzer(content)
    if type(raw) is not dict:
        raise ForensicInputError("local audit byte-summary API returned an invalid summary")
    audit = raw.get("audit") if type(raw.get("audit")) is dict else {}
    classifications = raw.get("classification_counts") if type(raw.get("classification_counts")) is dict else {}
    discarded = audit.get("discarded_records") if type(audit.get("discarded_records")) is dict else {}
    allowed_classifications = ("connection_only", "probe_like", "burst_pattern", "multi_command_pattern", "execution_related_text")
    return {
        "selected_source_label": "customer_selected_audit",
        "trust_provenance": "customer_supplied_unverified",
        "coverage": "provided_records_only_completeness_unknown",
        "input_bytes": _number(audit.get("input_bytes")),
        "physical_record_count": _number(audit.get("physical_records")),
        "accepted_record_count": _number(audit.get("accepted_records")),
        "discarded_record_count": sum(value for value in discarded.values() if type(value) is int and not isinstance(value, bool) and value >= 0),
        "session_count": _number(raw.get("session_count")),
        "fixed_classification_counts": {name: _number(classifications.get(name)) for name in allowed_classifications},
        "remote_ip_collection": "none",
        "timestamps": "supplied_claims_not_used_as_independent_time_evidence",
        "limitations": [
            "No raw commands, session identifiers, remote IP addresses, supplied timestamps, or audit text are emitted.",
            "Fixed classification counts describe supplied records only and do not establish a person, access, execution, impact, legal conclusion, or remote identity.",
            "Echoes and synthetic responses are not proof of unauthorized access.",
        ],
    }


def _source_specifications(text: str | None, baseline: str | None, audit: str | None, lab_report: str | None) -> list[dict[str, object]]:
    selected = (("text1", "text", text, MAX_TEXT_BYTES), ("baseline1", "baseline", baseline, MAX_TEXT_BYTES),
                ("audit1", "audit", audit, MAX_AUDIT_BYTES), ("lab_report1", "lab_report", lab_report, MAX_LAB_BYTES))
    result: list[dict[str, object]] = []
    used_paths: set[str] = set()
    for source_id, source_type, value, maximum in selected:
        if value is None:
            continue
        if type(value) is not str or not value:
            raise ForensicInputError(f"{source_id} path is required when selected")
        absolute = os.path.abspath(value)
        if len(absolute) > 4096 or "\x00" in absolute:
            raise ForensicInputError(f"{source_id} path is invalid")
        if absolute in used_paths:
            raise ForensicInputError("each selected input must be a distinct source file")
        used_paths.add(absolute)
        result.append({"source_id": source_id, "source_type": source_type, "path": absolute, "maximum": maximum})
    if not result:
        raise ForensicInputError("at least one selected input is required")
    return result


def authorization_scope_for_inputs(text: str | None = None, baseline: str | None = None, audit: str | None = None,
                                   lab_report: str | None = None, output_dir: str | None = None) -> tuple[AuthorizationScope, list[dict[str, object]]]:
    """Build an exact, bounded scope without opening any selected input."""
    if type(output_dir) is not str or not output_dir:
        raise ForensicInputError("a new output directory is required")
    output = os.path.abspath(output_dir)
    if len(output) > 4096 or "\x00" in output:
        raise ForensicInputError("output directory is invalid")
    specs = _source_specifications(text, baseline, audit, lab_report)
    scope_inputs = [{"path": item["path"], "type": item["source_type"]} for item in specs]
    canonical_inputs = _canonical(scope_inputs)
    if len(canonical_inputs) > 4096:
        raise ForensicInputError("selected input reference exceeds the authorization scope limit")
    scope_ref = sha256(canonical_inputs).hexdigest()
    return AuthorizationScope("customer_forensic_report", scope_ref, output), specs


def _checked_read(spec: Mapping[str, object], authorization: AuthorizationGrant, scope: AuthorizationScope) -> bytes:
    authorization.check(scope)
    path = spec.get("path")
    maximum = spec.get("maximum")
    source_id = spec.get("source_id")
    if type(path) is not str or type(maximum) is not int or type(source_id) is not str:
        raise ForensicInputError("invalid selected source specification")
    content = read_regular(path, maximum)
    authorization.check(scope)
    if len(content) > maximum:
        raise ForensicInputError(f"{source_id} exceeds its configured byte limit")
    return content


def _new_private_directory(output_dir: str, authorization: AuthorizationGrant, scope: AuthorizationScope) -> int:
    authorization.check(scope)
    try:
        before = os.lstat(output_dir)
    except FileNotFoundError:
        before = None
    if before is not None:
        raise ForensicInputError("output directory already exists; refusing overwrite")
    os.mkdir(output_dir, 0o700)
    info = os.lstat(output_dir)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ForensicInputError("new output directory did not meet private-directory requirements")
    return os.open(output_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))


def _write_new_file(directory_fd: int, name: str, content: bytes, created: set[str], authorization: AuthorizationGrant,
                    scope: AuthorizationScope) -> None:
    if name not in _OUTPUT_FILES:
        raise ForensicInputError("unsupported report artifact")
    authorization.check(scope)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    created.add(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    authorization.check(scope)


def _cleanup_created(output_dir: str, directory_fd: int | None, created: set[str], directory_created: bool) -> None:
    """Only remove fixed artifacts created by this invocation; never traverse."""
    if directory_fd is not None:
        for name in sorted(created, reverse=True):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass
    if directory_created:
        try:
            os.rmdir(output_dir)
        except OSError:
            pass


def _source_manifest_entry(spec: Mapping[str, object], content: bytes) -> dict[str, object]:
    return {
        "source_id": spec["source_id"],
        "source_type": spec["source_type"],
        "supplied_label": "customer_selected_" + str(spec["source_type"]),
        "sha256": sha256(content).hexdigest(),
        "byte_count": len(content),
        "trust_provenance": "customer_supplied_unverified_not_author_identity",
    }


def _references(entries: Sequence[Mapping[str, object]], types: set[str] | None = None) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for entry in entries:
        if types is None or entry.get("source_type") in types:
            source_id, digest = entry.get("source_id"), entry.get("sha256")
            if type(source_id) is str and type(digest) is str:
                result.append({"source_id": source_id, "whole_source_sha256": digest})
    return result


def _conclusion(statement: str, entries: Sequence[Mapping[str, object]], types: set[str] | None = None) -> dict[str, object]:
    return {
        "statement": statement,
        "ruleset_version": RULESET_VERSION,
        "source_references": _references(entries, types),
        "interpretation_boundary": "descriptive_observed_or_inferred_boundary_only",
    }


def _build_report(specs: Sequence[Mapping[str, object]], contents: Mapping[str, bytes], packet_id: str, generated_utc: str) -> dict[str, object]:
    sources = [_source_manifest_entry(spec, contents[str(spec["source_id"])]) for spec in specs]
    source_by_id = {str(item["source_id"]): item for item in sources}
    styles: dict[str, dict[str, object]] = {}
    if "text1" in contents:
        styles["text1"] = analyze_text(contents["text1"])
    if "baseline1" in contents:
        styles["baseline1"] = analyze_text(contents["baseline1"])
    technical: dict[str, object] = {"audit": None, "lab_report": None, "remote_ip_collection": "none"}
    if "audit1" in contents:
        technical["audit"] = _audit_summary(contents["audit1"])
    if "lab_report1" in contents:
        technical["lab_report"] = sanitize_lab_report(contents["lab_report1"])
    comparison = _baseline_comparison(styles["text1"], styles["baseline1"]) if {"text1", "baseline1"}.issubset(styles) else None
    counts = {kind: sum(entry["source_type"] == kind for entry in sources) for kind in ("text", "baseline", "audit", "lab_report")}
    conclusions = [
        _conclusion("Observed values are source-bounded descriptive aggregates, not a customer or author profile.", sources),
        _conclusion("All supplied records and lab reports remain unverified input; no independent attestation or activation occurred.", sources),
        _conclusion("No model was trained by these inputs, no policy changed, and VM deployment remains false.", sources),
    ]
    return {
        "format": REPORT_FORMAT,
        "packet_id": packet_id,
        "generated_utc": generated_utc,
        "ruleset_version": RULESET_VERSION,
        "source_counts": counts,
        "sources": sources,
        "observed_style_aggregates": styles,
        "baseline_comparison": comparison,
        "technical_section": technical,
        "conclusions": conclusions,
        "inferred_vs_observed": {
            "observed": "Only supplied byte hashes, bounded aggregate counts, fixed labels, and strict-boolean lab flags are represented.",
            "not_inferred": "No author identity, authorship match, customer psychology, disease, skill, intent, crime certainty, access, execution, or legal conclusion is inferred.",
        },
        "safety_state": {
            "automatic_actions": False,
            "network_calls": False,
            "supplied_content_executed": False,
            "model_trained_by_inputs": False,
            "policy_changed": False,
            "vm_deployment_authorized": False,
            "hidden_retention": False,
        },
    }


def _safe_int(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _style_row(style: object, metric: str) -> str:
    if type(style) is not dict:
        return "not supplied"
    value = style.get(metric)
    if type(value) in {int, float} and not isinstance(value, bool):
        return str(value)
    return "0"


def render_customer_markdown(report: Mapping[str, object]) -> str:
    """Render a fixed-label customer view containing no untrusted textual content."""
    packet_id = report.get("packet_id") if type(report.get("packet_id")) is str else "unknown"
    sources = report.get("sources") if type(report.get("sources")) is list else []
    styles = report.get("observed_style_aggregates") if type(report.get("observed_style_aggregates")) is dict else {}
    text_style = styles.get("text1") if type(styles) is dict else None
    baseline_style = styles.get("baseline1") if type(styles) is dict else None
    technical = report.get("technical_section") if type(report.get("technical_section")) is dict else {}
    audit = technical.get("audit") if type(technical) is dict and type(technical.get("audit")) is dict else None
    lab = technical.get("lab_report") if type(technical) is dict and type(technical.get("lab_report")) is dict else None
    lines = [
        "# Customer-selected forensic descriptive report",
        "",
        f"Packet ID: `{packet_id}`",
        f"Generated UTC: `{report.get('generated_utc', 'unknown')}`",
        "",
        "## Scope and interpretation boundary",
        "",
        "This local report describes only selected submitted bytes. It is not a customer profile, authorship result, identity determination, psychological assessment, legal conclusion, or evidence of intent, access, execution, or unauthorized activity.",
        "",
        "## Selected source ledger",
        "",
        "| Source ID | Type | SHA-256 | Bytes | Provenance |",
        "|---|---|---|---:|---|",
    ]
    for entry in sources:
        if type(entry) is not dict:
            continue
        source_id = entry.get("source_id") if type(entry.get("source_id")) is str else "unknown"
        source_type = entry.get("source_type") if type(entry.get("source_type")) is str else "unknown"
        digest = entry.get("sha256") if type(entry.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256")) else "unknown"
        byte_count = _safe_int(entry.get("byte_count"))
        lines.append(f"| {source_id} | {source_type} | `{digest}` | {byte_count} | supplied, unverified |")
    if len(lines) == 14:
        lines.append("| none | none | `unknown` | 0 | none |")
    lines += [
        "",
        "## Descriptive style aggregates",
        "",
        "| Fixed metric | Submitted text | Baseline text |",
        "|---|---:|---:|",
    ]
    for label, metric in (("Characters", "total_characters"), ("Words", "word_count"), ("Unique words", "unique_word_count"),
                          ("Type/token ratio", "type_token_ratio"), ("Hapax ratio", "hapax_ratio"),
                          ("Sentence-word mean proxy", "sentence_word_mean_proxy"), ("Repeated normalized bigram occurrences", "repeated_normalized_bigram_occurrences")):
        lines.append(f"| {label} | {_style_row(text_style, metric)} | {_style_row(baseline_style, metric)} |")
    lines += [
        "",
        "These are aggregate format proxies. Topic, quotation, language, and sample-length effects make baseline comparability unknown; no match score or identity inference is produced.",
        "",
        "## Technical selected-input counts",
        "",
    ]
    if type(audit) is dict:
        lines.extend([
            f"- Audit source label: `{audit.get('selected_source_label', 'customer_selected_audit')}` (supplied, unverified).",
            f"- Audit physical records: {_safe_int(audit.get('physical_record_count'))}; accepted records: {_safe_int(audit.get('accepted_record_count'))}; discarded records: {_safe_int(audit.get('discarded_record_count'))}; sessions: {_safe_int(audit.get('session_count'))}.",
            "- Remote IP collection: none. Supplied timestamps and any remote-address claims are not independently verified.",
        ])
    else:
        lines.append("- No selected audit was supplied.")
    if type(lab) is dict:
        fmt = lab.get("format") if lab.get("format") in {"trusted_software_vm_lab_v1", "backup_layer_smoke_v1", "resource_boundary_v1"} else "unknown"
        lines.append(f"- Lab-report format: `{fmt}`; provenance: `UNVERIFIED_INPUT`; independent attestation: false; deployment authorized: false.")
        controls = lab.get("reported_resource_controls")
        if type(controls) is dict:
            lines.append("- Resource status is supplied, not independently checked here: " + "; ".join(f"{name}={controls.get(name, 'unknown')}" for name in ("cpu", "mem", "io", "gpu")) + ".")
    else:
        lines.append("- No selected lab report was supplied.")
    lines += [
        "",
        "## Defensive resource boundary",
        "",
        "CPU/memory/PID and device-specific I/O limits are intended to protect the customer's workload and availability. This report does not apply or independently verify them. The echo grants no GPU workload; GPU timeslicing and side-channel isolation are not claimed. Missing enforcement is unknown. Throttling, contention and baseline deviations require investigation and are not proof of mining, cracking, exfiltration or malicious intent.",
        "",
        "## Safety state",
        "",
        "No supplied content was executed. No cloud call, service launch, automatic action, policy change, model training, hidden retention, or VM deployment authorization occurred. Synthetic echoes are not proof of unauthorized access.",
        "",
        "A separately retained manifest SHA-256 can detect later alteration of this packet. It does not establish an author, customer identity, source authenticity, or compatibility with the existing incident-packet verifier.",
    ]
    return "\n".join(lines) + "\n"


def create_customer_forensic_report(*, text: str | None = None, baseline: str | None = None, audit: str | None = None,
                                    lab_report: str | None = None, output_dir: str, authorization: AuthorizationGrant | None,
                                    scope: AuthorizationScope | None) -> dict[str, object]:
    """Read selected files once, write a new private report packet, and return its pin.

    A fresh exact scope is mandatory.  On a revoked, expired, stale, wrong, or
    interrupted grant, only artifacts this call created are removed and the call
    fails closed.
    """
    expected_scope, specs = authorization_scope_for_inputs(text, baseline, audit, lab_report, output_dir)
    if type(authorization) is not AuthorizationGrant or type(scope) is not AuthorizationScope:
        raise AuthorizationError("fresh customer forensic report authorization required")
    if scope != expected_scope:
        raise AuthorizationError("authorization scope does not match selected inputs and new output directory")
    directory_fd: int | None = None
    directory_created = False
    created: set[str] = set()
    try:
        authorization.begin(scope)
        directory_fd = _new_private_directory(scope.output_ref, authorization, scope)
        directory_created = True
        contents: dict[str, bytes] = {}
        for spec in specs:
            source_id = str(spec["source_id"])
            content = _checked_read(spec, authorization, scope)
            contents[source_id] = content
            if sum(len(item) for item in contents.values()) > MAX_TOTAL_BYTES:
                raise ForensicInputError("selected inputs exceed the 2 MiB combined limit")
        authorization.check(scope)
        packet_id = secrets.token_hex(16)
        generated_utc = _utc_now()
        report = _build_report(specs, contents, packet_id, generated_utc)
        report_bytes = _canonical(report) + b"\n"
        markdown_bytes = render_customer_markdown(report).encode("utf-8")
        _write_new_file(directory_fd, _ARTIFACTS[0], report_bytes, created, authorization, scope)
        _write_new_file(directory_fd, _ARTIFACTS[1], markdown_bytes, created, authorization, scope)
        manifest = {
            "format": MANIFEST_FORMAT,
            "packet_id": packet_id,
            "generated_utc": generated_utc,
            "ruleset_version": RULESET_VERSION,
            "source_counts": report["source_counts"],
            "sources": report["sources"],
            "artifacts": [
                {"name": _ARTIFACTS[0], "sha256": sha256(report_bytes).hexdigest(), "byte_count": len(report_bytes)},
                {"name": _ARTIFACTS[1], "sha256": sha256(markdown_bytes).hexdigest(), "byte_count": len(markdown_bytes)},
            ],
            "integrity_notice": "A separately retained manifest SHA-256 can detect alteration; it is not cryptographic identity or source-authenticity proof.",
            "existing_incident_packet_verifier_compatible": False,
            "safety_state": report["safety_state"],
        }
        manifest_bytes = _canonical(manifest) + b"\n"
        _write_new_file(directory_fd, _OUTPUT_FILES[-1], manifest_bytes, created, authorization, scope)
        authorization.check(scope)
        return {
            "output_dir": scope.output_ref,
            "manifest_sha256": sha256(manifest_bytes).hexdigest(),
            "packet_id": packet_id,
            "source_counts": report["source_counts"],
            "ruleset_version": RULESET_VERSION,
        }
    except BaseException:
        _cleanup_created(scope.output_ref, directory_fd, created, directory_created)
        directory_fd = None
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        authorization.revoke()


def verify_packet_manifest(manifest: bytes | Mapping[str, object], *, expected_manifest_sha256: str,
                           artifacts: Mapping[str, bytes] | None = None) -> dict[str, object]:
    """Purely verify a report manifest against an externally retained hash pin.

    ``artifacts`` may contain the two emitted artifact byte strings.  This helper
    does no filesystem, network, authorization, or identity operation.  A correct
    pin detects an altered manifest; artifact hashes additionally detect altered
    supplied artifact bytes.  Neither property authenticates any person or input.
    """
    if type(expected_manifest_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256):
        raise ForensicInputError("expected manifest SHA-256 must be lowercase hexadecimal")
    if isinstance(manifest, bytes):
        raw = manifest
        parsed = _strict_json(manifest.rstrip(b"\n"), "manifest")
    elif type(manifest) is dict:
        parsed = dict(manifest)
        raw = _canonical(parsed)
    else:
        raise ForensicInputError("manifest must be bytes or an object")
    if sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ForensicInputError("manifest hash does not match the separately retained pin")
    if parsed.get("format") != MANIFEST_FORMAT or parsed.get("existing_incident_packet_verifier_compatible") is not False:
        raise ForensicInputError("manifest has an unsupported format")
    listed = parsed.get("artifacts")
    if type(listed) is not list or len(listed) != len(_ARTIFACTS):
        raise ForensicInputError("manifest artifact list is invalid")
    names = [entry.get("name") for entry in listed if type(entry) is dict]
    if any(type(name) is not str for name in names) or len(names) != len(_ARTIFACTS) or set(names) != set(_ARTIFACTS):
        raise ForensicInputError("manifest must list each fixed artifact exactly once")
    status: dict[str, bool] = {}
    for entry in listed:
        if type(entry) is not dict or entry.get("name") not in _ARTIFACTS or type(entry.get("sha256")) is not str or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ForensicInputError("manifest artifact entry is invalid")
        name = str(entry["name"])
        if artifacts is not None:
            candidate = artifacts.get(name)
            status[name] = isinstance(candidate, bytes) and sha256(candidate).hexdigest() == entry["sha256"]
    if artifacts is not None and set(artifacts) != set(_ARTIFACTS):
        raise ForensicInputError("artifact mapping must contain only the fixed report artifacts")
    return {
        "verified": not status or all(status.values()),
        "manifest_pin_verified": True,
        "artifact_hashes_verified": status,
        "verification_scope": "local_packet_integrity_only",
        "source_authenticity": "unverified",
        "identity_proof": False,
        "existing_incident_packet_verifier_compatible": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create one new local descriptive report packet from explicitly selected customer inputs; no execution, cloud call, or automatic action.",
        allow_abbrev=False,
    )
    parser.add_argument("--text", help="explicit UTF-8 selected plaintext sample (maximum 256 KiB)")
    parser.add_argument("--baseline", help="explicit distinct UTF-8 baseline sample (maximum 256 KiB)")
    parser.add_argument("--audit", help="explicit local UTF-8 JSONL audit (maximum 1 MiB)")
    parser.add_argument("--lab-report", help="explicit local UTF-8 JSON lab report (maximum 64 KiB)")
    parser.add_argument("--output-dir", required=True, help="new private output directory; existing paths are refused")
    parser.add_argument("--consent", action="store_true", help="fresh permission for precisely these selected paths and this new output directory")
    args = parser.parse_args(argv)
    try:
        scope, _specs = authorization_scope_for_inputs(args.text, args.baseline, args.audit, args.lab_report, args.output_dir)
    except (ForensicInputError, ValueError) as exc:
        print(f"Input selection rejected: {exc}", file=sys.stderr)
        return 2
    grant = request_authorization(scope, consent=args.consent)
    if grant is None:
        print("Permission required; no selected input was read and no report was created.", file=sys.stderr)
        return 2
    try:
        with cancellation_guard(grant):
            result = create_customer_forensic_report(
                text=args.text, baseline=args.baseline, audit=args.audit, lab_report=args.lab_report,
                output_dir=args.output_dir, authorization=grant, scope=scope,
            )
        print("Created a new local descriptive packet. Preserve this manifest SHA-256 separately: " + str(result["manifest_sha256"]))
        return 0
    except (AuthorizationError, ForensicInputError, OSError, ValueError, UnicodeError, RecursionError, KeyboardInterrupt):
        print("Authorization, selected input, or private export failed; created partial outputs were removed where possible. No action was taken.", file=sys.stderr)
        return 2
    finally:
        grant.revoke()


if __name__ == "__main__":
    raise SystemExit(main())
