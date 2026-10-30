"""Fail-closed static admission for two deliberately non-deploying backup profiles.

The module has no network, subprocess, Docker, libvirt, KVM, socket, image, or file
operations.  Its result is a bounded structural-schema review plus an externally
supplied exact-document SHA-256 comparison, never an attestation of image content,
image provenance, host policy, bootability, or runtime isolation.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import re
from typing import Any, Final
from xml.etree import ElementTree as ET

__all__ = [
    "MAX_CONFIG_BYTES",
    "make_libvirt_candidate",
    "make_pc_free_candidate",
    "review_libvirt",
    "review_pc_free",
]

MAX_CONFIG_BYTES: Final = 64 * 1024
_API_VERSION: Final = "backup-admission/v2"
_HASH_RE: Final = re.compile(r"[a-f0-9]{64}\Z")
_SESSION_ID_RE: Final = re.compile(r"[a-f0-9]{16}\Z")
_PC_FREE_IMAGE_RE: Final = re.compile(
    r"(?:ghcr\.io/dockur/windows|docker\.io/dockurr/windows)@sha256:[a-f0-9]{64}\Z"
)

# Only documented upstream settings needed for the profile are emitted.  SHARED is
# deliberately absent: it was not supported by the environment reference reviewed
# for this profile, so it is not invented.  No credential, OEM, ISO, DOMAIN,
# COMMAND, ARGUMENTS, URL, or similar setting is admitted.
_PC_FREE_ENVIRONMENT: Final[dict[str, str]] = {
    "NETWORK": "N",
    "RAM_SIZE": "2G",
    "CPU_CORES": "2",
    "VERSION": "11",
}
_PC_FREE_TMPFS: Final[list[str]] = [
    "/run:rw,noexec,nosuid,nodev,size=64m",
    "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "/var/tmp:rw,noexec,nosuid,nodev,size=64m",
]


class _DuplicateKey(ValueError):
    pass


class _DepthExceeded(ValueError):
    pass


class _NodeLimitExceeded(ValueError):
    pass


class _InvalidNumber(ValueError):
    pass


class _SchemaRejected(ValueError):
    pass


class _BoundedTreeBuilder(ET.TreeBuilder):
    """Stop XML tree construction before excessive nesting or node count."""

    def __init__(self) -> None:
        super().__init__(insert_comments=True, insert_pis=True)
        self._depth = 0
        self._nodes = 0

    def start(self, tag: str, attrs: dict[str, str]) -> Any:
        self._depth += 1
        self._nodes += 1
        if self._depth > 12:
            raise _DepthExceeded()
        if self._nodes > 64:
            raise _NodeLimitExceeded()
        return super().start(tag, attrs)

    def end(self, tag: str) -> Any:
        result = super().end(tag)
        self._depth -= 1
        return result


def _result(code: str, config_sha256: str | None, expected_sha256: str | None) -> dict[str, Any]:
    """The source-free, fixed result contract shared by both profile reviewers."""
    return {
        "admission_code": code,
        "api_version": _API_VERSION,
        "claim_check": "STATIC_SCHEMA_ONLY",
        "config_sha256": config_sha256,
        "expected_config_sha256": expected_sha256,
        "machine_actions": [],
        "profile_only": True,
        "ready_for_deployment": False,
        "runtime_checks": "unknown",
        "source_authority": "unverified",
    }


def _validated_expected(expected_sha256: object) -> str | None:
    if type(expected_sha256) is str and _HASH_RE.fullmatch(expected_sha256) is not None:
        return expected_sha256
    return None


def _pin_raw(raw: object, expected_sha256: object) -> tuple[dict[str, Any] | None, bytes | None, str | None, str | None]:
    """Validate the external pin before attempting to parse untrusted bytes."""
    expected = _validated_expected(expected_sha256)
    if expected is None:
        return _result("EXPECTED_CONFIG_SHA256_INVALID", None, None), None, None, None
    if type(raw) is not bytes:
        return _result("INPUT_TYPE_INVALID", None, expected), None, None, expected
    if len(raw) > MAX_CONFIG_BYTES:
        return _result("INPUT_TOO_LARGE", None, expected), None, None, expected
    digest = sha256(raw).hexdigest()
    if not hmac.compare_digest(digest, expected):
        # Pin mismatch must precede decoding, JSON/XML parsing, or tree processing.
        return _result("PIN_MISMATCH", digest, expected), None, digest, expected
    return None, raw, digest, expected


# ----- PC-Free JSON Compose profile -------------------------------------------------

def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _bounded_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 9:
        raise _InvalidNumber()
    return int(value)


def _reject_float(_value: str) -> None:
    raise _InvalidNumber()


def _reject_constant(_value: str) -> None:
    raise _InvalidNumber()


def _check_json_depth(value: Any, depth: int = 1) -> None:
    if depth > 12:
        raise _DepthExceeded()
    if type(value) is dict:
        for child in value.values():
            _check_json_depth(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _check_json_depth(child, depth + 1)


def _expect_keys(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise _SchemaRejected()
    return value


def _expect_string(value: Any) -> str:
    if type(value) is not str or "\x00" in value:
        raise _SchemaRejected()
    return value


def _pc_free_volume_name(session_id: str) -> str:
    return f"pcfree_backup_{session_id}"


def _validate_pc_free_document(document: Any) -> None:
    """Accept only the generated grammar, apart from approved image and identity."""
    root = _expect_keys(document, {"services", "volumes"})
    services = _expect_keys(root["services"], {"windows"})
    volume_name = _pc_free_volume_name_from_document(root["volumes"])
    service = _expect_keys(services["windows"], {
        "image", "restart", "network_mode", "cap_drop", "security_opt", "devices",
        "read_only", "cpus", "mem_limit", "pids_limit", "logging", "environment",
        "volumes", "tmpfs", "stop_grace_period",
    })
    image = _expect_string(service["image"])
    if _PC_FREE_IMAGE_RE.fullmatch(image) is None:
        raise _SchemaRejected()
    if service["restart"] != "no" or service["network_mode"] != "none":
        raise _SchemaRejected()
    if service["cap_drop"] != ["ALL"] or service["security_opt"] != ["no-new-privileges:true"]:
        raise _SchemaRejected()
    if service["devices"] != ["/dev/kvm:/dev/kvm"] or service["read_only"] is not True:
        raise _SchemaRejected()
    if service["cpus"] != "2" or service["mem_limit"] != "3g" or service["pids_limit"] != 256:
        raise _SchemaRejected()
    logging = _expect_keys(service["logging"], {"driver", "options"})
    if logging["driver"] != "local" or logging["options"] != {"max-file": "1", "max-size": "10m"}:
        raise _SchemaRejected()
    if service["environment"] != _PC_FREE_ENVIRONMENT:
        raise _SchemaRejected()
    if service["tmpfs"] != _PC_FREE_TMPFS or service["stop_grace_period"] != "10s":
        raise _SchemaRejected()
    if type(service["volumes"]) is not list or len(service["volumes"]) != 1:
        raise _SchemaRejected()
    mount = _expect_keys(service["volumes"][0], {"type", "source", "target", "volume"})
    volume_options = _expect_keys(mount["volume"], {"nocopy"})
    if (mount["type"] != "volume" or mount["source"] != volume_name
            or mount["target"] != "/storage" or volume_options["nocopy"] is not True):
        raise _SchemaRejected()


def _pc_free_volume_name_from_document(value: Any) -> str:
    if type(value) is not dict or len(value) != 1:
        raise _SchemaRejected()
    volume_name = next(iter(value))
    if type(volume_name) is not str or not volume_name.startswith("pcfree_backup_"):
        raise _SchemaRejected()
    session_id = volume_name.removeprefix("pcfree_backup_")
    if _SESSION_ID_RE.fullmatch(session_id) is None or value != {volume_name: {}}:
        raise _SchemaRejected()
    return volume_name


def make_pc_free_candidate(image_digest: str, session_id: str) -> str:
    """Return JSON text for one PC-Free review candidate without I/O or deployment."""
    if type(image_digest) is not str or _PC_FREE_IMAGE_RE.fullmatch(image_digest) is None:
        raise ValueError("image must be an allowlisted digest-pinned reference")
    if type(session_id) is not str or _SESSION_ID_RE.fullmatch(session_id) is None:
        raise ValueError("session id must be exactly 16 lowercase hexadecimal characters")
    volume_name = _pc_free_volume_name(session_id)
    document = {
        "services": {
            "windows": {
                "image": image_digest,
                "restart": "no",
                "network_mode": "none",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "devices": ["/dev/kvm:/dev/kvm"],
                "read_only": True,
                "cpus": "2",
                "mem_limit": "3g",
                "pids_limit": 256,
                "logging": {"driver": "local", "options": {"max-file": "1", "max-size": "10m"}},
                "environment": dict(_PC_FREE_ENVIRONMENT),
                "volumes": [{
                    "type": "volume", "source": volume_name, "target": "/storage",
                    "volume": {"nocopy": True},
                }],
                "tmpfs": list(_PC_FREE_TMPFS),
                "stop_grace_period": "10s",
            }
        },
        "volumes": {volume_name: {}},
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def review_pc_free(raw: bytes, expected_sha256: str) -> dict[str, Any]:
    """Review bounded Compose JSON as an exact, static PC-Free profile only."""
    early, pinned, digest, expected = _pin_raw(raw, expected_sha256)
    if early is not None:
        return early
    assert pinned is not None and digest is not None and expected is not None
    try:
        document = json.loads(
            pinned.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_int=_bounded_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey:
        return _result("JSON_DUPLICATE_KEY", digest, expected)
    except _InvalidNumber:
        return _result("JSON_NUMBER_INVALID", digest, expected)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, TypeError):
        return _result("JSON_INVALID", digest, expected)
    try:
        _check_json_depth(document)
        _validate_pc_free_document(document)
    except _DepthExceeded:
        return _result("JSON_DEPTH_EXCEEDED", digest, expected)
    except (KeyError, TypeError, ValueError, StopIteration):
        return _result("SCHEMA_REJECTED", digest, expected)
    return _result("STATIC_PROFILE_ACCEPTED", digest, expected)


# ----- Minimal offline libvirt profile ------------------------------------------------

def _libvirt_name(session_id: str) -> str:
    return f"cloudsentry-backup-{session_id}"


def _libvirt_disk_path(session_id: str) -> str:
    return f"/var/lib/libvirt/images/cloudsentry-backup-{session_id}.qcow2"


def _libvirt_element(session_id: str) -> ET.Element:
    domain = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(domain, "name").text = _libvirt_name(session_id)
    ET.SubElement(domain, "memory", {"unit": "MiB"}).text = "2048"
    ET.SubElement(domain, "currentMemory", {"unit": "MiB"}).text = "2048"
    ET.SubElement(domain, "vcpu", {"placement": "static"}).text = "2"
    cputune = ET.SubElement(domain, "cputune")
    ET.SubElement(cputune, "period").text = "100000"
    ET.SubElement(cputune, "quota").text = "100000"
    operating_system = ET.SubElement(domain, "os")
    ET.SubElement(operating_system, "type", {"arch": "x86_64", "machine": "q35"}).text = "hvm"
    ET.SubElement(domain, "on_poweroff").text = "destroy"
    ET.SubElement(domain, "on_reboot").text = "destroy"
    ET.SubElement(domain, "on_crash").text = "destroy"
    devices = ET.SubElement(domain, "devices")
    disk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
    ET.SubElement(disk, "driver", {"name": "qemu", "type": "qcow2"})
    ET.SubElement(disk, "source", {"file": _libvirt_disk_path(session_id)})
    ET.SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
    return domain


def make_libvirt_candidate(session_id: str) -> str:
    """Return fixed, offline libvirt domain XML text without I/O or provisioning."""
    if type(session_id) is not str or _SESSION_ID_RE.fullmatch(session_id) is None:
        raise ValueError("session id must be exactly 16 lowercase hexadecimal characters")
    return ET.tostring(_libvirt_element(session_id), encoding="unicode", short_empty_elements=True)


def _has_forbidden_xml_construct(raw: bytes) -> bool:
    # Candidate grammar has no declaration, DTD, entity, namespace, XInclude, PI,
    # comment, or CDATA.  Reject prior to XML construction rather than relying on
    # parser-specific entity behavior.
    lowered = raw.lower()
    return any(token in lowered for token in (
        b"<!doctype", b"<!entity", b"<?", b"<!--", b"<![cdata[", b"xmlns", b"xinclude", b"xi:",
    ))


def _normal_form(element: ET.Element) -> tuple[Any, ...]:
    """Compare exact grammar while tolerating only formatting whitespace/attr order."""
    if type(element.tag) is not str or "{" in element.tag or "}" in element.tag:
        raise _SchemaRejected()
    attributes: list[tuple[str, str]] = []
    for key, value in element.attrib.items():
        if type(key) is not str or type(value) is not str or "{" in key or "}" in key:
            raise _SchemaRejected()
        attributes.append((key, value))
    if element.tail is not None and not element.tail.isspace():
        raise _SchemaRejected()
    text = "" if element.text is None else element.text.strip()
    return (element.tag, tuple(sorted(attributes)), text, tuple(_normal_form(child) for child in element))


def _validate_xml_tree_bounds(root: ET.Element) -> None:
    def walk(element: ET.Element, depth: int) -> int:
        if depth > 12:
            raise _DepthExceeded()
        if type(element.tag) is not str:
            raise _SchemaRejected()
        count = 1
        for child in element:
            count += walk(child, depth + 1)
            if count > 64:
                raise _NodeLimitExceeded()
        return count
    walk(root, 1)


def _session_id_from_xml(root: ET.Element) -> str:
    # This extraction is only to build an expected grammar.  The values are never
    # returned.  Exact full-tree comparison below prevents a partial match.
    if root.tag != "domain":
        raise _SchemaRejected()
    name = root.find("name")
    if name is None or type(name.text) is not str or not name.text.startswith("cloudsentry-backup-"):
        raise _SchemaRejected()
    session_id = name.text.removeprefix("cloudsentry-backup-")
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        raise _SchemaRejected()
    return session_id


def review_libvirt(raw: bytes, expected_sha256: str) -> dict[str, Any]:
    """Review bounded libvirt XML as the exact minimal offline grammar only."""
    early, pinned, digest, expected = _pin_raw(raw, expected_sha256)
    if early is not None:
        return early
    assert pinned is not None and digest is not None and expected is not None
    try:
        pinned.decode("utf-8", errors="strict")
    except UnicodeError:
        return _result("XML_INVALID", digest, expected)
    if b"\x00" in pinned:
        return _result("XML_INVALID", digest, expected)
    if _has_forbidden_xml_construct(pinned):
        return _result("XML_FORBIDDEN_CONSTRUCT", digest, expected)
    try:
        parser = ET.XMLParser(target=_BoundedTreeBuilder())
        root = ET.fromstring(pinned, parser=parser)
    except _DepthExceeded:
        return _result("XML_DEPTH_EXCEEDED", digest, expected)
    except _NodeLimitExceeded:
        return _result("XML_NODE_LIMIT_EXCEEDED", digest, expected)
    except (ET.ParseError, UnicodeError, ValueError, TypeError, RecursionError):
        # Includes duplicate attributes and malformed/entity-bearing documents.
        return _result("XML_INVALID", digest, expected)
    try:
        _validate_xml_tree_bounds(root)
        session_id = _session_id_from_xml(root)
        expected_root = _libvirt_element(session_id)
        if _normal_form(root) != _normal_form(expected_root):
            raise _SchemaRejected()
    except _DepthExceeded:
        return _result("XML_DEPTH_EXCEEDED", digest, expected)
    except _NodeLimitExceeded:
        return _result("XML_NODE_LIMIT_EXCEEDED", digest, expected)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _result("SCHEMA_REJECTED", digest, expected)
    return _result("STATIC_PROFILE_ACCEPTED", digest, expected)
