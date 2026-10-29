"""Offline, low-confidence typosquatting heuristics for supplied names only.

The checks here do not query DNS, package indexes, registries, public-suffix data,
or the operating system.  A string similarity or Unicode lookalike result is a
review cue, not proof of impersonation, maliciousness, ownership, or identity.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata

MAX_NAMES = 1_000
MAX_DOMAIN_LENGTH = 253
MAX_PACKAGE_LENGTH = 128
MAX_PAIR_COMPARISONS = 10_000
_NEAR_DISTANCE = 2

_PACKAGE_SEPARATORS = re.compile(r"[-_.]+")

# A deliberately small, transparent collection of common ASCII-confusable Greek
# and Cyrillic letters.  It detects some high-value review cases without claiming a
# complete Unicode confusables implementation (which is not in the stdlib).
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "А": "a", "α": "a", "Α": "a",
        "Ь": "b", "в": "b", "Β": "b",
        "с": "c", "С": "c", "ϲ": "c",
        "ԁ": "d",
        "е": "e", "Е": "e", "Ε": "e", "ε": "e",
        "ғ": "f",
        "һ": "h", "Η": "h",
        "і": "i", "І": "i", "Ι": "i", "ι": "i", "ӏ": "l",
        "ј": "j", "Ј": "j",
        "Κ": "k", "κ": "k",
        "ⅼ": "l",
        "М": "m", "Μ": "m",
        "Ν": "n", "ո": "n",
        "о": "o", "О": "o", "ο": "o", "Ο": "o",
        "р": "p", "Р": "p", "ρ": "p", "Ρ": "p",
        "ԛ": "q",
        "ѕ": "s", "Ѕ": "s",
        "Τ": "t", "τ": "t",
        "υ": "u", "Υ": "u",
        "ν": "v",
        "ԝ": "w",
        "х": "x", "Х": "x", "χ": "x", "Χ": "x",
        "у": "y", "У": "y", "γ": "y", "Υ": "y",
        "Ζ": "z",
    }
)

_LIMITATIONS = [
    "Offline heuristic only: a finding does not establish impersonation, maliciousness, ownership, or attacker identity.",
    "Domain processing uses local IDNA conversion only; it performs no DNS, registration, package-index, ownership, or public-suffix checks.",
    "Unicode lookalike detection is intentionally incomplete and can produce false positives; it is not proof of a threat.",
]


@dataclass(frozen=True)
class _Name:
    original: str
    canonical: str
    skeleton: str
    unicode_form: bool
    separatorless: str


def check_names(observed: list[str], trusted: list[str], kind: str = "domain") -> dict:
    """Check supplied names against supplied trusted names without any network use.

    ``kind`` is ``"domain"`` or ``"package"``.  Inputs are limited to 1,000
    names per list, 253 characters per domain, and 128 characters per package.
    Domain names are NFKC/casefolded and locally IDNA-canonicalized; package names
    are NFKC/casefolded and normalized with the conventional ``-``, ``_``, and ``.``
    separator equivalence.

    Findings are intentionally always ``confidence: "low"``.  Exact trusted names
    are excluded.  A trusted domain's proper subdomains are excluded, while a name
    that begins with ``trusted + '.'`` is labelled ``brand_boundary_mismatch`` only
    when that literal label boundary exists.  No public-suffix assumption is made.
    At most 10,000 non-exact observed/trusted pairs are considered; if that budget
    is reached, the result explicitly reports that it is incomplete.
    """
    if kind not in {"domain", "package"}:
        raise ValueError("kind must be 'domain' or 'package'")
    _validate_name_list(observed, "observed")
    _validate_name_list(trusted, "trusted")

    observed_names = [_make_name(name, kind) for name in observed]
    trusted_names = [_make_name(name, kind) for name in trusted]
    trusted_by_canonical: dict[str, list[_Name]] = {}
    for item in trusted_names:
        trusted_by_canonical.setdefault(item.canonical, []).append(item)

    findings: list[dict] = []
    warnings: list[str] = []
    warning_set: set[str] = set()
    compared_pairs = 0
    incomplete = False

    def warn(message: str) -> None:
        if message not in warning_set:
            warning_set.add(message)
            warnings.append(message)

    for candidate in observed_names:
        exact_matches = trusted_by_canonical.get(candidate.canonical, [])
        if exact_matches:
            for target in exact_matches:
                if candidate.original == target.original:
                    continue
                if candidate.unicode_form or target.unicode_form:
                    _append_finding(
                        findings,
                        candidate,
                        target,
                        "unicode_lookalike",
                        0,
                    )
                elif kind == "package" and candidate.separatorless == target.separatorless:
                    # PEP 503-style separator normalization is routine.  Retain a
                    # review warning, but deliberately do not flag it as suspicious.
                    warn(
                        "Package-name normalization collision was treated as benign; separator differences alone are not a suspicious finding."
                    )
            continue

        for target in trusted_names:
            if compared_pairs >= MAX_PAIR_COMPARISONS:
                incomplete = True
                break
            compared_pairs += 1
            if kind == "domain":
                # ``api.example.com`` is a subdomain of ``example.com`` and should
                # not be called squatting.  ``example.com.evil.tld`` instead begins
                # with the trusted name at a true dot boundary and is review-worthy.
                if candidate.canonical.endswith("." + target.canonical):
                    continue
                if candidate.canonical.startswith(target.canonical + "."):
                    _append_finding(
                        findings,
                        candidate,
                        target,
                        "brand_boundary_mismatch",
                        len(candidate.canonical) - len(target.canonical),
                    )
                    continue

            if (
                (candidate.unicode_form or target.unicode_form)
                and candidate.skeleton == target.skeleton
            ):
                _append_finding(findings, candidate, target, "unicode_lookalike", 0)
                continue

            if len(candidate.canonical) < 3 or len(target.canonical) < 3:
                continue
            if abs(len(candidate.canonical) - len(target.canonical)) > _NEAR_DISTANCE:
                continue
            if not _may_share_bigram(candidate.canonical, target.canonical):
                continue
            distance = _damerau_distance_at_most_two(candidate.canonical, target.canonical)
            if distance is not None and distance > 0:
                _append_finding(findings, candidate, target, "near_trusted_name", distance)
        if incomplete:
            break

    if incomplete:
        warn(
            "Typosquat comparison budget reached; results are incomplete after 10000 observed/trusted pairs."
        )

    findings.sort(
        key=lambda item: (item["observed"], item["trusted"], item["reason"], item["distance"])
    )
    return {
        "findings": findings,
        "checked_count": len(observed_names),
        "compared_pairs": compared_pairs,
        "complete": not incomplete,
        "warnings": warnings,
        "limitations": list(_LIMITATIONS),
        "simulation": False,
    }


def _validate_name_list(values: list[str], label: str) -> None:
    if not isinstance(values, list):
        raise TypeError(f"{label} must be a list of strings")
    if len(values) > MAX_NAMES:
        raise ValueError(f"{label} exceeds the {MAX_NAMES}-name limit")
    if any(not isinstance(value, str) for value in values):
        raise TypeError(f"{label} must contain only strings")


def _make_name(value: str, kind: str) -> _Name:
    max_length = MAX_DOMAIN_LENGTH if kind == "domain" else MAX_PACKAGE_LENGTH
    if not value or len(value) > max_length:
        raise ValueError(f"{kind} name is empty or exceeds its maximum length")

    normalised = unicodedata.normalize("NFKC", value).casefold()
    if not normalised:
        raise ValueError(f"{kind} name is empty after normalization")

    if kind == "domain":
        canonical, display = _canonical_domain(normalised)
        if len(canonical) > MAX_DOMAIN_LENGTH:
            raise ValueError("domain name exceeds the 253-character IDNA limit")
        separatorless = canonical.replace(".", "")
        unicode_form = any(ord(char) > 127 for char in value) or "xn--" in canonical.split(".")
    else:
        canonical = _PACKAGE_SEPARATORS.sub("-", normalised)
        if not canonical:
            raise ValueError("package name is empty after normalization")
        if len(canonical) > MAX_PACKAGE_LENGTH:
            raise ValueError("package name exceeds the 128-character normalized limit")
        display = normalised
        separatorless = _PACKAGE_SEPARATORS.sub("", normalised)
        unicode_form = any(ord(char) > 127 for char in value)

    return _Name(
        original=value,
        canonical=canonical,
        skeleton=_confusable_skeleton(display, kind),
        unicode_form=unicode_form,
        separatorless=separatorless,
    )


def _canonical_domain(value: str) -> tuple[str, str]:
    """Return local IDNA ASCII form plus a Unicode form for skeleton comparison."""
    # A single terminal root dot does not change the DNS name.  No resolver is ever
    # involved; this is solely local string canonicalization.
    if value.endswith("."):
        value = value[:-1]
    if not value or any(not label for label in value.split(".")):
        raise ValueError("domain name must contain non-empty labels")

    ascii_labels: list[str] = []
    display_labels: list[str] = []
    for label in value.split("."):
        try:
            ascii_label = label.encode("idna").decode("ascii")
            # Decoding the just-produced ASCII label lets an input already written
            # as xn-- punycode participate in the same local lookalike heuristic.
            display_label = ascii_label.encode("ascii").decode("idna")
        except UnicodeError as exc:
            raise ValueError("domain name cannot be IDNA-canonicalized") from exc
        if not ascii_label or len(ascii_label) > 63:
            raise ValueError("domain name contains an invalid IDNA label")
        ascii_labels.append(ascii_label)
        display_labels.append(display_label)
    return ".".join(ascii_labels), ".".join(display_labels)


def _confusable_skeleton(value: str, kind: str) -> str:
    skeleton = unicodedata.normalize("NFKC", value).casefold().translate(_CONFUSABLES)
    if kind == "package":
        return _PACKAGE_SEPARATORS.sub("-", skeleton)
    return skeleton


def _append_finding(
    findings: list[dict], candidate: _Name, target: _Name, reason: str, distance: int
) -> None:
    findings.append(
        {
            "observed": candidate.original,
            "trusted": target.original,
            "reason": reason,
            "distance": distance,
            "confidence": "low",
            "simulation": False,
        }
    )


def _may_share_bigram(left: str, right: str) -> bool:
    """Cheap, safe candidate filter for long strings before bounded edit distance.

    At distance at most two, two strings of length at least ten retain an unchanged
    adjacent-character pair.  Shorter names bypass the filter to avoid reducing
    coverage where every pair can be affected by two edits.
    """
    if min(len(left), len(right)) < 10:
        return True
    left_bigrams = {left[index : index + 2] for index in range(len(left) - 1)}
    return any(right[index : index + 2] in left_bigrams for index in range(len(right) - 1))


def _damerau_distance_at_most_two(left: str, right: str) -> int | None:
    """Return optimal-string-alignment distance only when it is at most two.

    The narrow band gives bounded work for a near-name check and includes one or
    two adjacent transpositions.  It is sufficient for the deliberately small
    review threshold; this is not a general-purpose full-distance API.
    """
    if abs(len(left) - len(right)) > _NEAR_DISTANCE:
        return None
    if left == right:
        return 0

    width = len(right)
    limit = _NEAR_DISTANCE + 1
    previous_previous: list[int] | None = None
    previous = list(range(width + 1))

    for left_index, left_char in enumerate(left, start=1):
        current = [limit] * (width + 1)
        current[0] = left_index if left_index <= _NEAR_DISTANCE else limit
        start = max(1, left_index - _NEAR_DISTANCE)
        end = min(width, left_index + _NEAR_DISTANCE)
        row_min = current[0]
        for right_index in range(start, end + 1):
            substitution = previous[right_index - 1] + (left_char != right[right_index - 1])
            deletion = previous[right_index] + 1
            insertion = current[right_index - 1] + 1
            value = min(substitution, deletion, insertion)
            if (
                previous_previous is not None
                and left_index > 1
                and right_index > 1
                and left_char == right[right_index - 2]
                and left[left_index - 2] == right[right_index - 1]
            ):
                value = min(value, previous_previous[right_index - 2] + 1)
            current[right_index] = value
            row_min = min(row_min, value)
        if row_min > _NEAR_DISTANCE:
            return None
        previous_previous, previous = previous, current

    return previous[width] if previous[width] <= _NEAR_DISTANCE else None


__all__ = [
    "MAX_DOMAIN_LENGTH",
    "MAX_NAMES",
    "MAX_PACKAGE_LENGTH",
    "MAX_PAIR_COMPARISONS",
    "check_names",
]
