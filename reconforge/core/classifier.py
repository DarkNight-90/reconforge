"""Deterministic, evidence-based operating-system classification."""

from collections.abc import Iterable
from dataclasses import dataclass
import json
from math import isfinite
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from .models import ConfidenceLevel, Evidence, Host, OSClassification, OSFamily, OSFingerprint, Service


class ClassifierConfigurationError(ValueError):
    """Raised when the classifier signature configuration is invalid."""


@dataclass(frozen=True)
class IndicatorRule:
    """One declarative case-insensitive substring matching rule."""

    family: OSFamily
    category: str
    pattern: str
    weight: float


DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parents[1] / "signatures" / "os_indicators.json"
_FAMILY_NAMES = MappingProxyType({"windows": OSFamily.WINDOWS, "unix": OSFamily.LINUX_UNIX})
_MEANINGFUL_SCORE = 1.0
_STRONG_EVIDENCE_WEIGHT = 5.0
_HIGH_SCORE = 10.0
_MEDIUM_SCORE = 4.0
_HIGH_MARGIN = 4.0
_MEDIUM_MARGIN = 2.0
_LOW_MARGIN = 1.0


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _read_signature_data(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ClassifierConfigurationError(f"unable to load signatures: {path}") from exc
    if not isinstance(data, dict):
        raise ClassifierConfigurationError("signature configuration must be an object")
    return data


def _rules_for_family(data: dict[str, Any], family_name: str, category: str) -> Iterable[IndicatorRule]:
    family_data = data.get(family_name)
    if not isinstance(family_data, dict):
        raise ClassifierConfigurationError(f"signature family must be an object: {family_name}")
    values = family_data.get(category, {})
    if not isinstance(values, dict):
        raise ClassifierConfigurationError(f"signature category must be an object: {family_name}.{category}")
    family = _FAMILY_NAMES[family_name]
    for pattern, weight in values.items():
        if not isinstance(pattern, str) or not pattern.strip():
            raise ClassifierConfigurationError("signature patterns must be non-empty strings")
        if not isinstance(weight, (int, float)) or isinstance(weight, bool) or not isfinite(weight) or weight < 0:
            raise ClassifierConfigurationError(f"signature weight must be a non-negative number: {pattern}")
        yield IndicatorRule(family, category, _normalize(pattern), float(weight))


def load_signatures(path: str | Path = DEFAULT_SIGNATURES_PATH) -> tuple[IndicatorRule, ...]:
    """Load and validate immutable classifier rules from JSON."""
    data = _read_signature_data(Path(path))
    if data.get("schema_version") != 1:
        raise ClassifierConfigurationError("unsupported signature schema_version")
    unknown_families = set(data) - {"schema_version", *_FAMILY_NAMES}
    if unknown_families:
        raise ClassifierConfigurationError(f"unsupported signature families: {sorted(unknown_families)}")
    rules = [
        rule
        for family_name in _FAMILY_NAMES
        for category in ("services", "products")
        for rule in _rules_for_family(data, family_name, category)
    ]
    return tuple(rules)


def _fingerprint_evidence(fingerprint: OSFingerprint) -> Evidence | None:
    text = _normalize(" ".join(part for part in (fingerprint.vendor, fingerprint.family) if part))
    if "windows" in text or "microsoft" in text:
        family = OSFamily.WINDOWS
    elif any(term in text for term in ("linux", "unix", "bsd")):
        family = OSFamily.LINUX_UNIX
    else:
        return None
    accuracy_text = f" accuracy={fingerprint.accuracy}" if fingerprint.accuracy is not None else ""
    details = (
        f"Nmap OS fingerprint: vendor={fingerprint.vendor} family={fingerprint.family} "
        f"generation={fingerprint.generation}{accuracy_text}"
    )
    weight = 5.0 if fingerprint.accuracy is None else min(10.0, max(1.0, 5.0 + fingerprint.accuracy / 20.0))
    return Evidence(
        source="nmap",
        indicator="os_fingerprint",
        value=fingerprint.family or fingerprint.vendor or "unknown",
        weight=weight,
        direction=family,
        details=details,
    )


class OSClassifier:
    """Classify a Host using raw Nmap and service observations."""

    def __init__(self, signatures_path: str | Path = DEFAULT_SIGNATURES_PATH) -> None:
        self._rules = load_signatures(signatures_path)

    def classify(self, host: Host) -> OSClassification:
        """Return a new classification without mutating the host observations."""
        evidence: list[Evidence] = []
        for fingerprint in host.os_fingerprints:
            item = _fingerprint_evidence(fingerprint)
            if item is not None:
                evidence.append(item)
        for service in host.services:
            evidence.extend(self._service_evidence(service))

        windows_score = sum(item.weight for item in evidence if item.direction is OSFamily.WINDOWS)
        unix_score = sum(item.weight for item in evidence if item.direction is OSFamily.LINUX_UNIX)
        family, confidence = self._decide(evidence, windows_score, unix_score)
        return OSClassification(
            family=family,
            confidence=confidence,
            evidence=tuple(evidence),
            windows_score=windows_score,
            unix_score=unix_score,
        )

    def _service_evidence(self, service: Service) -> tuple[Evidence, ...]:
        observations = (
            ("services", service.service_name, "service"),
            ("products", service.product, "product"),
            ("products", service.extra_info, "extra_info"),
        )
        evidence: list[Evidence] = []
        for category, value, source in observations:
            if not value:
                continue
            matches = [
                rule
                for rule in self._rules
                if rule.category == category and rule.pattern in _normalize(value)
            ]
            if not matches:
                continue
            rule = max(matches, key=lambda candidate: (candidate.weight, len(candidate.pattern)))
            evidence.append(
                Evidence(
                    source=source,
                    indicator=category[:-1],
                    value=value,
                    weight=rule.weight,
                    direction=rule.family,
                    details=f"Matched {rule.pattern} on {service.protocol}/{service.port}",
                )
            )
        return tuple(evidence)

    @staticmethod
    def _decide(
        evidence: tuple[Evidence, ...] | list[Evidence],
        windows_score: float,
        unix_score: float,
    ) -> tuple[OSFamily, ConfidenceLevel]:
        if max(windows_score, unix_score) < _MEANINGFUL_SCORE:
            return OSFamily.UNKNOWN, ConfidenceLevel.LOW
        windows_strong = any(item.direction is OSFamily.WINDOWS and item.weight >= _STRONG_EVIDENCE_WEIGHT for item in evidence)
        unix_strong = any(item.direction is OSFamily.LINUX_UNIX and item.weight >= _STRONG_EVIDENCE_WEIGHT for item in evidence)
        if windows_strong and unix_strong:
            return OSFamily.UNKNOWN, ConfidenceLevel.LOW

        winning_score = max(windows_score, unix_score)
        margin = abs(windows_score - unix_score)
        if margin < _LOW_MARGIN:
            return OSFamily.UNKNOWN, ConfidenceLevel.LOW
        family = OSFamily.WINDOWS if windows_score > unix_score else OSFamily.LINUX_UNIX
        if winning_score >= _HIGH_SCORE and margin >= _HIGH_MARGIN:
            return family, ConfidenceLevel.HIGH
        if winning_score >= _MEDIUM_SCORE and margin >= _MEDIUM_MARGIN:
            return family, ConfidenceLevel.MEDIUM
        return family, ConfidenceLevel.LOW
