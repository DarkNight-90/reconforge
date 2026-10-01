import json
from pathlib import Path

import pytest

from reconforge.core.classifier import (
    ClassifierConfigurationError,
    OSClassifier,
    load_signatures,
)
from reconforge.core.models import (
    ConfidenceLevel,
    Host,
    OSFamily,
    OSFingerprint,
    Service,
)


def service(
    port: int,
    name: str | None,
    *,
    product: str | None = None,
    extra_info: str | None = None,
) -> Service:
    return Service(
        port=port,
        protocol="tcp",
        state="open",
        service_name=name,
        product=product,
        extra_info=extra_info,
    )


def fingerprint(vendor: str, family: str, accuracy: int = 95) -> OSFingerprint:
    return OSFingerprint(vendor=vendor, family=family, generation="5.X", accuracy=accuracy, source="nmap")


def test_strong_windows_classification_and_scores() -> None:
    host = Host(
        ip="192.168.1.10",
        services=(
            service(445, "microsoft-ds"),
            service(3389, "rdp", product="Microsoft Terminal Services"),
        ),
        os_fingerprints=(fingerprint("Microsoft", "Windows"),),
    )

    result = OSClassifier().classify(host)

    assert result.family is OSFamily.WINDOWS
    assert result.confidence is ConfidenceLevel.HIGH
    assert result.windows_score == 25.75
    assert result.unix_score == 0
    assert host.classification is None
    assert any(item.indicator == "os_fingerprint" for item in result.evidence)
    assert any(item.value == "microsoft-ds" for item in result.evidence)


def test_strong_linux_classification_and_scores() -> None:
    host = Host(
        ip="192.168.1.11",
        services=(
            service(22, "ssh", product="OpenSSH"),
            service(80, "http", product="nginx"),
        ),
        os_fingerprints=(fingerprint("Linux", "Linux"),),
    )

    result = OSClassifier().classify(host)

    assert result.family is OSFamily.LINUX_UNIX
    assert result.confidence is ConfidenceLevel.HIGH
    assert result.unix_score == 16.25
    assert result.windows_score == 0


def test_weak_ssh_evidence_is_low_confidence() -> None:
    result = OSClassifier().classify(Host(ip="192.168.1.12", services=(service(22, "SSH"),)))

    assert result.family is OSFamily.LINUX_UNIX
    assert result.confidence is ConfidenceLevel.LOW
    assert result.unix_score == 2


def test_generic_http_is_unknown() -> None:
    result = OSClassifier().classify(Host(ip="192.168.1.13", services=(service(80, "HTTP"),)))

    assert result.family is OSFamily.UNKNOWN
    assert result.confidence is ConfidenceLevel.LOW
    assert result.unix_score == 0.5


def test_no_evidence_is_unknown() -> None:
    result = OSClassifier().classify(Host(ip="192.168.1.14"))

    assert result.family is OSFamily.UNKNOWN
    assert result.confidence is ConfidenceLevel.LOW
    assert result.windows_score == 0
    assert result.unix_score == 0


def test_conflicting_strong_evidence_is_unknown_low() -> None:
    host = Host(
        ip="192.168.1.15",
        services=(
            service(445, "SMB"),
            service(3389, "RDP", product="Microsoft Terminal Services"),
        ),
        os_fingerprints=(fingerprint("Linux", "Linux"),),
    )

    result = OSClassifier().classify(host)

    assert result.family is OSFamily.UNKNOWN
    assert result.confidence is ConfidenceLevel.LOW
    assert result.windows_score == 16
    assert result.unix_score == 9.75


def test_multiple_service_indicators_can_identify_windows_without_fingerprint() -> None:
    result = OSClassifier().classify(
        Host(
            ip="192.168.1.16",
            services=(
                service(445, "SMB"),
                service(3389, "RDP", product="Microsoft"),
            ),
        )
    )

    assert result.family is OSFamily.WINDOWS
    assert result.confidence is ConfidenceLevel.HIGH
    assert result.windows_score == 15


def test_multiple_fingerprints_are_all_considered_deterministically() -> None:
    host = Host(
        ip="192.168.1.17",
        os_fingerprints=(fingerprint("Linux", "Linux", 95), fingerprint("Linux", "Linux", 45)),
    )

    first = OSClassifier().classify(host)
    second = OSClassifier().classify(host)

    assert first == second
    assert len(first.evidence) == 2
    assert first.unix_score == 17


def test_missing_optional_service_fields_do_not_crash() -> None:
    result = OSClassifier().classify(
        Host(ip="192.168.1.18", services=(service(1234, None),))
    )

    assert result == OSClassifier().classify(Host(ip="192.168.1.18"))


def test_signatures_load_and_match_case_insensitively() -> None:
    rules = load_signatures()

    assert rules
    assert any(rule.pattern == "microsoft-ds" and rule.weight == 5 for rule in rules)
    result = OSClassifier().classify(Host(ip="192.168.1.19", services=(service(445, "MiCrOsOfT-Ds"),)))
    assert result.family is OSFamily.WINDOWS


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 1, "windows": [], "unix": {}},
        {"schema_version": 2, "windows": {}, "unix": {}},
        {"schema_version": 1, "windows": {"services": {"x": "strong"}}, "unix": {}},
        {"schema_version": 1, "windows": {}, "unix": {}, "macos": {}},
    ],
)
def test_malformed_signatures_fail_cleanly(tmp_path: Path, payload: dict[str, object]) -> None:
    path = tmp_path / "bad-signatures.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ClassifierConfigurationError):
        OSClassifier(path)
