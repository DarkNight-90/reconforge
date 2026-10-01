from datetime import datetime, timedelta, timezone
import pytest
from pathlib import Path

from reconforge.core.models import (
    ConfidenceLevel,
    ExecutionStatus,
    Host,
    NmapExecutionResult,
    OSClassification,
    OSFamily,
    Scan,
    ScanStatus,
)


def test_scan_and_host_models_have_safe_defaults() -> None:
    scan = Scan(id="scan-1", target="192.168.1.0/24", started_at=datetime.now(timezone.utc))
    host = Host(ip="192.168.1.10")

    assert scan.status is ScanStatus.RUNNING
    assert host.classification is None
    assert host.services == ()


def test_execution_result_contract() -> None:
    started = datetime.now(timezone.utc)
    result = NmapExecutionResult(
        phase="discovery",
        artifact_path=Path("discovery.xml"),
        arguments=("-sn", "-oX", "discovery.xml"),
        started_at=started,
        finished_at=started,
        duration=1.25,
        exit_code=0,
        status=ExecutionStatus.COMPLETED,
    )

    assert result.phase == "discovery"
    assert result.status is ExecutionStatus.COMPLETED
    assert result.arguments == ("-sn", "-oX", "discovery.xml")


def test_datetime_contracts_require_utc() -> None:
    now = datetime.now(timezone.utc)
    scan = Scan(id="scan-utc", target="192.168.1.0/24", started_at=now)

    assert scan.started_at.tzinfo is not None
    assert scan.started_at.utcoffset() == timedelta(0)

    with pytest.raises(ValueError, match="timezone-aware UTC"):
        Scan(id="scan-naive", target="192.168.1.0/24", started_at=datetime.now())


def test_classification_is_distinct_from_observations() -> None:
    classification = OSClassification(
        family=OSFamily.WINDOWS,
        confidence=ConfidenceLevel.HIGH,
    )
    host = Host(ip="192.168.1.10", classification=classification)

    assert host.classification is classification
    assert host.os_fingerprints == ()
