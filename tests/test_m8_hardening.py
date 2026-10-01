from datetime import datetime, timezone
from pathlib import Path

import pytest

from reconforge.core.controller import ReconController
from reconforge.core.models import (
    EnumerationDecision,
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    EnumerationTarget,
    ExecutionStatus,
    Host,
    ManifestExecution,
    ScanManifest,
    ScanStatus,
    Service,
)
from reconforge.core.repository import Repository


class FakeEnumerationEngine:
    def __init__(self, results=None) -> None:
        self.results = results or []
        self.modules = [
            type("M", (), {"name": "http", "enumerate": lambda self, target: self._result(target)})(),
        ]

    def decide(self, target):
        return EnumerationDecision(
            target=target,
            module="http",
            reason="service identified as http",
            priority="normal",
            status=EnumerationStatus.SUCCESS,
            evidence=(),
        )

    def _result(self, target):
        return EnumerationResult(
            scan_id=target.scan_id,
            host_id=target.host_id,
            ip=target.ip,
            port=target.port,
            protocol=target.protocol,
            module="http",
            status=EnumerationStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=0.1,
            evidence=(
                EnumerationEvidence("http_headers", "technology", "server", "nginx/1.24.0", "medium", "Server header"),
            ),
        )


class FakeRepository:
    def __init__(self):
        self._hosts = {}
        self._results = {}

    def create_scan(self, scan):
        pass

    def update_scan(self, scan):
        pass

    def save_host(self, scan_id, host):
        self._hosts.setdefault(scan_id, {})[host.ip] = host
        return 1

    def get_hosts(self, scan_id):
        return tuple(self._hosts.get(scan_id, {}).values())

    def get_host_id(self, scan_id, ip):
        return 1

    def save_enumeration_result(self, result):
        key = (result.scan_id, result.host_id, result.port, result.protocol, result.module)
        self._results[key] = result

    def get_enumeration_results(self, scan_id):
        return tuple(result for key, result in self._results.items() if key[0] == scan_id)


@pytest.mark.parametrize(
    "status",
    [
        ExecutionStatus.PENDING,
        ExecutionStatus.RUNNING,
        ExecutionStatus.COMPLETED,
        ExecutionStatus.FAILED,
        ExecutionStatus.TIMEOUT,
        ExecutionStatus.INTERRUPTED,
        ExecutionStatus.SKIPPED,
        ExecutionStatus.NOT_APPLICABLE,
    ],
)
def test_enumeration_lifecycle_statuses_exist(status: ExecutionStatus) -> None:
    assert status in ExecutionStatus


def test_supported_enumeration_success_persists_evidence_and_status(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "enum.sqlite")
    scan_id = "scan-1"
    repository.create_scan(
        __import__("reconforge.core.models", fromlist=["Scan"]).Scan(
            id=scan_id,
            target="127.0.0.1",
            started_at=datetime.now(timezone.utc),
            reconforge_version="0.1.0",
            workflow="default",
        )
    )
    host_id = repository.save_host(
        scan_id,
        Host("127.0.0.1", services=(Service(80, "tcp", "open", "http", "nginx", "1.24.0"),)),
    )
    result = EnumerationResult(
        scan_id=scan_id,
        host_id=host_id,
        ip="127.0.0.1",
        port=80,
        protocol="tcp",
        module="http",
        status=EnumerationStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.1,
        evidence=(
            EnumerationEvidence("http_headers", "technology", "server", "nginx/1.24.0", "medium", "Server header"),
        ),
    )
    repository.save_enumeration_result(result)
    stored = repository.get_enumeration_results(scan_id)
    assert stored[0].status is EnumerationStatus.SUCCESS
    assert stored[0].evidence[0].indicator == "server"


def test_enumeration_failure_and_timeout_are_distinct() -> None:
    failed = EnumerationResult(
        scan_id="scan",
        host_id=1,
        ip="127.0.0.1",
        port=80,
        protocol="tcp",
        module="http",
        status=EnumerationStatus.FAILED,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.1,
        error_message="failed",
    )
    timed = EnumerationResult(
        scan_id="scan",
        host_id=1,
        ip="127.0.0.1",
        port=443,
        protocol="tcp",
        module="tls",
        status=EnumerationStatus.TIMEOUT,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.1,
        error_message="timeout",
    )
    assert failed.status is EnumerationStatus.FAILED
    assert timed.status is EnumerationStatus.TIMEOUT
    assert failed.status != timed.status


def test_interrupted_enumeration_stays_interrupted() -> None:
    interrupted = EnumerationResult(
        scan_id="scan",
        host_id=1,
        ip="127.0.0.1",
        port=22,
        protocol="tcp",
        module="ssh",
        status=EnumerationStatus.INTERRUPTED,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.0,
        error_message="interrupted",
    )
    assert interrupted.status is EnumerationStatus.INTERRUPTED


def test_resume_uses_manifest_for_incomplete_enumeration_and_preserves_prior_phases() -> None:
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-r",
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 23, 9, 5, tzinfo=timezone.utc),
        scan_status=ScanStatus.RUNNING,
        executions=(
            ManifestExecution("discovery", "discovery.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("ports", "ports.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("services", "services.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("os", "os.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("enumeration", "enumeration.json", ExecutionStatus.RUNNING),
        ),
    )
    assert manifest.executions[-1].phase == "enumeration"
    assert manifest.executions[-1].status is ExecutionStatus.RUNNING
    assert any(item.phase == "discovery" and item.status is ExecutionStatus.COMPLETED for item in manifest.executions)


def test_duplicate_enumeration_records_are_deduplicated_by_identity(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "dedupe.sqlite")
    repository.create_scan(
        __import__("reconforge.core.models", fromlist=["Scan"]).Scan(
            id="scan-d",
            target="127.0.0.1",
            started_at=datetime.now(timezone.utc),
            reconforge_version="0.1.0",
            workflow="default",
        )
    )
    host_id = repository.save_host("scan-d", Host("127.0.0.1", services=(Service(80, "tcp", "open", "http"),)))
    result_1 = EnumerationResult(
        scan_id="scan-d",
        host_id=host_id,
        ip="127.0.0.1",
        port=80,
        protocol="tcp",
        module="http",
        status=EnumerationStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.1,
        evidence=(EnumerationEvidence("http_headers", "technology", "status", "200", "medium", "Status code")),
    )
    result_2 = EnumerationResult(
        scan_id="scan-d",
        host_id=host_id,
        ip="127.0.0.1",
        port=80,
        protocol="tcp",
        module="http",
        status=EnumerationStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration=0.2,
        evidence=(EnumerationEvidence("http_headers", "technology", "status", "200", "medium", "Status code")),
    )
    repository.save_enumeration_result(result_1)
    repository.save_enumeration_result(result_2)
    assert len(repository.get_enumeration_results("scan-d")) == 1


def test_show_uses_manifest_for_enumeration_state_and_not_just_db_rows() -> None:
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-show",
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 23, 9, 5, tzinfo=timezone.utc),
        scan_status=ScanStatus.RUNNING,
        executions=(
            ManifestExecution("discovery", "discovery.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("enumeration", "enumeration.json", ExecutionStatus.FAILED),
        ),
    )
    status = next(item.status.value for item in manifest.executions if item.phase == "enumeration")
    assert status == "failed"
