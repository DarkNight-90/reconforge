from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from reconforge.core.controller import ReconController
from reconforge.core.models import ExecutionStatus, ManifestExecution, ScanManifest, ScanStatus


def test_scans_command_lists_scans(monkeypatch: pytest.MonkeyPatch, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    now = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)

    class FakeController:
        def __init__(self, config) -> None:
            self.config = config

        def list_scans(self):
            return (
                SimpleNamespace(
                    id="scan-b",
                    target="192.168.1.0/24",
                    status=ScanStatus.COMPLETED,
                    started_at=now,
                    finished_at=now,
                    workflow="default",
                ),
                SimpleNamespace(
                    id="scan-a",
                    target="10.0.0.0/24",
                    status=ScanStatus.FAILED,
                    started_at=now,
                    finished_at=now,
                    workflow="default",
                ),
            )

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    from reconforge.cli import main

    assert main(["scans", "--data-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "SCAN ID" in out
    assert "scan-b" in out
    assert "scan-a" in out


def test_show_command_reads_scan_details(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    now = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)

    class FakeController:
        def __init__(self, config) -> None:
            self.config = config

        def show_scan(self, scan_id: str):
            return {
                "scan_id": scan_id,
                "target": "127.0.0.1",
                "status": ScanStatus.COMPLETED,
                "started_at": now,
                "finished_at": now,
                "workflow": "default",
                "executions": [
                    ManifestExecution("discovery", "discovery.xml", ExecutionStatus.COMPLETED),
                    ManifestExecution("ports", "ports.xml", ExecutionStatus.COMPLETED),
                ],
                "artifacts": {"discovery.xml": True, "ports.xml": True},
                "hosts": (SimpleNamespace(ip="127.0.0.1", classification=None, services=(SimpleNamespace(port=80, protocol="tcp"),)),),
            }

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    from reconforge.cli import main

    assert main(["show", "scan-123"]) == 0
    out = capsys.readouterr().out
    assert "Scan" in out
    assert "scan-123" in out
    assert "127.0.0.1" in out


def test_recovery_plan_propagates_dependencies() -> None:
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-1",
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 23, 9, 5, tzinfo=timezone.utc),
        scan_status=ScanStatus.FAILED,
        executions=(
            ManifestExecution("discovery", "discovery.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("ports", "ports.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("services", "services.xml", ExecutionStatus.FAILED),
            ManifestExecution("os", "os.xml", ExecutionStatus.SKIPPED),
        ),
    )

    plan = ReconController.plan_recovery_from_manifest(manifest)
    assert plan.recoverable is True
    assert plan.phases_to_run == ("services", "os")


def test_resume_command_reuses_existing_scan_id(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeController:
        def __init__(self, config) -> None:
            self.config = config

        def resume_scan(self, scan_id: str):
            return SimpleNamespace(scan=SimpleNamespace(id=scan_id, status=ScanStatus.COMPLETED), phases_to_run=("services", "os"))

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    from reconforge.cli import main

    assert main(["resume", "scan-42"]) == 0


def test_manifest_validation_rejects_unsafe_artifact_paths() -> None:
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-1",
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 23, 9, 5, tzinfo=timezone.utc),
        scan_status=ScanStatus.RUNNING,
        executions=(
            ManifestExecution("discovery", "../evil.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("ports", "ports.xml", ExecutionStatus.PENDING),
            ManifestExecution("services", "services.xml", ExecutionStatus.PENDING),
            ManifestExecution("os", "os.xml", ExecutionStatus.PENDING),
        ),
    )

    with pytest.raises(ValueError):
        ReconController.validate_manifest(manifest, Path="ignored")
