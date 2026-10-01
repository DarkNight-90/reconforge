import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from reconforge.cli import main
from reconforge.core.controller import ReconController
from reconforge.core.models import (
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    Host,
    Scan,
    ScanStatus,
    Service,
)
from reconforge.core.repository import Repository


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def _config(tmp_path: Path):
    return SimpleNamespace(
        data_directory=tmp_path,
        database_path=tmp_path / "reconforge.db",
        scan_timeout=5.0,
        workflow="default",
    )


def _manifest(scan_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scan_id": scan_id,
        "target": "127.0.0.1",
        "workflow": "default",
        "reconforge_version": "0.1.0",
        "nmap_version": "7.99",
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "scan_status": "completed",
        "executions": [
            {"phase": phase, "artifact": f"{phase}.xml", "status": "completed"}
            for phase in ("discovery", "ports", "services", "os")
        ],
    }


def test_controller_correlate_scan_reads_sqlite_and_is_repeatable(tmp_path: Path) -> None:
    config = _config(tmp_path)
    repository = Repository(config.database_path)
    scan_id = "scan-m9"
    scan_directory = tmp_path / "scans" / scan_id
    scan_directory.mkdir(parents=True)
    scan = Scan(
        id=scan_id,
        target="127.0.0.1",
        started_at=NOW,
        finished_at=NOW,
        status=ScanStatus.COMPLETED,
        results_path=scan_directory,
        reconforge_version="0.1.0",
    )
    repository.create_scan(scan)
    host_id = repository.save_host(
        scan_id,
        Host("127.0.0.1", state="up", services=(Service(80, "tcp", "open", "http"),)),
    )
    repository.save_enumeration_result(
        EnumerationResult(
            scan_id=scan_id,
            host_id=host_id,
            ip="127.0.0.1",
            port=80,
            protocol="tcp",
            module="http",
            status=EnumerationStatus.SUCCESS,
            started_at=NOW,
            finished_at=NOW,
            evidence=(EnumerationEvidence("http_headers", "technology", "server", "nginx/1.24.0"),),
        )
    )
    (scan_directory / "manifest.json").write_text(json.dumps(_manifest(scan_id)), encoding="utf-8")
    controller = ReconController(config, repository=repository)

    first = controller.correlate_scan(scan_id)
    second = controller.correlate_scan(scan_id)

    assert first == second
    assert [technology.name for technology in first.technologies] == ["nginx"]
    assert first.completeness.status.value == "complete"


def test_cli_attack_surface_renders_derived_model(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)
    repository = Repository(config.database_path)
    scan_id = "scan-cli-m9"
    scan_directory = tmp_path / "scans" / scan_id
    scan_directory.mkdir(parents=True)
    repository.create_scan(
        Scan(
            id=scan_id,
            target="127.0.0.1",
            started_at=NOW,
            finished_at=NOW,
            status=ScanStatus.COMPLETED,
            results_path=scan_directory,
            reconforge_version="0.1.0",
        )
    )
    repository.save_host(scan_id, Host("127.0.0.1", services=(Service(22, "tcp", "open", "ssh", "OpenSSH"),)))
    (scan_directory / "manifest.json").write_text(json.dumps(_manifest(scan_id)), encoding="utf-8")

    assert main(["attack-surface", scan_id, "--data-dir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "Attack Surface" in output
    assert "OpenSSH" in output
    assert "service_observed" in output


def test_cli_attack_surface_handles_missing_scan(tmp_path: Path, capsys) -> None:
    assert main(["attack-surface", "missing", "--data-dir", str(tmp_path)]) == 1
    assert "scan not found" in capsys.readouterr().err
