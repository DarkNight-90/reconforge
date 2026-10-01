import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconforge.cli import main
from reconforge.core.controller import ManifestValidationError, ReconController
from reconforge.core.models import Host, Scan, ScanManifest, ScanStatus, Service
from reconforge.core.repository import Repository


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def config(tmp_path: Path):
    return SimpleNamespace(
        data_directory=tmp_path,
        database_path=tmp_path / "reconforge.db",
        scan_timeout=5.0,
        workflow="default",
    )


def create_scan(tmp_path: Path, repository: Repository, scan_id: str, ports: tuple[int, ...]) -> None:
    scan_dir = tmp_path / "scans" / scan_id
    scan_dir.mkdir(parents=True)
    scan = Scan(
        id=scan_id,
        target="127.0.0.1",
        started_at=NOW,
        finished_at=NOW,
        status=ScanStatus.COMPLETED,
        results_path=scan_dir,
        reconforge_version="0.1.0",
    )
    repository.create_scan(scan)
    repository.save_host(
        scan_id,
        Host(
            "127.0.0.1",
            state="up",
            services=tuple(Service(port, "tcp", "open", "http", "nginx", "1.24") for port in ports),
        ),
    )
    manifest = ScanManifest(
        schema_version=1,
        scan_id=scan_id,
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=NOW,
        updated_at=NOW,
        scan_status=ScanStatus.COMPLETED,
    )
    ReconController._write_manifest(scan_dir, manifest)


def test_controller_diff_uses_sqlite_then_m9_and_preserves_source_state(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "baseline", (80,))
    create_scan(tmp_path, repository, "current", (80, 8080))
    current_manifest_path = tmp_path / "scans" / "current" / "manifest.json"
    manifest_before = current_manifest_path.read_bytes()
    with repository._connection() as connection:
        before_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scans", "hosts", "services", "enumeration_results", "enumeration_evidence")
        }
    controller = ReconController(config(tmp_path), repository=repository)

    diff = controller.diff_scans("baseline", "current")

    assert diff.id == "diff:baseline:current"
    assert any(change.comparison_key == "127.0.0.1:tcp:8080" for change in diff.service_changes)
    assert current_manifest_path.read_bytes() == manifest_before
    assert repository.get_scan("baseline").status is ScanStatus.COMPLETED
    assert repository.get_scan("current").status is ScanStatus.COMPLETED
    with repository._connection() as connection:
        after_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before_counts
        }
    assert after_counts == before_counts


def test_cli_diff_renders_added_service(tmp_path: Path, capsys) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "baseline", (80,))
    create_scan(tmp_path, repository, "current", (80, 8080))

    assert main(["diff", "baseline", "current", "--data-dir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "Attack Surface Diff" in output
    assert "127.0.0.1:tcp:8080" in output
    assert "Added" in output


def test_controller_rejects_same_scan_and_mismatched_manifest(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "same", (80,))
    controller = ReconController(config(tmp_path), repository=repository)
    with pytest.raises(Exception, match="must differ"):
        controller.diff_scans("same", "same")

    manifest_path = tmp_path / "scans" / "same" / "manifest.json"
    create_scan(tmp_path, repository, "same-2", (80,))
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["scan_id"] = "wrong"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ManifestValidationError, match="does not match"):
        controller.diff_scans("same", "same-2")


def test_cli_diff_handles_missing_scan(tmp_path: Path, capsys) -> None:
    assert main(["diff", "missing", "current", "--data-dir", str(tmp_path)]) == 1
    assert "scan not found" in capsys.readouterr().err


def test_controller_diff_does_not_invoke_collection_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "baseline", (80,))
    create_scan(tmp_path, repository, "current", (80, 8080))

    def forbidden(*args, **kwargs):
        raise AssertionError("M10 invoked a collection boundary")

    monkeypatch.setattr("reconforge.nmap.runner.NmapRunner.run", forbidden)
    monkeypatch.setattr("reconforge.enumeration.engine.EnumerationEngine.run", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)

    ReconController(config(tmp_path), repository=repository).diff_scans("baseline", "current")
