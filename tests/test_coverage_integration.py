import json
from pathlib import Path

import pytest

from reconforge.cli import main
from reconforge.core.controller import ReconController
from reconforge.core.repository import Repository
from reconforge.reports.structured import serialize_report
from test_m10_integration import config, create_scan


def test_controller_coverage_uses_sqlite_m9_and_preserves_source_state(tmp_path: Path):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))
    manifest_path = tmp_path / "scans" / "scan-a" / "manifest.json"
    manifest_before = manifest_path.read_bytes()
    with repository._connection() as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scans", "hosts", "services", "os_fingerprints", "enumeration_results", "enumeration_evidence")
        }

    report = ReconController(config(tmp_path), repository=repository).coverage_report("scan-a")

    assert report.id == "coverage:scan-a"
    assert report.host_coverage[0].ip == "127.0.0.1"
    assert report.service_coverage[0].id == "127.0.0.1:tcp:80"
    assert manifest_path.read_bytes() == manifest_before
    with repository._connection() as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        }
    assert after == before


def test_coverage_cli_terminal_and_json_output(tmp_path: Path, capsys):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))

    assert main(["coverage", "scan-a", "--data-dir", str(tmp_path)]) == 0
    assert "Evidence Coverage" in capsys.readouterr().out

    assert main(["coverage", "scan-a", "--format", "json", "--data-dir", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["report_type"] == "evidence_coverage"
    assert payload["scan_id"] == "scan-a"


def test_coverage_json_output_file_and_m11_serializer(tmp_path: Path):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))
    output = tmp_path / "reports" / "coverage.json"

    assert main(["coverage", "scan-a", "--format", "json", "--output", str(output), "--data-dir", str(tmp_path)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["report_type"] == "evidence_coverage"
    report = ReconController(config(tmp_path), repository=repository).coverage_report("scan-a")
    assert json.loads(serialize_report(report))["report_type"] == "evidence_coverage"


def test_coverage_handles_missing_scan_and_invalid_manifest(tmp_path: Path, capsys):
    assert main(["coverage", "missing", "--data-dir", str(tmp_path)]) == 1
    assert "scan not found" in capsys.readouterr().err

    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))
    manifest_path = tmp_path / "scans" / "scan-a" / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["scan_id"] = "wrong"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["coverage", "scan-a", "--data-dir", str(tmp_path)]) == 1
    assert "does not match" in capsys.readouterr().err


def test_coverage_does_not_invoke_collection_or_write_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))

    def forbidden(*args, **kwargs):
        raise AssertionError("M12 invoked a collection or write boundary")

    monkeypatch.setattr("reconforge.nmap.runner.NmapRunner.run", forbidden)
    monkeypatch.setattr("reconforge.enumeration.engine.EnumerationEngine.run", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr(Repository, "save_host", forbidden)
    monkeypatch.setattr(Repository, "save_enumeration_result", forbidden)
    monkeypatch.setattr(Repository, "update_scan", forbidden)
    monkeypatch.setattr(ReconController, "_write_manifest", forbidden)

    report = ReconController(config(tmp_path), repository=repository).coverage_report("scan-a")
    assert serialize_report(report)
