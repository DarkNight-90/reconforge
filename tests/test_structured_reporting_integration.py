import json
from pathlib import Path

import pytest

from reconforge.cli import main
from reconforge.core.controller import ReconController
from reconforge.core.repository import Repository
from test_m10_integration import config, create_scan


def test_attack_surface_json_cli_and_atomic_output(tmp_path: Path, capsys):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))
    manifest_path = tmp_path / "scans" / "scan-a" / "manifest.json"
    manifest_before = manifest_path.read_bytes()
    output_path = tmp_path / "reports" / "surface.json"

    assert main(["attack-surface", "scan-a", "--format", "json", "--output", str(output_path), "--data-dir", str(tmp_path)]) == 0

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["report_type"] == "attack_surface"
    assert payload["scan_id"] == "scan-a"
    assert manifest_path.read_bytes() == manifest_before
    assert capsys.readouterr().out == ""


def test_attack_surface_json_defaults_to_stdout(tmp_path: Path, capsys):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))

    assert main(["attack-surface", "scan-a", "--format", "json", "--data-dir", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report_type"] == "attack_surface"


def test_diff_json_cli_and_terminal_remains_default(tmp_path: Path, capsys):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "baseline", (80,))
    create_scan(tmp_path, repository, "current", (80, 8080))

    assert main(["diff", "baseline", "current", "--format", "json", "--data-dir", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report_type"] == "attack_surface_diff"
    assert payload["baseline_scan_id"] == "baseline"

    assert main(["diff", "baseline", "current", "--data-dir", str(tmp_path)]) == 0
    assert "Attack Surface Diff" in capsys.readouterr().out


def test_invalid_format_is_rejected_cleanly(tmp_path: Path):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))

    with pytest.raises(SystemExit) as error:
        main(["attack-surface", "scan-a", "--format", "xml", "--data-dir", str(tmp_path)])
    assert error.value.code == 2


def test_missing_scan_and_unwritable_output_are_controlled(tmp_path: Path, capsys):
    assert main(["diff", "missing", "current", "--format", "json", "--data-dir", str(tmp_path)]) == 1
    assert "scan not found" in capsys.readouterr().err

    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))
    directory_output = tmp_path / "existing-directory"
    directory_output.mkdir()
    assert main(["attack-surface", "scan-a", "--format", "json", "--output", str(directory_output), "--data-dir", str(tmp_path)]) == 1
    assert capsys.readouterr().err


def test_json_reporting_does_not_change_database(tmp_path: Path):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "baseline", (80,))
    create_scan(tmp_path, repository, "current", (80, 8080))
    with repository._connection() as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scans", "hosts", "services", "os_fingerprints", "enumeration_results", "enumeration_evidence")
        }
    controller = ReconController(config(tmp_path), repository=repository)
    diff = controller.diff_scans("baseline", "current")
    from reconforge.reports.structured import serialize_report
    serialize_report(diff)
    with repository._connection() as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        }
    assert after == before


def test_structured_reporting_does_not_invoke_repository_or_manifest_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = Repository(tmp_path / "reconforge.db")
    create_scan(tmp_path, repository, "scan-a", (80,))

    def forbidden(*args, **kwargs):
        raise AssertionError("structured reporting invoked a write boundary")

    monkeypatch.setattr(Repository, "save_host", forbidden)
    monkeypatch.setattr(Repository, "save_enumeration_result", forbidden)
    monkeypatch.setattr(Repository, "update_scan", forbidden)
    monkeypatch.setattr(ReconController, "_write_manifest", forbidden)

    assert main(["attack-surface", "scan-a", "--format", "json", "--data-dir", str(tmp_path)]) == 0
