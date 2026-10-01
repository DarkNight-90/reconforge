from types import SimpleNamespace

import pytest

from reconforge.core.models import ExecutionStatus, ManifestExecution, ScanStatus
from reconforge.cli import NOT_IMPLEMENTED_EXIT_CODE, main


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert "ReconForge 0.1.0" in capsys.readouterr().out


def test_scan_delegates_to_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class FakeController:
        def __init__(self, config) -> None:
            self.config = config

        def run(self, target: str):
            calls.append(target)
            return SimpleNamespace(scan=SimpleNamespace(status=ScanStatus.COMPLETED))

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    assert main(["scan", "192.168.1.0/24"]) == 0
    assert calls == ["192.168.1.0/24"]


def test_scan_accepts_configuration_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class FakeController:
        def __init__(self, config) -> None:
            captured["config"] = config

        def run(self, target: str):
            return SimpleNamespace(scan=SimpleNamespace(status=ScanStatus.COMPLETED))

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    assert main(["scan", "192.168.1.0/24", "--data-dir", "results", "--timeout", "15"]) == 0
    assert captured["config"].data_directory.name == "results"
    assert captured["config"].database_path.name == "reconforge.db"
    assert captured["config"].scan_timeout == 15


def test_scan_rejects_invalid_target() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", "not-a-cidr"])

    assert exc_info.value.code == 2


def test_reserved_commands_return_not_implemented() -> None:
    assert main(["services"]) == NOT_IMPLEMENTED_EXIT_CODE
    assert main(["show", "192.168.1.10"]) == NOT_IMPLEMENTED_EXIT_CODE


def test_hosts_requires_scan_id() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["hosts"])

    assert exc_info.value.code == 2


def test_show_renders_missing_artifact_name_without_crashing(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class FakeController:
        def __init__(self, config) -> None:
            self.config = config

        def show_scan(self, scan_id: str):
            return {
                "scan_id": scan_id,
                "target": "127.0.0.1/32",
                "status": ScanStatus.FAILED,
                "started_at": None,
                "finished_at": None,
                "workflow": "default",
                "executions": (ManifestExecution("discovery", "discovery.xml", ExecutionStatus.FAILED),),
                "artifacts": {None: False},
                "hosts": (),
            }

    monkeypatch.setattr("reconforge.cli.ReconController", FakeController)

    assert main(["show", "failed-scan"]) == 0
    output = capsys.readouterr().out
    assert "Status: failed" in output
    assert "N/A" in output
    assert "missing" in output
