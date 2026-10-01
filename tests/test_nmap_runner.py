from pathlib import Path
import subprocess

import pytest

from reconforge.core.models import ExecutionStatus
from reconforge.nmap.profiles import get_profile
from reconforge.nmap.runner import (
    NmapExecutionError,
    NmapInputError,
    NmapNotFoundError,
    NmapRunner,
    sanitize_arguments,
)


def runner() -> NmapRunner:
    return NmapRunner(default_timeout=10.0)


def test_build_command_is_an_argument_list_without_aggregate_options(tmp_path: Path) -> None:
    command = runner().build_command(
        get_profile("discovery"),
        "192.168.1.0/24",
        tmp_path / "discovery.xml",
    )

    assert command == (
        "nmap",
        "-sn",
        "-n",
        "-oX",
        str(tmp_path / "discovery.xml"),
        "192.168.1.0/24",
    )
    assert "-A" not in command


def test_successful_execution_returns_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    artifact = tmp_path / "discovery.xml"

    def fake_run(command: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[bytes]:
        artifact.write_bytes(b"<nmaprun />")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"notice")

    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("reconforge.nmap.runner.subprocess.run", fake_run)

    result = runner().run(get_profile("discovery"), "192.168.1.0/24", artifact)

    assert result.status is ExecutionStatus.COMPLETED
    assert result.exit_code == 0
    assert result.artifact_path == artifact
    assert result.duration is not None
    assert result.started_at.tzinfo is not None
    assert result.stderr_summary == "notice"
    assert artifact.read_bytes() == b"<nmaprun />"


def test_failed_execution_returns_failed_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        "reconforge.nmap.runner.subprocess.run",
        lambda command, **_: subprocess.CompletedProcess(command, 2, stderr=b"failure"),
    )

    result = runner().run(get_profile("ports"), ["192.168.1.10"], tmp_path / "ports.xml")

    assert result.status is ExecutionStatus.FAILED
    assert result.exit_code == 2
    assert result.stderr_summary == "failure"


def test_timeout_returns_timeout_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        "reconforge.nmap.runner.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("nmap", 1, stderr=b"timed out")
        ),
    )

    result = runner().run(get_profile("os"), "192.168.1.10", tmp_path / "os.xml", timeout=1)

    assert result.status is ExecutionStatus.TIMEOUT
    assert result.exit_code is None
    assert result.stderr_summary == "timed out"


def test_interruption_returns_interrupted_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        "reconforge.nmap.runner.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )

    result = runner().run(get_profile("services"), "192.168.1.10", tmp_path / "services.xml")

    assert result.status is ExecutionStatus.INTERRUPTED
    assert result.exit_code is None


def test_missing_nmap_is_controlled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: None)

    with pytest.raises(NmapNotFoundError):
        runner().run(get_profile("discovery"), "192.168.1.0/24", tmp_path / "discovery.xml")


def test_launch_failure_is_controlled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reconforge.nmap.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(
        "reconforge.nmap.runner.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("permission denied")),
    )

    with pytest.raises(NmapExecutionError):
        runner().run(get_profile("discovery"), "192.168.1.0/24", tmp_path / "discovery.xml")


def test_invalid_targets_and_artifacts_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(NmapInputError):
        runner().build_command(get_profile("discovery"), "", tmp_path / "discovery.xml")
    with pytest.raises(NmapInputError):
        runner().build_command(get_profile("discovery"), "2001:db8::1", tmp_path / "discovery.xml")
    with pytest.raises(NmapInputError):
        runner().build_command(get_profile("discovery"), "192.168.1.0/24", tmp_path / "wrong.xml")


def test_sensitive_argument_values_are_redacted() -> None:
    assert sanitize_arguments(("--token", "secret", "--password=hidden", "-n")) == (
        "--token",
        "<redacted>",
        "--password=<redacted>",
        "-n",
    )
