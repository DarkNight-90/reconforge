from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from reconforge.config import AppConfig
from reconforge.core.controller import (
    ControllerDependencyError,
    ControllerInputError,
    ReconController,
)
from reconforge.core.models import (
    ConfidenceLevel,
    ExecutionStatus,
    Host,
    NmapExecutionResult,
    OSClassification,
    OSFamily,
    OSFingerprint,
    Scan,
    ScanResult,
    Service,
)
from reconforge.nmap.runner import NmapNotFoundError


NOW = datetime(2026, 9, 23, 15, 0, tzinfo=timezone.utc)


class FakeRunner:
    def __init__(self, statuses: dict[str, ExecutionStatus] | None = None, unavailable: bool = False) -> None:
        self.statuses = statuses or {}
        self.unavailable = unavailable
        self.calls: list[str] = []

    def check_available(self) -> str:
        if self.unavailable:
            raise NmapNotFoundError("nmap missing")
        return "fake-nmap"

    def run(self, profile, target, artifact_path: Path, timeout: float) -> NmapExecutionResult:
        self.calls.append(profile.name)
        status = self.statuses.get(profile.name, ExecutionStatus.COMPLETED)
        target_arguments = tuple(target) if not isinstance(target, str) else (target,)
        return NmapExecutionResult(
            phase=profile.phase.value,
            artifact_path=artifact_path,
            arguments=(profile.name, *target_arguments),
            started_at=NOW,
            finished_at=NOW,
            duration=0.1,
            exit_code=0 if status is ExecutionStatus.COMPLETED else 1,
            status=status,
            stderr_summary=None if status is ExecutionStatus.COMPLETED else f"{profile.name} failed",
        )


class FakeParser:
    def __init__(self, observations: dict[str, tuple[Host, ...]]) -> None:
        self.observations = observations
        self.calls: list[str] = []

    def parse(self, path: Path) -> tuple[Host, ...]:
        self.calls.append(path.name)
        return self.observations[path.stem]


class FakeClassifier:
    def __init__(self) -> None:
        self.hosts: list[Host] = []

    def classify(self, host: Host) -> OSClassification:
        self.hosts.append(host)
        return OSClassification(
            family=OSFamily.LINUX_UNIX,
            confidence=ConfidenceLevel.HIGH,
            windows_score=0,
            unix_score=10,
        )


class FakeRepository:
    def __init__(self) -> None:
        self.created: list[Scan] = []
        self.updated: list[Scan] = []
        self.hosts: list[Host] = []

    def create_scan(self, scan: Scan) -> None:
        self.created.append(scan)

    def update_scan(self, scan: Scan) -> None:
        self.updated.append(scan)

    def save_host(self, scan_id: str, host: Host) -> int:
        self.hosts.append(host)
        return len(self.hosts)


def config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_directory=tmp_path, database_path=tmp_path / "db.sqlite", scan_timeout=5)


def observations() -> dict[str, tuple[Host, ...]]:
    return {
        "discovery": (Host("127.0.0.1", "localhost", "AA", "Vendor", "up"),),
        "ports": (Host("127.0.0.1", services=(Service(22, "tcp", "open"),)),),
        "services": (Host("127.0.0.1", services=(Service(22, "tcp", "open", "ssh", "OpenSSH", "9.6"),)),),
        "os": (Host("127.0.0.1", os_fingerprints=(OSFingerprint("Linux", "Linux", "5.X", 95, "nmap"),)),),
    }


def make_controller(tmp_path: Path, *, runner=None, parser=None, classifier=None, repository=None, reporter=None) -> ReconController:
    return ReconController(
        config(tmp_path),
        runner=runner or FakeRunner(),
        parser=parser or FakeParser(observations()),
        classifier=classifier or FakeClassifier(),
        repository=repository or FakeRepository(),
        reporter=reporter or (lambda result: None),
    )


def test_successful_workflow_order_merge_classification_persistence_and_manifest(tmp_path: Path) -> None:
    runner = FakeRunner()
    parser = FakeParser(observations())
    classifier = FakeClassifier()
    repository = FakeRepository()
    reports: list[ScanResult] = []

    result = make_controller(tmp_path, runner=runner, parser=parser, classifier=classifier, repository=repository, reporter=reports.append).run("127.0.0.1")

    assert runner.calls == ["discovery", "ports", "services", "os"]
    assert parser.calls == ["discovery.xml", "ports.xml", "services.xml", "os.xml"]
    assert result.scan.status.value == "completed"
    assert len(result.hosts) == 1
    assert result.hosts[0].services == (Service(22, "tcp", "open", "ssh", "OpenSSH", "9.6"),)
    assert len(result.hosts[0].os_fingerprints) == 1
    assert result.hosts[0].classification is not None
    assert classifier.hosts[0].services[0].product == "OpenSSH"
    assert repository.hosts == list(result.hosts)
    assert reports == [result]
    manifest = result.scan.results_path / "manifest.json"
    assert manifest.exists()
    assert [item.status for item in result.phase_results] == [ExecutionStatus.COMPLETED] * 4


def test_invalid_scope_does_not_call_runner_or_create_scan(tmp_path: Path) -> None:
    runner = FakeRunner()
    repository = FakeRepository()

    with pytest.raises(ControllerInputError):
        make_controller(tmp_path, runner=runner, repository=repository).run("not-a-target")

    assert runner.calls == []
    assert repository.created == []


def test_missing_nmap_is_controlled_before_scan_initialization(tmp_path: Path) -> None:
    repository = FakeRepository()

    with pytest.raises(ControllerDependencyError):
        make_controller(tmp_path, runner=FakeRunner(unavailable=True), repository=repository).run("127.0.0.1")

    assert repository.created == []


def test_zero_hosts_skips_dependent_phases(tmp_path: Path) -> None:
    runner = FakeRunner()
    parser = FakeParser({"discovery": (), "ports": (), "services": (), "os": ()})
    repository = FakeRepository()

    result = make_controller(tmp_path, runner=runner, parser=parser, repository=repository).run("127.0.0.1")

    assert runner.calls == ["discovery"]
    assert [item.status for item in result.phase_results] == [
        ExecutionStatus.COMPLETED,
        ExecutionStatus.SKIPPED,
        ExecutionStatus.SKIPPED,
        ExecutionStatus.SKIPPED,
    ]
    assert result.scan.status.value == "completed"
    assert result.hosts == ()


@pytest.mark.parametrize(
    ("failed_phase", "expected_statuses", "final_status", "expected_calls"),
    [
        ("discovery", ["failed", "skipped", "skipped", "skipped"], "failed", ["discovery"]),
        ("ports", ["completed", "failed", "skipped", "skipped"], "failed", ["discovery", "ports"]),
        ("services", ["completed", "completed", "failed", "skipped"], "failed", ["discovery", "ports", "services"]),
        ("os", ["completed", "completed", "completed", "failed"], "completed", ["discovery", "ports", "services", "os"]),
    ],
)
def test_phase_dependency_and_partial_failure_policy(
    tmp_path: Path,
    failed_phase: str,
    expected_statuses: list[str],
    final_status: str,
    expected_calls: list[str],
) -> None:
    runner = FakeRunner({failed_phase: ExecutionStatus.FAILED})
    repository = FakeRepository()
    result = make_controller(tmp_path, runner=runner, repository=repository).run("127.0.0.1")

    assert runner.calls == expected_calls
    assert [item.status.value for item in result.phase_results] == expected_statuses
    assert result.scan.status.value == final_status
    assert bool(repository.hosts) is (failed_phase != "discovery")


def test_keyboard_interrupt_marks_scan_interrupted(tmp_path: Path) -> None:
    class InterruptingRunner(FakeRunner):
        def run(self, profile, target, artifact_path: Path, timeout: float) -> NmapExecutionResult:
            self.calls.append(profile.name)
            raise KeyboardInterrupt

    repository = FakeRepository()
    result = make_controller(tmp_path, runner=InterruptingRunner(), repository=repository).run("127.0.0.1")

    assert result.scan.status.value == "interrupted"
    assert result.scan.finished_at is not None
    assert (result.scan.results_path / "manifest.json").exists()


def test_timeout_is_recorded_and_dependents_skip(tmp_path: Path) -> None:
    result = make_controller(
        tmp_path,
        runner=FakeRunner({"ports": ExecutionStatus.TIMEOUT}),
        repository=FakeRepository(),
    ).run("127.0.0.1")

    assert [item.status.value for item in result.phase_results] == ["completed", "timeout", "skipped", "skipped"]
    assert result.scan.status.value == "failed"


def test_manifest_arguments_are_sanitized_by_runner_contract(tmp_path: Path) -> None:
    result = make_controller(tmp_path).run("127.0.0.1")
    manifest_text = (result.scan.results_path / "manifest.json").read_text(encoding="utf-8")

    assert "password" not in manifest_text.lower()
    assert "token" not in manifest_text.lower()
