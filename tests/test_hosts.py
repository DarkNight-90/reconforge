from datetime import datetime, timezone

from reconforge.cli import main
from reconforge.core.models import ConfidenceLevel, Host, OSClassification, OSFamily, Scan
from reconforge.core.repository import Repository


def _create_scan(repository: Repository, scan_id: str = "scan-1") -> None:
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    repository.create_scan(
        Scan(
            id=scan_id,
            target="192.0.2.0/24",
            started_at=now,
            reconforge_version="0.1.0",
        )
    )


def test_hosts_lists_host_details_for_scan(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)
    repository.save_host(
        "scan-1",
        Host(
            ip="192.0.2.10",
            hostname="lab-host.local",
            state="up",
            mac_address="AA:BB:CC:DD:EE:FF",
            vendor="Example Corp",
            classification=OSClassification(OSFamily.LINUX_UNIX, ConfidenceLevel.HIGH),
        ),
    )

    assert main(["hosts", "scan-1", "--data-dir", str(data_dir)]) == 0
    output = capsys.readouterr().out
    assert "192.0.2.10" in output
    assert "Hostname: lab-host.local" in output
    assert "State: up" in output
    assert "MAC: AA:BB:CC:DD:EE:FF" in output
    assert "Vendor: Example Corp" in output
    assert "OS: Linux/Unix" in output
    assert "Confidence: High" in output


def test_hosts_reports_empty_scan(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)

    assert main(["hosts", "scan-1", "--data-dir", str(data_dir)]) == 0
    assert "No hosts found." in capsys.readouterr().out


def test_hosts_handles_unknown_scan_id_cleanly(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"

    assert main(["hosts", "missing-scan", "--data-dir", str(data_dir)]) == 1
    captured = capsys.readouterr()
    assert "scan not found: missing-scan" in captured.err
    assert captured.out == ""


def test_hosts_lists_multiple_hosts_in_repository_order(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)
    repository.save_host("scan-1", Host(ip="192.0.2.20", state="up"))
    repository.save_host("scan-1", Host(ip="192.0.2.10", state="up"))

    assert main(["hosts", "scan-1", "--data-dir", str(data_dir)]) == 0
    output = capsys.readouterr().out
    assert output.index("192.0.2.10") < output.index("192.0.2.20")
    assert output.count("Host: ") == 2
