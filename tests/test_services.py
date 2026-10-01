from datetime import datetime, timezone

from reconforge.cli import main
from reconforge.core.models import Host, Scan, Service
from reconforge.core.repository import Repository


def _create_scan(repository: Repository, scan_id: str = "scan-1") -> None:
    repository.create_scan(
        Scan(
            id=scan_id,
            target="192.0.2.0/24",
            started_at=datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc),
            reconforge_version="0.1.0",
        )
    )


def test_services_lists_persisted_service_details(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)
    repository.save_host(
        "scan-1",
        Host(
            ip="192.0.2.10",
            state="up",
            services=(Service(443, "tcp", "open", "https", "ExampleServer", "2.4", "TLS"),),
        ),
    )

    assert main(["services", "scan-1", "--data-dir", str(data_dir)]) == 0
    output = capsys.readouterr().out
    assert "Host: 192.0.2.10" in output
    assert "Port: 443/tcp" in output
    assert "State: open" in output
    assert "Service: https" in output
    assert "Product: ExampleServer 2.4" in output
    assert "Extra info: TLS" in output


def test_services_handles_scan_without_services(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)
    repository.save_host("scan-1", Host(ip="192.0.2.10", state="up"))

    assert main(["services", "scan-1", "--data-dir", str(data_dir)]) == 0
    assert "No services found." in capsys.readouterr().out


def test_services_reports_unknown_scan_id(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"

    assert main(["services", "missing-scan", "--data-dir", str(data_dir)]) == 1
    captured = capsys.readouterr()
    assert "scan not found: missing-scan" in captured.err
    assert captured.out == ""


def test_services_lists_services_from_multiple_hosts(tmp_path, capsys) -> None:
    data_dir = tmp_path / "data"
    repository = Repository(data_dir / "reconforge.db")
    _create_scan(repository)
    repository.save_host("scan-1", Host(ip="192.0.2.20", services=(Service(22, "tcp", "open", "ssh"),)))
    repository.save_host("scan-1", Host(ip="192.0.2.10", services=(Service(80, "tcp", "open", "http"),)))

    assert main(["services", "scan-1", "--data-dir", str(data_dir)]) == 0
    output = capsys.readouterr().out
    assert output.index("Host: 192.0.2.10") < output.index("Host: 192.0.2.20")
    assert "Port: 80/tcp" in output
    assert "Port: 22/tcp" in output
