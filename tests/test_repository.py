from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from reconforge.core.models import (
    ConfidenceLevel,
    Host,
    OSClassification,
    OSFamily,
    OSFingerprint,
    Scan,
    ScanStatus,
    Service,
)
from reconforge.core.repository import (
    RecordNotFoundError,
    Repository,
    RepositoryIntegrityError,
)


def scan(scan_id: str = "scan-1", status: ScanStatus = ScanStatus.RUNNING) -> Scan:
    started = datetime(2026, 9, 23, 12, 30, tzinfo=timezone.utc)
    return Scan(
        id=scan_id,
        target="192.168.1.0/24",
        started_at=started,
        finished_at=started if status is ScanStatus.COMPLETED else None,
        status=status,
        results_path=Path("data/scans") / scan_id,
        reconforge_version="0.1.0",
        nmap_version="7.99",
        workflow="default",
        arguments=("-sn", "-n"),
        error_message=None,
    )


def classified_host(ip: str = "192.168.1.10") -> Host:
    return Host(
        ip=ip,
        hostname="example.local",
        mac_address="AA:BB:CC:DD:EE:FF",
        vendor="Example Vendor",
        state="up",
        services=(
            Service(22, "tcp", "open", "ssh", "OpenSSH", "9.6", "Ubuntu"),
            Service(53, "udp", "open|filtered", "domain"),
        ),
        os_fingerprints=(
            OSFingerprint(
                vendor="Linux",
                family="Linux",
                generation="5.X",
                accuracy=95,
                source="nmap",
                evidence=("osmatch:name=Linux 5.x", "osclass:type=general purpose"),
            ),
        ),
        classification=OSClassification(
            family=OSFamily.LINUX_UNIX,
            confidence=ConfidenceLevel.HIGH,
            windows_score=0,
            unix_score=16.25,
        ),
    )


def test_database_initialization(tmp_path: Path) -> None:
    database = tmp_path / "nested" / "reconforge.db"
    Repository(database)

    repository = Repository(database)
    with repository._connection() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]

    assert tables == {"scans", "hosts", "services", "os_fingerprints", "enumeration_results", "enumeration_evidence"}
    assert {
        "idx_scans_started_at",
        "idx_hosts_scan_id",
        "idx_hosts_ip",
        "idx_services_host_id",
        "idx_services_port",
        "idx_os_fingerprints_host_id",
        "idx_enumeration_results_scan_id",
        "idx_enumeration_results_host_id",
        "idx_enumeration_evidence_result_id",
    } <= indexes
    assert foreign_keys == 1


def test_scan_create_retrieve_and_update(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    original = scan()
    repository.create_scan(original)

    assert repository.get_scan(original.id) == original

    completed = scan(status=ScanStatus.COMPLETED)
    repository.update_scan(completed)
    assert repository.get_scan(original.id).status is ScanStatus.COMPLETED
    assert repository.get_scan(original.id).finished_at == original.started_at


def test_scan_not_found_is_controlled(tmp_path: Path) -> None:
    with pytest.raises(RecordNotFoundError):
        Repository(tmp_path / "reconforge.db").get_scan("missing")


def test_host_and_children_round_trip(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())

    repository.save_host("scan-1", classified_host())
    hosts = repository.get_hosts("scan-1")

    assert hosts[0].ip == classified_host().ip
    assert hosts[0].services == classified_host().services
    assert hosts[0].os_fingerprints == classified_host().os_fingerprints
    assert hosts[0].classification is not None
    assert hosts[0].classification.family is OSFamily.LINUX_UNIX
    assert repository.get_services(1) == classified_host().services
    assert repository.get_os_fingerprints(1) == classified_host().os_fingerprints


def test_multiple_fingerprints_and_json_evidence_round_trip(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    host_id = repository.save_host("scan-1", Host(ip="192.168.1.20"))
    fingerprints = (
        OSFingerprint("Microsoft", "Windows", "10", 90, "nmap", ("match-a",)),
        OSFingerprint("Linux", "Linux", "5.X", 80, "nmap", ("match-b", "class-b")),
    )
    for item in fingerprints:
        repository.save_os_fingerprint(host_id, item)

    assert repository.get_os_fingerprints(host_id) == fingerprints
    with sqlite3.connect(tmp_path / "reconforge.db") as connection:
        stored = connection.execute("SELECT evidence FROM os_fingerprints ORDER BY id").fetchall()
    assert json.loads(stored[1][0]) == ["match-b", "class-b"]


def test_optional_fields_are_stored_as_null(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    host_id = repository.save_host("scan-1", Host(ip="192.168.1.30"))
    repository.save_service(host_id, Service(1234, "tcp", "closed"))
    repository.save_os_fingerprint(host_id, OSFingerprint())

    with sqlite3.connect(tmp_path / "reconforge.db") as connection:
        service_row = connection.execute("SELECT service_name, product FROM services").fetchone()
        fingerprint_row = connection.execute("SELECT vendor, family, source FROM os_fingerprints").fetchone()
    assert service_row == (None, None)
    assert fingerprint_row == (None, None, None)


def test_duplicate_host_is_rejected(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    repository.save_host("scan-1", Host(ip="192.168.1.40"))

    with pytest.raises(RepositoryIntegrityError):
        repository.save_host("scan-1", Host(ip="192.168.1.40"))


def test_duplicate_service_is_rejected(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    host_id = repository.save_host("scan-1", Host(ip="192.168.1.50"))
    service = Service(80, "tcp", "open", "http")
    repository.save_service(host_id, service)

    with pytest.raises(RepositoryIntegrityError):
        repository.save_service(host_id, service)


def test_foreign_keys_are_enforced(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")

    with pytest.raises(RepositoryIntegrityError):
        repository.save_host("missing", Host(ip="192.168.1.60"))
    with pytest.raises(RepositoryIntegrityError):
        repository.save_service(999, Service(80, "tcp", "open"))
    with pytest.raises(RepositoryIntegrityError):
        repository.save_os_fingerprint(999, OSFingerprint())


def test_save_host_is_atomic_when_child_insert_fails(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    host = Host(
        ip="192.168.1.70",
        services=(Service(80, "tcp", "open"), Service(80, "tcp", "closed")),
    )

    with pytest.raises(RepositoryIntegrityError):
        repository.save_host("scan-1", host)
    assert repository.get_hosts("scan-1") == ()


def test_deterministic_multiple_host_and_service_retrieval(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())
    repository.save_host("scan-1", Host(ip="192.168.1.90"))
    repository.save_host("scan-1", Host(ip="192.168.1.80"))
    host_id = repository.save_host("scan-1", Host(ip="192.168.1.85"))
    repository.save_service(host_id, Service(443, "tcp", "open"))
    repository.save_service(host_id, Service(22, "tcp", "open"))

    assert tuple(host.ip for host in repository.get_hosts("scan-1")) == (
        "192.168.1.80", "192.168.1.85", "192.168.1.90"
    )
    assert tuple(service.port for service in repository.get_services(host_id)) == (22, 443)


def test_empty_results_return_empty_tuples(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "reconforge.db")
    repository.create_scan(scan())

    assert repository.get_hosts("scan-1") == ()
    assert repository.get_services(999) == ()
    assert repository.get_os_fingerprints(999) == ()
