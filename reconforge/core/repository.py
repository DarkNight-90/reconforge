"""SQLite persistence for ReconForge domain observations."""

from contextlib import contextmanager
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
from typing import Any

from .models import (
    ConfidenceLevel,
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    Host,
    OSClassification,
    OSFamily,
    OSFingerprint,
    Scan,
    ScanStatus,
    Service,
)


class RepositoryError(RuntimeError):
    """Base class for controlled repository errors."""


class DatabaseInitializationError(RepositoryError):
    """Raised when the database schema cannot be initialized."""


class RecordNotFoundError(RepositoryError):
    """Raised when an expected record does not exist."""


class RepositoryIntegrityError(RepositoryError):
    """Raised when a foreign key or uniqueness constraint is violated."""


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    results_path TEXT,
    reconforge_version TEXT NOT NULL,
    nmap_version TEXT,
    workflow TEXT NOT NULL,
    arguments TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    vendor TEXT,
    state TEXT NOT NULL,
    os_family TEXT,
    os_confidence TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    UNIQUE (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE (host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS os_fingerprints (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL,
    vendor TEXT,
    family TEXT,
    generation TEXT,
    accuracy INTEGER,
    evidence TEXT NOT NULL,
    source TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enumeration_results (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    host_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration REAL,
    error_message TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE (scan_id, host_id, port, protocol, module)
);

CREATE TABLE IF NOT EXISTS enumeration_evidence (
    id INTEGER PRIMARY KEY,
    enumeration_result_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    indicator TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY (enumeration_result_id) REFERENCES enumeration_results(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);
CREATE INDEX IF NOT EXISTS idx_os_fingerprints_host_id ON os_fingerprints(host_id);
CREATE INDEX IF NOT EXISTS idx_enumeration_results_scan_id ON enumeration_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_enumeration_results_host_id ON enumeration_results(host_id);
CREATE INDEX IF NOT EXISTS idx_enumeration_evidence_result_id ON enumeration_evidence(enumeration_result_id);
"""


def _timestamp(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_timestamp(value: str | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RepositoryError(f"invalid stored timestamp for {field_name}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RepositoryError(f"stored timestamp is not UTC for {field_name}")
    return parsed


def _json_value(value: object, field_name: str) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise RepositoryError(f"unable to serialize {field_name}") from exc


def _load_json(value: str, field_name: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise RepositoryError(f"invalid stored JSON for {field_name}") from exc


class Repository:
    """Synchronous per-operation SQLite repository for domain observations."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.initialize()

    def initialize(self) -> None:
        """Create the database schema and approved indexes if needed."""
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connection() as connection:
                connection.executescript(_SCHEMA_SQL)
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseInitializationError(f"unable to initialize database: {self.database_path}") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        except Exception:
            if connection is not None:
                connection.rollback()
            raise
        else:
            if connection is not None:
                connection.commit()
        finally:
            if connection is not None:
                connection.close()

    def create_scan(self, scan: Scan) -> None:
        """Insert one scan record."""
        try:
            with self._connection() as connection:
                connection.execute(
                    """INSERT INTO scans
                    (id, target, started_at, finished_at, status, results_path,
                     reconforge_version, nmap_version, workflow, arguments, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan.id,
                        scan.target,
                        _timestamp(scan.started_at),
                        _timestamp(scan.finished_at),
                        scan.status.value,
                        str(scan.results_path) if scan.results_path is not None else None,
                        scan.reconforge_version,
                        scan.nmap_version,
                        scan.workflow,
                        _json_value(scan.arguments, "scan arguments"),
                        scan.error_message,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to create scan: {scan.id}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to create scan: {scan.id}") from exc

    def list_scans(self) -> tuple[Scan, ...]:
        """Return all known scans in newest-first order."""
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC, id DESC"
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError("unable to retrieve scan list") from exc
        return tuple(self._scan_from_row(row) for row in rows)

    def get_scan(self, scan_id: str) -> Scan:
        """Retrieve a scan by ID."""
        try:
            with self._connection() as connection:
                row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve scan: {scan_id}") from exc
        if row is None:
            raise RecordNotFoundError(f"scan not found: {scan_id}")
        return self._scan_from_row(row)

    def update_scan(self, scan: Scan) -> None:
        """Replace mutable scan metadata for an existing scan."""
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """UPDATE scans SET target = ?, started_at = ?, finished_at = ?, status = ?,
                    results_path = ?, reconforge_version = ?, nmap_version = ?, workflow = ?,
                    arguments = ?, error_message = ? WHERE id = ?""",
                    (
                        scan.target,
                        _timestamp(scan.started_at),
                        _timestamp(scan.finished_at),
                        scan.status.value,
                        str(scan.results_path) if scan.results_path is not None else None,
                        scan.reconforge_version,
                        scan.nmap_version,
                        scan.workflow,
                        _json_value(scan.arguments, "scan arguments"),
                        scan.error_message,
                        scan.id,
                    ),
                )
                if cursor.rowcount == 0:
                    raise RecordNotFoundError(f"scan not found: {scan.id}")
        except RecordNotFoundError:
            raise
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to update scan: {scan.id}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to update scan: {scan.id}") from exc

    def save_host(self, scan_id: str, host: Host) -> int:
        """Insert a host and all of its children in one transaction."""
        host_id: int
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """INSERT INTO hosts
                    (scan_id, ip, hostname, mac_address, vendor, state, os_family, os_confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        host.ip,
                        host.hostname,
                        host.mac_address,
                        host.vendor,
                        host.state,
                        host.classification.family.value if host.classification else None,
                        host.classification.confidence.value if host.classification else None,
                    ),
                )
                host_id = cursor.lastrowid
                for service in host.services:
                    self._insert_service(connection, host_id, service)
                for fingerprint in host.os_fingerprints:
                    self._insert_fingerprint(connection, host_id, fingerprint)
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to save host: {host.ip}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to save host: {host.ip}") from exc
        return host_id

    def update_host(self, scan_id: str, host: Host) -> None:
        """Merge refreshed host observations into an existing host transactionally."""
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT id FROM hosts WHERE scan_id = ? AND ip = ?", (scan_id, host.ip)
                ).fetchone()
                if row is None:
                    raise RecordNotFoundError(f"host not found: {host.ip}")
                host_id = int(row["id"])
                connection.execute(
                    """UPDATE hosts SET
                    hostname = COALESCE(?, hostname),
                    mac_address = COALESCE(?, mac_address),
                    vendor = COALESCE(?, vendor),
                    state = ?,
                    os_family = COALESCE(?, os_family),
                    os_confidence = COALESCE(?, os_confidence)
                    WHERE id = ?""",
                    (
                        host.hostname,
                        host.mac_address,
                        host.vendor,
                        host.state,
                        host.classification.family.value if host.classification else None,
                        host.classification.confidence.value if host.classification else None,
                        host_id,
                    ),
                )
                for service in host.services:
                    connection.execute(
                        """INSERT INTO services
                        (host_id, port, protocol, state, service_name, product, version, extra_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                        state = excluded.state,
                        service_name = COALESCE(excluded.service_name, services.service_name),
                        product = COALESCE(excluded.product, services.product),
                        version = COALESCE(excluded.version, services.version),
                        extra_info = COALESCE(excluded.extra_info, services.extra_info)""",
                        (
                            host_id,
                            service.port,
                            service.protocol,
                            service.state,
                            service.service_name,
                            service.product,
                            service.version,
                            service.extra_info,
                        ),
                    )
                for fingerprint in host.os_fingerprints:
                    evidence = _json_value(fingerprint.evidence, "fingerprint evidence")
                    duplicate = connection.execute(
                        """SELECT 1 FROM os_fingerprints
                        WHERE host_id = ? AND vendor IS ? AND family IS ? AND generation IS ?
                        AND accuracy IS ? AND evidence = ? AND source IS ? LIMIT 1""",
                        (
                            host_id,
                            fingerprint.vendor,
                            fingerprint.family,
                            fingerprint.generation,
                            fingerprint.accuracy,
                            evidence,
                            fingerprint.source,
                        ),
                    ).fetchone()
                    if duplicate is None:
                        self._insert_fingerprint(connection, host_id, fingerprint)
        except RecordNotFoundError:
            raise
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to update host: {host.ip}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to update host: {host.ip}") from exc

    def get_hosts(self, scan_id: str) -> tuple[Host, ...]:
        """Retrieve hosts and their observations in deterministic IP order."""
        try:
            with self._connection() as connection:
                rows = connection.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY ip", (scan_id,)).fetchall()
                return tuple(self._host_from_row(connection, row) for row in rows)
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve hosts for scan: {scan_id}") from exc

    def get_host_id(self, scan_id: str, ip: str) -> int:
        """Return the persisted host row ID for an IP in one scan."""
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT id FROM hosts WHERE scan_id = ? AND ip = ?",
                    (scan_id, ip),
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve host id for {ip} in scan: {scan_id}") from exc
        if row is None:
            raise RecordNotFoundError(f"host not found: {ip}")
        return int(row["id"])

    def save_service(self, host_id: int, service: Service) -> None:
        """Insert one service for an existing host."""
        try:
            with self._connection() as connection:
                self._insert_service(connection, host_id, service)
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to save service: {service.port}/{service.protocol}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to save service: {service.port}/{service.protocol}") from exc

    def get_services(self, host_id: int) -> tuple[Service, ...]:
        """Retrieve services in port and protocol order."""
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM services WHERE host_id = ? ORDER BY port, protocol", (host_id,)
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve services for host: {host_id}") from exc
        return tuple(self._service_from_row(row) for row in rows)

    def save_os_fingerprint(self, host_id: int, fingerprint: OSFingerprint) -> None:
        """Insert one raw OS fingerprint observation."""
        try:
            with self._connection() as connection:
                self._insert_fingerprint(connection, host_id, fingerprint)
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to save OS fingerprint for host: {host_id}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to save OS fingerprint for host: {host_id}") from exc

    def get_os_fingerprints(self, host_id: int) -> tuple[OSFingerprint, ...]:
        """Retrieve all fingerprints in insertion order."""
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM os_fingerprints WHERE host_id = ? ORDER BY id", (host_id,)
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve OS fingerprints for host: {host_id}") from exc
        return tuple(self._fingerprint_from_row(row) for row in rows)

    def save_enumeration_result(self, result: EnumerationResult) -> EnumerationResult:
        """Persist one enumeration result and all of its structured evidence."""
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """INSERT INTO enumeration_results
                    (scan_id, host_id, ip, port, protocol, module, status, started_at, finished_at, duration, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, host_id, port, protocol, module)
                    DO UPDATE SET
                        ip = excluded.ip,
                        status = excluded.status,
                        started_at = excluded.started_at,
                        finished_at = excluded.finished_at,
                        duration = excluded.duration,
                        error_message = excluded.error_message""",
                    (
                        result.scan_id,
                        result.host_id,
                        result.ip,
                        result.port,
                        result.protocol,
                        result.module,
                        result.status.value,
                        _timestamp(result.started_at),
                        _timestamp(result.finished_at),
                        result.duration,
                        result.error_message,
                    ),
                )
                result_id = connection.execute(
                    "SELECT id FROM enumeration_results WHERE scan_id = ? AND host_id = ? AND port = ? AND protocol = ? AND module = ?",
                    (result.scan_id, result.host_id, result.port, result.protocol, result.module),
                ).fetchone()["id"]
                connection.execute("DELETE FROM enumeration_evidence WHERE enumeration_result_id = ?", (result_id,))
                for evidence in tuple(result.evidence or ()):
                    connection.execute(
                        """INSERT INTO enumeration_evidence
                        (enumeration_result_id, source, category, indicator, value, confidence, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            result_id,
                            evidence.source,
                            evidence.category,
                            evidence.indicator,
                            evidence.value,
                            evidence.confidence,
                            evidence.details,
                        ),
                    )
                return replace(result, id=result_id)
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(f"unable to save enumeration result for {result.ip}:{result.port}") from exc
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to save enumeration result for {result.ip}:{result.port}") from exc

    def get_enumeration_results(self, scan_id: str) -> tuple[EnumerationResult, ...]:
        """Retrieve enumeration results and evidence in deterministic order."""
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM enumeration_results WHERE scan_id = ? ORDER BY host_id, port, protocol, module, id",
                    (scan_id,),
                ).fetchall()
                results: list[EnumerationResult] = []
                for row in rows:
                    evidence_rows = connection.execute(
                        "SELECT * FROM enumeration_evidence WHERE enumeration_result_id = ? ORDER BY id",
                        (row["id"],),
                    ).fetchall()
                    results.append(self._enumeration_result_from_row(row, tuple(self._evidence_from_row(item) for item in evidence_rows)))
                return tuple(results)
        except sqlite3.Error as exc:
            raise RepositoryError(f"unable to retrieve enumeration results for scan: {scan_id}") from exc

    @staticmethod
    def _evidence_from_row(row: sqlite3.Row) -> EnumerationEvidence:
        return EnumerationEvidence(
            source=row["source"],
            category=row["category"],
            indicator=row["indicator"],
            value=row["value"],
            confidence=row["confidence"],
            details=row["details"],
        )

    @staticmethod
    def _enumeration_result_from_row(row: sqlite3.Row, evidence: tuple[EnumerationEvidence, ...]) -> EnumerationResult:
        status = EnumerationStatus(row["status"])
        return EnumerationResult(
            id=row["id"],
            scan_id=row["scan_id"],
            host_id=row["host_id"],
            ip=row["ip"],
            port=row["port"],
            protocol=row["protocol"],
            module=row["module"],
            status=status,
            started_at=_parse_timestamp(row["started_at"], "started_at"),
            finished_at=_parse_timestamp(row["finished_at"], "finished_at"),
            duration=row["duration"],
            error_message=row["error_message"],
            evidence=evidence,
        )

    @staticmethod
    def _insert_service(connection: sqlite3.Connection, host_id: int, service: Service) -> None:
        connection.execute(
            """INSERT INTO services
            (host_id, port, protocol, state, service_name, product, version, extra_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, service.port, service.protocol, service.state, service.service_name,
             service.product, service.version, service.extra_info),
        )

    @staticmethod
    def _insert_fingerprint(connection: sqlite3.Connection, host_id: int, fingerprint: OSFingerprint) -> None:
        connection.execute(
            """INSERT INTO os_fingerprints
            (host_id, vendor, family, generation, accuracy, evidence, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (host_id, fingerprint.vendor, fingerprint.family, fingerprint.generation,
             fingerprint.accuracy, _json_value(fingerprint.evidence, "fingerprint evidence"), fingerprint.source),
        )

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> Scan:
        arguments = _load_json(row["arguments"], "scan arguments")
        if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
            raise RepositoryError("stored scan arguments must be a JSON string list")
        try:
            status = ScanStatus(row["status"])
        except ValueError as exc:
            raise RepositoryError(f"invalid stored scan status: {row['status']}") from exc
        return Scan(
            id=row["id"], target=row["target"], started_at=_parse_timestamp(row["started_at"], "started_at"),
            finished_at=_parse_timestamp(row["finished_at"], "finished_at"), status=status,
            results_path=Path(row["results_path"]) if row["results_path"] is not None else None,
            reconforge_version=row["reconforge_version"], nmap_version=row["nmap_version"],
            workflow=row["workflow"], arguments=tuple(arguments), error_message=row["error_message"],
        )

    def _host_from_row(self, connection: sqlite3.Connection, row: sqlite3.Row) -> Host:
        classification = None
        if row["os_family"] is not None and row["os_confidence"] is not None:
            try:
                classification = OSClassification(
                    family=OSFamily(row["os_family"]), confidence=ConfidenceLevel(row["os_confidence"])
                )
            except ValueError as exc:
                raise RepositoryError(f"invalid stored classification for host: {row['ip']}") from exc
        services = connection.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port, protocol", (row["id"],)
        ).fetchall()
        fingerprints = connection.execute(
            "SELECT * FROM os_fingerprints WHERE host_id = ? ORDER BY id", (row["id"],)
        ).fetchall()
        return Host(
            ip=row["ip"], hostname=row["hostname"], mac_address=row["mac_address"], vendor=row["vendor"],
            state=row["state"], services=tuple(self._service_from_row(item) for item in services),
            os_fingerprints=tuple(self._fingerprint_from_row(item) for item in fingerprints),
            classification=classification,
        )

    @staticmethod
    def _service_from_row(row: sqlite3.Row) -> Service:
        return Service(
            port=row["port"], protocol=row["protocol"], state=row["state"], service_name=row["service_name"],
            product=row["product"], version=row["version"], extra_info=row["extra_info"],
        )

    @staticmethod
    def _fingerprint_from_row(row: sqlite3.Row) -> OSFingerprint:
        evidence = _load_json(row["evidence"], "fingerprint evidence")
        if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
            raise RepositoryError("stored fingerprint evidence must be a JSON string list")
        return OSFingerprint(
            vendor=row["vendor"], family=row["family"], generation=row["generation"], accuracy=row["accuracy"],
            evidence=tuple(evidence), source=row["source"],
        )
