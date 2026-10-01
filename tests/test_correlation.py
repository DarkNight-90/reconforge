from datetime import datetime, timezone

from reconforge.correlation import AttackSurfaceCorrelator
from reconforge.core.models import (
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    ExecutionStatus,
    Host,
    ManifestExecution,
    OSClassification,
    OSFamily,
    ConfidenceLevel,
    Scan,
    ScanManifest,
    ScanStatus,
    Service,
)


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


class ReadOnlyRepository:
    def __init__(self, scan: Scan, hosts=(), results=()):
        self.scan = scan
        self.hosts = tuple(hosts)
        self.results = tuple(results)
        self.write_calls = 0

    def get_scan(self, scan_id):
        assert scan_id == self.scan.id
        return self.scan

    def get_hosts(self, scan_id):
        assert scan_id == self.scan.id
        return self.hosts

    def get_host_id(self, scan_id, ip):
        return {host.ip: index + 1 for index, host in enumerate(self.hosts)}[ip]

    def get_enumeration_results(self, scan_id):
        assert scan_id == self.scan.id
        return self.results


def completed_scan(scan_id="scan-1"):
    return Scan(
        id=scan_id,
        target="192.168.1.0/24",
        started_at=NOW,
        finished_at=NOW,
        status=ScanStatus.COMPLETED,
        reconforge_version="0.1.0",
    )


def complete_manifest(scan_id="scan-1"):
    return ScanManifest(
        schema_version=1,
        scan_id=scan_id,
        target="192.168.1.0/24",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=NOW,
        updated_at=NOW,
        scan_status=ScanStatus.COMPLETED,
        executions=tuple(
            ManifestExecution(phase, f"{phase}.xml", ExecutionStatus.COMPLETED)
            for phase in ("discovery", "ports", "services", "os")
        ),
    )


def enumerate_result(service, host_id=1, module="http", status=EnumerationStatus.SUCCESS, evidence=()):
    return EnumerationResult(
        scan_id="scan-1",
        host_id=host_id,
        ip="192.168.1.10",
        port=service.port,
        protocol=service.protocol,
        module=module,
        status=status,
        started_at=NOW,
        finished_at=NOW,
        evidence=tuple(evidence),
    )


def test_basic_host_and_service_correlation_creates_stable_entities():
    service = Service(443, "TCP", "filtered", "https", "nginx", "1.24.0")
    host = Host("192.168.1.10", state="up", services=(service,))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1", complete_manifest())

    assert surface.generated_at == NOW
    assert surface.completeness.status.value == "complete"
    assert surface.hosts[0].id == "host:scan-1:192.168.1.10"
    assert surface.hosts[0].services[0].id == "service:scan-1:192.168.1.10:tcp:443"
    assert {exposure.kind for exposure in surface.exposures} == {"service_observed", "https_service_observed"}
    assert next(exposure for exposure in surface.exposures if exposure.kind == "service_observed").state == "filtered"
    assert {relationship.type.value for relationship in surface.relationships} >= {"HOST_HAS_SERVICE", "SERVICE_EXPOSES_PORT"}


def test_port_alone_does_not_create_protocol_exposure_or_technology():
    host = Host("192.168.1.10", state="up", services=(Service(80, "tcp", "open"), Service(22, "tcp", "open")))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1")

    assert {exposure.kind for exposure in surface.exposures} == {"service_observed"}
    assert surface.technologies == ()


def test_explicit_service_names_create_protocol_exposures_without_generic_technologies():
    host = Host(
        "192.168.1.10",
        services=(Service(80, "tcp", "open", "http"), Service(22, "tcp", "open", "ssh")),
    )
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1")

    assert {exposure.kind for exposure in surface.exposures} == {
        "service_observed",
        "http_service_observed",
        "ssh_service_observed",
    }
    assert surface.technologies == ()


def test_os_classification_is_consumed_without_reclassification():
    classification = OSClassification(family=OSFamily.UNKNOWN, confidence=ConfidenceLevel.LOW)
    host = Host("192.168.1.10", classification=classification)
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1")

    assert surface.hosts[0].classification is classification
    assert any(relationship.type.value == "HOST_HAS_OS" for relationship in surface.relationships)


def test_successful_enumeration_creates_technology_with_provenance():
    service = Service(80, "tcp", "open", "http")
    result = enumerate_result(
        service,
        evidence=(EnumerationEvidence("http_headers", "technology", "server", "nginx/1.24.0", "medium", "Server header"),),
    )
    host = Host("192.168.1.10", services=(service,))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,), (result,))).correlate("scan-1")

    assert [(item.name, item.version) for item in surface.technologies] == [("nginx", "1.24.0")]
    assert surface.technologies[0].evidence_references[0].source_type == "enumeration_evidence"
    assert surface.hosts[0].services[0].enumeration_references[0].status is EnumerationStatus.SUCCESS


def test_service_product_and_conflicting_enumeration_technologies_are_preserved():
    service = Service(80, "tcp", "open", "http", "nginx")
    result = enumerate_result(
        service,
        evidence=(EnumerationEvidence("http_headers", "technology", "server", "Apache/2.4.0", "medium", "Server header"),),
    )
    host = Host("192.168.1.10", services=(service,))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,), (result,))).correlate("scan-1")

    assert {item.name for item in surface.technologies} == {"nginx", "Apache"}
    assert all(item.evidence_references for item in surface.technologies)


def test_failed_timeout_and_interrupted_enumeration_do_not_create_technology():
    service = Service(80, "tcp", "open", "http")
    results = tuple(
        enumerate_result(service, module=module, status=status)
        for module, status in (
            ("http-failed", EnumerationStatus.FAILED),
            ("http-timeout", EnumerationStatus.TIMEOUT),
            ("http-interrupted", EnumerationStatus.INTERRUPTED),
        )
    )
    host = Host("192.168.1.10", services=(service,))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,), results)).correlate("scan-1")

    assert surface.technologies == ()
    assert len(surface.exposures) == 2


def test_tls_certificate_metadata_creates_exposure_but_not_product_technology():
    service = Service(443, "tcp", "open", "https")
    result = enumerate_result(
        service,
        module="tls",
        evidence=(EnumerationEvidence("tls_certificate", "certificate", "subject", "example.test", "high", "Certificate subject"),),
    )
    host = Host("192.168.1.10", services=(service,))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,), (result,))).correlate("scan-1")

    assert "tls_certificate_observed" in {exposure.kind for exposure in surface.exposures}
    assert surface.technologies == ()


def test_invalid_service_fields_are_kept_but_do_not_create_exposure():
    host = Host("192.168.1.10", services=(Service(0, "", ""), Service(70000, "tcp", "open")))
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1")

    assert len(surface.hosts[0].services) == 2
    assert surface.exposures == ()


def test_partial_manifest_reports_incomplete_coverage():
    host = Host("192.168.1.10", services=(Service(80, "tcp", "open", "http"),))
    manifest = ScanManifest(
        schema_version=1,
        scan_id="scan-1",
        target="192.168.1.0/24",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version=None,
        created_at=NOW,
        updated_at=NOW,
        scan_status=ScanStatus.FAILED,
        executions=(
            ManifestExecution("discovery", "discovery.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("ports", "ports.xml", ExecutionStatus.COMPLETED),
            ManifestExecution("services", "services.xml", ExecutionStatus.FAILED),
            ManifestExecution("os", None, ExecutionStatus.SKIPPED),
        ),
    )
    surface = AttackSurfaceCorrelator(ReadOnlyRepository(completed_scan(), (host,))).correlate("scan-1", manifest)

    assert surface.completeness.status.value == "service_data_incomplete"
    assert "services:failed" in surface.completeness.issues


def test_same_evidence_in_different_insertion_order_is_deterministic():
    services = (Service(443, "tcp", "open", "https", "nginx", "1.24.0"), Service(22, "tcp", "open", "ssh", "OpenSSH"))
    first = Host("192.168.1.20", services=services)
    second = Host("192.168.1.10", services=tuple(reversed(services)))
    repo_a = ReadOnlyRepository(completed_scan(), (first, second))
    repo_b = ReadOnlyRepository(completed_scan(), (second, first))

    assert AttackSurfaceCorrelator(repo_a).correlate("scan-1") == AttackSurfaceCorrelator(repo_b).correlate("scan-1")


def test_correlator_performs_no_repository_writes():
    repository = ReadOnlyRepository(completed_scan(), (Host("192.168.1.10"),))
    AttackSurfaceCorrelator(repository).correlate("scan-1")

    assert repository.write_calls == 0
