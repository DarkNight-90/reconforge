from datetime import datetime, timezone

from reconforge.core.models import (
    AttackSurface,
    AttackSurfaceHost,
    AttackSurfaceService,
    ConfidenceLevel,
    CorrelationCompleteness,
    CorrelationCompletenessStatus,
    CoverageStatus,
    EnumerationReference,
    EnumerationStatus,
    EvidenceReference,
    Host,
    ManifestExecution,
    OSClassification,
    OSFamily,
    ScanManifest,
    ScanStatus,
    Service,
    Technology,
    ExecutionStatus,
)
from reconforge.coverage import EvidenceCoverageAnalyzer
from reconforge.correlation import AttackSurfaceCorrelator


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def manifest(scan_id="scan-1", statuses=None):
    statuses = statuses or {
        "discovery": ExecutionStatus.COMPLETED,
        "ports": ExecutionStatus.COMPLETED,
        "services": ExecutionStatus.COMPLETED,
        "os": ExecutionStatus.COMPLETED,
    }
    return ScanManifest(
        schema_version=1,
        scan_id=scan_id,
        target="127.0.0.1",
        workflow="default",
        reconforge_version="0.1.0",
        nmap_version="7.99",
        created_at=NOW,
        updated_at=NOW,
        scan_status=ScanStatus.COMPLETED,
        executions=tuple(ManifestExecution(phase, f"{phase}.xml", status) for phase, status in statuses.items()),
    )


def surface(scan_id="scan-1", *, classification=None, enum_status=None, service_name="http", technology_refs=True):
    host_id = f"host:{scan_id}:127.0.0.1"
    service_id = f"service:{scan_id}:127.0.0.1:tcp:80"
    evidence = (EvidenceReference("service", service_id, "service_name", service_name or ""),)
    technology_id = f"technology:{host_id}:nginx:1.24"
    technology = Technology(technology_id, "nginx", "1.24", evidence_references=evidence if technology_refs else ())
    service = AttackSurfaceService(
        id=service_id,
        host_id=host_id,
        port=80,
        protocol="tcp",
        state="open",
        service_name=service_name,
        product="nginx",
        version="1.24",
        technology_ids=(technology_id,),
        enumeration_references=() if enum_status is None else (EnumerationReference("enum-1", "http", enum_status, ("evidence-1",)),),
        evidence_references=evidence,
    )
    host = AttackSurfaceHost(
        id=host_id,
        scan_id=scan_id,
        ip="127.0.0.1",
        state="up",
        classification=classification,
        services=(service,),
        technology_ids=(technology_id,),
        evidence_references=evidence,
    )
    return AttackSurface(
        scan_id=scan_id,
        generated_at=NOW,
        hosts=(host,),
        technologies=(technology,),
        completeness=CorrelationCompleteness(CorrelationCompletenessStatus.COMPLETE),
    )


def test_complete_phase_host_service_and_successful_enumeration_coverage():
    report = EvidenceCoverageAnalyzer().analyze(
        surface(classification=OSClassification(OSFamily.LINUX_UNIX, ConfidenceLevel.HIGH), enum_status=EnumerationStatus.SUCCESS),
        manifest(),
    )

    assert report.id == "coverage:scan-1"
    assert report.generated_at == NOW
    assert report.overall_status is CoverageStatus.COMPLETE
    assert [item.status for item in report.phase_coverage] == [CoverageStatus.COMPLETE] * 4
    assert report.host_coverage[0].os_status is CoverageStatus.COMPLETE
    assert report.service_coverage[0].observation_status is CoverageStatus.COMPLETE
    assert report.service_coverage[0].enumeration_statuses == (CoverageStatus.COMPLETE,)
    assert report.references


def test_phase_lifecycle_maps_failed_timeout_interrupted_skipped_pending_and_running():
    statuses = {
        "discovery": ExecutionStatus.FAILED,
        "ports": ExecutionStatus.TIMEOUT,
        "services": ExecutionStatus.INTERRUPTED,
        "os": ExecutionStatus.SKIPPED,
        "future": ExecutionStatus.PENDING,
        "running": ExecutionStatus.RUNNING,
    }
    report = EvidenceCoverageAnalyzer().analyze(surface(), manifest(statuses=statuses))
    values = {item.phase: item.status for item in report.phase_coverage}

    assert values["discovery"] is CoverageStatus.FAILED
    assert values["ports"] is CoverageStatus.TIMEOUT
    assert values["services"] is CoverageStatus.INTERRUPTED
    assert values["os"] is CoverageStatus.NOT_ATTEMPTED
    assert values["future"] is CoverageStatus.NOT_ATTEMPTED
    assert values["running"] is CoverageStatus.PARTIAL
    assert report.overall_status is CoverageStatus.PARTIAL


def test_unknown_missing_and_incomplete_os_are_distinct():
    unknown = EvidenceCoverageAnalyzer().analyze(
        surface(classification=OSClassification(OSFamily.UNKNOWN, ConfidenceLevel.LOW)), manifest()
    )
    missing = EvidenceCoverageAnalyzer().analyze(surface(), manifest(statuses={"os": ExecutionStatus.SKIPPED}))
    failed = EvidenceCoverageAnalyzer().analyze(surface(), manifest(statuses={"os": ExecutionStatus.FAILED}))

    assert unknown.host_coverage[0].os_status is CoverageStatus.COMPLETE
    assert "os_classification_unknown" in unknown.host_coverage[0].limitations
    assert missing.host_coverage[0].os_status is CoverageStatus.NOT_ATTEMPTED
    assert failed.host_coverage[0].os_status is CoverageStatus.FAILED


def test_missing_enumeration_is_not_attempted_and_unsupported_is_preserved():
    missing = EvidenceCoverageAnalyzer().analyze(surface(), manifest())
    unsupported = EvidenceCoverageAnalyzer().analyze(surface(enum_status=EnumerationStatus.UNSUPPORTED), manifest())

    assert missing.service_coverage[0].enumeration_statuses == (CoverageStatus.NOT_ATTEMPTED,)
    assert unsupported.service_coverage[0].enumeration_statuses == (CoverageStatus.UNSUPPORTED,)
    assert "enumeration:not_attempted" in missing.service_coverage[0].limitations



def test_failed_timeout_and_interrupted_enumeration_are_preserved():
    for source_status, coverage_status in (
        (EnumerationStatus.FAILED, CoverageStatus.FAILED),
        (EnumerationStatus.TIMEOUT, CoverageStatus.TIMEOUT),
        (EnumerationStatus.INTERRUPTED, CoverageStatus.INTERRUPTED),
    ):
        report = EvidenceCoverageAnalyzer().analyze(surface(enum_status=source_status), manifest())
        assert report.service_coverage[0].enumeration_statuses == (coverage_status,)


def test_missing_metadata_is_partial_only_when_service_identity_is_missing():
    complete = EvidenceCoverageAnalyzer().analyze(surface(service_name="http"), manifest())
    missing = EvidenceCoverageAnalyzer().analyze(surface(service_name=None), manifest())

    assert complete.service_coverage[0].metadata_status is CoverageStatus.COMPLETE
    assert missing.service_coverage[0].metadata_status is CoverageStatus.PARTIAL
    assert "missing_metadata:service_name" in missing.service_coverage[0].limitations


def test_missing_technology_provenance_and_conflicts_are_limitations():
    no_provenance = EvidenceCoverageAnalyzer().analyze(surface(technology_refs=False), manifest())
    conflicting = surface()
    host = conflicting.hosts[0]
    service = host.services[0]
    other_id = f"technology:{host.id}:Apache:2.4"
    other = Technology(other_id, "Apache", "2.4", evidence_references=service.evidence_references)
    conflicting = AttackSurface(
        **{**conflicting.__dict__, "technologies": (conflicting.technologies[0], other), "hosts": (
            AttackSurfaceHost(**{**host.__dict__, "services": (AttackSurfaceService(**{**service.__dict__, "technology_ids": (conflicting.technologies[0].id, other_id)}),)}),
        )}
    )
    conflict_report = EvidenceCoverageAnalyzer().analyze(conflicting, manifest())

    assert any(item.startswith("technology_provenance_missing:") for item in no_provenance.limitations)
    assert any(item.startswith("conflicting_technology_observations:") for item in conflict_report.limitations)


def test_analyzer_is_deterministic_and_rejects_mismatched_manifest():
    analyzer = EvidenceCoverageAnalyzer()
    first = analyzer.analyze(surface(), manifest())
    second = analyzer.analyze(surface(), manifest())
    assert first == second
    assert first.generated_at == NOW

    try:
        analyzer.analyze(surface("scan-1"), manifest("scan-2"))
    except ValueError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("mismatched manifest was accepted")
