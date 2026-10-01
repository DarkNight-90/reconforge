from datetime import datetime, timezone

from reconforge.core.models import (
    AttackSurface,
    AttackSurfaceHost,
    AttackSurfaceService,
    CorrelationCompleteness,
    CorrelationCompletenessStatus,
    DiffChangeType,
    DiffCompletenessStatus,
    DiffEntityType,
    EnumerationReference,
    EnumerationStatus,
    EvidenceReference,
    Exposure,
    Relationship,
    RelationshipType,
    ScanStatus,
    Technology,
    OSClassification,
    OSFamily,
    ConfidenceLevel,
)
from reconforge.diff import AttackSurfaceDiffer


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def reference(scan_id: str, field: str, value: str) -> EvidenceReference:
    return EvidenceReference("service", f"service:{scan_id}:10.0.0.1:tcp:80", field, value)


def surface(
    scan_id: str,
    *,
    ip: str = "10.0.0.1",
    port: int = 80,
    state: str = "open",
    product: str | None = "nginx",
    version: str | None = "1.24",
    service_name: str | None = "http",
    technology: Technology | None = None,
    enumeration_status: EnumerationStatus | None = None,
    complete: bool = True,
    os: OSClassification | None = None,
) -> AttackSurface:
    host_id = f"host:{scan_id}:{ip}"
    service_id = f"service:{scan_id}:{ip}:tcp:{port}"
    service_ref = reference(scan_id, "product", product or "") if product else ()
    enum_refs = () if enumeration_status is None else (EnumerationReference(f"enumeration:{scan_id}:1:{port}:tcp:http", "http", enumeration_status),)
    service = AttackSurfaceService(
        id=service_id,
        host_id=host_id,
        port=port,
        protocol="tcp",
        state=state,
        service_name=service_name,
        product=product,
        version=version,
        enumeration_references=enum_refs,
        evidence_references=(service_ref,) if service_ref else (),
        technology_ids=(technology.id,) if technology else (),
    )
    exposure_id = f"exposure:{scan_id}:{ip}:tcp:{port}:service_observed"
    exposure = Exposure(
        id=exposure_id,
        host_id=host_id,
        service_id=service_id,
        kind="service_observed",
        port=port,
        protocol="tcp",
        state=state,
        service_name=service_name,
        evidence_references=(service_ref,) if service_ref else (),
    )
    host = AttackSurfaceHost(
        id=host_id,
        scan_id=scan_id,
        ip=ip,
        state="up",
        classification=os,
        services=(service,),
        technology_ids=(technology.id,) if technology else (),
        exposure_ids=(exposure_id,),
        evidence_references=(),
    )
    return AttackSurface(
        scan_id=scan_id,
        generated_at=NOW,
        hosts=(host,),
        technologies=(technology,) if technology else (),
        exposures=(exposure,),
        relationships=(
            Relationship(RelationshipType.HOST_HAS_SERVICE, host_id, service_id, (service_ref,) if service_ref else ()),
        ),
        source_scan_status=ScanStatus.COMPLETED,
        completeness=CorrelationCompleteness(
            CorrelationCompletenessStatus.COMPLETE if complete else CorrelationCompletenessStatus.SERVICE_DATA_INCOMPLETE,
            () if complete else ("services:failed",),
        ),
    )


def technology(scan_id: str, name: str = "nginx", version: str | None = "1.24") -> Technology:
    return Technology(
        id=f"technology:host:{scan_id}:10.0.0.1:{name}:{version or 'none'}",
        name=name,
        version=version,
        evidence_references=(reference(scan_id, "product", name),),
    )


def changes(diff):
    return diff.host_changes + diff.service_changes + diff.os_changes + diff.technology_changes + diff.exposure_changes + diff.relationship_changes + diff.enumeration_changes + diff.evidence_changes


def test_same_ip_matches_across_scan_scoped_m9_host_ids():
    diff = AttackSurfaceDiffer().compare(surface("scan-a"), surface("scan-b"))
    assert diff.host_changes == ()
    assert diff.service_changes == ()
    assert diff.id == "diff:scan-a:scan-b"


def test_ip_change_is_removed_and_added():
    diff = AttackSurfaceDiffer().compare(surface("scan-a", ip="10.0.0.1"), surface("scan-b", ip="10.0.0.2"))
    assert {item.change_type for item in diff.host_changes} == {DiffChangeType.ADDED, DiffChangeType.REMOVED}
    assert {item.comparison_key for item in diff.host_changes} == {"10.0.0.1", "10.0.0.2"}


def test_service_added_removed_and_changed():
    added = AttackSurfaceDiffer().compare(surface("scan-a", port=80), surface("scan-b", port=443))
    assert {item.change_type for item in added.service_changes} == {DiffChangeType.ADDED, DiffChangeType.REMOVED}
    changed = AttackSurfaceDiffer().compare(surface("scan-a", state="open"), surface("scan-b", state="filtered"))
    assert changed.service_changes[0].change_type is DiffChangeType.CHANGED
    assert changed.service_changes[0].comparison_key == "10.0.0.1:tcp:80"


def test_os_change_consumes_existing_classification():
    baseline = surface("scan-a", os=OSClassification(OSFamily.WINDOWS, ConfidenceLevel.HIGH))
    current = surface("scan-b", os=OSClassification(OSFamily.LINUX_UNIX, ConfidenceLevel.MEDIUM))
    diff = AttackSurfaceDiffer().compare(baseline, current)
    assert diff.os_changes[0].change_type is DiffChangeType.CHANGED
    assert diff.os_changes[0].entity_type is DiffEntityType.OS


def test_technology_version_change_is_changed_and_provenance_is_retained():
    diff = AttackSurfaceDiffer().compare(surface("scan-a", technology=technology("scan-a", version="1.24")), surface("scan-b", technology=technology("scan-b", version="1.25")))
    assert diff.technology_changes[0].change_type is DiffChangeType.CHANGED
    assert next(field.value for field in diff.technology_changes[0].before.fields if field.name == "version") == "1.24"
    assert diff.technology_changes[0].evidence_references


def test_exposure_state_change_is_changed():
    diff = AttackSurfaceDiffer().compare(surface("scan-a", state="open"), surface("scan-b", state="filtered"))
    assert any(item.change_type is DiffChangeType.CHANGED for item in diff.exposure_changes)


def test_enumeration_lifecycle_change_is_preserved():
    diff = AttackSurfaceDiffer().compare(surface("scan-a", enumeration_status=EnumerationStatus.SUCCESS), surface("scan-b", enumeration_status=EnumerationStatus.TIMEOUT))
    assert diff.enumeration_changes[0].change_type is DiffChangeType.CHANGED
    assert next(field.value for field in diff.enumeration_changes[0].after.fields if field.name == "status") == "timeout"


def test_incomplete_current_scan_does_not_confirm_removals():
    baseline = surface("scan-a", product="Apache", technology=technology("scan-a", name="Apache", version="2.4"))
    current = surface("scan-b", product=None, version=None, complete=False)
    diff = AttackSurfaceDiffer().compare(baseline, current)
    assert any(item.change_type is DiffChangeType.UNKNOWN for item in diff.technology_changes)
    assert any(item.qualification for item in diff.technology_changes)
    assert diff.completeness.status is not DiffCompletenessStatus.COMPLETE


def test_repeated_comparison_is_deterministic_and_directional():
    differ = AttackSurfaceDiffer()
    forward = differ.compare(surface("scan-a"), surface("scan-b", product="Apache"))
    repeated = differ.compare(surface("scan-a"), surface("scan-b", product="Apache"))
    reverse = differ.compare(surface("scan-b", product="Apache"), surface("scan-a"))
    assert forward == repeated
    assert forward.id != reverse.id
    assert any(item.change_type is DiffChangeType.CHANGED for item in forward.service_changes)


def test_relationships_normalize_scan_scoped_ids():
    diff = AttackSurfaceDiffer().compare(surface("scan-a"), surface("scan-b"))
    assert diff.relationship_changes == ()


def test_missing_technology_is_not_removed_when_enumeration_failed():
    baseline = surface("scan-a", technology=technology("scan-a"))
    current = surface("scan-b", enumeration_status=EnumerationStatus.FAILED)
    diff = AttackSurfaceDiffer().compare(baseline, current)
    assert any(item.change_type is DiffChangeType.UNKNOWN for item in diff.technology_changes)
