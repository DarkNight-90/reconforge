import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from reconforge.core.models import (
    AttackSurface,
    AttackSurfaceHost,
    AttackSurfaceService,
    ConfidenceLevel,
    CorrelationCompleteness,
    CorrelationCompletenessStatus,
    DiffChangeType,
    DiffCompleteness,
    DiffCompletenessStatus,
    DiffEntityType,
    DiffField,
    DiffSnapshot,
    EnumerationReference,
    EnumerationStatus,
    EvidenceReference,
    Exposure,
    Host,
    OSClassification,
    OSFamily,
    Relationship,
    RelationshipType,
    ScanStatus,
    SurfaceChange,
    Technology,
)
from reconforge.diff import AttackSurfaceDiffer
from reconforge.reports.structured import (
    SCHEMA_VERSION,
    attack_surface_diff_to_dict,
    attack_surface_to_dict,
    report_to_dict,
    serialize_report,
    write_report,
)


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def ref(source_id: str = "source-1", value: str = "nginx") -> EvidenceReference:
    return EvidenceReference("enumeration_evidence", source_id, "server", value, "Server header")


def populated_surface(scan_id: str = "scan-1") -> AttackSurface:
    host_id = f"host:{scan_id}:10.0.0.1"
    service_id = f"service:{scan_id}:10.0.0.1:tcp:443"
    technology_id = f"technology:10.0.0.1:nginx:1.24"
    exposure_id = f"exposure:{scan_id}:10.0.0.1:tcp:443:service_observed"
    evidence = ref(f"enumeration:{scan_id}:1:443:tcp:http:headers", "nginx/1.24")
    classification = OSClassification(
        family=OSFamily.LINUX_UNIX,
        confidence=ConfidenceLevel.HIGH,
        evidence=(),
        windows_score=0.0,
        unix_score=10.0,
    )
    service = AttackSurfaceService(
        id=service_id,
        host_id=host_id,
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
        product="nginx",
        version="1.24",
        extra_info=None,
        technology_ids=(technology_id,),
        enumeration_references=(EnumerationReference("enum-1", "http", EnumerationStatus.SUCCESS, ("evidence-1",)),),
        evidence_references=(evidence,),
    )
    host = AttackSurfaceHost(
        id=host_id,
        scan_id=scan_id,
        ip="10.0.0.1",
        hostname=None,
        state="up",
        mac_address=None,
        vendor="Example",
        classification=classification,
        services=(service,),
        technology_ids=(technology_id,),
        exposure_ids=(exposure_id,),
        evidence_references=(evidence,),
    )
    return AttackSurface(
        scan_id=scan_id,
        generated_at=NOW,
        hosts=(host,),
        technologies=(Technology(technology_id, "nginx", "1.24", "implementation", (evidence,)),),
        exposures=(Exposure(exposure_id, host_id, service_id, "service_observed", 443, "tcp", "open", "https", (evidence,)),),
        relationships=(Relationship(RelationshipType.HOST_HAS_SERVICE, host_id, service_id, (evidence,)),),
        source_scan_status=ScanStatus.COMPLETED,
        completeness=CorrelationCompleteness(CorrelationCompletenessStatus.COMPLETE),
    )


def test_minimal_and_empty_attack_surface_schema():
    surface = AttackSurface("empty", NOW)
    payload = attack_surface_to_dict(surface)

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["report_type"] == "attack_surface"
    assert payload["hosts"] == []
    assert payload["generated_at"] == NOW.isoformat()
    assert json.loads(serialize_report(surface))["completeness"]["status"] == "partial"


def test_populated_attack_surface_preserves_nested_models_and_provenance():
    payload = attack_surface_to_dict(populated_surface())

    assert payload["hosts"][0]["services"][0]["enumeration_references"][0]["status"] == "success"
    assert payload["technologies"][0]["evidence_references"][0]["source_id"].startswith("enumeration:")
    assert payload["exposures"][0]["state"] == "open"
    assert payload["relationships"][0]["type"] == "HOST_HAS_SERVICE"
    assert payload["hosts"][0]["classification"]["family"] == "Linux/Unix"
    assert payload["hosts"][0]["hostname"] is None


def test_diff_schema_preserves_snapshots_completeness_and_qualifications():
    before = DiffSnapshot((DiffField("state", "open", (ref("before"),)),))
    after = DiffSnapshot((DiffField("state", "filtered", (ref("after"),)),))
    change = SurfaceChange(
        "change:base:current:exposure:key:changed",
        DiffEntityType.EXPOSURE,
        DiffChangeType.UNKNOWN,
        "10.0.0.1:tcp:443:service_observed",
        before,
        after,
        (ref("change"),),
        "current_service_coverage_incomplete",
    )
    diff = __import__("reconforge.core.models", fromlist=["AttackSurfaceDiff"]).AttackSurfaceDiff(
        "base",
        "current",
        NOW,
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        DiffCompleteness(
            DiffCompletenessStatus.CURRENT_INCOMPLETE,
            ("current:services:failed",),
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
        ),
        exposure_changes=(change,),
    )
    payload = attack_surface_diff_to_dict(diff)

    assert payload["report_type"] == "attack_surface_diff"
    assert payload["completeness"]["baseline_scan_status"] == "completed"
    assert payload["completeness"]["current_scan_status"] == "failed"
    assert payload["exposure_changes"][0]["change_type"] == "unknown"
    assert payload["exposure_changes"][0]["qualification"] == "current_service_coverage_incomplete"
    assert payload["exposure_changes"][0]["before"]["fields"][0]["evidence_references"][0]["source_id"] == "before"


def test_all_enumeration_statuses_and_nullable_values_serialize():
    surface = populated_surface()
    service = surface.hosts[0].services[0]
    services = tuple(
        AttackSurfaceService(
            service.id + status.value,
            service.host_id,
            service.port,
            service.protocol,
            service.state,
            service.service_name,
            service.product,
            service.version,
            None,
            (),
            (EnumerationReference(status.value, "module", status),),
            (),
        )
        for status in EnumerationStatus
    )
    host = AttackSurfaceHost(**{**surface.hosts[0].__dict__, "services": services})
    value = AttackSurface(**{**surface.__dict__, "hosts": (host,)})
    payload = attack_surface_to_dict(value)

    assert {item["enumeration_references"][0]["status"] for item in payload["hosts"][0]["services"]} == {item.value for item in EnumerationStatus}
    assert all(item["extra_info"] is None for item in payload["hosts"][0]["services"])


def test_identical_model_serializes_to_identical_bytes(tmp_path: Path):
    surface = populated_surface()
    first = serialize_report(surface)
    second = serialize_report(surface)
    output = tmp_path / "surface.json"
    write_report(surface, output)

    assert first == second
    assert output.read_text(encoding="utf-8") == first + "\n"
    assert json.loads(first)["schema_version"] == 1


def test_diff_from_m9_models_serializes_without_new_analysis():
    baseline = populated_surface("base")
    current = populated_surface("current")
    diff = AttackSurfaceDiffer().compare(baseline, current)

    payload = report_to_dict(diff)

    assert payload["baseline_scan_id"] == "base"
    assert payload["current_scan_id"] == "current"
    assert payload["generated_at"] == NOW.isoformat()
    assert set(payload) == {
        "schema_version",
        "report_type",
        "baseline_scan_id",
        "current_scan_id",
        "generated_at",
        "baseline_status",
        "current_status",
        "completeness",
        "host_changes",
        "service_changes",
        "os_changes",
        "technology_changes",
        "exposure_changes",
        "relationship_changes",
        "enumeration_changes",
        "evidence_changes",
    }


def test_serializer_does_not_use_collection_boundaries(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("structured reporting invoked a collection boundary")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    assert "attack_surface" in serialize_report(populated_surface())


def test_unsupported_model_is_rejected():
    with pytest.raises(TypeError, match="unsupported report model"):
        serialize_report(object())
