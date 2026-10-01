"""Canonical JSON serialization for M9 and M10 domain models."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from ..core.models import (
    AttackSurface,
    AttackSurfaceDiff,
    AttackSurfaceHost,
    AttackSurfaceService,
    CoverageReference,
    DiffCompleteness,
    DiffField,
    DiffSnapshot,
    EnumerationReference,
    EvidenceReference,
    EvidenceCoverageReport,
    Exposure,
    HostCoverage,
    OSClassification,
    Relationship,
    PhaseCoverage,
    ServiceCoverage,
    SurfaceChange,
    Technology,
)

SCHEMA_VERSION = 1


def _datetime(value: datetime) -> str:
    return value.isoformat()


def _enum(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def evidence_reference_to_dict(reference: EvidenceReference) -> dict[str, Any]:
    return {
        "source_type": reference.source_type,
        "source_id": reference.source_id,
        "field": reference.field,
        "value": reference.value,
        "details": reference.details,
    }


def coverage_reference_to_dict(reference: CoverageReference) -> dict[str, Any]:
    return {
        "source_type": reference.source_type,
        "source_id": reference.source_id,
        "field": reference.field,
        "value": reference.value,
        "details": reference.details,
    }


def enumeration_reference_to_dict(reference: EnumerationReference) -> dict[str, Any]:
    return {
        "result_id": reference.result_id,
        "module": reference.module,
        "status": _enum(reference.status),
        "evidence_ids": list(reference.evidence_ids),
    }


def os_classification_to_dict(classification: OSClassification | None) -> dict[str, Any] | None:
    if classification is None:
        return None
    return {
        "family": _enum(classification.family),
        "confidence": _enum(classification.confidence),
        "evidence": [
            {
                "source": item.source,
                "indicator": item.indicator,
                "value": item.value,
                "weight": item.weight,
                "direction": _enum(item.direction),
                "details": item.details,
            }
            for item in classification.evidence
        ],
        "windows_score": classification.windows_score,
        "unix_score": classification.unix_score,
    }


def attack_surface_service_to_dict(service: AttackSurfaceService) -> dict[str, Any]:
    return {
        "id": service.id,
        "host_id": service.host_id,
        "port": service.port,
        "protocol": service.protocol,
        "state": service.state,
        "service_name": service.service_name,
        "product": service.product,
        "version": service.version,
        "extra_info": service.extra_info,
        "technology_ids": list(service.technology_ids),
        "enumeration_references": [enumeration_reference_to_dict(item) for item in service.enumeration_references],
        "evidence_references": [evidence_reference_to_dict(item) for item in service.evidence_references],
    }


def attack_surface_host_to_dict(host: AttackSurfaceHost) -> dict[str, Any]:
    return {
        "id": host.id,
        "scan_id": host.scan_id,
        "ip": host.ip,
        "hostname": host.hostname,
        "state": host.state,
        "mac_address": host.mac_address,
        "vendor": host.vendor,
        "classification": os_classification_to_dict(host.classification),
        "services": [attack_surface_service_to_dict(item) for item in host.services],
        "technology_ids": list(host.technology_ids),
        "exposure_ids": list(host.exposure_ids),
        "evidence_references": [evidence_reference_to_dict(item) for item in host.evidence_references],
    }


def technology_to_dict(technology: Technology) -> dict[str, Any]:
    return {
        "id": technology.id,
        "name": technology.name,
        "version": technology.version,
        "kind": technology.kind,
        "evidence_references": [evidence_reference_to_dict(item) for item in technology.evidence_references],
    }


def exposure_to_dict(exposure: Exposure) -> dict[str, Any]:
    return {
        "id": exposure.id,
        "host_id": exposure.host_id,
        "service_id": exposure.service_id,
        "kind": exposure.kind,
        "port": exposure.port,
        "protocol": exposure.protocol,
        "state": exposure.state,
        "service_name": exposure.service_name,
        "evidence_references": [evidence_reference_to_dict(item) for item in exposure.evidence_references],
    }


def relationship_to_dict(relationship: Relationship) -> dict[str, Any]:
    return {
        "type": _enum(relationship.type),
        "source_id": relationship.source_id,
        "target_id": relationship.target_id,
        "evidence_references": [evidence_reference_to_dict(item) for item in relationship.evidence_references],
    }


def completeness_to_dict(completeness: Any) -> dict[str, Any]:
    result = {
        "status": _enum(completeness.status),
        "issues": list(completeness.issues),
    }
    if isinstance(completeness, DiffCompleteness):
        result.update(
            {
                "baseline_scan_status": _enum(completeness.baseline_scan_status),
                "current_scan_status": _enum(completeness.current_scan_status),
            }
        )
    return result


def attack_surface_to_dict(surface: AttackSurface) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "attack_surface",
        "scan_id": surface.scan_id,
        "generated_at": _datetime(surface.generated_at),
        "source_scan_status": _enum(surface.source_scan_status),
        "completeness": completeness_to_dict(surface.completeness),
        "hosts": [attack_surface_host_to_dict(item) for item in surface.hosts],
        "technologies": [technology_to_dict(item) for item in surface.technologies],
        "exposures": [exposure_to_dict(item) for item in surface.exposures],
        "relationships": [relationship_to_dict(item) for item in surface.relationships],
    }


def diff_field_to_dict(field: DiffField) -> dict[str, Any]:
    return {
        "name": field.name,
        "value": field.value,
        "evidence_references": [evidence_reference_to_dict(item) for item in field.evidence_references],
    }


def diff_snapshot_to_dict(snapshot: DiffSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {"fields": [diff_field_to_dict(item) for item in snapshot.fields]}


def surface_change_to_dict(change: SurfaceChange) -> dict[str, Any]:
    return {
        "id": change.id,
        "entity_type": _enum(change.entity_type),
        "change_type": _enum(change.change_type),
        "comparison_key": change.comparison_key,
        "before": diff_snapshot_to_dict(change.before),
        "after": diff_snapshot_to_dict(change.after),
        "evidence_references": [evidence_reference_to_dict(item) for item in change.evidence_references],
        "qualification": change.qualification,
    }


def attack_surface_diff_to_dict(diff: AttackSurfaceDiff) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "attack_surface_diff",
        "baseline_scan_id": diff.baseline_scan_id,
        "current_scan_id": diff.current_scan_id,
        "generated_at": _datetime(diff.generated_at),
        "baseline_status": _enum(diff.baseline_status),
        "current_status": _enum(diff.current_status),
        "completeness": completeness_to_dict(diff.completeness),
        "host_changes": [surface_change_to_dict(item) for item in diff.host_changes],
        "service_changes": [surface_change_to_dict(item) for item in diff.service_changes],
        "os_changes": [surface_change_to_dict(item) for item in diff.os_changes],
        "technology_changes": [surface_change_to_dict(item) for item in diff.technology_changes],
        "exposure_changes": [surface_change_to_dict(item) for item in diff.exposure_changes],
        "relationship_changes": [surface_change_to_dict(item) for item in diff.relationship_changes],
        "enumeration_changes": [surface_change_to_dict(item) for item in diff.enumeration_changes],
        "evidence_changes": [surface_change_to_dict(item) for item in diff.evidence_changes],
    }


def phase_coverage_to_dict(coverage: PhaseCoverage) -> dict[str, Any]:
    return {
        "phase": coverage.phase,
        "status": _enum(coverage.status),
        "artifact": coverage.artifact,
        "started_at": _datetime(coverage.started_at) if coverage.started_at else None,
        "finished_at": _datetime(coverage.finished_at) if coverage.finished_at else None,
        "qualification": coverage.qualification,
        "references": [coverage_reference_to_dict(item) for item in coverage.references],
    }


def host_coverage_to_dict(coverage: HostCoverage) -> dict[str, Any]:
    return {
        "id": coverage.id,
        "ip": coverage.ip,
        "observed_state": coverage.observed_state,
        "os_status": _enum(coverage.os_status),
        "service_count": coverage.service_count,
        "service_status": _enum(coverage.service_status),
        "references": [coverage_reference_to_dict(item) for item in coverage.references],
        "limitations": list(coverage.limitations),
    }


def service_coverage_to_dict(coverage: ServiceCoverage) -> dict[str, Any]:
    return {
        "id": coverage.id,
        "host_ip": coverage.host_ip,
        "port": coverage.port,
        "protocol": coverage.protocol,
        "observation_status": _enum(coverage.observation_status),
        "metadata_status": _enum(coverage.metadata_status),
        "enumeration_statuses": [_enum(item) for item in coverage.enumeration_statuses],
        "references": [coverage_reference_to_dict(item) for item in coverage.references],
        "limitations": list(coverage.limitations),
    }


def evidence_coverage_report_to_dict(report: EvidenceCoverageReport) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "evidence_coverage",
        "scan_id": report.scan_id,
        "generated_at": _datetime(report.generated_at),
        "source_scan_status": _enum(report.source_scan_status),
        "overall_status": _enum(report.overall_status),
        "phase_coverage": [phase_coverage_to_dict(item) for item in report.phase_coverage],
        "host_coverage": [host_coverage_to_dict(item) for item in report.host_coverage],
        "service_coverage": [service_coverage_to_dict(item) for item in report.service_coverage],
        "limitations": list(report.limitations),
        "references": [coverage_reference_to_dict(item) for item in report.references],
    }


def report_to_dict(report: AttackSurface | AttackSurfaceDiff | EvidenceCoverageReport) -> dict[str, Any]:
    if isinstance(report, AttackSurface):
        return attack_surface_to_dict(report)
    if isinstance(report, AttackSurfaceDiff):
        return attack_surface_diff_to_dict(report)
    if isinstance(report, EvidenceCoverageReport):
        return evidence_coverage_report_to_dict(report)
    raise TypeError(f"unsupported report model: {type(report).__name__}")


def serialize_report(report: AttackSurface | AttackSurfaceDiff | EvidenceCoverageReport, *, pretty: bool = False) -> str:
    payload = report_to_dict(report)
    if pretty:
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def write_report(report: AttackSurface | AttackSurfaceDiff | EvidenceCoverageReport, output_path: str | Path, *, pretty: bool = False) -> None:
    """Atomically write a structured report without touching ReconForge state."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = handle.name
            content = serialize_report(report, pretty=pretty)
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
