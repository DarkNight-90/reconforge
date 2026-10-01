"""Pure evidence coverage analysis over M9 models and manifests."""

from __future__ import annotations

from collections.abc import Iterable
import re

from ..core.models import (
    AttackSurface,
    AttackSurfaceHost,
    AttackSurfaceService,
    CoverageReference,
    CoverageStatus,
    EnumerationReference,
    EnumerationStatus,
    EvidenceCoverageReport,
    EvidenceReference,
    HostCoverage,
    ManifestExecution,
    PhaseCoverage,
    ScanManifest,
    ServiceCoverage,
    ExecutionStatus,
)


class EvidenceCoverageAnalyzer:
    """Analyze collection and evidence coverage without performing collection."""

    _PHASE_ORDER = ("discovery", "ports", "services", "os")

    def analyze(self, surface: AttackSurface, manifest: ScanManifest) -> EvidenceCoverageReport:
        if manifest.scan_id != surface.scan_id:
            raise ValueError("manifest scan_id does not match attack surface scan_id")

        phase_coverage = self._phase_coverage(surface.scan_id, manifest)
        phase_statuses = {item.phase: item.status for item in phase_coverage}
        service_coverage: list[ServiceCoverage] = []
        host_coverage: list[HostCoverage] = []
        all_references: list[CoverageReference] = []
        limitations: set[str] = set()

        for host in surface.hosts:
            host_services = tuple(service for service in host.services if service.host_id == host.id)
            host_phase_status = phase_statuses.get("services", CoverageStatus.UNAVAILABLE)
            host_service_status = self._host_service_status(host_services, host_phase_status)
            os_status, os_limitations = self._os_status(host, phase_statuses)
            host_references = self._references_from_evidence(host.evidence_references)
            host_limitations = set(os_limitations)
            if host_service_status is not CoverageStatus.COMPLETE:
                host_limitations.add(f"service_coverage:{host_service_status.value}")
            host_item = HostCoverage(
                id=host.id,
                ip=host.ip,
                observed_state=host.state,
                os_status=os_status,
                service_count=len(host_services),
                service_status=host_service_status,
                references=self._sorted_references(host_references),
                limitations=tuple(sorted(host_limitations)),
            )
            host_coverage.append(host_item)
            all_references.extend(host_item.references)
            limitations.update(host_item.limitations)

            for service in sorted(host_services, key=self._service_sort_key):
                item = self._service_coverage(surface.scan_id, host.ip, service, phase_statuses)
                service_coverage.append(item)
                all_references.extend(item.references)
                limitations.update(item.limitations)

        for phase in phase_coverage:
            all_references.extend(phase.references)
            if phase.status is not CoverageStatus.COMPLETE:
                limitations.add(f"phase:{phase.phase}:{phase.status.value}")

        for technology in surface.technologies:
            if not technology.evidence_references:
                limitations.add(f"technology_provenance_missing:{technology.id}")
            all_references.extend(self._references_from_evidence(technology.evidence_references))

        limitations.update(self._conflict_limitations(surface))

        all_references = list(self._sorted_references(all_references))
        overall_status = self._overall_status(surface, phase_coverage, service_coverage, limitations)
        return EvidenceCoverageReport(
            scan_id=surface.scan_id,
            generated_at=surface.generated_at,
            source_scan_status=surface.source_scan_status,
            overall_status=overall_status,
            phase_coverage=tuple(phase_coverage),
            host_coverage=tuple(sorted(host_coverage, key=lambda item: item.ip)),
            service_coverage=tuple(sorted(service_coverage, key=lambda item: (item.host_ip, item.port, self._normalize(item.protocol)))),
            limitations=tuple(sorted(limitations)),
            references=tuple(all_references),
        )

    def _phase_coverage(self, scan_id: str, manifest: ScanManifest) -> tuple[PhaseCoverage, ...]:
        entries = sorted(
            manifest.executions,
            key=lambda item: (self._phase_index(item.phase), item.phase),
        )
        return tuple(self._phase_item(scan_id, item) for item in entries)

    @classmethod
    def _phase_item(cls, scan_id: str, execution: ManifestExecution) -> PhaseCoverage:
        status = {
            ExecutionStatus.COMPLETED: CoverageStatus.COMPLETE,
            ExecutionStatus.FAILED: CoverageStatus.FAILED,
            ExecutionStatus.TIMEOUT: CoverageStatus.TIMEOUT,
            ExecutionStatus.INTERRUPTED: CoverageStatus.INTERRUPTED,
            ExecutionStatus.SKIPPED: CoverageStatus.NOT_ATTEMPTED,
            ExecutionStatus.PENDING: CoverageStatus.NOT_ATTEMPTED,
            ExecutionStatus.RUNNING: CoverageStatus.PARTIAL,
            ExecutionStatus.NOT_APPLICABLE: CoverageStatus.NOT_APPLICABLE,
        }[execution.status]
        qualification = None
        if status is CoverageStatus.NOT_ATTEMPTED and execution.status is ExecutionStatus.PENDING:
            qualification = "phase_not_started"
        elif status is CoverageStatus.PARTIAL:
            qualification = "phase_still_running"
        references = (
            CoverageReference("manifest_execution", f"phase:{scan_id}:{execution.phase}", "status", execution.status.value, execution.stderr_summary),
        )
        return PhaseCoverage(
            phase=execution.phase,
            status=status,
            artifact=execution.artifact,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            qualification=qualification,
            references=references,
        )

    @classmethod
    def _host_service_status(cls, services: tuple[AttackSurfaceService, ...], phase_status: CoverageStatus) -> CoverageStatus:
        if phase_status is not CoverageStatus.COMPLETE:
            return phase_status
        return CoverageStatus.COMPLETE if services or phase_status is CoverageStatus.COMPLETE else CoverageStatus.NOT_ATTEMPTED

    @classmethod
    def _os_status(cls, host: AttackSurfaceHost, phases: dict[str, CoverageStatus]) -> tuple[CoverageStatus, tuple[str, ...]]:
        if host.classification is not None:
            if host.classification.family.value == "Unknown":
                return CoverageStatus.COMPLETE, ("os_classification_unknown",)
            return CoverageStatus.COMPLETE, ()
        phase_status = phases.get("os", CoverageStatus.UNAVAILABLE)
        if phase_status is CoverageStatus.COMPLETE:
            return CoverageStatus.PARTIAL, ("os_classification_missing",)
        return phase_status, (f"os_collection:{phase_status.value}",)

    @classmethod
    def _service_coverage(
        cls,
        scan_id: str,
        host_ip: str,
        service: AttackSurfaceService,
        phases: dict[str, CoverageStatus],
    ) -> ServiceCoverage:
        service_key = cls._service_key(host_ip, service)
        references = list(cls._references_from_evidence(service.evidence_references))
        limitations: set[str] = set()
        observation_status = phases.get("services", CoverageStatus.UNAVAILABLE)
        if observation_status is CoverageStatus.COMPLETE:
            observation_status = CoverageStatus.COMPLETE
        metadata_fields = {
            "service_name": service.service_name,
        }
        missing_metadata = tuple(name for name, value in metadata_fields.items() if not value)
        metadata_status = CoverageStatus.COMPLETE if service.service_name else CoverageStatus.PARTIAL
        if missing_metadata:
            limitations.add("missing_metadata:" + ",".join(missing_metadata))

        enumeration_statuses: list[CoverageStatus] = []
        if service.enumeration_references:
            for reference in sorted(service.enumeration_references, key=lambda item: (item.module, item.status.value, item.result_id)):
                status = cls._enumeration_status(reference.status)
                enumeration_statuses.append(status)
                references.append(
                    CoverageReference("enumeration_result", reference.result_id, "status", reference.status.value),
                )
                references.extend(
                    CoverageReference("enumeration_evidence", evidence_id, "evidence_id", evidence_id)
                    for evidence_id in sorted(reference.evidence_ids)
                )
                if status is not CoverageStatus.COMPLETE:
                    limitations.add(f"enumeration:{reference.module}:{status.value}")
        else:
            enumeration_statuses.append(CoverageStatus.NOT_ATTEMPTED)
            if phases.get("enumeration") in {CoverageStatus.FAILED, CoverageStatus.TIMEOUT, CoverageStatus.INTERRUPTED}:
                enumeration_statuses[0] = phases["enumeration"]
                limitations.add(f"enumeration:{enumeration_statuses[0].value}")
            else:
                limitations.add("enumeration:not_attempted")

        if observation_status is not CoverageStatus.COMPLETE:
            limitations.add(f"service_observation:{observation_status.value}")
        return ServiceCoverage(
            id=service_key,
            host_ip=host_ip,
            port=service.port,
            protocol=service.protocol,
            observation_status=observation_status,
            metadata_status=metadata_status,
            enumeration_statuses=tuple(enumeration_statuses),
            references=cls._sorted_references(references),
            limitations=tuple(sorted(limitations)),
        )

    @staticmethod
    def _enumeration_status(status: EnumerationStatus) -> CoverageStatus:
        return {
            EnumerationStatus.SUCCESS: CoverageStatus.COMPLETE,
            EnumerationStatus.FAILED: CoverageStatus.FAILED,
            EnumerationStatus.TIMEOUT: CoverageStatus.TIMEOUT,
            EnumerationStatus.INTERRUPTED: CoverageStatus.INTERRUPTED,
            EnumerationStatus.UNSUPPORTED: CoverageStatus.UNSUPPORTED,
        }[status]

    @classmethod
    def _overall_status(
        cls,
        surface: AttackSurface,
        phases: tuple[PhaseCoverage, ...],
        services: list[ServiceCoverage],
        limitations: set[str],
    ) -> CoverageStatus:
        discovery = next((item.status for item in phases if item.phase == "discovery"), CoverageStatus.UNAVAILABLE)
        if discovery is not CoverageStatus.COMPLETE and not surface.hosts:
            return CoverageStatus.UNAVAILABLE
        if any(item.status in {CoverageStatus.FAILED, CoverageStatus.TIMEOUT, CoverageStatus.INTERRUPTED, CoverageStatus.PARTIAL, CoverageStatus.NOT_ATTEMPTED, CoverageStatus.UNAVAILABLE} for item in phases):
            return CoverageStatus.PARTIAL
        if any(status is not CoverageStatus.COMPLETE for service in services for status in service.enumeration_statuses):
            return CoverageStatus.PARTIAL
        if limitations:
            return CoverageStatus.PARTIAL
        return CoverageStatus.COMPLETE

    @classmethod
    def _conflict_limitations(cls, surface: AttackSurface) -> set[str]:
        technologies = {item.id: item for item in surface.technologies}
        limitations: set[str] = set()
        for host in surface.hosts:
            for service in host.services:
                observed = {
                    cls._normalize(technology.name)
                    for technology_id in service.technology_ids
                    if (technology := technologies.get(technology_id)) is not None
                }
                if len(observed) > 1:
                    limitations.add(f"conflicting_technology_observations:{service.id}")
        return limitations

    @staticmethod
    def _references_from_evidence(references: Iterable[EvidenceReference]) -> tuple[CoverageReference, ...]:
        return tuple(
            CoverageReference(item.source_type, item.source_id, item.field, item.value, item.details)
            for item in references
        )

    @classmethod
    def _sorted_references(cls, references: Iterable[CoverageReference]) -> tuple[CoverageReference, ...]:
        unique = {
            (item.source_type, item.source_id, item.field, item.value, item.details): item
            for item in references
        }
        return tuple(
            sorted(
                unique.values(),
                key=lambda item: (item.source_type, item.source_id, item.field, cls._normalize(item.value), item.details or ""),
            )
        )

    @staticmethod
    def _phase_index(phase: str) -> int:
        try:
            return EvidenceCoverageAnalyzer._PHASE_ORDER.index(phase)
        except ValueError:
            return len(EvidenceCoverageAnalyzer._PHASE_ORDER)

    @classmethod
    def _service_key(cls, host_ip: str, service: AttackSurfaceService) -> str:
        return f"{host_ip}:{cls._normalize(service.protocol)}:{service.port}"

    @staticmethod
    def _service_sort_key(service: AttackSurfaceService) -> tuple[int, str]:
        return service.port, EvidenceCoverageAnalyzer._normalize(service.protocol)

    @staticmethod
    def _normalize(value: str | None) -> str:
        return re.sub(r"\s+", " ", (value or "").strip()).casefold()
