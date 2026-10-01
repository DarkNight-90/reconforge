"""Deterministic correlation of persisted ReconForge evidence."""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Protocol

from ..core.models import (
    AttackSurface,
    AttackSurfaceHost,
    AttackSurfaceService,
    CorrelationCompleteness,
    CorrelationCompletenessStatus,
    EnumerationReference,
    EnumerationResult,
    EnumerationStatus,
    EvidenceReference,
    Exposure,
    Host,
    ManifestExecution,
    Relationship,
    RelationshipType,
    Scan,
    ScanManifest,
    Service,
    Technology,
)


class CorrelationRepository(Protocol):
    def get_scan(self, scan_id: str) -> Scan: ...

    def get_hosts(self, scan_id: str) -> tuple[Host, ...]: ...

    def get_host_id(self, scan_id: str, ip: str) -> int: ...

    def get_enumeration_results(self, scan_id: str) -> tuple[EnumerationResult, ...]: ...


_GENERIC_SERVICE_NAMES = frozenset({
    "http",
    "https",
    "ssh",
    "microsoft ds",
    "microsoft-ds",
    "ssl",
    "tls",
})


class AttackSurfaceCorrelator:
    """Build an attack-surface model without executing collection logic."""

    def __init__(self, repository: CorrelationRepository) -> None:
        self.repository = repository

    def correlate(self, scan_id: str, manifest: ScanManifest | None = None) -> AttackSurface:
        scan = self.repository.get_scan(scan_id)
        hosts = tuple(sorted(self.repository.get_hosts(scan_id), key=lambda item: item.ip))
        enumeration_results = self.repository.get_enumeration_results(scan_id)
        results_by_service = self._group_enumeration(scan_id, enumeration_results)

        technologies: dict[str, Technology] = {}
        exposures: dict[str, Exposure] = {}
        relationships: dict[tuple[RelationshipType, str, str], Relationship] = {}
        surface_hosts: list[AttackSurfaceHost] = []

        for host in hosts:
            host_id = self._host_id(scan_id, host.ip)
            host_evidence = self._host_evidence(host, host_id)
            host_services: list[AttackSurfaceService] = []
            host_technology_ids: set[str] = set()
            host_exposure_ids: set[str] = set()

            if host.classification is not None:
                os_id = self._os_id(host_id, host.classification.family.value)
                self._add_relationship(
                    relationships,
                    Relationship(
                        RelationshipType.HOST_HAS_OS,
                        host_id,
                        os_id,
                        host_evidence,
                    ),
                )

            for service in sorted(host.services, key=self._service_sort_key):
                service_id = self._service_id(scan_id, host.ip, service)
                service_evidence = self._service_evidence(service, service_id)
                result_refs = tuple(
                    self._enumeration_reference(result)
                    for result in results_by_service.get((host.ip, service.port, self._normalize(service.protocol)), ())
                )
                service_technology_ids: set[str] = set()

                if self._meaningful(service.product):
                    technology_id = self._add_technology(
                        technologies,
                        host_id,
                        service.product or "",
                        service.version,
                        "service_product",
                        (self._reference("service", service_id, "product", service.product or ""),),
                    )
                    service_technology_ids.add(technology_id)
                    self._add_relationship(
                        relationships,
                        Relationship(
                            RelationshipType.SERVICE_INDICATES_TECHNOLOGY,
                            service_id,
                            technology_id,
                            (self._reference("service", service_id, "product", service.product or ""),),
                        ),
                    )

                for result in results_by_service.get((host.ip, service.port, self._normalize(service.protocol)), ()):
                    if result.status is not EnumerationStatus.SUCCESS:
                        continue
                    for evidence in result.evidence:
                        if not self._is_technology_evidence(evidence.category, evidence.indicator, evidence.value):
                            continue
                        name, version = self._technology_parts(evidence.value)
                        evidence_id = self._enumeration_evidence_id(result, evidence)
                        technology_id = self._add_technology(
                            technologies,
                            host_id,
                            name,
                            version,
                            "enumeration",
                            (self._reference("enumeration_evidence", evidence_id, evidence.indicator, evidence.value, evidence.details),),
                        )
                        service_technology_ids.add(technology_id)
                        self._add_relationship(
                            relationships,
                            Relationship(
                                RelationshipType.ENUMERATION_SUPPORTS_TECHNOLOGY,
                                self._result_id(result),
                                technology_id,
                                (self._reference("enumeration_evidence", evidence_id, evidence.indicator, evidence.value, evidence.details),),
                            ),
                        )

                service_exposure_ids: set[str] = set()
                if self._valid_service(service):
                    for kind in self._exposure_kinds(service, results_by_service.get((host.ip, service.port, self._normalize(service.protocol)), ())):
                        exposure_id = self._exposure_id(scan_id, host.ip, service, kind)
                        exposure_references = list(service_evidence)
                        if kind == "tls_certificate_observed":
                            exposure_references.extend(
                                self._successful_evidence_references(
                                    results_by_service.get((host.ip, service.port, self._normalize(service.protocol)), ()),
                                    category="certificate",
                                )
                            )
                        exposure = Exposure(
                            id=exposure_id,
                            host_id=host_id,
                            service_id=service_id,
                            kind=kind,
                            port=service.port,
                            protocol=service.protocol.strip(),
                            state=service.state.strip(),
                            service_name=service.service_name,
                            evidence_references=self._sorted_references(exposure_references),
                        )
                        exposures[exposure_id] = exposure
                        service_exposure_ids.add(exposure_id)
                        self._add_relationship(
                            relationships,
                            Relationship(
                                RelationshipType.SERVICE_EXPOSES_PORT,
                                service_id,
                                exposure_id,
                                exposure.evidence_references,
                            ),
                        )
                        for reference in exposure.evidence_references:
                            self._add_relationship(
                                relationships,
                                Relationship(
                                    RelationshipType.EVIDENCE_SUPPORTS_EXPOSURE,
                                    reference.source_id,
                                    exposure_id,
                                    (reference,),
                                ),
                            )

                host_technology_ids.update(service_technology_ids)
                host_exposure_ids.update(service_exposure_ids)
                host_services.append(
                    AttackSurfaceService(
                        id=service_id,
                        host_id=host_id,
                        port=service.port,
                        protocol=service.protocol,
                        state=service.state,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        extra_info=service.extra_info,
                        technology_ids=tuple(sorted(service_technology_ids)),
                        enumeration_references=result_refs,
                        evidence_references=self._sorted_references(service_evidence),
                    )
                )
                self._add_relationship(
                    relationships,
                    Relationship(RelationshipType.HOST_HAS_SERVICE, host_id, service_id, service_evidence),
                )

            surface_hosts.append(
                AttackSurfaceHost(
                    id=host_id,
                    scan_id=scan_id,
                    ip=host.ip,
                    hostname=host.hostname,
                    state=host.state,
                    mac_address=host.mac_address,
                    vendor=host.vendor,
                    classification=host.classification,
                    services=tuple(host_services),
                    technology_ids=tuple(sorted(host_technology_ids)),
                    exposure_ids=tuple(sorted(host_exposure_ids)),
                    evidence_references=self._sorted_references(host_evidence),
                )
            )

        completeness = self._completeness(scan, hosts, manifest)
        return AttackSurface(
            scan_id=scan.id,
            generated_at=scan.finished_at or scan.started_at,
            hosts=tuple(surface_hosts),
            technologies=tuple(sorted(technologies.values(), key=lambda item: (self._normalize(item.name), self._normalize(item.version), item.id))),
            exposures=tuple(sorted(exposures.values(), key=lambda item: (self._host_ip(item.host_id, surface_hosts), item.port, self._normalize(item.protocol), item.kind, item.id))),
            relationships=tuple(sorted(relationships.values(), key=lambda item: (item.type.value, item.source_id, item.target_id))),
            source_scan_status=scan.status,
            completeness=completeness,
        )

    @staticmethod
    def _normalize(value: str | None) -> str:
        return re.sub(r"\s+", " ", (value or "").strip()).casefold()

    @staticmethod
    def _display(value: str | None) -> str:
        return re.sub(r"\s+", " ", (value or "").strip())

    @classmethod
    def _meaningful(cls, value: str | None) -> bool:
        normalized = cls._normalize(value)
        return bool(normalized) and normalized not in _GENERIC_SERVICE_NAMES and normalized not in {"unknown", "n/a", "none"}

    @staticmethod
    def _host_id(scan_id: str, ip: str) -> str:
        return f"host:{scan_id}:{ip}"

    @classmethod
    def _service_id(cls, scan_id: str, ip: str, service: Service) -> str:
        return f"service:{scan_id}:{ip}:{cls._normalize(service.protocol)}:{service.port}"

    @classmethod
    def _exposure_id(cls, scan_id: str, ip: str, service: Service, kind: str) -> str:
        return f"exposure:{scan_id}:{ip}:{cls._normalize(service.protocol)}:{service.port}:{kind}"

    @classmethod
    def _os_id(cls, host_id: str, family: str) -> str:
        return f"os:{host_id}:{cls._normalize(family)}"

    @classmethod
    def _technology_id(cls, scope: str, name: str, version: str | None) -> str:
        normalized_version = cls._normalize(version) or "none"
        return f"technology:{scope}:{cls._normalize(name)}:{normalized_version}"

    @classmethod
    def _reference(cls, source_type: str, source_id: str, field: str, value: str, details: str | None = None) -> EvidenceReference:
        return EvidenceReference(source_type, source_id, field, cls._display(value), details)

    @classmethod
    def _service_evidence(cls, service: Service, service_id: str) -> tuple[EvidenceReference, ...]:
        references: list[EvidenceReference] = []
        for field, value in (("service_name", service.service_name), ("product", service.product), ("version", service.version), ("extra_info", service.extra_info), ("state", service.state)):
            if value is not None and cls._display(value):
                references.append(cls._reference("service", service_id, field, value))
        return cls._sorted_references(references)

    @classmethod
    def _host_evidence(cls, host: Host, host_id: str) -> tuple[EvidenceReference, ...]:
        references: list[EvidenceReference] = []
        if host.classification is not None:
            references.extend((
                cls._reference("os_classification", f"{host_id}:classification", "family", host.classification.family.value),
                cls._reference("os_classification", f"{host_id}:classification", "confidence", host.classification.confidence.value),
            ))
            for index, evidence in enumerate(host.classification.evidence):
                references.append(cls._reference("os_classification", f"{host_id}:classification:{index}", "evidence", evidence.value, evidence.details))
        for index, fingerprint in enumerate(host.os_fingerprints):
            source_id = f"osfp:{host_id}:{index}"
            for field, value in (("vendor", fingerprint.vendor), ("family", fingerprint.family), ("generation", fingerprint.generation), ("source", fingerprint.source)):
                if value:
                    references.append(cls._reference("os_fingerprint", source_id, field, value))
            for evidence in fingerprint.evidence:
                references.append(cls._reference("os_fingerprint", source_id, "evidence", evidence))
        return cls._sorted_references(references)

    @classmethod
    def _valid_service(cls, service: Service) -> bool:
        return 1 <= service.port <= 65535 and bool(cls._display(service.protocol)) and bool(cls._display(service.state))

    @classmethod
    def _exposure_kinds(cls, service: Service, results: Iterable[EnumerationResult]) -> tuple[str, ...]:
        kinds = ["service_observed"]
        name = cls._normalize(service.service_name)
        if name == "http":
            kinds.append("http_service_observed")
        elif name == "https":
            kinds.append("https_service_observed")
        elif name == "ssh":
            kinds.append("ssh_service_observed")
        if any(result.status is EnumerationStatus.SUCCESS and any(item.category == "certificate" for item in result.evidence) for result in results):
            kinds.append("tls_certificate_observed")
        return tuple(kinds)

    @classmethod
    def _add_technology(cls, technologies: dict[str, Technology], scope: str, name: str, version: str | None, kind: str, references: Iterable[EvidenceReference]) -> str:
        display_name = cls._display(name)
        if not cls._meaningful(display_name):
            return ""
        technology_id = cls._technology_id(scope, display_name, version)
        existing = technologies.get(technology_id)
        merged = cls._sorted_references((existing.evidence_references if existing else ()) + tuple(references))
        technologies[technology_id] = Technology(technology_id, display_name, cls._display(version) or None, kind, merged)
        return technology_id

    @classmethod
    def _technology_parts(cls, value: str) -> tuple[str, str | None]:
        display = cls._display(value)
        match = re.match(r"^(.+?)[/_-]v?(\d+(?:\.\d+)+)$", display)
        if match:
            return match.group(1).strip(), match.group(2)
        return display, None

    @classmethod
    def _is_technology_evidence(cls, category: str, indicator: str, value: str) -> bool:
        return cls._normalize(value) not in {"", "unknown", "n/a", "none"} and cls._normalize(indicator) in {"server", "implementation"} and cls._normalize(category) in {"technology", "service"}

    @classmethod
    def _result_id(cls, result: EnumerationResult) -> str:
        return f"enumeration:{result.scan_id}:{result.host_id}:{result.port}:{cls._normalize(result.protocol)}:{result.module}"

    @classmethod
    def _enumeration_evidence_id(cls, result: EnumerationResult, evidence: object) -> str:
        return f"{cls._result_id(result)}:{getattr(evidence, 'source')}:{getattr(evidence, 'category')}:{getattr(evidence, 'indicator')}:{cls._normalize(getattr(evidence, 'value'))}"

    @classmethod
    def _enumeration_reference(cls, result: EnumerationResult) -> EnumerationReference:
        evidence_ids = tuple(sorted(cls._enumeration_evidence_id(result, evidence) for evidence in result.evidence))
        return EnumerationReference(cls._result_id(result), result.module, result.status, evidence_ids)

    @classmethod
    def _successful_evidence_references(cls, results: Iterable[EnumerationResult], category: str) -> tuple[EvidenceReference, ...]:
        references: list[EvidenceReference] = []
        for result in results:
            if result.status is not EnumerationStatus.SUCCESS:
                continue
            for evidence in result.evidence:
                if cls._normalize(evidence.category) == cls._normalize(category):
                    references.append(cls._reference("enumeration_evidence", cls._enumeration_evidence_id(result, evidence), evidence.indicator, evidence.value, evidence.details))
        return cls._sorted_references(references)

    @classmethod
    def _group_enumeration(cls, scan_id: str, results: Iterable[EnumerationResult]) -> dict[tuple[str, int, str], tuple[EnumerationResult, ...]]:
        grouped: dict[tuple[str, int, str], list[EnumerationResult]] = {}
        for result in results:
            if result.scan_id != scan_id:
                continue
            key = (result.ip, result.port, cls._normalize(result.protocol))
            grouped.setdefault(key, []).append(result)
        return {key: tuple(sorted(value, key=lambda item: (item.module, item.id or 0))) for key, value in grouped.items()}

    @classmethod
    def _sorted_references(cls, references: Iterable[EvidenceReference]) -> tuple[EvidenceReference, ...]:
        unique = {(item.source_type, item.source_id, item.field, item.value, item.details): item for item in references}
        return tuple(sorted(unique.values(), key=lambda item: (item.source_type, item.source_id, item.field, cls._normalize(item.value), item.details or "")))

    @staticmethod
    def _add_relationship(relationships: dict[tuple[RelationshipType, str, str], Relationship], relationship: Relationship) -> None:
        key = (relationship.type, relationship.source_id, relationship.target_id)
        existing = relationships.get(key)
        if existing is None:
            relationships[key] = relationship
            return
        references = AttackSurfaceCorrelator._sorted_references(existing.evidence_references + relationship.evidence_references)
        relationships[key] = Relationship(existing.type, existing.source_id, existing.target_id, references)

    @classmethod
    def _service_sort_key(cls, service: Service) -> tuple[int, str]:
        return service.port, cls._normalize(service.protocol)

    @classmethod
    def _host_ip(cls, host_id: str, hosts: Iterable[AttackSurfaceHost]) -> str:
        for host in hosts:
            if host.id == host_id:
                return host.ip
        return host_id

    @classmethod
    def _completeness(cls, scan: Scan, hosts: tuple[Host, ...], manifest: ScanManifest | None) -> CorrelationCompleteness:
        if manifest is None:
            if scan.status.value == "completed":
                return CorrelationCompleteness(CorrelationCompletenessStatus.COMPLETE)
            return CorrelationCompleteness(CorrelationCompletenessStatus.PARTIAL, (f"scan_status:{scan.status.value}",))

        statuses = {item.phase: item.status for item in manifest.executions}
        issues: list[str] = []
        if statuses.get("discovery") is not None and statuses.get("discovery").value != "completed":
            issues.append(f"discovery:{statuses['discovery'].value}")
        if statuses.get("ports") is not None and statuses.get("ports").value != "completed":
            issues.append(f"ports:{statuses['ports'].value}")
        if statuses.get("services") is not None and statuses.get("services").value != "completed":
            issues.append(f"services:{statuses['services'].value}")
        if statuses.get("os") is not None and statuses.get("os").value != "completed":
            issues.append(f"os:{statuses['os'].value}")
        if statuses.get("enumeration") is not None and statuses.get("enumeration").value != "completed":
            issues.append(f"enumeration:{statuses['enumeration'].value}")

        if not hosts and any(item.startswith("discovery:") for item in issues):
            status = CorrelationCompletenessStatus.DISCOVERY_UNAVAILABLE
        elif any(item.startswith(prefix) for item in issues for prefix in ("ports:", "services:")):
            status = CorrelationCompletenessStatus.SERVICE_DATA_INCOMPLETE
        elif any(item.startswith("os:") for item in issues):
            status = CorrelationCompletenessStatus.OS_DATA_INCOMPLETE
        elif any(item.startswith("enumeration:") for item in issues):
            status = CorrelationCompletenessStatus.ENUMERATION_INCOMPLETE
        elif issues:
            status = CorrelationCompletenessStatus.PARTIAL
        else:
            status = CorrelationCompletenessStatus.COMPLETE
        return CorrelationCompleteness(status, tuple(sorted(issues)))
