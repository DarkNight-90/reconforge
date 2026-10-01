"""Pure, deterministic comparison of two M9 attack-surface models."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re

from ..core.models import (
    AttackSurface,
    AttackSurfaceDiff,
    AttackSurfaceHost,
    AttackSurfaceService,
    CorrelationCompletenessStatus,
    DiffChangeType,
    DiffCompleteness,
    DiffCompletenessStatus,
    DiffEntityType,
    DiffField,
    DiffSnapshot,
    EnumerationReference,
    EvidenceReference,
    Exposure,
    Relationship,
    SurfaceChange,
    Technology,
)


class AttackSurfaceDiffer:
    """Compare two M9 models without I/O or collection side effects."""

    def compare(self, baseline: AttackSurface, current: AttackSurface) -> AttackSurfaceDiff:
        if baseline.scan_id == current.scan_id:
            raise ValueError("baseline and current scan IDs must differ")

        baseline_hosts = {host.ip.strip(): host for host in baseline.hosts if host.ip.strip()}
        current_hosts = {host.ip.strip(): host for host in current.hosts if host.ip.strip()}
        baseline_service_map = self._services_by_key(baseline)
        current_service_map = self._services_by_key(current)
        baseline_technology_map = self._technologies_by_key(baseline)
        current_technology_map = self._technologies_by_key(current)
        baseline_exposure_map = self._exposures_by_key(baseline)
        current_exposure_map = self._exposures_by_key(current)
        baseline_relationship_map = self._relationships_by_key(baseline)
        current_relationship_map = self._relationships_by_key(current)
        baseline_enumeration_map = self._enumerations_by_key(baseline)
        current_enumeration_map = self._enumerations_by_key(current)

        current_issues = self._coverage_issues(current)
        host_changes = self._compare_hosts(baseline_hosts, current_hosts, current_issues, baseline.scan_id, current.scan_id)
        service_changes = self._compare_services(baseline_service_map, current_service_map, current_issues, baseline.scan_id, current.scan_id)
        os_changes = self._compare_os(baseline_hosts, current_hosts, current_issues, baseline.scan_id, current.scan_id)
        technology_changes = self._compare_technologies(baseline_technology_map, current_technology_map, current_issues, baseline.scan_id, current.scan_id)
        exposure_changes = self._compare_exposures(baseline_exposure_map, current_exposure_map, current_issues, baseline.scan_id, current.scan_id)
        relationship_changes = self._compare_relationships(baseline_relationship_map, current_relationship_map, baseline.scan_id, current.scan_id)
        enumeration_changes = self._compare_enumerations(baseline_enumeration_map, current_enumeration_map, baseline.scan_id, current.scan_id)
        evidence_changes = self._compare_evidence(baseline, current, current_issues, baseline.scan_id, current.scan_id)

        return AttackSurfaceDiff(
            baseline_scan_id=baseline.scan_id,
            current_scan_id=current.scan_id,
            generated_at=current.generated_at,
            baseline_status=baseline.source_scan_status,
            current_status=current.source_scan_status,
            completeness=self._diff_completeness(baseline, current, current_issues),
            host_changes=host_changes,
            service_changes=service_changes,
            os_changes=os_changes,
            technology_changes=technology_changes,
            exposure_changes=exposure_changes,
            relationship_changes=relationship_changes,
            enumeration_changes=enumeration_changes,
            evidence_changes=evidence_changes,
        )

    @classmethod
    def _compare_hosts(cls, baseline: Mapping[str, AttackSurfaceHost], current: Mapping[str, AttackSurfaceHost], issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) | set(current)):
            before = baseline.get(key)
            after = current.get(key)
            if before is None:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.HOST, DiffChangeType.ADDED, key, None, cls._host_snapshot(after)))
            elif after is None:
                change_type = DiffChangeType.REMOVED if cls._removal_allowed(DiffEntityType.HOST, issues) else DiffChangeType.UNKNOWN
                qualification = None if change_type is DiffChangeType.REMOVED else "current_discovery_coverage_incomplete"
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.HOST, change_type, key, cls._host_snapshot(before), None, qualification))
            else:
                fields = cls._changed_fields(
                    cls._host_fields(before),
                    cls._host_fields(after),
                )
                if fields[0]:
                    changes.append(cls._change(baseline_id, current_id, DiffEntityType.HOST, DiffChangeType.CHANGED, key, cls._snapshot(fields[0]), cls._snapshot(fields[1])))
        return tuple(changes)

    @classmethod
    def _compare_services(cls, baseline: Mapping[str, AttackSurfaceService], current: Mapping[str, AttackSurfaceService], issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) | set(current)):
            before = baseline.get(key)
            after = current.get(key)
            if before is None:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.SERVICE, DiffChangeType.ADDED, key, None, cls._service_snapshot(after)))
            elif after is None:
                change_type = DiffChangeType.REMOVED if cls._removal_allowed(DiffEntityType.SERVICE, issues) else DiffChangeType.UNKNOWN
                qualification = None if change_type is DiffChangeType.REMOVED else "current_service_coverage_incomplete"
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.SERVICE, change_type, key, cls._service_snapshot(before), None, qualification))
            else:
                before_fields, after_fields = cls._changed_fields(cls._service_fields(before), cls._service_fields(after))
                if before_fields:
                    changes.append(cls._change(baseline_id, current_id, DiffEntityType.SERVICE, DiffChangeType.CHANGED, key, cls._snapshot(before_fields), cls._snapshot(after_fields)))
        return tuple(changes)

    @classmethod
    def _compare_os(cls, baseline: Mapping[str, AttackSurfaceHost], current: Mapping[str, AttackSurfaceHost], issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) & set(current)):
            before = baseline[key].classification
            after = current[key].classification
            if before == after:
                continue
            before_snapshot = cls._classification_snapshot(baseline[key])
            after_snapshot = cls._classification_snapshot(current[key])
            if before is not None and after is None and not cls._removal_allowed(DiffEntityType.OS, issues):
                change_type = DiffChangeType.UNKNOWN
                qualification = "current_os_coverage_incomplete"
            elif before is None:
                change_type = DiffChangeType.ADDED
                qualification = None
            elif after is None:
                change_type = DiffChangeType.REMOVED
                qualification = None
            else:
                change_type = DiffChangeType.CHANGED
                qualification = None
            changes.append(cls._change(baseline_id, current_id, DiffEntityType.OS, change_type, key, before_snapshot, after_snapshot, qualification))
        return tuple(changes)

    @classmethod
    def _compare_technologies(cls, baseline: Mapping[str, Technology], current: Mapping[str, Technology], issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        baseline_by_name = cls._group_by_name(baseline)
        current_by_name = cls._group_by_name(current)
        for scope, name in sorted(set(baseline_by_name) | set(current_by_name)):
            before_items = baseline_by_name.get((scope, name), ())
            after_items = current_by_name.get((scope, name), ())
            before_by_version = {cls._normalize(item.version): (item_key, item) for item_key, item in before_items}
            after_by_version = {cls._normalize(item.version): (item_key, item) for item_key, item in after_items}
            common_versions = set(before_by_version) & set(after_by_version)
            for version in sorted(common_versions):
                before = before_by_version[version][1]
                after = after_by_version[version][1]
                if cls._reference_keys(before.evidence_references) != cls._reference_keys(after.evidence_references):
                    key = cls._technology_key(after)
                    changes.append(cls._change(baseline_id, current_id, DiffEntityType.EVIDENCE, DiffChangeType.CHANGED, key, cls._technology_snapshot(before), cls._technology_snapshot(after)))
            unmatched_before = [item for version, item in before_by_version.items() if version not in common_versions]
            unmatched_after = [item for version, item in after_by_version.items() if version not in common_versions]
            if unmatched_before and unmatched_after and len(unmatched_before) == len(unmatched_after) == 1:
                before = unmatched_before[0][1]
                after = unmatched_after[0][1]
                change_type = DiffChangeType.CHANGED
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.TECHNOLOGY, change_type, f"{scope}|{name}", cls._technology_snapshot(before), cls._technology_snapshot(after)))
                continue
            for item_key, item in unmatched_before:
                change_type = DiffChangeType.REMOVED if cls._removal_allowed(DiffEntityType.TECHNOLOGY, issues) else DiffChangeType.UNKNOWN
                qualification = None if change_type is DiffChangeType.REMOVED else "current_technology_coverage_incomplete"
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.TECHNOLOGY, change_type, item_key, cls._technology_snapshot(item), None, qualification))
            for item_key, item in unmatched_after:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.TECHNOLOGY, DiffChangeType.ADDED, item_key, None, cls._technology_snapshot(item)))
        return tuple(changes)

    @classmethod
    def _compare_exposures(cls, baseline: Mapping[str, Exposure], current: Mapping[str, Exposure], issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) | set(current)):
            before = baseline.get(key)
            after = current.get(key)
            if before is None:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.EXPOSURE, DiffChangeType.ADDED, key, None, cls._exposure_snapshot(after)))
            elif after is None:
                change_type = DiffChangeType.REMOVED if cls._removal_allowed(DiffEntityType.EXPOSURE, issues) else DiffChangeType.UNKNOWN
                qualification = None if change_type is DiffChangeType.REMOVED else "current_service_coverage_incomplete"
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.EXPOSURE, change_type, key, cls._exposure_snapshot(before), None, qualification))
            else:
                before_fields, after_fields = cls._changed_fields(cls._exposure_fields(before), cls._exposure_fields(after))
                if before_fields:
                    changes.append(cls._change(baseline_id, current_id, DiffEntityType.EXPOSURE, DiffChangeType.CHANGED, key, cls._snapshot(before_fields), cls._snapshot(after_fields)))
        return tuple(changes)

    @classmethod
    def _compare_relationships(cls, baseline: Mapping[str, Relationship], current: Mapping[str, Relationship], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) | set(current)):
            before = baseline.get(key)
            after = current.get(key)
            if before is None:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.RELATIONSHIP, DiffChangeType.ADDED, key, None, cls._relationship_snapshot(after)))
            elif after is None:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.RELATIONSHIP, DiffChangeType.REMOVED, key, cls._relationship_snapshot(before), None))
        return tuple(changes)

    @classmethod
    def _compare_enumerations(cls, baseline: Mapping[str, EnumerationReference], current: Mapping[str, EnumerationReference], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        changes: list[SurfaceChange] = []
        for key in sorted(set(baseline) | set(current)):
            before = baseline.get(key)
            after = current.get(key)
            if before == after:
                continue
            change_type = DiffChangeType.ADDED if before is None else DiffChangeType.REMOVED if after is None else DiffChangeType.CHANGED
            changes.append(cls._change(baseline_id, current_id, DiffEntityType.ENUMERATION, change_type, key, cls._enumeration_snapshot(before), cls._enumeration_snapshot(after)))
        return tuple(changes)

    @classmethod
    def _compare_evidence(cls, baseline: AttackSurface, current: AttackSurface, issues: set[str], baseline_id: str, current_id: str) -> tuple[SurfaceChange, ...]:
        before = cls._all_evidence(baseline)
        after = cls._all_evidence(current)
        changes: list[SurfaceChange] = []
        for key in sorted(set(before) | set(after)):
            if key in before and key in after:
                continue
            if key in before:
                change_type = DiffChangeType.REMOVED if cls._removal_allowed(DiffEntityType.EVIDENCE, issues) else DiffChangeType.UNKNOWN
                qualification = None if change_type is DiffChangeType.REMOVED else "current_evidence_coverage_incomplete"
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.EVIDENCE, change_type, key, cls._evidence_snapshot(before[key]), None, qualification))
            else:
                changes.append(cls._change(baseline_id, current_id, DiffEntityType.EVIDENCE, DiffChangeType.ADDED, key, None, cls._evidence_snapshot(after[key])))
        return tuple(changes)

    @classmethod
    def _services_by_key(cls, surface: AttackSurface) -> dict[str, AttackSurfaceService]:
        hosts = {host.id: host.ip.strip() for host in surface.hosts}
        return {cls._service_key(hosts.get(service.host_id, service.host_id), service): service for host in surface.hosts for service in host.services}

    @classmethod
    def _exposures_by_key(cls, surface: AttackSurface) -> dict[str, Exposure]:
        hosts = {host.id: host.ip.strip() for host in surface.hosts}
        return {cls._exposure_key(hosts.get(exposure.host_id, exposure.host_id), exposure): exposure for exposure in surface.exposures}

    @classmethod
    def _technologies_by_key(cls, surface: AttackSurface) -> dict[str, Technology]:
        scopes = {
            technology_id: host.ip.strip()
            for host in surface.hosts
            for technology_id in host.technology_ids
        }
        return {
            f"{scopes.get(item.id, '')}|{cls._technology_key(item)}": item
            for item in surface.technologies
        }

    @classmethod
    def _relationships_by_key(cls, surface: AttackSurface) -> dict[str, Relationship]:
        technology_keys = {item.id: cls._technology_key(item) for item in surface.technologies}
        hosts = {host.id: host.ip.strip() for host in surface.hosts}
        services = {service.id: cls._service_key(hosts.get(service.host_id, service.host_id), service) for host in surface.hosts for service in host.services}
        exposures = {item.id: cls._exposure_key(hosts.get(item.host_id, item.host_id), item) for item in surface.exposures}
        return {cls._relationship_key(item, hosts, services, exposures, technology_keys): item for item in surface.relationships}

    @classmethod
    def _enumerations_by_key(cls, surface: AttackSurface) -> dict[str, EnumerationReference]:
        hosts = {host.id: host.ip.strip() for host in surface.hosts}
        values: dict[str, EnumerationReference] = {}
        for host in surface.hosts:
            for service in host.services:
                service_key = cls._service_key(hosts.get(service.host_id, service.host_id), service)
                for reference in service.enumeration_references:
                    values[f"{service_key}:{reference.module}"] = reference
        return values

    @classmethod
    def _host_fields(cls, host: AttackSurfaceHost) -> tuple[DiffField, ...]:
        return tuple(DiffField(name, value, host.evidence_references) for name, value in (("hostname", host.hostname), ("state", host.state), ("mac_address", host.mac_address), ("vendor", host.vendor)))

    @classmethod
    def _service_fields(cls, service: AttackSurfaceService) -> tuple[DiffField, ...]:
        return tuple(DiffField(name, value, service.evidence_references) for name, value in (("state", service.state), ("service_name", service.service_name), ("product", service.product), ("version", service.version), ("extra_info", service.extra_info)))

    @classmethod
    def _exposure_fields(cls, exposure: Exposure) -> tuple[DiffField, ...]:
        return tuple(DiffField(name, value, exposure.evidence_references) for name, value in (("state", exposure.state), ("service_name", exposure.service_name)))

    @classmethod
    def _changed_fields(cls, before: tuple[DiffField, ...], after: tuple[DiffField, ...]) -> tuple[tuple[DiffField, ...], tuple[DiffField, ...]] | tuple[(), ()]:
        before_values = {field.name: field.value for field in before}
        after_values = {field.name: field.value for field in after}
        changed = [name for name in sorted(before_values) if before_values[name] != after_values[name] and before_values[name] is not None and after_values[name] is not None]
        if not changed:
            return (), ()
        before_map = {field.name: field for field in before}
        after_map = {field.name: field for field in after}
        return tuple(before_map[name] for name in changed), tuple(after_map[name] for name in changed)

    @classmethod
    def _host_snapshot(cls, host: AttackSurfaceHost | None) -> DiffSnapshot | None:
        return None if host is None else cls._snapshot(cls._host_fields(host), host.evidence_references)

    @classmethod
    def _service_snapshot(cls, service: AttackSurfaceService | None) -> DiffSnapshot | None:
        return None if service is None else cls._snapshot(cls._service_fields(service), service.evidence_references)

    @classmethod
    def _classification_snapshot(cls, host: AttackSurfaceHost) -> DiffSnapshot | None:
        if host.classification is None:
            return None
        fields = (DiffField("family", host.classification.family.value, host.evidence_references), DiffField("confidence", host.classification.confidence.value, host.evidence_references))
        return cls._snapshot(fields, host.evidence_references)

    @classmethod
    def _technology_snapshot(cls, item: Technology | None) -> DiffSnapshot | None:
        return None if item is None else cls._snapshot((DiffField("name", item.name, item.evidence_references), DiffField("version", item.version, item.evidence_references), DiffField("kind", item.kind, item.evidence_references)), item.evidence_references)

    @classmethod
    def _exposure_snapshot(cls, item: Exposure | None) -> DiffSnapshot | None:
        return None if item is None else cls._snapshot((DiffField("port", str(item.port), item.evidence_references), DiffField("protocol", item.protocol, item.evidence_references), DiffField("state", item.state, item.evidence_references), DiffField("kind", item.kind, item.evidence_references)), item.evidence_references)

    @classmethod
    def _relationship_snapshot(cls, item: Relationship | None) -> DiffSnapshot | None:
        return None if item is None else cls._snapshot((DiffField("type", item.type.value, item.evidence_references), DiffField("source_id", item.source_id, item.evidence_references), DiffField("target_id", item.target_id, item.evidence_references)), item.evidence_references)

    @classmethod
    def _enumeration_snapshot(cls, item: EnumerationReference | None) -> DiffSnapshot | None:
        return None if item is None else cls._snapshot((DiffField("module", item.module), DiffField("status", item.status.value), DiffField("evidence_ids", "|".join(item.evidence_ids))), ())

    @classmethod
    def _evidence_snapshot(cls, item: EvidenceReference) -> DiffSnapshot:
        return cls._snapshot((DiffField("source_type", item.source_type), DiffField("source_id", item.source_id), DiffField("field", item.field), DiffField("value", item.value), DiffField("details", item.details)), (item,))

    @classmethod
    def _snapshot(cls, fields: Iterable[DiffField], evidence: Iterable[EvidenceReference] = ()) -> DiffSnapshot:
        return DiffSnapshot(tuple(sorted(fields, key=lambda item: item.name)))

    @classmethod
    def _change(cls, baseline_id: str, current_id: str, entity_type: DiffEntityType, change_type: DiffChangeType, key: str, before: DiffSnapshot | None, after: DiffSnapshot | None, qualification: str | None = None) -> SurfaceChange:
        references = []
        for snapshot in (before, after):
            if snapshot is not None:
                for field in snapshot.fields:
                    references.extend(field.evidence_references)
        return SurfaceChange(
            id=f"change:{baseline_id}:{current_id}:{entity_type.value}:{key}:{change_type.value}",
            entity_type=entity_type,
            change_type=change_type,
            comparison_key=key,
            before=before,
            after=after,
            evidence_references=cls._sorted_references(references),
            qualification=qualification,
        )

    @classmethod
    def _technology_key(cls, item: Technology) -> str:
        return f"{cls._normalize(item.name)}:{cls._normalize(item.version) or 'none'}"

    @classmethod
    def _service_key(cls, ip: str, service: AttackSurfaceService) -> str:
        return f"{ip}:{cls._normalize(service.protocol)}:{service.port}"

    @classmethod
    def _exposure_key(cls, ip: str, exposure: Exposure) -> str:
        return f"{ip}:{cls._normalize(exposure.protocol)}:{exposure.port}:{cls._normalize(exposure.kind)}"

    @classmethod
    def _relationship_key(cls, relationship: Relationship, hosts: Mapping[str, str], services: Mapping[str, str], exposures: Mapping[str, str], technologies: Mapping[str, str]) -> str:
        source = cls._normalize_entity_id(relationship.source_id, hosts, services, exposures, technologies)
        target = cls._normalize_entity_id(relationship.target_id, hosts, services, exposures, technologies)
        return f"{relationship.type.value}:{source}:{target}"

    @staticmethod
    def _normalize_entity_id(value: str, hosts: Mapping[str, str], services: Mapping[str, str], exposures: Mapping[str, str], technologies: Mapping[str, str]) -> str:
        return hosts.get(value, services.get(value, exposures.get(value, technologies.get(value, value))))

    @classmethod
    def _group_by_name(cls, values: Mapping[str, Technology]) -> dict[tuple[str, str], tuple[tuple[str, Technology], ...]]:
        grouped: dict[tuple[str, str], list[tuple[str, Technology]]] = {}
        for item_key, item in values.items():
            scope, _, _ = item_key.partition("|")
            grouped.setdefault((scope, cls._normalize(item.name)), []).append((item_key, item))
        return {
            key: tuple(sorted(items, key=lambda pair: cls._normalize(pair[1].version)))
            for key, items in grouped.items()
        }

    @classmethod
    def _all_evidence(cls, surface: AttackSurface) -> dict[str, EvidenceReference]:
        references: list[EvidenceReference] = []
        for host in surface.hosts:
            references.extend(host.evidence_references)
            for service in host.services:
                references.extend(service.evidence_references)
        for item in surface.technologies:
            references.extend(item.evidence_references)
        for item in surface.exposures:
            references.extend(item.evidence_references)
        for item in surface.relationships:
            references.extend(item.evidence_references)
        return {cls._evidence_key(item): item for item in references}

    @classmethod
    def _evidence_key(cls, item: EvidenceReference) -> str:
        return f"{item.source_type}:{cls._normalize_source_id(item.source_id)}:{item.field}:{cls._normalize(item.value)}:{item.details or ''}"

    @classmethod
    def _normalize_source_id(cls, value: str) -> str:
        parts = value.split(":")
        if len(parts) >= 3 and parts[0] in {"host", "service", "exposure", "enumeration"}:
            return ":".join((parts[0], *parts[2:]))
        if len(parts) >= 4 and parts[0] == "osfp" and parts[1] == "host":
            return ":".join((parts[0], parts[1], parts[3], *parts[4:]))
        return value

    @classmethod
    def _reference_keys(cls, references: Iterable[EvidenceReference]) -> tuple[str, ...]:
        return tuple(sorted(cls._evidence_key(item) for item in references))

    @staticmethod
    def _normalize(value: str | None) -> str:
        return re.sub(r"\s+", " ", (value or "").strip()).casefold()

    @classmethod
    def _sorted_references(cls, references: Iterable[EvidenceReference]) -> tuple[EvidenceReference, ...]:
        unique = {(item.source_type, item.source_id, item.field, item.value, item.details): item for item in references}
        return tuple(sorted(unique.values(), key=lambda item: (item.source_type, item.source_id, item.field, cls._normalize(item.value), item.details or "")))

    @classmethod
    def _coverage_issues(cls, surface: AttackSurface) -> set[str]:
        issues = set(surface.completeness.issues)
        if surface.completeness.status is not CorrelationCompletenessStatus.COMPLETE:
            issues.add(surface.completeness.status.value)
        for host in surface.hosts:
            for service in host.services:
                for reference in service.enumeration_references:
                    if reference.status.value != "success":
                        issues.add(f"enumeration:{reference.status.value}")
        return issues

    @classmethod
    def _removal_allowed(cls, entity_type: DiffEntityType, issues: set[str]) -> bool:
        if not issues:
            return True
        prefixes = {
            DiffEntityType.HOST: ("discovery", "partial", "current_incomplete", "comparison_limited", "scan_status"),
            DiffEntityType.SERVICE: ("discovery", "ports", "services", "partial", "current_incomplete", "comparison_limited", "scan_status"),
            DiffEntityType.EXPOSURE: ("discovery", "ports", "services", "partial", "current_incomplete", "comparison_limited", "scan_status"),
            DiffEntityType.OS: ("discovery", "os", "partial", "current_incomplete", "comparison_limited", "scan_status"),
            DiffEntityType.TECHNOLOGY: ("discovery", "ports", "services", "enumeration", "partial", "current_incomplete", "comparison_limited", "scan_status"),
            DiffEntityType.EVIDENCE: ("discovery", "ports", "services", "enumeration", "partial", "current_incomplete", "comparison_limited", "scan_status"),
        }
        return not any(issue == prefix or issue.startswith(f"{prefix}:") for issue in issues for prefix in prefixes.get(entity_type, ()))

    @classmethod
    def _diff_completeness(cls, baseline: AttackSurface, current: AttackSurface, current_issues: set[str]) -> DiffCompleteness:
        baseline_issues = cls._coverage_issues(baseline)
        if not baseline_issues and not current_issues:
            status = DiffCompletenessStatus.COMPLETE
        elif baseline_issues and current_issues:
            status = DiffCompletenessStatus.COMPARISON_LIMITED
        elif baseline_issues:
            status = DiffCompletenessStatus.BASELINE_INCOMPLETE
        else:
            status = DiffCompletenessStatus.CURRENT_INCOMPLETE
        issues = tuple(sorted(f"baseline:{item}" for item in baseline_issues) + sorted(f"current:{item}" for item in current_issues))
        return DiffCompleteness(status, issues, baseline.source_scan_status, current.source_scan_status)
