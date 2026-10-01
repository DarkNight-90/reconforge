"""Typed domain and manifest contracts for ReconForge."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path


def _require_utc(value: datetime | None, field_name: str, *, allow_none: bool = True) -> None:
    """Require a timezone-aware datetime representing UTC."""
    if value is None and allow_none:
        return
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class OSFamily(StrEnum):
    WINDOWS = "Windows"
    LINUX_UNIX = "Linux/Unix"
    UNKNOWN = "Unknown"


class ConfidenceLevel(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class EnumerationStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    UNSUPPORTED = "unsupported"


class CorrelationCompletenessStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    DISCOVERY_UNAVAILABLE = "discovery_unavailable"
    SERVICE_DATA_INCOMPLETE = "service_data_incomplete"
    OS_DATA_INCOMPLETE = "os_data_incomplete"
    ENUMERATION_INCOMPLETE = "enumeration_incomplete"


class DiffChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNKNOWN = "unknown"


class DiffEntityType(StrEnum):
    HOST = "host"
    SERVICE = "service"
    OS = "os"
    TECHNOLOGY = "technology"
    EXPOSURE = "exposure"
    RELATIONSHIP = "relationship"
    ENUMERATION = "enumeration"
    EVIDENCE = "evidence"


class DiffCompletenessStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    BASELINE_INCOMPLETE = "baseline_incomplete"
    CURRENT_INCOMPLETE = "current_incomplete"
    COMPARISON_LIMITED = "comparison_limited"


class CoverageStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    UNSUPPORTED = "unsupported"
    NOT_ATTEMPTED = "not_attempted"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class RelationshipType(StrEnum):
    HOST_HAS_OS = "HOST_HAS_OS"
    HOST_HAS_SERVICE = "HOST_HAS_SERVICE"
    SERVICE_EXPOSES_PORT = "SERVICE_EXPOSES_PORT"
    SERVICE_INDICATES_TECHNOLOGY = "SERVICE_INDICATES_TECHNOLOGY"
    ENUMERATION_SUPPORTS_TECHNOLOGY = "ENUMERATION_SUPPORTS_TECHNOLOGY"
    EVIDENCE_SUPPORTS_EXPOSURE = "EVIDENCE_SUPPORTS_EXPOSURE"


@dataclass(frozen=True)
class Service:
    """An observed network service; no classification is implied."""

    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass(frozen=True)
class OSFingerprint:
    """Operating-system evidence observed by Nmap."""

    vendor: str | None = None
    family: str | None = None
    generation: str | None = None
    accuracy: int | None = None
    source: str | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    """A typed input used later by the OS classifier."""

    source: str
    indicator: str
    value: str
    weight: float = 0.0
    direction: OSFamily = OSFamily.UNKNOWN
    details: str | None = None


@dataclass(frozen=True)
class OSClassification:
    """ReconForge-derived OS conclusion, separate from Nmap observations."""

    family: OSFamily = OSFamily.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    evidence: tuple[Evidence, ...] = ()
    windows_score: float = 0.0
    unix_score: float = 0.0


@dataclass(frozen=True)
class EnumerationTarget:
    """A network service bound to a compatible M8 enumeration module."""

    scan_id: str
    host_id: int
    ip: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass(frozen=True)
class EnumerationEvidence:
    """Structured evidence produced by a passive service enumeration module."""

    source: str
    category: str
    indicator: str
    value: str
    confidence: str = "medium"
    details: str | None = None


@dataclass(frozen=True)
class EnumerationDecision:
    """A decision produced by the enumeration engine for one service target."""

    target: EnumerationTarget
    module: str | None
    reason: str
    priority: str = "normal"
    status: EnumerationStatus = EnumerationStatus.UNSUPPORTED
    evidence: tuple[EnumerationEvidence, ...] = ()


@dataclass(frozen=True)
class EnumerationResult:
    """Result of a safe protocol-specific enumeration pass."""

    scan_id: str
    host_id: int
    ip: str
    port: int
    protocol: str
    module: str
    status: EnumerationStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration: float | None = None
    error_message: str | None = None
    evidence: tuple[EnumerationEvidence, ...] = ()
    id: int | None = None

    def __post_init__(self) -> None:
        _require_utc(self.started_at, "started_at", allow_none=False)
        _require_utc(self.finished_at, "finished_at")
        if self.evidence is not None and not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", (self.evidence,))


@dataclass(frozen=True)
class Host:
    """A host with observed Nmap data and optional derived classification."""

    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    state: str = "unknown"
    services: tuple[Service, ...] = ()
    os_fingerprints: tuple[OSFingerprint, ...] = ()
    classification: OSClassification | None = None


@dataclass(frozen=True)
class NmapExecutionResult:
    """Contract returned by a future single-phase Nmap runner."""

    phase: str
    artifact_path: Path | None
    arguments: tuple[str, ...]
    started_at: datetime
    finished_at: datetime | None
    duration: float | None
    exit_code: int | None
    status: ExecutionStatus
    stderr_summary: str | None = None

    def __post_init__(self) -> None:
        _require_utc(self.started_at, "started_at", allow_none=False)
        _require_utc(self.finished_at, "finished_at")


@dataclass(frozen=True)
class Scan:
    """Metadata for the complete ReconForge reconnaissance session."""

    id: str
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    status: ScanStatus = ScanStatus.RUNNING
    results_path: Path | None = None
    reconforge_version: str = ""
    nmap_version: str | None = None
    workflow: str = "default"
    arguments: tuple[str, ...] = ()
    error_message: str | None = None

    def __post_init__(self) -> None:
        _require_utc(self.started_at, "started_at", allow_none=False)
        _require_utc(self.finished_at, "finished_at")


@dataclass(frozen=True)
class ManifestExecution:
    """One phase entry in a scan manifest."""

    phase: str
    artifact: str | None
    status: ExecutionStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration: float | None = None
    exit_code: int | None = None
    arguments: tuple[str, ...] = ()
    stderr_summary: str | None = None

    def __post_init__(self) -> None:
        _require_utc(self.started_at, "started_at")
        _require_utc(self.finished_at, "finished_at")


@dataclass(frozen=True)
class ScanManifest:
    """In-memory contract for a scan's execution-history manifest."""

    schema_version: int
    scan_id: str
    target: str
    workflow: str
    reconforge_version: str
    nmap_version: str | None
    created_at: datetime
    updated_at: datetime
    scan_status: ScanStatus
    executions: tuple[ManifestExecution, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _require_utc(self.created_at, "created_at", allow_none=False)
        _require_utc(self.updated_at, "updated_at", allow_none=False)


@dataclass(frozen=True)
class ScanResult:
    """Final controller output containing scan metadata and merged observations."""

    scan: Scan
    hosts: tuple[Host, ...]
    phase_results: tuple[ManifestExecution, ...]
    enumeration_results: tuple[EnumerationResult, ...] = ()


@dataclass(frozen=True)
class RecoveryPlan:
    """Deterministic recovery guidance for a scan manifest."""

    scan_id: str
    recoverable: bool
    reason: str
    phases_to_run: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceReference:
    """Traceability from derived correlation data to persisted evidence."""

    source_type: str
    source_id: str
    field: str
    value: str
    details: str | None = None


@dataclass(frozen=True)
class EnumerationReference:
    """Enumeration lifecycle and evidence references attached to a service."""

    result_id: str
    module: str
    status: EnumerationStatus
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationCompleteness:
    """Deterministic collection coverage metadata for a derived model."""

    status: CorrelationCompletenessStatus
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class Technology:
    """An implementation or platform explicitly supported by evidence."""

    id: str
    name: str
    version: str | None = None
    kind: str = "implementation"
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class Exposure:
    """An observable service/interface characteristic, not a vulnerability."""

    id: str
    host_id: str
    service_id: str
    kind: str
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class AttackSurfaceService:
    """A persisted service represented in the correlated attack surface."""

    id: str
    host_id: str
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    technology_ids: tuple[str, ...] = ()
    enumeration_references: tuple[EnumerationReference, ...] = ()
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class AttackSurfaceHost:
    """A persisted host and its correlated services and derived entities."""

    id: str
    scan_id: str
    ip: str
    hostname: str | None = None
    state: str = "unknown"
    mac_address: str | None = None
    vendor: str | None = None
    classification: OSClassification | None = None
    services: tuple[AttackSurfaceService, ...] = ()
    technology_ids: tuple[str, ...] = ()
    exposure_ids: tuple[str, ...] = ()
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class Relationship:
    """A small typed edge between stable attack-surface entities."""

    type: RelationshipType
    source_id: str
    target_id: str
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class AttackSurface:
    """Deterministic, read-only correlation output for one scan."""

    scan_id: str
    generated_at: datetime
    hosts: tuple[AttackSurfaceHost, ...] = ()
    technologies: tuple[Technology, ...] = ()
    exposures: tuple[Exposure, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    source_scan_status: ScanStatus = ScanStatus.RUNNING
    completeness: CorrelationCompleteness = field(
        default_factory=lambda: CorrelationCompleteness(CorrelationCompletenessStatus.PARTIAL)
    )


@dataclass(frozen=True)
class DiffField:
    """One comparable field value with its source provenance."""

    name: str
    value: str | None
    evidence_references: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class DiffSnapshot:
    """Immutable before/after representation for one changed entity."""

    fields: tuple[DiffField, ...] = ()


@dataclass(frozen=True)
class DiffCompleteness:
    """Coverage metadata qualifying an attack-surface comparison."""

    status: DiffCompletenessStatus
    issues: tuple[str, ...] = ()
    baseline_scan_status: ScanStatus = ScanStatus.RUNNING
    current_scan_status: ScanStatus = ScanStatus.RUNNING


@dataclass(frozen=True)
class SurfaceChange:
    """One deterministic, provenance-preserving attack-surface change."""

    id: str
    entity_type: DiffEntityType
    change_type: DiffChangeType
    comparison_key: str
    before: DiffSnapshot | None = None
    after: DiffSnapshot | None = None
    evidence_references: tuple[EvidenceReference, ...] = ()
    qualification: str | None = None


@dataclass(frozen=True)
class AttackSurfaceDiff:
    """Directional comparison of two derived attack-surface models."""

    baseline_scan_id: str
    current_scan_id: str
    generated_at: datetime
    baseline_status: ScanStatus
    current_status: ScanStatus
    completeness: DiffCompleteness
    host_changes: tuple[SurfaceChange, ...] = ()
    service_changes: tuple[SurfaceChange, ...] = ()
    os_changes: tuple[SurfaceChange, ...] = ()
    technology_changes: tuple[SurfaceChange, ...] = ()
    exposure_changes: tuple[SurfaceChange, ...] = ()
    relationship_changes: tuple[SurfaceChange, ...] = ()
    enumeration_changes: tuple[SurfaceChange, ...] = ()
    evidence_changes: tuple[SurfaceChange, ...] = ()

    @property
    def id(self) -> str:
        return f"diff:{self.baseline_scan_id}:{self.current_scan_id}"


@dataclass(frozen=True)
class CoverageReference:
    """Provenance explaining a collection or evidence coverage state."""

    source_type: str
    source_id: str
    field: str
    value: str
    details: str | None = None


@dataclass(frozen=True)
class PhaseCoverage:
    """Coverage state for one manifest-recorded execution phase."""

    phase: str
    status: CoverageStatus
    artifact: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    qualification: str | None = None
    references: tuple[CoverageReference, ...] = ()

    def __post_init__(self) -> None:
        _require_utc(self.started_at, "started_at")
        _require_utc(self.finished_at, "finished_at")


@dataclass(frozen=True)
class HostCoverage:
    """Evidence coverage for one host represented by M9."""

    id: str
    ip: str
    observed_state: str
    os_status: CoverageStatus
    service_count: int
    service_status: CoverageStatus
    references: tuple[CoverageReference, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceCoverage:
    """Separate service-observation and enumeration coverage."""

    id: str
    host_ip: str
    port: int
    protocol: str
    observation_status: CoverageStatus
    metadata_status: CoverageStatus
    enumeration_statuses: tuple[CoverageStatus, ...] = ()
    references: tuple[CoverageReference, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceCoverageReport:
    """Deterministic, read-only coverage analysis for one M9 surface."""

    scan_id: str
    generated_at: datetime
    source_scan_status: ScanStatus
    overall_status: CoverageStatus
    phase_coverage: tuple[PhaseCoverage, ...] = ()
    host_coverage: tuple[HostCoverage, ...] = ()
    service_coverage: tuple[ServiceCoverage, ...] = ()
    limitations: tuple[str, ...] = ()
    references: tuple[CoverageReference, ...] = ()

    def __post_init__(self) -> None:
        _require_utc(self.generated_at, "generated_at", allow_none=False)

    @property
    def id(self) -> str:
        return f"coverage:{self.scan_id}"
