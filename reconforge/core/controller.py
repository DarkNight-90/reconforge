"""Synchronous reconnaissance workflow orchestration."""

from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path as PathlibPath, PurePosixPath
from typing import Protocol
from uuid import uuid4

from .. import __version__
from ..config import InvalidCIDRError, UnsupportedInputError, validate_targets
from ..correlation.engine import AttackSurfaceCorrelator
from ..diff.engine import AttackSurfaceDiffer
from ..coverage.engine import EvidenceCoverageAnalyzer
from ..enumeration.engine import EnumerationEngine
from ..nmap.profiles import get_profile
from ..nmap.runner import NmapError, NmapRunner
from ..parsers.nmap_xml import NmapXMLFileError, NmapXMLParseError, NmapXMLParser
from ..reports.terminal import render_scan_summary
from .classifier import OSClassifier
from .models import (
    EnumerationTarget,
    ExecutionStatus,
    Host,
    ManifestExecution,
    NmapExecutionResult,
    OSFingerprint,
    RecoveryPlan,
    Scan,
    ScanManifest,
    ScanResult,
    Service,
    ScanStatus,
    AttackSurface,
    AttackSurfaceDiff,
    EvidenceCoverageReport,
)
from .repository import Repository


class ControllerError(RuntimeError):
    """Base class for controlled workflow errors."""


class ControllerInputError(ControllerError):
    """Raised when the requested target is invalid."""


class ControllerDependencyError(ControllerError):
    """Raised when a required workflow dependency is unavailable."""


class RunnerProtocol(Protocol):
    def check_available(self) -> str: ...

    def run(self, profile: object, target: str | Sequence[str], artifact_path: Path, timeout: float) -> NmapExecutionResult: ...


class ParserProtocol(Protocol):
    def parse(self, path: Path) -> tuple[Host, ...]: ...


class ClassifierProtocol(Protocol):
    def classify(self, host: Host): ...


class RepositoryProtocol(Protocol):
    def get_scan(self, scan_id: str) -> Scan: ...

    def get_hosts(self, scan_id: str) -> tuple[Host, ...]: ...

    def create_scan(self, scan: Scan) -> None: ...

    def update_scan(self, scan: Scan) -> None: ...

    def save_host(self, scan_id: str, host: Host) -> int: ...

    def update_host(self, scan_id: str, host: Host) -> None: ...


class ManifestValidationError(ControllerError, ValueError):
    """Raised when a manifest does not satisfy the execution-history contract."""


class ReconController:
    """Coordinate scan phases while delegating component behavior."""

    _PHASES = ("discovery", "ports", "services", "os")
    _ENUMERATION_PHASE = "enumeration"

    def __init__(
        self,
        config: object,
        runner: RunnerProtocol | None = None,
        parser: ParserProtocol | None = None,
        classifier: ClassifierProtocol | None = None,
        repository: RepositoryProtocol | None = None,
        reporter: Callable[[ScanResult], None] | None = None,
        enumeration_engine: object | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or NmapRunner(default_timeout=config.scan_timeout)
        self.parser = parser or NmapXMLParser()
        self.classifier = classifier or OSClassifier()
        self.repository = repository or Repository(config.database_path)
        self.enumeration_engine = enumeration_engine or EnumerationEngine()
        self.reporter = reporter or render_scan_summary
        self.logger = logging.getLogger(__name__)

    def run(self, target: str | Sequence[str]) -> ScanResult:
        """Run the standard discovery, ports, services, and OS workflow."""
        try:
            validated_target = validate_targets(target)
        except (InvalidCIDRError, UnsupportedInputError) as exc:
            raise ControllerInputError(str(exc)) from exc
        try:
            self.runner.check_available()
        except NmapError as exc:
            raise ControllerDependencyError(str(exc)) from exc

        scan_id = str(uuid4())
        scan_directory = self.config.data_directory / "scans" / scan_id
        scan_directory.mkdir(parents=True, exist_ok=False)
        started_at = datetime.now(timezone.utc)
        scan = Scan(
            id=scan_id,
            target=",".join(validated_target),
            started_at=started_at,
            results_path=scan_directory,
            reconforge_version=__version__,
            workflow=self.config.workflow,
        )
        self.repository.create_scan(scan)
        manifest = self._initial_manifest(scan)
        self._write_manifest(scan_directory, manifest)
        merged_hosts: dict[str, Host] = {}
        phase_results: list[ManifestExecution] = []
        enumeration_results: list[object] = []

        try:
            for index, phase in enumerate(self._PHASES):
                phase_target: str | Sequence[str] = validated_target if index == 0 else tuple(sorted(merged_hosts))
                if index > 0 and not merged_hosts:
                    manifest, skipped = self._skip_remaining(manifest, phase_results, scan_directory, index)
                    phase_results.extend(skipped)
                    break
                execution, observations, manifest = self._execute_phase(
                    phase, phase_target, scan_directory, manifest
                )
                phase_results.append(execution)
                self._write_manifest(scan_directory, manifest)
                if execution.status is ExecutionStatus.COMPLETED:
                    self._merge_hosts(merged_hosts, observations, allow_new=phase == "discovery")
                    continue
                manifest, skipped = self._skip_remaining(manifest, phase_results, scan_directory, index + 1)
                phase_results.extend(skipped)
                break

            for ip in sorted(merged_hosts):
                host = merged_hosts[ip]
                merged_hosts[ip] = replace(host, classification=self.classifier.classify(host))
            self._persist_hosts(scan_id, merged_hosts)
            manifest = self._replace_execution(manifest, ManifestExecution(self._ENUMERATION_PHASE, "enumeration.json", ExecutionStatus.PENDING))
            self._write_manifest(scan_directory, manifest)
            enumeration_results = self._enumerate_known_services(scan_id, merged_hosts, manifest, scan_directory)

            interrupted = any(item.status is ExecutionStatus.INTERRUPTED for item in phase_results)
            failed_early = any(
                item.status in {ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT}
                and item.phase != "os"
                for item in phase_results
            )
            final_status = ScanStatus.INTERRUPTED if interrupted else ScanStatus.FAILED if failed_early else ScanStatus.COMPLETED
            error_message = next((item.stderr_summary for item in phase_results if item.status in {
                ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT, ExecutionStatus.INTERRUPTED
            }), None)
            if self._ENUMERATION_PHASE in {item.phase for item in phase_results}:
                enum_status = next((item.status for item in phase_results if item.phase == self._ENUMERATION_PHASE), None)
                if enum_status in {ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT, ExecutionStatus.INTERRUPTED}:
                    error_message = error_message or enum_status.value
            finished_at = datetime.now(timezone.utc)
            scan = replace(scan, finished_at=finished_at, status=final_status, error_message=error_message)
            self.repository.update_scan(scan)
            manifest = replace(manifest, updated_at=finished_at, scan_status=final_status, executions=tuple(phase_results))
            self._write_manifest(scan_directory, manifest)
            result = ScanResult(
                scan=scan,
                hosts=tuple(merged_hosts[ip] for ip in sorted(merged_hosts)),
                phase_results=tuple(phase_results),
                enumeration_results=tuple(enumeration_results),
            )
            self.reporter(result)
            return result
        except KeyboardInterrupt:
            finished_at = datetime.now(timezone.utc)
            manifest = replace(manifest, updated_at=finished_at, scan_status=ScanStatus.INTERRUPTED, executions=tuple(phase_results))
            self._write_manifest(scan_directory, manifest)
            interrupted_scan = replace(scan, finished_at=finished_at, status=ScanStatus.INTERRUPTED)
            self.repository.update_scan(interrupted_scan)
            return ScanResult(interrupted_scan, tuple(merged_hosts.values()), tuple(phase_results))

    def list_scans(self) -> tuple[object, ...]:
        """List scans in deterministic newest-first order."""
        return self.repository.list_scans()

    def list_hosts(self, scan_id: str) -> tuple[Host, ...]:
        """Return persisted hosts for an existing scan in repository order."""
        self.repository.get_scan(scan_id)
        return self.repository.get_hosts(scan_id)

    def list_services(self, scan_id: str) -> tuple[tuple[str, Service], ...]:
        """Return persisted services with their host IP for an existing scan."""
        self.repository.get_scan(scan_id)
        return tuple(
            (host.ip, service)
            for host in self.repository.get_hosts(scan_id)
            for service in host.services
        )

    def show_scan(self, scan_id: str) -> dict[str, object]:
        """Return a read-only, human-friendly summary for one scan."""
        scan = self.repository.get_scan(scan_id)
        scan_directory = scan.results_path or self.config.data_directory / "scans" / scan_id
        manifest = self._load_manifest(scan_directory)
        self.validate_manifest(manifest, scan_directory)
        hosts = self.repository.get_hosts(scan_id)
        executions = tuple(sorted(manifest.executions, key=lambda item: self._PHASES.index(item.phase)))
        artifacts = {item.artifact: (scan_directory / item.artifact).exists() if item.artifact else False for item in executions}
        return {
            "scan_id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "workflow": scan.workflow,
            "duration": (scan.finished_at - scan.started_at).total_seconds() if scan.finished_at else None,
            "executions": executions,
            "artifacts": artifacts,
            "hosts": hosts,
            "manifest": manifest,
        }

    def correlate_scan(self, scan_id: str) -> AttackSurface:
        """Build a read-only attack-surface model from persisted evidence."""
        scan = self.repository.get_scan(scan_id)
        scan_directory = scan.results_path or self.config.data_directory / "scans" / scan_id
        manifest = self._load_manifest(scan_directory)
        self.validate_manifest(manifest, scan_directory)
        return AttackSurfaceCorrelator(self.repository).correlate(scan_id, manifest)

    def coverage_report(self, scan_id: str) -> EvidenceCoverageReport:
        """Build a read-only evidence coverage report for one scan."""
        scan = self.repository.get_scan(scan_id)
        scan_directory = scan.results_path or self.config.data_directory / "scans" / scan_id
        manifest = self._load_manifest(scan_directory)
        self.validate_manifest(manifest, scan_directory)
        if manifest.scan_id != scan.id:
            raise ManifestValidationError("manifest scan_id does not match scan")
        surface = AttackSurfaceCorrelator(self.repository).correlate(scan_id, manifest)
        return EvidenceCoverageAnalyzer().analyze(surface, manifest)

    def diff_scans(self, baseline_scan_id: str, current_scan_id: str) -> AttackSurfaceDiff:
        """Compare two scans through read-only M9 models and M10 analysis."""
        if baseline_scan_id == current_scan_id:
            raise ControllerError("baseline and current scan IDs must differ")
        baseline_scan = self.repository.get_scan(baseline_scan_id)
        current_scan = self.repository.get_scan(current_scan_id)
        baseline_directory = baseline_scan.results_path or self.config.data_directory / "scans" / baseline_scan_id
        current_directory = current_scan.results_path or self.config.data_directory / "scans" / current_scan_id
        baseline_manifest = self._load_manifest(baseline_directory)
        current_manifest = self._load_manifest(current_directory)
        self.validate_manifest(baseline_manifest, baseline_directory)
        self.validate_manifest(current_manifest, current_directory)
        if baseline_manifest.scan_id != baseline_scan.id:
            raise ManifestValidationError("baseline manifest scan_id does not match scan")
        if current_manifest.scan_id != current_scan.id:
            raise ManifestValidationError("current manifest scan_id does not match scan")
        correlator = AttackSurfaceCorrelator(self.repository)
        baseline_surface = correlator.correlate(baseline_scan_id, baseline_manifest)
        current_surface = correlator.correlate(current_scan_id, current_manifest)
        return AttackSurfaceDiffer().compare(baseline_surface, current_surface)

    def resume_scan(self, scan_id: str) -> ScanResult:
        """Resume a recoverable scan without creating a new scan ID or directory."""
        scan = self.repository.get_scan(scan_id)
        scan_directory = scan.results_path or self.config.data_directory / "scans" / scan_id
        manifest = self._load_manifest(scan_directory)
        self.validate_manifest(manifest, scan_directory)
        plan = self.plan_recovery_from_manifest(manifest)
        if not plan.recoverable:
            raise ControllerError(plan.reason)
        try:
            self.runner.check_available()
        except NmapError as exc:
            raise ControllerDependencyError(str(exc)) from exc

        merged_hosts: dict[str, Host] = {host.ip: host for host in self.repository.get_hosts(scan_id)}
        persisted_host_ips = set(merged_hosts)
        phase_results: list[ManifestExecution] = list(manifest.executions)
        target = scan.target
        if self._ENUMERATION_PHASE in {item.phase for item in phase_results}:
            phase_results = [item for item in phase_results if item.phase != self._ENUMERATION_PHASE]
        for phase in plan.phases_to_run:
            profile = get_profile(phase)
            phase_target: str | Sequence[str] = target if phase == "discovery" else tuple(sorted(merged_hosts))
            if phase != "discovery" and not merged_hosts:
                break
            execution, observations, manifest = self._execute_phase(phase, phase_target, scan_directory, manifest)
            phase_results = [item if item.phase != phase else execution for item in phase_results]
            self._write_manifest(scan_directory, manifest)
            if execution.status is ExecutionStatus.COMPLETED:
                self._merge_hosts(merged_hosts, observations, allow_new=phase == "discovery")
                continue
            break
        for ip in sorted(merged_hosts):
            host = merged_hosts[ip]
            merged_hosts[ip] = replace(host, classification=self.classifier.classify(host))
        self._persist_hosts(scan_id, merged_hosts, update_existing=persisted_host_ips)
        final_status = ScanStatus.COMPLETED
        error_message = next((item.stderr_summary for item in phase_results if item.status in {ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT, ExecutionStatus.INTERRUPTED}), None)
        if any(item.status in {ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT} for item in phase_results):
            final_status = ScanStatus.FAILED
        finished_at = datetime.now(timezone.utc)
        updated_scan = replace(scan, finished_at=finished_at, status=final_status, error_message=error_message)
        self.repository.update_scan(updated_scan)
        manifest = replace(manifest, updated_at=finished_at, scan_status=final_status, executions=tuple(phase_results))
        self._write_manifest(scan_directory, manifest)
        enumeration_results = self._enumerate_known_services(scan_id, merged_hosts, manifest, scan_directory)
        result = ScanResult(updated_scan, tuple(merged_hosts[ip] for ip in sorted(merged_hosts)), tuple(phase_results), tuple(enumeration_results))
        self.reporter(result)
        return result

    @staticmethod
    def validate_manifest(
        manifest: ScanManifest,
        scan_directory: str | PathlibPath | None = None,
        *,
        override_scan_directory: str | PathlibPath | None = None,
        Path: str | PathlibPath | None = None,
    ) -> None:
        """Validate the in-memory manifest model and any file-backed artifact paths."""
        if Path is not None and override_scan_directory is None and scan_directory is None:
            raise ManifestValidationError("invalid scan_directory override")
        resolved_scan_directory = (
            override_scan_directory
            if override_scan_directory is not None
            else scan_directory
            if scan_directory is not None
            else None
        )
        if manifest.schema_version != 1:
            raise ManifestValidationError("unsupported manifest schema_version")
        if not manifest.scan_id.strip():
            raise ManifestValidationError("manifest scan_id must not be empty")
        if not manifest.target.strip():
            raise ManifestValidationError("manifest target must not be empty")
        if not manifest.workflow.strip():
            raise ManifestValidationError("manifest workflow must not be empty")
        if not manifest.reconforge_version.strip():
            raise ManifestValidationError("manifest reconforge_version must not be empty")

        seen: set[str] = set()
        valid_statuses = {item for item in ExecutionStatus}
        for item in manifest.executions:
            if item.phase not in ReconController._PHASES:
                raise ManifestValidationError(f"unknown manifest phase: {item.phase}")
            if item.phase in seen:
                raise ManifestValidationError(f"duplicate manifest phase record: {item.phase}")
            seen.add(item.phase)
            if item.status not in valid_statuses:
                raise ManifestValidationError(f"invalid phase status for {item.phase}: {item.status}")
            if item.artifact is not None:
                raw = PurePosixPath(item.artifact)
                if raw.is_absolute() or ".." in raw.parts or raw.name in {".", ".."} or raw.name != item.artifact:
                    raise ManifestValidationError(f"unsafe artifact path for {item.phase}: {item.artifact}")
                if resolved_scan_directory is not None:
                    resolved_scan_dir = PathlibPath(resolved_scan_directory).resolve()
                    resolved_artifact = (PathlibPath(resolved_scan_directory) / item.artifact).resolve()
                    try:
                        resolved_artifact.relative_to(resolved_scan_dir)
                    except ValueError as exc:
                        raise ManifestValidationError(f"artifact path escapes scan directory: {item.artifact}") from exc

    @staticmethod
    def plan_recovery_from_manifest(manifest: ScanManifest) -> RecoveryPlan:
        """Return a deterministic resumption plan for the manifest."""
        if not manifest.executions:
            return RecoveryPlan(scan_id=manifest.scan_id, recoverable=True, reason="manifest has no phase records", phases_to_run=ReconController._PHASES)
        phase_status = {item.phase: item.status for item in manifest.executions}
        if manifest.scan_status is ScanStatus.COMPLETED and all(
            phase_status.get(phase, ExecutionStatus.PENDING) in {ExecutionStatus.COMPLETED, ExecutionStatus.SKIPPED}
            for phase in ReconController._PHASES
        ):
            return RecoveryPlan(scan_id=manifest.scan_id, recoverable=False, reason="scan already completed", phases_to_run=())

        for phase in ReconController._PHASES:
            status = phase_status.get(phase, ExecutionStatus.PENDING)
            if status in {ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT, ExecutionStatus.INTERRUPTED, ExecutionStatus.RUNNING, ExecutionStatus.PENDING}:
                if phase == "discovery":
                    phases = ReconController._PHASES
                elif phase == "ports":
                    phases = ("ports", "services", "os")
                elif phase == "services":
                    phases = ("services", "os")
                else:
                    phases = ("os",)
                return RecoveryPlan(scan_id=manifest.scan_id, recoverable=True, reason=f"phase {phase} requires rerun", phases_to_run=phases)

        return RecoveryPlan(scan_id=manifest.scan_id, recoverable=False, reason="scan has no recoverable phase", phases_to_run=())

    @staticmethod
    def _load_manifest(scan_directory: Path) -> ScanManifest:
        manifest_path = scan_directory / "manifest.json"
        if not manifest_path.exists():
            raise ManifestValidationError(f"manifest not found: {manifest_path}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ManifestValidationError(f"malformed JSON manifest: {manifest_path}") from exc
        try:
            executions = tuple(
                ManifestExecution(
                    phase=item["phase"],
                    artifact=item.get("artifact"),
                    status=ExecutionStatus(item["status"]),
                    started_at=datetime.fromisoformat(item["started_at"]) if item.get("started_at") else None,
                    finished_at=datetime.fromisoformat(item["finished_at"]) if item.get("finished_at") else None,
                    duration=item.get("duration"),
                    exit_code=item.get("exit_code"),
                    arguments=tuple(item.get("arguments") or ()),
                    stderr_summary=item.get("stderr_summary"),
                )
                for item in payload.get("executions", [])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestValidationError(f"invalid manifest execution entries: {manifest_path}") from exc
        try:
            scan_status = ScanStatus(payload["scan_status"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestValidationError(f"invalid scan status in manifest: {manifest_path}") from exc
        return ScanManifest(
            schema_version=payload["schema_version"],
            scan_id=payload["scan_id"],
            target=payload["target"],
            workflow=payload["workflow"],
            reconforge_version=payload["reconforge_version"],
            nmap_version=payload.get("nmap_version"),
            created_at=datetime.fromisoformat(payload["created_at"]),
            updated_at=datetime.fromisoformat(payload["updated_at"]),
            scan_status=scan_status,
            executions=executions,
        )

    def _execute_phase(
        self,
        phase: str,
        target: str | Sequence[str],
        scan_directory: Path,
        manifest: ScanManifest,
    ) -> tuple[ManifestExecution, tuple[Host, ...], ScanManifest]:
        profile = get_profile(phase)
        artifact_path = scan_directory / profile.artifact_name
        running = ManifestExecution(phase=phase, artifact=profile.artifact_name, status=ExecutionStatus.RUNNING, started_at=datetime.now(timezone.utc))
        manifest = self._replace_execution(manifest, running)
        self._write_manifest(scan_directory, manifest)
        try:
            execution = self.runner.run(profile, target, artifact_path, self.config.scan_timeout)
        except KeyboardInterrupt:
            finished = datetime.now(timezone.utc)
            execution = NmapExecutionResult(phase, artifact_path, (), running.started_at or finished, finished, 0.0, None, ExecutionStatus.INTERRUPTED)
        except NmapError as exc:
            finished = datetime.now(timezone.utc)
            execution = NmapExecutionResult(phase, artifact_path, (), running.started_at or finished, finished, 0.0, None, ExecutionStatus.FAILED, str(exc))
        manifest_execution = self._manifest_execution(execution, profile.artifact_name)
        manifest = self._replace_execution(manifest, manifest_execution)
        if execution.status is not ExecutionStatus.COMPLETED:
            return manifest_execution, (), manifest
        try:
            if execution.artifact_path is None:
                raise NmapXMLFileError(f"phase produced no artifact: {phase}")
            observations = self.parser.parse(execution.artifact_path)
        except (NmapXMLFileError, NmapXMLParseError) as exc:
            manifest_execution = replace(manifest_execution, status=ExecutionStatus.FAILED, stderr_summary=str(exc))
            manifest = self._replace_execution(manifest, manifest_execution)
            return manifest_execution, (), manifest
        return manifest_execution, observations, manifest

    def _persist_hosts(self, scan_id: str, hosts: dict[str, Host], *, update_existing: set[str] | None = None) -> None:
        for ip in sorted(hosts):
            if update_existing is not None and ip in update_existing:
                self.repository.update_host(scan_id, hosts[ip])
            else:
                self.repository.save_host(scan_id, hosts[ip])

    def _enumerate_known_services(
        self,
        scan_id: str,
        hosts: dict[str, Host],
        manifest: ScanManifest,
        scan_directory: Path,
    ) -> list[object]:
        results: list[object] = []
        manifest = self._replace_execution(manifest, ManifestExecution(self._ENUMERATION_PHASE, "enumeration.json", ExecutionStatus.RUNNING))
        self._write_manifest(scan_directory, manifest)
        try:
            for host_ip in sorted(hosts):
                host = hosts[host_ip]
                try:
                    host_id = self.repository.get_host_id(scan_id, host_ip)
                except Exception:
                    continue
                for service in host.services:
                    target = EnumerationTarget(
                        scan_id=scan_id,
                        host_id=host_id,
                        ip=host_ip,
                        port=service.port,
                        protocol=service.protocol,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        extra_info=service.extra_info,
                    )
                    decision = self.enumeration_engine.decide(target)
                    if decision.module is None:
                        continue
                    module = next((item for item in self.enumeration_engine.modules if getattr(item, "name", None) == decision.module), None)
                    if module is None:
                        continue
                    result = module.enumerate(target)
                    if hasattr(self.repository, "save_enumeration_result"):
                        self.repository.save_enumeration_result(result)
                    results.append(result)
            manifest = self._replace_execution(manifest, ManifestExecution(self._ENUMERATION_PHASE, "enumeration.json", ExecutionStatus.COMPLETED))
            self._write_manifest(scan_directory, manifest)
            return results
        except KeyboardInterrupt:
            manifest = self._replace_execution(manifest, ManifestExecution(self._ENUMERATION_PHASE, "enumeration.json", ExecutionStatus.INTERRUPTED))
            self._write_manifest(scan_directory, manifest)
            raise
        except Exception as exc:
            manifest = self._replace_execution(manifest, ManifestExecution(self._ENUMERATION_PHASE, "enumeration.json", ExecutionStatus.FAILED, stderr_summary=str(exc)[:2048]))
            self._write_manifest(scan_directory, manifest)
            return results

    def _initial_manifest(self, scan: Scan) -> ScanManifest:
        return ScanManifest(
            schema_version=1,
            scan_id=scan.id,
            target=scan.target,
            workflow=scan.workflow,
            reconforge_version=scan.reconforge_version,
            nmap_version=scan.nmap_version,
            created_at=scan.started_at,
            updated_at=scan.started_at,
            scan_status=scan.status,
            executions=tuple(ManifestExecution(phase, None, ExecutionStatus.PENDING) for phase in self._PHASES),
        )

    @staticmethod
    def _manifest_execution(execution: NmapExecutionResult, artifact: str) -> ManifestExecution:
        return ManifestExecution(
            phase=execution.phase,
            artifact=artifact,
            status=execution.status,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            duration=execution.duration,
            exit_code=execution.exit_code,
            arguments=execution.arguments,
            stderr_summary=execution.stderr_summary,
        )

    @staticmethod
    def _replace_execution(manifest: ScanManifest, execution: ManifestExecution) -> ScanManifest:
        executions = tuple(execution if item.phase == execution.phase else item for item in manifest.executions)
        return replace(manifest, executions=executions, updated_at=datetime.now(timezone.utc))

    def _skip_remaining(
        self,
        manifest: ScanManifest,
        phase_results: list[ManifestExecution],
        scan_directory: Path,
        start_index: int,
    ) -> tuple[ScanManifest, list[ManifestExecution]]:
        skipped: list[ManifestExecution] = []
        for phase in self._PHASES[start_index:]:
            item = ManifestExecution(phase, None, ExecutionStatus.SKIPPED)
            manifest = self._replace_execution(manifest, item)
            skipped.append(item)
        self._write_manifest(scan_directory, manifest)
        return manifest, skipped

    @staticmethod
    def _merge_hosts(target: dict[str, Host], incoming: Sequence[Host], *, allow_new: bool) -> None:
        for host in sorted(incoming, key=lambda item: item.ip):
            if host.ip not in target:
                if allow_new:
                    target[host.ip] = host
                continue
            target[host.ip] = ReconController._merge_host(target[host.ip], host)

    @staticmethod
    def _merge_host(existing: Host, incoming: Host) -> Host:
        services = {(service.port, service.protocol): service for service in existing.services}
        for service in incoming.services:
            key = (service.port, service.protocol)
            services[key] = ReconController._merge_service(services.get(key), service)
        fingerprints = existing.os_fingerprints + incoming.os_fingerprints
        return replace(
            existing,
            hostname=existing.hostname or incoming.hostname,
            mac_address=existing.mac_address or incoming.mac_address,
            vendor=existing.vendor or incoming.vendor,
            state="up" if existing.state == "up" or incoming.state == "up" else existing.state or incoming.state,
            services=tuple(services[key] for key in sorted(services)),
            os_fingerprints=fingerprints,
        )

    @staticmethod
    def _merge_service(existing: Service | None, incoming: Service) -> Service:
        if existing is None:
            return incoming
        return replace(
            existing,
            service_name=existing.service_name or incoming.service_name,
            product=existing.product or incoming.product,
            version=existing.version or incoming.version,
            extra_info=existing.extra_info or incoming.extra_info,
            state=incoming.state if existing.state == "unknown" else existing.state,
        )

    @staticmethod
    def _write_manifest(scan_directory: Path, manifest: ScanManifest) -> None:
        path = scan_directory / "manifest.json"
        temporary = scan_directory / "manifest.json.tmp"
        payload = {
            "schema_version": manifest.schema_version,
            "scan_id": manifest.scan_id,
            "target": manifest.target,
            "workflow": manifest.workflow,
            "reconforge_version": manifest.reconforge_version,
            "nmap_version": manifest.nmap_version,
            "created_at": manifest.created_at.isoformat(),
            "updated_at": manifest.updated_at.isoformat(),
            "scan_status": manifest.scan_status.value,
            "executions": [
                {
                    "phase": item.phase,
                    "artifact": item.artifact,
                    "status": item.status.value,
                    "started_at": item.started_at.isoformat() if item.started_at else None,
                    "finished_at": item.finished_at.isoformat() if item.finished_at else None,
                    "duration": item.duration,
                    "exit_code": item.exit_code,
                    "arguments": list(item.arguments),
                    "stderr_summary": item.stderr_summary,
                }
                for item in manifest.executions
            ],
        }
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
