"""Minimal command-line interface for the ReconForge foundation."""

import argparse
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import AppConfig, InvalidCIDRError, UnsupportedInputError, validate_targets
from .core.controller import ControllerDependencyError, ControllerError, ControllerInputError, ManifestValidationError, ReconController
from .core.models import AttackSurface, AttackSurfaceDiff, EvidenceCoverageReport
from .core.repository import RepositoryError
from .logging_config import configure_logging
from .reports.structured import serialize_report, write_report
from .reports.terminal import render_attack_surface, render_attack_surface_diff, render_evidence_coverage, render_hosts, render_services


NOT_IMPLEMENTED_EXIT_CODE = 3


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without executing any reconnaissance logic."""
    parser = argparse.ArgumentParser(prog="reconforge")
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="validate a target scope")
    scan_parser.add_argument("cidr", help="IPv4 network in CIDR notation")
    scan_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    scan_parser.add_argument("--timeout", type=float, help="configure the scan timeout in seconds")
    scans_parser = subparsers.add_parser("scans", help="list available scans")
    scans_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    show_parser = subparsers.add_parser("show", help="show a specific scan")
    show_parser.add_argument("scan_id", help="scan identifier")
    show_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    resume_parser = subparsers.add_parser("resume", help="resume a recoverable scan")
    resume_parser.add_argument("scan_id", help="scan identifier")
    resume_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    attack_surface_parser = subparsers.add_parser("attack-surface", help="show the derived attack surface")
    attack_surface_parser.add_argument("scan_id", help="scan identifier")
    attack_surface_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    attack_surface_parser.add_argument("--format", choices=("terminal", "json"), default="terminal", help="output format")
    attack_surface_parser.add_argument("--output", type=Path, help="write JSON output to a file")
    diff_parser = subparsers.add_parser("diff", help="compare two derived attack surfaces")
    diff_parser.add_argument("baseline_scan_id", help="baseline scan identifier")
    diff_parser.add_argument("current_scan_id", help="current scan identifier")
    diff_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    diff_parser.add_argument("--format", choices=("terminal", "json"), default="terminal", help="output format")
    diff_parser.add_argument("--output", type=Path, help="write JSON output to a file")
    coverage_parser = subparsers.add_parser("coverage", help="show evidence coverage for a scan")
    coverage_parser.add_argument("scan_id", help="scan identifier")
    coverage_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    coverage_parser.add_argument("--format", choices=("terminal", "json"), default="terminal", help="output format")
    coverage_parser.add_argument("--output", type=Path, help="write JSON output to a file")
    hosts_parser = subparsers.add_parser("hosts", help="list hosts discovered in a scan")
    hosts_parser.add_argument("scan_id", help="scan identifier")
    hosts_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    services_parser = subparsers.add_parser("services", help="list services discovered in a scan")
    services_parser.add_argument("scan_id", help="scan identifier")
    services_parser.add_argument("--data-dir", type=Path, help="configure the data directory")
    subparsers.add_parser("version", help="show ReconForge version")
    return parser


def _config_for_command(args: argparse.Namespace) -> AppConfig:
    config = AppConfig()
    config = replace(
        config,
        data_directory=args.data_dir or config.data_directory,
        scan_timeout=getattr(args, "timeout", None) if getattr(args, "timeout", None) is not None else config.scan_timeout,
    )
    if args.data_dir is not None:
        config = replace(config, database_path=args.data_dir / "reconforge.db")
    return config


def _render_scan_table(scans: object) -> str:
    rows: list[str] = [
        f"{'SCAN ID':<12} {'TARGET':<18} {'STATUS':<10} {'STARTED':<20} {'FINISHED':<20} {'WORKFLOW':<10}",
        "-" * 100,
    ]
    for scan in scans:
        started = getattr(scan, "started_at", None)
        finished = getattr(scan, "finished_at", None)
        rows.append(
            f"{getattr(scan, 'id', ''):<12} "
            f"{getattr(scan, 'target', ''):<18} "
            f"{str(getattr(scan, 'status', '')).split('.')[-1] if hasattr(getattr(scan, 'status', ''), 'value') else str(getattr(scan, 'status', '')):<10} "
            f"{started.isoformat() if started else '':<20} "
            f"{finished.isoformat() if finished else '':<20} "
            f"{getattr(scan, 'workflow', ''):<10}"
        )
    return "\n".join(rows)


def _emit_report(report: object, output_format: str, output_path: Path | None) -> None:
    if output_format == "terminal":
        if output_path is not None:
            raise ValueError("--output requires --format json")
        if isinstance(report, AttackSurface):
            render_attack_surface(report)
        elif isinstance(report, AttackSurfaceDiff):
            render_attack_surface_diff(report)
        elif isinstance(report, EvidenceCoverageReport):
            render_evidence_coverage(report)
        else:
            raise TypeError(f"unsupported report model: {type(report).__name__}")
        return
    if output_format != "json":
        raise ValueError(f"unsupported output format: {output_format}")
    if output_path is None:
        print(serialize_report(report))
    else:
        write_report(report, output_path)


def _render_show(scan_summary: dict[str, object]) -> str:
    lines = [
        "Scan",
        "────────────────────────────",
        f"ID: {scan_summary.get('scan_id', 'N/A')}",
        f"Target: {scan_summary.get('target', 'N/A')}",
        f"Status: {scan_summary.get('status', 'N/A')}",
        f"Workflow: {scan_summary.get('workflow', 'N/A')}",
        f"Started: {scan_summary['started_at'].isoformat() if scan_summary.get('started_at') else 'N/A'}",
        f"Finished: {scan_summary['finished_at'].isoformat() if scan_summary.get('finished_at') else 'N/A'}",
        f"Duration: {scan_summary.get('duration', 'N/A')}",
        "",
        "Executions",
        "────────────────────────────",
    ]
    for execution in scan_summary.get("executions", ()):
        phase_name = getattr(execution, "phase", execution[0] if isinstance(execution, tuple) else str(execution))
        status_name = getattr(getattr(execution, "status", None), "value", execution[1] if isinstance(execution, tuple) else "unknown")
        lines.append(f"{phase_name:<12} {status_name}")
    lines.extend(["", "Artifacts", "────────────────────────────"])
    for name, present in scan_summary.get("artifacts", {}).items():
        artifact_name = name if name is not None else "N/A"
        lines.append(f"{artifact_name:<16} {'present' if present else 'missing'}")
    enumeration_status = "not_applicable"
    executions = scan_summary.get("executions", ())
    for execution in executions:
        phase_name = getattr(execution, "phase", execution[0] if isinstance(execution, tuple) else str(execution))
        if phase_name == "enumeration":
            enumeration_status = getattr(getattr(execution, "status", None), "value", str(getattr(execution, "status", "not_applicable")))
            break
    lines.extend(["", "Enumeration", "────────────────────────────", f"Status: {enumeration_status}"])
    lines.extend(["", "Hosts", "────────────────────────────"])
    hosts = scan_summary.get("hosts", ())
    for host in hosts:
        lines.append(host.ip)
        if getattr(host, "classification", None) is not None:
            lines.append(f"  OS: {host.classification.family.value}")
            lines.append(f"  Confidence: {host.classification.confidence.value}")
        if getattr(host, "services", ()):
            lines.append("  Services:")
            for service in host.services:
                lines.append(f"    {service.port}/{service.protocol}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Dispatch a command and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)

    if args.command == "version":
        print(f"ReconForge {__version__}")
        return 0
    if args.command == "scan":
        try:
            validate_targets(args.cidr)
        except (InvalidCIDRError, UnsupportedInputError) as exc:
            parser.error(str(exc))
        config = _config_for_command(args)
        try:
            result = ReconController(config).run(args.cidr)
        except ControllerInputError as exc:
            print(str(exc), file=sys.stderr)
            return 3
        except ControllerDependencyError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except ControllerError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            return 130
        return 0 if result.scan.status.value == "completed" else 130 if result.scan.status.value == "interrupted" else 1

    if args.command == "scans":
        try:
            controller = ReconController(_config_for_command(args))
            scans = controller.list_scans()
            print(_render_scan_table(scans))
            return 0
        except (ControllerError, ManifestValidationError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "hosts":
        try:
            controller = ReconController(_config_for_command(args))
            hosts = controller.list_hosts(args.scan_id)
            render_hosts(args.scan_id, hosts)
            return 0
        except (ControllerError, RepositoryError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "services":
        try:
            controller = ReconController(_config_for_command(args))
            services = controller.list_services(args.scan_id)
            render_services(args.scan_id, services)
            return 0
        except (ControllerError, RepositoryError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "show":
        try:
            if args.scan_id and ":" not in args.scan_id and "." in args.scan_id:
                try:
                    from ipaddress import ip_address
                    ip_address(args.scan_id)
                    print(f"The 'show {args.scan_id}' command is not implemented yet.", file=sys.stderr)
                    return NOT_IMPLEMENTED_EXIT_CODE
                except ValueError:
                    pass
            controller = ReconController(_config_for_command(args))
            summary = controller.show_scan(args.scan_id)
            print(_render_show(summary))
            return 0
        except (ControllerError, ManifestValidationError, RepositoryError, FileNotFoundError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "resume":
        try:
            controller = ReconController(_config_for_command(args))
            result = controller.resume_scan(args.scan_id)
            scan = getattr(result, "scan", None)
            print(_render_show({
                "scan_id": getattr(scan, "id", args.scan_id),
                "target": getattr(scan, "target", "N/A"),
                "status": getattr(scan, "status", "unknown"),
                "started_at": getattr(scan, "started_at", None),
                "finished_at": getattr(scan, "finished_at", None),
                "workflow": getattr(scan, "workflow", "default"),
                "duration": (getattr(scan, "finished_at", None) - getattr(scan, "started_at", None)).total_seconds() if getattr(scan, "finished_at", None) and getattr(scan, "started_at", None) else None,
                "executions": getattr(result, "phase_results", ()),
                "artifacts": {item.artifact: item.artifact is not None for item in getattr(result, "phase_results", ())},
                "hosts": getattr(result, "hosts", ()),
            }))
            return 0 if getattr(scan, "status", None) is None or getattr(scan, "status").value == "completed" else 130 if getattr(scan, "status", None) is not None and getattr(scan, "status").value == "interrupted" else 1
        except ControllerInputError as exc:
            print(str(exc), file=sys.stderr)
            return 3
        except (ControllerError, ManifestValidationError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            return 130

    if args.command == "attack-surface":
        try:
            surface = ReconController(_config_for_command(args)).correlate_scan(args.scan_id)
            _emit_report(surface, args.format, args.output)
            return 0
        except (ControllerError, ManifestValidationError, RepositoryError, FileNotFoundError, OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "diff":
        try:
            diff = ReconController(_config_for_command(args)).diff_scans(args.baseline_scan_id, args.current_scan_id)
            _emit_report(diff, args.format, args.output)
            return 0
        except (ControllerError, ManifestValidationError, RepositoryError, FileNotFoundError, OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.command == "coverage":
        try:
            report = ReconController(_config_for_command(args)).coverage_report(args.scan_id)
            _emit_report(report, args.format, args.output)
            return 0
        except (ControllerError, ManifestValidationError, RepositoryError, FileNotFoundError, OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    print(f"The '{args.command}' command is not implemented yet.", file=sys.stderr)
    return NOT_IMPLEMENTED_EXIT_CODE
