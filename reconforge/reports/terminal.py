"""Concise terminal reporting for completed controller results."""

from ..core.models import AttackSurface, AttackSurfaceDiff, EvidenceCoverageReport, Host, ScanResult, Service, SurfaceChange


def render_hosts(scan_id: str, hosts: tuple[Host, ...]) -> None:
    """Print persisted host observations for one scan."""
    print("Hosts")
    print("─────")
    print(f"Scan: {scan_id}")
    if not hosts:
        print("No hosts found.")
        return
    print()
    for host in hosts:
        print(f"Host: {host.ip}")
        if host.hostname:
            print(f"  Hostname: {host.hostname}")
        print(f"  State: {host.state}")
        if host.mac_address:
            print(f"  MAC: {host.mac_address}")
        if host.vendor:
            print(f"  Vendor: {host.vendor}")
        if host.classification is not None:
            print(f"  OS: {host.classification.family.value}")
            print(f"  Confidence: {host.classification.confidence.value}")
        else:
            print("  OS: Unknown")
        print()


def render_services(scan_id: str, services: tuple[tuple[str, Service], ...]) -> None:
    """Print persisted service observations for one scan."""
    print("Services")
    print("────────")
    print(f"Scan: {scan_id}")
    if not services:
        print("No services found.")
        return
    print()
    for host_ip, service in services:
        print(f"Host: {host_ip}")
        print(f"  Port: {service.port}/{service.protocol}")
        print(f"  State: {service.state}")
        if service.service_name:
            print(f"  Service: {service.service_name}")
        if service.product:
            product_version = f" {service.version}" if service.version else ""
            print(f"  Product: {service.product}{product_version}")
        elif service.version:
            print(f"  Version: {service.version}")
        if service.extra_info:
            print(f"  Extra info: {service.extra_info}")
        print()


def render_scan_summary(result: ScanResult) -> None:
    """Print a compact workflow summary without raw Nmap output."""
    print(f"ReconForge scan {result.scan.id}")
    print(f"Target: {result.scan.target}")
    print(f"Status: {result.scan.status.value}")
    print(f"Hosts: {len(result.hosts)}")
    print("Phases:")
    for execution in result.phase_results:
        print(f"  {execution.phase}: {execution.status.value}")


def render_attack_surface(surface: AttackSurface) -> None:
    """Print a compact view of the derived attack surface."""
    technologies = {item.id: item for item in surface.technologies}
    exposures = {item.id: item for item in surface.exposures}
    print("Attack Surface")
    print("──────────────")
    print(f"Scan: {surface.scan_id}")
    print(f"Source status: {surface.source_scan_status.value}")
    print(f"Completeness: {surface.completeness.status.value}")
    if surface.completeness.issues:
        print(f"Issues: {', '.join(surface.completeness.issues)}")
    print()
    for host in surface.hosts:
        print(f"Host: {host.ip}")
        print(f"State: {host.state}")
        if host.classification is not None:
            print(f"OS: {host.classification.family.value} ({host.classification.confidence.value})")
        print("Services:")
        for service in host.services:
            print(f"  {service.port}/{service.protocol}")
            print(f"    State: {service.state}")
            if service.service_name:
                print(f"    Service: {service.service_name}")
            if service.product:
                print(f"    Product: {service.product}")
            if service.version:
                print(f"    Version: {service.version}")
            for technology_id in service.technology_ids:
                technology = technologies.get(technology_id)
                if technology is not None:
                    suffix = f" {technology.version}" if technology.version else ""
                    print(f"    Technology: {technology.name}{suffix}")
            for exposure_id in host.exposure_ids:
                exposure = exposures.get(exposure_id)
                if exposure is not None and exposure.service_id == service.id:
                    print(f"    Exposure: {exposure.kind}")
        print()
    print("Technologies:")
    for technology in surface.technologies:
        suffix = f" {technology.version}" if technology.version else ""
        print(f"  {technology.name}{suffix}")


def render_attack_surface_diff(diff: AttackSurfaceDiff) -> None:
    """Print observable changes without assigning security significance."""
    print("Attack Surface Diff")
    print("───────────────────")
    print(f"Baseline: {diff.baseline_scan_id}")
    print(f"Current:  {diff.current_scan_id}")
    print(f"Completeness: {diff.completeness.status.value}")
    print()
    sections = (
        ("Hosts", diff.host_changes),
        ("Services", diff.service_changes),
        ("Operating Systems", diff.os_changes),
        ("Technologies", diff.technology_changes),
        ("Exposures", diff.exposure_changes),
        ("Relationships", diff.relationship_changes),
        ("Enumeration", diff.enumeration_changes),
        ("Evidence", diff.evidence_changes),
    )
    for title, changes in sections:
        if not changes:
            continue
        print(title)
        for change_type in ("added", "removed", "changed", "unknown"):
            selected = tuple(item for item in changes if item.change_type.value == change_type)
            if not selected:
                continue
            print(f"  {change_type.capitalize()}:")
            for change in selected:
                print(f"    {change.comparison_key}")
                _render_change_values(change)
        print()
    if diff.completeness.issues:
        print("Limitations")
        for issue in diff.completeness.issues:
            print(f"  {issue}")


def render_evidence_coverage(report: EvidenceCoverageReport) -> None:
    """Print collection and evidence coverage without security conclusions."""
    print("Evidence Coverage")
    print("─────────────────")
    print(f"Scan: {report.scan_id}")
    print(f"Overall: {report.overall_status.value}")
    print()
    print("Phases:")
    for phase in report.phase_coverage:
        suffix = f" ({phase.qualification})" if phase.qualification else ""
        print(f"  {phase.phase}: {phase.status.value}{suffix}")
    print()
    print("Hosts:")
    for host in report.host_coverage:
        print(f"  {host.ip}")
        print(f"    OS: {host.os_status.value}")
        print(f"    Services: {host.service_count}")
        print(f"    Service coverage: {host.service_status.value}")
    print()
    print("Services:")
    for service in report.service_coverage:
        enumerations = ", ".join(item.value for item in service.enumeration_statuses)
        print(f"  {service.host_ip}:{service.port}/{service.protocol}")
        print(f"    Observation: {service.observation_status.value}")
        print(f"    Metadata: {service.metadata_status.value}")
        print(f"    Enumeration: {enumerations}")
        for limitation in service.limitations:
            print(f"    Limitation: {limitation}")
    if report.limitations:
        print()
        print("Limitations:")
        for limitation in report.limitations:
            print(f"  {limitation}")


def _render_change_values(change: SurfaceChange) -> None:
    before = {field.name: field.value for field in change.before.fields} if change.before else {}
    after = {field.name: field.value for field in change.after.fields} if change.after else {}
    for field_name in sorted(set(before) | set(after)):
        old = before.get(field_name, "<absent>")
        new = after.get(field_name, "<absent>")
        if old == new:
            continue
        print(f"      {field_name}: {old} -> {new}")
    if change.qualification:
        print(f"      Qualification: {change.qualification}")
