from datetime import datetime, timezone

from reconforge.core.models import (
    EnumerationDecision,
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    EnumerationTarget,
    Service,
)
from reconforge.core.repository import Repository
from reconforge.enumeration.engine import EnumerationEngine
from reconforge.enumeration.modules import HttpEnumerationModule, SshEnumerationModule


def test_decision_engine_matches_http_and_ssh_without_port_only_assumption() -> None:
    engine = EnumerationEngine()

    http_target = EnumerationTarget(
        scan_id="scan-1",
        host_id=1,
        ip="192.168.1.20",
        port=80,
        protocol="tcp",
        service_name="http",
        product="nginx",
        version="1.24.0",
    )
    http_decision = engine.decide(http_target)
    assert http_decision.module == "http"
    assert http_decision.reason.lower().find("http") >= 0
    assert http_decision.priority == "normal"

    ssh_target = EnumerationTarget(
        scan_id="scan-1",
        host_id=1,
        ip="192.168.1.20",
        port=22,
        protocol="tcp",
        service_name="ssh",
        product="OpenSSH",
        version="9.6",
    )
    ssh_decision = engine.decide(ssh_target)
    assert ssh_decision.module == "ssh"
    assert ssh_decision.reason.lower().find("ssh") >= 0

    smb_target = EnumerationTarget(
        scan_id="scan-1",
        host_id=1,
        ip="192.168.1.20",
        port=445,
        protocol="tcp",
        service_name="microsoft-ds",
        product="Microsoft Windows",
        version="",
    )
    smb_decision = engine.decide(smb_target)
    assert smb_decision.module is None
    assert smb_decision.status == EnumerationStatus.UNSUPPORTED


def test_http_module_collects_structured_evidence() -> None:
    class FakeHTTPClient:
        def fetch(self, url: str, timeout: float) -> dict[str, object]:
            return {
                "url": url,
                "status_code": 200,
                "headers": {"server": "nginx/1.24.0", "content-type": "text/html; charset=utf-8"},
                "title": "Portal",
            }

    module = HttpEnumerationModule(client=FakeHTTPClient())
    target = EnumerationTarget(
        scan_id="scan-1",
        host_id=1,
        ip="192.168.1.20",
        port=80,
        protocol="tcp",
        service_name="http",
        product="nginx",
        version="1.24.0",
    )

    result = module.enumerate(target)

    assert result.status == EnumerationStatus.SUCCESS
    assert result.module == "http"
    assert any(item.indicator == "server" and item.value == "nginx/1.24.0" for item in result.evidence)
    assert any(item.indicator == "title" and item.value == "Portal" for item in result.evidence)


def test_ssh_module_parses_banner_and_keeps_output_bounded() -> None:
    class FakeSSHClient:
        def connect(self, host: str, port: int, timeout: float):
            return "SSH-2.0-OpenSSH_9.6p1 Debian-3"

    module = SshEnumerationModule(client=FakeSSHClient())
    target = EnumerationTarget(
        scan_id="scan-1",
        host_id=1,
        ip="192.168.1.20",
        port=22,
        protocol="tcp",
        service_name="ssh",
        product="OpenSSH",
        version="9.6",
    )

    result = module.enumerate(target)

    assert result.status == EnumerationStatus.SUCCESS
    assert result.module == "ssh"
    assert any(item.indicator == "implementation" and item.value == "OpenSSH" for item in result.evidence)
    assert any(item.indicator == "protocol" and item.value == "SSH-2.0" for item in result.evidence)


def test_repository_round_trip_for_enumeration_result_and_evidence(tmp_path) -> None:
    repository = Repository(tmp_path / "enumeration.sqlite")
    scan_id = "scan-123"
    repository.create_scan(
        __import__("reconforge.core.models", fromlist=["Scan"]).Scan(
            id=scan_id,
            target="10.0.0.0/24",
            started_at=datetime.now(timezone.utc),
            reconforge_version="0.1.0",
            workflow="default",
        )
    )
    host_id = repository.save_host(
        scan_id,
        __import__("reconforge.core.models", fromlist=["Host"]).Host(
            "10.0.0.5",
            services=(
                __import__("reconforge.core.models", fromlist=["Service"]).Service(
                    80, "tcp", "open", "http", "nginx", "1.24.0"
                ),
            ),
        ),
    )
    must = datetime.now(timezone.utc)

    result = EnumerationResult(
        id=1,
        scan_id=scan_id,
        host_id=host_id,
        ip="10.0.0.5",
        port=80,
        protocol="tcp",
        module="http",
        status=EnumerationStatus.SUCCESS,
        started_at=must,
        finished_at=must,
        duration=0.1,
        error_message=None,
        evidence=(
            EnumerationEvidence(
                source="http_headers",
                category="technology",
                indicator="server",
                value="nginx/1.24.0",
                confidence="medium",
                details="Server header",
            ),
        ),
    )

    repository.save_enumeration_result(result)
    loaded = repository.get_enumeration_results(scan_id)
    assert len(loaded) == 1
    assert loaded[0].module == "http"
    assert loaded[0].evidence[0].indicator == "server"
