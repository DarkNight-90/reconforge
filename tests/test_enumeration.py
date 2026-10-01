from datetime import datetime, timezone
import urllib.request
from urllib.parse import urljoin

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


def mock_http_response(monkeypatch, *, redirect: str | None = None) -> list[str]:
    requested_urls: list[str] = []

    class Response:
        status = 200
        headers = {"Content-Type": "text/html", "Server": "test"}

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        @staticmethod
        def read(size: int) -> bytes:
            return b"<html><title>Mock response</title></html>"

    class Opener:
        def __init__(self, handler) -> None:
            self.redirect_handler = handler

        def open(self, request, timeout: float):
            requested_urls.append(request.full_url)
            if redirect is not None:
                destination = urljoin(request.full_url, redirect)
                followed = self.redirect_handler.redirect_request(
                    request, None, 302, "Found", {}, destination
                )
                requested_urls.append(followed.full_url)
            return Response()

    monkeypatch.setattr(urllib.request, "build_opener", lambda handler: Opener(handler))
    return requested_urls


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


def test_decision_engine_routes_https_to_tls_and_is_deterministic() -> None:
    engine = EnumerationEngine()
    targets = (
        ("http", "nginx", "http"),
        ("https", "nginx", "tls"),
        ("ssh", "OpenSSH", "ssh"),
    )
    for service_name, product, expected_module in targets:
        target = EnumerationTarget(
            scan_id="scan-1",
            host_id=1,
            ip="192.168.1.20",
            port=443 if service_name == "https" else 80,
            protocol="tcp",
            service_name=service_name,
            product=product,
        )
        first = engine.decide(target)
        second = engine.decide(target)
        assert first.module == expected_module
        assert second.module == first.module
        assert second.reason == first.reason


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


def test_http_module_fetches_normal_response_without_network(monkeypatch) -> None:
    requested_urls = mock_http_response(monkeypatch)
    target = EnumerationTarget("scan-1", 1, "127.0.0.1", 8080, service_name="http")
    result = HttpEnumerationModule(timeout=1).enumerate(target)

    assert result.status == EnumerationStatus.SUCCESS
    assert requested_urls == ["http://127.0.0.1:8080/"]
    assert any(item.indicator == "title" and item.value == "Mock response" for item in result.evidence)


def test_http_module_allows_same_host_redirect(monkeypatch) -> None:
    requested_urls = mock_http_response(monkeypatch, redirect="/final")
    target = EnumerationTarget("scan-1", 1, "127.0.0.1", 8080, service_name="http")
    result = HttpEnumerationModule(timeout=1).enumerate(target)

    assert result.status == EnumerationStatus.SUCCESS
    assert requested_urls == ["http://127.0.0.1:8080/", "http://127.0.0.1:8080/final"]


def test_http_module_blocks_cross_host_redirect_without_following_it(monkeypatch) -> None:
    requested_urls = mock_http_response(monkeypatch, redirect="http://127.0.0.2:8080/outside")
    target = EnumerationTarget("scan-1", 1, "127.0.0.1", 8080, service_name="http")
    result = HttpEnumerationModule(timeout=1).enumerate(target)

    assert result.status == EnumerationStatus.FAILED
    assert "outside the authorized target host" in (result.error_message or "")
    assert requested_urls == ["http://127.0.0.1:8080/"]


def test_http_module_preserves_timeout_and_error_statuses() -> None:
    class FailingHTTPClient:
        def __init__(self, error: Exception) -> None:
            self.error = error

        def fetch(self, url: str, timeout: float) -> dict[str, object]:
            raise self.error

    target = EnumerationTarget("scan-1", 1, "127.0.0.1", 80, service_name="http")
    timeout_result = HttpEnumerationModule(
        client=FailingHTTPClient(TimeoutError("request timeout"))
    ).enumerate(target)
    error_result = HttpEnumerationModule(client=FailingHTTPClient(OSError("connection refused"))).enumerate(target)

    assert timeout_result.status == EnumerationStatus.TIMEOUT
    assert error_result.status == EnumerationStatus.FAILED


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
