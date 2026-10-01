"""Safe, protocol-scoped enumeration modules for supported services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any
import urllib.request
from urllib.parse import urlsplit

from ..core.models import (
    EnumerationEvidence,
    EnumerationResult,
    EnumerationStatus,
    EnumerationTarget,
)


def _normalize(value: str | None) -> str:
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def _matches(value: str | None, *candidates: str) -> bool:
    normalized = _normalize(value)
    return any(normalized == candidate or normalized.startswith(f"{candidate} ") for candidate in candidates)


class _BaseProtocolClient:
    def fetch(self, url: str, timeout: float) -> dict[str, Any]:
        raise NotImplementedError


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow HTTP redirects only when they stay on the requested host."""

    def __init__(self, allowed_host: str | None) -> None:
        super().__init__()
        self.allowed_host = allowed_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl).hostname
        if _normalized_redirect_host(destination) != _normalized_redirect_host(self.allowed_host):
            raise ValueError("HTTP redirect destination is outside the authorized target host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class _HttpResponse:
    status_code: int
    headers: dict[str, str]
    title: str | None = None


class _HttpClient(_BaseProtocolClient):
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def fetch(self, url: str, timeout: float) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": "ReconForge/0.1"})
        target_host = urlsplit(url).hostname
        opener = urllib.request.build_opener(_SameHostRedirectHandler(target_host))
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(2048)
            page = payload.decode("utf-8", errors="replace")
            title_match = re.search(r"<title>(.*?)</title>", page, flags=re.I | re.S)
            return {
                "url": url,
                "status_code": getattr(response, "status", 200),
                "headers": dict(response.headers.items()),
                "title": title_match.group(1).strip() if title_match else None,
            }


def _normalized_redirect_host(host: str | None) -> str | None:
    if host is None:
        return None
    normalized = host.rstrip(".").casefold()
    try:
        return str(ip_address(normalized))
    except ValueError:
        return normalized


class HttpEnumerationModule:
    """Collect bounded metadata from HTTP and HTTPS endpoints."""

    name = "http"
    priority = "normal"

    def __init__(self, client: Any | None = None, timeout: float = 5.0) -> None:
        self.client = client or _HttpClient(timeout=timeout)
        self.timeout = timeout

    def supports(self, target: EnumerationTarget) -> bool:
        service_name = _normalize(target.service_name)
        product = _normalize(target.product)
        if service_name.startswith("https") or product.startswith("https"):
            return False
        if service_name.startswith("http") or product.startswith("http"):
            return True
        if "http" in service_name or "http" in product:
            return True
        if target.port in {80, 443, 8080, 8443} and _matches(target.service_name, "http", "https"):
            return True
        return False

    def enumerate(self, target: EnumerationTarget) -> EnumerationResult:
        started_at = datetime.now(timezone.utc)
        try:
            url = f"http://{target.ip}:{target.port}/"
            payload = self.client.fetch(url, timeout=self.timeout)
            status = payload.get("status_code", 200)
            headers = payload.get("headers", {})
            evidence = (
                EnumerationEvidence(
                    source="http_headers",
                    category="technology",
                    indicator="status",
                    value=str(status),
                    confidence="medium",
                    details="HTTP status code",
                ),
                EnumerationEvidence(
                    source="http_headers",
                    category="technology",
                    indicator="server",
                    value=str(headers.get("Server") or headers.get("server") or "unknown").strip()[:256],
                    confidence="medium",
                    details="Server header",
                ),
                EnumerationEvidence(
                    source="http_headers",
                    category="technology",
                    indicator="content_type",
                    value=str(headers.get("Content-Type") or headers.get("content-type") or "unknown").strip()[:256],
                    confidence="medium",
                    details="Content-Type header",
                ),
                EnumerationEvidence(
                    source="http_headers",
                    category="technology",
                    indicator="title",
                    value=str(payload.get("title") or "unknown").strip()[:256],
                    confidence="medium",
                    details="Page title",
                ),
            )
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.SUCCESS,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                duration=0.0,
                evidence=evidence,
            )
        except Exception as exc:  # pragma: no cover - safe failure boundary
            finished = datetime.now(timezone.utc)
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.TIMEOUT if "timeout" in str(exc).lower() else EnumerationStatus.FAILED,
                started_at=started_at,
                finished_at=finished,
                duration=0.0,
                error_message=str(exc)[:1024],
            )


class TlsEnumerationModule:
    """Collect safe TLS metadata for HTTPS-style services."""

    name = "tls"
    priority = "normal"

    def __init__(self, client: Any | None = None, timeout: float = 5.0) -> None:
        self.client = client or _TlsClient(timeout)
        self.timeout = timeout

    def supports(self, target: EnumerationTarget) -> bool:
        service_name = _normalize(target.service_name)
        product = _normalize(target.product)
        return any(marker in service_name or marker in product for marker in ("https", "tls", "ssl"))

    def enumerate(self, target: EnumerationTarget) -> EnumerationResult:
        started_at = datetime.now(timezone.utc)
        try:
            metadata = self.client.collect(target.ip, target.port, timeout=self.timeout)
            evidence = (
                EnumerationEvidence("tls_certificate", "certificate", "subject", metadata.get("subject", "unknown"), "high", "Certificate subject"),
                EnumerationEvidence("tls_certificate", "certificate", "issuer", metadata.get("issuer", "unknown"), "high", "Certificate issuer"),
                EnumerationEvidence("tls_certificate", "certificate", "protocol", metadata.get("protocol", "unknown"), "high", "Negotiated TLS protocol"),
                EnumerationEvidence("tls_certificate", "certificate", "san", ", ".join(metadata.get("sans", [])[:8]) if metadata.get("sans") else "unknown", "medium", "SANs"),
            )
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.SUCCESS,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                duration=0.0,
                evidence=evidence,
            )
        except Exception as exc:  # pragma: no cover - safety boundary
            finished = datetime.now(timezone.utc)
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.FAILED,
                started_at=started_at,
                finished_at=finished,
                duration=0.0,
                error_message=str(exc)[:1024],
            )


class _TlsClient:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def collect(self, host: str, port: int, timeout: float | None = None) -> dict[str, Any]:
        import ssl
        import socket

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout or self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                san = cert.get("subjectAltName", []) if cert else []
                names = [value for key, value in san if key == "DNS"]
                return {
                    "subject": cert.get("subject", ())[0][0][0] if cert else "unknown",
                    "issuer": cert.get("issuer", ())[0][0][0] if cert else "unknown",
                    "protocol": wrapped.version(),
                    "sans": names,
                }


class SshEnumerationModule:
    """Collect safe SSH banner metadata without authentication."""

    name = "ssh"
    priority = "normal"

    def __init__(self, client: Any | None = None, timeout: float = 5.0) -> None:
        self.client = client or _SshClient(timeout)
        self.timeout = timeout

    def supports(self, target: EnumerationTarget) -> bool:
        service_name = _normalize(target.service_name)
        product = _normalize(target.product)
        if service_name.startswith("ssh") or product.startswith("ssh"):
            return True
        return "openssh" in service_name or "openssh" in product

    def enumerate(self, target: EnumerationTarget) -> EnumerationResult:
        started_at = datetime.now(timezone.utc)
        try:
            banner = self.client.connect(target.ip, target.port, timeout=self.timeout)
            implementation = "unknown"
            protocol = "unknown"
            if banner:
                if banner.startswith("SSH-"):
                    match = re.search(r"SSH-(\d+\.\d+)", banner)
                    protocol = f"SSH-{match.group(1)}" if match else "unknown"
                    implementation = "OpenSSH" if "openssh" in banner.lower() else "unknown"
            evidence = (
                EnumerationEvidence("ssh_banner", "service", "implementation", implementation, "high", "SSH implementation"),
                EnumerationEvidence("ssh_banner", "service", "protocol", protocol, "high", "SSH protocol"),
                EnumerationEvidence("ssh_banner", "service", "banner", banner[:256], "medium", "SSH banner"),
            )
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.SUCCESS,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                duration=0.0,
                evidence=evidence,
            )
        except Exception as exc:  # pragma: no cover - safety boundary
            finished = datetime.now(timezone.utc)
            return EnumerationResult(
                scan_id=target.scan_id,
                host_id=target.host_id,
                ip=target.ip,
                port=target.port,
                protocol=target.protocol,
                module=self.name,
                status=EnumerationStatus.TIMEOUT if "timeout" in str(exc).lower() else EnumerationStatus.FAILED,
                started_at=started_at,
                finished_at=finished,
                duration=0.0,
                error_message=str(exc)[:1024],
            )


class _SshClient:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def connect(self, host: str, port: int, timeout: float | None = None) -> str:
        import socket

        with socket.create_connection((host, port), timeout=timeout or self.timeout) as sock:
            sock.settimeout(timeout or self.timeout)
            banner = sock.recv(4096)
            return banner.decode("utf-8", errors="replace").strip()
