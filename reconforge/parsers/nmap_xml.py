"""Parser for existing Nmap XML artifacts."""

from collections.abc import Iterable
from pathlib import Path
import xml.etree.ElementTree as ET

from ..core.models import Host, OSFingerprint, Service


class NmapXMLFileError(ValueError):
    """Raised when an Nmap XML artifact cannot be read as a regular file."""


class NmapXMLParseError(ValueError):
    """Raised when an Nmap XML artifact is malformed or structurally invalid."""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> Iterable[ET.Element]:
    return (child for child in element if _local_name(child.tag) == name)


def _first_child(element: ET.Element, name: str) -> ET.Element | None:
    return next(iter(_children(element, name)), None)


def _optional_int(value: str | None, field_name: str) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise NmapXMLParseError(f"invalid integer for {field_name}: {value}") from exc


def _parse_service(port: ET.Element) -> Service:
    port_id = port.attrib.get("portid")
    protocol = port.attrib.get("protocol")
    if port_id is None or protocol is None or not protocol.strip():
        raise NmapXMLParseError("port is missing portid or protocol")
    try:
        port_number = int(port_id)
    except ValueError as exc:
        raise NmapXMLParseError(f"invalid port number: {port_id}") from exc

    state_element = _first_child(port, "state")
    service_element = _first_child(port, "service")
    return Service(
        port=port_number,
        protocol=protocol,
        state=state_element.attrib.get("state", "unknown") if state_element is not None else "unknown",
        service_name=service_element.attrib.get("name") if service_element is not None else None,
        product=service_element.attrib.get("product") if service_element is not None else None,
        version=service_element.attrib.get("version") if service_element is not None else None,
        extra_info=service_element.attrib.get("extrainfo") if service_element is not None else None,
    )


def _parse_os_fingerprints(host: ET.Element) -> tuple[OSFingerprint, ...]:
    os_element = _first_child(host, "os")
    if os_element is None:
        return ()

    fingerprints: list[OSFingerprint] = []
    for os_match in _children(os_element, "osmatch"):
        match_name = os_match.attrib.get("name")
        match_accuracy = _optional_int(os_match.attrib.get("accuracy"), "osmatch accuracy")
        os_classes = tuple(_children(os_match, "osclass"))
        if not os_classes:
            fingerprints.append(
                OSFingerprint(
                    accuracy=match_accuracy,
                    source="nmap",
                    evidence=(f"osmatch:name={match_name}" if match_name else "osmatch",),
                )
            )
            continue
        for os_class in os_classes:
            class_accuracy = _optional_int(os_class.attrib.get("accuracy"), "osclass accuracy")
            evidence = [f"osmatch:name={match_name}" if match_name else "osmatch"]
            if os_class.attrib.get("type"):
                evidence.append(f"osclass:type={os_class.attrib['type']}")
            fingerprints.append(
                OSFingerprint(
                    vendor=os_class.attrib.get("vendor"),
                    family=os_class.attrib.get("osfamily"),
                    generation=os_class.attrib.get("osgen"),
                    accuracy=class_accuracy if class_accuracy is not None else match_accuracy,
                    source="nmap",
                    evidence=tuple(evidence),
                )
            )
    return tuple(fingerprints)


def _parse_host(host: ET.Element) -> Host | None:
    addresses = tuple(_children(host, "address"))
    ipv4 = next((address.attrib.get("addr") for address in addresses if address.attrib.get("addrtype") == "ipv4"), None)
    if not ipv4:
        return None

    status = _first_child(host, "status")
    hostnames = _first_child(host, "hostnames")
    hostname = None
    if hostnames is not None:
        hostname = next(
            (item.attrib.get("name") for item in _children(hostnames, "hostname") if item.attrib.get("name")),
            None,
        )

    mac = next((address for address in addresses if address.attrib.get("addrtype") == "mac"), None)
    ports_element = _first_child(host, "ports")
    services = () if ports_element is None else tuple(
        _parse_service(port) for port in _children(ports_element, "port")
    )
    return Host(
        ip=ipv4,
        hostname=hostname,
        mac_address=mac.attrib.get("addr") if mac is not None else None,
        vendor=mac.attrib.get("vendor") if mac is not None else None,
        state=status.attrib.get("state", "unknown") if status is not None else "unknown",
        services=services,
        os_fingerprints=_parse_os_fingerprints(host),
    )


class NmapXMLParser:
    """Parse one existing Nmap XML file into observed host models."""

    def parse(self, path: str | Path) -> tuple[Host, ...]:
        """Read and parse one artifact without modifying it or performing I/O beyond reading."""
        artifact = Path(path)
        if not artifact.exists():
            raise NmapXMLFileError(f"Nmap XML file does not exist: {artifact}")
        if not artifact.is_file():
            raise NmapXMLFileError(f"Nmap XML path is not a regular file: {artifact}")
        try:
            payload = artifact.read_bytes()
        except OSError as exc:
            raise NmapXMLFileError(f"unable to read Nmap XML file: {artifact}") from exc
        if not payload.strip():
            raise NmapXMLParseError(f"Nmap XML file is empty: {artifact}")
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise NmapXMLParseError(f"malformed Nmap XML: {artifact}") from exc
        if _local_name(root.tag) != "nmaprun":
            raise NmapXMLParseError("Nmap XML root element must be nmaprun")
        return tuple(host for host_element in _children(root, "host") if (host := _parse_host(host_element)) is not None)


def parse_nmap_xml(path: str | Path) -> tuple[Host, ...]:
    """Parse one Nmap XML artifact using the default parser."""
    return NmapXMLParser().parse(path)
