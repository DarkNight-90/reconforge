from pathlib import Path

import pytest

from reconforge.parsers.nmap_xml import (
    NmapXMLFileError,
    NmapXMLParseError,
    NmapXMLParser,
    parse_nmap_xml,
)


FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_basic_host_and_metadata_parsing() -> None:
    hosts = parse_nmap_xml(FIXTURE)

    assert len(hosts) == 3
    assert [(host.ip, host.state) for host in hosts] == [
        ("192.168.1.10", "up"),
        ("192.168.1.20", "up"),
        ("192.168.1.30", "up"),
    ]
    assert hosts[0].hostname == "example.local"
    assert hosts[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert hosts[0].vendor == "Example Vendor"
    assert hosts[1].hostname is None
    assert hosts[1].mac_address is None
    assert hosts[2].services == ()


def test_service_observations_preserve_protocol_state_and_optional_fields() -> None:
    first, second, _ = NmapXMLParser().parse(FIXTURE)

    assert len(first.services) == 3
    assert first.services[0].port == 22
    assert first.services[0].protocol == "tcp"
    assert first.services[0].state == "open"
    assert first.services[0].service_name == "ssh"
    assert first.services[0].product == "OpenSSH"
    assert first.services[0].version == "9.6"
    assert first.services[0].extra_info == "Ubuntu"
    assert first.services[2].protocol == "udp"
    assert first.services[2].state == "open|filtered"
    assert first.services[2].service_name == "domain"
    assert first.services[2].product is None
    assert second.services[0].state == "filtered"
    assert second.services[0].service_name == "microsoft-ds"
    assert second.services[0].product is None


def test_os_observations_are_preserved_without_classification() -> None:
    hosts = NmapXMLParser().parse(FIXTURE)

    assert hosts[0].classification is None
    assert hosts[0].os_fingerprints[0].vendor == "Linux"
    assert hosts[0].os_fingerprints[0].family == "Linux"
    assert hosts[0].os_fingerprints[0].generation == "5.X"
    assert hosts[0].os_fingerprints[0].accuracy == 95
    assert hosts[0].os_fingerprints[0].source == "nmap"
    assert len(hosts[1].os_fingerprints) == 3
    assert hosts[1].os_fingerprints[0].evidence == ("osmatch:name=Microsoft Windows 10",)
    assert hosts[1].os_fingerprints[2].generation == "3.X"


def test_deterministic_results() -> None:
    assert parse_nmap_xml(FIXTURE) == parse_nmap_xml(FIXTURE)


@pytest.mark.parametrize("path_factory", [lambda tmp_path: tmp_path / "missing.xml", lambda tmp_path: tmp_path])
def test_missing_or_directory_path_is_rejected(path_factory, tmp_path: Path) -> None:
    with pytest.raises(NmapXMLFileError):
        parse_nmap_xml(path_factory(tmp_path))


def test_empty_and_malformed_xml_are_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty.xml"
    empty.write_bytes(b" ")
    malformed = tmp_path / "malformed.xml"
    malformed.write_text("<nmaprun>", encoding="utf-8")

    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml(empty)
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml(malformed)


def test_valid_xml_without_hosts_returns_empty_tuple(tmp_path: Path) -> None:
    artifact = tmp_path / "no_hosts.xml"
    artifact.write_text("<nmaprun><runstats /></nmaprun>", encoding="utf-8")

    assert parse_nmap_xml(artifact) == ()


def test_host_without_ipv4_is_skipped(tmp_path: Path) -> None:
    artifact = tmp_path / "no_ipv4.xml"
    artifact.write_text(
        '<nmaprun><host><status state="up" /><address addr="AA:BB" addrtype="mac" /></host></nmaprun>',
        encoding="utf-8",
    )

    assert parse_nmap_xml(artifact) == ()
