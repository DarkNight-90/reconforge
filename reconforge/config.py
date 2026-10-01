"""Application configuration and input validation."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from collections.abc import Sequence


class InvalidCIDRError(ValueError):
    """Raised when input is not a valid IPv4 network."""


class UnsupportedInputError(ValueError):
    """Raised when input is outside the MVP's supported input types."""


def validate_cidr(value: str) -> IPv4Network:
    """Validate and return an IPv4 network in CIDR notation."""
    if not isinstance(value, str):
        raise UnsupportedInputError("CIDR input must be text")
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise InvalidCIDRError(f"invalid IPv4 CIDR: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise UnsupportedInputError("only IPv4 networks are supported")
    return network


def validate_targets(value: str | Sequence[str]) -> tuple[str, ...]:
    """Validate IPv4 addresses, IPv4 CIDR networks, or a non-empty IP list."""
    if isinstance(value, str):
        if not value.strip():
            raise UnsupportedInputError("target must not be empty")
        try:
            address = ip_address(value)
        except ValueError:
            try:
                network = ip_network(value, strict=True)
            except ValueError as exc:
                raise InvalidCIDRError(f"invalid IPv4 target: {value}") from exc
            if not isinstance(network, IPv4Network):
                raise UnsupportedInputError("only IPv4 targets are supported")
            return (str(network),)
        if not isinstance(address, IPv4Address):
            raise UnsupportedInputError("only IPv4 targets are supported")
        return (str(address),)

    if not value:
        raise UnsupportedInputError("target list must not be empty")
    targets: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise UnsupportedInputError("target list must contain non-empty text")
        try:
            address = ip_address(item)
        except ValueError:
            try:
                network = ip_network(item, strict=True)
            except ValueError as exc:
                raise InvalidCIDRError(f"invalid IPv4 target: {item}") from exc
            if not isinstance(network, IPv4Network):
                raise UnsupportedInputError("only IPv4 targets are supported")
            targets.append(str(network))
            continue
        if not isinstance(address, IPv4Address):
            raise UnsupportedInputError("only IPv4 targets are supported")
        targets.append(str(address))
    return tuple(targets)


@dataclass(frozen=True)
class AppConfig:
    """Runtime settings that can be injected into future components."""

    data_directory: Path = Path("data")
    database_path: Path = Path("data/reconforge.db")
    scan_timeout: float = 300.0
    log_level: str = "INFO"
    workflow: str = "default"

    def __post_init__(self) -> None:
        if self.scan_timeout <= 0:
            raise ValueError("scan_timeout must be positive")
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, or ERROR")
        if not self.workflow.strip():
            raise ValueError("workflow must not be empty")
