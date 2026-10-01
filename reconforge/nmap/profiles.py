"""Declarative, conservative Nmap phase profiles."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePath


class ProfileValidationError(ValueError):
	"""Raised when a profile violates the runner contract."""


class NmapPhase(StrEnum):
	DISCOVERY = "discovery"
	PORTS = "ports"
	SERVICES = "services"
	OS = "os"


class RequiredInput(StrEnum):
	TARGET = "target"
	HOSTS = "hosts"


@dataclass(frozen=True)
class NmapProfile:
	"""A declarative description of one Nmap execution phase."""

	name: str
	phase: NmapPhase
	arguments: tuple[str, ...]
	artifact_name: str
	required_input: RequiredInput
	enabled: bool = True
	timeout: float | None = None

	def __post_init__(self) -> None:
		if not self.name.strip():
			raise ProfileValidationError("profile name must not be empty")
		if not isinstance(self.phase, NmapPhase):
			raise ProfileValidationError("phase must be a supported Nmap phase")
		if not isinstance(self.required_input, RequiredInput):
			raise ProfileValidationError("required_input must be supported")
		if not self.arguments or any(not argument.strip() for argument in self.arguments):
			raise ProfileValidationError("profile arguments must not be empty")
		artifact = PurePath(self.artifact_name)
		if (
			not self.artifact_name
			or artifact.name != self.artifact_name
			or artifact.name in {".", ".."}
			or artifact.suffix != ".xml"
		):
			raise ProfileValidationError("artifact_name must be a simple .xml filename")
		if self.timeout is not None and self.timeout <= 0:
			raise ProfileValidationError("profile timeout must be positive")


PHASE_NAMES = tuple(phase.value for phase in NmapPhase)


DEFAULT_PROFILES: dict[str, NmapProfile] = {
	"discovery": NmapProfile(
		name="discovery",
		phase=NmapPhase.DISCOVERY,
		arguments=("-sn", "-n"),
		artifact_name="discovery.xml",
		required_input=RequiredInput.TARGET,
	),
	"ports": NmapProfile(
		name="ports",
		phase=NmapPhase.PORTS,
		arguments=("-Pn", "-n", "--open", "-p-"),
		artifact_name="ports.xml",
		required_input=RequiredInput.HOSTS,
	),
	"services": NmapProfile(
		name="services",
		phase=NmapPhase.SERVICES,
		arguments=("-Pn", "-n", "-sV"),
		artifact_name="services.xml",
		required_input=RequiredInput.HOSTS,
	),
	"os": NmapProfile(
		name="os",
		phase=NmapPhase.OS,
		arguments=("-Pn", "-n", "-O", "--osscan-limit"),
		artifact_name="os.xml",
		required_input=RequiredInput.HOSTS,
	),
}


def get_profile(name: str) -> NmapProfile:
	"""Return a named default profile."""
	try:
		return DEFAULT_PROFILES[name]
	except KeyError as exc:
		raise ProfileValidationError(f"unknown Nmap profile: {name}") from exc
