"""Safe subprocess boundary for one Nmap phase."""

from collections.abc import Sequence
from datetime import datetime, timezone
import logging
from pathlib import Path
import shutil
import subprocess
import time

from ..config import InvalidCIDRError, UnsupportedInputError, validate_targets
from ..core.models import ExecutionStatus, NmapExecutionResult
from .profiles import NmapProfile


class NmapError(RuntimeError):
    """Base class for controlled Nmap runner errors."""


class NmapNotFoundError(NmapError):
    """Raised when the configured Nmap executable is unavailable."""


class NmapInputError(NmapError):
    """Raised when runner input cannot be safely executed."""


class NmapExecutionError(NmapError):
    """Raised when Nmap cannot be started."""


MAX_STDERR_SUMMARY = 2048
_SENSITIVE_FLAGS = {"--password", "--pass", "--token", "--credential", "--secret"}


def sanitize_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    """Redact values following common sensitive command flags."""
    sanitized: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue
        if any(argument.startswith(f"{flag}=") for flag in _SENSITIVE_FLAGS):
            sanitized.append(argument.split("=", 1)[0] + "=<redacted>")
        else:
            sanitized.append(argument)
            if argument in _SENSITIVE_FLAGS:
                redact_next = True
    return tuple(sanitized)


def _stderr_summary(stderr: bytes | str | None) -> str | None:
    if stderr is None:
        return None
    text = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr
    text = text.strip()
    if not text:
        return None
    return text[:MAX_STDERR_SUMMARY]


class NmapRunner:
    """Execute one validated Nmap profile and return typed metadata."""

    def __init__(self, executable: str = "nmap", default_timeout: float = 300.0) -> None:
        if not executable.strip():
            raise ValueError("Nmap executable must not be empty")
        if default_timeout <= 0:
            raise ValueError("default_timeout must be positive")
        self.executable = executable
        self.default_timeout = default_timeout
        self.logger = logging.getLogger(__name__)

    def check_available(self) -> str:
        """Return the executable path or raise a controlled availability error."""
        executable = shutil.which(self.executable)
        if executable is None:
            raise NmapNotFoundError(f"Nmap executable not found: {self.executable}")
        return executable

    def build_command(
        self,
        profile: NmapProfile,
        target: str | Sequence[str],
        artifact_path: Path,
    ) -> tuple[str, ...]:
        """Build a shell-free Nmap argument vector."""
        if artifact_path.name != profile.artifact_name:
            raise NmapInputError(
                f"artifact filename must be {profile.artifact_name}, got {artifact_path.name}"
            )
        try:
            targets = validate_targets(target)
        except (InvalidCIDRError, UnsupportedInputError) as exc:
            raise NmapInputError(str(exc)) from exc
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        return (
            self.executable,
            *profile.arguments,
            "-oX",
            str(artifact_path),
            *targets,
        )

    def run(
        self,
        profile: NmapProfile,
        target: str | Sequence[str],
        artifact_path: Path,
        timeout: float | None = None,
    ) -> NmapExecutionResult:
        """Execute one profile without shell interpretation or XML parsing."""
        if not profile.enabled:
            raise NmapInputError(f"profile is disabled: {profile.name}")
        command = self.build_command(profile, target, artifact_path)
        execution_timeout = timeout if timeout is not None else profile.timeout or self.default_timeout
        if execution_timeout <= 0:
            raise NmapInputError("timeout must be positive")
        self.check_available()
        started_at = datetime.now(timezone.utc)
        started_clock = time.monotonic()
        sanitized_command = sanitize_arguments(command)
        self.logger.info("Starting Nmap phase: %s", profile.phase.value)
        self.logger.info("Nmap executable: %s", self.executable)
        self.logger.info("Target: %s", ",".join(validate_targets(target)))
        self.logger.info("Artifact: %s", artifact_path)
        try:
            completed = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                timeout=execution_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            finished_at = datetime.now(timezone.utc)
            return self._result(
                profile,
                artifact_path,
                sanitized_command,
                started_at,
                finished_at,
                started_clock,
                None,
                ExecutionStatus.TIMEOUT,
                _stderr_summary(exc.stderr),
            )
        except KeyboardInterrupt:
            finished_at = datetime.now(timezone.utc)
            result = self._result(
                profile,
                artifact_path,
                sanitized_command,
                started_at,
                finished_at,
                started_clock,
                None,
                ExecutionStatus.INTERRUPTED,
                None,
            )
            self.logger.warning("Nmap phase interrupted: %s", profile.phase.value)
            return result
        except OSError as exc:
            raise NmapExecutionError(f"failed to start Nmap: {exc}") from exc

        finished_at = datetime.now(timezone.utc)
        status = ExecutionStatus.COMPLETED if completed.returncode == 0 else ExecutionStatus.FAILED
        result = self._result(
            profile,
            artifact_path,
            sanitized_command,
            started_at,
            finished_at,
            started_clock,
            completed.returncode,
            status,
            _stderr_summary(completed.stderr),
        )
        self.logger.info("Execution completed: phase=%s exit_code=%s duration=%.3f", profile.phase.value, result.exit_code, result.duration or 0.0)
        return result

    @staticmethod
    def _result(
        profile: NmapProfile,
        artifact_path: Path,
        arguments: tuple[str, ...],
        started_at: datetime,
        finished_at: datetime,
        started_clock: float,
        exit_code: int | None,
        status: ExecutionStatus,
        stderr_summary: str | None,
    ) -> NmapExecutionResult:
        return NmapExecutionResult(
            phase=profile.phase.value,
            artifact_path=artifact_path,
            arguments=arguments,
            started_at=started_at,
            finished_at=finished_at,
            duration=max(0.0, time.monotonic() - started_clock),
            exit_code=exit_code,
            status=status,
            stderr_summary=stderr_summary,
        )
