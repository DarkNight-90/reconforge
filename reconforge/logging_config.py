"""Centralized standard-library logging configuration."""

import logging


LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def configure_logging(level: str = "INFO", *, verbose: bool = False) -> None:
    """Configure application logging without logging command secrets."""
    normalized = "DEBUG" if verbose else level.upper()
    if normalized not in LOG_LEVELS:
        raise ValueError(f"unsupported log level: {level}")
    logging.basicConfig(
        level=getattr(logging, normalized),
        format="%(levelname)s %(name)s: %(message)s",
    )
