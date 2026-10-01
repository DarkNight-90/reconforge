from pathlib import Path

import pytest

from reconforge.config import AppConfig


def test_default_configuration() -> None:
    config = AppConfig()

    assert config.data_directory == Path("data")
    assert config.database_path == Path("data/reconforge.db")
    assert config.scan_timeout == 300.0
    assert config.log_level == "INFO"
    assert config.workflow == "default"


def test_custom_configuration() -> None:
    config = AppConfig(
        data_directory=Path("results"),
        database_path=Path("results/results.db"),
        scan_timeout=15.0,
        log_level="debug",
        workflow="full-recon",
    )

    assert config.data_directory == Path("results")
    assert config.database_path == Path("results/results.db")
    assert config.scan_timeout == 15.0
    assert config.workflow == "full-recon"


def test_configuration_rejects_invalid_timeout() -> None:
    with pytest.raises(ValueError):
        AppConfig(scan_timeout=0)
