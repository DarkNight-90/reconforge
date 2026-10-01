import pytest

from reconforge.config import InvalidCIDRError, UnsupportedInputError, validate_cidr, validate_targets


def test_valid_ipv4_cidr() -> None:
    assert str(validate_cidr("192.168.1.0/24")) == "192.168.1.0/24"


def test_invalid_cidr() -> None:
    with pytest.raises(InvalidCIDRError):
        validate_cidr("192.168.1.1/24")


def test_invalid_ip() -> None:
    with pytest.raises(InvalidCIDRError):
        validate_cidr("192.168.999.0/24")


def test_unsupported_ipv6_input() -> None:
    with pytest.raises(UnsupportedInputError):
        validate_cidr("2001:db8::/32")


def test_unsupported_non_text_input() -> None:
    with pytest.raises(UnsupportedInputError):
        validate_cidr(123)  # type: ignore[arg-type]


def test_runner_target_validation_supports_address_network_and_ip_list() -> None:
    assert validate_targets("192.168.1.10") == ("192.168.1.10",)
    assert validate_targets("192.168.1.0/24") == ("192.168.1.0/24",)
    assert validate_targets(("127.0.0.1/32",)) == ("127.0.0.1/32",)
    assert validate_targets(("192.168.1.1/32", "192.168.1.0/24")) == (
        "192.168.1.1/32",
        "192.168.1.0/24",
    )
    assert validate_targets(["192.168.1.10", "192.168.1.11"]) == (
        "192.168.1.10",
        "192.168.1.11",
    )


@pytest.mark.parametrize("target", ["127.0.0.1/32", "192.168.1.1/32", "192.168.1.0/24"])
def test_valid_ipv4_targets_pass_all_target_validation_paths(target: str) -> None:
    assert validate_targets(target) == (target,)
    assert validate_targets((target,)) == (target,)


def test_invalid_sequence_target_is_rejected() -> None:
    with pytest.raises(InvalidCIDRError):
        validate_targets(("192.168.1.1/24",))
