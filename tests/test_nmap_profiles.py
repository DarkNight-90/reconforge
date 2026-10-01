import pytest

from reconforge.nmap.profiles import (
    DEFAULT_PROFILES,
    NmapPhase,
    NmapProfile,
    ProfileValidationError,
    RequiredInput,
    get_profile,
)


def test_all_default_profiles_are_present_and_valid() -> None:
    assert set(DEFAULT_PROFILES) == {"discovery", "ports", "services", "os"}
    assert get_profile("discovery").artifact_name == "discovery.xml"
    assert get_profile("ports").artifact_name == "ports.xml"
    assert get_profile("services").artifact_name == "services.xml"
    assert get_profile("os").artifact_name == "os.xml"


def test_default_profile_arguments_are_conservative() -> None:
    assert get_profile("discovery").arguments == ("-sn", "-n")
    assert get_profile("ports").arguments == ("-Pn", "-n", "--open", "-p-")
    assert get_profile("services").arguments == ("-Pn", "-n", "-sV")
    assert get_profile("os").arguments == ("-Pn", "-n", "-O", "--osscan-limit")
    assert all("-A" not in profile.arguments for profile in DEFAULT_PROFILES.values())


def test_profiles_declare_input_boundaries() -> None:
    assert get_profile("discovery").required_input is RequiredInput.TARGET
    assert get_profile("ports").required_input is RequiredInput.HOSTS
    assert get_profile("services").required_input is RequiredInput.HOSTS
    assert get_profile("os").required_input is RequiredInput.HOSTS


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "arguments": ("-n",), "artifact_name": "x.xml"},
        {"name": "bad", "arguments": (), "artifact_name": "x.xml"},
        {"name": "bad", "arguments": ("-n",), "artifact_name": "nested/x.xml"},
        {"name": "bad", "arguments": ("-n",), "artifact_name": "x.txt"},
    ],
)
def test_invalid_profiles_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ProfileValidationError):
        NmapProfile(
            name=kwargs["name"],
            phase=NmapPhase.DISCOVERY,
            arguments=kwargs["arguments"],
            artifact_name=kwargs["artifact_name"],
            required_input=RequiredInput.TARGET,
        )


def test_unsupported_profile_enums_are_rejected() -> None:
    with pytest.raises(ProfileValidationError):
        NmapProfile(
            name="bad-phase",
            phase="unknown",  # type: ignore[arg-type]
            arguments=("-n",),
            artifact_name="bad-phase.xml",
            required_input=RequiredInput.TARGET,
        )
