import pytest

from clijson import UnknownPlatformError, detect_platform, get_platform
from clijson.platforms import match_prompt


@pytest.mark.parametrize(
    ("alias", "name"),
    [
        ("xr", "iosxr"),
        ("Cisco_XR", "iosxr"),
        ("juniper", "junos"),
        ("crpd", "junos"),
        ("huawei", "vrp"),
        ("ne40e", "vrp"),
        ("vrpv8", "vrp"),
    ],
)
def test_aliases(alias, name):
    assert get_platform(alias).name == name


def test_unknown_platform():
    with pytest.raises(UnknownPlatformError) as exc:
        get_platform("nxos-nope")
    assert "Known platforms" in str(exc.value)


@pytest.mark.parametrize(
    ("line", "platform", "cmd"),
    [
        ("RP/0/RSP0/CPU0:PE1#show version", "iosxr", "show version"),
        ("RP/0/RP0/CPU0:ncs-5501(config)#show run", "iosxr", "show run"),
        ("lab@mx960-re0> show bgp summary", "junos", "show bgp summary"),
        ("{master:0}", None, None),
        ("<HUAWEI>display version", "vrp", "display version"),
        ("[~NE40E-GigabitEthernet0/0/1]display this", "vrp", "display this"),
        ("[edit]", None, None),
    ],
)
def test_prompts(line, platform, cmd):
    hit = match_prompt(line)
    if platform is None:
        assert hit is None
    else:
        assert hit[0].name == platform
        assert hit[1].group("cmd") == cmd


def test_detect_by_command_verb():
    assert detect_platform("", "display interface brief").platform.name == "vrp"


def test_detect_by_fingerprints():
    assert detect_platform("Cisco IOS XR Software, Version 7.9.2").platform.name == "iosxr"
    assert detect_platform("Physical interface: ge-0/0/0, Enabled, Physical link is Up").platform.name == "junos"
    assert (
        detect_platform("Huawei Versatile Routing Platform Software\nVRP (R) software, Version 8.180").platform.name
        == "vrp"
    )


def test_detect_ambiguous():
    det = detect_platform("hello world")
    assert det.platform is None and not det
