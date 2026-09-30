import json
from pathlib import Path

import pytest

import clijson
from clijson.cli import main

DATA = Path(__file__).parent / "data"


def test_diff_matches_records_by_natural_key():
    before = clijson.parse((DATA / "xr_bgp_pre.txt").read_text(), normalize=True)
    after = clijson.parse((DATA / "xr_bgp_post.txt").read_text(), normalize=True)
    changes = clijson.diff(before, after)
    summary = {(c.path, c.kind) for c in changes}
    assert ("[neighbor=10.255.0.2].state", "changed") in summary
    assert ("[neighbor=10.255.0.4]", "removed") in summary
    assert ("[neighbor=10.255.0.5]", "added") in summary
    # reordering and counters/timers are not changes
    assert not any("10.255.0.3" in c.path for c in changes)
    assert not any("uptime" in c.path for c in changes)
    assert str(changes[0]).startswith("~ [neighbor=10.255.0.2]")


def test_diff_can_include_volatile_fields_and_plain_data():
    a = {"peers": [{"neighbor": "1.1.1.1", "uptime": "1d"}]}
    b = {"peers": [{"neighbor": "1.1.1.1", "uptime": "2d"}]}
    assert clijson.diff(a, b) == []
    assert [c.path for c in clijson.diff(a, b, ignore=None)] == ["peers[neighbor=1.1.1.1].uptime"]


def test_cli_diff(capsys):
    assert main(["diff", str(DATA / "xr_bgp_pre.txt"), str(DATA / "xr_bgp_post.txt"), "-f", "json-compact"]) == 1
    kinds = sorted(c["kind"] for c in json.loads(capsys.readouterr().out))
    assert kinds.count("added") == 1 and kinds.count("removed") == 1
    assert main(["diff", str(DATA / "xr_bgp_pre.txt"), str(DATA / "xr_bgp_pre.txt")]) == 0
    assert "no differences" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("text", "platform"),
    [
        ("RP/0/RP0/CPU0:r1#show bgp sumary\n                ^\n% Invalid input detected at '^' marker.\n", "iosxr"),
        ("lab@mx1> show bgp summry\n              ^\nsyntax error, expecting <command>.\n", "junos"),
        ("<NE40E>display bgp peerr\n              ^\nError: Unrecognized command found at '^' position.\n", "vrp"),
    ],
)
def test_device_errors_are_reported(text, platform):
    res = clijson.parse(text)
    assert res.engine == "device-error"
    assert res.platform == platform
    assert res.data is None and not res.ok
    assert res.metadata["device_error"]
    assert "device returned an error" in res.warnings[0]


def test_bytes_input_and_records():
    res = clijson.parse(b"Loopback0  10.0.0.1  Up  Up  default\n", "show ipv4 interface brief", "xr")
    assert res.records() == [
        {"interface": "Loopback0", "ip_address": "10.0.0.1", "status": "Up", "protocol": "Up", "vrf": "default"}
    ]


def test_records_flattens_dict_of_dicts():
    bundle = clijson.parse(
        "Bundle-Ether1\n  Status:  Up\n  Local links <active/standby/configured>:   2 / 0 / 2\n", "show bundle", "iosxr"
    )
    rows = bundle.records()
    assert rows == [
        {"name": "Bundle-Ether1", "status": "Up", "links.active": 2, "links.standby": 0, "links.configured": 2}
    ]
