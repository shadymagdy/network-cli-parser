"""Cisco NSO integration: live-status output unwrapping and the clijson.nso helpers (with fake maagic objects)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import clijson
import clijson.nso

FIX = Path(__file__).parent / "fixtures"
BGP = """BGP router identifier 192.0.2.1, local AS number 65000
BGP generic scan interval 60 secs
BGP table state: Active
Table ID: 0xe0000000   RD version: 12
BGP main routing table version 12
BGP scan interval 60 secs

BGP is operating in STANDALONE mode.

Process       RcvTblVer   bRIB/RIB   LabelVer  ImportVer  SendTblVer  StandbyVer
Speaker              12         12         12         12          12           0

Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
192.0.2.2         0 65001     120     118       12    0    0 01:57:59         5
198.51.100.2      0 65002       0       0        0    0    0 00:00:00 Idle
"""
# what the IOS XR NED returns in `result`: CRLF, the device timestamp and the trailing prompt
RESULT = "\r\nMon Oct  4 10:00:00.123 UTC\r\n" + BGP.replace("\n", "\r\n") + "\r\nRP/0/RP0/CPU0:PE1#"


def _peers(res):
    return [p["neighbor"] for p in res.normalized]


# --------------------------------------------------------------------------- #
# Output collected through NSO
# --------------------------------------------------------------------------- #


def test_python_api_result_string():
    res = clijson.parse(RESULT, "show bgp summary", "iosxr", normalize=True)
    assert res.parser == "iosxr.show_bgp_summary"
    assert _peers(res) == ["192.0.2.2", "198.51.100.2"]


@pytest.mark.parametrize(
    "body",
    [
        {"tailf-ned-cisco-ios-xr-stats:output": {"result": RESULT}},
        {"output": {"result": RESULT}},
        {"result": RESULT},
        {"jsonrpc": "2.0", "id": 1, "result": {"tailf-ned-cisco-ios-xr-stats:output": {"result": RESULT}}},
    ],
    ids=["restconf", "restconf-unprefixed", "bare", "json-rpc"],
)
def test_restconf_and_json_rpc_responses_are_unwrapped(body):
    res = clijson.parse(json.dumps(body), "show bgp summary", "iosxr", normalize=True)
    assert res.engine == "native"
    assert _peers(res) == ["192.0.2.2", "198.51.100.2"]
    assert res.metadata["source"] == "nso-live-status"


def test_ncs_cli_paste_with_echoed_command_needs_no_hints():
    pasted = "result \nshow bgp summary\nMon Oct  4 10:00:00.123 UTC\n" + BGP + "RP/0/RP0/CPU0:PE1#\n"
    res = clijson.parse(pasted, normalize=True)
    assert res.platform == "iosxr"
    assert res.command == "show bgp summary"
    assert res.parser == "iosxr.show_bgp_summary"
    assert res.metadata["source"] == "nso-live-status"


def test_ncs_cli_result_on_the_same_line():
    pasted = "result Mon Oct  4 10:00:00.123 UTC\n" + BGP
    res = clijson.parse(pasted, "show bgp summary", "iosxr", normalize=True)
    assert len(res.normalized) == 2


def test_real_json_output_is_not_mistaken_for_nso():
    junos_json = (Path(__file__).parent / "data" / "junos_terse.json").read_text(encoding="utf-8")
    res = clijson.parse(junos_json, "show interfaces terse | display json", "junos")
    assert "source" not in res.metadata


def test_nso_platform_names_resolve():
    assert clijson.get_platform("cisco-iosxr").name == "iosxr"
    assert clijson.get_platform("huawei-vrp").name == "vrp"
    assert clijson.get_platform("juniper-junos").name == "junos"


# --------------------------------------------------------------------------- #
# clijson.nso helpers against fake maagic objects
# --------------------------------------------------------------------------- #


class FakeAction:
    """Mimics a maagic action: get_input() returns an input node, calling it returns the output node."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def get_input(self):
        return SimpleNamespace(args=None)

    def __call__(self, inp):
        (cmd,) = inp.args
        self.calls.append(cmd)
        if cmd not in self.outputs:
            raise RuntimeError("syntax error: unknown command")
        return SimpleNamespace(result=self.outputs[cmd])


def device(name="pe1", exec_name="cisco_ios_xr_stats__exec", platform="ios-xr", ned=None, outputs=None):
    action = FakeAction(outputs or {})
    live = SimpleNamespace(**{exec_name: SimpleNamespace(any=action)})
    dev = SimpleNamespace(
        name=name,
        live_status=live,
        platform=SimpleNamespace(name=platform),
        device_type=SimpleNamespace(cli=SimpleNamespace(ned_id=ned)),
    )
    return dev, action


def test_show_runs_exec_any_and_parses():
    dev, action = device(outputs={"show bgp summary": RESULT})
    res = clijson.nso.show(dev, "show bgp summary", normalize=True)
    assert action.calls == ["show bgp summary"]
    assert res.platform == "iosxr"
    assert _peers(res) == ["192.0.2.2", "198.51.100.2"]
    assert res.metadata["device"] == "pe1"


def test_platform_from_ned_id_when_platform_name_is_missing():
    dev, _ = device(platform=None, ned="cisco-iosxr-cli-7.61:cisco-iosxr-cli-7.61")
    assert clijson.nso.platform_of(dev) == "iosxr"
    dev, _ = device(platform=None, ned="huawei-vrp-cli-6.48:huawei-vrp-cli-6.48")
    assert clijson.nso.platform_of(dev) == "vrp"
    dev, _ = device(platform=None, ned=None)
    assert clijson.nso.platform_of(dev) is None


def test_exec_action_is_discovered_for_other_neds():
    vsi = (FIX / "vrp" / "display_vsi_protect_group" / "vsi_protect_group.txt").read_text(encoding="utf-8")
    dev, _ = device(
        exec_name="some_vendor_stats__exec", platform="huawei-vrp", outputs={"display vsi protect-group": vsi}
    )
    res = clijson.nso.show(dev, "display vsi protect-group", normalize=True)
    report = clijson.checks.pseudowire_redundancy(res.normalized)
    assert res.platform == "vrp"
    assert report.ok


def test_show_many_and_errors():
    dev, _ = device(outputs={"show bgp summary": RESULT, "show version": "Cisco IOS XR Software, Version 7.11.2"})
    results = clijson.nso.show_many(dev, ["show bgp summary", "show version"])
    assert list(results) == ["show bgp summary", "show version"]
    with pytest.raises(clijson.nso.NsoError, match="live-status exec failed"):
        clijson.nso.show(dev, "show nonsense")
    no_live = SimpleNamespace(name="nc1", live_status=None)
    with pytest.raises(clijson.nso.NsoError, match="no live-status"):
        clijson.nso.exec_any(no_live, "show version")
    no_exec = SimpleNamespace(name="nc2", live_status=SimpleNamespace())
    with pytest.raises(clijson.nso.NsoError, match="exec any"):
        clijson.nso.exec_any(no_exec, "show version")
