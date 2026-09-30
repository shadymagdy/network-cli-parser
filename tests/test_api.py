from pathlib import Path

import pytest

import clijson
from clijson import ParseError, Parser, ParserNotFound, register
from clijson.api import split_session

DATA = Path(__file__).parent / "data"

XR_BRIEF = """RP/0/RSP0/CPU0:PE1#show ip int brief
Wed Mar 14 12:31:28.607 UTC

Interface                      IP-Address      Status          Protocol Vrf-Name
Loopback0                      10.255.0.1      Up              Up       default
TenGigE0/0/0/0                 unassigned      Shutdown        Down     default
RP/0/RSP0/CPU0:PE1#"""


def test_prompt_command_and_timestamp_are_extracted():
    res = clijson.parse(XR_BRIEF)
    assert res.platform == "iosxr"
    assert res.command == "show ip int brief"
    assert res.parser == "iosxr.show_ipv4_interface_brief"
    assert res.metadata["hostname"] == "PE1"
    assert res.metadata["timestamp"].startswith("Wed Mar 14")
    assert res.data[1] == {
        "interface": "TenGigE0/0/0/0",
        "ip_address": None,
        "status": "Shutdown",
        "protocol": "Down",
        "vrf": "default",
    }


def test_normalized_view():
    res = clijson.parse(XR_BRIEF, normalize=True)
    assert res.normalized[1] == {
        "name": "TenGigE0/0/0/0",
        "admin_status": "admin-down",
        "oper_status": "down",
        "ip_address": None,
        "vrf": "default",
        "description": None,
    }


def test_result_helpers():
    res = clijson.parse(XR_BRIEF)
    assert len(res) == 2 and res[0]["interface"] == "Loopback0"
    assert res.ok
    assert '"interface": "Loopback0"' in res.to_json()
    meta = res.to_dict()
    assert meta["engine"] == "native" and meta["confidence"] == 1.0
    assert "ParseResult(" in repr(res)


def test_echo_line_without_prompt():
    res = clijson.parse("show clock\n10:15:02.123 UTC Mon May 13 2024\n", platform="iosxr")
    assert res.command == "show clock"
    assert res.data["year"] == 2024


def test_huawei_show_alias_and_detection():
    out = "Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors\nGE0/0/1                     up    up           0%     0%          0          0\n"
    res = clijson.parse(out, "show interface brief")
    assert res.platform == "vrp"
    assert res.parser == "vrp.display_interface_brief"


def test_filtered_output_warning():
    res = clijson.parse(XR_BRIEF.replace("show ip int brief", "show ip int brief | i Up"))
    assert any("filtered" in w for w in res.warnings)


def test_unknown_command_falls_back_to_generic_with_hints():
    res = clijson.parse("Name   Value\nfoo    1\nbar    2\n", "show bgp summry", "iosxr")
    assert res.engine in ("generic", "ntc")
    if res.engine == "generic":
        assert res.data["tables"][0]["rows"][0] == {"name": "foo", "value": 1}
        assert any("closest supported" in w for w in res.warnings)


def test_strict_mode():
    with pytest.raises(ParserNotFound) as exc:
        clijson.parse("x", "show something unknown", "iosxr", strict=True)
    assert exc.value.platform == "iosxr"


def test_engines_selection():
    res = clijson.parse(XR_BRIEF, engines=["generic"])
    assert res.engine == "generic" and res.confidence < 1


def test_session_log():
    text = (DATA / "xr_session.log").read_text()
    chunks = split_session(text)
    assert [c.command for c in chunks] == ["show version", "show ipv4 interface brief", "show bgp summary"]
    results = clijson.parse_session(text, normalize=True)
    assert [r.parser for r in results] == [
        "iosxr.show_version",
        "iosxr.show_ipv4_interface_brief",
        "iosxr.show_bgp_summary",
    ]
    bgp = results[2]
    assert [n["neighbor"] for n in bgp.data["neighbors"]] == ["10.255.0.2", "10.255.0.3", "2001:db8:ffff::11"]
    assert bgp.data["neighbors"][1]["state"] == "Idle (Admin)"
    assert bgp.normalized[0]["established"] is True and bgp.normalized[0]["prefixes_received"] == 512
    assert results[0].data["hostname"] == "PE1"


def test_parse_file(tmp_path):
    p = tmp_path / "out.txt"
    p.write_text(XR_BRIEF)
    assert clijson.parse_file(p).parser == "iosxr.show_ipv4_interface_brief"
    many = clijson.parse_file(DATA / "xr_session.log")
    assert isinstance(many, list) and len(many) == 3


def test_custom_parser_registration_and_failure_fallback():
    @register("iosxr", "show clijson-demo")
    class Demo(Parser):
        """Demo parser used in tests."""

        def parse(self, text):
            if "boom" in text:
                raise ValueError("kaboom")
            return {"lines": text.splitlines()}

    assert clijson.parse("a\nb", "show clijson-demo", "iosxr").data == {"lines": ["a", "b"]}
    res = clijson.parse("boom", "show clijson-demo", "iosxr", engines=["native", "generic"])
    assert res.engine == "generic" and any("kaboom" in w for w in res.warnings)
    with pytest.raises(ParseError):
        clijson.parse("boom", "show clijson-demo", "iosxr", raise_on_error=True)


def test_supported_commands_catalog():
    rows = clijson.supported_commands("junos")
    assert rows and all(r["platform"] == "junos" for r in rows)
    assert len(clijson.supported_commands()) > 150
    assert clijson.find_parser("vrp", "dis bgp peer").parser.name == "vrp.display_bgp_peer"


def test_empty_output():
    res = clijson.parse("", "show arp", "iosxr")
    assert res.engine == "native" and res.data == []
