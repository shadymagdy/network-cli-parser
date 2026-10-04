"""Every regression capture, delivered through every Cisco NSO channel, must parse exactly like the plain capture.

This is the guarantee behind the NSO integration: whichever platform and command (all fixtures of IOS XR, Junos
and VRP), and however the output was collected through NSO (Python API, RESTCONF, JSON-RPC, NETCONF, ncs_cli in
either CLI style, `| display json/xml`, or copied with escaped line breaks), the result is the same.
"""

import json
from xml.sax.saxutils import escape

import pytest

import clijson

from .conftest import fixture_cases, read_json

DEVICE_PROMPT = {"iosxr": "RP/0/RP0/CPU0:pe1#", "junos": "admin@pe1> ", "vrp": "<pe1>"}
STATS_NS = {
    "iosxr": ("tailf-ned-cisco-ios-xr-stats", "http://tail-f.com/ned/cisco-ios-xr-stats"),
    "junos": ("junos-stats", "http://tail-f.com/ned/juniper-junos-stats"),
    "vrp": ("vrp-stats", "http://tail-f.com/ned/huawei-vrp-stats"),
}


def python_api(text, command, platform):
    """What `action(inp).result` returns: CRLF line endings and the device prompt after the output."""
    return "\r\n" + text.replace("\n", "\r\n") + "\r\n" + DEVICE_PROMPT[platform]


def restconf_json(text, command, platform):
    return json.dumps({f"{STATS_NS[platform][0]}:output": {"result": python_api(text, command, platform)}}, indent=2)


def json_rpc_nested(text, command, platform):
    inner = {f"{STATS_NS[platform][0]}:output": {"result": python_api(text, command, platform)}}
    return json.dumps({"jsonrpc": "2.0", "id": 7, "result": inner})


def json_rpc_pairs(text, command, platform):
    return json.dumps(
        {"jsonrpc": "2.0", "id": 7, "result": [{"name": "result", "value": python_api(text, command, platform)}]}
    )


def restconf_xml(text, command, platform):
    return f'<output xmlns="{STATS_NS[platform][1]}">\n  <result>{escape(python_api(text, command, platform))}</result>\n</output>'


def netconf_reply(text, command, platform):
    return (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">'
        f'<result xmlns="{STATS_NS[platform][1]}">{escape(python_api(text, command, platform))}</result></rpc-reply>'
    )


def ncs_cli_c_style(text, command, platform):
    return (
        f'admin@ncs# devices device pe1 live-status exec any "{command}"\n'
        f"result \n{text}\n{DEVICE_PROMPT[platform]}\nadmin@ncs# "
    )


def ncs_cli_j_style(text, command, platform):
    return (
        f'admin@ncs> request devices device pe1 live-status exec any args [ "{command}" ]\n'
        f"result \n{text}\n{DEVICE_PROMPT[platform]}\n[ok][2026-10-04 10:00:00]\n\nadmin@ncs> "
    )


def escaped_copy(text, command, platform):
    """The result string copied out of a JSON log without decoding it."""
    return python_api(text, command, platform).replace("\r", "\\r").replace("\n", "\\n")


WRAPPERS = [
    python_api,
    restconf_json,
    json_rpc_nested,
    json_rpc_pairs,
    restconf_xml,
    netconf_reply,
    ncs_cli_c_style,
    ncs_cli_j_style,
    escaped_copy,
]
CASES = list(fixture_cases())


@pytest.mark.parametrize("wrap", WRAPPERS, ids=[w.__name__ for w in WRAPPERS])
@pytest.mark.parametrize(("txt", "js"), CASES)
def test_nso_delivered_output_parses_like_the_capture(txt, js, wrap):
    meta = read_json(js)
    text = txt.read_text(encoding="utf-8")
    wrapped = wrap(text, meta["command"], meta["platform"])
    res = clijson.parse(wrapped, meta["command"], meta["platform"], normalize=True)
    assert res.engine == "native", (res.engine, res.warnings)
    assert res.data == meta["expected"]
    if "normalized" in meta:
        assert res.normalized == meta["normalized"]


@pytest.mark.parametrize("wrap", [ncs_cli_c_style, ncs_cli_j_style], ids=["c-style", "j-style"])
@pytest.mark.parametrize(("txt", "js"), CASES)
def test_ncs_cli_transcript_needs_no_hints(txt, js, wrap):
    """The command comes from NSO's command line; NSO's prompt must never be mistaken for a Junos prompt."""
    meta = read_json(js)
    wrapped = wrap(txt.read_text(encoding="utf-8"), meta["command"], meta["platform"])
    res = clijson.parse(wrapped, normalize=True)
    assert res.command == meta["command"]
    assert res.metadata["device"] == "pe1"
    assert res.platform == meta["platform"]
    assert res.data == meta["expected"]
