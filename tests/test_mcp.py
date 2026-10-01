"""MCP server: tool logic (always) and the SDK wiring end to end (when the mcp extra is installed)."""

import asyncio
import json
from pathlib import Path

import pytest

from clijson.mcp_server import (
    tool_detect_platform,
    tool_diff_outputs,
    tool_get_model_schema,
    tool_list_commands,
    tool_parse_output,
    tool_parse_session,
)

DATA = Path(__file__).parent / "data"
FIX = Path(__file__).parent / "fixtures"
ARP = (FIX / "iosxr" / "show_arp" / "ntc_cisco_xr_show_arp.txt").read_text(encoding="utf-8")


def test_parse_output_returns_data_and_model():
    out = tool_parse_output(ARP, "sh arp", "iosxr")
    assert out["platform"] == "iosxr"
    assert out["engine"] == "native"
    assert out["intent"] == "arp"
    assert out["normalized"][0]["mac_address"].count(":") == 5
    json.dumps(out)


def test_parse_output_truncates_large_results():
    out = tool_parse_output(ARP, "show arp", "iosxr", max_records=1)
    assert len(out["normalized"]) == 1
    assert "truncated" in out


def test_parse_output_reports_errors_instead_of_raising():
    assert "error" in tool_parse_output("x", "show version", "not-a-platform")


def test_parse_session_splits_commands():
    out = tool_parse_session((DATA / "xr_session.log").read_text(encoding="utf-8"))
    assert len(out["commands"]) >= 2
    assert all(c["platform"] == "iosxr" for c in out["commands"])


def test_detect_platform():
    out = tool_detect_platform(ARP, "show arp")
    assert out["platform"] == "iosxr"
    assert 0 < out["confidence"] <= 1


def test_diff_outputs():
    before = (DATA / "xr_bgp_pre.txt").read_text(encoding="utf-8")
    after = (DATA / "xr_bgp_post.txt").read_text(encoding="utf-8")
    out = tool_diff_outputs(before, after, "show bgp summary", "iosxr")
    assert out["changed"] is True
    assert {c["kind"] for c in out["changes"]} <= {"added", "removed", "changed"}
    assert tool_diff_outputs(before, before, "show bgp summary", "iosxr")["changed"] is False


def test_list_commands_filters():
    out = tool_list_commands("junos", "bgp")
    assert out["count"] == len(out["commands"]) > 0
    assert all(c["platform"] == "junos" for c in out["commands"])
    assert "error" in tool_list_commands("nope")


def test_model_schema():
    assert tool_get_model_schema("routes")["$id"].endswith("routes.json")
    missing = tool_get_model_schema("nope")
    assert "error" in missing
    assert "routes" in missing["models"]


# --------------------------------------------------------------------------- #
# End to end through the official SDK (in-process client)
# --------------------------------------------------------------------------- #


def _client():
    mcp = pytest.importorskip("mcp")
    if not hasattr(mcp, "Client"):  # pragma: no cover - SDK v1 has no in-process client
        pytest.skip("in-process client needs mcp>=2")
    from clijson.mcp_server import build_server

    return mcp.Client(build_server())


def _structured(result):
    if getattr(result, "structured_content", None) is not None:
        return result.structured_content
    if getattr(result, "structuredContent", None) is not None:  # pragma: no cover - camelCase models
        return result.structuredContent
    return json.loads(result.content[0].text)  # pragma: no cover


def test_sdk_lists_read_only_tools():
    async def go():
        async with _client() as client:
            return await client.list_tools()

    tools = {t.name: t for t in asyncio.run(go()).tools}
    assert set(tools) == {
        "parse_output",
        "parse_session",
        "detect_platform",
        "diff_outputs",
        "list_commands",
        "get_model_schema",
    }
    parse_tool = tools["parse_output"]
    assert parse_tool.input_schema["required"] == ["output"]
    assert "abbreviations" in parse_tool.input_schema["properties"]["command"]["description"]
    assert parse_tool.annotations.read_only_hint is True


def test_sdk_calls_parse_tool():
    async def go():
        async with _client() as client:
            return await client.call_tool("parse_output", {"output": ARP, "command": "show arp"})

    result = asyncio.run(go())
    assert not result.is_error
    data = _structured(result)
    assert data["platform"] == "iosxr"
    assert data["intent"] == "arp"


def test_sdk_reads_resources():
    async def go():
        async with _client() as client:
            commands = await client.read_resource("clijson://commands")
            schema = await client.read_resource("clijson://models/bgp.summary")
            return commands, schema

    commands, schema = asyncio.run(go())
    assert len(json.loads(commands.contents[0].text)) > 200
    assert json.loads(schema.contents[0].text)["title"] == "clijson bgp.summary"
