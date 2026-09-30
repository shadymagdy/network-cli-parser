"""Model Context Protocol (MCP) server: let AI assistants and agents parse router output with clijson.

    $ pip install "clijson[mcp]"
    $ clijson mcp                                   # stdio, for Claude Desktop / Claude Code / Cursor / VS Code
    $ clijson mcp --transport http --port 8000      # Streamable HTTP at http://127.0.0.1:8000/mcp

Tools (all read-only, no network access):

``parse_output``        raw show/display output -> structured JSON (+ normalized model)
``parse_session``       a whole terminal log with many commands
``detect_platform``     which OS produced this output?
``diff_outputs``        structural pre/post comparison of two captures
``list_commands``       commands with dedicated parsers (filterable)
``get_model_schema``    JSON Schema of a normalized model

Resources: ``clijson://commands`` (the catalog) and ``clijson://models/{intent}`` (JSON Schemas).

The tool functions below are plain Python and are tested without the SDK; :func:`build_server` wires them into
the official ``mcp`` SDK (v2 ``MCPServer``, with a fallback to v1 ``FastMCP``).
"""

# No ``from __future__ import annotations`` here: the SDK introspects the tool signatures at runtime, and the
# parameter types are local ``Annotated`` aliases that must be real objects, not strings.
import json
from typing import Any

from . import __version__
from .api import parse, parse_session, supported_commands
from .diff import VOLATILE, diff
from .exceptions import CliJsonError
from .models import INTENTS, json_schema
from .platforms import detect_platform, list_platforms

INSTRUCTIONS = """\
clijson turns the text output of router show/display commands (Cisco IOS XR, Juniper Junos, Huawei VRP) into
structured JSON. Pass the raw output exactly as captured; prompts, pagers and ANSI codes are handled. Give the
command when you know it (abbreviations such as "sh bgp summ" work) and the platform when you know it
(iosxr, junos, vrp); both are auto-detected otherwise. Set normalize=true to get a vendor-neutral model
(same field names on every vendor) for BGP peers, interfaces, routes, LLDP, OSPF, IS-IS, ARP and more.
"""

#: Keep tool responses a sensible size for a model's context window.
MAX_RECORDS = 500


def _truncate(data: Any, limit: int) -> tuple[Any, bool]:
    if isinstance(data, list) and len(data) > limit:
        return data[:limit], True
    return data, False


def tool_parse_output(
    output: str,
    command: str | None = None,
    platform: str | None = None,
    normalize: bool = True,
    max_records: int = MAX_RECORDS,
) -> dict[str, Any]:
    """Parse the output of one show/display command into structured JSON."""
    try:
        res = parse(output, command, platform, normalize=normalize)
    except CliJsonError as exc:
        return {"error": str(exc)}
    out: dict[str, Any] = {
        "platform": res.platform,
        "command": res.command,
        "engine": res.engine,
        "parser": res.parser,
        "confidence": res.confidence,
    }
    data, cut = _truncate(res.data, max_records)
    out["data"] = data
    if res.normalized is not None:
        out["intent"] = res.intent
        out["normalized"], cut_n = _truncate(res.normalized, max_records)
        cut = cut or cut_n
    if res.warnings:
        out["warnings"] = res.warnings
    if cut:
        out["truncated"] = f"only the first {max_records} records are included"
    return out


def tool_parse_session(output: str, platform: str | None = None, normalize: bool = True) -> dict[str, Any]:
    """Parse every command found in a terminal session log (prompt + command + output, repeated)."""
    try:
        results = parse_session(output, platform, normalize=normalize)
    except CliJsonError as exc:
        return {"error": str(exc)}
    return {
        "commands": [
            {
                "command": r.command,
                "platform": r.platform,
                "engine": r.engine,
                "hostname": r.metadata.get("hostname"),
                "data": r.normalized if r.normalized is not None else r.data,
            }
            for r in results
        ]
    }


def tool_detect_platform(output: str, command: str | None = None) -> dict[str, Any]:
    """Guess which network OS produced some output."""
    det = detect_platform(output, command)
    return {
        "platform": det.platform.name if det.platform else None,
        "confidence": round(det.confidence, 3),
        "scores": det.scores,
        "reasons": det.reasons,
    }


def tool_diff_outputs(
    before: str,
    after: str,
    command: str | None = None,
    platform: str | None = None,
    include_counters: bool = False,
) -> dict[str, Any]:
    """Compare two captures of the same command (e.g. before/after a change) and list what changed."""
    try:
        a = parse(before, command, platform, normalize=True)
        b = parse(after, command or a.command, platform or a.platform, normalize=True)
    except CliJsonError as exc:
        return {"error": str(exc)}
    changes = diff(a, b, ignore=None if include_counters else VOLATILE)
    return {
        "command": a.command,
        "platform": a.platform,
        "changed": bool(changes),
        "changes": [{"path": c.path, "kind": c.kind, "before": c.before, "after": c.after} for c in changes],
    }


def tool_list_commands(platform: str | None = None, search: str | None = None) -> dict[str, Any]:
    """List commands that have dedicated parsers, optionally for one platform or matching some text."""
    try:
        rows = supported_commands(platform)
    except CliJsonError as exc:
        return {"error": str(exc)}
    if search:
        needle = search.lower()
        rows = [r for r in rows if needle in r["command"].lower() or needle in (r["description"] or "").lower()]
    return {
        "count": len(rows),
        "commands": [{k: r[k] for k in ("platform", "command", "intent", "description")} for r in rows],
    }


def tool_get_model_schema(intent: str) -> dict[str, Any]:
    """JSON Schema of a normalized model (e.g. bgp.summary, interfaces.brief, routes)."""
    try:
        return json_schema(intent)
    except KeyError as exc:
        return {"error": exc.args[0], "models": list(INTENTS)}


# --------------------------------------------------------------------------- #
# SDK wiring
# --------------------------------------------------------------------------- #


def _sdk() -> tuple[Any, Any, Any]:
    """Return (server class, ToolAnnotations factory, pydantic Field), preferring MCP SDK v2."""
    import importlib

    try:
        field = importlib.import_module("pydantic").Field
        try:
            server_cls = importlib.import_module("mcp.server.mcpserver").MCPServer
        except ImportError:  # pragma: no cover - mcp v1
            server_cls = importlib.import_module("mcp.server.fastmcp").FastMCP
        tool_annotations = importlib.import_module("mcp.types").ToolAnnotations
    except ImportError as exc:
        raise ImportError('the MCP server needs the mcp SDK: pip install "clijson[mcp]"') from exc

    hints = {"read_only_hint": True, "destructive_hint": False, "idempotent_hint": True, "open_world_hint": False}
    if "read_only_hint" not in getattr(tool_annotations, "model_fields", {}):  # pragma: no cover - v1: camelCase
        hints = {"".join(w.title() if i else w for i, w in enumerate(k.split("_"))): v for k, v in hints.items()}

    def annotations(title: str) -> Any:
        return tool_annotations(title=title, **hints)

    return server_cls, annotations, field


def build_server(name: str = "clijson") -> Any:
    """Create the MCP server with every clijson tool and resource registered."""
    from typing import Annotated

    Server, annotations, Field = _sdk()
    server = Server(name, instructions=INSTRUCTIONS, version=__version__)

    platforms = ", ".join(p.name for p in list_platforms())
    Output = Annotated[str, Field(description="Raw command output exactly as captured from the device")]
    Command = Annotated[
        str | None, Field(description="The command that produced the output; abbreviations work (sh bgp summ)")
    ]
    Plat = Annotated[str | None, Field(description=f"Platform: {platforms} (or an alias); auto-detected if omitted")]
    Normalize = Annotated[bool, Field(description="Add the vendor-neutral model (same fields on every vendor)")]

    def parse_output(
        output: Output, command: Command = None, platform: Plat = None, normalize: Normalize = True
    ) -> dict[str, Any]:
        return tool_parse_output(output, command, platform, normalize)

    def parse_session_log(output: Output, platform: Plat = None, normalize: Normalize = True) -> dict[str, Any]:
        return tool_parse_session(output, platform, normalize)

    def detect(output: Output, command: Command = None) -> dict[str, Any]:
        return tool_detect_platform(output, command)

    def diff_outputs(
        before: Annotated[str, Field(description="Output captured before the change")],
        after: Annotated[str, Field(description="Output of the same command captured after the change")],
        command: Command = None,
        platform: Plat = None,
        include_counters: Annotated[bool, Field(description="Also report counters, timers and uptimes")] = False,
    ) -> dict[str, Any]:
        return tool_diff_outputs(before, after, command, platform, include_counters)

    def list_commands(
        platform: Plat = None,
        search: Annotated[str | None, Field(description="Only commands containing this text")] = None,
    ) -> dict[str, Any]:
        return tool_list_commands(platform, search)

    def get_model_schema(
        intent: Annotated[str, Field(description=f"Normalized model name: {', '.join(INTENTS)}")],
    ) -> dict[str, Any]:
        return tool_get_model_schema(intent)

    tools = [
        (parse_output, "parse_output", "Parse show output", tool_parse_output),
        (parse_session_log, "parse_session", "Parse a session log", tool_parse_session),
        (detect, "detect_platform", "Detect the platform", tool_detect_platform),
        (diff_outputs, "diff_outputs", "Compare two captures", tool_diff_outputs),
        (list_commands, "list_commands", "List supported commands", tool_list_commands),
        (get_model_schema, "get_model_schema", "Get a model's JSON Schema", tool_get_model_schema),
    ]
    for fn, tool_name, title, impl in tools:
        server.add_tool(fn, name=tool_name, title=title, description=impl.__doc__, annotations=annotations(title))

    def commands_resource() -> str:
        return json.dumps(supported_commands(), indent=1)

    def model_resource(intent: str) -> str:
        return json.dumps(json_schema(intent), indent=1)

    server.resource(
        "clijson://commands",
        name="commands",
        description="Every command with a dedicated parser",
        mime_type="application/json",
    )(commands_resource)
    server.resource(
        "clijson://models/{intent}",
        name="model-schema",
        description="JSON Schema of a normalized model",
        mime_type="application/schema+json",
    )(model_resource)
    return server


def run(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover - blocking
    """Run the server (``stdio`` or ``http`` = Streamable HTTP)."""
    server = build_server()
    if transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", host=host, port=port)
