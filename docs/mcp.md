# Using clijson from AI assistants (MCP)

clijson ships a [Model Context Protocol](https://modelcontextprotocol.io) server. Any MCP client can then turn
router output into structured JSON by calling clijson as a tool. That includes Claude Desktop, Claude Code,
Cursor, VS Code, Windsurf and your own agents. The assistant gets exact, schema'd data instead of guessing at
column layouts.

```bash
pip install "clijson[mcp]"      # or: uv tool install "clijson[mcp]"
clijson mcp                     # stdio transport (what desktop clients launch)
clijson mcp -t http --port 8000 # Streamable HTTP at http://127.0.0.1:8000/mcp
```

The server is built on the official `mcp` Python SDK (v2). It speaks every protocol revision the SDK supports,
including the stateless 2026-07-28 revision and the 2025 revisions.

## Tools

Every tool is **read-only** and makes no network connections. It only transforms the text you pass in.
The tools are annotated as such (`readOnlyHint`, `idempotentHint`, no `openWorldHint`), so clients can run
them without extra confirmation.

| Tool | What it does | Key arguments |
|---|---|---|
| `parse_output` | Parse one command's output into JSON. It adds the vendor-neutral model when one exists. | `output`, `command`?, `platform`?, `normalize` (default `true`) |
| `parse_session` | Parse a terminal log with many `prompt# command` blocks | `output`, `platform`? |
| `detect_platform` | Work out which OS produced some output, with a confidence and reasons | `output`, `command`? |
| `diff_outputs` | Structural pre/post comparison. Counters and timers are ignored unless asked. | `before`, `after`, `command`?, `platform`?, `include_counters` |
| `list_commands` | Commands with dedicated parsers | `platform`?, `search`? |
| `get_model_schema` | JSON Schema of a normalized model | `intent` (e.g. `bgp.summary`) |
| `check_pseudowire_redundancy` | Verdict on L2VPN PW redundancy: one forwarding PW per service, backups in standby, nothing down. With `before`, it also checks the pre-change capture and lists the changes. | `output`, `command`?, `platform`?, `before`?, `require_backup` |

Large results are capped at 500 records per list and flagged with `truncated`, so a full BGP table doesn't flood
the model's context.

## Resources

| URI | Content |
|---|---|
| `clijson://commands` | The full catalog of supported commands (JSON) |
| `clijson://models/{intent}` | JSON Schema of a normalized model |

## Client configuration

**Claude Code**

```bash
claude mcp add clijson -- uvx --from "clijson[mcp]" clijson mcp
```

**Claude Desktop / Cursor / Windsurf** (`claude_desktop_config.json`, `.cursor/mcp.json`, ...)

```json
{
  "mcpServers": {
    "clijson": {
      "command": "uvx",
      "args": ["--from", "clijson[mcp]", "clijson", "mcp"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`)

```json
{
  "servers": {
    "clijson": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "clijson[mcp]", "clijson", "mcp"]
    }
  }
}
```

`uvx` runs clijson in an isolated, cached environment, so nothing needs to be installed globally. If clijson
is already installed, use `"command": "clijson", "args": ["mcp"]` instead.

**Remote / shared** (Streamable HTTP):

```bash
clijson mcp --transport http --host 0.0.0.0 --port 8000
```

Then point the client at `http://<host>:8000/mcp`. The server has no authentication of its own, so put it behind
your usual reverse proxy or VPN before exposing it beyond localhost.

## Example conversation

> **You:** here's `show bgp summary` from pe1 and pe2, which peers are down?
>
> **Assistant** calls `parse_output(output=..., command="show bgp summary")` for each capture. It then reads
> `normalized[*].established` and answers from the exact data, whatever the vendor.

> **You:** here's `show l2vpn bridge-domain detail` from before and after adding the backup PW. Did it work?
>
> **Assistant** calls `check_pseudowire_redundancy(output=<after>, before=<before>, require_backup=true)`. Before the
> change it finds "no backup pseudowire". After the change it gets `ok: true`: one forwarding PW and the new backup
> in standby. The `changes` list shows the backup that was added.

## Embedding the server

```python
from clijson.mcp_server import build_server

server = build_server()          # an mcp MCPServer instance; add your own tools, then:
server.run("stdio")
```

The tool functions are plain Python and can be used without the SDK: `tool_parse_output`, `tool_diff_outputs`,
`tool_detect_platform`, ... in `clijson.mcp_server`.
