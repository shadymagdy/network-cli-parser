# Command line

`clijson` is installed with the package (or run it with `uvx clijson`). `clijson FILE ...` is shorthand for
`clijson parse FILE ...`, and piping into `clijson` parses stdin.

| Command | What it does |
|---|---|
| `clijson parse [FILE] [-c CMD] [-p PLATFORM]` | Parse output from a file or stdin. `-n` adds the normalized model, `-m` adds provenance, `-f json\|yaml\|table\|json-compact` picks the format, `--strict` requires a dedicated parser. |
| `clijson diff BEFORE AFTER [-c CMD]` | Structural diff of two captures. Exits 1 when something changed. `--all` includes counters and timers. |
| `clijson commands [-p PLATFORM] [-s TEXT]` | List the commands with dedicated parsers |
| `clijson detect [FILE]` | Detect which OS produced some output |
| `clijson platforms` | Supported platforms and their aliases |
| `clijson schema [MODEL] [--out DIR] [--check FILE]` | List, print, export or validate against the [normalized models](models.md) |
| `clijson serve [--host H] [--port P]` | Zero-dependency HTTP API: `POST /parse`, `GET /commands`, `GET /health` |
| `clijson mcp [-t stdio\|http]` | [MCP server](mcp.md) for AI assistants (needs `clijson[mcp]`) |
| `clijson run HOST -p PLATFORM -c CMD ...` | Run commands on a live device and parse them (needs `clijson[netmiko]` or `[scrapli]`) |
| `clijson version` | Version, Python and available engines |

## Examples

```bash
clijson parse show_bgp.txt -p iosxr -c "show bgp summary"
ssh mx1 "show interfaces terse" | clijson parse -p junos -c "show interfaces terse"
clijson session.log                                   # every command in a terminal log
clijson parse out.txt -c "dis bgp peer" -n -f table   # normalized, as a table
clijson diff pre.txt post.txt -c "show bgp summary"   # what changed?
clijson commands -p vrp --search lldp                 # what is supported?
clijson parse out.txt -c "show arp" -n | clijson schema arp --check -   # validate in CI
```

## HTTP API

```bash
clijson serve --port 8080 &
curl -s localhost:8080/parse \
  -d '{"platform":"vrp","command":"display interface brief","output":"...","normalize":true}'
curl -s "localhost:8080/commands?platform=junos"
```

The request body for `POST /parse` takes `output` (required) and optionally `command`, `platform`, `normalize`
and `strict`. The response is `ParseResult.to_dict()`.
