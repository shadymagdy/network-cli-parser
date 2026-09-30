# Architecture

```
src/clijson/
├── api.py            parse(), parse_session(), parse_file(): the pipeline
├── commands.py       command grammar, abbreviation-aware matching, pipe handling
├── registry.py       Parser base class, @register, plugin discovery
├── platforms.py      platform catalogue, aliases, prompts, fingerprints, detection
├── result.py         ParseResult (data + provenance)
├── models.py         vendor-neutral schemas ("intents") and helpers
├── textutils.py      building blocks for parser authors
├── engines/
│   ├── generic.py    heuristic engine: tables, key/value, indented sections
│   ├── structured.py Junos | display json / xml, generic XML/JSON
│   ├── config.py     running-config → tree (indent, curly, set)
│   └── external.py   optional ntc-templates / Genie adapters
├── parsers/          dedicated parsers, one package per platform
│   ├── iosxr/  junos/  vrp/
├── cli.py            `clijson` command
├── server.py         HTTP API (stdlib only)
└── live.py           scrapli / netmiko collection
```

## The pipeline (`clijson.parse`)

1. **Cleaning.** Normalise CRLF, strip ANSI escapes, backspaces and pager prompts (`--More--`,
   `---- More ----`), convert tabs and dedent pasted text.
2. **Prompt and echo extraction.** If the first line is a prompt plus a command
   (`RP/0/RP0/CPU0:PE1#show bgp sum`, `lab@mx1> show route`, `<NE40E>display version`), take the command and
   hostname from it. Trailing bare prompts and `{master}` lines are dropped. A bare echoed command
   (`show bgp summary` on the first line) also works. IOS XR timestamp lines go into `metadata.timestamp`.
3. **Platform resolution.** In order of precedence: the explicit argument, then the prompt, then detection
   (command verb, weighted fingerprints such as interface naming, Junos table names and Huawei legend lines).
   If detection is still ambiguous and a command is known, **trial parsing** runs every vendor's parser for
   that command and keeps the richest result.
4. **Structured short-cut.** `| display json` / `| display xml` (or output that looks like JSON/XML) goes
   straight to the structured engine.
5. **Resolution.** The command is split into a base command and `| pipes`. Filtering pipes add a warning. The
   base is scored against every pattern registered for the platform.
6. **Engines.** `native` (dedicated parser), then `ntc`, `genie`, and finally `generic`. If a dedicated parser
   raises, the failure is recorded as a warning and the next engine takes over (`raise_on_error=True` disables this).
7. **Normalization.** When asked, the parser's `normalize()` maps its native output to the vendor-neutral
   schema.

## Design choices

* **Native output keeps vendor vocabulary.** Nothing is thrown away, and field names are snake_case versions of
  what the device prints. The normalized view sits alongside it rather than replacing it.
* **Flat lists with context tags** instead of deep vendor hierarchies. For example, BGP neighbors are one list,
  and each neighbor carries `instance`, `vrf` and `address_family`. This makes filtering and DataFrames easy.
* **Values are typed** (`int`, `float`, `bool`, `None`) where that is unambiguous. Identifiers such as asdot ASNs
  (`65000.100`), zero-padded IDs and interface names stay strings.
* **Per-line matching** (`textutils.match_lines`) instead of multi-line regexes, so a short line can never
  steal fields from the next one.
* **Zero dependencies.** Optional features (YAML, pretty tables, TextFSM, Genie, SSH) are extras and are
  detected at runtime.

## Confidence

| engine | confidence | meaning |
|---|---|---|
| `native` | 1.0 | dedicated, tested parser |
| `json` / `xml` | 1.0 | device produced structured output |
| `ntc` / `genie` | 0.9 | community template matched |
| `generic` | 0.6 when tables were found, otherwise 0.4 | heuristic structure |
