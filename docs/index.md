---
title: clijson
hide:
  - navigation
---

# clijson

**Router CLI output → clean, predictable JSON.** clijson turns the output of `show` / `display` commands from
**Cisco IOS XR**, **Juniper Junos** and **Huawei VRP** into structured data. It has **no runtime dependencies**.

```python
>>> import clijson
>>> r = clijson.parse(open("pe1.log").read())        # platform and command are auto-detected
>>> r.parser, r.platform
('iosxr.show_bgp_summary', 'iosxr')
>>> r.normalized[0]
{'neighbor': '10.255.0.2', 'remote_as': 65000, 'state': 'Established', 'established': True, ...}
```

<div class="grid cards" markdown>

-   :material-rocket-launch: **Get started in a minute**

    ---

    `pip install clijson`, or try it with `uvx clijson`.

    [:octicons-arrow-right-24: Getting started](getting-started.md)

-   :material-console: **A complete CLI**

    ---

    Parse files or stdin, diff captures, detect platforms, export schemas, serve an API.

    [:octicons-arrow-right-24: Command line](cli.md)

-   :material-shape: **One model for every vendor**

    ---

    19 typed, schema'd models (BGP peers, interfaces, routes, LLDP, pseudowires, ...) with the same fields on every vendor.

    [:octicons-arrow-right-24: Normalized models](models.md)

-   :material-robot: **Built for AI assistants**

    ---

    `clijson mcp` exposes the parsers to Claude, Cursor, VS Code and any MCP client.

    [:octicons-arrow-right-24: MCP server](mcp.md)

</div>

## Why clijson

| | |
|---|---|
| **Works on any command** | 173 dedicated parsers (251 command patterns). A generic engine structures *any* other output, so you always get JSON back. |
| **Understands you like a router does** | `sh ip int br`, `dis int br` and `show interfaces brief` all resolve. Parameters such as a VRF or interface are captured. |
| **Zero configuration** | The platform is detected from prompts, command verbs or fingerprints in the output, with trial parsing as a last resort. Pagers, ANSI codes and timestamps are removed. |
| **Typed and schema'd** | Normalized models are `TypedDict`s with JSON Schemas (draft 2020-12). `py.typed` is included and the codebase is checked with `mypy --strict`. |
| **Pre/post change checks** | `clijson.diff()` matches records by natural key and ignores counters and timers by default. |
| **Tested on real output** | 254 regression fixtures from ASR9K, NCS5500, 8000, MX, PTX, QFX, EX, SRX, NE40E, CX600, CE and more. |
