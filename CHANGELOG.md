# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

* Typed normalized models: every intent is a `TypedDict` in `clijson.models` (`BgpNeighbor`, `Route`, `Interface`,
  `Arp`, ...) with per-field descriptions, so editors and type checkers know the shape of `result.normalized`.
* JSON Schema (draft 2020-12) for every model: `clijson.models.json_schema()`, `clijson schema` (list, print,
  export with `--out`) and the committed `schemas/` directory.
* `clijson.models.validate()` and `clijson schema <model> --check FILE` to check data against a model without
  extra dependencies. The test suite checks every normalized fixture against its schema with both this validator
  and `jsonschema`.
* MCP server (`clijson mcp`, extra `clijson[mcp]`). AI assistants and agents can parse output, parse session
  logs, detect platforms, diff captures, list commands and fetch model schemas through read-only tools. It also
  exposes `clijson://commands` and `clijson://models/{intent}` resources, supports stdio and Streamable HTTP,
  and is built on the official `mcp` SDK v2. See [docs/mcp.md](docs/mcp.md).

### Changed

* Build and packaging moved to [uv](https://docs.astral.sh/uv/). The `uv_build` backend replaces setuptools,
  development tools are PEP 735 dependency groups, and `uv.lock` pins every tool version.
* Python 3.10 or newer is required (3.8 and 3.9 are end-of-life). Python 3.14 is supported and tested.
* License metadata uses a PEP 639 SPDX expression.
* `clijson.__version__` is read from the installed package metadata.
* Code is formatted with `ruff format` (120 columns), and more ruff rule families are enabled
  (bugbear, comprehensions, simplify, perf, pytest style).
* pre-commit hooks for ruff, the lockfile and basic file hygiene.
* CI runs on `astral-sh/setup-uv` with a locked environment and dependency caching. It also cancels superseded
  runs and builds and smoke-tests the wheel.
* GitHub Actions are pinned to commit SHAs. Dependabot keeps them and `uv.lock` up to date.
* A plugin that fails to load now raises a `RuntimeWarning` instead of failing silently.
* The codebase uses modern Python 3.10 syntax (`list[str]`, `X | None`, PEP 613 aliases). It is checked with
  `mypy --strict` in CI and pre-commit, and ships `py.typed` so your editor and type checker see full types.
* **Normalized output:** `ospf.neighbors.dead_time`, `arp.age` and `ipv6.neighbors.age` are now always integer
  seconds on every vendor. Before, IOS XR gave `"00:00:31"` strings and VRP gave ARP expiry in minutes.

### Removed

* The `dev` extra. Use `uv sync` (the `dev` dependency group) instead.

## 0.1.0

First release.

* 161 dedicated parsers (237 command patterns) for Cisco IOS XR, Juniper Junos and Huawei VRP.
* Abbreviation-aware command grammar. Huawei `show` alias.
* Platform detection from prompts, command verbs and output fingerprints, with trial parsing as a fallback.
* Generic engine for any other output: tables, key/value pairs and indented sections.
* Junos `| display json` and `| display xml` support.
* Configuration trees for IOS XR / VRP (indented) and Junos (curly braces and `| display set`).
* Vendor-neutral normalized models for 18 concepts.
* Session logs with many commands (`parse_session`).
* Structural `diff` of two captures, matched by natural key, with volatile fields ignored by default.
* Device error detection (`engine="device-error"`), bytes input, `records()` and `to_dataframe()`.
* Optional ntc-templates and Genie fallback engines.
* CLI (`clijson`), HTTP API (`clijson serve`) and live collection (`clijson run`, scrapli/netmiko).
* Typed command parameters (prefixes, addresses and interfaces must look like one), so typos aren't swallowed.
* containerlab lab and `scripts/harvest.py` for checking new OS releases against every supported command.
* 238 regression fixtures (217 captured from real devices).
