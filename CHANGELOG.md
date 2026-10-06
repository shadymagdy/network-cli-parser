# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

## 0.6.0 - 2026-10-06

Fixes and additions requested for running clijson behind an NSO package. Data shapes and keys stay
backward-compatible: fields were only added, none were renamed or removed.

### Fixed

* **CJ-01 (P1)** Junos `show l2circuit connections`: a row without the "Time last up" and "# Up trans" columns,
  such as a standby circuit (`ae22.100(vc 7000)  rmt  RS`), was dropped silently. Rows now parse with
  `last_up` / `up_transitions` set to `null`, their detail lines still attach, and they normalize to state
  `standby`, `active: false`, role `backup`. This applies to every status code in the legend (`Up`, `RS`, `ST`,
  `HS`, `BK`, `OL`, `NP`, `VC-Dn`, `CM`, `RD`, ...), with or without the time columns, and to the
  `| match rmt` form (one row, `neighbor: null`, and the filter warning kept). VPLS rows get the same fix.
  A time without a count no longer loses its year.
* **CJ-10 (P4)** Prompt auto-detection: a Junos prompt with an empty user (`@host-re1>`) and a bare
  routing-engine host (`host-re1>`) are recognised. The command, host name and platform are read from them, and
  the `set cli timestamp` line that follows is stripped into `metadata["timestamp"]` instead of being parsed as
  data.

### Added

* **G-1 (P1)** No silent data loss: the L2VPN and MAC table parsers report every line they cannot place
  (neither header, legend, row nor detail). The result gets the warning
  `unparsed line(s): N (first: '...')`, with the first line shortened to 80 characters, and
  `confidence` drops to 0.8. This covers Junos `show l2circuit connections`, `show vpls connections` and
  `show vpls/bridge/evpn mac-table`, and VRP `display vsi remote`, `display vsi peer-info` and the per-slot
  `display mac-address`. Parsers opt in with `Parser.note_unparsed(line)`.
* **G-2 (P2)** Secret redaction:
  * `clijson.redact(text)` and a `redact=False` parameter on `parse()`, `parse_file()`, `parse_session()`,
    `clijson.nso.show()` and `clijson.nso.show_many()`.
  * When on, secrets are masked with `clijson.REDACTED` (`<redacted>`) before parsing, in both `data` and
    `raw`, and `metadata["redacted"]` is `True`.
  * Covered: Junos `$9$` and `$1$`/`$5$`/`$6$`/`$8$` crypt strings; `authentication-key`, `encrypted-password`,
    `pre-shared-key`, `secret` and `password`; IOS XR `secret <n>`, `password <n>`, `password encrypted` and
    `key <n>`; Huawei `cipher`, `password cipher` and `irreversible-cipher`; SNMP communities in Junos (`set`
    and `{ }`), IOS XR and Huawei form.
  * The surrounding syntax (keywords, key types, quotes, `;`) is kept, so configuration trees parse the same,
    and NSO JSON payloads stay valid JSON.
* **G-3 (P2)** `clijson.nso.unwrap(payload) -> str`, also available as `clijson.textutils.unwrap_nso`, strips
  NSO `live-status` wrapping from output collected elsewhere. It is a stable, documented API. The private
  `clijson._nso_wrap.unwrap` keeps its name and return value.
* **G-4 (P3)** `l2vpn.pseudowires` has new optional fields: `status_code` (the native code: Junos `Up` / `RS` /
  `HS` ..., VRP `FORWARD` / `up`, IOS XR `up` / `standby`), `local_status_code` and `remote_status_code` (hex),
  `control_word`, `pw_status_tlv`, `flow_label_tx` and `flow_label_rx`. They are filled where the output shows
  them: Junos l2circuit and VPLS, VRP `display vsi` verbose, `display vsi remote`, `display vsi peer-info`,
  protect-group and `display mpls l2vc`, and IOS XR bridge-domain and xconnect detail. They are `null`
  elsewhere.
  * Junos l2circuit `role` is now `primary` for an `Up` circuit and `backup` for `RS` / `ST` / `HS` / `BK`
    (it was `null`).
  * VRP `display vsi remote` `service` is now the VSI ID (it was `null`).
* **G-5 (P3)** VRP `display vsi name <vsi> peer-info` normalizes to `l2vpn.pseudowires`: service = VSI name,
  neighbor, `pw_id` = VC ID, labels, state and `status_code`. Without `normalize`, `records()` gives one row per
  peer, carrying the VSI name and signaling. Parsers opt into this with `Parser.record_path`, and `records()`
  is unchanged for every other command.
* **G-6 (P4)** `clijson.config.has(result, statement, anchored=True)` and `clijson.config.lines(result)`:
  check a configuration statement from the root of the hierarchy, or flatten the tree into one full-path line
  per statement. They behave the same for Junos `display set`, Junos `{ }`, IOS XR `running-config` and VRP
  `current-configuration`, comparing word by word (quoting, whitespace and how the tree grouped words don't
  matter).
* Release notes now list the SHA-256 of the wheel and sdist published to PyPI.

## 0.5.0 - 2026-10-04

### Added

* `ping` on IOS XR, Junos and Huawei VRP. The new `ping` model gives target, sent, received, loss, success and
  min/avg/max round-trip time, so reachability can be compared before and after a change.
* Junos `show vpls mac-table` (also `show bridge mac-table` and `show evpn mac-table`): MACs per routing instance
  and bridging domain, normalized to `mac.table`.
* Huawei VRP `display vsi remote ldp [pw-id <id>]`: the remote side of each PW (label, encapsulation, MTU, state
  code), normalized to `l2vpn.pseudowires`.
* IOS XR `show l2vpn bridge-domain pw-id <id>`.
* Junos `show bgp summary instance <instance> group <group>`.

### Fixed

* Junos `show l2circuit connections ... | match rmt`, `show vpls connections ... | match rmt` and
  `show bgp summary | match <peer>` returned nothing. The matching rows are now parsed; the VPLS instance or
  l2circuit neighbor comes from the command when the output no longer shows it.
* Junos `show route advertising-protocol` / `receive-protocol`: an AS path with a single AS was read as the
  local preference. The header columns now decide when they line up with the rows.
* Huawei VRP `display vsi peer-info`: the layout with transport VC ID, local / remote VC labels and VC state was
  mapped to the wrong fields.
* Huawei VRP `display mac-address`: the per-slot layout (`MAC address table of slot ...`, PEVLAN / CEVLAN
  columns) returned no entries. Rows wrapped by a narrow terminal are joined, and the normalized view lists each
  MAC once instead of once per slot.

### Changed

* `l2vpn.pseudowires`: `neighbor` may be `null` when the output doesn't show it (a row filtered with `| match`).
* `FORWARD` is recognised as an up pseudowire state.

### Cisco NSO

* Every new and fixed check command, `ping` included, has been verified to work through `live-status exec any`.
  A new test runs every regression capture through `clijson.nso.show()` on mock IOS XR, Junos and VRP NED
  devices, with the platform taken from the NED-id alone.
* `ncs_cli` transcripts: escaped quotes inside the command (`exec any "... | match \"x\""`) are unescaped.
  NSO's own pipe after the command (`exec any "show bgp summary" | match <peer>`), which removes the `result`
  line, is understood, and the result is marked as filtered.
* Guide: [Check commands through NSO](docs/guides/cisco-nso.md#check-commands-through-nso).

## 0.4.0 - 2026-10-04

### Added

* Cisco NSO integration, `clijson.nso`:
  * `show(device, command)` runs the command through the device's `live-status exec any` action and parses the
    result, taking the platform from the device's NED.
  * Also `show_many()`, `exec_any()`, `platform_of()` and `NsoError`.
  * It works with any CLI NED (the exec action is discovered) and doesn't import `ncs`.
* `clijson.parse()` unwraps every form of NSO `live-status` output:
  * RESTCONF and `| display json` JSON;
  * JSON-RPC (nested and name/value);
  * RESTCONF XML, NETCONF `rpc-reply` and `| display xml` (XML-escaped);
  * `ncs_cli` transcripts in C-style and J-style;
  * text with literal `\r\n` escapes.

  For transcripts, the device and command are read from NSO's command line, and NSO's prompt is never
  mistaken for a Junos prompt. A new test parses every regression capture through each of these forms and
  requires identical results.
* `do show ...` / `run show ...` (commands sent from configuration mode) resolve to the same parsers.
* Platform aliases `cisco-iosxr`, `cisco-ios-xr`, `huawei-vrp` and `juniper-junos`, as used in NED names.
* Guide: [Using clijson inside Cisco NSO](docs/guides/cisco-nso.md), with installation, an action package
  example, service pre/post checks and RESTCONF usage.

## 0.3.1 - 2026-10-01

### Added

* `clijson.checks.pseudowire_redundancy()` gives a verdict on normalized pseudowires: one forwarding PW per
  service, backups in standby, nothing down, and optionally "every service has a backup". It returns a
  `RedundancyReport` with the problems and a per-service status.
* MCP tool `check_pseudowire_redundancy`. It runs that check on a capture and, given the pre-change capture as
  `before`, also returns the pre-change verdict and the changes.
* The MCP server instructions now tell assistants about the pseudowire commands and the change-verification
  workflow.

## 0.3.0 - 2026-10-01

### Added

* L2VPN / pseudowire redundancy verification commands:
  * Huawei VRP: `display vsi` (summary and `verbose`), `display vsi peer-info`, `display vsi protect-group`,
    `display mpls l2vc`, `display bridge-domain`, and `display mac-address` filtered by `vsi` or `bridge-domain`.
  * Cisco IOS XR: `show l2vpn bridge-domain` (default and `detail`, filtered by bd-name, group, interface or
    neighbor), `show l2vpn xconnect detail` and `show l2vpn forwarding bridge-domain mac-address`.
  * Juniper Junos: `show l2circuit connections` (all variants, with status codes decoded), `show vpls connections`,
    `show bgp group` and `show route forwarding-table`.
* New vendor-neutral model `l2vpn.pseudowires` (service, neighbor, PW ID, state, primary/backup role, active
  flag, VC type, MTU, labels), produced by all of the above.
* `clijson.diff()` matches pseudowires by neighbor + PW ID, so new labels or reordered output aren't reported
  as changes.
* Guide: [Pseudowire redundancy pre/post change checks](docs/guides/pseudowire-checks.md).

### Fixed

* Junos `show route forwarding-table` was handled by the generic `show route` parser. It now has a dedicated
  parser.

### Changed

* `mac.table` normalized records allow `vlan: null` when the device reports a bridge-domain or PW instead of
  a VLAN.

## 0.2.0 - 2026-10-01

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

* Documentation site built with [Zensical](https://zensical.org), the successor of Material for MkDocs. It has
  getting started, CLI and MCP guides, the generated command and model catalogs, and an API reference generated
  from docstrings (mkdocstrings). It is built on every PR and deployed to GitHub Pages from `main`.

* Release automation: pushing a `vX.Y.Z` tag builds, attests and publishes to PyPI with trusted publishing, then
  creates a GitHub release from the changelog ([RELEASING.md](RELEASING.md)).
* CodeQL code scanning, issue forms (parsing problem, feature request), a PR template, CODEOWNERS, `SECURITY.md`
  and `CODE_OF_CONDUCT.md`.

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
