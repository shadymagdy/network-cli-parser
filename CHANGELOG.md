# Changelog

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
