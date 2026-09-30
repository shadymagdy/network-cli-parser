# Changelog

## 0.1.0

First release.

* 124 dedicated parsers (190 command patterns) for Cisco IOS XR, Juniper Junos and Huawei VRP.
* Abbreviation-aware command grammar. Huawei `show` alias.
* Platform detection from prompts, command verbs and output fingerprints, with trial parsing as a fallback.
* Generic engine for any other output: tables, key/value pairs and indented sections.
* Junos `| display json` and `| display xml` support.
* Configuration trees for IOS XR / VRP (indented) and Junos (curly braces and `| display set`).
* Vendor-neutral normalized models for 18 concepts.
* Session logs with many commands (`parse_session`).
* Optional ntc-templates and Genie fallback engines.
* CLI (`clijson`), HTTP API (`clijson serve`) and live collection (`clijson run`, scrapli/netmiko).
* 185 regression fixtures from real devices.
