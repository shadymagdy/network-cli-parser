# Fixture provenance

The raw outputs in this directory come from three sources. Each fixture's `.json` names its source in the
`source` field.

* **ntc-templates**: https://github.com/networktocode/ntc-templates
  Copyright Network to Code, LLC. Licensed under the Apache License, Version 2.0.
  Files prefixed `ntc_` are unmodified copies of that project's `tests/**/*.raw` captures.
* **genieparser**: https://github.com/CiscoTestAutomation/genieparser
  Copyright Cisco Systems, Inc. Licensed under the Apache License, Version 2.0.
  Files prefixed `genie_` are unmodified copies of that project's `golden_output*_output.txt` captures.
* **clijson**: outputs written for this project from vendor documentation formats (MIT).

The expected JSON files were produced by clijson and are licensed under this repository's MIT license.
A copy of the Apache License 2.0 is available at https://www.apache.org/licenses/LICENSE-2.0.
