"""List interfaces with input/output errors using the normalized interface model."""

from pathlib import Path

import clijson

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
for path, cmd, platform in [
    (FIX / "iosxr/show_interfaces/ntc_cisco_xr_show_interfaces.txt", "show interfaces", "iosxr"),
    (
        FIX / "junos/show_interfaces_extensive/genie_showinterfacesextensive_output2.txt",
        "show interfaces extensive",
        "junos",
    ),
    (FIX / "vrp/display_interface/ntc_huawei_vrp_display_interface1.txt", "display interface", "vrp"),
]:
    for intf in clijson.parse(path.read_text(), cmd, platform, normalize=True).normalized:
        errors = (intf["input_errors"] or 0) + (intf["output_errors"] or 0)
        print(f"{platform:6} {intf['name']:<28} {intf['oper_status'] or '?':<6} errors={errors}")
