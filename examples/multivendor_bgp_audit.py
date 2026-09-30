"""Audit BGP sessions across Cisco IOS XR, Juniper and Huawei with one code path.

    python examples/multivendor_bgp_audit.py
"""

from pathlib import Path

import clijson

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
CAPTURES = [
    (FIX / "iosxr/show_bgp_summary/ntc_cisco_xr_show_ip_bgp_summary.txt", "show bgp summary", "iosxr"),
    (FIX / "junos/show_bgp_summary/genie_showbgpsummary_output.txt", "show bgp summary", "junos"),
    (FIX / "vrp/display_bgp_peer/ntc_huawei_vrp_display_bgp_peer2.txt", "display bgp peer", "vrp"),
]

for path, command, platform in CAPTURES:
    result = clijson.parse(path.read_text(), command, platform, normalize=True)
    peers = result.normalized
    down = [p for p in peers if not p["established"]]
    print(f"{platform:6} {len(peers):3} peers, {len(down)} not established")
    for p in down:
        print(f"         - {p['neighbor']:<28} AS{p['remote_as']:<8} {p['state']}")
