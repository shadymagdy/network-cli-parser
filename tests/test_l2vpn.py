"""L2VPN pseudowire redundancy: parsing, the vendor-neutral model and pre/post change comparison."""

from pathlib import Path

import pytest

import clijson
from clijson import find_parser
from clijson.models import SCHEMAS, validate

FIX = Path(__file__).parent / "fixtures"


def _text(platform: str, folder: str, name: str) -> str:
    return (FIX / platform / folder / f"{name}.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("platform", "folder", "name", "command"),
    [
        ("junos", "show_l2circuit_connections", "l2circuit_primary_backup", "show l2circuit connections"),
        ("junos", "show_vpls_connections", "vpls_ldp", "show vpls connections"),
        ("iosxr", "show_l2vpn_bridge_domain", "bd_access_pw_vfi", "show l2vpn bridge-domain"),
        ("iosxr", "show_l2vpn_bridge_domain_detail", "bd_detail_backup_pw", "show l2vpn bridge-domain detail"),
        ("iosxr", "show_l2vpn_xconnect_detail", "xc_detail_backup_pw", "show l2vpn xconnect detail"),
        ("vrp", "display_vsi_verbose", "vsi_verbose_primary_secondary", "display vsi verbose"),
        ("vrp", "display_vsi_protect_group", "vsi_protect_group", "display vsi protect-group"),
        ("vrp", "display_mpls_l2vc", "l2vc_up_down", "display mpls l2vc"),
    ],
)
def test_every_vendor_produces_the_same_pseudowire_model(platform, folder, name, command):
    r = clijson.parse(_text(platform, folder, name), command, platform, normalize=True)
    assert r.intent == "l2vpn.pseudowires"
    assert r.normalized
    assert validate("l2vpn.pseudowires", r.normalized) == []
    for pw in r.normalized:
        assert list(pw) == SCHEMAS["l2vpn.pseudowires"]
        assert pw["state"] in ("up", "standby", "down")
        assert pw["active"] is (pw["state"] == "up")


@pytest.mark.parametrize(
    ("platform", "folder", "name", "command"),
    [
        ("junos", "show_l2circuit_connections", "l2circuit_primary_backup", "show l2circuit connections"),
        ("iosxr", "show_l2vpn_bridge_domain_detail", "bd_detail_backup_pw", "show l2vpn bridge-domain detail"),
        ("iosxr", "show_l2vpn_xconnect_detail", "xc_detail_backup_pw", "show l2vpn xconnect detail"),
        ("vrp", "display_vsi_verbose", "vsi_verbose_primary_secondary", "display vsi verbose"),
        ("vrp", "display_vsi_protect_group", "vsi_protect_group", "display vsi protect-group"),
    ],
)
def test_backup_pseudowire_is_standby(platform, folder, name, command):
    """The redundancy post-check: exactly one active primary and a standby backup per service."""
    r = clijson.parse(_text(platform, folder, name), command, platform, normalize=True)
    backups = [pw for pw in r.normalized if pw["role"] == "backup"]
    assert backups
    assert all(pw["state"] == "standby" and pw["active"] is False for pw in backups)
    for b in backups:
        same_service = [pw for pw in r.normalized if pw["service"] == b["service"] and pw["pw_id"] == b["pw_id"]]
        assert sum(pw["active"] for pw in same_service) == 1


def test_junos_status_codes_are_decoded():
    data = clijson.parse(
        _text("junos", "show_l2circuit_connections", "l2circuit_primary_backup"), "show l2circuit connections", "junos"
    ).data
    by = {(c["neighbor"], c["pw_id"]): c for c in data["connections"]}
    assert by[("192.0.2.11", 3200)]["status_text"] == "mtu mismatch"
    assert by[("198.51.100.21", 3100)]["status_text"] == "hot-standby connection"
    assert by[("192.0.2.11", 3100)]["flow_label_transmit"] is True
    assert by[("192.0.2.11", 3100)]["negotiated_pw_status_tlv"] is True


def test_failover_is_visible_in_a_pre_post_diff():
    pre = _text("junos", "show_l2circuit_connections", "l2circuit_primary_backup")
    # simulate the failover test: primary goes down, the hot-standby backup takes over
    post = pre.replace("ae4.3100(vc 3100)         rmt   Up ", "ae4.3100(vc 3100)         rmt   Dn ", 1)
    post = post.replace("ae4.3100(vc 3100)         rmt   HS ", "ae4.3100(vc 3100)         rmt   Up ", 1)
    before = clijson.parse(pre, "show l2circuit connections", "junos", normalize=True)
    after = clijson.parse(post, "show l2circuit connections", "junos", normalize=True)
    changes = {(c.path, c.before, c.after) for c in clijson.diff(before, after)}
    assert ("[neighbor=192.0.2.11,pw_id=3100].state", "up", "down") in changes
    assert ("[neighbor=198.51.100.21,pw_id=3100].state", "standby", "up") in changes
    assert ("[neighbor=198.51.100.21,pw_id=3100].active", False, True) in changes


@pytest.mark.parametrize(
    ("platform", "typed", "parser"),
    [
        ("junos", "sh l2circuit conn ext", "junos.show_l2circuit_connections"),
        ("junos", "show l2circuit connections interface ae4.3100", "junos.show_l2circuit_connections"),
        ("junos", "show l2circuit connections neighbor 192.0.2.11 extensive", "junos.show_l2circuit_connections"),
        ("junos", "show vpls connections instance VPLS-1", "junos.show_vpls_connections"),
        ("junos", "show bgp group CUST-EBGP", "junos.show_bgp_group"),
        ("junos", "show route forwarding-table destination 203.0.113.0/24", "junos.show_route_forwarding_table"),
        ("junos", "show route forwarding-table table CUST-B", "junos.show_route_forwarding_table"),
        ("iosxr", "sh l2vpn bridge-domain bd-name BD3100 det", "iosxr.show_l2vpn_bridge_domain"),
        ("iosxr", "show l2vpn bridge-domain neighbor 192.0.2.11 pw-id 3100 detail", "iosxr.show_l2vpn_bridge_domain"),
        ("iosxr", "show l2vpn bridge-domain group BG-CUST", "iosxr.show_l2vpn_bridge_domain"),
        ("iosxr", "show l2vpn xconnect group CUST-XC detail", "iosxr.show_l2vpn_xconnect_detail"),
        ("iosxr", "show l2vpn xconnect", "iosxr.show_l2vpn_xconnect"),
        ("iosxr", "show l2vpn bridge-domain summary", "iosxr.show_l2vpn_bridge_domain_summary"),
        ("vrp", "dis vsi name 3100 verbose", "vrp.display_vsi"),
        ("vrp", "display vsi name 3100 peer-info", "vrp.display_vsi_peer_info"),
        ("vrp", "display vsi name 3100 protect-group", "vrp.display_vsi_protect_group"),
        ("vrp", "display mpls l2vc interface GigabitEthernet1/0/3.200", "vrp.display_mpls_l2vc"),
        ("vrp", "display bridge-domain 3100", "vrp.display_bridge_domain"),
        ("vrp", "display mac-address bridge-domain 3100", "vrp.display_mac_address"),
        ("vrp", "display mac-address dynamic vsi 3100", "vrp.display_mac_address"),
    ],
)
def test_pre_post_check_commands_resolve(platform, typed, parser):
    res = find_parser(platform, typed)
    assert res is not None, typed
    assert res.parser.name == parser


def test_vrp_vsi_summary_has_no_pw_model():
    r = clijson.parse(_text("vrp", "display_vsi", "vsi_summary"), "display vsi", "vrp", normalize=True)
    assert r.data["up"] == 2
    assert r.normalized is None
