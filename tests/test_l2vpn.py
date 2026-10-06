"""L2VPN pseudowire redundancy: parsing, the vendor-neutral model and pre/post change comparison."""

from pathlib import Path

import pytest

import clijson
from clijson.models import SCHEMAS, validate
from clijson.parsers.junos.l2vpn import STATUS_CODES

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
    res = clijson.find_parser(platform, typed)
    assert res is not None, typed
    assert res.parser.name == parser


def test_vrp_vsi_summary_has_no_pw_model():
    r = clijson.parse(_text("vrp", "display_vsi", "vsi_summary"), "display vsi", "vrp", normalize=True)
    assert r.data["up"] == 2
    assert r.normalized is None


# --------------------------------------------------------------------------- #
# Junos rows without "Time last up" / "# Up trans"
# --------------------------------------------------------------------------- #

STANDBY_ROW = """Layer-2 Circuit Connections:

Legend for connection status (St)
RS -- remote site standby        HS -- Hot-standby Connection

Neighbor: 192.0.2.30
Interface                 Type St      Time last up          # Up trans
    ae22.100(vc 7000)         rmt   RS
      local PW status code: 0x00000000, Neighbor PW status code: 0x00000020
"""


def test_l2circuit_standby_row_without_time_columns_is_kept():
    res = clijson.parse(STANDBY_ROW, "show l2circuit connections interface ae22.100", "junos", normalize=True)
    assert res.data == {
        "connections": [
            {
                "interface": "ae22.100",
                "pw_id": 7000,
                "type": "remote",
                "status": "RS",
                "status_text": "remote site standby",
                "last_up": None,
                "up_transitions": None,
                "neighbor": "192.0.2.30",
                "local_pw_status_code": "0x00000000",
                "neighbor_pw_status_code": "0x00000020",
            }
        ]
    }
    (pw,) = res.normalized
    assert (pw["state"], pw["active"], pw["role"]) == ("standby", False, "backup")
    assert (pw["status_code"], pw["local_status_code"], pw["remote_status_code"]) == ("RS", "0x00000000", "0x00000020")
    assert res.warnings == []
    assert res.confidence == 1.0


def test_l2circuit_piped_row_without_time_columns():
    res = clijson.parse(
        "    ae22.100(vc 7000)         rmt   RS\n",
        "show l2circuit connections interface ae22.100 | match rmt",
        "junos",
        normalize=True,
    )
    (row,) = res.data["connections"]
    assert (row["interface"], row["pw_id"], row["status"], row["neighbor"]) == ("ae22.100", 7000, "RS", None)
    assert (row["last_up"], row["up_transitions"]) == (None, None)
    assert res.normalized[0]["neighbor"] is None
    assert res.warnings == ["output was filtered by '| match rmt'; some fields may be missing"]


@pytest.mark.parametrize("code", sorted(STATUS_CODES))
@pytest.mark.parametrize("with_time", [True, False], ids=["with-time", "without-time"])
def test_l2circuit_every_legend_code(code, with_time):
    tail = "     Apr 17 05:43:09 2025           1" if with_time else ""
    text = f"Neighbor: 192.0.2.30\n    ae22.100(vc 7000)         rmt   {code}{tail}\n"
    res = clijson.parse(text, "show l2circuit connections", "junos", normalize=True)
    (row,) = res.data["connections"]
    assert row["status"] == code
    assert row["status_text"] == STATUS_CODES[code]
    assert row["up_transitions"] == (1 if with_time else None)
    assert row["last_up"] == ("Apr 17 05:43:09 2025" if with_time else None)
    (pw,) = res.normalized
    assert pw["status_code"] == code
    if code == "Up":
        assert (pw["state"], pw["role"], pw["active"]) == ("up", "primary", True)
    elif code in ("RS", "ST", "HS", "BK"):
        assert (pw["state"], pw["role"], pw["active"]) == ("standby", "backup", False)
    else:
        assert pw["active"] is False and pw["role"] is None


def test_l2circuit_time_without_count_keeps_the_year():
    res = clijson.parse(
        "Neighbor: 192.0.2.30\n    ae22.100(vc 7000)   rmt   Up     Apr 17 05:43:09 2025\n",
        "show l2circuit connections",
        "junos",
    )
    row = res.data["connections"][0]
    assert (row["last_up"], row["up_transitions"]) == ("Apr 17 05:43:09 2025", None)


def test_l2circuit_last_up_keeps_its_spacing():
    """Junos pads one-digit days ("Feb  2"); the value must stay as printed, like 0.5.0 returned it."""
    res = clijson.parse(
        "Neighbor: 192.0.2.1\n    ge-0/0/1.0(vc 0)  loc  Up  Feb  2 10:00:00 2024  1\n",
        "show l2circuit connections",
        "junos",
    )
    row = res.data["connections"][0]
    assert (row["last_up"], row["up_transitions"]) == ("Feb  2 10:00:00 2024", 1)


def test_l2circuit_vpls_row_without_time_columns():
    res = clijson.parse(
        "Instance: VPLS-A\n  VPLS-id: 7000\n    192.0.2.204(vpls-id 7000) rmt   RS\n",
        "show vpls connections instance VPLS-A",
        "junos",
        normalize=True,
    )
    (pw,) = res.normalized
    assert (pw["service"], pw["neighbor"], pw["state"], pw["role"]) == ("VPLS-A", "192.0.2.204", "standby", "backup")


# --------------------------------------------------------------------------- #
# Lines a table parser cannot place are reported, never dropped silently
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("platform", "command", "text", "junk"),
    [
        ("junos", "show l2circuit connections", STANDBY_ROW, "ae22.100 vc 7000 rmt RS garbled"),
        (
            "vrp",
            "display vsi remote ldp",
            (
                "Vsi        Peer            VC      Group      Encap    MTU    Vsi    State\n"
                "ID         RouterID        Label   ID         Type     Value  Index  Code\n"
                "6000       192.0.2.18      8189    0          vlan     1500   377    FORWARD\n"
            ),
            "6001       192.0.2.19      8190",
        ),
        (
            "vrp",
            "display vsi name VSI-A peer-info",
            (
                "VSI Name: VSI-A                                       Signaling: ldp\n"
                "Peer                Transport Local       Remote      VC\n"
                "Addr                VC ID      VC Label   VC Label    State\n"
                "192.0.2.18          11000      48178      8189        up\n"
            ),
            "192.0.2.19          11001      48179",
        ),
        (
            "junos",
            "show vpls mac-table instance VPLS-A",
            (
                "Routing instance : VPLS-A\n Bridging domain : __VPLS-A__, VLAN : none\n"
                "   MAC                 MAC      Logical          NH     MAC         active\n"
                "   address             flags    interface        Index  property    source\n"
                "   00:00:5e:00:53:01   D        ae2.100\n"
            ),
            "00:00:5e:00:53 D ae2.100",
        ),
    ],
    ids=["junos-l2circuit", "vrp-vsi-remote", "vrp-peer-info", "junos-vpls-mac-table"],
)
def test_unparsed_unparsed_lines_are_reported(platform, command, text, junk):
    clean = clijson.parse(text, command, platform)
    assert not [w for w in clean.warnings if w.startswith("unparsed")]
    assert clean.confidence == 1.0

    res = clijson.parse(text.rstrip("\n") + "\n" + junk + "\n", command, platform)
    (warning,) = [w for w in res.warnings if w.startswith("unparsed line(s)")]
    assert warning == f"unparsed line(s): 1 (first: {junk!r})"
    assert res.confidence < 1.0
    assert res.data == clean.data  # the recognised rows are still there


@pytest.mark.parametrize(
    ("command", "text"),
    [
        (
            "show vpls mac-table",
            (
                "MAC flags (S -static MAC, D -dynamic MAC, L -locally learned, C -Control MAC\n"
                "    SE -Statistics enabled, NM -Non configured MAC, R -Remote PE MAC)\n\n"
                "Routing instance : VPLS-A\n Bridging domain : __VPLS-A__, VLAN : none\n"
                "   MAC                 MAC      Logical          NH     RTR\n"
                "   address             flags    interface        Index  ID\n"
                "   00:00:5e:00:53:01   D        ae2.100\n"
            ),
        ),
        (
            "show vpls connections",
            (
                "Instance: VPLS-A\n  Edge protection: Not-Primary\n  VPLS-id: 7000\n"
                "    Neighbor                  Type  St     Time last up          # Up trans\n"
                "    192.0.2.204(vpls-id 7000) rmt   Up     Apr 28 11:06:51 2026           1\n"
            ),
        ),
    ],
    ids=["older-mac-flags-legend", "instance-level-details"],
)
def test_unparsed_no_spurious_warning_on_legitimate_lines(command, text):
    res = clijson.parse(text, command, "junos")
    assert res.warnings == [] and res.confidence == 1.0
    assert res.data[next(iter(res.data))]  # the row is there


def test_unparsed_custom_parser_without_super_init_still_works():
    class Legacy(clijson.Parser):
        def __init__(self, params=None, command=""):
            super().__init__(params, command)
            del self.unparsed  # like a parser written before 0.6.0 that set its own attributes only

        def parse(self, text):
            return {"text": text.strip()}

    clijson.register("junos", "show zz-legacy-parser")(Legacy)
    res = clijson.parse("hello", "show zz-legacy-parser", "junos")
    assert (res.data, res.warnings, res.confidence) == ({"text": "hello"}, [], 1.0)


def test_unparsed_long_unparsed_line_is_shortened():
    junk = "x" * 200
    res = clijson.parse(STANDBY_ROW + junk + "\n", "show l2circuit connections", "junos")
    (warning,) = [w for w in res.warnings if w.startswith("unparsed")]
    assert len(warning) < 120 and warning.endswith("...')")


# --------------------------------------------------------------------------- #
# Pseudowire fields and VRP peer-info
# --------------------------------------------------------------------------- #

PEER_INFO = """VSI Name: VSI-A                                       Signaling: ldp
--------------------------------------------------------------------
Peer                Transport Local       Remote      VC
Addr                VC ID      VC Label   VC Label    State
--------------------------------------------------------------------
192.0.2.18          11000      48178      8189        up
"""


def test_pseudowire_vrp_peer_info_is_normalized():
    res = clijson.parse(PEER_INFO, "display vsi name VSI-A peer-info", "vrp", normalize=True)
    assert res.intent == "l2vpn.pseudowires"
    (pw,) = res.normalized
    assert {k: pw[k] for k in ("service", "neighbor", "pw_id", "local_label", "remote_label", "state", "active")} == {
        "service": "VSI-A",
        "neighbor": "192.0.2.18",
        "pw_id": 11000,
        "local_label": 48178,
        "remote_label": 8189,
        "state": "up",
        "active": True,
    }
    assert pw["status_code"] == "up"


def test_pseudowire_records_flatten_peers_with_the_vsi_name():
    res = clijson.parse(PEER_INFO, "display vsi name VSI-A peer-info", "vrp")
    assert res.records() == [
        {
            "name": "VSI-A",
            "signaling": "ldp",
            "peer": "192.0.2.18",
            "vc_id": 11000,
            "local_vc_label": 48178,
            "remote_vc_label": 8189,
            "state": "up",
        }
    ]


def test_pseudowire_vrp_vsi_remote_service_and_status_code():
    res = clijson.parse(
        "Vsi        Peer            VC      Group      Encap    MTU    Vsi    State\n"
        "ID         RouterID        Label   ID         Type     Value  Index  Code\n"
        "6000       192.0.2.18      8189    0          vlan     1500   377    FORWARD\n",
        "display vsi remote ldp pw-id 6000",
        "vrp",
        normalize=True,
    )
    (pw,) = res.normalized
    assert (pw["service"], pw["status_code"], pw["state"]) == ("6000", "FORWARD", "up")


def test_pseudowire_junos_l2circuit_detail_fields():
    text = (FIX / "junos" / "show_l2circuit_connections_extensive" / "l2circuit_extensive_history.txt").read_text()
    res = clijson.parse(text, "show l2circuit connections extensive", "junos", normalize=True)
    pw = res.normalized[0]
    assert pw["role"] == "primary"
    assert (pw["control_word"], pw["pw_status_tlv"], pw["flow_label_tx"], pw["flow_label_rx"]) == (
        False,
        True,
        True,
        True,
    )
    assert (pw["local_status_code"], pw["remote_status_code"]) == ("0x00000000", "0x00000000")


def test_pseudowire_iosxr_bridge_domain_detail_fields():
    text = (FIX / "iosxr" / "show_l2vpn_bridge_domain_detail" / "bd_detail_backup_pw.txt").read_text()
    res = clijson.parse(text, "show l2vpn bridge-domain detail", "iosxr", normalize=True)
    primary, backup = res.normalized[:2]
    assert (primary["status_code"], primary["control_word"], primary["pw_status_tlv"]) == ("up", False, True)
    assert (primary["local_status_code"], primary["remote_status_code"]) == ("0x0", "0x0")
    assert (backup["status_code"], backup["role"]) == ("standby", "backup")


def test_pseudowire_new_fields_are_optional_and_appended():
    keys = SCHEMAS["l2vpn.pseudowires"]
    assert keys[:10] == [
        "service",
        "neighbor",
        "pw_id",
        "state",
        "role",
        "active",
        "vc_type",
        "mtu",
        "local_label",
        "remote_label",
    ]
    assert keys[10:] == [
        "status_code",
        "local_status_code",
        "remote_status_code",
        "control_word",
        "pw_status_tlv",
        "flow_label_tx",
        "flow_label_rx",
    ]
