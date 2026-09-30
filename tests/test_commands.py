import pytest

from clijson.commands import GrammarError, canonical, compile_pattern, match_tokens, render, slugify, split_command
from clijson.registry import REGISTRY


def m(pattern, command):
    return match_tokens(compile_pattern(pattern), command.split())


def test_literal_and_abbreviation():
    assert m("show ip interface brief", "show ip interface brief")
    assert m("show ip interface brief", "sh ip int br")
    assert m("show ip interface brief", "SH IP INT BRIEF")
    assert m("show ip interface brief", "show ip interface") is None
    assert m("show ip interface brief", "show ip interface brief extra") is None


def test_single_letter_abbreviation_is_rejected():
    assert m("show version", "s version") is None


def test_params_optional_and_choice():
    pat = "show bgp [vrf (all|<vrf>)] [(ipv4|ipv6) [unicast]] summary"
    r = m(pat, "show bgp vrf CUST-A ipv6 unicast summary")
    assert r.params == {"vrf": "CUST-A"}
    assert m(pat, "show bgp vrf all summary").params == {}
    assert m(pat, "show bgp summary")
    assert m(pat, "show bgp ipv4 sum")


def test_rest_param():
    r = m("show route [<target...>]", "show route 10.0.0.0/8 longer-prefixes")
    assert r.params == {"target": "10.0.0.0/8 longer-prefixes"}


def test_exact_beats_param():
    exact = m("show interfaces brief", "show interfaces brief")
    param = m("show interfaces [<name>]", "show interfaces brief")
    assert exact > param


def test_typed_params_reject_typos():
    assert m("show bgp [<prefix>]", "show bgp 10.0.0.0/8").params == {"prefix": "10.0.0.0/8"}
    assert m("show bgp [<prefix>]", "show bgp summry") is None
    assert m("show interfaces [<interface>]", "show interfaces irb.100")
    assert m("show interfaces [<interface>]", "show interfaces breif") is None


def test_render_and_canonical():
    seq = compile_pattern("show bgp [vrf <vrf>] (summary|sum-alias)")
    assert render(seq) == "show bgp [vrf <vrf>] (summary | sum-alias)"
    assert canonical(seq) == "show bgp summary"


@pytest.mark.parametrize("bad", ["show [bgp", "show (a|b", "show ]"])
def test_bad_grammar(bad):
    with pytest.raises(GrammarError):
        compile_pattern(bad)


def test_split_command_pipes():
    c = split_command("show bgp summary | include Estab")
    assert c.base == "show bgp summary"
    assert c.pipes == ["include Estab"]
    assert c.filtered
    assert c.output_format is None
    assert split_command("show interfaces terse | display json").output_format == "json"
    assert split_command("show version | display xml").output_format == "xml"
    assert not split_command("show version | no-more").filtered


def test_slugify():
    assert slugify("show ip interface brief") == "show_ip_interface_brief"
    assert slugify("display eth-trunk <trunk>") == "display_eth_trunk_trunk"


@pytest.mark.parametrize(
    "platform,command,parser",
    [
        ("iosxr", "sh ip int br", "iosxr.show_ipv4_interface_brief"),
        ("iosxr", "show interfaces brief", "iosxr.show_interfaces_brief"),
        ("iosxr", "show int TenGigE0/0/0/1", "iosxr.show_interfaces"),
        ("iosxr", "show bgp vrf all ipv4 unicast summary", "iosxr.show_bgp_summary"),
        ("iosxr", "show route vrf CUST ipv4 summary", "iosxr.show_route_summary"),
        ("iosxr", "show route ipv6 2001:db8::/32", "iosxr.show_route"),
        ("junos", "show route table inet.3 10.0.0.1 extensive", "junos.show_route"),
        ("junos", "show route summary", "junos.show_route_summary"),
        ("junos", "sh int terse", "junos.show_interfaces_terse"),
        ("junos", "show interfaces ge-0/0/0 extensive", "junos.show_interfaces"),
        ("vrp", "dis int br", "vrp.display_interface_brief"),
        ("vrp", "show interface brief", "vrp.display_interface_brief"),
        ("vrp", "display ip routing-table statistics", "vrp.display_ip_routing_table_statistics"),
        ("vrp", "display bgp vpnv4 vpn-instance CUST-A peer", "vrp.display_bgp_peer"),
        ("vrp", "dis cur", "vrp.display_current_configuration"),
    ],
)
def test_registry_resolution(platform, command, parser):
    res = REGISTRY.resolve(platform, command.split())
    assert res is not None and res.parser.name == parser


def test_suggestions():
    hints = REGISTRY.suggest("iosxr", "show bgp summry")
    assert any("show bgp" in h for h in hints)
