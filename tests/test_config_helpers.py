"""G-6: clijson.config.has / lines behave the same on every configuration format."""

import pytest

import clijson

JUNOS_BRACES = """interfaces {
    ae24 {
        unit 100 {
            description "cust a";
            vlan-id 100;
            family inet {
                address 198.51.100.100/31;
            }
        }
    }
}
routing-instances {
    VRF-B {
        instance-type virtual-router;
        interface ae24.100;
        interface ae24.200;
    }
}
policy-options {
    prefix-list LIST-A {
        203.0.113.0/24;
    }
}
"""

JUNOS_SET = """set interfaces ae24 unit 100 description "cust a"
set interfaces ae24 unit 100 vlan-id 100
set interfaces ae24 unit 100 family inet address 198.51.100.100/31
set routing-instances VRF-B instance-type virtual-router
set routing-instances VRF-B interface ae24.100
set routing-instances VRF-B interface ae24.200
set policy-options prefix-list LIST-A 203.0.113.0/24
"""

IOSXR = """l2vpn
 bridge group GRP-A
  bridge-domain 100
   interface Bundle-Ether520.100
   !
   neighbor 192.0.2.18 pw-id 5000
    pw-class PW-A
   !
  !
 !
!
router bgp 65000
 neighbor 192.0.2.1
  remote-as 65000
  description peer one
 !
!
"""

VRP = """#
interface Vlanif200
 description 200 - cust b
 l2 binding vsi V200
#
vsi V200 static
 pwsignal ldp
  vsi-id 6000
  peer 192.0.2.18
#
"""


@pytest.mark.parametrize(
    ("text", "command"), [(JUNOS_BRACES, "show configuration"), (JUNOS_SET, "show configuration | display set")]
)
def test_junos_braces_and_set_give_the_same_answers(text, command):
    res = clijson.parse(text, command, "junos")
    assert clijson.config.has(res, "routing-instances VRF-B interface ae24.100", anchored=True)
    assert clijson.config.has(res, "routing-instances VRF-B interface ae24.200")
    assert clijson.config.has(res, "routing-instances VRF-B")  # the container
    assert clijson.config.has(res, 'interfaces ae24 unit 100 description "cust a"')
    assert clijson.config.has(res, "policy-options prefix-list LIST-A 203.0.113.0/24")
    assert not clijson.config.has(res, "routing-instances VRF-B interface ae24.300")
    assert not clijson.config.has(res, "routing-instances VRF-B interface ae24.1")  # whole words only
    # not anchored at the root unless asked
    assert not clijson.config.has(res, "VRF-B interface ae24.100")
    assert clijson.config.has(res, "VRF-B interface ae24.100", anchored=False)
    assert sorted(clijson.config.lines(res)) == sorted(
        [
            'interfaces ae24 unit 100 description "cust a"',
            "interfaces ae24 unit 100 vlan-id 100",
            "interfaces ae24 unit 100 family inet address 198.51.100.100/31",
            "routing-instances VRF-B instance-type virtual-router",
            "routing-instances VRF-B interface ae24.100",
            "routing-instances VRF-B interface ae24.200",
            "policy-options prefix-list LIST-A 203.0.113.0/24",
        ]
    )


def test_iosxr_running_config():
    res = clijson.parse(IOSXR, "show running-config", "iosxr")
    assert clijson.config.has(res, "l2vpn bridge group GRP-A bridge-domain 100 interface Bundle-Ether520.100")
    assert clijson.config.has(res, "l2vpn bridge group GRP-A bridge-domain 100 neighbor 192.0.2.18 pw-id 5000")
    assert clijson.config.has(res, "router bgp 65000 neighbor 192.0.2.1 remote-as 65000")
    assert not clijson.config.has(res, "router bgp 65000 neighbor 192.0.2.1 remote-as 65001")
    assert "router bgp 65000 neighbor 192.0.2.1 description peer one" in clijson.config.lines(res)


def test_vrp_current_configuration():
    res = clijson.parse(VRP, "display current-configuration", "vrp")
    assert clijson.config.has(res, "interface Vlanif200 l2 binding vsi V200")
    assert clijson.config.has(res, "vsi V200 static pwsignal ldp peer 192.0.2.18")
    assert clijson.config.has(res, "peer 192.0.2.18", anchored=False)
    assert not clijson.config.has(res, "peer 192.0.2.18")
    assert clijson.config.lines(res) == [
        "interface Vlanif200 description 200 - cust b",
        "interface Vlanif200 l2 binding vsi V200",
        "vsi V200 static pwsignal ldp vsi-id 6000",
        "vsi V200 static pwsignal ldp peer 192.0.2.18",
    ]


def test_works_on_plain_data_and_non_trees():
    res = clijson.parse(JUNOS_SET, "show configuration | display set", "junos")
    assert clijson.config.has(res.data, "routing-instances VRF-B interface ae24.100")
    assert clijson.config.lines([]) == [] and not clijson.config.has([], "x")
    assert not clijson.config.has(res, "")


# --------------------------------------------------------------------------- #
# CJ-10: prompt auto-detection
# --------------------------------------------------------------------------- #

CJ10 = """@PE2-re1> show arp no-resolve interface ae4.100 | no-more
Sep 17 06:08:37
MAC Address       Address         Interface                Flags
00:00:5e:00:53:10 198.51.100.2    ae4.100                  none
Total entries: 1
"""


@pytest.mark.parametrize(
    "prompt",
    ["@PE2-re1>", "PE2-re1>", "{master}\nPE2-re1>", "ops@PE2-re1>"],
    ids=["empty-user", "bare-host", "master", "user"],
)
def test_cj10_prompt_is_recognised_and_timestamp_stripped(prompt):
    res = clijson.parse(CJ10.replace("@PE2-re1>", prompt, 1), normalize=True)
    assert res.platform == "junos"
    assert res.command == "show arp no-resolve interface ae4.100 | no-more"
    assert res.parser == "junos.show_arp"
    assert res.data == {
        "entries": [
            {"mac_address": "00:00:5e:00:53:10", "ip_address": "198.51.100.2", "interface": "ae4.100", "flags": "none"}
        ],
        "total": 1,
    }
    assert res.metadata["hostname"] == "PE2-re1"
    assert res.metadata["timestamp"] == "Sep 17 06:08:37"
    assert res.metadata["detected_by"] == "prompt"


def test_cj10_prompt_regex_is_linear():
    import time

    from clijson.platforms import match_prompt

    for hostile in ("a-" * 50_000 + "re1x>", "-re1" * 50_000 + ">x", "@" + "a." * 50_000):
        start = time.perf_counter()
        match_prompt(hostile)
        assert time.perf_counter() - start < 1
