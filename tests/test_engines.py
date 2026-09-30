from pathlib import Path

import clijson
from clijson.engines.config import parse_config, parse_junos_curly, parse_junos_set
from clijson.engines.generic import parse_generic
from clijson.engines.structured import looks_like_json, looks_like_xml, parse_json, parse_xml

DATA = Path(__file__).parent / "data"


def test_generic_table_with_separator():
    text = """Name          Status    Speed
----          ------    -----
port1         up        10G
port2         down      1G
"""
    out = parse_generic(text)
    assert out["tables"][0]["rows"] == [{"name": "port1", "status": "up", "speed": "10G"}, {"name": "port2", "status": "down", "speed": "1G"}]


def test_generic_key_values_and_sections():
    text = """Hostname: r1
Uptime: 3 days
Power supplies:
  PSU 1: OK
  PSU 2: Failed
free text line
"""
    out = parse_generic(text)
    assert out["fields"]["hostname"] == "r1"
    assert out["fields"]["power_supplies"] == {"psu_1": "OK", "psu_2": "Failed"}
    assert out["lines"] == ["free text line"]


def test_generic_multi_kv_per_line():
    out = parse_generic("BGP state = Established, up for 1d02h\n")
    assert out["fields"] == {"bgp_state": "Established", "up_for": "1d02h"} or out["fields"]["bgp_state"].startswith("Established")


def test_generic_implicit_aligned_table():
    text = """Interface               Admin Link Proto    Local
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     10.0.0.1/24
lo0.0                   up    up   inet     10.255.0.1
"""
    rows = parse_generic(text)["tables"][0]["rows"]
    assert rows[1] == {"interface": "ge-0/0/0.0", "admin": "up", "link": "up", "proto": "inet", "local": "10.0.0.1/24"}


def test_junos_json_is_simplified():
    text = (DATA / "junos_terse.json").read_text()
    assert looks_like_json(text)
    data = parse_json(text)
    phy = data["interface_information"]["physical_interface"]
    assert phy[0]["name"] == "ge-0/0/0"
    assert phy[0]["logical_interface"]["address_family"]["interface_address"]["ifa_local"] == "10.0.0.1/30"
    assert phy[1]["admin_status"] == "down"


def test_junos_xml_is_converted():
    text = (DATA / "junos_bgp.xml").read_text()
    assert looks_like_xml(text)
    data = parse_xml(text)
    info = data["bgp_information"]
    assert info["peer_count"] == 2
    assert info["bgp_peer"][0]["elapsed_time"] == {"value": "1d 2:03:04", "seconds": 93784}
    assert info["bgp_peer"][1]["peer_state"] == "Active"


def test_parse_dispatches_structured_output():
    res = clijson.parse((DATA / "junos_bgp.xml").read_text(), "show bgp summary | display xml", "junos")
    assert res.engine == "xml"
    res = clijson.parse((DATA / "junos_terse.json").read_text(), "show interfaces terse | display json")
    assert res.engine == "json"


def test_junos_curly_config():
    cfg = parse_junos_curly((DATA / "junos_config.txt").read_text())
    assert cfg["system"]["host-name"] == "mx1"
    assert cfg["system"]["services"]["netconf"] == {"ssh": True}
    assert cfg["system"]["name-server"] == ["8.8.8.8", "1.1.1.1"]
    assert cfg["interfaces"]["ge-0/0/0"]["description"] == "to core-1"
    assert cfg["interfaces"]["ge-0/0/0"]["unit"]["0"]["family"]["inet"] == {"address": "10.0.0.1/30"}
    assert cfg["interfaces"]["ge-0/0/1"] == {"disable": True}
    assert cfg["protocols"]["bgp"]["group"]["IBGP"]["neighbor"] == ["10.255.0.2", "10.255.0.3"]


def test_junos_set_config():
    cfg = parse_junos_set((DATA / "junos_config_set.txt").read_text())
    assert cfg["system"]["host-name"] == "mx1"
    assert cfg["interfaces"]["ge-0/0/0"]["unit"]["0"]["family"]["inet"]["address"] == "10.0.0.1/30"
    assert cfg["protocols"]["bgp"]["group"]["IBGP"]["neighbor"] == ["10.255.0.2", "10.255.0.3"]


def test_indented_config_xr():
    text = """Building configuration...
!! IOS XR Configuration 7.9.2
hostname PE1
interface Loopback0
 ipv4 address 10.255.0.1 255.255.255.255
!
interface FourHundredGigE0/0/0/0
 description core-1
 mtu 9216
 shutdown
!
router bgp 65000
 neighbor 10.255.0.2
  remote-as 65000
  address-family ipv4 unicast
  !
 !
!
end
"""
    cfg = parse_config(text, "iosxr")
    assert cfg["hostname"] == "PE1"
    assert cfg["interface"]["FourHundredGigE0/0/0/0"] == {"description": "core-1", "mtu": "9216", "shutdown": True}
    assert cfg["router"]["bgp 65000"]["neighbor"]["10.255.0.2"]["remote-as"] == "65000"
