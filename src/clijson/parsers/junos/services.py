"""Junos neighbor discovery, ARP/ND, switching and routing instances."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import mac, record
from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, snake, to_num


@register("junos", "show lldp neighbors", intent="lldp.neighbors")
class ShowLldpNeighbors(Parser):
    """LLDP neighbor table."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<local>\S+)\s+(?P<parent>\S+)\s+(?P<chassis>(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}|\S+)\s+(?P<port>\S+)\s+(?P<system>.*?)\s*$",
            text,
        ):
            if m["local"] == "Local":
                continue
            out.append(
                {
                    "local_interface": m["local"],
                    "parent_interface": none_if(m["parent"]),
                    "chassis_id": m["chassis"],
                    "port_info": m["port"],
                    "system_name": m["system"] or None,
                }
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "lldp.neighbors",
                local_interface=n["local_interface"],
                neighbor=n["system_name"],
                neighbor_interface=n["port_info"],
                chassis_id=mac(n["chassis_id"]),
            )
            for n in data
        ]


@register("junos", "show lldp neighbors interface <interface>", "show lldp neighbors detail", intent="lldp.neighbors")
class ShowLldpNeighborsInterface(Parser):
    """LLDP neighbor detail (chassis/port IDs, system name/description, capabilities, management address)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        section: Optional[str] = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^LLDP Neighbor Information:", s)
            if m:
                cur = {}
                out.append(cur)
                section = None
                continue
            if cur is None:
                cur = {}
                out.append(cur)
            if s.startswith(("Management Info", "Management Information")):
                section = "management"
                continue
            if s.startswith(("Address Type", "Type ")):
                continue
            if section == "management":
                m = re.match(r"^(?:IPv4|IPv6|Address)\s+(?P<a>\S+)", s)
                if m:
                    cur.setdefault("management_addresses", []).append(m["a"])
                    continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /()\-]*?)\s*:\s*(?P<v>.*)$", s)
            if m:
                k = snake(m["k"])
                v = m["v"].strip()
                if k == "address" and section == "management":
                    cur.setdefault("management_addresses", []).append(v)
                    continue
                cur[k] = to_num(v) if v else None
        return [compact(c) for c in out if c]

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "lldp.neighbors",
                local_interface=n.get("local_interface"),
                neighbor=n.get("system_name"),
                neighbor_interface=n.get("port_id") or n.get("port_description"),
                chassis_id=mac(str(n.get("chassis_id"))) if n.get("chassis_id") else None,
                capabilities=n.get("system_capabilities_enabled") or n.get("enabled_capabilities"),
                ttl=n.get("ttl"),
            )
            for n in data
        ]


@register(
    "junos",
    "show arp [(no-resolve|expiration-time|hostname <host>|interface <interface>|vpn <vpn>)]",
    "show arp no-resolve [(interface <interface>|vpn <vpn>)]",
    intent="arp",
)
class ShowArp(Parser):
    """ARP table."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"entries": []}
        for m in match_lines(
            r"^(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?:(?P<name>\S+)\s+)?(?P<intf>[a-z]\S*)\s+(?P<flags>\S+(?: \S+)*)(?:\s+(?P<ttl>\d+))?\s*$",
            text,
        ):
            name = m["name"]
            entry = {"mac_address": m["mac"], "ip_address": m["ip"], "interface": m["intf"], "flags": m["flags"]}
            if name and name != m["ip"]:
                entry["name"] = name
            if m["ttl"]:
                entry["ttl"] = int(m["ttl"])
            out["entries"].append(entry)
        m = re.search(r"Total entries:\s*(\d+)", text)
        if m:
            out["total"] = int(m.group(1))
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "arp",
                ip_address=e["ip_address"],
                mac_address=mac(e["mac_address"]),
                interface=e["interface"],
                type="permanent" if "permanent" in e["flags"] else "dynamic",
            )
            for e in data["entries"]
        ]


@register("junos", "show ipv6 neighbors [<address>]", intent="ipv6.neighbors")
class ShowIpv6Neighbors(Parser):
    """IPv6 neighbor cache."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"entries": []}
        for m in match_lines(
            r"^(?P<ip>[0-9a-fA-F:]+:[0-9a-fA-F:.]*)\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|none)\s+(?P<state>\S+)\s+(?P<exp>\d+)\s+(?P<rtr>yes|no)\s+(?P<sec>yes|no)\s+(?P<intf>\S+)\s*$",
            text,
        ):
            out["entries"].append(
                {
                    "ip_address": m["ip"],
                    "mac_address": none_if(m["mac"], "none"),
                    "state": m["state"],
                    "expire": int(m["exp"]),
                    "router": m["rtr"] == "yes",
                    "secure": m["sec"] == "yes",
                    "interface": m["intf"],
                }
            )
        m = re.search(r"Total entries:\s*(\d+)", text)
        if m:
            out["total"] = int(m.group(1))
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "ipv6.neighbors",
                ip_address=e["ip_address"],
                mac_address=mac(e["mac_address"]),
                interface=e["interface"],
                state=e["state"],
                age=e["expire"],
            )
            for e in data["entries"]
        ]


@register("junos", "show vlans [<vlan>] [(brief|detail|extensive)]")
class ShowVlans(Parser):
    """VLANs with tag, routing instance and member interfaces (``*`` = active)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith(("Routing instance", "Name ")):
                continue
            m = re.match(r"^(?P<ri>\S+)\s+(?P<name>\S+)\s+(?P<tag>\d+|NA|none)\s*(?P<intf>\S+)?\s*$", raw)
            if m and not raw.startswith(" "):
                cur = {"routing_instance": m["ri"], "name": m["name"], "tag": to_num(m["tag"]), "interfaces": []}
                out.append(cur)
                if m["intf"]:
                    _vlan_member(cur, m["intf"])
                continue
            m = re.match(r"^\s+(?P<intf>\S+)\s*$", raw)
            if m and cur is not None:
                _vlan_member(cur, m["intf"])
        return out


def _vlan_member(cur: Dict[str, Any], intf: str) -> None:
    cur["interfaces"].append({"interface": intf.rstrip("*"), "active": intf.endswith("*")})


@register(
    "junos",
    "show ethernet-switching table [(brief|detail|extensive|vlan-name <vlan>|interface <interface>)]",
    "show ethernet-switching table vlan-id <vlan>",
    intent="mac.table",
)
class ShowEthernetSwitchingTable(Parser):
    """MAC address table (ELS style)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"entries": []}
        m = re.search(r"Ethernet switching table\s*:\s*(\d+) entries,\s*(\d+) learned", text)
        if m:
            out["total"], out["learned"] = int(m.group(1)), int(m.group(2))
        ri = None
        for raw in text.splitlines():
            s = raw.strip()
            mm = re.match(r"^Routing instance\s*:\s*(\S+)", s)
            if mm:
                ri = mm.group(1)
                continue
            mm = re.match(
                r"^(?P<vlan>\S+)\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?P<flags>\S+)\s+(?P<age>\S+)\s+(?P<intf>\S+)(?:\s+(?P<nh>\d+))?(?:\s+(?P<rtr>\d+))?\s*$",
                s,
            )
            if mm:
                out["entries"].append(
                    compact(
                        {
                            "vlan": mm["vlan"],
                            "mac_address": mm["mac"],
                            "flags": mm["flags"],
                            "age": none_if(mm["age"]),
                            "interface": mm["intf"],
                            "nh_index": to_num(mm["nh"]) if mm["nh"] else None,
                            "rtr_id": to_num(mm["rtr"]) if mm["rtr"] else None,
                            "routing_instance": ri,
                        }
                    )
                )
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "mac.table",
                mac_address=mac(e["mac_address"]),
                vlan=e["vlan"],
                interface=e["interface"],
                type="static" if "S" in e["flags"] else "dynamic",
            )
            for e in data["entries"]
        ]


@register("junos", "show route instance [<instance>] [(detail|summary|extensive)]", intent="vrfs")
class ShowRouteInstance(Parser):
    """Routing instances (VRFs): type, state, RD, interfaces and tables."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if not re.search(r"^[ \t]*\S+:\s*$", text, re.M):
            # summary/brief table: Instance  Type  Primary RIB  Active/holddown/hidden
            cur = None
            for raw in text.splitlines():
                m = re.match(r"^(?P<name>\S+)\s+(?P<type>\S+)\s*$", raw)
                if m and not raw.startswith(" ") and m["name"] != "Instance":
                    cur = out.setdefault(m["name"], {"type": m["type"], "tables": {}})
                    continue
                m = re.match(r"^\s+(?P<table>\S+)\s+(?P<a>\d+)/(?P<h>\d+)/(?P<hid>\d+)", raw)
                if m and cur is not None:
                    cur["tables"][m["table"]] = {
                        "active": int(m["a"]),
                        "holddown": int(m["h"]),
                        "hidden": int(m["hid"]),
                    }
            return out
        cur = None
        section = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^(?P<name>\S+):$", s)
            if m and not raw.startswith("    ") and s not in ("Interfaces:", "Tables:"):
                cur = out[m["name"]] = {"interfaces": [], "tables": {}}
                section = None
                continue
            if cur is None:
                continue
            m = re.match(r"^Router ID: (\S+)", s)
            if m:
                cur["router_id"] = m.group(1)
                continue
            m = re.match(r"^Type: (?P<t>\S+)\s+State: (?P<st>\S+)", s)
            if m:
                cur["type"], cur["state"] = m["t"], m["st"]
                continue
            m = re.match(r"^Route-distinguisher: (\S+)", s)
            if m:
                cur["rd"] = m.group(1)
                continue
            m = re.match(r"^Vrf-(import|export): \[ (.+?) \]", s)
            if m:
                cur[f"vrf_{m.group(1)}"] = m.group(2).split()
                continue
            m = re.match(r"^Vrf-(import|export)-target: \[ (.+?) \]", s)
            if m:
                cur[f"vrf_{m.group(1)}_targets"] = m.group(2).split()
                continue
            if s == "Interfaces:":
                section = "interfaces"
                continue
            if s == "Tables:":
                section = "tables"
                continue
            if section == "interfaces":
                cur["interfaces"].append(s)
                continue
            if section == "tables":
                m = re.match(
                    r"^(?P<t>\S+?)\s*: (?P<r>\d+) routes \((?P<a>\d+) active, (?P<h>\d+) holddown, (?P<hid>\d+) hidden\)",
                    s,
                )
                if m:
                    cur["tables"][m["t"]] = {
                        "routes": int(m["r"]),
                        "active": int(m["a"]),
                        "holddown": int(m["h"]),
                        "hidden": int(m["hid"]),
                    }
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("vrfs", name=k, rd=v.get("rd"), interfaces=v.get("interfaces")) for k, v in data.items()]
