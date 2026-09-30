"""IOS XR interface commands."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ...models import mac, record, status
from ...registry import Parser, register
from ...textutils import match_lines, none_if, to_num

_IFACE_HDR = re.compile(
    r"^\s*(?P<name>\S+) is (?P<admin>administratively down|up|down|deleted|shutdown|not ready|admin-down)(?:\s*\([^)]*\))?,\s+"
    r"line protocol is (?P<oper>administratively down|up|down|deleted|dormant|not ready|admin-down)(?:\s*\([^)]*\))?\s*$"
)


def _counter_line(line: str, d: Dict[str, Any]) -> None:
    """Parse comma separated ``<number> <label>`` counters into *d*."""
    for num, label in re.findall(r"(\d+)\s+([A-Za-z][\w\- ]*?)(?=,|$)", line.strip()):
        key = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
        d[key] = int(num)


@register(
    "iosxr",
    "show interfaces [<interface>] [(detail|accounting)]",
    "show interface [<interface>] [detail]",
    intent="interfaces.detail",
)
class ShowInterfaces(Parser):
    """Detailed interface state, addressing, rates and counters."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        in_members = False
        for raw in text.splitlines():
            ln = raw.strip()
            if not ln:
                continue
            m = _IFACE_HDR.match(raw)
            if m:
                cur = {"admin_status": _xr_state(m["admin"]), "oper_status": _xr_state(m["oper"])}
                out[m["name"]] = cur
                in_members = False
                continue
            if not cur:
                continue
            if in_members:
                mm = re.match(r"^(?P<name>\S+)\s+(?P<duplex>\S+-duplex|\S+)\s+(?P<speed>\S+)\s+(?P<state>\S+)\s*$", ln)
                if mm and "/" in mm["name"]:
                    cur["bundle_members"][mm["name"]] = {
                        "duplex": mm["duplex"],
                        "speed": mm["speed"],
                        "state": mm["state"],
                    }
                    continue
                in_members = False
            if _match(r"^Interface state transitions: (?P<n>\d+)", ln, cur, n="state_transitions"):
                continue
            m = re.match(r"^Hardware is (?P<hw>.+?)(?:, address is (?P<mac>\S+)(?: \(bia (?P<bia>\S+)\))?)?$", ln)
            if m:
                cur["hardware"] = m["hw"]
                if m["mac"]:
                    cur["mac_address"] = m["mac"]
                if m["bia"]:
                    cur["bia"] = m["bia"]
                continue
            m = re.match(r"^Description: ?(?P<d>.*)$", ln)
            if m:
                cur["description"] = m["d"].strip()
                continue
            m = re.match(r"^Internet address is (?P<ip>\S+)", ln)
            if m:
                cur["ipv4_address"] = none_if(m["ip"], "unknown")
                continue
            m = re.match(r"^Secondary address (?P<ip>\S+)", ln)
            if m:
                cur.setdefault("ipv4_secondary", []).append(m["ip"])
                continue
            m = re.match(r"^MTU (?P<mtu>\d+) bytes, BW (?P<bw>\d+) Kbit(?: \(Max: (?P<max>\d+) Kbit\))?", ln)
            if m:
                cur["mtu"] = int(m["mtu"])
                cur["bandwidth_kbps"] = int(m["bw"])
                if m["max"]:
                    cur["max_bandwidth_kbps"] = int(m["max"])
                continue
            m = re.match(r"^reliability (?P<r>\S+), txload (?P<tx>\S+), rxload (?P<rx>\S+)$", ln)
            if m:
                cur["reliability"], cur["txload"], cur["rxload"] = m["r"], m["tx"], m["rx"]
                continue
            m = re.match(
                r"^Encapsulation (?P<enc>[^,]+),?(?:\s*VLAN Id (?P<vlan>\d+),?)?(?:.*?loopback (?P<lb>not set|set))?",
                ln,
            )
            if m:
                cur["encapsulation"] = m["enc"].strip()
                if m["vlan"]:
                    cur["vlan_id"] = int(m["vlan"])
                if m["lb"]:
                    cur["loopback"] = m["lb"]
                continue
            m = re.match(r"^Outer Match: Dot1Q VLAN (?P<v>\S+)", ln)
            if m:
                cur["vlan_id"] = to_num(m["v"])
                continue
            m = re.match(
                r"^(?P<duplex>Full-duplex|Half-duplex|Duplex unknown), (?P<speed>[^,]+)(?:, (?P<media>[^,]+))?(?:, link type is (?P<lt>\S+))?",
                ln,
            )
            if m:
                cur["duplex"] = m["duplex"].replace("Duplex unknown", "unknown").replace("-duplex", "").lower()
                cur["speed"] = m["speed"]
                if m["media"]:
                    cur["media_type"] = m["media"]
                if m["lt"]:
                    cur["link_type"] = m["lt"]
                continue
            m = re.match(r"^output flow control is (?P<o>\w+), input flow control is (?P<i>\w+)", ln)
            if m:
                cur["flow_control"] = {"output": m["o"], "input": m["i"]}
                continue
            if ln.startswith("loopback "):
                cur["loopback"] = ln.split(" ", 1)[1].rstrip(",")
                continue
            if ln == "Layer 2 Transport Mode":
                cur["l2_transport"] = True
                continue
            m = re.match(r"^Last link flapped (?P<v>.+)$", ln)
            if m:
                cur["last_link_flapped"] = m["v"]
                continue
            m = re.match(r"^ARP type (?P<t>\S+), ARP timeout (?P<to>\S+)", ln)
            if m:
                cur["arp_type"], cur["arp_timeout"] = m["t"], m["to"]
                continue
            m = re.match(
                r"^Carrier delay \(up\) is (?P<up>\d+) msec(?:, Carrier delay \(down\) is (?P<down>\d+) msec)?", ln
            )
            if m:
                cur["carrier_delay_up_ms"] = int(m["up"])
                if m["down"]:
                    cur["carrier_delay_down_ms"] = int(m["down"])
                continue
            m = re.match(r"^No\. of members in this bundle: (?P<n>\d+)", ln)
            if m:
                cur["bundle_member_count"] = int(m["n"])
                cur["bundle_members"] = {}
                in_members = True
                continue
            m = re.match(r"^Last input (?P<i>[^,]+), output (?P<o>.+)$", ln)
            if m:
                cur["last_input"], cur["last_output"] = m["i"], m["o"]
                continue
            m = re.match(r'^Last clearing of "show interface" counters (?P<v>.+)$', ln)
            if m:
                cur["last_clearing"] = m["v"]
                continue
            if ln.startswith("Input/output data rate is disabled"):
                cur["data_rate_disabled"] = True
                continue
            m = re.match(
                r"^(?P<n>\d+) (?P<unit>minute|second)s? (?P<dir>input|output) rate (?P<bps>\d+) bits/sec, (?P<pps>\d+) packets/sec",
                ln,
            )
            if m:
                cur["rate_interval_seconds"] = int(m["n"]) * (60 if m["unit"] == "minute" else 1)
                cur[f"{m['dir']}_rate_bps"] = int(m["bps"])
                cur[f"{m['dir']}_rate_pps"] = int(m["pps"])
                continue
            m = re.match(
                r"^(?P<p>\d+) packets (?P<dir>input|output), (?P<b>\d+) bytes(?:, (?P<d>\d+) total (?:input|output) drops)?",
                ln,
            )
            if m:
                c = cur.setdefault("counters", {})
                c[f"{m['dir']}_packets"] = int(m["p"])
                c[f"{m['dir']}_bytes"] = int(m["b"])
                if m["d"]:
                    c[f"{m['dir']}_drops"] = int(m["d"])
                continue
            m = re.match(r"^(?:Received|Output) (?P<b>\d+) broadcast packets, (?P<mc>\d+) multicast packets", ln)
            if m:
                d = "input" if ln.startswith("Received") else "output"
                c = cur.setdefault("counters", {})
                c[f"{d}_broadcast"] = int(m["b"])
                c[f"{d}_multicast"] = int(m["mc"])
                continue
            if (re.match(r"^\d+ ", ln) and "counters" in cur) or re.match(
                r"^\d+ (?:runts|input errors|output errors|drops for|output buffer|carrier|input drops|output drops)",
                ln,
            ):
                c = cur.setdefault("counters", {})
                _counter_line(ln, c)
                continue
        for data in out.values():
            c = data.get("counters", {})
            if "drops_for_unrecognized_upper_level_protocol" in c:
                c["unknown_protocol_drops"] = c.pop("drops_for_unrecognized_upper_level_protocol")
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        out = []
        for name, d in data.items():
            c = d.get("counters", {})
            ips = [d["ipv4_address"]] if d.get("ipv4_address") else []
            ips += d.get("ipv4_secondary", [])
            out.append(
                record(
                    "interfaces.detail",
                    name=name,
                    admin_status=status(d.get("admin_status")),
                    oper_status=status(d.get("oper_status")),
                    description=d.get("description"),
                    mac_address=mac(d.get("mac_address")),
                    mtu=d.get("mtu"),
                    bandwidth_kbps=d.get("bandwidth_kbps"),
                    ipv4_addresses=ips,
                    input_rate_bps=d.get("input_rate_bps"),
                    output_rate_bps=d.get("output_rate_bps"),
                    input_packets=c.get("input_packets"),
                    output_packets=c.get("output_packets"),
                    input_errors=c.get("input_errors"),
                    output_errors=c.get("output_errors"),
                )
            )
        return out


def _xr_state(s: str) -> str:
    return {"administratively down": "admin-down"}.get(s, s)


def _match(pattern: str, line: str, d: Dict[str, Any], **names: str) -> bool:
    m = re.match(pattern, line)
    if not m:
        return False
    for group, key in names.items():
        d[key] = to_num(m.group(group))
    return True


@register(
    "iosxr",
    "show (ip|ipv4) interface brief [vrf (all|<vrf>)] [<interface>]",
    "show (ip|ipv4) vrf (all|<vrf>) interface brief",
    "show ipv4 interface brief summary",
    intent="interfaces.brief",
)
class ShowIpv4InterfaceBrief(Parser):
    """IPv4 address, status and VRF of every interface."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<intf>[A-Za-z]\S*\d\S*)\s+(?P<ip>\S+)\s+(?P<status>Up|Down|Shutdown|Deleted|Unknown|\w+)\s+(?P<proto>Up|Down|Shutdown|Deleted|Unknown|\w+)(?:\s+(?P<vrf>\S+))?\s*$",
            text,
        ):
            if m["intf"].lower() == "interface":
                continue
            out.append(
                {
                    "interface": m["intf"],
                    "ip_address": none_if(m["ip"], "unassigned"),
                    "status": m["status"],
                    "protocol": m["proto"],
                    "vrf": m["vrf"] or "default",
                }
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "interfaces.brief",
                name=r["interface"],
                admin_status="admin-down"
                if r["status"].lower() == "shutdown"
                else ("up" if r["status"].lower() != "deleted" else "down"),
                oper_status=status(r["protocol"]) if r["protocol"].lower() != "shutdown" else "down",
                ip_address=r["ip_address"],
                vrf=r["vrf"],
            )
            for r in data
        ]


@register("iosxr", "show (ipv6|ip) interface brief [vrf (all|<vrf>)]", "show ipv6 vrf (all|<vrf>) interface brief")
class ShowIpv6InterfaceBrief(Parser):
    """IPv6 addresses per interface (``show ipv6 interface brief``)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur = None
        for ln in text.splitlines():
            m = re.match(r"^(?P<intf>\S+)\s+\[(?P<status>[\w\-]+)/(?P<proto>[\w\-]+)\](?:\s+(?P<vrf>\S+))?", ln)
            if m:
                cur = out[m["intf"]] = {"status": m["status"], "protocol": m["proto"], "addresses": []}
                if m["vrf"]:
                    cur["vrf"] = m["vrf"]
                continue
            m = re.match(r"^\s+(?P<addr>[0-9a-fA-F:]+:[0-9a-fA-F:]*|unassigned)\s*$", ln)
            if m and cur is not None and m["addr"] != "unassigned":
                cur["addresses"].append(m["addr"])
        return out


@register(
    "iosxr", "show interfaces brief", "show interface brief", "show interfaces summary brief", intent="interfaces.brief"
)
class ShowInterfacesBrief(Parser):
    """One line per interface: state, encapsulation, MTU, bandwidth."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<intf>\S+)\s+(?P<state>up|down|admin-down|not-ready|deleted|\S+)\s+(?P<linep>up|down|admin-down|not-ready|deleted|\S+)\s+(?P<encap>\S+(?: \S+)?)\s+(?P<mtu>\d+)\s+(?P<bw>\d+)\s*$",
            text,
        ):
            out.append(
                {
                    "interface": m["intf"],
                    "state": m["state"],
                    "line_protocol_state": m["linep"],
                    "encapsulation": m["encap"],
                    "mtu": int(m["mtu"]),
                    "bandwidth_kbps": int(m["bw"]),
                }
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "interfaces.brief",
                name=r["interface"],
                admin_status="admin-down" if r["state"] == "admin-down" else "up",
                oper_status=status(r["line_protocol_state"]),
            )
            for r in data
        ]


@register("iosxr", "show interfaces description", "show interface description", intent="interfaces.description")
class ShowInterfacesDescription(Parser):
    """Interface status and description."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for ln in text.splitlines():
            m = re.match(
                r"^(?P<intf>[A-Za-z]\S*\d\S*)\s+(?P<status>up|down|admin-down|deleted|not-ready|\S+)\s+(?P<proto>up|down|admin-down|deleted|not-ready|\S+)(?:\s+(?P<desc>.*?))?\s*$",
                ln.strip(),
            )
            if not m or m["intf"] == "Interface":
                continue
            out.append(
                {
                    "interface": m["intf"],
                    "status": m["status"],
                    "protocol": m["proto"],
                    "description": m["desc"] or None,
                }
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "interfaces.description",
                name=r["interface"],
                admin_status="admin-down" if r["status"] in ("admin-down", "deleted") else "up",
                oper_status=status(r["protocol"]),
                description=r["description"],
            )
            for r in data
        ]


@register("iosxr", "show interfaces summary", "show interface summary")
class ShowInterfacesSummary(Parser):
    """Interface counts per type (total/up/down/admin-down)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in match_lines(
            r"^\s*(?P<type>[A-Z][A-Z_ ]*?[A-Z])\s+(?P<total>\d+)\s+(?P<up>\d+)\s+(?P<down>\d+)\s+(?P<admin>\d+)\s*$",
            text,
        ):
            key = "all" if m["type"] == "ALL TYPES" else m["type"]
            out[key] = {
                "total": int(m["total"]),
                "up": int(m["up"]),
                "down": int(m["down"]),
                "admin_down": int(m["admin"]),
            }
        return out


@register(
    "iosxr",
    "show ipv4 interface [<interface>]",
    "show ipv4 vrf (all|<vrf>) interface [<interface>]",
    "show ip interface [<interface>]",
)
class ShowIpv4Interface(Parser):
    """Per-interface IPv4 configuration (addresses, MTU, ACLs, ICMP settings)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        for raw in text.splitlines():
            ln = raw.strip()
            m = re.match(
                r"^(?P<name>\S+) is (?P<admin>[\w ]+?), (?:ipv4 protocol|line protocol) is (?P<oper>[\w ]+?)\s*$", ln
            )
            if m:
                cur = out[m["name"]] = {"status": m["admin"], "protocol": m["oper"]}
                continue
            if not cur:
                continue
            m = re.match(r"^Vrf is (?P<vrf>\S+)(?: \(vrfid (?P<id>\S+)\))?", ln)
            if m:
                cur["vrf"] = m["vrf"]
                if m["id"]:
                    cur["vrf_id"] = m["id"]
                continue
            m = re.match(r"^Internet address is (?P<ip>\S+)", ln)
            if m:
                cur["ipv4_address"] = none_if(m["ip"], "unassigned", "unknown")
                continue
            m = re.match(r"^Secondary address (?P<ip>\S+)", ln)
            if m:
                cur.setdefault("secondary_addresses", []).append(m["ip"])
                continue
            m = re.match(r"^MTU is (?P<mtu>\d+) \((?P<ip>\d+) is available to IP\)", ln)
            if m:
                cur["mtu"], cur["ip_mtu"] = int(m["mtu"]), int(m["ip"])
                continue
            m = re.match(
                r"^(Helper address|Directed broadcast forwarding|Outgoing access list|Inbound\s+access list|Inbound common access list|Outgoing Common access list|Proxy ARP|ICMP redirects|ICMP unreachables|ICMP mask replies|Table Id) is (?P<v>.+)$",
                ln,
            )
            if m:
                key = re.sub(r"\s+", "_", m.group(1).strip().lower())
                cur[key] = m["v"]
                continue
            m = re.match(r"^Multicast reserved groups joined: (?P<g>.+)$", ln)
            if m:
                cur["multicast_groups"] = m["g"].split()
        return out
