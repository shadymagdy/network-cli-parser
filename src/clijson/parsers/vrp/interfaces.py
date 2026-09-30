"""Huawei VRP interface commands."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import mac, record, status
from ...registry import Parser, register
from ...textutils import match_lines, none_if, snake, to_num

_FLAGS = {
    "(l)": "loopback",
    "(s)": "spoofing",
    "(E)": "e_trunk_down",
    "(b)": "bfd_down",
    "(B)": "bit_error_down",
    "(e)": "ethoam_down",
    "(d)": "dampening_suppressed",
    "(dl)": "dldp_down",
    "(lb)": "lbdt_block",
    "(v)": "virtual_port",
}


def _vrp_state(value: str) -> Dict[str, Any]:
    """``*down`` -> admin down, ``^down`` -> standby, ``up(s)`` -> up + spoofing flag."""
    out: Dict[str, Any] = {}
    v = value
    flags = re.findall(r"\([a-zA-Z]+\)", v)
    for f in flags:
        v = v.replace(f, "")
    if v.startswith("*"):
        out["state"], out["admin_down"] = "down", True
        v = v[1:]
    elif v.startswith("^"):
        out["state"], out["standby"] = "down", True
        v = v[1:]
    elif v.startswith(("#", "-")):
        out["state"] = "down"
        out["reason"] = {"#": "lbdt", "-": "link_flap"}[v[0]]
        v = v[1:]
    else:
        out["state"] = v.lower()
    if "state" not in out or out["state"] in ("", None):
        out["state"] = v.lower()
    if flags:
        out["flags"] = [_FLAGS.get(f, f.strip("()")) for f in flags]
    return out


def _split_intf_flags(name: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    m = re.match(r"^(?P<n>.+?)(?P<extra>(?:\([^)]*\))+)?$", name)
    out["interface"] = m["n"] if m else name
    if m and m["extra"]:
        for part in re.findall(r"\(([^)]*)\)", m["extra"]):
            if re.match(r"^\d+(?:\.\d+)?[GM]$", part):
                out["speed"] = part
            else:
                out.setdefault("flags", []).append(_FLAGS.get(f"({part})", part))
    return out


@register("vrp", "display interface brief [(main|<type>)]", "display interface <type> brief", intent="interfaces.brief")
class DisplayInterfaceBrief(Parser):
    """Physical/protocol state, utilisation and error counters (Eth-Trunk members nested)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        trunk: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            m = re.match(
                r"^(?P<indent>\s*)(?P<intf>[A-Za-z][\w\-/.:]*\d(?:\([^)]*\))*)\s+(?P<phy>[*^#\-]?\w+(?:\([a-zA-Z]+\))*)\s+(?P<proto>[*^]?\w+(?:\([a-zA-Z]+\))*)\s+(?P<inu>[\d.]+%|--)\s+(?P<outu>[\d.]+%|--)\s+(?P<inerr>\d+)\s+(?P<outerr>\d+)\s*$",
                raw,
            )
            if not m:
                continue
            phy, proto = _vrp_state(m["phy"]), _vrp_state(m["proto"])
            entry: Dict[str, Any] = {
                **_split_intf_flags(m["intf"]),
                "physical": phy["state"],
                "protocol": proto["state"],
                "input_utilization": _pct(m["inu"]),
                "output_utilization": _pct(m["outu"]),
                "input_errors": int(m["inerr"]),
                "output_errors": int(m["outerr"]),
            }
            if phy.get("admin_down"):
                entry["admin_down"] = True
            if phy.get("standby"):
                entry["standby"] = True
            flags = phy.get("flags", []) + proto.get("flags", []) + entry.pop("flags", [])
            if flags:
                entry["flags"] = flags
            if m["indent"] and trunk is not None:
                trunk.setdefault("members", []).append(entry)
                continue
            out.append(entry)
            trunk = entry if re.match(r"^(Eth-Trunk|Ip-Trunk|Trunk)\d+$", entry["interface"]) else None
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        res = []
        for r in data:
            for e in [r, *r.get("members", [])]:
                res.append(
                    record(
                        "interfaces.brief",
                        name=e["interface"],
                        admin_status="admin-down" if e.get("admin_down") else "up",
                        oper_status=status(e["protocol"]) if e["physical"] == "up" else "down",
                    )
                )
        return res


def _pct(v: str) -> Optional[float]:
    return None if v == "--" else float(v.rstrip("%"))


@register("vrp", "display ip interface brief [(<type>|vpn-instance <vrf>)]", intent="interfaces.brief")
class DisplayIpInterfaceBrief(Parser):
    """IPv4 address, mask and state per interface."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"interfaces": []}
        for key, rx in (
            ("up_physical", r"The number of interface that is UP in Physical is (\d+)"),
            ("down_physical", r"The number of interface that is DOWN in Physical is (\d+)"),
            ("up_protocol", r"The number of interface that is UP in Protocol is (\d+)"),
            ("down_protocol", r"The number of interface that is DOWN in Protocol is (\d+)"),
        ):
            m = re.search(rx, text)
            if m:
                out.setdefault("summary", {})[key] = int(m.group(1))
        for m in match_lines(
            r"^(?P<intf>[A-Za-z][\w\-/.:]*\d\S*)\s+(?P<ip>\d+\.\d+\.\d+\.\d+/\d+|unassigned)\s+(?P<phy>[*^]?\w+(?:\([a-zA-Z]+\))?)\s+(?P<proto>[*^]?\w+(?:\([a-zA-Z]+\))?)(?:\s+(?P<vrf>\S+))?\s*$",
            text,
        ):
            phy, proto = _vrp_state(m["phy"]), _vrp_state(m["proto"])
            e = {
                "interface": m["intf"],
                "ip_address": none_if(m["ip"], "unassigned"),
                "physical": phy["state"],
                "protocol": proto["state"],
            }
            if phy.get("admin_down"):
                e["admin_down"] = True
            if none_if(m["vrf"]):
                e["vpn_instance"] = m["vrf"]
            out["interfaces"].append(e)
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "interfaces.brief",
                name=e["interface"],
                admin_status="admin-down" if e.get("admin_down") else "up",
                oper_status=status(e["protocol"]),
                ip_address=e["ip_address"],
                vrf=e.get("vpn_instance"),
            )
            for e in data["interfaces"]
        ]


@register("vrp", "display interface description [<interface>]", intent="interfaces.description")
class DisplayInterfaceDescription(Parser):
    """Interface state and description."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<intf>[A-Za-z][\w\-/.:]*\d\S*)\s+(?P<phy>[*^#\-]?\w+(?:\([a-zA-Z]+\))?)\s+(?P<proto>[*^]?\w+(?:\([a-zA-Z]+\))?)(?:\s+(?P<desc>.*?))?\s*$",
            text,
        ):
            if m["intf"] in ("Interface",):
                continue
            phy, proto = _vrp_state(m["phy"]), _vrp_state(m["proto"])
            e = {
                "interface": m["intf"],
                "physical": phy["state"],
                "protocol": proto["state"],
                "description": m["desc"] or None,
            }
            if phy.get("admin_down"):
                e["admin_down"] = True
            out.append(e)
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "interfaces.description",
                name=e["interface"],
                admin_status="admin-down" if e.get("admin_down") else "up",
                oper_status=status(e["protocol"]),
                description=e["description"],
            )
            for e in data
        ]


def _pairs(line: str) -> Dict[str, Any]:
    """``Unicast:  0,  Multicast:  0`` -> {'unicast': 0, 'multicast': 0}."""
    out: Dict[str, Any] = {}
    for k, v in re.findall(r"([A-Za-z][\w ]*?)\s*:\s*([\d]+)", line):
        out[snake(k)] = int(v)
    return out


@register("vrp", "display interface [<interface>]", "display interface <type> <number>", intent="interfaces.detail")
class DisplayInterface(Parser):
    """Detailed interface state, addressing, rates, counters and errors."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        direction: Optional[str] = None
        in_trunk = False
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^(?P<name>\S+) current state\s*:\s*(?P<st>[\w ]+?)\s*(?:\((?P<extra>[^)]*)\))?\s*,?$", s)
            if m and not raw.startswith(" "):
                cur = out[m["name"]] = {
                    "physical_state": m["st"].strip().lower().replace("administratively down", "admin-down")
                }
                if m["extra"]:
                    em = re.search(r"ifindex:\s*(\d+)", m["extra"])
                    if em:
                        cur["ifindex"] = int(em.group(1))
                direction = None
                in_trunk = False
                continue
            if not cur:
                continue
            m = re.match(r"^Line protocol current state\s*:\s*(?P<st>\w+(?: \w+)?)(?:\s*\((?P<why>[^)]*)\))?", s)
            if m:
                cur["protocol_state"] = m["st"].lower()
                if m["why"]:
                    cur["protocol_note"] = m["why"]
                continue
            m = re.match(r"^Description\s*:\s*(?P<d>.*)$", s)
            if m:
                cur["description"] = m["d"].strip() or None
                continue
            m = re.match(r"^(?P<mode>Route Port|Switch Port)\s*,\s*(?P<rest>.*)$", s)
            if m:
                cur["port_mode"] = m["mode"].split()[0].lower()
                mm = re.search(r"(?:Maximum Transmit Unit|MTU) is (\d+)", m["rest"])
                if mm:
                    cur["mtu"] = int(mm.group(1))
                mm = re.search(r"Link-type\s*:\s*(\S+?),", m["rest"])
                if mm:
                    cur["link_type"] = mm.group(1)
                continue
            m = re.match(r"^PVID\s*:\s*(\d+)", s)
            if m:
                cur["pvid"] = int(m.group(1))
                mm = re.search(r"Maximum Frame Length is (\d+)", s)
                if mm:
                    cur["max_frame_length"] = int(mm.group(1))
                mm = re.search(r"Current BW: (\S+?),", s)
                if mm:
                    cur["current_bandwidth"] = mm.group(1)
                continue
            m = re.match(
                r"^Internet Address is (?:(?P<how>negotiated|allocated by \w+|unnumbered), )?(?P<ip>\d+\.\d+\.\d+\.\d+/\d+)(?P<sub> Sub)?",
                s,
            )
            if m:
                cur.setdefault("ipv4_addresses", []).append(m["ip"])
                if m["how"]:
                    cur["address_assignment"] = m["how"]
                continue
            m = re.match(r"^Internet protocol processing\s*:\s*(\w+)", s)
            if m:
                cur["ip_processing"] = m.group(1)
                continue
            m = re.match(r"^IP Sending Frames' Format is (?P<f>[^,]+), Hardware address is (?P<mac>\S+)", s)
            if m:
                cur["frame_format"], cur["mac_address"] = m["f"], m["mac"]
                continue
            m = re.match(r"^Last physical (up|down) time\s*:\s*(?P<t>.+)$", s)
            if m:
                cur[f"last_physical_{m.group(1)}"] = none_if(m["t"].strip())
                continue
            m = re.match(r"^Last line protocol (up|down) time\s*:\s*(?P<t>.+)$", s)
            if m:
                cur[f"last_protocol_{m.group(1)}"] = none_if(m["t"].strip())
                continue
            m = re.match(
                r"^Port BW\s*:\s*(?P<bw>[^,]+)(?:, Transceiver max BW\s*:\s*(?P<tbw>[^,]+))?(?:, Transceiver Mode\s*:\s*(?P<tm>\S+))?",
                s,
            )
            if m:
                cur["port_bandwidth"] = m["bw"].strip()
                if m["tbw"]:
                    cur["transceiver_max_bandwidth"] = m["tbw"].strip()
                if m["tm"]:
                    cur["transceiver_mode"] = m["tm"]
                continue
            m = re.match(r"^Speed\s*:\s*(?P<sp>\w+)\s*,\s*Loopback\s*:\s*(?P<lb>\w+)", s)
            if m:
                cur["speed"], cur["loopback"] = to_num(m["sp"]), m["lb"]
                continue
            m = re.match(r"^Duplex\s*:\s*(?P<d>\w+)\s*,\s*Negotiation\s*:\s*(?P<n>\w+)", s)
            if m:
                cur["duplex"], cur["negotiation"] = m["d"].lower(), m["n"].lower()
                continue
            m = re.match(
                r"^(?:Last (?P<n>\d+) seconds|Realtime (?P<rt>\d+) seconds) (?P<dir>input|output) rate:?\s*(?:(?P<Bps>\d+) bytes/sec,?\s*)?(?P<bps>\d+) bits/sec,\s*(?P<pps>\d+) packets/sec",
                s,
            )
            if m:
                if m["n"]:
                    cur["rate_interval_seconds"] = int(m["n"])
                    cur[f"{m['dir']}_rate_bps"] = int(m["bps"])
                    cur[f"{m['dir']}_rate_pps"] = int(m["pps"])
                continue
            m = re.match(r"^(?P<dir>Input|Output)\s*:\s*(?P<p>\d+) [Pp]ackets,\s*(?P<b>\d+) [Bb]ytes", s)
            if m:
                direction = m["dir"].lower()
                c = cur.setdefault("counters", {})
                c[f"{direction}_packets"], c[f"{direction}_bytes"] = int(m["p"]), int(m["b"])
                continue
            m = re.match(r"^(?P<dir>Input|Output) bandwidth utilization\s*:\s*(?P<u>[\d.]+%|--)", s)
            if m:
                cur[f"{m['dir'].lower()}_utilization"] = _pct(m["u"])
                continue
            if re.match(r"^-+$", s):
                continue
            if s.startswith("PortName"):
                in_trunk = True
                cur["members"] = []
                continue
            if in_trunk:
                m = re.match(r"^(?P<p>\S+)\s+(?P<st>UP|DOWN|Up|Down|Selected|Unselect)\s+(?P<w>\d+)$", s)
                if m:
                    cur["members"].append({"interface": m["p"], "status": m["st"].lower(), "weight": int(m["w"])})
                    continue
                m = re.match(r"^The Number of (UP )?Ports in Trunk\s*:\s*(\d+)", s)
                if m:
                    cur["up_members" if m.group(1) else "member_count"] = int(m.group(2))
                    continue
            if direction and ":" in s:
                pairs = _pairs(s)
                if pairs:
                    c = cur.setdefault("counters", {})
                    for k, v in pairs.items():
                        c[f"{direction}_{k}"] = v
                    continue
            if direction:
                # "0 unicast,0 broadcast,0 multicast" style
                found = re.findall(r"(\d+)\s+([a-z][a-z ]*?)(?:,|$)", s)
                if found:
                    c = cur.setdefault("counters", {})
                    for v, k in found:
                        c[f"{direction}_{snake(k)}"] = int(v)
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        res = []
        for name, d in data.items():
            c = d.get("counters", {})
            res.append(
                record(
                    "interfaces.detail",
                    name=name,
                    admin_status="admin-down" if "admin" in d.get("physical_state", "") else "up",
                    oper_status=status(d.get("protocol_state")),
                    description=d.get("description"),
                    mac_address=mac(d.get("mac_address")),
                    mtu=d.get("mtu"),
                    ipv4_addresses=d.get("ipv4_addresses", []),
                    input_rate_bps=d.get("input_rate_bps"),
                    output_rate_bps=d.get("output_rate_bps"),
                    input_packets=c.get("input_packets"),
                    output_packets=c.get("output_packets"),
                    input_errors=c.get("input_total_error", c.get("input_errors")),
                    output_errors=c.get("output_total_error", c.get("output_errors")),
                )
            )
        return res


@register("vrp", "display eth-trunk [<trunk>] [(verbose|brief)]", intent="lag")
class DisplayEthTrunk(Parser):
    """Eth-Trunk (LAG) mode, status, hashing and member/partner ports."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        section = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^(?P<name>Eth-Trunk\d+)'s state information is:", s)
            if m:
                cur = out[m["name"]] = {"members": {}}
                section = None
                continue
            if not cur:
                continue
            if s in ("Local:", "Partner:"):
                section = s[:-1].lower()
                continue
            if re.match(r"^-+$", s):
                continue
            if s.startswith(("PortName", "ActorPortName")):
                section = section or "local"
                continue
            m = re.match(r"^(?P<p>\S+)\s+(?P<st>Up|Down|Selected|Unselect|Indep)\s+(?P<w>\d+)$", s)
            if m:
                cur["members"][m["p"]] = {"status": m["st"].lower(), "weight": int(m["w"])}
                continue
            m = re.match(
                r"^(?P<p>\S+)\s+(?P<st>Selected|Unselect|Indep)\s+(?P<type>\S+)\s+(?P<pri>\d+)\s+(?P<no>\d+)\s+(?P<key>\d+)\s+(?P<state>[01]+)\s+(?P<w>\d+)$",
                s,
            )
            if m:
                cur["members"][m["p"]] = {
                    "status": m["st"].lower(),
                    "port_type": m["type"],
                    "port_priority": int(m["pri"]),
                    "port_number": int(m["no"]),
                    "port_key": int(m["key"]),
                    "port_state": m["state"],
                    "weight": int(m["w"]),
                }
                continue
            m = re.match(
                r"^(?P<p>\S+)\s+(?P<pri>\d+)\s+(?P<sid>[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(?P<ppri>\d+)\s+(?P<no>\d+)\s+(?P<key>\d+)\s+(?P<state>[01]+)$",
                s,
            )
            if m and section == "partner":
                cur["members"].setdefault(m["p"], {})["partner"] = {
                    "system_priority": int(m["pri"]),
                    "system_id": m["sid"],
                    "port_priority": int(m["ppri"]),
                    "port_number": int(m["no"]),
                    "port_key": int(m["key"]),
                    "port_state": m["state"],
                }
                continue
            for k, v in re.findall(r"([A-Z][\w\- ]*?)\s*:\s*(.+?)(?=\s{2,}[A-Z][\w\- ]*?\s*:|$)", s):
                cur[snake(k)] = to_num(v.strip())
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record("lag", name=k, status=status(str(v.get("operate_status", ""))), members=list(v["members"]))
            for k, v in data.items()
        ]


@register("vrp", "display port vlan [(active|<interface>)]")
class DisplayPortVlan(Parser):
    """Port link-type, PVID and allowed VLANs."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for raw in text.splitlines():
            m = re.match(
                r"^(?P<p>[A-Za-z][\w\-/.:]*\d\S*)\s+(?P<lt>access|trunk|hybrid|dot1q-tunnel|desirable|auto|--)\s+(?P<pvid>\d+|-)\s*(?P<vl>.*?)\s*$",
                raw,
            )
            if m:
                out.append(
                    {
                        "interface": m["p"],
                        "link_type": m["lt"],
                        "pvid": to_num(m["pvid"]) if m["pvid"] != "-" else None,
                        "vlans": _vlan_list(m["vl"]),
                    }
                )
                continue
            m = re.match(r"^ {20,}(?P<vl>[\d\-][\d\- ]*)$", raw)
            if m and out:
                out[-1]["vlans"].extend(_vlan_list(m["vl"]))
        return out


def _vlan_list(v: str) -> List[Any]:
    items: List[Any] = []
    for tok in v.split():
        if tok in ("-", "--"):
            continue
        items.append(to_num(tok))
    return items


@register("vrp", "display vlan [(summary|<vlan>)]", "display vlan brief")
class DisplayVlan(Parser):
    """VLANs with type/status and tagged/untagged member ports (and their state)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"vlans": {}}
        m = re.search(r"The total number of vlans is\s*:\s*(\d+)", text, re.I)
        if m:
            out["total"] = int(m.group(1))
        cur: Optional[Dict[str, Any]] = None
        mode: Optional[str] = None
        table: Optional[str] = None
        for raw in text.splitlines():
            if re.match(r"^\s*VID\s+(Type\s+Ports|Ports|Name\s+Status\s+Ports|Type\s+Status\s+Ports)", raw) or re.match(
                r"^\s*VID\s+Type\s+Ports", raw
            ):
                table = "ports"
                continue
            if re.match(r"^\s*(VID|VLAN ID)\s+(Type\s+)?Status\s+", raw):
                table = "props"
                continue
            if table is None or not raw.strip() or re.match(r"^-+\s*$", raw.strip()):
                continue
            if table == "props":
                m = re.match(
                    r"^\s*(?P<vid>\d+)\s+(?P<type>common|super|sub|mux|dynamic|\S+)\s+(?P<st>enable|disable)\s+(?P<rest>.*?)\s*$",
                    raw,
                )
                if m:
                    v = out["vlans"].setdefault(m["vid"], {"untagged": [], "tagged": []})
                    v["type"], v["status"] = m["type"], m["st"]
                    dm = re.search(
                        r"(?:FWD|DSD|forward|discard)\s+(?:FWD|DSD|forward|discard)\s+(?:FWD|DSD|forward|discard)\s+(?P<desc>\S.*?)?(?:\s{2,}\*.*)?$",
                        m["rest"],
                    )
                    if dm and dm["desc"] and not dm["desc"].startswith(("default", "*")):
                        v["description"] = dm["desc"].strip()
                continue
            m = re.match(
                r"^\s*(?P<vid>\d+)\s+(?:(?P<type>common|super|sub|mux|dynamic)\s+)?(?:(?P<name>(?!UT:|TG:|MP:|ST:|enable|disable)\S+)\s+)?(?:(?P<st>enable|disable)\s+)?(?P<rest>(?:UT|TG|MP|ST):.*)?$",
                raw,
            )
            if m and (m["rest"] or m["st"] or m["type"]):
                cur = out["vlans"].setdefault(m["vid"], {"untagged": [], "tagged": []})
                if m["type"]:
                    cur["type"] = m["type"]
                if m["name"]:
                    cur["name"] = m["name"]
                if m["st"]:
                    cur["status"] = m["st"]
                mode = None
                if m["rest"]:
                    mode = _vlan_ports(cur, m["rest"], mode)
                continue
            if cur is not None and raw.startswith(" "):
                mode = _vlan_ports(cur, raw.strip(), mode)
        return out


def _vlan_ports(cur: Dict[str, Any], s: str, mode: Optional[str]) -> Optional[str]:
    for tok in re.findall(r"(?:UT|TG|MP|ST):|\S+", s):
        if tok.endswith(":") and tok[:-1] in ("UT", "TG", "MP", "ST"):
            mode = {"UT": "untagged", "TG": "tagged", "MP": "mapping", "ST": "stacking"}[tok[:-1]]
            cur.setdefault(mode, [])
            continue
        if mode is None:
            continue
        m = re.match(r"^(?P<p>.+?)\((?P<st>[UD])\)$", tok)
        if m:
            cur[mode].append({"interface": m["p"], "state": "up" if m["st"] == "U" else "down"})
        else:
            cur[mode].append({"interface": tok})
    return mode
