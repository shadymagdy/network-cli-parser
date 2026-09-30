"""Junos interface commands."""

from __future__ import annotations

import re
from typing import Any

from ...models import mac, record, status
from ...registry import Parser, register
from ...textutils import match_lines, none_if, snake, to_num


@register(
    "junos",
    "show interfaces [<interface>] terse",
    "show interfaces terse [<interface>]",
    "show interfaces terse routing-instance (all|<instance>)",
    intent="interfaces.brief",
)
class ShowInterfacesTerse(Parser):
    """Admin/link state and addresses per family for physical and logical interfaces."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur: dict[str, Any] | None = None
        fam: dict[str, Any] | None = None
        for raw in text.splitlines():
            if not raw.strip() or re.match(r"^\s*Interface\s+Admin\s+Link", raw):
                continue
            m = re.match(
                r"^(?P<name>\S+)\s+(?P<admin>up|down)\s+(?P<link>up|down)(?:\s+(?P<proto>\S+))?(?:\s+(?P<local>\S+))?(?:\s+(?:-->\s*)?(?P<remote>\S+))?\s*$",
                raw,
            )
            if m and not raw.startswith(" "):
                cur = {"interface": m["name"], "admin": m["admin"], "link": m["link"], "families": []}
                out.append(cur)
                fam = None
                if m["proto"]:
                    fam = {"family": m["proto"], "addresses": []}
                    cur["families"].append(fam)
                    _addr(fam, m["local"], m["remote"])
                continue
            if cur is None:
                continue
            m = re.match(
                r"^\s{20,}(?P<proto>[a-z][\w\-]*)(?:\s+(?P<local>\S+))?(?:\s+(?:-->\s*)?(?P<remote>\S+))?\s*$", raw
            )
            if m and len(raw) - len(raw.lstrip()) < 45 and not re.match(r"^[\d.:a-f/]+$", m["proto"]):
                fam = {"family": m["proto"], "addresses": []}
                cur["families"].append(fam)
                _addr(fam, m["local"], m["remote"])
                continue
            m = re.match(r"^\s+(?P<local>\S+)(?:\s+(?:-->\s*)?(?P<remote>\S+))?\s*$", raw)
            if m and fam is not None:
                _addr(fam, m["local"], m["remote"])
        return out

    def normalize(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        res = []
        for r in data:
            ip = next((a["local"] for f in r["families"] if f["family"] == "inet" for a in f["addresses"]), None)
            res.append(
                record(
                    "interfaces.brief",
                    name=r["interface"],
                    admin_status=status(r["admin"]) if r["admin"] == "up" else "admin-down",
                    oper_status=status(r["link"]),
                    ip_address=ip,
                )
            )
        return res


def _addr(fam: dict[str, Any], local: str | None, remote: str | None) -> None:
    if local:
        a = {"local": local}
        if remote:
            a["remote"] = remote
        fam["addresses"].append(a)


@register("junos", "show interfaces descriptions [<interface>]", intent="interfaces.description")
class ShowInterfacesDescriptions(Parser):
    """Interface admin/link state and description."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(r"^(?P<name>\S+)\s+(?P<admin>up|down)\s+(?P<link>up|down)\s+(?P<desc>.*?)\s*$", text):
            out.append({"interface": m["name"], "admin": m["admin"], "link": m["link"], "description": m["desc"]})
        return out

    def normalize(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            record(
                "interfaces.description",
                name=r["interface"],
                admin_status="up" if r["admin"] == "up" else "admin-down",
                oper_status=status(r["link"]),
                description=r["description"],
            )
            for r in data
        ]


_KV_SPLIT = re.compile(r",\s+")


def _kv_line(line: str) -> dict[str, Any]:
    """``Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps`` -> dict."""
    out: dict[str, Any] = {}
    for part in _KV_SPLIT.split(line.strip().rstrip(",")):
        if ":" not in part:
            if part.strip():
                out.setdefault("flags", []).append(part.strip())
            continue
        k, v = part.split(":", 1)
        v = v.strip().rstrip(",")
        out[snake(k)] = to_num(v) if v != "" else None
    return out


@register(
    "junos",
    "show interfaces [<interface>] [(detail|extensive|statistics|brief|media)]",
    "show interfaces (detail|extensive|statistics) [<interface>]",
    intent="interfaces.detail",
)
class ShowInterfaces(Parser):
    """Physical and logical interfaces: state, speed, MAC, counters, errors, families and addresses."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        phy: dict[str, Any] = {}
        logical: dict[str, Any] | None = None
        proto: dict[str, Any] | None = None
        section: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(
                r"^Physical interface: (?P<name>[^,\s]+),\s*(?P<admin>Enabled|Administratively down|Disabled),\s*Physical link is (?P<link>\w+)",
                s,
            )
            if m:
                phy = out[m["name"]] = {
                    "admin_status": "up" if m["admin"] == "Enabled" else "down",
                    "oper_status": m["link"].lower(),
                    "logical_interfaces": {},
                }
                logical = proto = None
                section = None
                continue
            m = re.match(
                r"^Logical interface (?P<name>\S+) \(Index (?P<idx>\d+)\)(?: \(SNMP ifIndex (?P<snmp>\d+)\))?(?: \(Generation (?P<gen>\d+)\))?",
                s,
            )
            if m:
                parent_name = m["name"].rsplit(".", 1)[0]
                if not phy:
                    # "show interfaces irb.100" style output: no physical header
                    phy = out.setdefault(parent_name, {"logical_interfaces": {}})
                elif parent_name not in out and phy is not out.get(parent_name):
                    phy = out.setdefault(parent_name, {"logical_interfaces": {}})
                logical = phy["logical_interfaces"][m["name"]] = {"index": int(m["idx"]), "protocols": {}}
                if m["snmp"]:
                    logical["snmp_index"] = int(m["snmp"])
                proto = None
                section = None
                continue
            if not phy:
                continue
            target = logical if logical is not None else phy
            if logical is not None and re.match(
                r"^(Protocol [\w\-]+|Flags: |Addresses, Flags|Destination: |Local: )", s
            ):
                section = None
            if logical is not None and section not in (
                "traffic_statistics",
                "ipv6_transit_statistics",
                "label_switched_interface_lsi_traffic_statistics",
            ):
                m = re.match(r"^Protocol (?P<p>[\w\-]+)(?:, MTU: (?P<mtu>\w+))?(?:, (?P<rest>.+))?$", s)
                if m:
                    proto = logical["protocols"][m["p"]] = {"addresses": []}
                    if m["mtu"]:
                        proto["mtu"] = to_num(m["mtu"])
                    if m["rest"]:
                        proto.update(_kv_line(m["rest"]))
                    continue
                m = re.match(
                    r"^Destination: (?P<dst>[^,]+)(?:, Local: (?P<local>[^,]+))?(?:, Broadcast: (?P<bcast>\S+))?", s
                )
                if m and proto is not None:
                    proto["addresses"].append(
                        {
                            k: v.strip(",")
                            for k, v in {"destination": m["dst"], "local": m["local"], "broadcast": m["bcast"]}.items()
                            if v
                        }
                    )
                    continue
                m = re.match(r"^Local: (?P<local>\S+)", s)
                if m and proto is not None:
                    proto["addresses"].append({"local": m["local"]})
                    continue
                m = re.match(r"^Flags: (?P<f>.+?)(?:\s+Encapsulation: (?P<enc>\S+))?$", s)
                if m:
                    tgt = proto if proto is not None else logical
                    tgt["flags"] = [f for f in re.split(r"[,\s]+", m["f"]) if f]
                    if m["enc"]:
                        logical["encapsulation"] = m["enc"]
                    continue
                m = re.match(r"^(Input|Output) packets\s*:\s*(\d+)$", s)
                if m:
                    logical[f"{m.group(1).lower()}_packets"] = int(m.group(2))
                    continue
                m = re.match(r"^MAC: (?P<mac>\S+)", s)
                if m:
                    logical["mac_address"] = m["mac"]
                    continue
                m = re.match(r"^Routing Instance: (?P<ri>\S+)(?: Bridging Domain: (?P<bd>\S+))?", s)
                if m:
                    logical["routing_instance"] = m["ri"]
                    if m["bd"]:
                        logical["bridge_domain"] = m["bd"]
                    continue
            m = re.match(r"^Interface index: (?P<i>\d+), SNMP ifIndex: (?P<s>\d+)", s)
            if m:
                phy["index"], phy["snmp_index"] = int(m["i"]), int(m["s"])
                continue
            m = re.match(r"^Description: (?P<d>.*)$", s)
            if m:
                target["description"] = m["d"]
                continue
            m = re.match(r"^Current address: (?P<cur>[0-9a-fA-F:]+), Hardware address: (?P<hw>[0-9a-fA-F:]+)", s)
            if m:
                phy["mac_address"], phy["hardware_address"] = m["cur"], m["hw"]
                continue
            m = re.match(r"^Last flapped\s*: (?P<t>.+?)(?: \((?P<ago>[^)]+) ago\))?$", s)
            if m:
                phy["last_flapped"] = m["t"]
                continue
            m = re.match(r"^(?P<dir>Input|Output) rate\s*: (?P<bps>\d+) bps \((?P<pps>\d+) pps\)", s)
            if m:
                phy[f"{m['dir'].lower()}_rate_bps"], phy[f"{m['dir'].lower()}_rate_pps"] = int(m["bps"]), int(m["pps"])
                continue
            m = re.match(
                r"^(?P<k>Device flags|Interface flags|Link flags|Active alarms|Active defects|CoS queues)\s*: (?P<v>.+)$",
                s,
            )
            if m:
                v = m["v"].strip()
                phy[snake(m["k"])] = None if v == "None" else (v.split() if "flags" in m["k"] else v)
                continue
            if re.match(
                r"^(Traffic statistics|Input errors|Output errors|IPv6 transit statistics|Label-switched interface \(LSI\) traffic statistics|Dropped traffic statistics.*|MAC statistics|Filter statistics|PCS statistics)",
                s,
            ):
                section = snake(s.split(":")[0].split("  ")[0])
                continue
            if section in (
                "traffic_statistics",
                "ipv6_transit_statistics",
                "label_switched_interface_lsi_traffic_statistics",
            ):
                m = re.match(
                    r"^(?P<dir>Input|Output)\s+(?P<what>bytes|packets)\s*:\s*(?P<n>\d+)(?:\s+(?P<rate>\d+) (?:bps|pps))?",
                    s,
                )
                if m:
                    st = target.setdefault(section, {})
                    st[f"{m['dir'].lower()}_{m['what']}"] = int(m["n"])
                    if m["rate"]:
                        st[f"{m['dir'].lower()}_{'bps' if m['what'] == 'bytes' else 'pps'}"] = int(m["rate"])
                    continue
            if section in ("input_errors", "output_errors") and ":" in s:
                target.setdefault(section, {}).update(_kv_line(s))
                continue
            if section == "mac_statistics":
                m = re.match(r"^(?P<k>[A-Za-z][\w/ ]*?)\s{2,}(?P<rx>\d+)(?:\s+(?P<tx>\d+))?$", s)
                if m:
                    st = phy.setdefault("mac_statistics", {})
                    st[snake(m["k"])] = {"receive": int(m["rx"]), **({"transmit": int(m["tx"])} if m["tx"] else {})}
                    continue
            if section == "pcs_statistics":
                m = re.match(r"^(?P<k>[A-Za-z][\w ]*?)\s{2,}(?P<v>\d+)$", s)
                if m:
                    phy.setdefault("pcs_statistics", {})[snake(m["k"])] = int(m["v"])
                    continue
            if (
                re.match(
                    r"^(Link-level type|Speed|Loop Detect|Source filtering|Pad to minimum|Link-mode|Bandwidth|Type|MTU|Auto-negotiation|Remote fault|Local resolution|Generation)",
                    s,
                )
                and ":" in s
            ):
                section = None
                kv = _kv_line(s)
                if logical is not None and "bandwidth" in kv:
                    logical["bandwidth"] = kv["bandwidth"]
                else:
                    phy.update({k: v for k, v in kv.items() if k != "flags"})
                continue
            if logical is None:
                m = re.match(r"^(Input|Output) packets\s*:\s*(\d+)", s)
                if m:
                    phy[f"{m.group(1).lower()}_packets"] = int(m.group(2))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        res = []
        for name, d in data.items():
            ips = [
                a["local"] + ("/" + a["destination"].split("/")[1] if "/" in a.get("destination", "") else "")
                for li in d.get("logical_interfaces", {}).values()
                for p, pv in li.get("protocols", {}).items()
                if p == "inet"
                for a in pv.get("addresses", [])
                if a.get("local")
            ]
            ts = d.get("traffic_statistics", {})
            ie, oe = d.get("input_errors", {}), d.get("output_errors", {})
            speed = d.get("speed")
            bw = None
            if isinstance(speed, str):
                sm = re.match(r"(\d+)\s*([kmg])bps", speed.lower())
                if sm:
                    bw = int(sm.group(1)) * {"k": 1, "m": 1000, "g": 1000000}[sm.group(2)]
            res.append(
                record(
                    "interfaces.detail",
                    name=name,
                    admin_status=status(d.get("admin_status")),
                    oper_status=status(d.get("oper_status")),
                    description=d.get("description"),
                    mac_address=mac(d.get("mac_address")),
                    mtu=d.get("mtu") if isinstance(d.get("mtu"), int) else None,
                    bandwidth_kbps=bw,
                    ipv4_addresses=ips,
                    input_rate_bps=d.get("input_rate_bps"),
                    output_rate_bps=d.get("output_rate_bps"),
                    input_packets=ts.get("input_packets", d.get("input_packets")),
                    output_packets=ts.get("output_packets", d.get("output_packets")),
                    input_errors=ie.get("errors"),
                    output_errors=oe.get("errors"),
                )
            )
        return res


@register("junos", "show lacp interfaces [<interface>] [extensive]", intent="lag")
class ShowLacpInterfaces(Parser):
    """LACP actor/partner state and mux state per aggregated Ethernet member."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] | None = None
        section = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Aggregated interface: (\S+)", s)
            if m:
                cur = out[m.group(1)] = {"members": {}}
                continue
            if cur is None or not s:
                continue
            if s.startswith("LACP state:"):
                section = "state"
                continue
            if s.startswith("LACP protocol:"):
                section = "protocol"
                continue
            if section == "state":
                m = re.match(
                    r"^(?P<intf>\S+)\s+(?P<role>Actor|Partner)\s+(?P<exp>Yes|No)\s+(?P<def>Yes|No)\s+(?P<dist>Yes|No)\s+(?P<col>Yes|No)\s+(?P<syn>Yes|No)\s+(?P<aggr>Yes|No)\s+(?P<timeout>Fast|Slow)\s+(?P<act>Active|Passive)",
                    s,
                )
                if m:
                    cur["members"].setdefault(m["intf"], {})[m["role"].lower()] = {
                        "expired": m["exp"] == "Yes",
                        "defaulted": m["def"] == "Yes",
                        "distributing": m["dist"] == "Yes",
                        "collecting": m["col"] == "Yes",
                        "synchronization": m["syn"] == "Yes",
                        "aggregation": m["aggr"] == "Yes",
                        "timeout": m["timeout"].lower(),
                        "activity": m["act"].lower(),
                    }
                    continue
            if section == "protocol":
                m = re.match(
                    r"^(?P<intf>\S+)\s+(?P<rx>Current|Expired|Defaulted|Initialize|Port disabled|LACP disabled|\S+)\s+(?P<tx>(?:Fast|Slow|No) periodic|\S+)\s+(?P<mux>\S.*?)\s*$",
                    s,
                )
                if m and m["intf"] != "Member":
                    mem = cur["members"].setdefault(m["intf"], {})
                    mem["receive_state"], mem["transmit_state"], mem["mux_state"] = m["rx"], m["tx"], m["mux"]
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        res = []
        for k, v in data.items():
            up = any(
                m.get("mux_state", "").lower().startswith("collecting distributing") for m in v["members"].values()
            )
            res.append(record("lag", name=k, status="up" if up else "down", members=list(v["members"])))
        return res


@register("junos", "show interfaces diagnostics optics [<interface>]")
class ShowInterfacesDiagnosticsOptics(Parser):
    """Optical transceiver DOM readings (Tx/Rx power, bias, temperature, voltage)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] | None = None
        lane: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Physical interface: (\S+)", s)
            if m:
                cur = out[m.group(1)] = {}
                lane = None
                continue
            if cur is None or not s:
                continue
            m = re.match(r"^Lane (\d+)", s)
            if m:
                lane = cur.setdefault("lanes", {}).setdefault(m.group(1), {})
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /()\-]*?)\s*:\s*(?P<v>.+)$", s)
            if m:
                k = snake(m["k"])
                v = m["v"].strip()
                nm = re.match(r"^(-?[\d.]+) (mA|mW|dBm|V|degrees C)(?: / (-?[\d.]+) (dBm|degrees F))?", v)
                tgt = lane if lane is not None else cur
                if nm:
                    unit = nm.group(2)
                    tgt[f"{k}_{ {'mA': 'ma', 'mW': 'mw', 'dBm': 'dbm', 'V': 'v', 'degrees C': 'c'}[unit] }"] = float(
                        nm.group(1)
                    )
                    if nm.group(3) and nm.group(4) == "dBm":
                        tgt[f"{k}_dbm"] = float(nm.group(3)) if nm.group(3) not in ("-Inf",) else None
                else:
                    tgt[k] = none_if(to_num(v), "-inf")
        return out
