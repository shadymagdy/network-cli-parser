"""Junos: BGP advertised/received routes, firewall counters, NTP, forwarding table, SRX and switching extras."""

from __future__ import annotations

import re
from typing import Any

from ...registry import Parser, register
from ...textutils import compact, match_lines, snake, to_num

_TABLE_HDR = re.compile(
    r"^(?P<table>[\w.\-:]+): (?P<dest>\d+) destinations, (?P<routes>\d+) routes \((?P<active>\d+) active, (?P<hold>\d+) holddown, (?P<hidden>\d+) hidden\)"
)


@register("junos", "show route (advertising-protocol|receive-protocol) bgp <neighbor> [<args...>]")
class ShowRouteAdvertisedReceived(Parser):
    """Routes advertised to / received from a BGP neighbor (prefix, next hop, MED, local-pref, AS path)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "neighbor": self.params.get("neighbor"),
            "direction": "received" if "receive-protocol" in self.command.lower() else "advertised",
            "tables": {},
            "routes": [],
        }
        table = "inet.0"
        med_end = lp_end = None
        pending_prefix: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = _TABLE_HDR.match(s)
            if m:
                table = m["table"]
                out["tables"][table] = {
                    "destinations": int(m["dest"]),
                    "routes": int(m["routes"]),
                    "active": int(m["active"]),
                }
                continue
            if s.startswith("Prefix") and "Nexthop" in s:
                med_end = raw.index("MED") + 3 if "MED" in raw else None
                lp_end = raw.index("Lclpref") + 7 if "Lclpref" in raw else None
                continue
            m = re.match(r"^(?P<act>[*+\-])?\s*(?P<prefix>[0-9a-fA-F.:]+/\d+)\s*$", s)
            if m:
                pending_prefix = m["prefix"]
                if m["act"]:
                    pending_prefix = "*" + pending_prefix
                continue
            m = re.match(r"^(?P<act>[*+\-])?\s*(?:(?P<prefix>[0-9a-fA-F.:]+/\d+)\s+)?(?P<nh>\S+)(?P<rest>.*)$", s)
            if not m or (m["prefix"] is None and pending_prefix is None):
                continue
            prefix = m["prefix"]
            active = bool(m["act"])
            if prefix is None and pending_prefix:
                active = active or pending_prefix.startswith("*")
                prefix = pending_prefix.lstrip("*")
                pending_prefix = None
            rest = m["rest"]
            route: dict[str, Any] = {"table": table, "prefix": prefix, "active": active, "next_hop": m["nh"]}
            nums = list(re.finditer(r"(?<!\()\b(\d+)\b(?![^()]*\))", rest))
            path_start = 0
            numeric = []
            for n in nums:
                if rest[path_start : n.start()].strip():
                    break
                numeric.append(n)
                path_start = n.end()
            if len(numeric) >= 2:
                route["med"], route["local_preference"] = int(numeric[0].group(1)), int(numeric[1].group(1))
            elif len(numeric) == 1:
                col = raw.index(rest) + numeric[0].end() if rest in raw else None
                if (
                    col is not None
                    and med_end is not None
                    and lp_end is not None
                    and abs(col - lp_end) < abs(col - med_end)
                ):
                    route["local_preference"] = int(numeric[0].group(1))
                else:
                    route["med"] = int(numeric[0].group(1))
            path = rest[path_start:].strip()
            if path:
                pm = re.match(r"^(?P<path>.*?)\s*(?P<origin>[IE?])$", path)
                if pm:
                    route["as_path"] = pm["path"].strip() or None
                    route["origin"] = {"I": "igp", "E": "egp", "?": "incomplete"}[pm["origin"]]
                else:
                    route["as_path"] = path
            out["routes"].append(route)
        return out


@register("junos", "show firewall [(filter <filter>|counter <counter...>|log|terse)]")
class ShowFirewall(Parser):
    """Firewall filter counters and policers (bytes/packets)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] | None = None
        section = "counters"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Filter:\s*(\S+)", s)
            if m:
                cur = out[m.group(1)] = {}
                continue
            if cur is None:
                continue
            m = re.match(r"^(Counters|Policers):$", s)
            if m:
                section = m.group(1).lower()
                cur.setdefault(section, {})
                continue
            m = re.match(r"^(?P<name>\S+)\s+(?P<bytes>\d+)\s+(?P<pkts>\d+)$", s)
            if m and m["name"] != "Name":
                cur.setdefault(section, {})[m["name"]] = {"bytes": int(m["bytes"]), "packets": int(m["pkts"])}
        return out


@register("junos", "show ntp status [no-resolve]")
class ShowNtpStatus(Parser):
    """NTP daemon variables (stratum, offset, jitter, reference, leap, sync state)."""

    def parse(self, text: str) -> dict[str, Any]:
        blob = " ".join(ln.strip() for ln in text.splitlines())
        out: dict[str, Any] = {}
        if "=" not in blob:
            return out
        m = re.search(r"status=(?P<status>\S+)\s+(?P<flags>[^=]+?),\s*(?=\w+=)", blob)
        if m:
            out["status"] = m["status"]
            flags = [f.strip() for f in m["flags"].split(",") if f.strip()]
            out["flags"] = flags
            out["synchronized"] = any(f.startswith("sync_") and f != "sync_unspec" for f in flags)
        for k, v in re.findall(r"(\w{1,40})=(\"[^\"]*\"|[^,\s]+(?:\s+[A-Z][a-z]{2},[^,=]{1,60}?(?=,|\s*$))?)", blob):
            if k == "status":
                continue
            v = v.strip().strip('"')
            out[k] = to_num(v)
        return out


@register("junos", "show system information")
class ShowSystemInformation(Parser):
    """Model, family, Junos release and hostname."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for m in match_lines(
            r"^\s*(?P<k>Model|Family|Junos|Hostname|Serial Number|Junos Release):\s*(?P<v>.+?)\s*$", text
        ):
            key = {"junos": "version", "junos_release": "version"}.get(snake(m["k"]), snake(m["k"]))
            out[key] = m["v"]
        return out


@register("junos", "show chassis firmware [(detail|no-forwarding)]")
class ShowChassisFirmware(Parser):
    """ROM / O/S firmware versions per component."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        part = None
        for raw in text.splitlines():
            if re.match(r"^\s*Part\s+Type\s+Version", raw) or not raw.strip():
                continue
            m = re.match(
                r"^(?P<part>\S.*?)\s{2,}(?P<type>ROM|O/S|FPGA|PLD|BIOS|CPLD|U-Boot|\S+)\s{2,}(?P<ver>.+?)\s*$", raw
            )
            if m and not raw.startswith(" "):
                part = m["part"].strip()
                out.append({"part": part, "type": m["type"], "version": m["ver"]})
                continue
            m = re.match(r"^\s+(?P<type>ROM|O/S|FPGA|PLD|BIOS|CPLD|U-Boot|\S+)\s{2,}(?P<ver>.+?)\s*$", raw)
            if m and part:
                out.append({"part": part, "type": m["type"], "version": m["ver"]})
        return out


@register("junos", "show route forwarding-table summary [(family <family>|table <table>)]")
class ShowRouteForwardingTableSummary(Parser):
    """Forwarding-table route counts per table and route type."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Routing table:\s*(\S+)", s)
            if m:
                cur = out[m.group(1)] = {"routes": {}}
                continue
            if cur is None:
                continue
            m = re.match(r"^Enabled protocols:\s*(.*)$", s)
            if m:
                cur["enabled_protocols"] = [p.strip() for p in m.group(1).split(",") if p.strip()]
                continue
            m = re.match(r"^(\w[\w\-]*):\s+(\d+) routes", s)
            if m:
                cur["routes"][m.group(1)] = int(m.group(2))
                continue
            m = re.match(r"^(Internet|Internet6|MPLS|Bridging|VPLS|ISO|DHCP Snooping|\w+):$", s)
            if m:
                cur["family"] = m.group(1)
        return out


@register("junos", "show chassis cluster interfaces")
class ShowChassisClusterInterfaces(Parser):
    """SRX cluster control/fabric links and redundant-ethernet interfaces."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"control_interfaces": [], "fabric_interfaces": [], "redundant_ethernet": []}
        section = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^(Control|Fabric) link status:\s*(\S+)", s)
            if m:
                out[f"{m.group(1).lower()}_link_status"] = m.group(2)
                continue
            if s.startswith("Control interfaces"):
                section = "control"
                continue
            if s.startswith("Fabric interfaces"):
                section = "fabric"
                continue
            if s.startswith("Redundant-ethernet Information"):
                section = "reth"
                continue
            if s.startswith(("Redundant-pseudo-interface", "Interface Monitoring")):
                section = None
                continue
            if section == "control":
                m = re.match(r"^(?P<idx>\d+)\s+(?P<intf>\S+)\s+(?P<st>\S+)\s+(?P<extra>\S+)$", s)
                if m:
                    out["control_interfaces"].append(
                        {"index": int(m["idx"]), "interface": m["intf"], "status": m["st"], "security": m["extra"]}
                    )
            elif section == "fabric":
                m = re.match(
                    r"^(?P<name>fab\d+)\s+(?P<child>\S+)\s+(?P<phy>Up|Down)\s*(?:/\s*(?P<mon>Up|Down))?(?:\s+(?P<sec>\S+))?$",
                    s,
                )
                if m:
                    out["fabric_interfaces"].append(
                        compact(
                            {
                                "name": m["name"],
                                "child_interface": m["child"],
                                "physical": m["phy"],
                                "monitored": m["mon"],
                                "security": m["sec"],
                            }
                        )
                    )
            elif section == "reth":
                m = re.match(r"^(?P<name>reth\d+)\s+(?P<st>Up|Down)\s+(?P<rg>\d+|Not configured)$", s)
                if m:
                    out["redundant_ethernet"].append(
                        {
                            "name": m["name"],
                            "status": m["st"],
                            "redundancy_group": to_num(m["rg"]) if m["rg"].isdigit() else None,
                        }
                    )
        return out


@register("junos", "show ethernet-switching interfaces [<interface>] [(brief|detail)]")
class ShowEthernetSwitchingInterfaces(Parser):
    """Switch ports: state, VLAN membership, tagging and blocking status."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("Interface"):
                continue
            m = re.match(r"^(?P<intf>\S+)\s+(?P<state>up|down)\s+(?P<vlan>\S+)\s*(?P<rest>.*)$", raw)
            if m and not raw.startswith(" "):
                cur = {"interface": m["intf"], "state": m["state"], "vlans": []}
                out.append(cur)
                cur["vlans"].append(_vlan_member(m["vlan"], m["rest"]))
                continue
            m = re.match(r"^\s+(?P<vlan>\S+)\s*(?P<rest>.*)$", raw)
            if m and cur is not None:
                cur["vlans"].append(_vlan_member(m["vlan"], m["rest"]))
        return out


def _vlan_member(vlan: str, rest: str) -> dict[str, Any]:
    m = re.match(r"^(?P<tag>\d+)?\s*(?P<tagging>tagged|untagged)?\s*(?P<blocking>.*?)\s*$", rest)
    out: dict[str, Any] = {"vlan": vlan}
    if m:
        if m["tag"]:
            out["tag"] = int(m["tag"])
        if m["tagging"]:
            out["tagging"] = m["tagging"]
        if m["blocking"]:
            out["blocking"] = m["blocking"]
    return out


@register("junos", "show security policies hit-count [(from-zone <from> to-zone <to>|logical-system <ls>)]")
class ShowSecurityPoliciesHitCount(Parser):
    """SRX security policy hit counters."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        ls = None
        for raw in text.splitlines():
            m = re.match(r"^\s*Logical system:\s*(\S+)", raw)
            if m:
                ls = m.group(1)
                continue
            m = re.match(r"^\s*(?P<idx>\d+)\s+(?P<frm>\S+)\s+(?P<to>\S+)\s+(?P<name>\S+)\s+(?P<count>\d+)\s*$", raw)
            if m:
                out.append(
                    {
                        "index": int(m["idx"]),
                        "from_zone": m["frm"],
                        "to_zone": m["to"],
                        "policy": m["name"],
                        "hit_count": int(m["count"]),
                        "logical_system": ls,
                    }
                )
        return out
