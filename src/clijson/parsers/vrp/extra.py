"""Huawei VRP: MPLS TE, ACLs, licenses, modules, files, VRRP, BGP routes, power and fans."""

from __future__ import annotations

import re
from typing import Any

from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, parse_table, snake, to_num


@register("vrp", "display mpls te tunnel [(<tunnel>|name <name>|verbose|statistics)]")
class DisplayMplsTeTunnel(Parser):
    """TE LSPs: ingress LSR, destination, LSP ID, labels, role and tunnel name."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<detour>\*)?(?P<ing>\d+\.\d+\.\d+\.\d+)\s+(?P<dst>\d+\.\d+\.\d+\.\d+)\s+(?P<lsp>\d+)\s+(?P<inl>\S+)/(?P<outl>\S+)\s+(?P<role>[ITE])\s+(?P<name>\S+)\s*$",
            text,
        ):
            out.append(
                {
                    "ingress_lsr_id": m["ing"],
                    "destination": m["dst"],
                    "lsp_id": int(m["lsp"]),
                    "in_label": to_num(m["inl"]) if m["inl"] != "-" else None,
                    "out_label": to_num(m["outl"]) if m["outl"] != "-" else None,
                    "role": {"I": "ingress", "T": "transit", "E": "egress"}[m["role"]],
                    "tunnel": m["name"],
                    "detour": bool(m["detour"]),
                }
            )
        return out


@register("vrp", "display acl (all|<acl>|name <name>)", "display acl ipv6 (all|<acl>)")
class DisplayAcl(Parser):
    """ACLs with type, step and rules (action, match text, hit counter, description)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"acls": {}}
        m = re.search(r"Total quantity of nonempty ACL number is (\d+)", text)
        if m:
            out["nonempty_count"] = int(m.group(1))
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(
                r"^(?P<type>Basic|Advanced|Layer 2|User|Ethernet frame header|Interface-based|Mpls)\s+(?:IPv6 )?ACL\s+(?:(?P<name>\S+)\s+)?(?P<num>\d+),\s*(?P<n>\d+) rules?",
                s,
            )
            if m:
                key = m["name"] or m["num"]
                cur = out["acls"][key] = {"number": int(m["num"]), "type": m["type"].lower(), "rules": []}
                if m["name"]:
                    cur["name"] = m["name"]
                continue
            if cur is None:
                continue
            m = re.match(r"^Acl's step is (\d+)", s)
            if m:
                cur["step"] = int(m.group(1))
                continue
            m = re.match(r'^rule (?P<id>\d+) description "?(?P<d>.*?)"?$', s)
            if m:
                for r in cur["rules"]:
                    if r["id"] == int(m["id"]):
                        r["description"] = m["d"]
                continue
            m = re.match(
                r"^rule (?P<id>\d+) (?P<action>permit|deny)\s*(?P<match>.*?)\s*(?:\((?P<hits>\d+) (?:matches|times matched)\))?\s*(?P<inactive>\(inactive\))?$",
                s,
            )
            if m:
                rule: dict[str, Any] = {
                    "id": int(m["id"]),
                    "action": m["action"],
                    "match": m["match"] or None,
                    "matches": int(m["hits"]) if m["hits"] else 0,
                }
                if m["inactive"]:
                    rule["inactive"] = True
                cur["rules"].append(rule)
        return out


@register("vrp", "display license [(verbose|esn|state|resource usage)]")
class DisplayLicense(Parser):
    """License file details, features and control items."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"features": []}
        feature: dict[str, Any] | None = None
        item: dict[str, Any] | None = None
        for m in match_lines(r"^\s*(?P<k>[A-Za-z][\w .]*?)\s*:\s*(?P<v>.*?)\s*$", text):
            k, v = snake(m["k"]), none_if(m["v"])
            if k == "feature_name":
                feature = {"name": v, "items": []}
                out["features"].append(feature)
                item = None
                continue
            if k == "sale_name" and feature is not None:
                item = {"sale_name": v}
                feature["items"].append(item)
                continue
            target = item if item is not None else (feature if feature is not None else out)
            target[k] = to_num(v) if isinstance(v, str) else v
        if not out["features"]:
            out.pop("features")
        return out


@register("vrp", "display module-information [(verbose|next-startup)]")
class DisplayModuleInformation(Parser):
    """Installed modules (plug-ins) and per-board module processes."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"modules": [], "boards": []}
        for m in match_lines(
            r"^(?P<mod>\S+)\s+(?P<ver>\S+)\s+(?P<t>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?P<pkg>\S+)\s*$", text
        ):
            out["modules"].append(
                {"module": m["mod"], "version": m["ver"], "install_time": m["t"], "package": m["pkg"]}
            )
        for m in match_lines(
            r"^(?P<slot>\d+/\d+)\s+(?P<proc>\S+)\s+(?P<type>\S+)\s+(?P<file>\S+)\s+(?P<t>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<mod>\S+)\s*$",
            text,
        ):
            out["boards"].append(
                {
                    "slot_cpu": m["slot"],
                    "process": m["proc"],
                    "type": m["type"],
                    "file": m["file"],
                    "effective_time": m["t"],
                    "module": m["mod"],
                }
            )
        return out


@register("vrp", "dir [<path...>]")
class Dir(Parser):
    """Directory listing with totals."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"files": []}
        m = re.search(r"Directory of (\S+)", text)
        if m:
            out["directory"] = m.group(1)
        for m in match_lines(
            r"^\s*(?P<idx>\d+)\s+(?P<attr>[-drwx]{4})\s+(?P<size>[\d,]+|-)\s+(?P<date>\w{3} \d\d \d{4})\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<name>.+?)\s*$",
            text,
        ):
            out["files"].append(
                {
                    "index": int(m["idx"]),
                    "name": m["name"],
                    "attributes": m["attr"],
                    "directory": m["attr"].startswith("d"),
                    "size": int(m["size"].replace(",", "")) if m["size"] != "-" else None,
                    "date": f"{m['date']} {m['time']}",
                }
            )
        m = re.search(r"([\d,]+) KB total(?: available)? \(([\d,]+) KB free\)", text)
        if m:
            out["total_kb"], out["free_kb"] = int(m.group(1).replace(",", "")), int(m.group(2).replace(",", ""))
        return out


@register(
    "vrp", "display vrrp [(brief|verbose|<interface>|statistics)]", "display vrrp <interface> <vrid> [(brief|verbose)]"
)
class DisplayVrrp(Parser):
    """VRRP groups: VRID, state, interface, type and virtual IP (brief or verbose)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in match_lines(
            r"^\s*(?P<vrid>\d+)\s+(?P<state>Master|Backup|Initialize|Init)\s+(?P<intf>\S+)\s+(?P<type>Normal|Vgmp|Admin-vrrp|Member|\S+)\s+(?P<vip>[\d.:a-fA-F]+)\s*$",
            text,
        ):
            out.append(
                {
                    "vrid": int(row["vrid"]),
                    "state": row["state"],
                    "interface": row["intf"],
                    "type": row["type"],
                    "virtual_ip": row["vip"],
                }
            )
        if out:
            return out
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^(?P<intf>\S+)\s*\|\s*Virtual Router (?P<vrid>\d+)$", s)
            if m:
                cur = {"interface": m["intf"], "vrid": int(m["vrid"])}
                out.append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w .\-]*?)\s*:\s*(?P<v>.*?)\s*$", s)
            if m:
                k = snake(m["k"])
                if k == "virtual_ip":
                    cur.setdefault("virtual_ips", []).append(m["v"])
                else:
                    cur[k] = to_num(m["v"]) if m["v"] else None
        return out


@register("vrp", "display bgp [(vpnv4|ipv6|evpn)] [(all|vpn-instance <vrf>)] routing-table [<target...>]")
class DisplayBgpRoutingTable(Parser):
    """BGP RIB: status codes, network, next hop, MED, local-pref, preferred value and AS path."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"routes": []}
        m = re.search(r"BGP Local router ID is (\S+)", text)
        if m:
            out["router_id"] = m.group(1)
        m = re.search(r"Total Number of Routes:\s*(\d+)", text)
        if m:
            out["total_routes"] = int(m.group(1))
        rd = vrf = None
        for raw in text.splitlines():
            s = raw.strip()
            mm = re.match(r"^Route Distinguisher:\s*(\S+)", s)
            if mm:
                rd = mm.group(1)
                continue
            mm = re.match(r"^VPN-Instance (\S+?),", s)
            if mm:
                vrf = mm.group(1)
                continue
            mm = re.match(
                r"^(?P<codes>[*>disahSxVIN ]+?)\s*(?P<net>[0-9a-fA-F.:]+(?:/\d+)?)\s+(?:(?P<nh>[0-9a-fA-F]*[.:][0-9a-fA-F.:]+)\s+)?(?P<rest>.*)$",
                s,
            )
            if not mm or not re.search(r"[*>]", mm["codes"]):
                continue
            network, next_hop = mm["net"], mm["nh"]
            if next_hop is None:
                # ECMP / additional path: only the next hop is printed
                if not out["routes"]:
                    continue
                network, next_hop = out["routes"][-1]["network"], mm["net"]
            nums = mm["rest"].split()
            route: dict[str, Any] = {
                "network": network,
                "next_hop": next_hop,
                "valid": "*" in mm["codes"],
                "best": ">" in mm["codes"],
                "internal": "i" in mm["codes"].replace(" ", "")[1:],
            }
            vals: list[Any] = []
            i = 0
            while i < len(nums) and re.fullmatch(r"\d+", nums[i]):
                vals.append(int(nums[i]))
                i += 1
            path = " ".join(nums[i:])
            if len(vals) >= 2:
                if len(vals) >= 3:
                    route["med"], route["local_preference"], route["preferred_value"] = vals[0], vals[1], vals[2]
                else:
                    route["med"], route["preferred_value"] = vals[0], vals[1]
            elif vals:
                route["preferred_value"] = vals[0]
            pm = re.match(r"^(?P<path>.*?)\s*(?P<o>[ie?])$", path)
            if pm:
                route["as_path"] = pm["path"] or None
                route["origin"] = {"i": "igp", "e": "egp", "?": "incomplete"}[pm["o"]]
            if rd:
                route["route_distinguisher"] = rd
            if vrf:
                route["vrf"] = vrf
            out["routes"].append(route)
        return out


@register("vrp", "display power [(slot <slot>|manage)]", "display power-supply")
class DisplayPower(Parser):
    """Power modules: state, mode, voltage/current/power where printed."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<slot>PWR\d+|\d+(?:/\d+)?|PM\d+)\s+(?P<present>YES|NO|Present|Absent)\s+(?P<mode>AC|DC|HVDC|\S+)\s+(?P<state>Supply|NotSupply|Normal|Abnormal|Sleep|\S+)(?P<rest>.*)$",
            text,
        ):
            e: dict[str, Any] = {
                "slot": m["slot"],
                "present": m["present"].upper() in ("YES", "PRESENT"),
                "mode": m["mode"],
                "state": m["state"],
            }
            nums = re.findall(r"-?[\d.]+", m["rest"])
            if len(nums) >= 3:
                e["current_a"], e["voltage_v"], e["power_w"] = (to_num(n) for n in nums[:3])
            out.append(e)
        return out


@register("vrp", "display fan [(slot <slot>|verbose)]")
class DisplayFan(Parser):
    """Fan modules: presence, status, speed, mode and air flow (header-driven, any product layout)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = parse_table(text, header=r"^\s*(Slot|FanID|FAN)\s+", skip=r"^\s*-+\s*$")
        return [compact(r) for r in rows if any(v is not None for v in r.values())]
