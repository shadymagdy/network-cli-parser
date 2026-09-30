"""IOS XR routing: RIB, BGP, OSPF, IS-IS."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import record, seconds
from ...registry import Parser, register
from ...textutils import compact, to_num

# --------------------------------------------------------------------------- #
# RIB
# --------------------------------------------------------------------------- #

CISCO_ROUTE_CODES = {
    "C": "connected", "L": "local", "S": "static", "R": "rip", "B": "bgp", "D": "eigrp", "EX": "eigrp",
    "O": "ospf", "IA": "ospf", "N1": "ospf", "N2": "ospf", "E1": "ospf", "E2": "ospf", "E": "egp",
    "i": "isis", "L1": "isis", "L2": "isis", "ia": "isis", "su": "isis", "U": "static", "o": "odr",
    "G": "dagr", "l": "lisp", "A": "subscriber", "a": "application", "M": "mobile", "r": "rpl",
    "t": "te-client", "m": "mobile", "d": "dagr", "I": "igrp",
}

_ROUTE_LINE = re.compile(
    r"^(?P<codes>[A-Za-z][A-Za-z0-9]?(?:[ *+%>]{1,2}[A-Za-z0-9]{1,2})?[*+%>]?)\s+(?P<prefix>[0-9a-fA-F.:]+/\d+),?(?:\s+(?P<rest>.*))?$"
)
_NH = re.compile(
    r"^\s*\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nh>[^\s,]+)(?:\s+\(nexthop in vrf (?P<nhvrf>[^)]+)\))?"
    r"(?:,\s*(?P<age>[^,\s]+))?(?:,\s*(?P<intf>[^,\s]+))?(?:\s+\((?P<flag>[!>])\))?"
)
_CONNECTED = re.compile(r"^is directly connected,\s*(?P<age>[^,\s]+)?(?:,\s*(?P<intf>\S+))?")


def parse_cisco_routes(text: str) -> Dict[str, Any]:
    """Shared RIB parser for Cisco style ``show route`` output."""
    out: Dict[str, Any] = {"routes": []}
    vrf = "default"
    cur: Optional[Dict[str, Any]] = None
    pending_connected = False
    for raw in text.splitlines():
        if not raw.strip():
            continue
        m = re.match(r"^\s*VRF:\s*(?P<vrf>\S+)", raw)
        if m:
            vrf = m["vrf"]
            continue
        m = re.match(r"^\s*Gateway of last resort is (?P<gw>.+?)\s*$", raw)
        if m:
            g = m["gw"]
            gm = re.match(r"(?P<nh>\S+) to network (?P<net>\S+)", g)
            out.setdefault("gateway_of_last_resort", {})[vrf] = {"next_hop": gm["nh"], "network": gm["net"]} if gm else None
            continue
        if re.match(r"^\s*(Codes:|[A-Za-z0-9]{1,3} - |\s+[A-Za-z]{1,3}\s+-\s)", raw) and " - " in raw and "via" not in raw:
            continue
        m = _ROUTE_LINE.match(raw.lstrip() if raw.startswith(("   ", "\t")) is False else raw)
        if m and not raw.startswith(" "):
            star = "*" in m["codes"]
            code_words = [c for c in re.split(r"[\s*+%>]+", m["codes"]) if c]
            proto = CISCO_ROUTE_CODES.get(code_words[0], code_words[0]) if code_words else None
            cur = {
                "prefix": m["prefix"],
                "vrf": vrf,
                "protocol": proto,
                "code": " ".join(code_words),
                "candidate_default": star,
                "next_hops": [],
            }
            out["routes"].append(cur)
            rest = (m["rest"] or "").strip()
            pending_connected = False
            if rest:
                _route_rest(cur, rest)
                pending_connected = bool(cur["next_hops"]) and rest.startswith("is directly connected") and not cur["next_hops"][-1].get("interface")
            continue
        if cur is None:
            continue
        s = raw.strip()
        if pending_connected:
            # IPv6 style wrap: "is directly connected,\n    01:52:24, Loopback0"
            parts = [p.strip() for p in s.split(",")]
            nh = cur["next_hops"][-1]
            if len(parts) >= 2:
                nh["age"], nh["interface"] = parts[0], parts[1]
            elif parts:
                nh["interface"] = parts[0]
            pending_connected = False
            continue
        if s.startswith("[") or s.startswith("is directly connected"):
            _route_rest(cur, s)
            if s.startswith("is directly connected") and not cur["next_hops"][-1].get("interface"):
                pending_connected = True
    for r in out["routes"]:
        if r["next_hops"]:
            r["distance"] = r["next_hops"][0].get("distance")
            r["metric"] = r["next_hops"][0].get("metric")
        r["next_hops"] = [compact(nh) for nh in r["next_hops"]]
    return out


def _route_rest(cur: Dict[str, Any], rest: str) -> None:
    m = _NH.match(rest)
    if m:
        nh: Dict[str, Any] = {
            "next_hop": m["nh"],
            "interface": m["intf"],
            "age": m["age"],
            "distance": int(m["ad"]),
            "metric": int(m["metric"]),
        }
        if m["nhvrf"]:
            nh["next_hop_vrf"] = m["nhvrf"]
        if m["flag"] == "!":
            nh["backup"] = True
        if m["flag"] == ">":
            nh["diversion"] = True
        cur["next_hops"].append(nh)
        return
    m = _CONNECTED.match(rest)
    if m:
        cur["next_hops"].append({"interface": m["intf"], "age": m["age"], "distance": 0, "metric": 0, "directly_connected": True})
        return
    if not rest.startswith("["):
        cur["description"] = rest.strip()


def _parse_route_detail(text: str) -> Dict[str, Any]:
    """``show route <prefix>`` detail view (``Routing entry for``)."""
    entries = []
    cur: Dict[str, Any] = {}
    in_rdb = False
    vrf = "default"
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"^VRF:\s*(?P<vrf>\S+)", s)
        if m:
            vrf = m["vrf"]
            continue
        m = re.match(r"^Routing entry for (?P<p>\S+)(?:, (?P<extra>.+))?", s)
        if m:
            cur = {"prefix": m["p"], "vrf": vrf, "next_hops": []}
            if m["extra"]:
                cur["flags"] = m["extra"]
            entries.append(cur)
            in_rdb = False
            continue
        if not cur:
            continue
        m = re.match(r'^Known via "(?P<src>[^"]+)", distance (?P<ad>\d+), metric (?P<metric>\d+)(?:,?\s*(?P<rest>.*))?', s)
        if m:
            src = m["src"].split()
            cur["protocol"] = src[0]
            if len(src) > 1:
                cur["process"] = " ".join(src[1:])
            cur["distance"], cur["metric"] = int(m["ad"]), int(m["metric"])
            if m["rest"]:
                for part in [p.strip() for p in m["rest"].split(",") if p.strip()]:
                    if part == "candidate default path":
                        cur["candidate_default"] = True
                    elif part.startswith("type "):
                        cur["type"] = part[5:]
                    else:
                        cur.setdefault("attributes", []).append(part)
            continue
        m = re.match(r"^Tag (?P<tag>\d+)(?:, type (?P<type>.+))?", s)
        if m:
            cur["tag"] = int(m["tag"])
            if m["type"]:
                cur["type"] = m["type"]
            continue
        m = re.match(r"^Installed (?P<when>.+?) for (?P<age>\S+)", s)
        if m:
            cur["installed"], cur["age"] = m["when"], m["age"]
            continue
        if s == "Routing Descriptor Blocks":
            in_rdb = True
            continue
        if in_rdb:
            m = re.match(r"^(?P<nh>[\w.:]+|directly connected)(?:, from (?P<frm>[\w.:]+))?(?:, via (?P<intf>\S+?))?(?:,\s*(?P<flags>.+))?$", s)
            if m and not s.startswith(("Route metric", "No advertising", "Label", "Tunnel", "Binding", "Extended", "NHID", "Path")):
                nh = {"next_hop": m["nh"], "from": m["frm"], "interface": m["intf"]}
                if m["flags"]:
                    nh["flags"] = m["flags"]
                cur["next_hops"].append(compact(nh))
                continue
            m = re.match(r"^Route metric is (?P<m>\d+)", s)
            if m and cur["next_hops"]:
                cur["next_hops"][-1]["metric"] = int(m["m"])
                continue
            m = re.match(r"^Label: (?P<l>\S+)", s)
            if m and cur["next_hops"]:
                cur["next_hops"][-1]["label"] = to_num(m["l"])
                continue
        if s.startswith("No advertising protos"):
            in_rdb = False
    return {"routes": entries}


@register(
    "iosxr",
    "show route [vrf (all|<vrf>)] [(ipv4|ipv6|afi-all)] [(unicast|multicast|safi-all)] [(connected|local|static|bgp|ospf|isis|rip|eigrp|application|subscriber|best-local|longer-prefixes)] [<target...>]",
    "show (ip|ipv6) route [vrf (all|<vrf>)] [<target...>]",
    intent="routes",
)
class ShowRoute(Parser):
    """Routing table (RIB) with next-hops, distance/metric and flags."""

    def parse(self, text: str) -> Dict[str, Any]:
        if re.search(r"^\s*Routing entry for ", text, re.M):
            return _parse_route_detail(text)
        data = parse_cisco_routes(text)
        vrf = self.params.get("vrf")
        if vrf and vrf != "all":
            for r in data["routes"]:
                if r["vrf"] == "default":
                    r["vrf"] = vrf
        return data

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "routes",
                prefix=r["prefix"],
                protocol=r.get("protocol"),
                next_hops=[{"next_hop": nh.get("next_hop"), "interface": nh.get("interface")} for nh in r.get("next_hops", [])],
                distance=r.get("distance"),
                metric=r.get("metric"),
                vrf=r.get("vrf", "default"),
                age=(r.get("next_hops") or [{}])[0].get("age") or r.get("age"),
            )
            for r in data["routes"]
        ]


@register("iosxr", "show route [vrf (all|<vrf>)] [(ipv4|ipv6|afi-all)] [(unicast|multicast|safi-all)] summary [detail]")
class ShowRouteSummary(Parser):
    """Route counts per source (connected, static, bgp, ...)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        vrf = self.params.get("vrf") or "default"
        for raw in text.splitlines():
            m = re.match(r"^\s*VRF:\s*(\S+)", raw)
            if m:
                vrf = m.group(1)
                continue
            m = re.match(r"^\s*(?P<src>[A-Za-z][\w\-]*(?: [\w\-]+)?)\s+(?P<routes>\d+)\s+(?P<backup>\d+)\s+(?P<deleted>\d+)\s+(?P<mem>\d+)\s*$", raw)
            if m:
                entry = {"routes": int(m["routes"]), "backup": int(m["backup"]), "deleted": int(m["deleted"]), "memory_bytes": int(m["mem"])}
                v = out.setdefault(vrf, {"sources": {}})
                if m["src"] == "Total":
                    v["total"] = entry
                else:
                    v["sources"][m["src"]] = entry
        return out


# --------------------------------------------------------------------------- #
# BGP
# --------------------------------------------------------------------------- #

_AFI_RE = re.compile(r"^\s*Address Family:\s*(?P<af>.+?)\s*$")


@register(
    "iosxr",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|l2vpn|link-state|all|rt-filter)] [(unicast|multicast|labeled-unicast|all|evpn|vpls|flowspec|mvpn|link-state|mdt|rt-filter)] summary",
    "show ip bgp [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|all)] [(unicast|multicast|all)] summary",
    "show bgp summary",
    intent="bgp.summary",
)
class ShowBgpSummary(Parser):
    """BGP peers per instance / VRF / address family, flattened to one list."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbors": [], "contexts": []}
        ctx: Dict[str, Any] = {"instance": self.params.get("instance") if self.params.get("instance") not in (None, "all") else "default",
                               "vrf": self.params.get("vrf") if self.params.get("vrf") not in (None, "all") else "default",
                               "address_family": af_from_command(self.command)}
        info: Dict[str, Any] = {}
        in_table = False
        pending: Optional[str] = None

        def flush_ctx() -> None:
            nonlocal info
            if info:
                out["contexts"].append({**{k: ctx[k] for k in ("instance", "vrf", "address_family")}, **info})
            info = {}

        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^BGP instance \d+: '(?P<inst>[^']+)'", s)
            if m:
                flush_ctx()
                ctx["instance"] = m["inst"]
                in_table = False
                continue
            m = re.match(r"^VRF:\s*(?P<vrf>\S+)", s)
            if m:
                flush_ctx()
                ctx["vrf"] = m["vrf"]
                in_table = False
                continue
            m = _AFI_RE.match(s)
            if m:
                flush_ctx()
                ctx["address_family"] = m["af"].lower()
                in_table = False
                continue
            m = re.match(r"^BGP VRF (?P<vrf>\S+), state: (?P<st>\S+)", s)
            if m:
                ctx["vrf"] = m["vrf"]
                info["vrf_state"] = m["st"]
                continue
            m = re.match(r"^BGP Route Distinguisher: (?P<rd>\S+)", s)
            if m:
                info["route_distinguisher"] = m["rd"]
                continue
            m = re.match(r"^BGP router identifier (?P<rid>\S+), local AS number (?P<las>\S+)", s)
            if m:
                info["router_id"] = m["rid"]
                info["local_as"] = _asn(m["las"])
                continue
            m = re.match(r"^BGP table state: (?P<st>\S+)", s)
            if m:
                info["table_state"] = m["st"]
                continue
            m = re.match(r"^BGP main routing table version (?P<v>\d+)", s)
            if m:
                info["table_version"] = int(m["v"])
                continue
            m = re.match(r"^BGP is operating in (?P<mode>\S+) mode", s)
            if m:
                info["mode"] = m["mode"].lower()
                continue
            if s.startswith("Non-stop routing is"):
                info["nsr"] = s.endswith("enabled")
                continue
            if re.match(r"^Neighbor\s+Spk\s+AS", s):
                in_table = True
                continue
            if not in_table:
                continue
            if pending and not re.match(r"^[0-9a-fA-F.:]+$", s):
                s = pending + " " + s
                pending = None
            if re.match(r"^[0-9a-fA-F.:]+$", s):
                pending = s
                continue
            m = re.match(
                r"^(?P<nbr>[0-9a-fA-F.:]+)\s+(?P<spk>\d+)\s+(?P<as>[\d.]+)\s+(?P<rcvd>\d+)\s+(?P<sent>\d+)\s+(?P<tblver>\d+)\s+(?P<inq>\d+)\s+(?P<outq>\d+)\s+(?P<updown>\S+)\s+(?P<st>[^\s!]+(?: \([^)]*\))?)(?P<bang>!)?$",
                s,
            )
            if m:
                state = m["st"]
                established = state.isdigit()
                nbr = {
                    "neighbor": m["nbr"],
                    "instance": ctx["instance"],
                    "vrf": ctx["vrf"],
                    "address_family": ctx["address_family"],
                    "speaker_id": int(m["spk"]),
                    "remote_as": _asn(m["as"]),
                    "messages_received": int(m["rcvd"]),
                    "messages_sent": int(m["sent"]),
                    "table_version": int(m["tblver"]),
                    "input_queue": int(m["inq"]),
                    "output_queue": int(m["outq"]),
                    "up_down": m["updown"],
                    "state": "Established" if established else state,
                    "prefixes_received": int(state) if established else None,
                }
                if m["bang"]:
                    nbr["missing_policy"] = True
                out["neighbors"].append(nbr)
        flush_ctx()
        if len(out["contexts"]) == 1:
            c = out.pop("contexts")[0]
            for k in ("router_id", "local_as"):
                if k in c:
                    out[k] = c[k]
            out["context"] = c
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "bgp.summary",
                neighbor=n["neighbor"],
                remote_as=n["remote_as"],
                state=n["state"],
                established=n["state"] == "Established",
                uptime=n["up_down"],
                uptime_seconds=seconds(n["up_down"]),
                prefixes_received=n["prefixes_received"],
                vrf=n["vrf"],
                address_family=n["address_family"],
            )
            for n in data["neighbors"]
        ]


_AFIS = ("ipv4", "ipv6", "vpnv4", "vpnv6", "l2vpn", "link-state", "rt-filter")
_SAFIS = ("unicast", "multicast", "labeled-unicast", "evpn", "vpls", "flowspec", "mvpn", "mdt")


def af_from_command(command: str) -> str:
    """Infer the address family from the typed command (default ``ipv4 unicast``)."""
    words = command.lower().split()
    afi = next((w for w in words if w in _AFIS), None)
    safi = next((s for s in _SAFIS for w in words if len(w) >= 3 and s.startswith(w)), None)
    if afi is None:
        return "ipv4 unicast"
    if afi in ("vpnv4", "vpnv6") and safi is None:
        safi = "unicast"
    if afi == "l2vpn" and safi is None:
        safi = "evpn"
    return f"{afi} {safi or 'unicast'}"


def _asn(v: str) -> Any:
    """Keep asdot notation (``65000.100``) as string, plain numbers as int."""
    return int(v) if v.isdigit() else v


@register(
    "iosxr",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|l2vpn|all)] [(unicast|multicast|labeled-unicast|all|evpn|vpls|flowspec)] neighbors [<neighbor>] [detail]",
    "show ip bgp [vrf (all|<vrf>)] neighbors [<neighbor>]",
)
class ShowBgpNeighbors(Parser):
    """Detailed BGP session information per neighbor."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        af: Optional[Dict[str, Any]] = None
        section = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^BGP neighbor is (?P<n>\S+?)(?:,\s*vrf (?P<vrf>\S+))?$", s)
            if m:
                cur = {"vrf": m["vrf"] or self.params.get("vrf") or "default", "address_families": {}}
                key = m["n"] if not m["vrf"] else f"{m['vrf']}:{m['n']}"
                cur["neighbor"] = m["n"]
                out[key] = cur
                af, section = None, None
                continue
            if not cur:
                continue
            m = re.match(r"^Remote AS (?P<ras>[\d.]+), local AS (?P<las>[\d.]+)(?:\s+(?P<flags>no-prepend|replace-as|dual-as)[^,]*)?,\s*(?P<link>\S+) link", s)
            if m:
                cur["remote_as"], cur["local_as"], cur["link"] = _asn(m["ras"]), _asn(m["las"]), m["link"]
                continue
            m = re.match(r"^Description: (?P<d>.*)$", s)
            if m and af is None:
                cur["description"] = m["d"]
                continue
            m = re.match(r"^Remote router ID (?P<rid>\S+)", s)
            if m:
                cur["remote_router_id"] = m["rid"]
                continue
            m = re.match(r"^Cluster ID (?P<c>\S+)", s)
            if m:
                cur["cluster_id"] = m["c"]
                continue
            m = re.match(r"^BGP state = (?P<st>\w+)(?:, up for (?P<up>\S+))?(?:, down for (?P<down>\S+))?", s)
            if m:
                cur["state"] = m["st"]
                if m["up"]:
                    cur["uptime"] = m["up"]
                if m["down"]:
                    cur["downtime"] = m["down"]
                continue
            m = re.match(r"^NSR State: (?P<st>.+)$", s)
            if m:
                cur["nsr_state"] = m["st"]
                continue
            m = re.match(r"^Hold time is (?P<h>\d+), keepalive interval is (?P<k>\d+) seconds", s)
            if m:
                cur["hold_time"], cur["keepalive_interval"] = int(m["h"]), int(m["k"])
                continue
            m = re.match(r"^Configured hold time: (?P<h>\d+), keepalive: (?P<k>\d+), min acceptable hold time: (?P<mh>\d+)", s)
            if m:
                cur["configured_hold_time"], cur["configured_keepalive"], cur["min_hold_time"] = int(m["h"]), int(m["k"]), int(m["mh"])
                continue
            m = re.match(r"^(?P<dir>Received|Sent) (?P<msgs>\d+) messages, (?P<notif>\d+) notifications, (?P<q>\d+) in queue", s)
            if m:
                d = "received" if m["dir"] == "Received" else "sent"
                cur[f"messages_{d}"] = int(m["msgs"])
                cur[f"notifications_{d}"] = int(m["notif"])
                continue
            if s == "Neighbor capabilities:":
                section = "caps"
                cur["capabilities"] = {}
                continue
            if section == "caps" and raw.startswith("    ") and ":" in s:
                k, _, v = s.partition(":")
                cur["capabilities"][k.strip()] = v.strip()
                continue
            section = None
            m = re.match(r"^For Address Family: (?P<af>.+)$", s)
            if m:
                af = cur["address_families"].setdefault(m["af"].lower(), {})
                continue
            m = re.match(r"^Connections established (?P<e>\d+); dropped (?P<d>\d+)", s)
            if m:
                cur["connections_established"], cur["connections_dropped"] = int(m["e"]), int(m["d"])
                af = None
                continue
            m = re.match(r"^Local host: (?P<h>\S+), Local port: (?P<p>\d+)(?:, IF Handle: (?P<ifh>\S+))?", s)
            if m:
                cur["local_host"], cur["local_port"] = m["h"], int(m["p"])
                continue
            m = re.match(r"^Foreign host: (?P<h>\S+), Foreign port: (?P<p>\d+)", s)
            if m:
                cur["foreign_host"], cur["foreign_port"] = m["h"], int(m["p"])
                continue
            m = re.match(r"^Last reset (?P<when>\S+), due to (?P<why>.+)$", s)
            if m:
                cur["last_reset"], cur["last_reset_reason"] = m["when"], m["why"]
                continue
            m = re.match(r"^Peer reset reason: (?P<why>.+)$", s)
            if m:
                cur["peer_reset_reason"] = m["why"]
                continue
            if s.startswith("Graceful restart is enabled"):
                cur["graceful_restart"] = True
                continue
            m = re.match(r"^Update source: (?P<src>\S+)", s)
            if m:
                cur["update_source"] = m["src"]
                continue
            m = re.match(r"^BFD (?:enabled|disabled)", s)
            if m:
                cur["bfd"] = s
                continue
            if af is not None:
                m = re.match(r"^(?P<acc>\d+) accepted prefixes, (?P<best>\d+) are bestpaths", s)
                if m:
                    af["accepted_prefixes"], af["best_paths"] = int(m["acc"]), int(m["best"])
                    continue
                m = re.match(r"^Prefix advertised (?P<a>\d+), suppressed (?P<s>\d+), withdrawn (?P<w>\d+)", s)
                if m:
                    af["prefixes_advertised"], af["prefixes_suppressed"], af["prefixes_withdrawn"] = int(m["a"]), int(m["s"]), int(m["w"])
                    continue
                m = re.match(r"^Maximum prefixes allowed (?P<n>\d+)", s)
                if m:
                    af["maximum_prefixes"] = int(m["n"])
                    continue
                m = re.match(r"^Policy for (?P<dir>incoming|outgoing) advertisements is (?P<p>\S+)", s)
                if m:
                    af[f"{'inbound' if m['dir'] == 'incoming' else 'outbound'}_policy"] = m["p"]
                    continue
                m = re.match(r"^BGP neighbor version (?P<v>\d+)", s)
                if m:
                    af["neighbor_version"] = int(m["v"])
                    continue
                m = re.match(r"^Update group: (?P<ug>\S+)(?:\s+Filter-group: (?P<fg>\S+))?", s)
                if m:
                    af["update_group"] = m["ug"]
                    if m["fg"]:
                        af["filter_group"] = m["fg"]
                    continue
                m = re.match(r"^Route refresh request: received (?P<r>\d+), sent (?P<s>\d+)", s)
                if m:
                    af["route_refresh_received"], af["route_refresh_sent"] = int(m["r"]), int(m["s"])
                    continue
                if s in ("NEXT_HOP is always this router", "Route-Reflector Client", "Community attribute sent to this neighbor", "Extended community attribute sent to this neighbor"):
                    af.setdefault("flags", []).append(s)
                    continue
                m = re.match(r"^Cumulative no\. of prefixes denied: (?P<n>\d+)", s)
                if m:
                    af["prefixes_denied"] = int(m["n"])
                    continue
        return out


# --------------------------------------------------------------------------- #
# OSPF
# --------------------------------------------------------------------------- #


@register("iosxr", "show [(ospf|ospfv3)] [<process>] [vrf (all|<vrf>)] neighbor [<interface>] [<neighbor>]", "show (ospf|ospfv3) [<process>] [vrf (all|<vrf>)] neighbor", "show ospf [vrf (all|<vrf>)] neighbor", intent="ospf.neighbors")
class ShowOspfNeighbor(Parser):
    """OSPF adjacencies with state, DR role, dead timer and uptime."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbors": []}
        process = vrf = None
        last = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Neighbors for OSPF(?:v3)? (?P<p>\S+?)(?:, VRF (?P<vrf>\S+))?$", s)
            if m:
                process, vrf = m["p"], m["vrf"] or "default"
                continue
            m = re.match(
                r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<pri>\d+)\s+(?P<state>\w+)(?:/\s*(?P<role>[\w-]+))?\s+(?P<dead>\S+)\s+(?P<addr>\S+)\s+(?P<intf>\S+(?: \d\S*)?)(?:\s+(?P<flags>[*#]+))?$",
                s,
            )
            if m:
                last = {
                    "neighbor_id": m["id"],
                    "priority": int(m["pri"]),
                    "state": m["state"],
                    "role": None if m["role"] in (None, "-") else m["role"],
                    "dead_time": m["dead"],
                    "address": m["addr"],
                    "interface": m["intf"],
                    "process": process,
                    "vrf": vrf or "default",
                }
                out["neighbors"].append(last)
                continue
            m = re.match(r"^Neighbor is up for (?P<up>\S+)", s)
            if m and last:
                last["uptime"] = m["up"]
                continue
            m = re.match(r"^Total neighbor count: (?P<n>\d+)", s)
            if m:
                out["total"] = out.get("total", 0) + int(m["n"])
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record("ospf.neighbors", neighbor_id=n["neighbor_id"], priority=n["priority"], state=n["state"].lower(), address=n["address"], interface=n["interface"], dead_time=n["dead_time"])
            for n in data["neighbors"]
        ]


@register("iosxr", "show (ospf|ospfv3) [<process>] [vrf (all|<vrf>)] interface brief", "show ospf [vrf (all|<vrf>)] interface brief")
class ShowOspfInterfaceBrief(Parser):
    """OSPF enabled interfaces with area, cost and state."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        vrf = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^\* Indicates|^Interfaces for OSPF (?P<p>\S+?)(?:, VRF (?P<vrf>\S+))?$", s)
            if m and m.groupdict().get("vrf"):
                vrf = m["vrf"]
            m = re.match(r"^(?P<intf>\S+)\s+(?P<pid>\S+)\s+(?P<area>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+/\d+)\s+(?P<cost>\d+)\s+(?P<state>\S+)\s+(?P<nbrs>\d+)/(?P<full>\d+)$", s)
            if m:
                out.append(
                    {
                        "interface": m["intf"],
                        "process": m["pid"],
                        "area": to_num(m["area"]),
                        "ip_address": m["ip"],
                        "cost": int(m["cost"]),
                        "state": m["state"],
                        "neighbors": int(m["nbrs"]),
                        "neighbors_full": int(m["full"]),
                        "vrf": vrf or "default",
                    }
                )
        return out


# --------------------------------------------------------------------------- #
# IS-IS
# --------------------------------------------------------------------------- #


@register("iosxr", "show isis [instance <instance>] adjacency [(detail|level-1|level-2|<interface>)]", intent="isis.adjacency")
class ShowIsisAdjacency(Parser):
    """IS-IS adjacencies per level."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"adjacencies": []}
        inst = level = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^IS-IS (?P<inst>\S+) (?P<lvl>Level-\d) adjacencies:", s)
            if m:
                inst, level = m["inst"], m["lvl"].lower()
                continue
            m = re.match(
                r"^(?P<sys>\S+)\s+(?P<intf>\S+)\s+(?P<snpa>\S+)\s+(?P<state>Up|Down|Init|Failed|None)\s+(?P<hold>\d+)\s+(?P<changed>\S+)(?:\s+(?P<nsf>\S+))?(?:\s+(?P<bfd4>\S+))?(?:\s+(?P<bfd6>\S+))?$",
                s,
            )
            if m and inst:
                adj = {
                    "instance": inst,
                    "level": level,
                    "system_id": m["sys"],
                    "interface": m["intf"],
                    "snpa": m["snpa"],
                    "state": m["state"],
                    "hold_time": int(m["hold"]),
                    "changed": m["changed"],
                    "nsf": m["nsf"],
                    "bfd": m["bfd4"],
                }
                if m["bfd6"]:
                    adj["ipv4_bfd"], adj["ipv6_bfd"] = adj.pop("bfd"), m["bfd6"]
                out["adjacencies"].append(compact(adj))
                continue
            m = re.match(r"^Total adjacency count: (?P<n>\d+)", s)
            if m:
                out["total"] = out.get("total", 0) + int(m["n"])
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("isis.adjacency", system_id=a["system_id"], interface=a["interface"], state=a["state"].lower(), level=a.get("level"), hold_time=a.get("hold_time"), snpa=a.get("snpa")) for a in data["adjacencies"]]


@register("iosxr", "show isis [instance <instance>] neighbors [(detail|summary|<interface>)]", intent="isis.adjacency")
class ShowIsisNeighbors(Parser):
    """IS-IS neighbors with SNPA, hold time and circuit type."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbors": []}
        inst = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^IS-IS (?P<inst>\S+) neighbors:", s)
            if m:
                inst = m["inst"]
                continue
            m = re.match(r"^(?P<sys>\S+)\s+(?P<intf>\S+)\s+(?P<snpa>\S+)\s+(?P<state>Up|Down|Init|Failed)\s+(?P<hold>\d+)\s+(?P<type>L1L2|L1|L2)\s+(?P<nsf>\S+)$", s)
            if m:
                out["neighbors"].append(
                    {"instance": inst, "system_id": m["sys"], "interface": m["intf"], "snpa": m["snpa"], "state": m["state"], "hold_time": int(m["hold"]), "type": m["type"], "ietf_nsf": m["nsf"]}
                )
                continue
            m = re.match(r"^Total neighbor count: (?P<n>\d+)", s)
            if m:
                out["total"] = out.get("total", 0) + int(m["n"])
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("isis.adjacency", system_id=a["system_id"], interface=a["interface"], state=a["state"].lower(), level=a["type"], hold_time=a["hold_time"], snpa=a["snpa"]) for a in data["neighbors"]]
