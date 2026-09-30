"""IOS XR BGP RIB: ``show bgp``, per-prefix detail and per-neighbor advertised/received routes."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from ...registry import Parser, register
from ...textutils import to_num
from .routing import af_from_command

_IP = r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+"
_ROW = re.compile(rf"^(?P<codes>[sdhirSNmbfxac*> ]*?)(?P<net>(?:{_IP})/\d+)?\s+(?P<nh>{_IP})(?P<rest>(?:\s.*)?)$")
_NET_ONLY = re.compile(rf"^(?P<codes>[sdhirSNmbfxac*> ]*?)(?P<net>(?:{_IP})/\d+)\s*$")
_ORIGIN = {"i": "igp", "e": "egp", "?": "incomplete"}


def _path_origin(text: str) -> Dict[str, Any]:
    text = text.strip()
    m = re.match(r"^(?P<path>.*?)\s*(?P<o>[ie?])$", text)
    if not m:
        return {"as_path": text or None}
    return {"as_path": m["path"].strip() or None, "origin": _ORIGIN[m["o"]]}


def parse_bgp_table(text: str, vrf: Optional[str], af: str) -> Dict[str, Any]:
    """Parse the ``Network  Next Hop  Metric LocPrf Weight Path`` table (shared by several commands)."""
    out: Dict[str, Any] = {"routes": []}
    m = re.search(r"BGP router identifier (\S+), local AS number (\S+)", text)
    if m:
        out["router_id"] = m.group(1)
        out["local_as"] = int(m.group(2)) if m.group(2).isdigit() else m.group(2)
    rd = None
    cur_vrf = vrf or "default"
    cols: Dict[str, int] = {}
    network: Optional[str] = None
    pending: Optional[str] = None
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.strip():
            continue
        m = re.match(r"^\s*VRF:\s*(\S+)", s)
        if m:
            cur_vrf = m.group(1)
            continue
        m = re.match(r"^\s*Route Distinguisher:\s*(?P<rd>\S+)(?:\s*\(default for vrf (?P<vrf>[^)]+)\))?", s)
        if m:
            rd = m["rd"]
            if m["vrf"]:
                cur_vrf = m["vrf"]
            continue
        if re.match(r"^\s*Network\s+Next[ -][Hh]op", s):
            for name in ("Metric", "LocPrf", "Weight", "Path"):
                idx = s.find(name)
                if idx >= 0:
                    cols[name] = idx + len(name)
            continue
        if not cols:
            continue
        m = _NET_ONLY.match(s)
        if m and "*" in (m["codes"] or ""):
            pending = m["net"]
            pending_codes = m["codes"]
            continue
        m = _ROW.match(s)
        if not m:
            continue
        codes = m["codes"] or ""
        if pending and not m["net"]:
            codes = codes.strip() or pending_codes
            network = pending
            pending = None
        elif m["net"]:
            network = m["net"]
        if network is None or ("*" not in codes and not codes.strip()):
            continue
        route: Dict[str, Any] = {
            "network": network,
            "next_hop": m["nh"],
            "valid": "*" in codes,
            "best": ">" in codes,
            "internal": "i" in codes,
            "vrf": cur_vrf,
            "address_family": af,
        }
        for code, key in (("s", "suppressed"), ("d", "damped"), ("h", "history"), ("r", "rib_failure"), ("S", "stale")):
            if code in codes:
                route[key] = True
        if rd:
            route["route_distinguisher"] = rd
        rest = m["rest"] or ""
        offset = len(s) - len(rest)
        # Metric/LocPrf are right-aligned and optional; Weight is always printed and is the last
        # number that starts inside the Weight column. Anything after it is the AS path.
        weight_end = cols.get("Weight", 10**6)
        zone = []
        path_start = len(rest)
        for tok in re.finditer(r"\S+", rest):
            if tok.group().isdigit() and offset + tok.start() <= weight_end and len(zone) < 3:
                zone.append(tok)
                continue
            path_start = tok.start()
            break
        route["metric"] = route["local_preference"] = route["weight"] = None
        if zone:
            route["weight"] = int(zone[-1].group())
            before = zone[:-1]
            if len(before) == 2:
                route["metric"], route["local_preference"] = int(before[0].group()), int(before[1].group())
            elif before:
                if offset + before[0].end() <= cols.get("Metric", 0) + 1:
                    route["metric"] = int(before[0].group())
                else:
                    route["local_preference"] = int(before[0].group())
        route.update(_path_origin(rest[path_start:]))
        out["routes"].append(route)
    m = re.search(r"Processed (\d+) prefixes, (\d+) paths", text)
    if m:
        out["processed_prefixes"], out["processed_paths"] = int(m.group(1)), int(m.group(2))
    return out


def _parse_prefix_detail(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"entries": []}
    cur: Optional[Dict[str, Any]] = None
    path: Optional[Dict[str, Any]] = None
    expect_path_as = False
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        m = re.match(r"^BGP routing table entry for (?P<p>\S+?)(?:, Route Distinguisher: (?P<rd>\S+))?$", s)
        if m:
            cur = {"prefix": m["p"], "paths": []}
            if m["rd"]:
                cur["route_distinguisher"] = m["rd"]
            out["entries"].append(cur)
            path = None
            continue
        if cur is None:
            continue
        m = re.match(r"^Local Label: (\S+)", s)
        if m:
            cur["local_label"] = to_num(m.group(1))
            continue
        m = re.match(r"^Last Modified: (?P<t>.+?) for (?P<age>\S+)", s)
        if m:
            cur["last_modified"], cur["age"] = m["t"], m["age"]
            continue
        m = re.match(r"^Paths: \((?P<n>\d+) available(?:, best #(?P<best>\d+))?", s)
        if m:
            cur["paths_available"] = int(m["n"])
            if m["best"]:
                cur["best_path"] = int(m["best"])
            continue
        m = re.match(r"^Path #(?P<n>\d+): (?P<desc>.+)$", s)
        if m:
            path = {"index": int(m["n"]), "received_by": m["desc"]}
            cur["paths"].append(path)
            expect_path_as = True
            continue
        if path is None:
            continue
        m = re.match(rf"^(?P<nh>{_IP}|::)(?:\s+\(metric (?P<igp>\d+)\))? from (?P<frm>{_IP}|::) \((?P<rid>[^)]+)\)", s)
        if m:
            path["next_hop"], path["from"], path["router_id"] = m["nh"], m["frm"], m["rid"]
            if m["igp"]:
                path["igp_metric"] = int(m["igp"])
            expect_path_as = False
            continue
        if expect_path_as and not s.startswith(("Advertised", "Not advertised")) and not re.match(rf"^{_IP}\s*$", s):
            path["as_path"] = None if s == "Local" else s
            continue
        m = re.match(r"^Origin (?P<o>\w+)(?P<rest>.*)$", s)
        if m:
            path["origin"] = m["o"].lower()
            for part in [p.strip() for p in m["rest"].split(",") if p.strip()]:
                kv = re.match(r"^(metric|localpref|weight)\s+(\d+)$", part)
                if kv:
                    path[{"localpref": "local_preference"}.get(kv.group(1), kv.group(1))] = int(kv.group(2))
                else:
                    path.setdefault("flags", []).append(part)
            path["best"] = "best" in path.get("flags", [])
            continue
        m = re.match(r"^(?:Extended )?[Cc]ommunity: (?P<c>.+)$", s)
        if m:
            path["extended_communities" if s.startswith("Extended") else "communities"] = m["c"].split()
            continue
        m = re.match(r"^Large Community: (?P<c>.+)$", s)
        if m:
            path["large_communities"] = m["c"].split()
    return out


@register(
    "iosxr",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|all)] [(unicast|multicast|labeled-unicast|all)] [<prefix>]",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|all)] [(unicast|multicast|labeled-unicast|all)] rd <rd> [<prefix>]",
    "show ip bgp [vrf (all|<vrf>)] [<prefix>]",
)
class ShowBgp(Parser):
    """BGP table (status codes, next hop, metric, local-pref, weight, AS path, origin) or per-prefix path detail."""

    def parse(self, text: str) -> Dict[str, Any]:
        if re.search(r"^\s*BGP routing table entry for ", text, re.M):
            return _parse_prefix_detail(text)
        vrf = self.params.get("vrf")
        return parse_bgp_table(text, None if vrf in (None, "all") else vrf, af_from_command(self.command))


@register(
    "iosxr",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|all)] [(unicast|multicast|labeled-unicast|all)] neighbors <neighbor> (routes|received routes|received-routes|dampened-routes|flap-statistics)",
)
class ShowBgpNeighborRoutes(Parser):
    """Routes received from a neighbor (accepted or pre-policy)."""

    def parse(self, text: str) -> Dict[str, Any]:
        vrf = self.params.get("vrf")
        data = parse_bgp_table(text, None if vrf in (None, "all") else vrf, af_from_command(self.command))
        data["neighbor"] = self.params.get("neighbor")
        return data


@register(
    "iosxr",
    "show bgp [instance (all|<instance>)] [vrf (all|<vrf>)] [(ipv4|ipv6|vpnv4|vpnv6|all)] [(unicast|multicast|labeled-unicast|all)] neighbors <neighbor> advertised-routes [summary]",
)
class ShowBgpNeighborAdvertisedRoutes(Parser):
    """Routes advertised to a neighbor: network, next hop, from, AS path, origin."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbor": self.params.get("neighbor"), "routes": []}
        vrf = self.params.get("vrf") if self.params.get("vrf") not in (None, "all") else "default"
        rd = None
        pending: Optional[str] = None
        af = af_from_command(self.command)
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^VRF:\s*(\S+)", s)
            if m:
                vrf = m.group(1)
                continue
            m = re.match(r"^Route Distinguisher:\s*(?P<rd>\S+)(?:\s*\(default for vrf (?P<vrf>[^)]+)\))?", s)
            if m:
                rd = m["rd"]
                if m["vrf"]:
                    vrf = m["vrf"]
                continue
            m = re.match(rf"^(?P<net>(?:{_IP})/\d+)\s*$", s)
            if m:
                pending = m["net"]
                continue
            m = re.match(rf"^(?:(?P<net>(?:{_IP})/\d+)\s+)?(?P<nh>{_IP})\s+(?P<frm>{_IP}|Local)\s*(?P<path>.*)$", s)
            if not m:
                continue
            net = m["net"] or pending
            pending = None
            if not net:
                continue
            route = {"network": net, "next_hop": m["nh"], "from": m["frm"], "vrf": vrf, "address_family": af}
            if rd:
                route["route_distinguisher"] = rd
            route.update(_path_origin(m["path"]))
            out["routes"].append(route)
        m = re.search(r"Processed (\d+) prefixes, (\d+) paths", text)
        if m:
            out["processed_prefixes"], out["processed_paths"] = int(m.group(1)), int(m.group(2))
        return out
