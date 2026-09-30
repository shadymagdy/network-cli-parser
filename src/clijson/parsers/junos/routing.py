"""Junos routing: route tables, BGP, OSPF/OSPFv3, IS-IS, LDP, RSVP, MPLS and BFD."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import record
from ...registry import Parser, register
from ...textutils import compact, match_lines, snake, to_num

# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

_TABLE_HDR = re.compile(
    r"^(?P<table>[\w.\-:]+): (?P<dest>\d+) destinations, (?P<routes>\d+) routes \((?P<active>\d+) active, (?P<hold>\d+) holddown, (?P<hidden>\d+) hidden\)"
)
_PATH = re.compile(
    r"^(?P<flag>[*+\-]{0,2})\[(?P<proto>[\w\-]+)/(?P<pref>\d+)(?:/(?P<pref2>-?\d+))?\]\s+(?P<age>[^,]+?)(?:,\s*(?P<attrs>.*))?$"
)
_NH = re.compile(r"^(?P<sel>>)?\s*(?:to (?P<nh>\S+)\s+)?via (?P<intf>[^,\s]+)(?:,\s*(?P<ops>.+))?$")
_SPECIAL_NH = re.compile(
    r"^(?P<sel>>)?\s*(?P<what>Local via (?P<intf>\S+)|Discard|Reject|Receive|Multicast.*|Indirect.*|Table \S+)$"
)


@register("junos", "show route [<args...>]", intent="routes")
class ShowRoute(Parser):
    """Route tables with every path (active flag, protocol, preference, metrics, AS path, next-hops, labels)."""

    def parse(self, text: str) -> Dict[str, Any]:
        args = (self.params.get("args") or "").split()
        default_table = args[args.index("table") + 1] if "table" in args[:-1] else "inet.0"
        if re.search(r"^[ \t]*\S+ \(\d+ entr(?:y|ies), \d+ announced\)", text, re.M):
            return _parse_route_detail(text, default_table)
        tables: Dict[str, Any] = {}
        routes: List[Dict[str, Any]] = []
        table = default_table
        cur_route: Optional[Dict[str, Any]] = None
        cur_path: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            if not raw.strip():
                continue
            s = raw.strip()
            m = _TABLE_HDR.match(s)
            if m:
                table = m["table"]
                tables[table] = {
                    "destinations": int(m["dest"]),
                    "routes": int(m["routes"]),
                    "active": int(m["active"]),
                    "holddown": int(m["hold"]),
                    "hidden": int(m["hidden"]),
                }
                cur_route = cur_path = None
                continue
            if s.startswith(("+ = Active Route", "Restart Complete")):
                continue
            if not raw.startswith(" "):
                # destination line (may carry the first path)
                parts = s.split(None, 1)
                cur_route = {"table": table, "prefix": parts[0], "paths": []}
                routes.append(cur_route)
                cur_path = None
                if len(parts) > 1:
                    pm = _PATH.match(parts[1].strip())
                    if pm:
                        cur_path = _new_path(pm)
                        cur_route["paths"].append(cur_path)
                continue
            if cur_route is None:
                continue
            pm = _PATH.match(s)
            if pm:
                cur_path = _new_path(pm)
                cur_route["paths"].append(cur_path)
                continue
            if cur_path is None:
                continue
            m = re.match(r"^AS path: (?P<path>.+?)(?:,\s*validation-state: (?P<vs>\S+))?$", s)
            if m:
                cur_path["as_path"] = m["path"].strip()
                if m["vs"]:
                    cur_path["validation_state"] = m["vs"]
                continue
            m = _NH.match(s)
            if m:
                nh: Dict[str, Any] = {"next_hop": m["nh"], "interface": m["intf"], "selected": bool(m["sel"])}
                if m["ops"]:
                    nh["label_operation"] = m["ops"].strip()
                cur_path["next_hops"].append({k: v for k, v in nh.items() if v is not None})
                continue
            m = _SPECIAL_NH.match(s)
            if m:
                cur_path["next_hops"].append(
                    compact({"type": m["what"].split()[0].lower(), "interface": m["intf"], "selected": bool(m["sel"])})
                )
                continue
        out: Dict[str, Any] = {"tables": tables, "routes": routes}
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        res = []
        for r in data["routes"]:
            active = next((p for p in r["paths"] if p.get("active")), r["paths"][0] if r["paths"] else {})
            res.append(
                record(
                    "routes",
                    prefix=r["prefix"],
                    protocol=(active.get("protocol") or "").lower() or None,
                    next_hops=[
                        {"next_hop": nh.get("next_hop"), "interface": nh.get("interface")}
                        for nh in active.get("next_hops", [])
                    ],
                    distance=active.get("preference"),
                    metric=active.get("metric"),
                    vrf=r["table"].split(".")[0] if r["table"] not in ("inet.0", "inet6.0") else "default",
                    age=active.get("age"),
                )
            )
        return res


def _parse_route_detail(text: str, table: str) -> Dict[str, Any]:
    """``show route ... detail|extensive``: one block per destination, one sub-block per path."""
    tables: Dict[str, Any] = {}
    routes: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    path: Optional[Dict[str, Any]] = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        m = _TABLE_HDR.match(s)
        if m:
            table = m["table"]
            tables[table] = {
                "destinations": int(m["dest"]),
                "routes": int(m["routes"]),
                "active": int(m["active"]),
                "holddown": int(m["hold"]),
                "hidden": int(m["hidden"]),
            }
            continue
        m = re.match(r"^(?P<prefix>\S+) \((?P<n>\d+) entr(?:y|ies), (?P<ann>\d+) announced\)", s)
        if m:
            cur = {
                "table": table,
                "prefix": m["prefix"],
                "entries": int(m["n"]),
                "announced": int(m["ann"]),
                "paths": [],
            }
            routes.append(cur)
            path = None
            continue
        if cur is None:
            continue
        m = re.match(
            r"^(?P<flag>[*+\-]{0,2})(?P<proto>[A-Za-z][\w\-]*)\s+Preference: (?P<pref>\d+)(?:/(?P<pref2>-?\d+))?", s
        )
        if m:
            flag = m["flag"] or ""
            path = {
                "active": "*" in flag or "+" in flag,
                "protocol": m["proto"],
                "preference": int(m["pref"]),
                "next_hops": [],
            }
            if m["pref2"]:
                path["preference2"] = int(m["pref2"])
            cur["paths"].append(path)
            continue
        if path is None:
            continue
        m = re.match(r"^Next hop: (?:(?P<nh>\S+) )?via (?P<intf>\S+)(?P<rest>.*)$", s)
        if m:
            path["next_hops"].append(
                compact({"next_hop": m["nh"], "interface": m["intf"], "selected": "selected" in m["rest"]})
            )
            continue
        m = re.match(r"^Age: (?P<age>.+?)(?:\s+Metric: (?P<metric>\d+))?(?:\s+Metric2: (?P<m2>\d+))?\s*$", s)
        if m:
            path["age"] = m["age"].strip()
            if m["metric"]:
                path["metric"] = int(m["metric"])
            if m["m2"]:
                path["metric2"] = int(m["m2"])
            continue
        m = re.match(r"^State: <(?P<st>[^>]*)>", s)
        if m:
            path["state"] = m["st"].split()
            continue
        m = re.match(
            r"^(?P<k>Protocol next hop|Local AS|Peer AS|Area|Task|AS path|Communities|Localpref|Router ID|Source|Validation State|Label operation|Indirect next hop|Next hop type|Label TTL action|Cluster list|Originator ID|Accepted Multipath|Primary Routing Table|Secondary Tables|Tag):\s*(?P<v>.+)$",
            s,
        )
        if m:
            key = snake(m["k"])
            if key == "protocol_next_hop":
                path.setdefault("protocol_next_hops", []).append(m["v"].strip())
            else:
                path[key] = to_num(m["v"].strip())
    return {"tables": tables, "routes": routes}


def _new_path(m: "re.Match[str]") -> Dict[str, Any]:
    flag = m["flag"] or ""
    path: Dict[str, Any] = {
        "active": "*" in flag or "+" in flag,
        "last_active": "-" in flag or "*" in flag,
        "protocol": m["proto"],
        "preference": int(m["pref"]),
        "age": m["age"].strip(),
        "next_hops": [],
    }
    if m["pref2"]:
        path["preference2"] = int(m["pref2"])
    for attr in (m["attrs"] or "").split(","):
        attr = attr.strip()
        am = re.match(r"^(metric|metric2|MED|localpref|from|tag|tag2)\s+(\S+)$", attr)
        if am:
            key = {"MED": "med"}.get(am.group(1), am.group(1).lower())
            path[key] = to_num(am.group(2))
        elif attr:
            path.setdefault("flags", []).append(attr)
    return path


@register("junos", "show route summary [(table <table>|instance <instance>)]")
class ShowRouteSummary(Parser):
    """Route counts per table and protocol."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"tables": {}}
        m = re.search(r"Autonomous system number:\s*(\d+)", text)
        if m:
            out["local_as"] = int(m.group(1))
        m = re.search(r"Router ID:\s*(\S+)", text)
        if m:
            out["router_id"] = m.group(1)
        cur: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            s = raw.strip()
            m = _TABLE_HDR.match(s)
            if m:
                cur = out["tables"][m["table"]] = {
                    "destinations": int(m["dest"]),
                    "routes": int(m["routes"]),
                    "active": int(m["active"]),
                    "holddown": int(m["hold"]),
                    "hidden": int(m["hidden"]),
                    "protocols": {},
                }
                continue
            m = re.match(r"^(?P<proto>[\w\-]+):\s+(?P<routes>\d+) routes,\s+(?P<active>\d+) active", s)
            if m and cur is not None:
                cur["protocols"][m["proto"]] = {"routes": int(m["routes"]), "active": int(m["active"])}
        return out


# --------------------------------------------------------------------------- #
# BGP
# --------------------------------------------------------------------------- #


@register(
    "junos",
    "show bgp summary [(instance <instance>|group <group>|logical-system <ls>)]",
    "show bgp summary (instance <instance>|group <group>)",
    intent="bgp.summary",
)
class ShowBgpSummary(Parser):
    """BGP peers with state, flaps, uptime and per-table prefix counters."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"tables": {}, "neighbors": []}
        m = re.search(r"Groups:\s*(\d+)\s+Peers:\s*(\d+)\s+Down peers:\s*(\d+)", text)
        if m:
            out["groups"], out["peers"], out["down_peers"] = int(m.group(1)), int(m.group(2)), int(m.group(3))
        m = re.search(r"Threading mode:\s*(.+)", text)
        if m:
            out["threading_mode"] = m.group(1).strip()
        lines = text.splitlines()
        i = 0
        in_tables = in_peers = False
        pending_table: Optional[str] = None
        last: Optional[Dict[str, Any]] = None
        while i < len(lines):
            s = lines[i].strip()
            i += 1
            if not s:
                continue
            if s.startswith("Table") and "Tot Paths" in s:
                in_tables, in_peers = True, False
                continue
            if s.startswith("Peer") and " AS " in f" {s} ":
                in_tables, in_peers = False, True
                continue
            if in_tables:
                m = re.match(r"^(?P<t>[\w.\-:]+)(?:\s+(?P<nums>[\d\s]+))?$", s)
                if m and not s[0].isdigit():
                    nums = (m["nums"] or "").split()
                    if len(nums) >= 6:
                        out["tables"][m["t"]] = _table_counts(nums)
                        pending_table = None
                    else:
                        pending_table = m["t"]
                    continue
                if pending_table and re.match(r"^[\d\s]+$", s):
                    out["tables"][pending_table] = _table_counts(s.split())
                    pending_table = None
                    continue
            if in_peers:
                m = re.match(
                    r"^(?P<peer>[0-9a-fA-F.:]+)(?:\+\d+)?\s+(?P<as>[\d.]+)\s+(?P<inpkt>\d+)\s+(?P<outpkt>\d+)\s+(?P<outq>\d+)\s+(?P<flaps>\d+)\s+(?P<updown>\d[\dwdhms:]*(?:\s+\d+:\d\d:\d\d)?)\s+(?P<state>.+?)\s*$",
                    s,
                )
                if m:
                    state_raw = m["state"].strip()
                    last = {
                        "neighbor": m["peer"],
                        "remote_as": int(m["as"]) if m["as"].isdigit() else m["as"],
                        "input_messages": int(m["inpkt"]),
                        "output_messages": int(m["outpkt"]),
                        "output_queue": int(m["outq"]),
                        "flaps": int(m["flaps"]),
                        "up_down": m["updown"].strip(),
                        "state": state_raw,
                        "tables": {},
                    }
                    counts = re.findall(r"(\d+)/(\d+)/(\d+)/(\d+)", state_raw)
                    if counts or state_raw.startswith("Establ"):
                        last["state"] = "Established"
                        if counts:
                            # "0/0/0/0  0/0/0/0" = counters for tables listed above, in order
                            for tname, c in zip(list(out["tables"]) or ["inet.0"], counts):
                                last["tables"][tname] = _peer_counts(c)
                    out["neighbors"].append(last)
                    continue
                m = re.match(r"^(?P<t>[\w.\-:]+):\s*(?P<a>\d+)/(?P<r>\d+)/(?P<acc>\d+)/(?P<d>\d+)$", s)
                if m and last is not None:
                    last["tables"][m["t"]] = _peer_counts((m["a"], m["r"], m["acc"], m["d"]))
                    continue
        for n in out["neighbors"]:
            n["prefixes_received"] = sum(t["received"] for t in n["tables"].values()) if n["tables"] else None
            n["uptime_seconds"] = bgp_uptime_seconds(n["up_down"])
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        res = []
        for n in data["neighbors"]:
            tables = list(n["tables"]) or [None]
            res.append(
                record(
                    "bgp.summary",
                    neighbor=n["neighbor"],
                    remote_as=n["remote_as"],
                    state=n["state"],
                    established=n["state"] == "Established",
                    uptime=n["up_down"],
                    uptime_seconds=n.get("uptime_seconds"),
                    prefixes_received=n.get("prefixes_received"),
                    vrf=self.params.get("instance") or "default",
                    address_family=_table_af(tables[0]),
                )
            )
        return res


def bgp_uptime_seconds(value: str) -> Optional[int]:
    """Junos ``Last Up/Dwn``: ``9w2d 5:23:37``, ``1d 2:03:04``, ``1:02:03``, ``4:05`` (m:s) or ``9`` (s)."""
    m = re.match(r"^\s*(?:(\d+)w)?(?:(\d+)d)?\s*(?:(\d+):)?(?:(\d+):)?(\d+)\s*$", value)
    if not m:
        return None
    w, d, a, b, c = m.groups()
    if a is not None and b is not None:
        h, mi = int(a), int(b)
    elif a is not None:
        h, mi = 0, int(a)
    else:
        h, mi = 0, 0
    return int(w or 0) * 604800 + int(d or 0) * 86400 + h * 3600 + mi * 60 + int(c)


def _table_counts(nums: List[str]) -> Dict[str, int]:
    keys = ["total_paths", "active_paths", "suppressed", "history", "damp_state", "pending"]
    return {k: int(v) for k, v in zip(keys, nums)}


def _peer_counts(c: Any) -> Dict[str, int]:
    return {"active": int(c[0]), "received": int(c[1]), "accepted": int(c[2]), "damped": int(c[3])}


def _table_af(table: Optional[str]) -> Optional[str]:
    if not table:
        return None
    name = table.split(".")[-2] if table.count(".") >= 1 else table
    return {
        "inet": "ipv4 unicast",
        "inet6": "ipv6 unicast",
        "l3vpn": "vpnv4 unicast",
        "l3vpn-inet6": "vpnv6 unicast",
        "evpn": "l2vpn evpn",
        "inet3": "ipv4 labeled-unicast",
        "l2vpn": "l2vpn vpls",
        "inetflow": "ipv4 flowspec",
    }.get(name, table)


@register(
    "junos",
    "show bgp neighbor [<neighbor>] [(instance <instance>|exact-instance <instance>)]",
    "show bgp neighbor instance <instance> [<neighbor>]",
)
class ShowBgpNeighbor(Parser):
    """Detailed BGP peer information: group, state, options, NLRI, per-table prefix counts."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        table: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(
                r"^Peer: (?P<peer>[0-9a-fA-F.:]+)(?:\+(?P<pport>\d+))?\s+AS (?P<pas>[\d.]+)\s+Local: (?P<local>[0-9a-fA-F.:]+)?(?:\+(?P<lport>\d+))?\s+AS (?P<las>[\d.]+)",
                s,
            )
            if m:
                cur = out[m["peer"]] = {
                    "peer_as": to_num(m["pas"]),
                    "local_address": m["local"],
                    "local_as": to_num(m["las"]),
                    "tables": {},
                }
                if m["pport"]:
                    cur["peer_port"] = int(m["pport"])
                if m["lport"]:
                    cur["local_port"] = int(m["lport"])
                table = None
                continue
            if not cur:
                continue
            m = re.match(r"^Table (?P<t>\S+)(?: Bit: (?P<bit>\S+))?", s)
            if m:
                table = cur["tables"][m["t"]] = {}
                continue
            if table is not None:
                m = re.match(
                    r"^(?P<k>Active|Received|Accepted|Advertised|Suppressed due to damping) prefixes?:?\s*(?P<v>\d+)$|^(?P<k2>Suppressed due to damping):\s*(?P<v2>\d+)$",
                    s,
                )
                if m:
                    k = m["k"] or m["k2"]
                    table[snake(k) + ("_prefixes" if "prefix" not in snake(k) and "damping" not in k else "")] = int(
                        m["v"] or m["v2"]
                    )
                    continue
                m = re.match(r"^(RIB State|Send state):\s*(?P<v>.+)$", s)
                if m:
                    table[snake(m.group(1))] = m["v"]
                    continue
            m = re.match(
                r"^Type: (?P<type>\S+)\s+State: (?P<state>\S+)(?:\s+\((?P<note>[^)]*)\))?\s*Flags: <(?P<flags>[^>]*)>",
                s,
            )
            if m:
                cur["type"], cur["state"] = m["type"], m["state"]
                if m["note"]:
                    cur["note"] = m["note"]
                cur["flags"] = m["flags"].split()
                continue
            m = re.match(r"^Group: (?P<g>\S+)\s+Routing-Instance: (?P<ri>\S+)", s)
            if m:
                cur["group"], cur["routing_instance"] = m["g"], m["ri"]
                continue
            m = re.match(r"^Last State: (?P<ls>\S+)\s+Last Event: (?P<le>\S+)", s)
            if m:
                cur["last_state"], cur["last_event"] = m["ls"], m["le"]
                continue
            m = re.match(r"^Export: \[ (?P<exp>.+?) \](?:\s*Import: \[ (?P<imp>.+?) \])?", s)
            if m:
                cur["export"] = m["exp"]
                if m["imp"]:
                    cur["import"] = m["imp"]
                continue
            m = re.match(r"^Import: \[ (?P<imp>.+?) \]", s)
            if m:
                cur["import"] = m["imp"]
                continue
            m = re.match(r"^Options: <(?P<o>[^>]*)>", s)
            if m:
                cur.setdefault("options", []).extend(m["o"].split())
                continue
            m = re.match(r"^Local Address: (?P<la>\S+) Holdtime: (?P<h>\d+) Preference: (?P<p>\d+)", s)
            if m:
                cur["holdtime"], cur["preference"] = int(m["h"]), int(m["p"])
                continue
            m = re.match(r"^Peer ID: (?P<pid>\S+)\s+Local ID: (?P<lid>\S+)\s+Active Holdtime: (?P<ah>\d+)", s)
            if m:
                cur["peer_id"], cur["local_id"], cur["active_holdtime"] = m["pid"], m["lid"], int(m["ah"])
                continue
            m = re.match(r"^Keepalive Interval: (?P<k>\d+)", s)
            if m:
                cur["keepalive_interval"] = int(m["k"])
                continue
            m = re.match(r"^Number of flaps: (?P<n>\d+)", s)
            if m:
                cur["flaps"] = int(m["n"])
                continue
            m = re.match(r"^Last flap event: (?P<e>.+)$", s)
            if m:
                cur["last_flap_event"] = m["e"]
                continue
            m = re.match(r"^Last Error: (?P<e>.+)$", s)
            if m:
                cur["last_error"] = m["e"]
                continue
            m = re.match(r"^Description: (?P<d>.+)$", s)
            if m:
                cur["description"] = m["d"]
                continue
            m = re.match(r"^BFD: (?P<b>.+)$", s)
            if m:
                cur["bfd"] = m["b"]
                continue
            m = re.match(
                r"^(?P<k>NLRI for this session|NLRI advertised by peer|Address families configured): (?P<v>.+)$", s
            )
            if m:
                cur[snake(m["k"])] = m["v"].split()
                continue
            m = re.match(r"^Last traffic \(seconds\): Received (?P<r>\d+)\s+Sent (?P<s>\d+)\s+Checked (?P<c>\d+)", s)
            if m:
                cur["last_traffic"] = {"received": int(m["r"]), "sent": int(m["s"]), "checked": int(m["c"])}
                continue
            m = re.match(r"^Input messages:\s+Total (?P<t>\d+)\s+Updates (?P<u>\d+)", s)
            if m:
                cur["input_messages"], cur["input_updates"] = int(m["t"]), int(m["u"])
                continue
            m = re.match(r"^Output messages:\s+Total (?P<t>\d+)\s+Updates (?P<u>\d+)", s)
            if m:
                cur["output_messages"], cur["output_updates"] = int(m["t"]), int(m["u"])
        return out


# --------------------------------------------------------------------------- #
# OSPF / OSPFv3
# --------------------------------------------------------------------------- #


@register(
    "junos",
    "show (ospf|ospf3) neighbor [<neighbor>] [(instance <instance>|area <area>|interface <interface>)] [(brief|detail|extensive)]",
    intent="ospf.neighbors",
)
class ShowOspfNeighbor(Parser):
    """OSPF / OSPFv3 adjacencies."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbors": []}
        last: Optional[Dict[str, Any]] = None
        v3 = "ospf3" in self.command.lower()
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            if not v3:
                m = re.match(
                    r"^(?P<addr>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)\s+(?P<state>\S+)\s+(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<pri>\d+)\s+(?P<dead>\d+)$",
                    s,
                )
                if m:
                    last = {
                        "address": m["addr"],
                        "interface": m["intf"],
                        "state": m["state"],
                        "neighbor_id": m["id"],
                        "priority": int(m["pri"]),
                        "dead_time": int(m["dead"]),
                    }
                    out["neighbors"].append(last)
                    continue
            else:
                m = re.match(
                    r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)\s+(?P<state>\S+)\s+(?P<pri>\d+)\s+(?P<dead>\d+)$", s
                )
                if m:
                    last = {
                        "neighbor_id": m["id"],
                        "interface": m["intf"],
                        "state": m["state"],
                        "priority": int(m["pri"]),
                        "dead_time": int(m["dead"]),
                    }
                    out["neighbors"].append(last)
                    continue
                m = re.match(r"^Neighbor-address (?P<a>\S+)", s)
                if m and last is not None:
                    last["address"] = m["a"]
                    continue
            if last is not None:
                m = re.match(r"^Area (?P<area>\S+), opt (?P<opt>\S+), DR (?P<dr>\S+), BDR (?P<bdr>\S+)", s)
                if m:
                    last.update({"area": m["area"], "options": m["opt"], "dr": m["dr"], "bdr": m["bdr"]})
                    continue
                m = re.match(r"^Up (?P<up>.+?), adjacent (?P<adj>.+)$", s)
                if m:
                    last["uptime"], last["adjacent_time"] = m["up"], m["adj"]
                    continue
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "ospf.neighbors",
                neighbor_id=n["neighbor_id"],
                priority=n["priority"],
                state=n["state"].lower(),
                address=n.get("address"),
                interface=n["interface"],
                dead_time=n["dead_time"],
            )
            for n in data["neighbors"]
        ]


@register(
    "junos",
    "show (ospf|ospf3) interface [<interface>] [(brief|detail|extensive)] [instance <instance>]",
    "show (ospf|ospf3) interface [instance <instance>] [<interface>] [(brief|detail|extensive)]",
)
class ShowOspfInterface(Parser):
    """OSPF interfaces: state, area, DR/BDR and neighbor count."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        last: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(
                r"^(?P<intf>\S+)\s+(?P<state>PtToPt|DR|BDR|DRother|Down|Waiting|Loopback|DROther|PtToMPt)\s+(?P<area>\d+\.\d+\.\d+\.\d+)\s+(?P<dr>\S+)\s+(?P<bdr>\S+)\s+(?P<nbrs>\d+)$",
                s,
            )
            if m:
                last = {
                    "interface": m["intf"],
                    "state": m["state"],
                    "area": m["area"],
                    "dr_id": m["dr"],
                    "bdr_id": m["bdr"],
                    "neighbors": int(m["nbrs"]),
                }
                out.append(last)
                continue
            if last is None:
                continue
            m = re.match(
                r"^Type: (?P<t>\S+), Address: (?P<a>\S+), Mask: (?P<mask>\S+), MTU: (?P<mtu>\d+), Cost: (?P<c>\d+)", s
            )
            if m:
                last.update(
                    {"type": m["t"], "address": m["a"], "mask": m["mask"], "mtu": int(m["mtu"]), "cost": int(m["c"])}
                )
                continue
            m = re.match(r"^Hello: (?P<h>\d+), Dead: (?P<d>\d+), ReXmit: (?P<r>\d+)", s)
            if m:
                last.update({"hello": int(m["h"]), "dead": int(m["d"]), "retransmit": int(m["r"])})
        return out


# --------------------------------------------------------------------------- #
# IS-IS
# --------------------------------------------------------------------------- #


@register(
    "junos", "show isis adjacency [<system>] [(brief|detail|extensive)] [instance <instance>]", intent="isis.adjacency"
)
class ShowIsisAdjacency(Parser):
    """IS-IS adjacencies per interface and level."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<intf>\S+)\s+(?P<sys>\S+)\s+(?P<lvl>[123])\s+(?P<state>Up|Down|Initializing|New|One-way|Rejected)\s+(?P<hold>\d+)(?:\s+(?P<snpa>\S+))?\s*$",
            text,
        ):
            out.append(
                compact(
                    {
                        "interface": m["intf"],
                        "system": m["sys"],
                        "level": int(m["lvl"]),
                        "state": m["state"],
                        "hold_time": int(m["hold"]),
                        "snpa": m["snpa"],
                    }
                )
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        lv = {1: "level-1", 2: "level-2", 3: "level-1-2"}
        return [
            record(
                "isis.adjacency",
                system_id=a["system"],
                interface=a["interface"],
                state=a["state"].lower(),
                level=lv.get(a["level"]),
                hold_time=a["hold_time"],
                snpa=a.get("snpa"),
            )
            for a in data
        ]


# --------------------------------------------------------------------------- #
# LDP / RSVP / MPLS
# --------------------------------------------------------------------------- #


@register("junos", "show ldp neighbor [(detail|extensive)] [instance <instance>]", intent="ldp.neighbors")
class ShowLdpNeighbor(Parser):
    """LDP hello adjacencies."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<addr>[0-9a-fA-F.:]+)\s+(?P<intf>\S+)\s+(?P<ls>\S+:\d+)\s+(?P<hold>\d+)\s*$", text
        ):
            out.append(
                {"address": m["addr"], "interface": m["intf"], "label_space_id": m["ls"], "hold_time": int(m["hold"])}
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "ldp.neighbors",
                neighbor=n["label_space_id"].split(":")[0],
                state="discovered",
                discovery_sources=[n["interface"]],
            )
            for n in data
        ]


@register(
    "junos", "show ldp session [<address>] [(brief|detail|extensive)] [instance <instance>]", intent="ldp.neighbors"
)
class ShowLdpSession(Parser):
    """LDP sessions: state, connection, hold time, label advertisement mode."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<addr>[0-9a-fA-F.:]+)\s+(?P<state>Operational|Nonexistent|Initialized|OpenRec|OpenSent|Closing|\S+)\s+(?P<conn>Open|Closed|Connecting|\S+)\s+(?P<hold>\d+)\s+(?P<mode>DU|DoD|\S+)\s*$",
            text,
        ):
            out.append(
                {
                    "address": m["addr"],
                    "state": m["state"],
                    "connection": m["conn"],
                    "hold_time": int(m["hold"]),
                    "advertisement_mode": m["mode"],
                }
            )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [record("ldp.neighbors", neighbor=n["address"], state=n["state"].lower()) for n in data]


def _lsp_sections(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    section = None
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"^(?P<dir>Ingress|Egress|Transit) (?:RSVP|LSP): (?P<n>\d+) sessions?", s)
        if m:
            section = m["dir"].lower()
            out[section] = {"sessions": int(m["n"]), "lsps": []}
            continue
        m = re.match(r"^Total (?P<t>\d+) displayed, Up (?P<u>\d+), Down (?P<d>\d+)", s)
        if m and section:
            out[section].update({"displayed": int(m["t"]), "up": int(m["u"]), "down": int(m["d"])})
            continue
        if not section or s.startswith(("To ", "Total")):
            continue
        m = re.match(
            r"^(?P<to>\d+\.\d+\.\d+\.\d+)\s+(?P<frm>\d+\.\d+\.\d+\.\d+)\s+(?P<state>Up|Dn|Down)\s+(?P<rt>\d+)\s+(?P<style>\d+ \w+|\*|\S+)?\s*(?P<lin>\S+)?\s+(?P<lout>\S+)?\s+(?P<name>\S+)$",
            s,
        )
        if m and section in ("egress", "transit"):
            out[section]["lsps"].append(
                compact(
                    {
                        "to": m["to"],
                        "from": m["frm"],
                        "state": m["state"],
                        "route_count": int(m["rt"]),
                        "style": m["style"],
                        "label_in": to_num(m["lin"]) if m["lin"] != "-" else None,
                        "label_out": to_num(m["lout"]) if m["lout"] != "-" else None,
                        "name": m["name"],
                    }
                )
            )
            continue
        m = re.match(
            r"^(?P<to>\d+\.\d+\.\d+\.\d+)\s+(?P<frm>\d+\.\d+\.\d+\.\d+)\s+(?P<state>Up|Dn|Down)\s+(?P<rt>\d+)\s+(?P<p>\*)?\s*(?P<path>\S+)?\s+(?P<name>\S+)$",
            s,
        )
        if m:
            out[section]["lsps"].append(
                compact(
                    {
                        "to": m["to"],
                        "from": m["frm"],
                        "state": m["state"],
                        "route_count": int(m["rt"]),
                        "primary": bool(m["p"]),
                        "active_path": m["path"],
                        "name": m["name"],
                    }
                )
            )
            continue
        m = re.match(
            r"^(?P<to>\d+\.\d+\.\d+\.\d+)\s+(?P<frm>\d+\.\d+\.\d+\.\d+)\s+(?P<state>Up|Dn|Down)\s+(?P<rt>\d+)\s+(?P<name>\S+)$",
            s,
        )
        if m:
            out[section]["lsps"].append(
                {"to": m["to"], "from": m["frm"], "state": m["state"], "route_count": int(m["rt"]), "name": m["name"]}
            )
    return out


@register("junos", "show rsvp session [(ingress|egress|transit|up|down|brief|detail|extensive)] [name <name>]")
class ShowRsvpSession(Parser):
    """RSVP sessions grouped by ingress / egress / transit."""

    def parse(self, text: str) -> Dict[str, Any]:
        return _lsp_sections(text)


@register(
    "junos",
    "show mpls lsp [(ingress|egress|transit|up|down|brief|detail|extensive|terse|statistics)] [name <name>]",
    "show mpls lsp name <name> [(detail|extensive)]",
)
class ShowMplsLsp(Parser):
    """MPLS LSPs grouped by ingress / egress / transit."""

    def parse(self, text: str) -> Dict[str, Any]:
        return _lsp_sections(text)


@register("junos", "show rsvp interface [(detail|extensive)]")
class ShowRsvpInterface(Parser):
    """RSVP interfaces: state, reservations, bandwidth accounting."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"interfaces": []}
        m = re.search(r"RSVP interface: (\d+) active", text)
        if m:
            out["active"] = int(m.group(1))
        for m in match_lines(
            r"^(?P<intf>\S+)\s+(?P<state>Up|Down)\s+(?P<resv>\d+)\s+(?P<sub>\d+)%\s+(?P<static>\S+)\s+(?P<avail>\S+)\s+(?P<reserved>\S+)\s+(?P<hw>\S+)\s*$",
            text,
        ):
            out["interfaces"].append(
                {
                    "interface": m["intf"],
                    "state": m["state"],
                    "active_reservations": int(m["resv"]),
                    "subscription_percent": int(m["sub"]),
                    "static_bw": m["static"],
                    "available_bw": m["avail"],
                    "reserved_bw": m["reserved"],
                    "highwater_mark": m["hw"],
                }
            )
        return out


# --------------------------------------------------------------------------- #
# BFD
# --------------------------------------------------------------------------- #


@register("junos", "show bfd session [(address <address>|brief|detail|extensive|summary)]", intent="bfd.sessions")
class ShowBfdSession(Parser):
    """BFD sessions with detect time, transmit interval and multiplier."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"sessions": []}
        for m in match_lines(
            r"^\s*(?P<addr>[0-9a-fA-F.:]+)\s+(?P<state>Up|Down|Init|AdminDown|Failing)\s+(?P<intf>\S+)?\s+(?P<detect>[\d.]+)\s+(?P<tx>[\d.]+)\s+(?P<mult>\d+)\s*$",
            text,
        ):
            out["sessions"].append(
                compact(
                    {
                        "address": m["addr"],
                        "state": m["state"],
                        "interface": m["intf"],
                        "detect_time": float(m["detect"]),
                        "transmit_interval": float(m["tx"]),
                        "multiplier": int(m["mult"]),
                    }
                )
            )
        m = re.search(r"(\d+) sessions?, (\d+) clients?", text)
        if m:
            out["total_sessions"], out["total_clients"] = int(m.group(1)), int(m.group(2))
        m = re.search(r"Cumulative transmit rate ([\d.]+) pps, cumulative receive rate ([\d.]+) pps", text)
        if m:
            out["transmit_rate_pps"], out["receive_rate_pps"] = float(m.group(1)), float(m.group(2))
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record(
                "bfd.sessions",
                neighbor=s["address"],
                interface=s.get("interface"),
                state=s["state"].lower(),
                detect_time_ms=int(s["detect_time"] * 1000),
            )
            for s in data["sessions"]
        ]
