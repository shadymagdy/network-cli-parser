"""Huawei VRP routing: RIB, BGP, OSPF, IS-IS, LDP and BFD."""

from __future__ import annotations

import re
from typing import Any

from ...models import record, seconds
from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, snake, to_num

# --------------------------------------------------------------------------- #
# RIB
# --------------------------------------------------------------------------- #

_VRP_PROTOCOLS = {
    "direct": "connected",
    "static": "static",
    "ospf": "ospf",
    "o_ase": "ospf",
    "o_nssa": "ospf",
    "ospfv3": "ospf",
    "isis": "isis",
    "isis-l1": "isis",
    "isis-l2": "isis",
    "ibgp": "bgp",
    "ebgp": "bgp",
    "bgp": "bgp",
    "rip": "rip",
    "unr": "unr",
    "ripng": "rip",
    "o_ase_v3": "ospf",
}


@register(
    "vrp",
    "display ip routing-table [(vpn-instance <vrf>|all-vpn-instance)] [(protocol <protocol>|verbose|<target...>)]",
    "display ipv6 routing-table [(vpn-instance <vrf>|all-vpn-instance)] [(protocol <protocol>|verbose|<target...>)]",
    intent="routes",
)
class DisplayIpRoutingTable(Parser):
    """IPv4/IPv6 routing table (brief or verbose) including ECMP next-hops."""

    def parse(self, text: str) -> dict[str, Any]:
        if re.search(r"^[ \t]*Destination\s*:\s*\S+", text, re.M):
            return self._verbose(text)
        if re.search(r"^[ \t]*Destination\s*:\s*\S+\s+PrefixLength", text, re.M):
            return self._verbose(text)
        out: dict[str, Any] = {"tables": {}, "routes": []}
        table = self.params.get("vrf") or "_public_"
        last: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Routing Tables?\s*:\s*(?P<t>\S+)", s)
            if m:
                table = {"Public": "_public_"}.get(m["t"], m["t"])
                continue
            m = re.match(r"^Destinations\s*:\s*(?P<d>\d+)\s+Routes\s*:\s*(?P<r>\d+)", s)
            if m:
                out["tables"][table] = {"destinations": int(m["d"]), "routes": int(m["r"])}
                continue
            m = re.match(
                r"^(?P<dst>[0-9a-fA-F.:]+/\d+)\s+(?P<proto>[A-Za-z][\w\-]*)\s+(?P<pre>\d+)\s+(?P<cost>\d+)\s+(?P<flags>[A-Z]*)\s+(?P<nh>[0-9a-fA-F.:]+)\s+(?P<intf>\S+)$",
                s,
            )
            if m:
                last = {
                    "prefix": m["dst"],
                    "vrf": table,
                    "protocol": m["proto"],
                    "preference": int(m["pre"]),
                    "cost": int(m["cost"]),
                    "flags": m["flags"] or None,
                    "next_hops": [{"next_hop": m["nh"], "interface": m["intf"]}],
                }
                out["routes"].append(last)
                continue
            m = re.match(
                r"^(?P<proto>[A-Za-z][\w\-]*)\s+(?P<pre>\d+)\s+(?P<cost>\d+)\s+(?P<flags>[A-Z]*)\s+(?P<nh>[0-9a-fA-F.:]+)\s+(?P<intf>\S+)$",
                s,
            )
            if m and last is not None:
                if (
                    m["proto"] == last["protocol"]
                    and int(m["pre"]) == last["preference"]
                    and int(m["cost"]) == last["cost"]
                ):
                    last["next_hops"].append({"next_hop": m["nh"], "interface": m["intf"]})
                else:
                    last = {
                        **last,
                        "protocol": m["proto"],
                        "preference": int(m["pre"]),
                        "cost": int(m["cost"]),
                        "flags": m["flags"] or None,
                        "next_hops": [{"next_hop": m["nh"], "interface": m["intf"]}],
                    }
                    out["routes"].append(last)
                continue
            # IPv6 brief: multi-line blocks "Destination : x PrefixLength : 64"
        return out

    def _verbose(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"tables": {}, "routes": []}
        table = self.params.get("vrf") or "_public_"
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Routing Tables?\s*:\s*(?P<t>\S+)", s)
            if m:
                table = {"Public": "_public_"}.get(m["t"], m["t"])
                continue
            m = re.match(r"^Destinations\s*:\s*(?P<d>\d+)\s+Routes\s*:\s*(?P<r>\d+)", s)
            if m:
                out["tables"][table] = {"destinations": int(m["d"]), "routes": int(m["r"])}
                continue
            m = re.match(r"^Destination\s*:\s*(?P<d>\S+)(?:\s+PrefixLength\s*:\s*(?P<pl>\d+))?", s)
            if m:
                prefix = m["d"] if not m["pl"] else f"{m['d']}/{m['pl']}"
                cur = {"prefix": prefix, "vrf": table, "next_hops": []}
                out["routes"].append(cur)
                continue
            if cur is None:
                continue
            for k, v in re.findall(r"([A-Za-z][\w ]*?)\s*:\s*(\S+(?: \S+)?)(?=\s{2,}[A-Za-z][\w ]*?\s*:|\s*$)", s):
                key = snake(k)
                val = v.strip()
                if key in ("nexthop", "next_hop"):
                    cur["next_hops"].append({"next_hop": val})
                elif key == "interface":
                    if cur["next_hops"]:
                        cur["next_hops"][-1]["interface"] = val
                    else:
                        cur["next_hops"].append({"interface": val})
                elif key in ("preference", "cost", "process_id"):
                    cur[key] = to_num(val)
                elif key == "state":
                    cur["state"] = val
                    cur["active"] = val.startswith("Active")
                else:
                    cur[key] = to_num(val) if val else None
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "routes",
                prefix=r["prefix"],
                protocol=_VRP_PROTOCOLS.get(
                    str(r.get("protocol", "")).lower(), str(r.get("protocol", "")).lower() or None
                ),
                next_hops=[{"next_hop": nh.get("next_hop"), "interface": nh.get("interface")} for nh in r["next_hops"]],
                distance=r.get("preference"),
                metric=r.get("cost"),
                vrf="default" if r["vrf"] == "_public_" else r["vrf"],
                age=r.get("age"),
            )
            for r in data["routes"]
        ]


@register("vrp", "display ip routing-table statistics [vpn-instance <vrf>]")
class DisplayIpRoutingTableStatistics(Parser):
    """Route counts per protocol (total/active/added/deleted/freed)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"protocols": {}}
        for m in match_lines(
            r"^\s*(?P<proto>[A-Za-z][\w\-]*)\s+(?P<total>\d+)\s+(?P<active>\d+)\s+(?P<added>\d+)\s+(?P<deleted>\d+)\s+(?P<freed>\d+)\s*$",
            text,
        ):
            entry = {
                "total": int(m["total"]),
                "active": int(m["active"]),
                "added": int(m["added"]),
                "deleted": int(m["deleted"]),
                "freed": int(m["freed"]),
            }
            if m["proto"].upper() == "TOTAL":
                out["total"] = entry
            else:
                out["protocols"][m["proto"]] = entry
        mt = re.search(r"Summary Prefixes\s*:\s*(\d+)", text)
        if mt:
            out["summary_prefixes"] = int(mt.group(1))
        return out


# --------------------------------------------------------------------------- #
# BGP
# --------------------------------------------------------------------------- #


@register(
    "vrp",
    "display bgp [(ipv6|vpnv4|vpnv6|evpn|l2vpn-ad|flow|labeled|multicast)] [(all|vpn-instance <vrf>)] peer [<neighbor>]",
    "display bgp vpnv4 vpn-instance <vrf> peer",
    "display bgp instance <instance> peer",
    intent="bgp.summary",
)
class DisplayBgpPeer(Parser):
    """BGP peers: version, AS, messages, up/down time, state and prefixes received."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"neighbors": []}
        m = re.search(r"BGP [Ll]ocal router ID\s*:\s*(\S+)", text)
        if m:
            out["router_id"] = m.group(1)
        m = re.search(r"[Ll]ocal AS number\s*:\s*(\S+)", text)
        if m:
            out["local_as"] = _asn(m.group(1))
        m = re.search(r"Total number of peers\s*:\s*(\d+)", text)
        if m:
            out["total_peers"] = int(m.group(1))
        m = re.search(r"Peers in established state\s*:\s*(\d+)", text)
        if m:
            out["established_peers"] = int(m.group(1))
        vrf = self.params.get("vrf") or "default"
        af = self._af()
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(
                r"^(?:Peer of IPv\d-family for )?[Vv]pn instance\s*:?\s*(?P<v>\S+?)\s*:?$|^VPN-Instance (?P<v2>\S+?), Router ID",
                s,
            )
            if m:
                vrf = m["v"] or m["v2"]
                continue
            m = re.match(
                r"^(?P<dyn>\*)?(?P<peer>[0-9a-fA-F.:]+)\s+(?P<v>\d)\s+(?P<as>[\d.]+)\s+(?P<rcv>\d+)\s+(?P<sent>\d+)\s+(?P<outq>\d+)\s+(?P<updown>\S+)\s+(?P<state>\S+)\s+(?P<pfx>\d+)$",
                s,
            )
            if m:
                out["neighbors"].append(
                    {
                        "neighbor": m["peer"],
                        "version": int(m["v"]),
                        "remote_as": _asn(m["as"]),
                        "messages_received": int(m["rcv"]),
                        "messages_sent": int(m["sent"]),
                        "output_queue": int(m["outq"]),
                        "up_down": m["updown"],
                        "state": m["state"],
                        "prefixes_received": int(m["pfx"]),
                        "vrf": vrf,
                        "address_family": af,
                        **({"dynamic": True} if m["dyn"] else {}),
                    }
                )
        return out

    def _af(self) -> str:
        c = self.command.lower()
        for key, af in (
            ("vpnv4", "vpnv4 unicast"),
            ("vpnv6", "vpnv6 unicast"),
            ("evpn", "l2vpn evpn"),
            ("ipv6", "ipv6 unicast"),
            ("flow", "ipv4 flowspec"),
            ("labeled", "ipv4 labeled-unicast"),
            ("multicast", "ipv4 multicast"),
        ):
            if f" {key}" in f" {c}":
                return af
        return "ipv4 unicast"

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "bgp.summary",
                neighbor=n["neighbor"],
                remote_as=n["remote_as"],
                state=n["state"],
                established=n["state"].lower().startswith("estab"),
                uptime=n["up_down"],
                uptime_seconds=seconds(n["up_down"]),
                prefixes_received=n["prefixes_received"],
                vrf=n["vrf"],
                address_family=n["address_family"],
            )
            for n in data["neighbors"]
        ]


def _asn(v: str) -> Any:
    return int(v) if v.isdigit() else v


@register(
    "vrp",
    "display bgp [(ipv6|vpnv4|vpnv6|evpn)] [(all|vpn-instance <vrf>)] peer <neighbor> verbose",
    "display bgp peer verbose",
)
class DisplayBgpPeerVerbose(Parser):
    """Detailed BGP peer information."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] = {}
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^BGP Peer is (?P<p>\S+?),\s+remote AS (?P<as>\S+)", s)
            if m:
                cur = out[m["p"]] = {"remote_as": _asn(m["as"])}
                continue
            if not cur:
                continue
            m = re.match(r"^Type:\s*(?P<t>.+?)\s*$", s)
            if m:
                cur["type"] = m["t"]
                continue
            m = re.match(r"^BGP current state:\s*(?P<st>\w+)(?:, (?:Up|Down) for (?P<up>\S+))?", s)
            if m:
                cur["state"] = m["st"]
                if m["up"]:
                    cur["uptime"] = m["up"]
                continue
            m = re.match(r"^Remote router ID (?P<rid>\S+)", s)
            if m:
                cur["remote_router_id"] = m["rid"]
                continue
            m = re.match(r"^Received total routes:\s*(\d+)", s)
            if m:
                cur["received_routes"] = int(m.group(1))
                continue
            m = re.match(r"^Received active routes total:\s*(\d+)", s)
            if m:
                cur["active_routes"] = int(m.group(1))
                continue
            m = re.match(r"^Advertised total routes:\s*(\d+)", s)
            if m:
                cur["advertised_routes"] = int(m.group(1))
                continue
            m = re.match(r"^Port:\s*Local - (?P<l>\d+)\s+Remote - (?P<r>\d+)", s)
            if m:
                cur["local_port"], cur["remote_port"] = int(m["l"]), int(m["r"])
                continue
            m = re.match(r"^Configured: Connect-retry Time: (?P<cr>\d+) sec", s)
            if m:
                cur["connect_retry"] = int(m["cr"])
                continue
            m = re.match(r"^Negotiated: Active Hold Time: (?P<h>\d+) sec\s+Keepalive Time:\s*(?P<k>\d+) sec", s)
            if m:
                cur["hold_time"], cur["keepalive"] = int(m["h"]), int(m["k"])
                continue
            m = re.match(r"^(Import|Export) route policy is:\s*(\S+)", s)
            if m:
                cur[f"{m.group(1).lower()}_policy"] = m.group(2)
                continue
            m = re.match(r"^Peer's BGP version is (\d+)", s)
            if m:
                cur["version"] = int(m.group(1))
        return out


# --------------------------------------------------------------------------- #
# OSPF
# --------------------------------------------------------------------------- #


@register(
    "vrp", "display ospf [<process>] peer brief", "display ospfv3 [<process>] peer brief", intent="ospf.neighbors"
)
class DisplayOspfPeerBrief(Parser):
    """OSPF neighbors: area, interface, router ID, state."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"neighbors": []}
        process = router_id = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^OSPF(?:v3)? Process (?P<p>\d+) with Router ID (?P<rid>\S+)", s)
            if m:
                process, router_id = int(m["p"]), m["rid"]
                continue
            m = re.match(
                r"^(?P<area>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)\s+(?P<nbr>\d+\.\d+\.\d+\.\d+)\s+(?P<state>\S+)(?:\s+(?P<extra>.+))?$",
                s,
            )
            if m:
                out["neighbors"].append(
                    compact(
                        {
                            "process": process,
                            "router_id": router_id,
                            "area": m["area"],
                            "interface": m["intf"],
                            "neighbor_id": m["nbr"],
                            "state": m["state"],
                        }
                    )
                )
                continue
            m = re.match(r"^Total Peer\(s\)\s*:\s*(\d+)", s)
            if m:
                out["total"] = out.get("total", 0) + int(m.group(1))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record("ospf.neighbors", neighbor_id=n["neighbor_id"], state=n["state"].lower(), interface=n["interface"])
            for n in data["neighbors"]
        ]


@register(
    "vrp",
    "display ospf [<process>] peer [(<interface>|<neighbor>)]",
    "display ospf [<process>] peer verbose",
    intent="ospf.neighbors",
)
class DisplayOspfPeer(Parser):
    """OSPF neighbors in detail: address, state, priority, DR/BDR, dead timer, uptime."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"neighbors": []}
        process = None
        area = intf = local_ip = None
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^OSPF Process (?P<p>\d+) with Router ID (?P<rid>\S+)", s)
            if m:
                process = int(m["p"])
                out.setdefault("router_id", m["rid"])
                continue
            m = re.match(r"^Area (?P<area>\S+) interface (?P<ip>\S+)\((?P<intf>[^)]+)\)'s neighbors", s)
            if m:
                area, local_ip, intf = m["area"], m["ip"], m["intf"]
                continue
            m = re.match(r"^Router ID\s*:\s*(?P<rid>\S+)\s+Address\s*:\s*(?P<addr>\S+)", s)
            if m:
                cur = {
                    "process": process,
                    "area": area,
                    "interface": intf,
                    "local_address": local_ip,
                    "neighbor_id": m["rid"],
                    "address": m["addr"],
                }
                out["neighbors"].append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^State\s*:\s*(?P<st>\S+)\s+Mode\s*:\s*(?P<mode>.+?)\s+Priority\s*:\s*(?P<pri>\d+)", s)
            if m:
                cur["state"], cur["mode"], cur["priority"] = m["st"], m["mode"].strip(), int(m["pri"])
                continue
            m = re.match(r"^DR\s*:\s*(?P<dr>\S+)\s+BDR\s*:\s*(?P<bdr>\S+)\s+MTU\s*:\s*(?P<mtu>\d+)", s)
            if m:
                cur["dr"], cur["bdr"], cur["mtu"] = m["dr"], m["bdr"], int(m["mtu"])
                continue
            m = re.match(r"^Dead timer due (?:in )?(?P<d>\d+)\s*sec", s)
            if m:
                cur["dead_time"] = int(m["d"])
                continue
            m = re.match(r"^Neighbor is up for (?P<up>\S+)", s)
            if m:
                cur["uptime"] = m["up"]
                continue
            m = re.match(r"^Retrans timer interval\s*:\s*(\d+)", s)
            if m:
                cur["retransmit_interval"] = int(m.group(1))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "ospf.neighbors",
                neighbor_id=n["neighbor_id"],
                priority=n.get("priority"),
                state=(n.get("state") or "").lower() or None,
                address=n.get("address"),
                interface=n.get("interface"),
                dead_time=seconds(n.get("dead_time")),
            )
            for n in data["neighbors"]
        ]


# --------------------------------------------------------------------------- #
# IS-IS
# --------------------------------------------------------------------------- #


@register(
    "vrp", "display isis [<process>] peer [(verbose|brief)]", "display isis peer [<process>]", intent="isis.adjacency"
)
class DisplayIsisPeer(Parser):
    """IS-IS neighbors per process (wrapped system IDs are re-joined)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"peers": []}
        process = None
        last: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Peer information for ISIS\((?P<p>\S+)\)", s)
            if m:
                process = to_num(m["p"])
                continue
            m = re.match(
                r"^(?P<sys>\S+)\s+(?P<intf>\S+)\s+(?P<cid>\S+)\s+(?P<state>Up|Down|Init)\s+(?P<hold>\d+)s?\s+(?P<type>L1L2|L1|L2)(?:\(L1L2\))?\s+(?P<pri>\S+)$",
                s,
            )
            if m:
                last = {
                    "process": process,
                    "system_id": m["sys"],
                    "interface": m["intf"],
                    "circuit_id": m["cid"],
                    "state": m["state"],
                    "hold_time": int(m["hold"]),
                    "type": m["type"],
                    "priority": to_num(m["pri"]) if m["pri"] != "--" else None,
                }
                out["peers"].append(last)
                continue
            if (
                last is not None
                and re.match(r"^[\w\-*.]+$", s)
                and not set(s) <= set("-")
                and not s.startswith("Total")
            ):
                last["system_id"] += s.rstrip("*")
                if s.endswith("*"):
                    last["restarting"] = True
                continue
            m = re.match(r"^Total Peer\(s\)\s*:\s*(\d+)", s)
            if m:
                out["total"] = out.get("total", 0) + int(m.group(1))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "isis.adjacency",
                system_id=p["system_id"],
                interface=p["interface"],
                state=p["state"].lower(),
                level=p["type"],
                hold_time=p["hold_time"],
            )
            for p in data["peers"]
        ]


# --------------------------------------------------------------------------- #
# MPLS LDP
# --------------------------------------------------------------------------- #


@register("vrp", "display mpls ldp session [(all|verbose|<peer>)] [vpn-instance <vrf>]", intent="ldp.neighbors")
class DisplayMplsLdpSession(Parser):
    """LDP sessions: status, label advertisement mode, role, age and keepalives."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<del>\*)?(?P<peer>\d+\.\d+\.\d+\.\d+:\d+)\s+(?P<status>\S+)\s+(?P<lam>DU|DoD|\S+)\s+(?P<role>Active|Passive|\S+)\s+(?P<age>\S+)\s+(?P<sent>\d+)/(?P<rcv>\d+)\s*$",
            text,
        ):
            out.append(
                {
                    "peer": m["peer"],
                    "status": m["status"],
                    "label_advertisement_mode": m["lam"],
                    "session_role": m["role"],
                    "session_age": m["age"],
                    "keepalives_sent": int(m["sent"]),
                    "keepalives_received": int(m["rcv"]),
                    **({"deleting": True} if m["del"] else {}),
                }
            )
        return out

    def normalize(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            record(
                "ldp.neighbors", neighbor=n["peer"].split(":")[0], state=n["status"].lower(), uptime=n["session_age"]
            )
            for n in data
        ]


@register("vrp", "display mpls ldp peer [(all|verbose|<peer>)]")
class DisplayMplsLdpPeer(Parser):
    """LDP peers with transport address and discovery source."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in text.splitlines():
            m = re.match(
                r"^\s*(?P<del>\*)?(?P<peer>\d+\.\d+\.\d+\.\d+:\d+)\s+(?P<ta>\d+\.\d+\.\d+\.\d+)\s+(?P<src>\S+)\s*$", raw
            )
            if m:
                out.append({"peer": m["peer"], "transport_address": m["ta"], "discovery_sources": [m["src"]]})
                continue
            m = re.match(r"^\s{20,}(?P<src>\S+)\s*$", raw)
            if m and out:
                out[-1]["discovery_sources"].append(m["src"])
        return out


@register("vrp", "display mpls lsp [(protocol <protocol>|verbose|statistics|<target...>)]")
class DisplayMplsLsp(Parser):
    """MPLS LSPs (FEC, in/out labels, interfaces) grouped by protocol."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        proto = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^LSP Information:\s*(?P<p>.+?)\s*LSP", s)
            if m:
                proto = m["p"].strip()
                continue
            m = re.match(
                r"^(?P<fec>\d+\.\d+\.\d+\.\d+/\d+)\s+(?P<inl>\S+)/(?P<outl>\S+)\s+(?P<inif>\S+)/(?P<outif>\S+)(?:\s+(?P<vrf>\S+))?$",
                s,
            )
            if m:
                out.append(
                    compact(
                        {
                            "protocol": proto,
                            "fec": m["fec"],
                            "in_label": to_num(none_if(m["inl"], "NULL")) if m["inl"] != "NULL" else None,
                            "out_label": to_num(m["outl"]) if m["outl"] != "NULL" else None,
                            "in_interface": none_if(m["inif"]),
                            "out_interface": none_if(m["outif"]),
                            "vrf": m["vrf"],
                        }
                    )
                )
        return out


# --------------------------------------------------------------------------- #
# BFD
# --------------------------------------------------------------------------- #


@register(
    "vrp",
    "display bfd session (all|static|dynamic|discriminator <disc>|peer-ip <ip>|mpls-te <te...>) [verbose]",
    "display bfd session",
    intent="bfd.sessions",
)
class DisplayBfdSession(Parser):
    """BFD sessions: discriminators, peer, state, type and interface."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"sessions": []}
        for m in match_lines(
            r"^\s*(?P<local>\d+)\s+(?P<remote>\d+)\s+(?P<peer>[0-9a-fA-F.:]+)\s+(?P<state>Up|Down|Init|AdminDown)\s+(?P<type>\S+)\s+(?P<intf>\S+)\s*$",
            text,
        ):
            out["sessions"].append(
                {
                    "local_discriminator": int(m["local"]),
                    "remote_discriminator": int(m["remote"]),
                    "peer": m["peer"],
                    "state": m["state"],
                    "type": m["type"],
                    "interface": none_if(m["intf"]),
                }
            )
        mt = re.search(r"Total UP/DOWN Session Number\s*:\s*(\d+)/(\d+)", text)
        if mt:
            out["up"], out["down"] = int(mt.group(1)), int(mt.group(2))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "bfd.sessions",
                neighbor=s["peer"],
                interface=s["interface"],
                state=s["state"].lower(),
                local_discriminator=s["local_discriminator"],
                remote_discriminator=s["remote_discriminator"],
            )
            for s in data["sessions"]
        ]
