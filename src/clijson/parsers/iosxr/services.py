"""IOS XR MPLS, neighbor discovery, ARP/ND, bundles, VRFs, L2VPN and BFD."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import mac, record, status
from ...registry import Parser, register
from ...textutils import blocks, compact, match_lines, none_if, to_num

# --------------------------------------------------------------------------- #
# MPLS / LDP
# --------------------------------------------------------------------------- #


@register("iosxr", "show mpls ldp [vrf <vrf>] neighbor brief", intent="ldp.neighbors")
class ShowMplsLdpNeighborBrief(Parser):
    """LDP sessions: GR/NSR, uptime and discovery/address/label counts."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<peer>\d+\.\d+\.\d+\.\d+:\d+)\s+(?P<gr>\S+)\s+(?:(?P<nsr>\S+)\s+)?(?P<up>\S+)\s+(?P<d4>\d+)\s+(?P<d6>\d+)\s+(?P<a4>\d+)\s+(?P<a6>\d+)\s+(?P<l4>\d+)\s+(?P<l6>\d+)\s*$", text):
            out.append(
                {
                    "peer": m["peer"],
                    "graceful_restart": m["gr"] == "Y",
                    "nsr": None if m["nsr"] in (None, "N/A") else m["nsr"] == "Y",
                    "uptime": m["up"],
                    "discovery": {"ipv4": int(m["d4"]), "ipv6": int(m["d6"])},
                    "addresses": {"ipv4": int(m["a4"]), "ipv6": int(m["a6"])},
                    "labels": {"ipv4": int(m["l4"]), "ipv6": int(m["l6"])},
                }
            )
        if not out:
            # pre-IPv6 layout: Peer GR Up Time Discovery Address
            for m in match_lines(r"^\s*(?P<peer>\d+\.\d+\.\d+\.\d+:\d+)\s+(?P<gr>[YN])\s+(?P<up>\S+)\s+(?P<disc>\d+)\s+(?P<addr>\d+)\s*$", text):
                out.append({"peer": m["peer"], "graceful_restart": m["gr"] == "Y", "uptime": m["up"], "discovery": int(m["disc"]), "addresses": int(m["addr"])})
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [record("ldp.neighbors", neighbor=n["peer"].split(":")[0], state="operational", uptime=n["uptime"]) for n in data]


@register("iosxr", "show mpls ldp [vrf <vrf>] neighbor [<neighbor>] [detail]", intent="ldp.neighbors")
class ShowMplsLdpNeighbor(Parser):
    """LDP sessions in detail: TCP endpoints, state, discovery sources, bound addresses."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        section: Optional[str] = None
        af: Optional[str] = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^Peer LDP Identifier: (?P<id>\S+)", s)
            if m:
                cur = out[m["id"]] = {"discovery_sources": {}, "bound_addresses": {}}
                section = af = None
                continue
            if not cur:
                continue
            m = re.match(r"^TCP connection: (?P<peer>\S+) - (?P<local>\S+)", s)
            if m:
                cur["tcp_peer"], cur["tcp_local"] = m["peer"], m["local"]
                continue
            m = re.match(r"^Graceful Restart: (?P<gr>\S+)", s)
            if m:
                cur["graceful_restart"] = m["gr"].lower().startswith("y")
                continue
            m = re.match(r"^Session Holdtime: (?P<h>\d+) sec", s)
            if m:
                cur["session_holdtime"] = int(m["h"])
                continue
            m = re.match(r"^State: (?P<st>\w+); Msgs sent/rcvd: (?P<sent>\d+)/(?P<rcvd>\d+);\s*(?P<mode>.+)$", s)
            if m:
                cur["state"], cur["messages_sent"], cur["messages_received"], cur["label_advertisement"] = m["st"], int(m["sent"]), int(m["rcvd"]), m["mode"].strip()
                continue
            m = re.match(r"^Up time: (?P<up>\S+)", s)
            if m:
                cur["uptime"] = m["up"]
                continue
            if s.startswith("LDP Discovery Sources"):
                section = "discovery_sources"
                continue
            if s.startswith("Addresses bound to this peer"):
                section = "bound_addresses"
                continue
            m = re.match(r"^(?P<af>IPv4|IPv6): \((?P<n>\d+)\)", s)
            if m and section:
                af = m["af"].lower()
                cur[section][af] = []
                continue
            if section and af:
                cur[section][af].extend(s.split())
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            record("ldp.neighbors", neighbor=k.split(":")[0], state=(v.get("state") or "").lower() or None, uptime=v.get("uptime"), discovery_sources=sum(v["discovery_sources"].values(), []))
            for k, v in data.items()
        ]


@register("iosxr", "show mpls forwarding [(labels <labels...>|prefix <prefix>|interface <interface>|vrf <vrf>|summary|detail|tunnels)]")
class ShowMplsForwarding(Parser):
    """Label forwarding table (LFIB)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        last_local: Any = None
        rx = re.compile(
            r"^(?P<local>\d+|\s{2,})\s+(?P<out>\S+(?: \S+)?)\s+(?P<prefix>.+?)\s{2,}(?P<intf>\S+)\s+(?P<nh>\S+)\s+(?P<bytes>\d+)(?:\s+(?P<flag>\([^)]*\)|\S))?\s*$"
        )
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith(("Local", "Label", "---")):
                continue
            m = rx.match(raw)
            if not m:
                # rows without next hop (e.g. Aggregate / exp-null)
                m2 = re.match(r"^(?P<local>\d+)\s+(?P<out>\S+)\s+(?P<prefix>.+?)\s{2,}(?P<intf>\S+)?\s*(?P<bytes>\d+)\s*$", raw)
                if m2:
                    last_local = int(m2["local"])
                    out.append(compact({"local_label": last_local, "outgoing_label": to_num(m2["out"]), "prefix_or_id": m2["prefix"].strip(), "outgoing_interface": m2["intf"], "bytes_switched": int(m2["bytes"])}))
                continue
            local = m["local"].strip()
            if local:
                last_local = int(local)
            entry = {
                "local_label": last_local,
                "outgoing_label": to_num(m["out"]),
                "prefix_or_id": m["prefix"].strip() or None,
                "outgoing_interface": m["intf"],
                "next_hop": m["nh"],
                "bytes_switched": int(m["bytes"]),
            }
            if m["flag"]:
                entry["backup" if "(!)" in m["flag"] else "flags"] = True if "(!)" in m["flag"] else m["flag"]
            if not entry["prefix_or_id"] and out:
                entry["prefix_or_id"] = out[-1].get("prefix_or_id")
            out.append(compact(entry))
        return out


@register("iosxr", "show mpls interfaces [<interface>] [detail]")
class ShowMplsInterfaces(Parser):
    """Interfaces enabled for LDP / TE / static MPLS."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?P<intf>[A-Za-z]\S+)\s+(?P<ldp>Yes|No)(?:\s+\((?P<sync>[^)]*)\))?\s+(?P<te>Yes|No)\s+(?P<static>Yes|No)\s+(?P<enabled>Yes|No)\s*$", text):
            out.append({"interface": m["intf"], "ldp": m["ldp"] == "Yes", "tunnel": m["te"] == "Yes", "static": m["static"] == "Yes", "enabled": m["enabled"] == "Yes"})
        return out


# --------------------------------------------------------------------------- #
# LLDP / CDP
# --------------------------------------------------------------------------- #


@register("iosxr", "show lldp neighbors [<interface>]", intent="lldp.neighbors")
class ShowLldpNeighbors(Parser):
    """LLDP neighbor table."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"neighbors": []}
        pending_dev: Optional[str] = None
        for raw in text.splitlines():
            s = raw.rstrip()
            if not s.strip() or s.lstrip().startswith(("Capability codes", "(R)", "(W)", "Device ID")):
                continue
            m = re.match(r"^Total entries displayed: (?P<n>\d+)", s.strip())
            if m:
                out["total"] = int(m["n"])
                continue
            m = re.match(r"^(?P<dev>\S.*?)\s+(?P<local>[A-Za-z][\w\-]*\d\S*)\s+(?P<hold>\d+)\s+(?P<cap>[A-Z](?:,[A-Z])*|\[[A-Z,]*\])?\s+(?P<port>\S.*?)\s*$", s)
            if m:
                dev = m["dev"]
                if pending_dev:
                    dev, pending_dev = pending_dev, None
                out["neighbors"].append(
                    {"device_id": dev, "local_interface": m["local"], "hold_time": int(m["hold"]), "capabilities": (m["cap"] or "").strip("[]").split(",") if m["cap"] else [], "port_id": m["port"]}
                )
                continue
            if re.match(r"^\S+$", s):
                pending_dev = s  # long device id printed on its own line
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("lldp.neighbors", local_interface=n["local_interface"], neighbor=n["device_id"], neighbor_interface=n["port_id"], capabilities=n["capabilities"], ttl=n["hold_time"]) for n in data["neighbors"]]


def _lldp_detail_blocks(text: str) -> List[Dict[str, Any]]:
    out = []
    for b in re.split(r"^\s*-{10,}\s*$", text, flags=re.M):
        if "Local Interface" not in b and "Local Intf" not in b:
            continue
        item: Dict[str, Any] = {}
        lines = b.splitlines()
        i = 0
        while i < len(lines):
            s = lines[i].strip()
            i += 1
            if not s:
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /]*?):\s*(?P<v>.*)$", s)
            if not m:
                continue
            k, v = m["k"].strip().lower().replace(" ", "_").replace("/", "_"), m["v"].strip()
            if k == "system_description" and not v:
                desc = []
                while i < len(lines) and lines[i].strip() and not re.match(r"^\s*(Time remaining|Hold Time|System Capabilities):", lines[i]):
                    desc.append(lines[i].strip())
                    i += 1
                v = "\n".join(desc)
            elif k == "management_addresses":
                addrs = []
                while i < len(lines) and re.match(r"^\s+(IPv4|IPv6) address:", lines[i]):
                    addrs.append(lines[i].split(":", 1)[1].strip())
                    i += 1
                item["management_addresses"] = addrs
                continue
            elif k in ("ipv4_address", "ipv6_address"):
                item.setdefault("management_addresses", []).append(v)
                continue
            m2 = re.match(r"^(\d+) seconds?$", v)
            item[k] = int(m2.group(1)) if m2 else (none_if(v) if v else None)
        for k in ("system_capabilities", "enabled_capabilities"):
            if isinstance(item.get(k), str):
                item[k] = [c.strip() for c in item[k].split(",") if c.strip()]
        out.append(item)
    return out


@register("iosxr", "show lldp neighbors [<interface>] detail", "show lldp entry <entry>", intent="lldp.neighbors")
class ShowLldpNeighborsDetail(Parser):
    """LLDP neighbors with chassis/port IDs, system description and management addresses."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        return _lldp_detail_blocks(text)

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record(
                "lldp.neighbors",
                local_interface=n.get("local_interface"),
                neighbor=n.get("system_name"),
                neighbor_interface=n.get("port_id"),
                chassis_id=mac(n.get("chassis_id")),
                capabilities=n.get("enabled_capabilities") or n.get("system_capabilities"),
                ttl=n.get("hold_time"),
            )
            for n in data
        ]


@register("iosxr", "show cdp neighbors [<interface>]", intent="lldp.neighbors")
class ShowCdpNeighbors(Parser):
    """CDP neighbor table."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        pending: Optional[str] = None
        for raw in text.splitlines():
            s = raw.rstrip()
            if not s.strip() or s.lstrip().startswith(("Capability Codes", "S - Switch", "Device ID")) or re.match(r"^\s+[a-zA-Z] - ", s):
                continue
            m = re.match(r"^(?P<dev>\S+)?\s+(?P<local>[A-Za-z][\w\-]*\d\S*)\s+(?P<hold>\d+)\s+(?P<cap>(?:[RTBSHIrPDCM] ?)+)\s+(?P<plat>\S+(?: \S+)?)\s+(?P<port>\S+(?: \S+)?)\s*$", s)
            if m:
                dev = m["dev"] or pending
                pending = None
                out.append({"device_id": dev, "local_interface": m["local"], "hold_time": int(m["hold"]), "capabilities": m["cap"].split(), "platform": m["plat"], "port_id": m["port"]})
                continue
            if re.match(r"^\S+$", s):
                pending = s
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [record("lldp.neighbors", local_interface=n["local_interface"], neighbor=n["device_id"], neighbor_interface=n["port_id"], capabilities=n["capabilities"], ttl=n["hold_time"]) for n in data]


@register("iosxr", "show cdp neighbors [<interface>] detail", "show cdp entry <entry>")
class ShowCdpNeighborsDetail(Parser):
    """CDP neighbors with platform, addresses and software version."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for b in blocks(text, start=r"^\s*Device ID\s*:"):
            item: Dict[str, Any] = {}
            lines = b.splitlines()
            i = 0
            while i < len(lines):
                s = lines[i].strip()
                i += 1
                if not s or set(s) <= set("-"):
                    continue
                m = re.match(r"^Platform: (?P<p>[^,]+),\s+Capabilities: (?P<c>.*)$", s)
                if m:
                    item["platform"], item["capabilities"] = m["p"].strip(), m["c"].split()
                    continue
                m = re.match(r"^Interface: (?P<i>[^,]+),\s*Port ID \(outgoing port\): (?P<p>.+)$", s)
                if m:
                    item["local_interface"], item["port_id"] = m["i"], m["p"]
                    continue
                m = re.match(r"^(IPv4|IPv6|IP) address: (?P<a>\S+)", s)
                if m:
                    item.setdefault("addresses", []).append(m["a"])
                    continue
                if s.startswith("Version"):
                    ver = []
                    while i < len(lines) and lines[i].strip():
                        ver.append(lines[i].strip())
                        i += 1
                    item["version"] = "\n".join(ver)
                    continue
                m = re.match(r"^(?P<k>[A-Za-z][\w ()]*?)\s*:\s*(?P<v>.*)$", s)
                if m:
                    k = re.sub(r"[^a-z0-9]+", "_", m["k"].lower()).strip("_")
                    v = m["v"].strip()
                    if k == "port_id_outgoing_port":
                        k = "port_id"
                    if k == "interface":
                        k = "local_interface"
                    if k == "holdtime":
                        k, v = "hold_time", to_num(v.replace("sec", "").strip())
                    if k == "entry_address_es":
                        continue
                    item[k] = v if v != "" else None
            out.append(compact(item))
        return out


# --------------------------------------------------------------------------- #
# ARP / ND
# --------------------------------------------------------------------------- #


@register("iosxr", "show arp [vrf (all|<vrf>)] [<target>] [location <location>] [detail]", intent="arp")
class ShowArp(Parser):
    """ARP table per node/VRF."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        location = None
        vrf = self.params.get("vrf") if self.params.get("vrf") not in (None, "all") else None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^(\d+/\S+/CPU\d+|\d+/\d+/CPU\d+)$", s)
            if m:
                location = m.group(1)
                continue
            m = re.match(r"^VRF:\s*(\S+)", s)
            if m:
                vrf = m.group(1)
                continue
            m = re.match(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<age>\S+)\s+(?P<mac>[0-9a-fA-F.]{14})\s+(?P<state>\S+)\s+(?:(?P<flag>\S+)\s+)?(?P<type>ARPA|SNAP|SAP|IEEE|Dot1Q|\S+)\s+(?P<intf>[A-Za-z]\S*\d\S*)$", s)
            if m:
                out.append(
                    compact(
                        {
                            "ip_address": m["ip"],
                            "age": none_if(m["age"]),
                            "mac_address": m["mac"],
                            "state": m["state"],
                            "type": m["type"],
                            "flag": m["flag"],
                            "interface": m["intf"],
                            "location": location,
                            "vrf": vrf,
                        }
                    )
                )
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [record("arp", ip_address=r["ip_address"], mac_address=mac(r["mac_address"]), interface=r["interface"], age=r.get("age"), type=r["state"].lower()) for r in data]


@register("iosxr", "show ipv6 neighbors [vrf (all|<vrf>)] [<interface>] [(detail|location <location>)]", intent="ipv6.neighbors")
class ShowIpv6Neighbors(Parser):
    """IPv6 neighbor discovery cache."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^(?P<ip>[0-9a-fA-F:]+:[0-9a-fA-F:.]*)\s+(?P<age>\S+)\s+(?P<mac>[0-9a-fA-F.]{14})\s+(?P<state>\S+)\s+(?P<intf>\S+)(?:\s+(?P<loc>\S+))?\s*$", text):
            out.append(compact({"ip_address": m["ip"], "age": none_if(to_num(m["age"])), "mac_address": m["mac"], "state": m["state"], "interface": m["intf"], "location": m["loc"]}))
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [record("ipv6.neighbors", ip_address=r["ip_address"], mac_address=mac(r["mac_address"]), interface=r["interface"], state=r["state"].lower(), age=r.get("age")) for r in data]


# --------------------------------------------------------------------------- #
# Bundles
# --------------------------------------------------------------------------- #


@register("iosxr", "show bundle [(bundle-ether|Bundle-Ether|be) <id>]", "show bundle <bundle>", intent="lag")
class ShowBundle(Parser):
    """Link bundles (LAG): status, bandwidth, LACP and member links."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        in_ports = False
        last_port: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^(Bundle-(?:Ether|POS)) ?(\d+(?:\.\d+)?)$", s)
            if m and not raw.startswith("    "):
                cur = out[m.group(1) + m.group(2)] = {"members": {}}
                in_ports = False
                continue
            if not cur:
                continue
            if re.match(r"^Port\s+Device\s+State", s):
                in_ports = True
                continue
            if in_ports:
                if set(s) <= set("- "):
                    continue
                m = re.match(r"^(?P<port>\S+)\s+(?P<dev>\S+)\s+(?P<state>\S+)\s+(?P<pid>0x[0-9a-f]+, 0x[0-9a-f]+)\s+(?P<bw>\d+)$", s)
                if m:
                    last_port = cur["members"][m["port"]] = {"device": m["dev"], "state": m["state"], "port_id": m["pid"], "bandwidth_kbps": int(m["bw"])}
                    continue
                if last_port is not None and s.startswith("Link is"):
                    last_port["reason"] = s
                    continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /<>()\-]*?):\s+(?P<v>.*)$", s)
            if m:
                k, v = m["k"], m["v"].strip()
                if k.startswith("Local links"):
                    a = [int(x) for x in re.findall(r"\d+", v)]
                    cur["links"] = dict(zip(("active", "standby", "configured"), a))
                elif k.startswith("Local bandwidth"):
                    bm = re.match(r"(\d+) \((\d+)\) kbps", v)
                    if bm:
                        cur["bandwidth_kbps"] = {"effective": int(bm.group(1)), "available": int(bm.group(2))}
                elif k.startswith("MAC address"):
                    mm = re.match(r"(\S+)(?: \((.+)\))?", v)
                    if mm:
                        cur["mac_address"], cur["mac_source"] = mm.group(1), mm.group(2)
                elif k.startswith("Minimum active links"):
                    a = re.findall(r"\d+", v)
                    if len(a) >= 2:
                        cur["minimum_active"] = {"links": int(a[0]), "bandwidth_kbps": int(a[1])}
                else:
                    key = re.sub(r"[^a-z0-9]+", "_", k.lower()).strip("_")
                    cur[key] = to_num(v) if v else None
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("lag", name=k, status=status(v.get("status")), members=list(v.get("members", {}))) for k, v in data.items()]


@register("iosxr", "show bundle brief")
class ShowBundleBrief(Parser):
    """One line per bundle: state, LACP, BFD, link counts and bandwidth."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?P<name>BE\d+|Bundle-\S+|BP\d+)\s+(?P<ig>\S+)\s+(?P<state>\S+(?: \S+)?)\s+(?P<lacp>On|Off)\s+(?P<bfd>On|Off)\s+(?P<act>\d+)\s*/\s*(?P<stb>\d+)\s*/\s*(?P<cfg>\d+)\s+(?P<bw>\d+)\s*$", text):
            out.append(
                {
                    "name": m["name"],
                    "iccp_group": none_if(m["ig"]),
                    "state": m["state"],
                    "lacp": m["lacp"] == "On",
                    "bfd": m["bfd"] == "On",
                    "links": {"active": int(m["act"]), "standby": int(m["stb"]), "configured": int(m["cfg"])},
                    "bandwidth_kbps": int(m["bw"]),
                }
            )
        return out


# --------------------------------------------------------------------------- #
# VRF
# --------------------------------------------------------------------------- #


@register("iosxr", "show vrf (all|<vrf>) detail", intent="vrfs")
class ShowVrfDetail(Parser):
    """VRFs with RD, interfaces and import/export route-targets per address family."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        af: Optional[Dict[str, Any]] = None
        section: Optional[str] = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^VRF (?P<name>\S+); RD (?P<rd>[^;]+); VPN ID (?P<vpn>.+)$", s)
            if m:
                cur = out[m["name"]] = {"rd": none_if(m["rd"], "not set"), "vpn_id": none_if(m["vpn"], "not set"), "interfaces": [], "address_families": {}}
                af, section = None, None
                continue
            if not cur:
                continue
            m = re.match(r"^VRF mode: (?P<m>.+)$", s)
            if m:
                cur["mode"] = m["m"]
                continue
            m = re.match(r"^Description (?P<d>.+)$", s)
            if m:
                cur["description"] = none_if(m["d"], "not set")
                continue
            if s == "Interfaces:":
                section = "interfaces"
                continue
            m = re.match(r"^Address family (?P<af>.+)$", s)
            if m:
                af = cur["address_families"].setdefault(m["af"].lower(), {"import_route_targets": [], "export_route_targets": []})
                section = None
                continue
            m = re.match(r"^(?P<dir>Import|Export) VPN route-target communities:", s)
            if m and af is not None:
                section = f"{m['dir'].lower()}_route_targets"
                continue
            m = re.match(r"^(?P<dir>Import|Export) route policy: (?P<p>\S+)", s)
            if m and af is not None:
                af[f"{m['dir'].lower()}_route_policy"] = m["p"]
                section = None
                continue
            if s.startswith("No "):
                section = None
                continue
            if section == "interfaces":
                cur["interfaces"].append(s)
            elif section and af is not None:
                af[section].append(s.replace("RT:", ""))
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("vrfs", name=k, rd=v["rd"], interfaces=v["interfaces"]) for k, v in data.items()]


@register("iosxr", "show vrf (all|<vrf>)", intent="vrfs")
class ShowVrf(Parser):
    """VRF list with RD and route-targets."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            if not raw.strip() or re.match(r"^\s*VRF\s+RD\s+RT", raw):
                continue
            m = re.match(r"^(?P<name>\S+)\s+(?P<rd>\S+(?: set)?)\s*(?:(?P<dir>import|export)\s+(?P<rt>\S+)\s+(?P<afi>\S+)\s+(?P<safi>\S+))?\s*$", raw)
            if m and not raw.startswith(" "):
                cur = out.setdefault(m["name"], {"rd": none_if(m["rd"], "not set"), "route_targets": []})
                if m["dir"]:
                    cur["route_targets"].append({"direction": m["dir"], "rt": m["rt"], "afi": m["afi"], "safi": m["safi"]})
                continue
            m = re.match(r"^\s+(?P<dir>import|export)\s+(?P<rt>\S+)\s+(?P<afi>\S+)\s+(?P<safi>\S+)\s*$", raw)
            if m and cur is not None:
                cur["route_targets"].append({"direction": m["dir"], "rt": m["rt"], "afi": m["afi"], "safi": m["safi"]})
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("vrfs", name=k, rd=v["rd"], interfaces=None) for k, v in data.items()]


# --------------------------------------------------------------------------- #
# L2VPN
# --------------------------------------------------------------------------- #

_XC_STATES = {"UP", "DN", "AD", "UR", "SB", "SR", "(PP)"}


@register("iosxr", "show l2vpn xconnect [(group <group>|interface <interface>|state <state>|pw-id <pwid>)]")
class ShowL2vpnXconnect(Parser):
    """Point-to-point cross-connects with segment states."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        started = False
        buf: List[str] = []
        group = None

        def flush() -> None:
            nonlocal buf, group
            tokens = " ".join(buf).split()
            buf = []
            if not tokens:
                return
            # tokens: [group] name ST seg1 ST1 seg2... ST2
            states = [i for i, t in enumerate(tokens) if t in _XC_STATES]
            if len(states) < 3:
                if len(tokens) == 1:
                    group = tokens[0]
                return
            i_st, i_st1, i_st2 = states[0], states[1], states[-1]
            head = tokens[:i_st]
            if len(head) >= 2:
                group, name = head[0], " ".join(head[1:])
            else:
                name = head[0] if head else None
            out.append(
                {
                    "group": group,
                    "name": name,
                    "state": tokens[i_st],
                    "segment1": {"description": " ".join(tokens[i_st + 1 : i_st1]), "state": tokens[i_st1]},
                    "segment2": {"description": " ".join(tokens[i_st1 + 1 : i_st2]), "state": tokens[i_st2]},
                }
            )

        for raw in text.splitlines():
            s = raw.strip()
            if re.match(r"^-{5,}", s):
                if started:
                    flush()
                started = True
                continue
            if not started or not s:
                continue
            buf.append(s)
        flush()
        return out


@register("iosxr", "show l2vpn xconnect summary")
class ShowL2vpnXconnectSummary(Parser):
    """Cross-connect counters (up/down/unresolved)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        section = "xconnects"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Number of (?P<what>[\w\- ]+?):\s*(?P<n>\d+)$", s)
            if m:
                section = re.sub(r"[^a-z0-9]+", "_", m["what"].lower()).strip("_")
                out.setdefault(section, {})["total"] = int(m["n"])
                continue
            for k, v in re.findall(r"([A-Z][\w\- ]*?):\s*(\d+)", s):
                out.setdefault(section, {})[re.sub(r"[^a-z0-9]+", "_", k.lower()).strip("_")] = int(v)
        return out


# --------------------------------------------------------------------------- #
# BFD
# --------------------------------------------------------------------------- #


@register("iosxr", "show bfd [(ipv4|ipv6|all)] session [(interface <interface>|destination <dest>)] [(detail|location <location>)]", "show bfd [(ipv4|ipv6|all)] sessions", intent="bfd.sessions")
class ShowBfdSession(Parser):
    """BFD sessions: echo/async timers, state and hardware offload."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for raw in text.splitlines():
            s = raw.rstrip()
            m = re.match(r"^(?P<intf>\S+)\s+(?P<dest>[\d.:a-fA-F]+)\s+(?P<echo>\S+)\s+(?P<async>\S+)\s+(?P<state>UP|DOWN|INIT|ADMIN_DOWN|ADMINDOWN|Up|Down|Init|AdminDown)\s*(?P<hw>Yes|No)?\s*(?P<npu>\S+)?\s*$", s)
            if m:
                out.append(
                    compact(
                        {
                            "interface": m["intf"],
                            "destination": m["dest"],
                            "echo_detect_time": none_if(m["echo"], "n/a"),
                            "async_detect_time": m["async"],
                            "state": m["state"].upper(),
                            "hardware": (m["hw"] == "Yes") if m["hw"] else None,
                            "npu": none_if(m["npu"], "n/a") if m["npu"] else None,
                        }
                    )
                )
                continue
            m = re.match(r"^\s+(?P<hw>Yes|No)\s+(?P<npu>\S+)\s*$", s)
            if m and out:
                out[-1]["hardware"] = m["hw"] == "Yes"
                if m["npu"] not in ("n/a", "N/A"):
                    out[-1]["npu"] = m["npu"]
        return out

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        res = []
        for s in data:
            ms = re.match(r"(\d+)(ms|s)", s.get("async_detect_time", ""))
            detect = (int(ms.group(1)) * (1000 if ms.group(2) == "s" else 1)) if ms else None
            res.append(record("bfd.sessions", neighbor=s["destination"], interface=s["interface"], state=s["state"].lower(), detect_time_ms=detect))
        return res
