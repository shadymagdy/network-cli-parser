"""Huawei VRP neighbor discovery, ARP/ND, MAC table and VPN instances."""

from __future__ import annotations

import re
from typing import Any

from ...models import mac, record, seconds
from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, snake, to_num


@register("vrp", "display lldp neighbor brief", intent="lldp.neighbors")
class DisplayLldpNeighborBrief(Parser):
    """LLDP neighbors (one line each)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<local>[A-Za-z][\w\-/.:]*\d\S*)\s+(?P<exp>\d+)\s+(?P<nintf>\S+)\s+(?P<ndev>\S+)\s*$", text
        ):
            out.append(
                {
                    "local_interface": m["local"],
                    "expire": int(m["exp"]),
                    "neighbor_interface": m["nintf"],
                    "neighbor": m["ndev"],
                }
            )
        if not out:
            # CE layout: Local Interface  Exptime(s)  Neighbor Interface  Neighbor Device
            for m in match_lines(
                r"^(?P<local>[A-Za-z][\w\-/.:]*\d\S*)\s+(?P<ndev>\S+)\s+(?P<nintf>\S+)\s+(?P<exp>\d+)\s*$", text
            ):
                out.append(
                    {
                        "local_interface": m["local"],
                        "expire": int(m["exp"]),
                        "neighbor_interface": m["nintf"],
                        "neighbor": m["ndev"],
                    }
                )
        return out

    def normalize(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            record(
                "lldp.neighbors",
                local_interface=n["local_interface"],
                neighbor=n["neighbor"],
                neighbor_interface=n["neighbor_interface"],
                ttl=n["expire"],
            )
            for n in data
        ]


@register(
    "vrp", "display lldp neighbor [interface <interface>]", "display lldp neighbor <interface>", intent="lldp.neighbors"
)
class DisplayLldpNeighbor(Parser):
    """LLDP neighbors in detail (chassis/port IDs, system name/description, capabilities, management address)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        local = None
        cur: dict[str, Any] | None = None
        last_key: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                last_key = None
                continue
            m = re.match(r"^(?P<intf>\S+) has (?P<n>\d+) neighbors?", s)
            if m:
                local = m["intf"]
                continue
            m = re.match(r"^Neighbor index\s*:\s*(\d+)", s)
            if m:
                cur = {"local_interface": local, "index": int(m.group(1))}
                out.append(cur)
                last_key = None
                continue
            if cur is None:
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /()\-]*?)\s*:\s*(?P<v>.*)$", s)
            if m and not (
                last_key == "system_description"
                and not re.match(r"^(System capabilities|Management address|Expired time)", s)
            ):
                k, v = snake(m["k"]), m["v"].strip()
                if k == "management_address":
                    cur.setdefault("management_addresses", []).append(v)
                elif k in ("system_capabilities_supported", "system_capabilities_enabled"):
                    cur[k] = v.split()
                elif k == "expired_time":
                    cur["expired_time"] = to_num(v.rstrip("s"))
                else:
                    cur[k] = to_num(v) if v else None
                last_key = k
                continue
            if last_key == "system_description":
                cur["system_description"] = f"{cur.get('system_description') or ''}\n{s}".strip()
        return [compact(c) for c in out]

    def normalize(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            record(
                "lldp.neighbors",
                local_interface=n.get("local_interface"),
                neighbor=n.get("system_name"),
                neighbor_interface=n.get("port_id"),
                chassis_id=mac(str(n["chassis_id"])) if n.get("chassis_id") else None,
                capabilities=n.get("system_capabilities_enabled"),
                ttl=n.get("expired_time"),
            )
            for n in data
        ]


@register(
    "vrp",
    "display arp [(all|brief|dynamic|static|interface <interface>|vpn-instance <vrf>|slot <slot>)]",
    "display arp all [vpn-instance <vrf>]",
    intent="arp",
)
class DisplayArp(Parser):
    """ARP table (with VLAN/CE-VLAN and VPN instance)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"entries": []}
        for raw in text.splitlines():
            m = re.match(
                r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}|Incomplete)\s+(?P<exp>\d+)?\s*(?P<type>[IDS]\S*(?: -)?|\S+)\s+(?P<intf>\S+)(?:\s+(?P<extra>\S+))?\s*$",
                raw,
            )
            if m:
                typ = m["type"].replace(" ", "")
                e = {
                    "ip_address": m["ip"],
                    "mac_address": none_if(m["mac"], "incomplete"),
                    "expire_minutes": int(m["exp"]) if m["exp"] else None,
                    "type": {"I": "interface", "D": "dynamic", "S": "static"}.get(typ[:1], typ),
                    "type_code": typ,
                    "interface": m["intf"],
                }
                if m["extra"]:
                    if re.match(r"^\d+/", m["extra"]):
                        e["vlan"] = m["extra"]
                    else:
                        e["vpn_instance"] = m["extra"]
                out["entries"].append(compact(e))
                continue
            m = re.match(r"^\s{20,}(?P<vlan>\d+/\S+)\s*$", raw)
            if m and out["entries"]:
                out["entries"][-1]["vlan"] = m["vlan"]
        m = re.search(r"Total:\s*(\d+)\s+Dynamic:\s*(\d+)\s+Static:\s*(\d+)\s+Interface:\s*(\d+)", text)
        if m:
            out["summary"] = {
                "total": int(m.group(1)),
                "dynamic": int(m.group(2)),
                "static": int(m.group(3)),
                "interface": int(m.group(4)),
            }
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "arp",
                ip_address=e["ip_address"],
                mac_address=mac(e.get("mac_address")),
                interface=e["interface"],
                age=e["expire_minutes"] * 60 if isinstance(e.get("expire_minutes"), int) else None,
                type=e["type"],
            )
            for e in data["entries"]
        ]


@register("vrp", "display ipv6 neighbors [(brief|<interface>|vpn-instance <vrf>)]", intent="ipv6.neighbors")
class DisplayIpv6Neighbors(Parser):
    """IPv6 neighbor cache (block format)."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"entries": []}
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^IPv6 Address\s*:\s*(\S+)", s)
            if m:
                cur = {"ip_address": m.group(1)}
                out["entries"].append(cur)
                continue
            if cur is None or s.startswith("Total:") or set(s) <= set("-"):
                continue
            for k, v in re.findall(r"([A-Za-z][\w\- ]*?)\s*:\s*(\S*)(?=\s{2,}|\s*$)", s):
                key = snake(k)
                if key == "link_layer":
                    key = "mac_address"
                cur[key] = to_num(v) if v not in ("", "-") else None
        m = re.search(r"Total:\s*(\d+)\s+Dynamic:\s*(\d+)\s+Static:\s*(\d+)", text)
        if m:
            out["summary"] = {"total": int(m.group(1)), "dynamic": int(m.group(2)), "static": int(m.group(3))}
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "ipv6.neighbors",
                ip_address=e["ip_address"],
                mac_address=mac(e.get("mac_address")),
                interface=e.get("interface"),
                state=str(e.get("state", "")).lower() or None,
                age=seconds(e.get("age")),
            )
            for e in data["entries"]
        ]


@register(
    "vrp",
    "display mac-address [(dynamic|static|black-hole|summary)] [(vlan <vlan>|vsi <vsi>|bridge-domain <bd>|interface <interface>|<mac>)]",
    intent="mac.table",
)
class DisplayMacAddress(Parser):
    """MAC address table."""

    def parse(self, text: str) -> dict[str, Any]:
        if "PEVLAN" in text:
            return _parse_mac_slots(text)
        out: dict[str, Any] = {"entries": []}
        for m in match_lines(
            r"^\s*(?P<mac>[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(?P<vlan>\S+)\s+(?P<intf>\S+)\s+(?P<type>\S+)(?:\s+(?P<age>\S+))?\s*$",
            text,
        ):
            vlan = m["vlan"]
            parts = vlan.split("/")
            e: dict[str, Any] = {
                "mac_address": m["mac"],
                "vlan": to_num(parts[0]) if parts[0] not in ("-", "") else None,
                "interface": m["intf"],
                "type": m["type"],
            }
            if len(parts) > 1 and parts[1] not in ("-", ""):
                e["vsi"] = parts[1]
            if len(parts) > 2 and parts[2] not in ("-", ""):
                e["bd"] = to_num(parts[2])
            if m["age"]:
                e["age"] = m["age"]
            out["entries"].append(e)
        mt = re.search(r"Total (?:items displayed|matching items[^=]*?)\s*=\s*(\d+)", text)
        if mt:
            out["total"] = int(mt.group(1))
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for e in data["entries"]:
            row = record(
                "mac.table",
                mac_address=mac(e["mac_address"]),
                vlan=e.get("vlan"),
                interface=e["interface"],
                type=e["type"],
            )
            key = tuple(row.values())
            if key not in seen:  # the per-slot tables repeat the same entry on every line card
                seen.add(key)
                rows.append(row)
        return rows


_MAC_RE = re.compile(r"^[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}$")


def _parse_mac_slots(text: str) -> dict[str, Any]:
    """Newer layout, one table per slot: ``MAC Address  VLAN/BD/VSI/SI/EVPN  PEVLAN CEVLAN Port/Peerip  Type  LSP/LSR-ID``.

    A row wrapped onto a second line by a narrow terminal is joined back together.
    """
    out: dict[str, Any] = {"entries": []}
    slot: str | None = None
    lines = [ln.strip() for ln in text.splitlines()]
    i = 0
    while i < len(lines):
        s = lines[i]
        i += 1
        m = re.match(r"^MAC address table of slot (\S+?):?$", s)
        if m:
            slot = m.group(1)
            continue
        tokens = s.split()
        if not tokens or not _MAC_RE.match(tokens[0]):
            continue
        while len(tokens) < 7 and i < len(lines) and lines[i] and not set(lines[i]) <= {"-"}:
            nxt = lines[i].split()
            if _MAC_RE.match(nxt[0]) or lines[i].startswith(("Total", "MAC")):
                break
            tokens += nxt
            i += 1
        if len(tokens) < 6:
            continue
        mac_addr, where, pevlan, cevlan, port, mac_type = tokens[:6]
        e: dict[str, Any] = {"mac_address": mac_addr}
        pe, ce = to_num(pevlan) if pevlan != "-" else None, to_num(cevlan) if cevlan != "-" else None
        e["vlan"] = int(where) if where.isdigit() else where  # a VLAN, or the VSI / BD / EVPN name
        if not where.isdigit():
            e["vsi"] = where
        e.update({"pe_vlan": pe, "ce_vlan": ce, "interface": port, "type": mac_type})
        if len(tokens) > 6 and tokens[6] != "-":
            e["lsp"] = tokens[6]
        if slot:
            e["slot"] = slot
        out["entries"].append(e)
    totals = [int(t) for t in re.findall(r"Total (?:items displayed|matching items[^=\n]*?)\s*=\s*(\d+)", text)]
    if totals:
        out["total"] = sum(totals)
    return out


@register("vrp", "display ip vpn-instance [(verbose|<vrf>)]", intent="vrfs")
class DisplayIpVpnInstance(Parser):
    """VPN instances (VRFs) with RD and address families."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"vpn_instances": {}}
        for k, rx in (
            ("total", r"Total VPN-Instances configured\s*:\s*(\d+)"),
            ("total_ipv4", r"Total IPv4 VPN-Instances configured\s*:\s*(\d+)"),
            ("total_ipv6", r"Total IPv6 VPN-Instances configured\s*:\s*(\d+)"),
        ):
            m = re.search(rx, text)
            if m:
                out[k] = int(m.group(1))
        for m in match_lines(
            r"^\s*(?P<name>\S+)\s+(?P<rd>\d+[:.]\S+|<not set>|-)\s+(?P<af>IPv4|IPv6|IPv4&IPv6|\S+)\s*$", text
        ):
            if m["name"] in ("VPN-Instance",):
                continue
            v = out["vpn_instances"].setdefault(
                m["name"], {"rd": none_if(m["rd"], "<not set>", "-"), "address_families": []}
            )
            v["address_families"].append(m["af"])
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [record("vrfs", name=k, rd=v["rd"]) for k, v in data["vpn_instances"].items()]


@register("vrp", "display ip vpn-instance interface", "display ip vpn-instance [<vrf>] interface")
class DisplayIpVpnInstanceInterface(Parser):
    """Interfaces bound to each VPN instance."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        cur: dict[str, Any] | None = None
        in_list = False
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^VPN-Instance Name and ID\s*:\s*(?P<n>[^,]+),\s*(?P<id>\d+)", s)
            if m:
                cur = out[m["n"].strip()] = {"id": int(m["id"]), "interfaces": []}
                in_list = False
                continue
            if cur is None:
                continue
            m = re.match(r"^Interface Number\s*:\s*(\d+)", s)
            if m:
                cur["interface_count"] = int(m.group(1))
                continue
            m = re.match(r"^Interface list\s*:\s*(?P<l>.*)$", s)
            if m:
                in_list = True
                cur["interfaces"].extend(i.strip() for i in m["l"].split(",") if i.strip())
                continue
            if in_list and s:
                cur["interfaces"].extend(i.strip() for i in s.split(",") if i.strip())
        return out
