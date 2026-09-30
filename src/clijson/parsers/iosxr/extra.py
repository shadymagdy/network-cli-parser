"""IOS XR optics, first-hop redundancy, L2VPN/EVPN, LACP, TE, multicast and platform health."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from ...models import record
from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, snake, to_num


@register("iosxr", "show controllers optics <port> [(brief|detail)]", "show controllers <interface> optics")
class ShowControllersOptics(Parser):
    """Transceiver state, DOM readings (per lane), thresholds, alarms and vendor details."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        section: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(
                r"^(Controller State|Transport Admin State|Laser State|LED State|FEC State|Power Mode|Dom Data Status|Host Squelch Status|Last link flapped|Optics Status|Performance Monitoring)\s*:?\s*(?P<v>.*)$",
                s,
            )
            if m and m.group(1) != "Optics Status":
                out[snake(m.group(1))] = m["v"].strip() or None
                section = None
                continue
            if s.startswith("Detected Alarms:"):
                v = s.split(":", 1)[1].strip()
                out["alarms"] = [] if v in ("", "None") else v.split()
                section = "alarms" if v == "" else None
                continue
            if section == "alarms" and re.match(r"^[A-Z0-9_\-]+(\s+[A-Z0-9_\-]+)*$", s):
                out["alarms"].extend(s.split())
                continue
            m = re.match(r"^Detected LOS/LOL/FAULT:\s*(?P<v>.+)$", s)
            if m:
                out["los_lol_fault"] = m["v"].split()
                continue
            if s.startswith("Parameter") and "High Alarm" in s:
                section = "thresholds"
                out["thresholds"] = {}
                continue
            if section == "thresholds":
                m = re.match(
                    r"^(?P<p>[A-Za-z][\w. ]*?)\s*Threshold\((?P<u>[^)]+)\)\s+(?P<ha>-?[\d.]+)\s+(?P<la>-?[\d.]+)\s+(?P<hw>-?[\d.]+)\s+(?P<lw>-?[\d.]+)$",
                    s,
                )
                if m:
                    key = f"{snake(m['p'])}_{m['u'].lower().replace('.', '')}"
                    out["thresholds"][key] = {
                        "high_alarm": float(m["ha"]),
                        "low_alarm": float(m["la"]),
                        "high_warning": float(m["hw"]),
                        "low_warning": float(m["lw"]),
                    }
                    continue
                if set(s) <= set("- "):
                    continue
                section = None
            if s.startswith("Lane") and "Laser Bias" in s:
                section = "lanes"
                out["lanes"] = []
                continue
            if section == "lanes":
                m = re.match(
                    r"^(?P<lane>\d+)\s+(?P<bias>-?[\d.]+) mA\s+(?P<tx>-?[\d.]+) dBm\s+(?P<rx>-?[\d.]+) dBm(?:\s+(?P<freq>\S+))?",
                    s,
                )
                if m:
                    out["lanes"].append(
                        compact(
                            {
                                "lane": int(m["lane"]),
                                "laser_bias_ma": float(m["bias"]),
                                "tx_power_dbm": float(m["tx"]),
                                "rx_power_dbm": float(m["rx"]),
                                "output_frequency": none_if(m["freq"], "N/A") if m["freq"] else None,
                            }
                        )
                    )
                    continue
                if set(s) <= set("- "):
                    continue
                section = None
            m = re.match(
                r"^(?P<k>Optics Type|Wavelength|TX Power|RX Power|Temperature|Voltage|Laser Bias Current|Actual TX Power|RX Signal Power|Frequency)\s*[:=]\s*(?P<v>.+?)\s*$",
                s,
            )
            if m:
                k, v = snake(m["k"]), m["v"]
                vm = re.match(r"^(-?[\d.]+)\s*(nm|dBm|mW|mA|Celsius|V|GHz|THz)\b", v)
                if vm:
                    unit = {"Celsius": "c"}.get(vm.group(2), vm.group(2).lower())
                    out[f"{k}_{unit}"] = float(vm.group(1))
                else:
                    out[k] = none_if(v, "N/A")
                continue
            if s.startswith("Transceiver Vendor Details"):
                section = "vendor"
                out["vendor"] = {}
                continue
            if section == "vendor":
                m = re.match(r"^(?P<k>[A-Za-z][\w ()/]*?)\s*:\s*(?P<v>.+)$", s)
                if m:
                    out["vendor"][snake(m["k"])] = m["v"].strip()
        return out


def _fhrp_rows(text: str) -> list[dict[str, Any]]:
    """Shared by ``show hsrp`` / ``show vrrp`` brief tables (IPv6 group address may wrap)."""
    out: list[dict[str, Any]] = []
    family = "ipv4"
    for raw in text.splitlines():
        s = raw.rstrip()
        m = re.match(r"^\s*IPv(4|6)\s+Groups?:", s)
        if m:
            family = f"ipv{m.group(1)}"
            continue
        m = re.match(
            r"^(?P<intf>[A-Za-z]\S*\d\S*)\s+(?P<grp>\d+)\s+(?P<pri>\d+)\s+(?P<p>P)?\s*(?P<state>Active|Standby|Speak|Listen|Learn|Init|Master|Backup|Initial)\s+(?P<a>\S+)?\s*(?P<b>\S+)?\s*(?P<c>\S+)?\s*$",
            s,
        )
        if m:
            out.append(
                {
                    "interface": m["intf"],
                    "group": int(m["grp"]),
                    "priority": int(m["pri"]),
                    "preempt": bool(m["p"]),
                    "state": m["state"],
                    "family": family,
                    "_addrs": [x for x in (m["a"], m["b"], m["c"]) if x],
                }
            )
            continue
        m = re.match(r"^\s{20,}(?P<a>\S+)(?:\s+(?P<b>\S+))?\s*$", s)
        if m and out:
            out[-1]["_addrs"].extend(x for x in (m["a"], m["b"]) if x)
    return out


@register("iosxr", "show hsrp [<interface>] [brief]", "show hsrp (ipv4|ipv6) [brief]")
class ShowHsrp(Parser):
    """HSRP groups: priority, preempt, state, active/standby/virtual addresses."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = _fhrp_rows(text)
        for r in rows:
            a = r.pop("_addrs")
            r["active_address"], r["standby_address"], r["virtual_address"] = ([*a, None, None, None])[:3]
        return rows


@register("iosxr", "show vrrp [<interface>] [brief]", "show vrrp (ipv4|ipv6) [brief]")
class ShowVrrp(Parser):
    """VRRP groups: priority, preempt, state, master and virtual addresses."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = _fhrp_rows(text)
        for r in rows:
            a = r.pop("_addrs")
            r["master_address"], r["virtual_address"] = ([*a, None, None])[:2]
        return rows


@register("iosxr", "show l2vpn bridge-domain [(group <group>|bd-name <bd>)] brief")
class ShowL2vpnBridgeDomainBrief(Parser):
    """Bridge domains with state and AC/PW/PBB/VNI up counts."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^(?P<name>\S+?)(?::|/)(?P<bd>\S+)\s+(?P<id>\d+)\s+(?P<state>up|down|admin down)\s+(?P<acs>\d+)/(?P<acsu>\d+)\s+(?P<pws>\d+)/(?P<pwsu>\d+)(?:\s+(?P<pbb>\d+)/(?P<pbbu>\d+))?(?:\s+(?P<vni>\d+)/(?P<vniu>\d+))?\s*$",
            text,
        ):
            e: dict[str, Any] = {
                "group": m["name"],
                "bridge_domain": m["bd"],
                "id": int(m["id"]),
                "state": m["state"],
                "acs": {"total": int(m["acs"]), "up": int(m["acsu"])},
                "pws": {"total": int(m["pws"]), "up": int(m["pwsu"])},
            }
            if m["pbb"]:
                e["pbbs"] = {"total": int(m["pbb"]), "up": int(m["pbbu"])}
            if m["vni"]:
                e["vnis"] = {"total": int(m["vni"]), "up": int(m["vniu"])}
            out.append(e)
        return out


@register("iosxr", "show l2vpn bridge-domain summary")
class ShowL2vpnBridgeDomainSummary(Parser):
    """Bridge-domain, AC, PW counters."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        section = "summary"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Number of ([\w\- ]+?):\s*(\d+)(.*)$", s)
            if m:
                section = snake(m.group(1))
                out.setdefault(section, {})["total"] = int(m.group(2))
                for k, v in re.findall(r"([A-Za-z][\w\- ]{0,40}?):\s*(\d+)", m.group(3)[:500]):
                    out[section][snake(k)] = int(v)
                continue
            for k, v in re.findall(r"([A-Za-z][\w\- ]{0,40}?):\s*(\d+)", s[:500]):
                out.setdefault(section, {})[snake(k)] = int(v)
        return out


@register("iosxr", "show evpn evi [(vpn-id <evi>|detail)]")
class ShowEvpnEvi(Parser):
    """EVPN instances with bridge domain and type."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?P<evi>\d+)\s+(?P<bd>\S+)\s+(?P<type>\S.*?)\s*$", text):
            out.append({"evi": int(m["evi"]), "bridge_domain": m["bd"], "type": m["type"]})
        return out


@register("iosxr", "show evpn ethernet-segment [(interface <interface>|esi <esi>|carving)] [detail]")
class ShowEvpnEthernetSegment(Parser):
    """EVPN ethernet segments: ESI, interface and next-hops."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            m = re.match(
                r"^(?P<esi>[0-9a-fA-F]{4}\.[0-9a-fA-F.]+|N/A|\S+\.\S+\.\S+)\s+(?P<intf>\S+)\s+(?P<nh>[\d.:a-fA-F]+)\s*$",
                raw,
            )
            if m and not raw.startswith(" "):
                cur = {"esi": m["esi"], "interface": m["intf"], "next_hops": [m["nh"]]}
                out.append(cur)
                continue
            m = re.match(r"^\s{20,}(?P<nh>[\d.:a-fA-F]+)\s*$", raw)
            if m and cur is not None:
                cur["next_hops"].append(m["nh"])
        return out


@register("iosxr", "show lacp [(<bundle>|system-id|counters)]", intent="lag")
class ShowLacp(Parser):
    """LACP actor/partner state flags, port IDs, keys, system IDs and mux state per bundle member."""

    _FLAGS: ClassVar[dict[str, str]] = {
        "a": "aggregatable",
        "s": "synchronized",
        "c": "collecting",
        "d": "distributing",
        "A": "active",
        "F": "fast",
        "D": "defaulted",
        "E": "expired",
    }

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        bundle: dict[str, Any] | None = None
        last_port: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^(Bundle-Ether\d+|Bundle-POS\d+)$", s)
            if m:
                bundle = out.setdefault(m.group(1), {"members": {}})
                continue
            if bundle is None:
                continue
            m = re.match(
                r"^(?P<port>\S+)\s+(?P<rate>\d+s)\s+(?P<state>[a-zA-Z\-]{8})\s+(?P<pid>0x[0-9a-f]+,\s*0x[0-9a-f]+)\s+(?P<key>0x[0-9a-f]+)\s+(?P<sys>0x[0-9a-f]+,\s*[0-9a-f\-]+)$",
                s,
            )
            if m:
                info = {
                    "rate": m["rate"],
                    "state": m["state"],
                    "flags": [v for k, v in self._FLAGS.items() if k in m["state"]],
                    "port_id": m["pid"],
                    "key": m["key"],
                    "system_id": m["sys"],
                }
                if m["port"] == "Partner" and last_port:
                    bundle["members"][last_port]["partner"] = info
                else:
                    last_port = m["port"]
                    bundle["members"].setdefault(last_port, {})["actor"] = info
                continue
            m = re.match(
                r"^(?P<port>\S+)\s+(?P<rx>Current|Expired|Defaulted|Init|Disabled|\S+)\s+(?P<period>Fast|Slow|None)\s+(?P<sel>Selected|Unselected|Standby)\s+(?P<mux>\S+)\s+(?P<ac>\S+)\s+(?P<pc>\S+)$",
                s,
            )
            if m and m["port"] in bundle["members"]:
                bundle["members"][m["port"]].update(
                    {
                        "receive": m["rx"],
                        "period": m["period"],
                        "selection": m["sel"],
                        "mux": m["mux"],
                        "actor_churn": m["ac"],
                        "partner_churn": m["pc"],
                    }
                )
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        res = []
        for name, b in data.items():
            up = any(m.get("mux", "").lower().startswith("distrib") for m in b["members"].values())
            res.append(record("lag", name=name, status="up" if up else "down", members=list(b["members"])))
        return res


@register("iosxr", "show ntp status")
class ShowNtpStatus(Parser):
    """NTP clock state, stratum, reference, offsets and delays."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        m = re.search(r"Clock is (?P<st>\w+), stratum (?P<stratum>\d+)(?:, reference is (?P<ref>\S+))?", text)
        if m:
            out["synchronized"] = m["st"] == "synchronized"
            out["stratum"] = int(m["stratum"])
            if m["ref"]:
                out["reference"] = m["ref"]
        for key, rx in (
            ("nominal_frequency_hz", r"nominal freq is ([\d.]+) Hz"),
            ("actual_frequency_hz", r"actual freq is ([\d.]+) Hz"),
            ("offset_ms", r"clock offset is (-?[\d.]+) msec"),
            ("root_delay_ms", r"root delay is (-?[\d.]+) msec"),
            ("root_dispersion_ms", r"root dispersion is (-?[\d.]+) msec"),
            ("peer_dispersion_ms", r"peer dispersion is (-?[\d.]+) msec"),
            ("poll_interval", r"system poll interval is (\d+)"),
            ("last_update_seconds", r"last update was (\d+) sec ago"),
        ):
            m = re.search(rx, text)
            if m:
                out[key] = to_num(m.group(1))
        m = re.search(r"precision is (\S+)", text)
        if m:
            out["precision"] = m.group(1).rstrip(",")
        m = re.search(r"reference time is \S+ \((?P<t>[^)]+)\)", text)
        if m:
            out["reference_time"] = m["t"]
        return out


@register("iosxr", "show isis [instance <instance>] interface brief")
class ShowIsisInterfaceBrief(Parser):
    """IS-IS interfaces: adjacency counts per level, topologies, CLNS state, MTU and priority."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        inst = None
        for raw in text.splitlines():
            m = re.match(r"^IS-IS (\S+) Interfaces", raw.strip())
            if m:
                inst = m.group(1)
                continue
            m = re.match(
                r"^(?P<intf>[A-Za-z]\S*\d\S*)\s+(?P<ok>Yes|No)(?:\s+(?P<l1>\S+)\s+(?P<l2>\S+)\s+(?P<adj>\d+/\d+)\s+(?P<adv>\d+/\d+)\s+(?P<clns>Up|Down)\s+(?P<mtu>\d+)\s+(?P<p1>\S+)\s+(?P<p2>\S+))?\s*$",
                raw,
            )
            if m:
                e: dict[str, Any] = {"instance": inst, "interface": m["intf"], "all_ok": m["ok"] == "Yes"}
                if m["l1"]:
                    e.update(
                        {
                            "adjacencies": {
                                "level_1": to_num(none_if(m["l1"]) or 0) if m["l1"] != "-" else None,
                                "level_2": to_num(m["l2"].rstrip("*")) if m["l2"] != "-" else None,
                            },
                            "adjacency_topologies": m["adj"],
                            "advertised_topologies": m["adv"],
                            "clns": m["clns"],
                            "mtu": int(m["mtu"]),
                            "priority": {
                                "level_1": to_num(m["p1"]) if m["p1"] != "-" else None,
                                "level_2": to_num(m["p2"]) if m["p2"] != "-" else None,
                            },
                        }
                    )
                out.append(e)
        return out


@register("iosxr", "show rsvp neighbors [detail]")
class ShowRsvpNeighbors(Parser):
    """RSVP global neighbors and their interface neighbors."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Global Neighbor:\s*(\S+)", s)
            if m:
                cur = {"global_neighbor": m.group(1), "interface_neighbors": []}
                out.append(cur)
                continue
            m = re.match(r"^(?P<nbr>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)$", s)
            if m and cur is not None:
                cur["interface_neighbors"].append({"neighbor": m["nbr"], "interface": m["intf"]})
        return out


@register("iosxr", "show pim [vrf (all|<vrf>)] [(ipv4|ipv6)] neighbor [<interface>]")
class ShowPimNeighbor(Parser):
    """PIM neighbors: interface, uptime, expiry, DR priority and capability flags."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        vrf = self.params.get("vrf") or "default"
        for raw in text.splitlines():
            m = re.match(r"^PIM neighbors in VRF (\S+)", raw.strip())
            if m:
                vrf = m.group(1)
                continue
            m = re.match(
                r"^(?P<addr>[\d.:a-fA-F]+)(?P<self>\*)?\s+(?P<intf>\S+)\s+(?P<up>\S+)\s+(?P<exp>\S+)\s+(?P<pri>\d+)\s*(?P<dr>\(DR\))?\s*(?P<flags>.*?)\s*$",
                raw,
            )
            if m:
                out.append(
                    {
                        "address": m["addr"],
                        "interface": m["intf"],
                        "uptime": m["up"],
                        "expires": m["exp"],
                        "dr_priority": int(m["pri"]),
                        "dr": bool(m["dr"]),
                        "self": bool(m["self"]),
                        "flags": m["flags"].split(),
                        "vrf": vrf,
                    }
                )
        return out


@register("iosxr", "show mpls traffic-eng tunnels tabular")
class ShowMplsTrafficEngTunnelsTabular(Parser):
    """RSVP-TE tunnels: LSP ID, endpoints, state, FRR state, role and path protection."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<name>\S+)\s+(?P<lsp>\d+)\s+(?P<dst>\d+\.\d+\.\d+\.\d+)\s+(?P<src>\d+\.\d+\.\d+\.\d+)\s+(?P<state>up|down|admin-down|\S+)\s+(?P<frr>\S+)\s+(?P<role>Head|Mid|Tail)(?:\s+(?P<prot>\S+))?\s*$",
            text,
        ):
            out.append(
                compact(
                    {
                        "tunnel": m["name"],
                        "lsp_id": int(m["lsp"]),
                        "destination": m["dst"],
                        "source": m["src"],
                        "state": m["state"],
                        "frr_state": m["frr"],
                        "role": m["role"].lower(),
                        "path_protection": m["prot"],
                    }
                )
            )
        return out


@register("iosxr", "show watchdog memory-state [location <location>]", "show watchdog memory-state location all")
class ShowWatchdogMemoryState(Parser):
    """Physical/free memory and memory state per node."""

    def parse(self, text: str) -> dict[str, Any]:
        nodes: dict[str, Any] = {}
        node = "local"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^-+\s*node(\S+?)\s*-+$", s)
            if m:
                node = m.group(1).replace("_", "/")
                continue
            m = re.match(r"^(Physical Memory|Free Memory|Memory State)\s*:\s*(?P<v>[\d.]+|\w+)\s*(?P<u>MB|GB)?", s)
            if m:
                key = snake(m.group(1)) + ("_mb" if m["u"] else "")
                nodes.setdefault(node, {})[key] = to_num(m["v"])
        return nodes.get("local", nodes) if list(nodes) == ["local"] else nodes


@register("iosxr", "show filesystem [location (all|<location>)]", "show filesystem location all")
class ShowFilesystem(Parser):
    """File systems per node: size, free, type, flags and prefixes."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        node = "local"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^node:\s*node(\S+)", s)
            if m:
                node = m.group(1).replace("_", "/")
                continue
            m = re.match(r"^(?P<size>\d+)\s+(?P<free>\d+)\s+(?P<type>\S+)\s+(?P<flags>\S+)\s+(?P<prefix>\S+)$", s)
            if m:
                out.setdefault(node, []).append(
                    {
                        "prefix": m["prefix"],
                        "size_bytes": int(m["size"]),
                        "free_bytes": int(m["free"]),
                        "type": m["type"],
                        "flags": m["flags"],
                    }
                )
        return out.get("local", out) if list(out) == ["local"] else out


@register("iosxr", "dir [<path...>]")
class Dir(Parser):
    """Directory listing with totals."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"files": []}
        m = re.search(r"Directory of (\S+)", text)
        if m:
            out["directory"] = m.group(1)
        for m in match_lines(
            r"^\s*(?P<inode>\d+)\s+(?P<perm>[-dlrwxstST]{10}\.?|[-drwx]{4})\s+(?P<links>\d+\s+)?(?P<size>\d+)\s+(?P<date>\w{3}\s+\d+\s+(?:\d{4}|\d\d:\d\d)(?:\s+\d{4})?)\s+(?P<name>.+?)\s*$",
            text,
        ):
            out["files"].append(
                {
                    "name": m["name"],
                    "size": int(m["size"]),
                    "permissions": m["perm"],
                    "date": re.sub(r"\s+", " ", m["date"]),
                    "inode": int(m["inode"]),
                }
            )
        m = re.search(r"(\d+) kbytes total \((\d+) kbytes free\)", text)
        if m:
            out["total_kbytes"], out["free_kbytes"] = int(m.group(1)), int(m.group(2))
        return out
