"""Huawei VRP L2VPN: VSIs (VPLS), VSI peers and protect-groups, LDP L2VCs (VLL) and bridge-domains.

``display vsi ... verbose`` and ``display mpls l2vc`` print ``Key : value`` blocks where a leading ``*`` marks a
new record (``***VSI Name``, ``*Peer Router ID``, ``*Peer Ip Address``, ``*Client Interface``); the parsers below
follow those markers.
"""

from __future__ import annotations

import re
from typing import Any

from ...models import pw_state, record
from ...registry import Parser, register
from ...textutils import none_if, snake, to_num

_IP = r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+"
_KV = re.compile(r"^(?P<stars>\*{0,3})\s*(?P<key>[A-Za-z][\w /().\-]*?)\s*:\s*(?P<val>.*?)\s*$")
_ENCAP = {"vlan": "ethernet-vlan", "ethernet": "ethernet", "ethernet-vlan": "ethernet-vlan"}


def _val(v: str) -> Any:
    v = v.strip()
    if v in ("--", "-", ""):
        return None
    return to_num(v)


def _vc_type(value: Any) -> str | None:
    if not value:
        return None
    return _ENCAP.get(str(value).lower(), str(value).lower())


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _enabled(*values: Any) -> bool | None:
    """``enable`` / ``disable`` words -> bool; several values (local, remote) must all be enabled."""
    words = [str(v).strip().lower() for v in values if v is not None]
    if not words or any(w not in ("enable", "enabled", "disable", "disabled") for w in words):
        return None
    return all(w.startswith("enable") for w in words)


def _code(value: Any) -> str | None:
    return None if value is None else str(value)


# --------------------------------------------------------------------------- #
# display vsi
# --------------------------------------------------------------------------- #


def _parse_vsi_verbose(text: str) -> list[dict[str, Any]]:
    vsis: list[dict[str, Any]] = []
    vsi: dict[str, Any] | None = None
    target: dict[str, Any] | None = None
    in_pw = False
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("**PW Information"):
            in_pw = True
            target = None
            continue
        m = _KV.match(s)
        if not m:
            continue
        key, val = snake(m["key"]), _val(m["val"])
        if key == "vsi_name" and m["stars"] == "***":
            vsi = {"name": str(m["val"]).strip(), "peers": [], "interfaces": [], "pws": []}
            vsis.append(vsi)
            target, in_pw = vsi, False
            continue
        if vsi is None:
            continue
        if key == "peer_router_id":
            target = {"peer": val}
            vsi["peers"].append(target)
            in_pw = False
            continue
        if key == "interface_name":
            target = {"interface": val}
            vsi["interfaces"].append(target)
            in_pw = False
            continue
        if key == "peer_ip_address" and in_pw:
            target = {"peer": val}
            vsi["pws"].append(target)
            continue
        if target is None:
            target = vsi
        target[key] = val
    return vsis


_VSI_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<disc>\S+)\s+(?P<pw>ldp|bgp|bgpad|mixed|unspecified|--)\s+(?P<learn>\S+)\s+"
    r"(?P<encap>\S+)\s+(?P<mtu>\d+)\s+(?P<state>\S+)\s*$",
    re.I,
)


def _parse_vsi_table(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"vsis": []}
    m = re.search(r"Total VSI number is (\d+), (\d+) is up, (\d+) is down", text)
    if m:
        out["total"], out["up"], out["down"] = (int(x) for x in m.groups())
    for raw in text.splitlines():
        r = _VSI_ROW.match(raw.strip())
        if r and r["name"].lower() not in ("vsi", "name"):
            out["vsis"].append(
                {
                    "name": r["name"],
                    "member_discovery": none_if(r["disc"], "--"),
                    "pw_signaling": r["pw"].lower(),
                    "mac_learning": r["learn"],
                    "encapsulation": r["encap"],
                    "mtu": int(r["mtu"]),
                    "state": r["state"],
                }
            )
    return out


@register(
    "vrp",
    "display vsi [name <vsi>] [verbose]",
    "display vsi verbose",
    intent="l2vpn.pseudowires",
)
class DisplayVsi(Parser):
    """VSIs: summary table (signaling, encapsulation, MTU, state) or verbose peers, ACs and PW labels/state."""

    def parse(self, text: str) -> dict[str, Any]:
        if re.search(r"^[ \t]*\*{3}[ \t]*VSI Name", text, re.M):
            return {"vsis": _parse_vsi_verbose(text)}
        return _parse_vsi_table(text)

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]] | None:
        if not any("peers" in vsi for vsi in data["vsis"]):
            return None  # the summary table has no per-PW information
        rows: list[dict[str, Any]] = []
        for vsi in data["vsis"]:
            if "peers" not in vsi:
                continue
            peers = {p.get("peer"): p for p in vsi["peers"]}
            pws = vsi["pws"] or [{"peer": p.get("peer"), "pw_state": p.get("session")} for p in vsi["peers"]]
            for pw in pws:
                peer = peers.get(pw.get("peer"), {})
                state = pw_state(str(pw.get("pw_state") or "down")) or "down"
                which = str(peer.get("primary_or_secondary") or "").lower()
                rows.append(
                    record(
                        "l2vpn.pseudowires",
                        service=vsi["name"],
                        neighbor=str(pw.get("peer")),
                        pw_id=_int(peer.get("negotiation_vc_id")) or _int(vsi.get("vsi_id")),
                        state=state,
                        role="backup" if which == "secondary" else "primary" if which == "primary" else None,
                        active=state == "up",
                        vc_type=_vc_type(peer.get("encapsulation_type") or vsi.get("encapsulation_type")),
                        mtu=_int(vsi.get("mtu")),
                        local_label=_int(pw.get("local_vc_label")),
                        remote_label=_int(pw.get("remote_vc_label")),
                        status_code=_code(pw.get("pw_state")),
                        control_word=_enabled(
                            *(v for v in (peer.get("control_word"), pw.get("remote_control_word")) if v is not None)
                        ),
                    )
                )
        return rows


@register("vrp", "display vsi [name <vsi>] peer-info", intent="l2vpn.pseudowires")
class DisplayVsiPeerInfo(Parser):
    """VSI peers per VSI: transport VC ID, local / remote VC label and VC state, or peer type, session and tunnel."""

    #: ``records()`` gives one row per peer, carrying the VSI's name and signaling
    record_path = ("vsis", "peers")

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"vsis": []}
        cur: dict[str, Any] | None = None
        peer: dict[str, Any] | None = None
        transport_layout = False  # "Peer Addr | Transport VC ID | Local VC Label | Remote VC Label | VC State"
        for raw in text.splitlines():
            s = raw.strip()
            if not s or set(s) <= {"-"}:
                continue
            m = re.match(r"^VSI Name\s*:\s*(\S+)(?:\s+Signaling\s*:\s*(\S+))?", s)
            if m:
                cur, peer = {"name": m.group(1), "peers": []}, None
                if m.group(2):
                    cur["signaling"] = m.group(2)
                out["vsis"].append(cur)
                continue
            if cur is None:
                continue
            if s.startswith("Peer") and "Transport" in s:
                transport_layout = True
                continue
            if transport_layout:
                m = re.match(
                    rf"^(?P<peer>{_IP})\s+(?P<vc>\d+)\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+(?P<state>\S+)\s*$", s
                )
                if not m and not s.startswith("Addr "):
                    self.note_unparsed(s)
                if m:
                    cur["peers"].append(
                        {
                            "peer": m["peer"],
                            "vc_id": int(m["vc"]),
                            "local_vc_label": _val(m["local"]),
                            "remote_vc_label": _val(m["remote"]),
                            "state": m["state"],
                        }
                    )
                continue
            m = re.match(
                rf"^(?P<peer>{_IP})\s+(?P<label>\d+|--)\s+(?P<type>\S+)\s+(?P<session>\S+)\s+(?P<tunnel>\S+)(?:\s+(?P<status>\S+))?\s*$",
                s,
            )
            if m:
                cur["peers"].append(
                    {
                        "peer": m["peer"],
                        "vc_label": _val(m["label"]),
                        "peer_type": m["type"],
                        "session": m["session"],
                        "tunnel_id": _val(m["tunnel"]),
                        "status": m["status"],
                    }
                )
                continue
            kv = _KV.match(s)
            if kv:
                key, val = snake(kv["key"]), _val(kv["val"])
                if key in ("peer_router_id", "peer"):
                    peer = {"peer": val}
                    cur["peers"].append(peer)
                elif peer is not None:
                    peer[key] = val
                else:
                    cur[key] = val
                continue
            if not s.startswith("Peer "):  # the column header
                self.note_unparsed(s)
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for vsi in data["vsis"]:
            for p in vsi["peers"]:
                native = p.get("state") or p.get("status") or p.get("session")
                state = pw_state(str(native)) if native is not None else None
                rows.append(
                    record(
                        "l2vpn.pseudowires",
                        service=vsi["name"],
                        neighbor=None if p.get("peer") is None else str(p.get("peer")),
                        pw_id=_int(p.get("vc_id")),
                        state=state or "down",
                        active=state == "up",
                        local_label=_int(p.get("local_vc_label")) or _int(p.get("vc_label")),
                        remote_label=_int(p.get("remote_vc_label")),
                        status_code=_code(native),
                    )
                )
        return rows


@register(
    "vrp",
    "display vsi [name <vsi>] protect-group [<group>]",
    intent="l2vpn.pseudowires",
)
class DisplayVsiProtectGroup(Parser):
    """VSI PW protect-groups: protect mode, reroute policy, members with preference and active/inactive state."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"groups": []}
        cur: dict[str, Any] | None = None
        vsi: str | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if not s or set(s) <= {"-"}:
                continue
            m = re.match(
                rf"^(?P<peer>{_IP})(?::(?P<vc>\d+))?\s+(?:(?P<id>\d+)\s+)?(?P<pref>\d+)\s+(?P<state>[A-Za-z][\w\-]*)\s*$",
                s,
            )
            if m:
                if cur is None:
                    cur = {"vsi": vsi, "members": []}
                    out["groups"].append(cur)
                pw_id = m["vc"] or m["id"]
                cur["members"].append(
                    {
                        "peer": m["peer"],
                        "pw_id": int(pw_id) if pw_id else None,
                        "preference": int(m["pref"]),
                        "state": m["state"],
                    }
                )
                continue
            kv = _KV.match(s)
            if not kv:
                continue
            key, val = snake(kv["key"]), _val(kv["val"])
            if key in ("vsi_name", "vsi"):
                vsi = str(val)
                cur = None
            elif key in ("protect_group", "protect_group_name", "group_name", "protect_group_id"):
                cur = {"vsi": vsi, "name": str(val), "members": []}
                out["groups"].append(cur)
            elif cur is not None:
                cur[key] = val
            elif key in ("protect_mode", "reroute_policy", "reroute"):
                cur = {"vsi": vsi, "members": [], key: val}
                out["groups"].append(cur)
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for g in data["groups"]:
            prefs = [m["preference"] for m in g["members"]]
            best = min(prefs) if prefs else None
            for mbr in g["members"]:
                word = mbr["state"].lower()
                active = word in ("active", "up", "master")
                rows.append(
                    record(
                        "l2vpn.pseudowires",
                        service=g.get("vsi") or g.get("name"),
                        neighbor=mbr["peer"],
                        pw_id=mbr["pw_id"],
                        state="up" if active else pw_state(word) or word,
                        role="primary" if mbr["preference"] == best else "backup",
                        active=active,
                        status_code=mbr["state"],
                    )
                )
        return rows


# --------------------------------------------------------------------------- #
# display mpls l2vc (LDP VLL)
# --------------------------------------------------------------------------- #


@register(
    "vrp",
    "display mpls l2vc [(brief|interface <interface>|vc-id <vcid>|remote-info|state (up|down))]",
    intent="l2vpn.pseudowires",
)
class DisplayMplsL2vc(Parser):
    """LDP L2VCs (VLL): client interface, AC/VC state, VC ID and type, destination, labels, MTU and tunnel."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"vcs": []}
        m = re.search(r"Total LDP VC\s*:\s*(\d+)\s+(\d+)\s+up\s+(\d+)\s+down", text)
        if m:
            out["total"], out["up"], out["down"] = (int(x) for x in m.groups())
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            tm = re.match(r"^\s*NO\.(?P<n>\d+)\s+TNL type\s*:\s*(?P<type>\S+)\s*,\s*TNL ID\s*:\s*(?P<id>\S+)", raw)
            if tm and cur is not None:
                cur.setdefault("tunnels", []).append({"type": tm["type"], "tunnel_id": tm["id"]})
                continue
            kv = _KV.match(raw.strip())
            if not kv:
                continue
            key, val = snake(kv["key"]), _val(kv["val"])
            if key == "client_interface":
                cur = {"interface": val}
                out["vcs"].append(cur)
                continue
            if cur is not None:
                # backup/secondary blocks repeat keys: keep the first and prefix the rest
                if key in cur and key not in ("interface",):
                    key = f"backup_{key}"
                cur[key] = val
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for vc in data["vcs"]:
            state = pw_state(str(vc.get("vc_state") or "down")) or "down"
            which = str(vc.get("primary_or_secondary") or "").lower()
            rows.append(
                record(
                    "l2vpn.pseudowires",
                    service=vc.get("interface"),
                    neighbor=str(vc.get("destination")),
                    pw_id=_int(vc.get("vc_id")),
                    state=state,
                    role="backup" if which == "secondary" else "primary" if which == "primary" else None,
                    active=state == "up",
                    vc_type=_vc_type(vc.get("vc_type")),
                    mtu=_int(vc.get("local_vc_mtu")),
                    local_label=_int(vc.get("local_vc_label")),
                    remote_label=_int(vc.get("remote_vc_label")),
                    status_code=_code(vc.get("vc_state")),
                    control_word=_enabled(
                        *(v for v in (vc.get("local_control_word"), vc.get("remote_control_word")) if v is not None)
                    ),
                )
            )
        return rows


# --------------------------------------------------------------------------- #
# display vsi remote
# --------------------------------------------------------------------------- #

_REMOTE_ROW = re.compile(
    rf"^(?P<vsi_id>\d+)\s+(?P<peer>{_IP})\s+(?P<label>\d+|-+)\s+(?P<group>\d+|-+)\s+(?P<encap>\S+)\s+"
    r"(?P<mtu>\d+|-+)\s+(?P<index>\d+|-+)\s+(?P<state>\S+)\s*$"
)


@register(
    "vrp", "display vsi remote (ldp|bgp) [(pw-id <pwid>|router-id <peer>|unicast|unused)]", intent="l2vpn.pseudowires"
)
class DisplayVsiRemote(Parser):
    """Remote VSI (PW) entries learned from peers: PW / VSI ID, peer, remote VC label, encapsulation, MTU, state code."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"remotes": []}
        for raw in text.splitlines():
            s = raw.strip()
            m = _REMOTE_ROW.match(s)
            if not m:
                if s and not set(s) <= {"-"} and not s.startswith(("Vsi ", "ID ")):
                    self.note_unparsed(s)
                continue
            out["remotes"].append(
                {
                    "vsi_id": int(m["vsi_id"]),
                    "peer": m["peer"],
                    "vc_label": _val(m["label"]),
                    "group_id": _val(m["group"]),
                    "encapsulation": m["encap"],
                    "mtu": _val(m["mtu"]),
                    "vsi_index": _val(m["index"]),
                    "state": m["state"],
                }
            )
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "l2vpn.pseudowires",
                service=str(r["vsi_id"]),  # the table only shows the VSI ID
                neighbor=r["peer"],
                pw_id=r["vsi_id"],
                state=pw_state(r["state"]) or "down",
                role=None,
                active=pw_state(r["state"]) == "up",
                vc_type=_vc_type(r["encapsulation"]),
                mtu=_int(r["mtu"]),
                local_label=None,
                remote_label=_int(r["vc_label"]),
                status_code=r["state"],
            )
            for r in data["remotes"]
        ]


# --------------------------------------------------------------------------- #
# display bridge-domain
# --------------------------------------------------------------------------- #

_BD_ROW = re.compile(
    r"^(?P<bd>\d+)\s+(?P<state>\*?down|up)\s+(?P<learn>enable|disable)\s+(?P<stat>enable|disable)\s+"
    r"(?P<bc>\S+)\s+(?P<mc>\S+)\s+(?P<uc>\S+)\s+(?P<split>enable|disable)(?:\s+(?P<desc>.+?))?\s*$"
)


@register("vrp", "display bridge-domain [<bd>] [(verbose|brief)]")
class DisplayBridgeDomain(Parser):
    """Bridge-domains: state, MAC learning, statistics, BC/MC/UC forwarding, split-horizon, bound VSI and interfaces."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"bridge_domains": []}
        m = re.search(r"total number of bridge-domains is\s*:\s*(\d+)", text, re.I)
        if m:
            out["total"] = int(m.group(1))
        for raw in text.splitlines():
            r = _BD_ROW.match(raw.strip())
            if r:
                out["bridge_domains"].append(
                    {
                        "bd_id": int(r["bd"]),
                        "state": "admin-down" if r["state"] == "*down" else r["state"],
                        "mac_learning": r["learn"],
                        "statistics": r["stat"],
                        "broadcast": r["bc"],
                        "unknown_multicast": r["mc"],
                        "unknown_unicast": r["uc"],
                        "split_horizon": r["split"],
                        "description": r["desc"],
                    }
                )
        if out["bridge_domains"]:
            return out
        cur: dict[str, Any] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            kv = _KV.match(s)
            if kv:
                key, val = snake(kv["key"]), _val(kv["val"])
                if key in ("bridge_domain_id", "bd_id"):
                    cur = {"bd_id": val, "interfaces": []}
                    out["bridge_domains"].append(cur)
                elif cur is not None:
                    cur[key] = val
                continue
            im = re.match(r"^(?P<intf>[A-Za-z][\w\-/.:]*\d)\s+(?P<state>up|down|\*down)\b", s)
            if im and cur is not None:
                cur["interfaces"].append({"interface": im["intf"], "state": im["state"]})
        return out
