"""IOS XR L2VPN: bridge-domains (default/detail), xconnect detail and the L2VPN forwarding MAC table.

PW redundancy is visible in all of them: a backup pseudowire is listed after ``Backup PW:`` and reports
``state is standby`` / ``Backup for neighbor X PW ID N``, while the primary reports ``Backup PW for neighbor ...``.
"""

from __future__ import annotations

import re
from typing import Any

from ...models import mac, pw_state, record
from ...registry import Parser, register
from ...textutils import to_num

_IP = r"[0-9a-fA-F.:]+"
_BD_HDR = re.compile(
    r"^Bridge group: (?P<group>[^,]+), bridge-domain: (?P<bd>[^,]+), id: (?P<id>\d+), state: (?P<state>[^,]+)"
    r"(?:, ShgId: (?P<shg>\d+))?(?:, MSTi: (?P<msti>\d+))?"
)
_XC_HDR = re.compile(
    r"^Group (?P<group>\S+), XC (?P<xc>\S+), state is (?P<state>[^;]+?)(?:; Interworking (?P<iw>\S+))?\s*$"
)
_PW_DETAIL = re.compile(
    rf"^PW: neighbor (?P<nbr>{_IP}), PW ID (?P<id>\d+), state is (?P<state>[\w\- ]+?)\s*(?:\(\s*(?P<detail>[^)]*?)\s*\))?\s*$"
)
_PW_BRIEF = re.compile(
    rf"^Neighbor (?P<nbr>{_IP}) pw-id (?P<id>\d+), state: (?P<state>[^,]+)(?:, Static MAC addresses: (?P<smac>\d+))?"
)
_AC_DETAIL = re.compile(r"^AC: (?P<intf>\S+), state is (?P<state>[\w\- ]+?)\s*(?:\((?P<detail>[^)]*)\))?\s*$")
_AC_BRIEF = re.compile(
    r"^(?P<intf>[A-Za-z][\w/.:\-]*\d), state: (?P<state>[^,]+)(?:, Static MAC addresses: (?P<smac>\d+))?"
)
_MPLS_ROW = re.compile(
    r"^(?P<key>Label|Group ID|Interface|MTU|Control word|PW type|VCCV CV type|VCCV CC type)\s{2,}(?P<rest>.+)$"
)
_VC_TYPE = {"ethernet vlan": "ethernet-vlan", "ethernet": "ethernet", "ethernet vpls": "ethernet"}


def _two_cols(rest: str) -> tuple[str | None, str | None]:
    parts = [p.strip() for p in re.split(r"\s{2,}", rest.strip()) if p.strip()]
    if not parts:
        return None, None
    return parts[0], (parts[1] if len(parts) > 1 else None)


class _L2vpnText:
    """Line-oriented reader shared by bridge-domain and xconnect output."""

    def __init__(self) -> None:
        self.services: list[dict[str, Any]] = []
        self.svc: dict[str, Any] | None = None
        self.pw: dict[str, Any] | None = None
        self.ac: dict[str, Any] | None = None
        self.vfi: str | None = None
        self.next_is_backup = False
        self.section: str | None = None
        self.status_dir: str | None = None

    def feed(self, raw: str) -> None:
        s = raw.strip()
        if not s or s.startswith(("Legend", "----")):
            return
        m = _BD_HDR.match(s)
        if m:
            self._new_service(
                {
                    "group": m["group"].strip(),
                    "bridge_domain": m["bd"].strip(),
                    "id": int(m["id"]),
                    "state": m["state"].strip(),
                    **({"shg_id": int(m["shg"])} if m["shg"] else {}),
                    **({"msti": int(m["msti"])} if m["msti"] else {}),
                }
            )
            return
        m = _XC_HDR.match(s)
        if m:
            self._new_service(
                {"group": m["group"], "xconnect": m["xc"], "state": m["state"].strip(), "interworking": m["iw"]}
            )
            return
        if self.svc is None:
            return
        if s.startswith("List of "):
            self.section = s[8:].rstrip(":").lower()
            self.vfi, self.pw, self.ac = None, None, None
            return
        m = re.match(r"^VFI (?P<vfi>\S+)(?: \((?P<state>[^)]*)\))?", s)
        if m and self.section and "vfi" in self.section:
            self.vfi = m["vfi"]
            self.svc.setdefault("vfis", []).append({"name": m["vfi"], "state": m["state"]})
            self.pw = None
            return
        if s == "Backup PW:":
            self.next_is_backup = True
            return
        m = _PW_DETAIL.match(s) or _PW_BRIEF.match(s)
        if m:
            self._new_pw(m)
            return
        m = _AC_DETAIL.match(s)
        if m or (self.section == "acs" and (m := _AC_BRIEF.match(s))):
            self.pw = None
            self.ac = {"interface": m["intf"], "state": m["state"].strip()}
            if "smac" in m.groupdict() and m["smac"] is not None:
                self.ac["static_mac_addresses"] = int(m["smac"])
            self.svc.setdefault("acs", []).append(self.ac)
            return
        if self.pw is not None:
            self._pw_line(s)
        elif self.ac is not None:
            self._ac_line(s)
        else:
            self._service_line(s)

    def _new_service(self, svc: dict[str, Any]) -> None:
        self.svc, self.pw, self.ac, self.vfi, self.section = svc, None, None, None, None
        svc.setdefault("acs", [])
        svc.setdefault("pws", [])
        self.services.append(svc)

    def _new_pw(self, m: re.Match[str]) -> None:
        assert self.svc is not None
        self.ac = None
        gd = m.groupdict()
        self.pw = {"neighbor": m["nbr"], "pw_id": int(m["id"]), "state": m["state"].strip()}
        if gd.get("detail"):
            self.pw["state_detail"] = gd["detail"]
        if gd.get("smac") is not None:
            self.pw["static_mac_addresses"] = int(gd["smac"])
        if self.vfi:
            self.pw["vfi"] = self.vfi
        if self.section:
            self.pw["kind"] = "access" if "access" in self.section else "vfi" if "vfi" in self.section else self.section
        if self.next_is_backup:
            self.pw["backup"] = True
            self.next_is_backup = False
        self.svc["pws"].append(self.pw)

    def _pw_line(self, s: str) -> None:
        pw = self.pw
        assert pw is not None
        m = re.match(rf"^Backup for neighbor (?P<nbr>{_IP}) PW ID (?P<id>\d+)(?: \(\s*(?P<st>[^)]*?)\s*\))?", s)
        if m:
            pw["backup"] = True
            pw["backup_for"] = {"neighbor": m["nbr"], "pw_id": int(m["id"])}
            if m["st"]:
                pw["backup_state"] = m["st"]
            return
        m = re.match(rf"^Backup PW for neighbor (?P<nbr>{_IP}) PW ID (?P<id>\d+)", s)
        if m:
            pw["backup_pw"] = {"neighbor": m["nbr"], "pw_id": int(m["id"])}
            return
        m = re.match(r"^PW class (?P<cls>.+?), XC ID (?P<xc>\S+)", s)
        if m:
            pw["pw_class"] = None if m["cls"] == "not set" else m["cls"]
            pw["xc_id"] = m["xc"]
            return
        m = re.match(r"^Encapsulation (?P<enc>\S+), protocol (?P<proto>\S+)", s)
        if m:
            pw["encapsulation"], pw["protocol"] = m["enc"], m["proto"]
            return
        m = re.match(r"^Source address (\S+)", s)
        if m:
            pw["source_address"] = m.group(1)
            return
        m = re.match(r"^PW type (?P<type>[^,]+), control word (?P<cw>[^,]+), interworking (?P<iw>\S+)", s)
        if m:
            pw["pw_type"], pw["control_word"], pw["interworking"] = m["type"].strip(), m["cw"].strip(), m["iw"]
            return
        m = re.match(r"^PW backup disable delay (\d+) sec", s)
        if m:
            pw["backup_disable_delay"] = int(m.group(1))
            return
        if s == "PW Status TLV in use":
            pw["pw_status_tlv"] = True
            return
        m = _MPLS_ROW.match(s)
        if m:
            local, remote = _two_cols(m["rest"])
            key = m["key"].lower().replace(" ", "_")
            pw.setdefault("mpls", {})[key] = {"local": to_num(local), "remote": to_num(remote)}
            return
        m = re.match(r"^(Incoming|Outgoing) Status \(PW Status TLV\):", s)
        if m:
            self.status_dir = m.group(1).lower()
            return
        m = re.match(r"^Status code: (?P<code>\S+) \((?P<text>[^)]*)\)", s)
        if m and self.status_dir:
            pw[f"{self.status_dir}_status"] = {"code": m["code"], "text": m["text"]}
            return
        m = re.match(r"^(Create time|Last time status changed): (?P<t>.+?)(?: \((?P<ago>[^)]*) ago\))?$", s)
        if m:
            key = "create_time" if m.group(1) == "Create time" else "last_status_change"
            pw[key] = m["t"]
            return
        m = re.match(r"^(packets|bytes): received (\d+), sent (\d+)", s)
        if m:
            pw.setdefault("statistics", {})[m.group(1)] = {"received": int(m.group(2)), "sent": int(m.group(3))}

    def _ac_line(self, s: str) -> None:
        ac = self.ac
        assert ac is not None
        m = re.match(r"^Type (?P<type>[^;]+)(?:; Num Ranges: (?P<n>\d+))?", s)
        if m:
            ac["type"] = m["type"].strip()
            return
        m = re.match(r"^VLAN ranges: \[(?P<a>\d+), (?P<b>\d+)\]", s)
        if m:
            ac["vlan_range"] = [int(m["a"]), int(m["b"])]
            return
        m = re.match(r"^MTU (?P<mtu>\d+); XC ID (?P<xc>\S+); interworking (?P<iw>\S+)", s)
        if m:
            ac["mtu"], ac["xc_id"], ac["interworking"] = int(m["mtu"]), m["xc"], m["iw"]
            return
        m = re.match(r"^(packets|bytes): received (\d+)(?: \([^)]*\))?, sent (\d+)", s)
        if m:
            ac.setdefault("statistics", {})[m.group(1)] = {"received": int(m.group(2)), "sent": int(m.group(3))}

    def _service_line(self, s: str) -> None:
        svc = self.svc
        assert svc is not None
        m = re.match(
            r"^ACs: (?P<acs>\d+) \((?P<acs_up>\d+) up\), VFIs: (?P<vfis>\d+), PWs: (?P<pws>\d+) \((?P<pws_up>\d+) up\)",
            s,
        )
        if m:
            svc["counts"] = {k: int(v) for k, v in m.groupdict().items()}
            return
        m = re.match(
            r"^Aging: (?P<age>\d+) s, MAC limit: (?P<lim>\d+), Action: (?P<act>[^,]+), Notification: (?P<n>\S+)", s
        )
        if m:
            svc["mac_aging"], svc["mac_limit"] = int(m["age"]), int(m["lim"])
            svc["mac_limit_action"], svc["mac_limit_notification"] = m["act"], m["n"]
            return
        m = re.match(r"^(MTU|Bridge MTU|MAC learning|Coupled state|Split Horizon Group|Filter MAC addresses): (.+)$", s)
        if m:
            svc[m.group(1).lower().replace(" ", "_")] = to_num(m.group(2).strip())


def _vc_type(pw: dict[str, Any]) -> str | None:
    t = pw.get("pw_type") or (pw.get("mpls", {}).get("pw_type") or {}).get("local")
    return _VC_TYPE.get(str(t).lower(), str(t).lower()) if t else None


def _pseudowires(services: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    rows = []
    for svc in services:
        for pw in svc["pws"]:
            state = pw_state(pw["state"]) or "down"
            mpls = pw.get("mpls", {})
            role = "backup" if pw.get("backup") or state == "standby" else "primary" if pw.get("backup_pw") else None
            rows.append(
                record(
                    "l2vpn.pseudowires",
                    service=svc.get(key),
                    neighbor=pw["neighbor"],
                    pw_id=pw["pw_id"],
                    state=state,
                    role=role,
                    active=state == "up",
                    vc_type=_vc_type(pw),
                    mtu=(mpls.get("mtu") or {}).get("local"),
                    local_label=(mpls.get("label") or {}).get("local"),
                    remote_label=(mpls.get("label") or {}).get("remote"),
                )
            )
    return rows


@register(
    "iosxr",
    "show l2vpn bridge-domain [(bd-name <bd>|group <group>|interface <interface>|neighbor <neighbor> [pw-id <pwid>])] [(detail|private)]",
    "show l2vpn bridge-domain pw-id <pwid> [(detail|private)]",
    intent="l2vpn.pseudowires",
)
class ShowL2vpnBridgeDomain(Parser):
    """Bridge-domains with state, ACs, access/VFI pseudowires, PW class, labels, MTU and backup PW role."""

    def parse(self, text: str) -> dict[str, Any]:
        reader = _L2vpnText()
        for raw in text.splitlines():
            reader.feed(raw)
        return {"bridge_domains": reader.services}

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _pseudowires(data["bridge_domains"], "bridge_domain")


@register(
    "iosxr",
    "show l2vpn xconnect [(group <group> [xc-name <xc>]|interface <interface>|neighbor <neighbor> [pw-id <pwid>]|state <state>)] detail",
    intent="l2vpn.pseudowires",
)
class ShowL2vpnXconnectDetail(Parser):
    """Point-to-point cross-connects in detail: AC, primary and backup PWs, PW class, labels, MTU and status TLV."""

    def parse(self, text: str) -> dict[str, Any]:
        reader = _L2vpnText()
        for raw in text.splitlines():
            reader.feed(raw)
        return {"xconnects": reader.services}

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _pseudowires(data["xconnects"], "xconnect")


@register(
    "iosxr",
    "show l2vpn forwarding bridge-domain [<bd>] mac-address [<mac>] [(detail|hardware ingress|hardware egress)] location <location>",
    "show l2vpn forwarding bridge-domain [<bd>] mac-address [<mac>] [(detail|hardware ingress|hardware egress)]",
    intent="mac.table",
)
class ShowL2vpnForwardingBridgeDomainMacAddress(Parser):
    """L2VPN MAC table: address, type, learned-from (AC interface or PW neighbor/ID), line card and age."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"entries": []}
        for raw in text.splitlines():
            m = re.match(
                rf"^(?P<mac>[0-9a-fA-F]{{4}}\.[0-9a-fA-F]{{4}}\.[0-9a-fA-F]{{4}})\s+(?P<type>\S+)\s+"
                rf"(?P<src>\(\s*{_IP},\s*\d+\s*\)|\S+)\s+(?P<lc>\S+)\s+(?P<rest>.*?)\s*$",
                raw.strip(),
            )
            if not m:
                continue
            src = m["src"]
            e: dict[str, Any] = {"mac_address": m["mac"], "type": m["type"], "learned_from": src, "location": m["lc"]}
            pm = re.match(rf"^\(\s*(?P<nbr>{_IP}),\s*(?P<id>\d+)\s*\)$", src)
            if pm:
                e["neighbor"], e["pw_id"] = pm["nbr"], int(pm["id"])
            else:
                e["interface"] = src
            rest = m["rest"]
            am = re.match(r"^(?P<age>(?:\d+d\s*)?\d+h\s*\d+m\s*\d+s|N/A)(?:\s+(?P<mapped>\S+))?$", rest)
            if am:
                e["age"] = None if am["age"] == "N/A" else am["age"]
                if am["mapped"] and am["mapped"] != "N/A":
                    e["mapped_to"] = am["mapped"]
            elif rest:
                e["age"] = rest
            out["entries"].append(e)
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        bd = self.params.get("bd")
        return [
            record(
                "mac.table",
                mac_address=mac(e["mac_address"]),
                vlan=to_num(bd) if bd else None,
                interface=e.get("interface") or f"{e.get('neighbor')}:{e.get('pw_id')}",
                type=e["type"],
            )
            for e in data["entries"]
        ]
