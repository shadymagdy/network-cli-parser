"""Junos L2VPN: ``show l2circuit connections`` and ``show vpls connections`` (LDP pseudowires, hot-standby backups)."""

from __future__ import annotations

import re
from typing import Any

from ...models import pw_state, record
from ...registry import Parser, register
from ...textutils import snake, to_num

#: Connection status codes from the command's legend.
STATUS_CODES = {
    "EI": "encapsulation invalid",
    "NP": "interface hardware not present",
    "MM": "mtu mismatch",
    "Dn": "down",
    "EM": "encapsulation mismatch",
    "VC-Dn": "virtual circuit down",
    "CM": "control-word mismatch",
    "Up": "operational",
    "VM": "vlan id mismatch",
    "CF": "call admission control failure",
    "OL": "no outgoing label",
    "IB": "TDM incompatible bitrate",
    "NC": "interface encapsulation not CCC/TCC",
    "TM": "TDM misconfiguration",
    "BK": "backup connection",
    "ST": "standby connection",
    "CB": "received cell-bundle size bad",
    "SP": "static pseudowire",
    "LD": "local site signaled down",
    "RS": "remote site standby",
    "RD": "remote site signaled down",
    "HS": "hot-standby connection",
    "XX": "unknown",
}
_BACKUP_CODES = {"HS", "ST", "BK"}

_ROW = re.compile(
    r"^\s+(?P<name>\S+?)\((?P<kind>vc|vpls-id|vpls) (?P<id>\d+)\)\s+(?P<type>rmt|loc)\s+(?P<st>\S+)"
    r"(?:\s+(?P<last_up>.+?))?\s+(?P<trans>\d+)\s*$"
)
_ENCAP = {"VLAN": "ethernet-vlan", "ETHERNET": "ethernet", "VLAN-CCC": "ethernet-vlan"}


def _kv_line(line: str) -> dict[str, Any]:
    """``Remote PE: 192.0.2.2, Negotiated control-word: No`` -> ``{"remote_pe": ..., "negotiated_control_word": False}``."""
    out: dict[str, Any] = {}
    s = line.strip()
    if s.startswith("Description:"):
        return {"description": s.split(":", 1)[1].strip()}
    for part in s.split(", "):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        v = v.strip()
        out[snake(k)] = True if v == "Yes" else False if v == "No" else to_num(v)
    return out


def parse_connections(text: str, section: str) -> dict[str, Any]:
    """Shared parser: *section* is ``neighbor`` (l2circuit) or ``instance`` (vpls)."""
    out: dict[str, Any] = {"connections": []}
    group: str | None = None
    vpls_id: Any = None
    cur: dict[str, Any] | None = None
    in_history = False
    for raw in text.splitlines():
        if not raw.strip():
            continue
        m = re.match(r"^\s*(Neighbor|Instance):\s*(\S+)\s*$", raw)
        if m:
            group, cur, in_history = m.group(2), None, False
            continue
        m = re.match(r"^\s*VPLS-id:\s*(\S+)", raw)
        if m:
            vpls_id = to_num(m.group(1))
            continue
        m = _ROW.match(raw)
        if m and group is not None:
            st = m["st"]
            cur = {
                section: group,
                "pw_id": int(m["id"]),
                "type": "remote" if m["type"] == "rmt" else "local",
                "status": st,
                "status_text": STATUS_CODES.get(st),
                "last_up": None if not m["last_up"] or set(m["last_up"].strip()) <= {"-"} else m["last_up"].strip(),
                "up_transitions": int(m["trans"]),
            }
            if section == "neighbor":
                cur["interface"] = m["name"]
            else:
                cur["neighbor"] = m["name"]
                if vpls_id is not None:
                    cur["vpls_id"] = vpls_id
            out["connections"].append(cur)
            in_history = False
            continue
        if cur is None:
            continue
        s = raw.strip()
        if s.startswith("Connection History"):
            in_history = True
            cur["history"] = []
            continue
        if in_history:
            hm = re.match(r"^(?P<time>\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+(?P<event>.+?)\s*$", s)
            if hm:
                cur["history"].append({"time": hm["time"], "event": hm["event"]})
                continue
            in_history = False
        if ":" in s and not s.startswith(("Legend", "Layer-2", "Interface ", "Neighbor ")):
            kv = _kv_line(s)
            # "Status" belongs to the local interface, not the PW status code shown in the table
            if "local_interface" in kv and "status" in kv:
                kv["local_interface_status"] = kv.pop("status")
            cur.update(kv)
    return out


def _normalize(data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    rows = []
    for c in data["connections"]:
        code = c["status"]
        state = pw_state(code) or "down"
        encap = str(c.get("encapsulation") or "").upper()
        rows.append(
            record(
                "l2vpn.pseudowires",
                service=c.get("interface") if section == "neighbor" else c.get("instance"),
                neighbor=c.get("remote_pe") or c.get("neighbor"),
                pw_id=c["pw_id"],
                state=state,
                role="backup" if code in _BACKUP_CODES else None,
                active=state == "up",
                vc_type=_ENCAP.get(encap) if encap else None,
                mtu=c.get("mtu") if isinstance(c.get("mtu"), int) else None,
                local_label=c.get("incoming_label") if isinstance(c.get("incoming_label"), int) else None,
                remote_label=c.get("outgoing_label") if isinstance(c.get("outgoing_label"), int) else None,
            )
        )
    return rows


@register("junos", "show l2circuit connections [<args...>]", intent="l2vpn.pseudowires")
class ShowL2circuitConnections(Parser):
    """Layer-2 circuits per neighbor: status code (Up, HS hot-standby, MM, ...), labels, PW status TLV, flow labels."""

    def parse(self, text: str) -> dict[str, Any]:
        return parse_connections(text, "neighbor")

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _normalize(data, "neighbor")


@register("junos", "show vpls connections [<args...>]", intent="l2vpn.pseudowires")
class ShowVplsConnections(Parser):
    """VPLS pseudowires per instance: neighbor, VPLS-id, status code, labels and local LSI interface."""

    def parse(self, text: str) -> dict[str, Any]:
        return parse_connections(text, "instance")

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _normalize(data, "instance")
