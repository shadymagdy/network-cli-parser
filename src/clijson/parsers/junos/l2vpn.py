"""Junos L2VPN: ``show l2circuit connections`` and ``show vpls connections`` (LDP pseudowires, hot-standby backups)."""

from __future__ import annotations

import re
from typing import Any

from ...models import mac, pw_state, record
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
_BACKUP_CODES = {"HS", "ST", "BK", "RS"}

# the row up to the status code; "Time last up" and "# Up trans" are parsed from the rest by hand (both are
# missing on a standby or never-up circuit: "ae22.100(vc 7000)  rmt  RS")
_ROW = re.compile(
    r"^\s*(?P<name>[^\s(]+)\((?P<kind>vc|vpls-id|vpls) (?P<id>\d+)\)\s+(?P<type>rmt|loc)\s+(?P<st>\S+)(?P<rest>.*)$"
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


def _command_arg(command: str, keyword: str) -> str | None:
    """``show vpls connections instance VPLS-A | match rmt`` -> ``VPLS-A`` for *keyword* ``instance``."""
    words = command.split("|", 1)[0].split()
    for i, word in enumerate(words[:-1]):
        if word == keyword:
            return words[i + 1]
    return None


def _time_and_transitions(rest: str) -> tuple[str | None, int | None]:
    """``"Apr 17 05:43:09 2025           1"`` -> (``"Apr 17 05:43:09 2025"``, 1); ``""`` -> (None, None).

    The count is the last number, when it follows the year or a ``-----`` placeholder (or stands alone), so a time
    without a count never loses its year. The time keeps its spacing as printed (``"Feb  2 ..."``).
    """
    text = rest.strip()
    tokens = text.split()
    trans = None
    if tokens and tokens[-1].isdigit() and (len(tokens) == 1 or tokens[-2].isdigit() or set(tokens[-2]) <= {"-"}):
        trans = int(tokens[-1])
        text = text[: len(text) - len(tokens[-1])].rstrip()
    last_up = text or None
    if last_up and set(last_up) <= {"-"}:
        last_up = None
    return last_up, trans


def _is_header(s: str) -> bool:
    """Section titles, the legend and the column header line."""
    return (
        " -- " in s
        or s.startswith(
            ("Legend for", "Layer-2 Circuit Connections", "Layer-2 VPN connections", "Layer-2 VPN Connections")
        )
        or (s.startswith(("Interface ", "Neighbor ")) and " Type " in f" {s} " and " St" in s)
    )


def parse_connections(text: str, section: str, command: str = "", parser: Parser | None = None) -> dict[str, Any]:
    """Shared parser: *section* is ``neighbor`` (l2circuit) or ``instance`` (vpls).

    Rows filtered out of their section (``| match rmt``) still parse; the section then comes from the command
    (``neighbor X`` / ``instance X``) when it names one. Lines that are neither header, legend, row nor detail are
    reported to *parser* (``note_unparsed``) instead of being dropped silently.
    """
    out: dict[str, Any] = {"connections": []}
    group: str | None = _command_arg(command, section)
    vpls_id: Any = None
    cur: dict[str, Any] | None = None
    in_history = False

    def unparsed(line: str) -> None:
        if parser is not None:
            parser.note_unparsed(line)

    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        m = re.match(r"^(Neighbor|Instance):\s*(\S+)$", s)
        if m:
            group, cur, in_history = m.group(2), None, False
            continue
        m = re.match(r"^VPLS-id:\s*(\S+)", s)
        if m:
            vpls_id = to_num(m.group(1))
            continue
        m = _ROW.match(raw)
        if m:
            st = m["st"]
            last_up, trans = _time_and_transitions(m["rest"])
            cur = {
                section: group,
                "pw_id": int(m["id"]),
                "type": "remote" if m["type"] == "rmt" else "local",
                "status": st,
                "status_text": STATUS_CODES.get(st),
                "last_up": last_up,
                "up_transitions": trans,
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
        if _is_header(s):
            continue
        if cur is None:
            # section-level details before the first row ("Edge protection: Not-Primary", "Local site: ...")
            # describe the instance, not a connection; anything else is unexpected
            if not (":" in s and (group is not None or vpls_id is not None)):
                unparsed(s)
            continue
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
        if ":" in s:
            kv = _kv_line(s)
            # "Status" belongs to the local interface, not the PW status code shown in the table
            if "local_interface" in kv and "status" in kv:
                kv["local_interface_status"] = kv.pop("status")
            cur.update(kv)
            continue
        unparsed(s)
    return out


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _hex(value: Any) -> str | None:
    return value if isinstance(value, str) and value.lower().startswith("0x") else None


def _normalize(data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    rows = []
    for c in data["connections"]:
        code = c["status"]
        state = pw_state(code) or "down"
        encap = str(c.get("encapsulation") or "").upper()
        if code in _BACKUP_CODES:
            role: str | None = "backup"
        elif section == "neighbor" and state == "up":
            role = "primary"  # l2circuit: the forwarding circuit; standby ones are RS / ST / HS / BK
        else:
            role = None
        rows.append(
            record(
                "l2vpn.pseudowires",
                service=c.get("interface") if section == "neighbor" else c.get("instance"),
                neighbor=c.get("remote_pe") or c.get("neighbor"),
                pw_id=c["pw_id"],
                state=state,
                role=role,
                active=state == "up",
                vc_type=_ENCAP.get(encap) if encap else None,
                mtu=c.get("mtu") if isinstance(c.get("mtu"), int) else None,
                local_label=c.get("incoming_label") if isinstance(c.get("incoming_label"), int) else None,
                remote_label=c.get("outgoing_label") if isinstance(c.get("outgoing_label"), int) else None,
                status_code=code,
                local_status_code=_hex(c.get("local_pw_status_code")),
                remote_status_code=_hex(c.get("neighbor_pw_status_code")),
                control_word=_bool(c.get("negotiated_control_word")),
                pw_status_tlv=_bool(c.get("negotiated_pw_status_tlv")),
                flow_label_tx=_bool(c.get("flow_label_transmit")),
                flow_label_rx=_bool(c.get("flow_label_receive")),
            )
        )
    return rows


@register("junos", "show l2circuit connections [<args...>]", intent="l2vpn.pseudowires")
class ShowL2circuitConnections(Parser):
    """Layer-2 circuits per neighbor: status code (Up, HS hot-standby, MM, ...), labels, PW status TLV, flow labels."""

    def parse(self, text: str) -> dict[str, Any]:
        return parse_connections(text, "neighbor", self.command, self)

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _normalize(data, "neighbor")


@register("junos", "show vpls connections [<args...>]", intent="l2vpn.pseudowires")
class ShowVplsConnections(Parser):
    """VPLS pseudowires per instance: neighbor, VPLS-id, status code, labels and local LSI interface."""

    def parse(self, text: str) -> dict[str, Any]:
        return parse_connections(text, "instance", self.command, self)

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return _normalize(data, "instance")


def _mac_table_header(s: str) -> bool:
    """Column headers and per-instance counters (the flags legend is skipped by the caller)."""
    return (
        s.startswith(("MAC ", "address ", "Routing instance", "Bridging domain"))
        or "MAC address learned" in s
        or "MAC addresses learned" in s
    )


_MAC_ROW = re.compile(r"^(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?P<flags>\S+)\s+(?P<intf>\S+)(?P<rest>.*)$")


@register(
    "junos",
    "show (vpls|bridge|evpn) mac-table [<args...>]",
    intent="mac.table",
)
class ShowVplsMacTable(Parser):
    """MAC table per routing instance and bridging domain (VPLS, bridge domains, EVPN): flags, interface, source."""

    def parse(self, text: str) -> dict[str, Any]:
        out: dict[str, Any] = {"entries": []}
        instance = _command_arg(self.command, "instance")
        domain: str | None = None
        vlan: Any = None
        in_legend = False
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Routing instance\s*:\s*(\S+)", s)
            if m:
                instance, domain, vlan = m.group(1), None, None
                continue
            m = re.match(r"^Bridging domain\s*:\s*([^,\s]+)(?:,\s*VLAN\s*:\s*(\S+))?", s)
            if m:
                domain = m.group(1)
                vlan = None if not m.group(2) or m.group(2) == "none" else to_num(m.group(2))
                continue
            if in_legend:  # continuation of "MAC flags (...": up to the closing parenthesis
                in_legend = ")" not in s
                continue
            if s.startswith("MAC flags"):
                in_legend = ")" not in s
                continue
            m = _MAC_ROW.match(s)
            if not m:
                if s and not _mac_table_header(s):
                    self.note_unparsed(s)
                continue
            rest = m["rest"].split()
            entry: dict[str, Any] = {
                "mac_address": m["mac"].lower(),
                "flags": m["flags"].split(","),
                "interface": m["intf"],
                "routing_instance": instance,
                "bridging_domain": domain,
                "vlan": vlan,
            }
            if rest and rest[0].isdigit():
                entry["nh_index"] = int(rest.pop(0))
            if rest:
                entry["active_source"] = rest[-1]
            out["entries"].append(entry)
        return out

    def normalize(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            record(
                "mac.table",
                mac_address=mac(e["mac_address"]),
                vlan=e["vlan"] if e["vlan"] is not None else e["routing_instance"],
                interface=e["interface"],
                type="static" if "S" in e["flags"] else "dynamic",
            )
            for e in data["entries"]
        ]
