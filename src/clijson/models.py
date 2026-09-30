"""Vendor-neutral data models ("intents").

Native parsers keep vendor terminology so nothing is lost. Parsers that map to
a common concept also implement ``normalize()`` which returns records with
exactly the fields listed below, whatever the vendor. This is what makes
multi-vendor automation pleasant::

    for platform, cmd in [("iosxr", "show bgp summary"), ("junos", "show bgp summary"), ("vrp", "display bgp peer")]:
        for peer in clijson.parse(out[platform], cmd, platform, normalize=True).normalized:
            print(peer["neighbor"], peer["state"])
"""

from __future__ import annotations

from typing import Any

from .textutils import normalize_mac, parse_duration

SCHEMAS: dict[str, list[str]] = {
    "system.version": ["hostname", "vendor", "os", "version", "model", "serial_number", "uptime", "uptime_seconds"],
    "interfaces.brief": ["name", "admin_status", "oper_status", "ip_address", "vrf", "description"],
    "interfaces.detail": [
        "name",
        "admin_status",
        "oper_status",
        "description",
        "mac_address",
        "mtu",
        "bandwidth_kbps",
        "ipv4_addresses",
        "input_rate_bps",
        "output_rate_bps",
        "input_packets",
        "output_packets",
        "input_errors",
        "output_errors",
    ],
    "interfaces.description": ["name", "admin_status", "oper_status", "description"],
    "bgp.summary": [
        "neighbor",
        "remote_as",
        "state",
        "established",
        "uptime",
        "uptime_seconds",
        "prefixes_received",
        "vrf",
        "address_family",
    ],
    "ospf.neighbors": ["neighbor_id", "priority", "state", "address", "interface", "dead_time"],
    "isis.adjacency": ["system_id", "interface", "state", "level", "hold_time", "snpa"],
    "lldp.neighbors": ["local_interface", "neighbor", "neighbor_interface", "chassis_id", "capabilities", "ttl"],
    "arp": ["ip_address", "mac_address", "interface", "age", "type"],
    "ipv6.neighbors": ["ip_address", "mac_address", "interface", "state", "age"],
    "routes": ["prefix", "protocol", "next_hops", "distance", "metric", "vrf", "age"],
    "ldp.neighbors": ["neighbor", "state", "uptime", "discovery_sources"],
    "bfd.sessions": ["neighbor", "interface", "state", "local_discriminator", "remote_discriminator", "detect_time_ms"],
    "inventory": ["name", "description", "part_number", "serial_number", "version"],
    "cpu": ["location", "one_minute", "five_minute", "five_second"],
    "vrfs": ["name", "rd", "interfaces"],
    "mac.table": ["mac_address", "vlan", "interface", "type"],
    "lag": ["name", "status", "members"],
}


def record(intent: str, **fields: Any) -> dict[str, Any]:
    """Build a record for *intent* with all schema keys present, in order."""
    keys = SCHEMAS[intent]
    unknown = set(fields) - set(keys)
    if unknown:  # pragma: no cover - programming error guard
        raise KeyError(f"{intent}: unknown fields {sorted(unknown)}")
    return {k: fields.get(k) for k in keys}


_UP = {"up", "u", "connected", "enabled", "enable", "online", "active", "ok", "*up"}
_DOWN = {"down", "d", "disabled", "disable", "notconnect", "not-connected", "offline", "inactive"}
_ADMIN_DOWN = {
    "admin-down",
    "admin down",
    "administratively down",
    "*down",
    "shutdown",
    "adm-down",
    "admindown",
    "deleted",
}


def status(value: str | None) -> str | None:
    """Map vendor state words to ``up`` / ``down`` / ``admin-down``."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in _UP:
        return "up"
    if v in _ADMIN_DOWN:
        return "admin-down"
    if v in _DOWN:
        return "down"
    if v.startswith("up"):
        return "up"
    if "admin" in v and "down" in v:
        return "admin-down"
    if v.startswith("down"):
        return "down"
    return v


def mac(value: str | None) -> str | None:
    return normalize_mac(value) if value else value


def seconds(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return parse_duration(str(value))
