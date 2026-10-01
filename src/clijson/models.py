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

import types
from typing import Annotated, Any, Literal, TypedDict, Union, get_args, get_origin, get_type_hints

from .textutils import normalize_mac, parse_duration

__all__ = [
    "INTENTS",
    "SCHEMAS",
    "SINGLE_RECORD",
    "Arp",
    "BfdSession",
    "BgpNeighbor",
    "Cpu",
    "Interface",
    "InterfaceDescription",
    "InterfaceDetail",
    "Inventory",
    "Ipv6Neighbor",
    "IsisAdjacency",
    "Lag",
    "LdpNeighbor",
    "LldpNeighbor",
    "MacEntry",
    "NextHop",
    "OspfNeighbor",
    "Route",
    "SystemVersion",
    "Vrf",
    "json_schema",
    "mac",
    "record",
    "seconds",
    "status",
    "validate",
]

#: ``up``, ``down`` or ``admin-down`` when the vendor word is recognised, else the vendor word lowercased.
Status = Annotated[str, "up | down | admin-down (vendor word if unrecognised)"]
#: MAC address in ``aa:bb:cc:dd:ee:ff`` form.
Mac = Annotated[str, "MAC address, lowercase colon-separated (aa:bb:cc:dd:ee:ff)"]


class SystemVersion(TypedDict):
    """Device identity and software release."""

    hostname: Annotated[str | None, "Configured hostname"]
    vendor: Annotated[str, "cisco | juniper | huawei"]
    os: Annotated[str, "iosxr | junos | vrp"]
    version: Annotated[str, "Software release, e.g. 7.9.2, 23.4R1.9, V800R021C10SPC600"]
    model: Annotated[str | None, "Chassis / platform model"]
    serial_number: Annotated[str | None, "Chassis serial number"]
    uptime: Annotated[str | None, "Uptime as printed by the device"]
    uptime_seconds: Annotated[int | None, "Uptime in seconds"]


class Interface(TypedDict):
    """One row per interface."""

    name: Annotated[str, "Interface name as the device prints it"]
    admin_status: Status
    oper_status: Status
    ip_address: Annotated[str | None, "Primary IPv4 address, with /len when shown"]
    vrf: Annotated[str | None, "VRF / routing instance, if not the default"]
    description: Annotated[str | None, "Interface description"]


class InterfaceDetail(TypedDict):
    """Per-interface state, addressing and counters."""

    name: str
    admin_status: Status
    oper_status: Status
    description: str | None
    mac_address: Mac | None
    mtu: Annotated[int | None, "MTU in bytes"]
    bandwidth_kbps: Annotated[int | None, "Configured / negotiated bandwidth in kbit/s"]
    ipv4_addresses: Annotated[list[str], "IPv4 addresses with prefix length"]
    input_rate_bps: Annotated[int | None, "Input rate in bit/s"]
    output_rate_bps: Annotated[int | None, "Output rate in bit/s"]
    input_packets: int | None
    output_packets: int | None
    input_errors: int | None
    output_errors: int | None


class InterfaceDescription(TypedDict):
    """Interface descriptions with state."""

    name: str
    admin_status: Status
    oper_status: Status
    description: str | None


class BgpNeighbor(TypedDict):
    """One row per BGP peer (and address family, where the device splits them)."""

    neighbor: Annotated[str, "Peer address"]
    remote_as: Annotated[int | str, "Peer AS; asdot notation (65000.1) stays a string"]
    state: Annotated[str, "Established, Idle, Active, Connect, OpenSent, OpenConfirm, ..."]
    established: Annotated[bool, "True when the session is Established"]
    uptime: Annotated[str, "Up/down time as printed by the device"]
    uptime_seconds: Annotated[int | None, "Up/down time in seconds"]
    prefixes_received: Annotated[int | None, "Accepted prefixes (when established)"]
    vrf: Annotated[str, "VRF / routing instance (default for the global table)"]
    address_family: Annotated[str | None, "e.g. ipv4 unicast, vpnv4 unicast"]


class OspfNeighbor(TypedDict):
    """OSPF adjacencies."""

    neighbor_id: Annotated[str, "Neighbor router ID"]
    priority: int | None
    state: Annotated[str, "full, 2way, init, exstart, ... (lowercase, without /DR suffix)"]
    address: Annotated[str | None, "Neighbor interface address"]
    interface: str
    dead_time: Annotated[int | None, "Seconds until the dead timer expires"]


class IsisAdjacency(TypedDict):
    """IS-IS adjacencies."""

    system_id: Annotated[str, "Neighbor system ID or hostname"]
    interface: str
    state: str
    level: Annotated[str, "L1, L2 or L1L2"]
    hold_time: Annotated[int | None, "Seconds of hold time left"]
    snpa: Annotated[str | None, "Subnetwork point of attachment (MAC)"]


class LldpNeighbor(TypedDict):
    """LLDP neighbors."""

    local_interface: str
    neighbor: Annotated[str, "Neighbor system name"]
    neighbor_interface: Annotated[str, "Neighbor port ID"]
    chassis_id: str | None
    capabilities: Annotated[list[str] | None, 'Enabled capabilities, e.g. ["router", "bridge"]']
    ttl: Annotated[int | None, "Hold time in seconds"]


class Arp(TypedDict):
    """IPv4 ARP entries."""

    ip_address: str
    mac_address: Mac
    interface: str
    age: Annotated[int | None, "Seconds since learned (or remaining lifetime when that is all the device shows)"]
    type: Annotated[str, "dynamic, static, interface, ... (vendor word)"]


class Ipv6Neighbor(TypedDict):
    """IPv6 neighbor discovery cache."""

    ip_address: str
    mac_address: Mac | None
    interface: str | None
    state: Annotated[str | None, "reach, stale, delay, probe, ... (lowercase)"]
    age: Annotated[int | None, "Seconds since last reachability confirmation (or remaining lifetime)"]


class NextHop(TypedDict):
    """One next hop of a route."""

    next_hop: Annotated[str | None, "Next-hop address (None for connected / discard routes)"]
    interface: Annotated[str | None, "Outgoing interface"]


class Route(TypedDict):
    """Routing table entries."""

    prefix: Annotated[str, "Destination prefix with length"]
    protocol: Annotated[str, "connected, static, ospf, isis, bgp, local, ... (lowercase)"]
    next_hops: list[NextHop]
    distance: Annotated[int | None, "Administrative distance / preference"]
    metric: int | None
    vrf: Annotated[str, "VRF / routing table (default for the global table)"]
    age: Annotated[str | None, "Route age as printed by the device"]


class LdpNeighbor(TypedDict):
    """LDP sessions."""

    neighbor: Annotated[str, "Peer LDP ID or address"]
    state: str
    uptime: str | None
    discovery_sources: Annotated[list[str] | None, "Interfaces / targeted sources the peer was discovered on"]


class BfdSession(TypedDict):
    """BFD sessions."""

    neighbor: str
    interface: str | None
    state: Annotated[str, "up, down, init, admindown (lowercase)"]
    local_discriminator: int | None
    remote_discriminator: int | None
    detect_time_ms: Annotated[int | None, "Detection time in milliseconds"]


class Inventory(TypedDict):
    """Hardware components."""

    name: str
    description: str | None
    part_number: str | None
    serial_number: str | None
    version: Annotated[str | None, "Hardware revision"]


class Cpu(TypedDict):
    """CPU utilisation per location, in percent."""

    location: Annotated[str | None, "Node / slot / routing engine"]
    one_minute: int | None
    five_minute: int | None
    five_second: int | None


class Vrf(TypedDict):
    """VRFs / routing instances."""

    name: str
    rd: Annotated[str | None, "Route distinguisher"]
    interfaces: list[str] | None


class MacEntry(TypedDict):
    """MAC address table entries."""

    mac_address: Mac
    vlan: Annotated[int | str, "VLAN ID, or VLAN / bridge-domain name where the device shows one"]
    interface: str
    type: Annotated[str, "dynamic, static, ... (vendor word)"]


class Lag(TypedDict):
    """Link aggregation groups."""

    name: str
    status: str
    members: Annotated[list[str], "Member interfaces"]


#: Intent name -> record type.
INTENTS: dict[str, type[Any]] = {
    "system.version": SystemVersion,
    "interfaces.brief": Interface,
    "interfaces.detail": InterfaceDetail,
    "interfaces.description": InterfaceDescription,
    "bgp.summary": BgpNeighbor,
    "ospf.neighbors": OspfNeighbor,
    "isis.adjacency": IsisAdjacency,
    "lldp.neighbors": LldpNeighbor,
    "arp": Arp,
    "ipv6.neighbors": Ipv6Neighbor,
    "routes": Route,
    "ldp.neighbors": LdpNeighbor,
    "bfd.sessions": BfdSession,
    "inventory": Inventory,
    "cpu": Cpu,
    "vrfs": Vrf,
    "mac.table": MacEntry,
    "lag": Lag,
}

#: Intents whose normalized output is a single record rather than a list of records.
SINGLE_RECORD = frozenset({"system.version"})

#: Intent name -> ordered field names (derived from :data:`INTENTS`).
SCHEMAS: dict[str, list[str]] = {name: list(get_type_hints(cls)) for name, cls in INTENTS.items()}


# --------------------------------------------------------------------------- #
# JSON Schema
# --------------------------------------------------------------------------- #

_JSON_TYPES: dict[Any, str] = {str: "string", int: "integer", float: "number", bool: "boolean", type(None): "null"}
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_BASE = "https://raw.githubusercontent.com/shadymagdy/network-cli-parser/main/schemas/"


def _type_schema(tp: Any, defs: dict[str, Any]) -> dict[str, Any]:
    origin = get_origin(tp)
    if origin is Annotated:
        inner, *meta = get_args(tp)
        out = _type_schema(inner, defs)
        doc = next((m for m in meta if isinstance(m, str)), None)
        if doc and "description" not in out:
            out = {**out, "description": doc}
        return out
    if origin in (Union, types.UnionType):
        parts = [_type_schema(a, defs) for a in get_args(tp)]
        doc = next((p.pop("description") for p in parts if "description" in p), None)
        merged: dict[str, Any]
        if all(set(p) == {"type"} and isinstance(p["type"], str) for p in parts):
            merged = {"type": [p["type"] for p in parts]}
        else:
            merged = {"anyOf": parts}
        if doc:
            merged["description"] = doc
        return merged
    if origin is list:
        (item,) = get_args(tp) or (Any,)
        return {"type": "array", "items": _type_schema(item, defs)}
    if origin is dict:
        return {"type": "object"}
    if origin is Literal:
        return {"enum": list(get_args(tp))}
    if tp in _JSON_TYPES:
        return {"type": _JSON_TYPES[tp]}
    if isinstance(tp, type) and issubclass(tp, dict) and hasattr(tp, "__annotations__"):
        if tp.__name__ not in defs:
            defs[tp.__name__] = {}  # guard against recursion
            defs[tp.__name__] = _object_schema(tp, defs)
        return {"$ref": f"#/$defs/{tp.__name__}"}
    return {}


def _object_schema(cls: type[Any], defs: dict[str, Any]) -> dict[str, Any]:
    hints = get_type_hints(cls, include_extras=True)
    return {
        "type": "object",
        "description": (cls.__doc__ or "").strip(),
        "properties": {name: _type_schema(tp, defs) for name, tp in hints.items()},
        "required": list(hints),
        "additionalProperties": False,
    }


def json_schema(intent: str) -> dict[str, Any]:
    """JSON Schema (draft 2020-12) of the normalized output for *intent*.

    Most intents normalize to an array of records; those in :data:`SINGLE_RECORD` to one object.

    ```python
    >>> json_schema("bgp.summary")["items"]["properties"]["remote_as"]
    {'type': ['integer', 'string'], 'description': 'Peer AS; asdot notation (65000.1) stays a string'}
    ```
    """
    try:
        cls = INTENTS[intent]
    except KeyError:
        raise KeyError(f"unknown intent {intent!r}; choose from {', '.join(INTENTS)}") from None
    defs: dict[str, Any] = {}
    item = _object_schema(cls, defs)
    head = {"$schema": SCHEMA_DIALECT, "$id": f"{SCHEMA_BASE}{intent}.json", "title": f"clijson {intent}"}
    if intent in SINGLE_RECORD:
        schema: dict[str, Any] = {**head, **item}
    else:
        schema = {**head, "description": item["description"], "type": "array", "items": item}
    if defs:
        schema["$defs"] = defs
    return schema


def validate(intent: str, records: Any) -> list[str]:
    """Check normalized *records* against the model for *intent*; returns a list of problems (empty = valid).

    A dependency-free structural check (types, required and unexpected keys) that mirrors :func:`json_schema`.
    """
    schema = json_schema(intent)
    errors: list[str] = []
    _check(records, schema, "$", schema.get("$defs", {}), errors)
    return errors


def _check(value: Any, schema: dict[str, Any], path: str, defs: dict[str, Any], errors: list[str]) -> None:
    if "$ref" in schema:
        schema = defs[schema["$ref"].rsplit("/", 1)[-1]]
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            sub: list[str] = []
            _check(value, option, path, defs, sub)
            if not sub:
                return
        errors.append(f"{path}: {value!r} matches none of the allowed types")
        return
    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_is_json_type(value, t) for t in allowed):
            errors.append(f"{path}: expected {' or '.join(allowed)}, got {type(value).__name__} {value!r}")
            return
    if isinstance(value, dict) and "properties" in schema:
        props = schema["properties"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing field {key!r}")
        for key, item in value.items():
            if key not in props:
                if schema.get("additionalProperties") is False:
                    errors.append(f"{path}: unexpected field {key!r}")
                continue
            _check(item, props[key], f"{path}.{key}", defs, errors)
    elif isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(item, schema["items"], f"{path}[{i}]", defs, errors)


def _is_json_type(value: Any, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = {"string": str, "boolean": bool, "null": type(None), "array": list, "object": dict}[name]
    return isinstance(value, py)


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
