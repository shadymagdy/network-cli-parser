"""Structural diff of two parses: the pre/post maintenance-window check.

    >>> before = clijson.parse(pre_text, "show bgp summary", "iosxr", normalize=True)
    >>> after = clijson.parse(post_text, "show bgp summary", "iosxr", normalize=True)
    >>> for change in clijson.diff(before, after):
    ...     print(change)
    Change(path='[neighbor=10.0.0.2].state', kind='changed', before='Established', after='Idle')

Lists of records are matched by their natural key (``neighbor``, ``name``, ``prefix``, ...), not by position,
so reordering doesn't count as a change. Counters, timers and uptimes change on every capture, so they are
ignored by default. Pass ``ignore=None`` to compare everything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Pattern, Sequence, Union

from .result import ParseResult

IDENTITY_KEYS: Sequence[str] = (
    "neighbor",
    "neighbor_id",
    "peer",
    "system_id",
    "system",
    "prefix",
    "network",
    "interface",
    "name",
    "local_interface",
    "ip_address",
    "mac_address",
    "address",
    "vrid",
    "group",
    "tunnel",
    "lsp_id",
    "node",
    "slot",
    "filesystem",
    "prefix_or_id",
    "local_label",
    "destination",
    "remote",
    "source",
    "part",
    "item",
    "vlan",
    "index",
    "id",
)

#: Keys that change on every capture (counters, timers, ages, rates).
VOLATILE = re.compile(
    r"(^|_)(uptime|age|up_down|updown|elapsed|since|when|expire[sd]?|expiration|dead_time|hold_time|holdtime|time_remaining|"
    r"last_(input|output|clearing|read|write|flapped|update|link_flapped|change)|keepalives?_(sent|received)|"
    r"messages?_(sent|received)|input_messages|output_messages|notifications_|table_version|neighbor_version|"
    r"(input|output)_(packets|bytes|rate_bps|rate_pps|bps|pps|queue|broadcast|multicast|drops)|bytes|packets|"
    r"(in|out)(q|_q)|delay|offset|jitter|dispersion|reach|poll|load_average|cpu_|utilization|five_|one_minute|"
    r"fifteen_|current_time|timestamp|seconds|stat_time|free|used|counters|traffic_statistics|mac_statistics|"
    r"rates?|matches|hit_count|temperature|voltage|power_|_dbm|_mw|_ma)($|_)"
)


@dataclass
class Change:
    path: str
    kind: str  # added | removed | changed
    before: Any = None
    after: Any = None

    def __str__(self) -> str:
        if self.kind == "added":
            return f"+ {self.path}: {self.after!r}"
        if self.kind == "removed":
            return f"- {self.path}: {self.before!r}"
        return f"~ {self.path}: {self.before!r} -> {self.after!r}"


def _data(obj: Any, prefer_normalized: bool) -> Any:
    if isinstance(obj, ParseResult):
        return obj.normalized if prefer_normalized and obj.normalized is not None else obj.data
    return obj


def _unique(sides: Sequence[List[dict]], fn: Any) -> bool:
    for items in sides:
        values = [fn(i) for i in items]
        if any(v is None or (isinstance(v, tuple) and v[0] is None) for v in values) or len(
            set(map(str, values))
        ) != len(values):
            return False
    return True


def _identity(a: List[Any], b: List[Any]) -> Optional[str]:
    """Natural key that is present and unique on *each* side."""
    items = a + b
    if not items or not all(isinstance(i, dict) for i in items):
        return None
    for key in IDENTITY_KEYS:
        if _unique((a, b), lambda i, k=key: i.get(k)):
            return key
    # composite keys, e.g. neighbor + vrf / address family / level
    for extra in ("vrf", "address_family", "instance", "table", "level", "family"):
        for key in IDENTITY_KEYS:
            if _unique((a, b), lambda i, k=key, e=extra: (i.get(k), i.get(e))):
                return f"{key}+{extra}"
    return None


def _key_of(item: dict, ident: str) -> str:
    if "+" in ident:
        a, b = ident.split("+")
        return f"{a}={item.get(a)},{b}={item.get(b)}"
    return f"{ident}={item.get(ident)}"


def diff(
    before: Union[ParseResult, Any],
    after: Union[ParseResult, Any],
    ignore: Union[str, Pattern[str], None] = VOLATILE,
    normalized: bool = True,
) -> List[Change]:
    """Compare two parse results (or plain data) and list what changed."""
    rx = re.compile(ignore) if isinstance(ignore, str) else ignore
    changes: List[Change] = []
    _walk(_data(before, normalized), _data(after, normalized), "", changes, rx)
    return changes


def _walk(a: Any, b: Any, path: str, out: List[Change], rx: Optional[Pattern[str]]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if rx is not None and rx.search(str(k)):
                continue
            p = f"{path}.{k}" if path else str(k)
            if k not in b:
                out.append(Change(p, "removed", before=a[k]))
            elif k not in a:
                out.append(Change(p, "added", after=b[k]))
            else:
                _walk(a[k], b[k], p, out, rx)
        return
    if isinstance(a, list) and isinstance(b, list):
        ident = _identity(a, b) if (a or b) else None
        if ident:
            ka = {_key_of(i, ident): i for i in a}
            kb = {_key_of(i, ident): i for i in b}
            for k in list(ka) + [k for k in kb if k not in ka]:
                p = f"{path}[{k}]"
                if k not in kb:
                    out.append(Change(p, "removed", before=ka[k]))
                elif k not in ka:
                    out.append(Change(p, "added", after=kb[k]))
                else:
                    _walk(ka[k], kb[k], p, out, rx)
            return
        if all(not isinstance(x, (dict, list)) for x in a + b):
            if sorted(map(str, a)) != sorted(map(str, b)):
                out.append(Change(path, "changed", before=a, after=b))
            return
        for i in range(max(len(a), len(b))):
            p = f"{path}[{i}]"
            if i >= len(b):
                out.append(Change(p, "removed", before=a[i]))
            elif i >= len(a):
                out.append(Change(p, "added", after=b[i]))
            else:
                _walk(a[i], b[i], p, out, rx)
        return
    if a != b:
        out.append(Change(path, "changed", before=a, after=b))
