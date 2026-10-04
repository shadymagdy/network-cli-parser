"""``ping`` on every platform: IOS XR (``Success rate is ...``), Junos (BSD style) and Huawei VRP."""

from __future__ import annotations

import re
from typing import Any

from ..models import record
from ..registry import Parser, register

_IP_OR_NAME = r"[\w.:\-]+"


def parse_ping(text: str) -> dict[str, Any]:
    """Statistics of a ping, whichever platform printed it."""
    out: dict[str, Any] = {"target": None, "sent": None, "received": None, "loss_percent": None}
    m = (
        re.search(rf"^[ \t]*PING[ \t]+(?P<t>{_IP_OR_NAME})", text, re.M)
        or re.search(rf"ICMP Echos to (?P<t>{_IP_OR_NAME}),", text)
        or re.search(rf"^---[ \t]*(?P<t>{_IP_OR_NAME}) ping statistics", text, re.M)
    )
    if m:
        out["target"] = m["t"].rstrip(":")  # VRP: "PING 192.0.2.1: 56  data bytes"
    m = re.search(r"(\d+) packets? transmitted, (\d+) (?:packets? )?received", text)  # Junos
    if m:
        out["sent"], out["received"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text)  # IOS XR
    if m:
        out["received"], out["sent"] = int(m.group(2)), int(m.group(3))
    m = re.search(r"(\d+) packet\(s\) transmitted", text)  # VRP
    if m:
        out["sent"] = int(m.group(1))
    m = re.search(r"(\d+) packet\(s\) received", text)
    if m:
        out["received"] = int(m.group(1))
    m = re.search(r"([\d.]+)% packet loss", text)
    if m:
        out["loss_percent"] = float(m.group(1))
    elif out["sent"]:
        out["loss_percent"] = round(100.0 * (out["sent"] - (out["received"] or 0)) / out["sent"], 2)
    m = re.search(r"round-trip (?:\(ms\)\s+)?min/avg/max(?:/\w+)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?", text)
    if m:
        out["rtt_min"], out["rtt_avg"], out["rtt_max"] = (float(v) for v in m.groups()[:3])
        if m.group(4):
            out["rtt_stddev"] = float(m.group(4))
    replies = [line.strip() for line in text.splitlines() if line.strip() and set(line.strip()) <= set("!.UQM?&")]
    if replies:
        out["replies"] = "".join(replies)
    return out


class _Ping(Parser):
    def parse(self, text: str) -> dict[str, Any]:
        return parse_ping(text)

    def normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        received = data.get("received")
        return record(
            "ping",
            target=data.get("target"),
            sent=data.get("sent"),
            received=received,
            loss_percent=data.get("loss_percent"),
            success=None if received is None else received > 0,
            rtt_min=data.get("rtt_min"),
            rtt_avg=data.get("rtt_avg"),
            rtt_max=data.get("rtt_max"),
        )


@register("iosxr", "ping [<args...>]", intent="ping")
class IosxrPing(_Ping):
    """Ping statistics: success rate, sent / received and min/avg/max round-trip time."""


@register("junos", "ping [<args...>]", intent="ping")
class JunosPing(_Ping):
    """Ping statistics: packets transmitted / received, loss and min/avg/max/stddev round-trip time."""


@register("vrp", "ping [<args...>]", intent="ping")
class VrpPing(_Ping):
    """Ping statistics: packets transmitted / received, loss and min/avg/max round-trip time."""


for _cls in (IosxrPing, JunosPing, VrpPing):
    _cls.name = f"{_cls.platform}.ping"
