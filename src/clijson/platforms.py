"""Platform catalogue and automatic platform detection.

Every supported network operating system is described by a :class:`Platform`.
Users may refer to a platform by any of its aliases (``"xr"``, ``"cisco_xr"``,
``"ios-xr"`` ...), and when no platform is given at all the library inspects
the command and the output to make an educated guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

from .exceptions import UnknownPlatformError


@dataclass(frozen=True)
class Platform:
    """Static description of a network operating system."""

    name: str
    vendor: str
    display_name: str
    verb: str
    aliases: Tuple[str, ...] = ()
    #: Names used by other ecosystems, handy for engine adapters.
    ntc_name: Optional[str] = None
    genie_name: Optional[str] = None
    netmiko_name: Optional[str] = None
    scrapli_name: Optional[str] = None
    #: Regexes that identify a CLI prompt; group ``host`` is the hostname and
    #: group ``cmd`` is whatever was typed after the prompt.
    prompts: Tuple[Pattern[str], ...] = field(default_factory=tuple)
    #: Weighted output fingerprints used for auto detection.
    fingerprints: Tuple[Tuple[Pattern[str], int], ...] = field(default_factory=tuple)
    #: Verb-level aliases, e.g. users may type ``show`` on a Huawei box.
    verb_aliases: Tuple[str, ...] = ()

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


def _rx(pattern: str, flags: int = re.M) -> Pattern[str]:
    return re.compile(pattern, flags)


IOSXR = Platform(
    name="iosxr",
    vendor="Cisco",
    display_name="Cisco IOS XR",
    verb="show",
    aliases=("iosxr", "xr", "ios-xr", "ios_xr", "cisco_xr", "cisco-xr", "cisco_iosxr", "iosxrv", "xrd", "asr9k", "ncs", "ncs5500", "crs", "8000"),
    ntc_name="cisco_xr",
    genie_name="iosxr",
    netmiko_name="cisco_xr",
    scrapli_name="cisco_iosxr",
    prompts=(
        _rx(r"^(?P<prompt>(?:RP|LC)/\d+/(?:RS?P)?\d*/?CPU\d+:(?P<host>[\w.\-]+)(?:\([\w\-]+\))?#)\s*(?P<cmd>.*)$"),
        _rx(r"^(?P<prompt>(?:sysadmin-vm|sysadmin):[\w/]+#)\s*(?P<cmd>.*)$"),
        _rx(r"^(?P<prompt>(?P<host>[\w.\-]+)#)\s?(?P<cmd>(?:sh|sho|show|admin|run)\s.*)$"),
    ),
    fingerprints=(
        (_rx(r"Cisco IOS XR Software"), 50),
        (_rx(r"IOS XR"), 25),
        (_rx(r"^(?:RP|LC)/\d+/(?:RS?P)?\d*/?CPU\d+:"), 40),
        (_rx(r"\b(?:Gi|Te|Hu|Fo|TenGigE|HundredGigE|FortyGigE|FourHundredGigE|GigabitEthernet|TwentyFiveGigE)\d+/\d+/\d+/\d+"), 15),
        (_rx(r"\bBundle-Ether\d+"), 15),
        (_rx(r"\bMgmtEth\d+/"), 20),
        (_rx(r"\b0/(?:RS?P)?\d+/CPU0\b"), 15),
        (_rx(r"^\w{3} \w{3} +\d+ \d\d:\d\d:\d\d\.\d{3} \w+\s*$"), 10),
        (_rx(r"\basr9k|\bncs5[05]\d{2}|\bNCS-?5[05]\d{2}|\bXRd\b|\bXRv", re.M | re.I), 20),
    ),
)

JUNOS = Platform(
    name="junos",
    vendor="Juniper",
    display_name="Juniper Junos OS / Junos OS Evolved",
    verb="show",
    aliases=("junos", "juniper", "juniper_junos", "junos-evo", "junos_evo", "junosevo", "evo", "vmx", "vjunos", "crpd", "vsrx", "mx", "ptx", "qfx", "srx", "ex"),
    ntc_name="juniper_junos",
    genie_name="junos",
    netmiko_name="juniper_junos",
    scrapli_name="juniper_junos",
    prompts=(
        _rx(r"^(?:\{(?:master|backup|primary|secondary|linecard)(?::\d+)?\}\s*)?(?P<prompt>(?P<user>[\w.\-]+)@(?P<host>[\w.\-]+)[>#%])\s*(?P<cmd>.*)$"),
    ),
    fingerprints=(
        (_rx(r"^JUNOS |^Junos: |Junos OS|JUNOS Software Release|junos-evo|Junos OS Evolved", re.M | re.I), 50),
        (_rx(r"^\{(?:master|backup|primary|secondary)(?::\d+)?\}\s*$"), 40),
        (_rx(r"\b(?:ge|xe|et|mge)-\d+/\d+/\d+"), 20),
        (_rx(r"\bae\d+\.\d+\b|\bfxp0\b|\blo0\.\d+\b|\birb\.\d+\b"), 15),
        (_rx(r"\binet\.0\b|\binet6\.0\b|\bmpls\.0\b|\bbgp\.l3vpn\.0\b"), 25),
        (_rx(r"^Physical interface: ", re.M), 30),
        (_rx(r"^[ \t]*Logical interface ", re.M), 10),
        (_rx(r"<rpc-reply|junos:style|xmlns:junos", re.M), 50),
        (_rx(r"Routing Engine \d|FPC \d+|PIC \d+", re.M), 10),
    ),
)

VRP = Platform(
    name="vrp",
    vendor="Huawei",
    display_name="Huawei VRP (NE/CX/AR/CE/S series)",
    verb="display",
    aliases=("vrp", "huawei", "huawei_vrp", "huawei_vrpv8", "vrpv8", "vrp8", "vrp5", "ne40e", "ne8000", "ne", "ce", "cloudengine", "huawei_ce", "huawei_ne"),
    ntc_name="huawei_vrp",
    genie_name=None,
    netmiko_name="huawei",
    scrapli_name="huawei_vrp",
    prompts=(
        _rx(r"^(?P<prompt><(?P<host>[A-Za-z0-9_][\w\-.:~]*)>)\s*(?P<cmd>.*)$"),
        _rx(r"^(?P<prompt>\[[~*]?(?!edit\b)(?P<host>[A-Za-z0-9_][^\[\]\s]*?)(?:-[\w\-/.:]+)?\])\s*(?P<cmd>.*)$"),
    ),
    fingerprints=(
        (_rx(r"Huawei Versatile Routing Platform|HUAWEI TECH|Huawei Technologies", re.M | re.I), 50),
        (_rx(r"VRP \(R\) software"), 40),
        (_rx(r"^<[\w\-.]+>", re.M), 25),
        (_rx(r"\bEth-Trunk\d+"), 25),
        (_rx(r"\bVlanif\d+"), 20),
        (_rx(r"\b(?:10|25|40|100|400)GE\d+/\d+/\d+"), 20),
        (_rx(r"\bMEth\d+/\d+/\d+|\bLoopBack\d+\b|\bNULL0\b"), 15),
        (_rx(r"\bvpn-instance\b|\bVPN-Instance\b"), 10),
        (_rx(r"Public routing table|Routing Table : _public_|Destinations : \d+\s+Routes : \d+"), 30),
        (_rx(r"^[ \t]*PHY: Physical\b|^\*down: administratively down", re.M), 40),
        (_rx(r"\(l\): loopback|\(s\): spoofing|\(E\): E-Trunk down", re.M), 30),
        (_rx(r"^[ \t]*Interface\s+PHY\s+Protocol\b", re.M), 40),
        (_rx(r"\b(?:GE|XGE|MEth)\d+/\d+/\d+\b"), 15),
        (_rx(r"\b[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}\b"), 15),
    ),
    verb_aliases=("show",),
)


PLATFORMS: Dict[str, Platform] = {p.name: p for p in (IOSXR, JUNOS, VRP)}

_ALIASES: Dict[str, str] = {}
for _p in PLATFORMS.values():
    _ALIASES[_p.name] = _p.name
    for _a in _p.aliases:
        _ALIASES[_a.lower()] = _p.name


def get_platform(name: "str | Platform") -> Platform:
    """Return the :class:`Platform` for *name* (any alias, case insensitive)."""
    if isinstance(name, Platform):
        return name
    key = str(name).strip().lower().replace(" ", "_")
    try:
        return PLATFORMS[_ALIASES[key]]
    except KeyError:
        raise UnknownPlatformError(name, sorted(_ALIASES)) from None


def list_platforms() -> List[Platform]:
    return list(PLATFORMS.values())


@dataclass
class Detection:
    """Outcome of :func:`detect_platform`."""

    platform: Optional[Platform]
    confidence: float
    scores: Dict[str, int]
    reasons: List[str]

    def __bool__(self) -> bool:
        return self.platform is not None


def match_prompt(line: str) -> Optional[Tuple[Platform, "re.Match[str]"]]:
    """Return ``(platform, match)`` if *line* looks like a CLI prompt."""
    stripped = line.rstrip()
    for platform in PLATFORMS.values():
        for rx in platform.prompts:
            m = rx.match(stripped)
            if m:
                return platform, m
    return None


def detect_platform(output: str = "", command: Optional[str] = None) -> Detection:
    """Guess the platform that produced *output* (and/or accepts *command*).

    Scoring combines prompt recognition, the command verb (``display`` is a
    Huawei hallmark) and weighted fingerprints such as interface naming
    conventions. The winner must beat the runner-up by a margin, otherwise
    ``platform`` is ``None`` and the caller should ask the user.
    """
    scores: Dict[str, int] = {p: 0 for p in PLATFORMS}
    reasons: List[str] = []

    if command:
        first = command.strip().split(" ", 1)[0].lower()
        if len(first) >= 3 and "display".startswith(first):
            scores["vrp"] += 60
            reasons.append("command verb 'display' is Huawei VRP syntax")
        if "| display" in command or "| no-more" in command:
            scores["junos"] += 40
            reasons.append("pipe modifier is Junos syntax")

    head = output[:20000]
    for line in head.splitlines()[:5] + head.splitlines()[-3:]:
        hit = match_prompt(line)
        if hit:
            scores[hit[0].name] += 60
            reasons.append(f"prompt {line.strip()[:40]!r} matches {hit[0].display_name}")
            break

    for platform in PLATFORMS.values():
        for rx, weight in platform.fingerprints:
            if weight and rx.search(head):
                scores[platform.name] += weight
                reasons.append(f"{platform.name}: /{rx.pattern[:50]}/ (+{weight})")

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best, best_score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    if best_score < 15 or best_score - runner_up < 10:
        return Detection(None, 0.0, scores, reasons)
    confidence = min(1.0, (best_score - runner_up) / 100.0 + 0.3)
    return Detection(PLATFORMS[best], round(confidence, 2), scores, reasons)
