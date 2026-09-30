"""Optional adapters to third-party parser ecosystems.

``clijson`` has zero required dependencies, but if you have
`ntc-templates <https://github.com/networktocode/ntc-templates>`_ or Cisco
`Genie <https://github.com/CiscoTestAutomation/genieparser>`_ installed, their
hundreds of community templates become extra fallback engines automatically
(``pip install "clijson[ntc]"`` / ``"clijson[genie]"``). The native parser is
always tried first and the heuristic generic engine last.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from ..platforms import Platform


class EngineUnavailable(Exception):
    pass


@functools.cache
def ntc_available() -> bool:
    try:
        import ntc_templates.parse  # noqa: F401
    except Exception:
        return False
    return True


@functools.cache
def genie_available() -> bool:
    try:
        import genie.libs.parser  # noqa: F401
        from genie.conf.base import Device  # noqa: F401
    except Exception:
        return False
    return True


def parse_ntc(platform: Platform, command: str, text: str) -> list[dict[str, Any]] | None:
    """Parse with ntc-templates (TextFSM). Returns ``None`` if no template matches."""
    if not platform.ntc_name or not ntc_available():
        raise EngineUnavailable("ntc-templates")
    from ntc_templates.parse import parse_output

    try:
        rows = parse_output(platform=platform.ntc_name, command=command, data=text)
    except Exception:
        return None
    return rows or None


def parse_genie(platform: Platform, command: str, text: str) -> dict[str, Any] | None:
    """Parse with Cisco Genie. Returns ``None`` if Genie has no parser for the command."""
    if not platform.genie_name or not genie_available():
        raise EngineUnavailable("genie")
    from genie.conf.base import Device

    device = Device("clijson", os=platform.genie_name)
    device.custom.setdefault("abstraction", {})["order"] = ["os"]
    try:
        return device.parse(command, output=text) or None
    except Exception:
        return None


ENGINES: dict[str, Callable[[Platform, str, str], Any]] = {
    "ntc": parse_ntc,
    "genie": parse_genie,
}


def available_engines() -> dict[str, bool]:
    return {"ntc": ntc_available(), "genie": genie_available()}
