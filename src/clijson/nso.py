"""Cisco NSO integration: run show commands through ``live-status exec`` and parse them, from services and actions.

Inside an NSO Python package (an action callback, a service ``cb_create``, a nano-service step)::

    import clijson.nso

    with ncs.maapi.single_read_trans("admin", "python") as t:
        root = ncs.maagic.get_root(t)
        device = root.devices.device["pe1"]
        result = clijson.nso.show(device, "show l2vpn bridge-domain detail", normalize=True)
        report = clijson.checks.pseudowire_redundancy(result.normalized)

``show()`` finds the device's exec action (``cisco_ios_xr_stats__exec``, ``vrp_stats__exec``, ... depending on the
NED), runs the command, and parses the ``result`` text with the platform taken from the device's NED. This module
does not import ``ncs`` itself. It only uses the maagic device object you pass in, so it can be imported and
tested anywhere.

Output that was already collected elsewhere, for example the RESTCONF response of
``/devices/device=pe1/live-status/tailf-ned-cisco-ios-xr-stats:exec/any`` or text pasted from ``ncs_cli``, can be
given straight to :func:`clijson.parse`, which removes the NSO wrapping.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from typing import Any

from .api import parse
from .exceptions import CliJsonError
from .platforms import get_platform
from .result import ParseResult

__all__ = ["NsoError", "exec_any", "platform_of", "show", "show_many"]

#: NED-id prefixes (``devices device X device-type cli ned-id``) -> clijson platform.
NED_PLATFORMS: dict[str, str] = {
    "cisco-iosxr": "iosxr",
    "cisco-ios-xr": "iosxr",
    "huawei-vrp": "vrp",
    "huawei-ce": "vrp",
    "juniper-junos": "junos",
    "junos": "junos",
}

#: Exec action container names, as maagic attribute names, of the common CLI NEDs; others are discovered.
EXEC_ACTIONS: tuple[str, ...] = (
    "cisco_ios_xr_stats__exec",
    "vrp_stats__exec",
    "huawei_vrp_stats__exec",
    "junos_stats__exec",
    "exec",
)


class NsoError(CliJsonError):
    """The device has no usable ``live-status exec`` action, or the action failed."""


def _get(node: Any, *path: str) -> Any:
    for name in path:
        if node is None:
            return None
        try:
            node = getattr(node, name)
        except Exception:  # maagic raises on missing / non-existent nodes
            return None
    return node


def platform_of(device: Any) -> str | None:
    """clijson platform of an NSO device, from ``platform name`` or the NED-id; ``None`` when unknown."""
    name = _get(device, "platform", "name")
    if name:
        try:
            return get_platform(str(name)).name
        except CliJsonError:
            pass
    for kind in ("cli", "netconf", "generic"):
        ned = _get(device, "device_type", kind, "ned_id")
        if ned:
            ned_id = str(ned).split(":")[-1].lower()
            for prefix, plat in NED_PLATFORMS.items():
                if ned_id.startswith(prefix):
                    return plat
    return None


def _exec_action(device: Any) -> Any:
    live = _get(device, "live_status")
    if live is None:
        raise NsoError(f"device {_name(device)!r} has no live-status (is it a CLI NED device?)")
    candidates = list(EXEC_ACTIONS)
    with contextlib.suppress(Exception):  # dir() on maagic nodes lists the child nodes
        candidates += [n for n in dir(live) if n.endswith("__exec") and n not in candidates]
    for name in candidates:
        any_action = _get(live, name, "any")
        if any_action is not None and callable(any_action):
            return any_action
    raise NsoError(
        f"no 'live-status exec any' action on device {_name(device)!r}; this needs a CLI NED "
        "(NETCONF-managed devices expose RPCs instead)"
    )


def _name(device: Any) -> str:
    return str(_get(device, "name") or "?")


def exec_any(device: Any, command: str) -> str:
    """Run *command* with the device's ``live-status exec any`` action and return the raw ``result`` text."""
    action = _exec_action(device)
    try:
        inp = action.get_input()
        inp.args = [command]
        out = action(inp)
    except Exception as exc:
        raise NsoError(f"{_name(device)}: live-status exec failed for {command!r}: {exc}") from exc
    return str(getattr(out, "result", "") or "")


def show(device: Any, command: str, *, platform: str | None = None, **parse_kwargs: Any) -> ParseResult:
    """Run *command* on an NSO device and parse it. Keyword arguments go to :func:`clijson.parse`.

    The platform comes from the device's NED unless *platform* is given. ``result.metadata`` gets the device
    name.
    """
    text = exec_any(device, command)
    res = parse(text, command, platform or platform_of(device), **parse_kwargs)
    res.metadata.setdefault("device", _name(device))
    res.metadata.setdefault("source", "nso-live-status")
    return res


def show_many(device: Any, commands: Iterable[str], **parse_kwargs: Any) -> dict[str, ParseResult]:
    """Run several commands on one device; returns ``{command: ParseResult}`` in order."""
    return {cmd: show(device, cmd, **parse_kwargs) for cmd in commands}
