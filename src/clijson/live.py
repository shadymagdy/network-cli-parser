"""Collect and parse output from live devices.

Uses `Scrapli <https://github.com/carlmontanari/scrapli>`_ if installed,
otherwise `Netmiko <https://github.com/ktbyers/netmiko>`_::

    pip install "clijson[netmiko]"     # or "clijson[scrapli]"

    from clijson.live import collect
    for result in collect("10.0.0.1", "junos", ["show version", "show bgp summary"],
                          username="lab", password="lab123", normalize=True):
        print(result.command, result.normalized)

Tip: containerlab (https://containerlab.dev) runs Cisco XRd, Juniper
cRPD/vJunos and Huawei VRP images locally - a perfect sandbox for this.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Union

from .api import parse
from .exceptions import DeviceError
from .platforms import get_platform
from .result import ParseResult


def _as_list(commands: Union[str, Iterable[str]]) -> List[str]:
    return [commands] if isinstance(commands, str) else list(commands)


def collect(
    host: str,
    platform: str,
    commands: Union[str, Iterable[str]],
    username: Optional[str] = None,
    password: Optional[str] = None,
    port: int = 22,
    normalize: bool = False,
    **connection_kwargs: Any,
) -> List[ParseResult]:
    """SSH to *host*, run *commands* and return one :class:`ParseResult` each."""
    plat = get_platform(platform)
    cmds = _as_list(commands)
    outputs = _run_scrapli(plat, host, cmds, username, password, port, connection_kwargs)
    if outputs is None:
        outputs = _run_netmiko(plat, host, cmds, username, password, port, connection_kwargs)
    if outputs is None:
        raise DeviceError(
            "live collection needs scrapli or netmiko: pip install 'clijson[scrapli]' or 'clijson[netmiko]'"
        )
    results = []
    for cmd, out in zip(cmds, outputs):
        res = parse(out, cmd, plat, normalize=normalize)
        res.metadata.setdefault("hostname", host)
        results.append(res)
    return results


def _run_scrapli(
    plat, host, cmds, username, password, port, extra
) -> Optional[List[str]]:  # pragma: no cover - needs a device
    try:
        from scrapli import Scrapli
    except ImportError:
        return None
    params = {
        "host": host,
        "auth_username": username,
        "auth_password": password,
        "auth_strict_key": False,
        "port": port,
        "platform": plat.scrapli_name,
        **extra,
    }
    try:
        with Scrapli(**params) as conn:
            return [r.result for r in conn.send_commands(cmds)]
    except Exception as exc:
        raise DeviceError(f"{host}: {exc}") from exc


def _run_netmiko(
    plat, host, cmds, username, password, port, extra
) -> Optional[List[str]]:  # pragma: no cover - needs a device
    try:
        from netmiko import ConnectHandler
    except ImportError:
        return None
    params = {
        "device_type": plat.netmiko_name,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        **extra,
    }
    try:
        with ConnectHandler(**params) as conn:
            return [conn.send_command(c, read_timeout=120) for c in cmds]
    except Exception as exc:
        raise DeviceError(f"{host}: {exc}") from exc
