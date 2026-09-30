"""Huawei VRP configuration commands."""

from __future__ import annotations

from typing import Any, Dict

from ...engines.config import parse_config
from ...registry import Parser, register


@register(
    "vrp",
    "display current-configuration [<section...>]",
    "display saved-configuration [<section...>]",
    "display this",
    "display configuration [<section...>]",
    intent="config",
)
class DisplayCurrentConfiguration(Parser):
    """Configuration as a nested tree (``interface -> GigabitEthernet0/0/1 -> ...``)."""

    def parse(self, text: str) -> Dict[str, Any]:
        return parse_config(text, "vrp")
