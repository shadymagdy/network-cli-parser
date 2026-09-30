"""Junos configuration commands."""

from __future__ import annotations

from typing import Any

from ...engines.config import parse_config
from ...registry import Parser, register


@register("junos", "show configuration [<section...>]", "show running-config", intent="config")
class ShowConfiguration(Parser):
    """Configuration (curly-brace or ``| display set``) as a nested tree."""

    def parse(self, text: str) -> dict[str, Any]:
        return parse_config(text, "junos")
