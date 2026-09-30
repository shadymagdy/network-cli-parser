"""IOS XR configuration commands."""

from __future__ import annotations

from typing import Any, Dict, List

from ...engines.config import parse_config
from ...registry import Parser, register
from ...textutils import match_lines


@register("iosxr", "show running-config [<section...>]", "show configuration [(running|merge|running-config)] [<section...>]", intent="config")
class ShowRunningConfig(Parser):
    """Running configuration as a nested tree (``interface -> Gi0/0/0/0 -> ...``)."""

    def parse(self, text: str) -> Dict[str, Any]:
        return parse_config(text, "iosxr")


@register("iosxr", "show configuration commit list [<count>] [detail]")
class ShowConfigurationCommitList(Parser):
    """Commit history: id, user, line, client and timestamp."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(
            r"^\s*(?P<no>\d+)\s+(?P<id>\d{10})\s+(?P<user>\S+)\s+(?P<line>\S+)\s+(?P<client>\S+(?: \S+)?)\s+(?P<ts>\w{3} \w{3}\s+\d+ \d\d:\d\d:\d\d \d{4})\s*$", text):
            out.append({"number": int(m["no"]), "commit_id": m["id"], "user": m["user"], "line": m["line"], "client": m["client"], "timestamp": m["ts"]})
        return out
