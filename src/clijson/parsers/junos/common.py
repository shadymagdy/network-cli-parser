"""Helpers shared by Junos parsers."""

from __future__ import annotations

import re

_RE_HDR = re.compile(r"^(?P<name>(?:fpc|node|re|member|lcc|sfc|psd|rsd)\d+|localre|re0|re1|primary|backup):\s*$")


def split_re_sections(text: str) -> list[tuple[str | None, str]]:
    """Split multi-RE / virtual-chassis / cluster output.

    Junos prefixes per-member output with ``fpc0:`` / ``node1:`` / ``re0:``
    followed by a dashed line. Returns ``[(member, body), ...]``; a single
    ``(None, text)`` item when there are no member headers.
    """
    sections: list[tuple[str | None, list[str]]] = []
    cur: tuple[str | None, list[str]] | None = None
    for ln in text.splitlines():
        m = _RE_HDR.match(ln.strip())
        if m:
            cur = (m.group("name"), [])
            sections.append(cur)
            continue
        if re.match(r"^-{10,}\s*$", ln.strip()) and cur is not None and not cur[1]:
            continue
        if re.match(r"^\{(?:master|backup|primary|secondary|linecard)(?::\d+)?\}\s*$", ln.strip()):
            continue
        if cur is None:
            cur = (None, [])
            sections.append(cur)
        cur[1].append(ln)
    out = [(name, "\n".join(body).strip("\n")) for name, body in sections]
    out = [(n, b) for n, b in out if b.strip() or n]
    return out or [(None, text)]
