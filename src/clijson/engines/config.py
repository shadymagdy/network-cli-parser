"""Configuration parsers: turn running configurations into nested JSON.

* Cisco IOS XR and Huawei VRP use indentation to express hierarchy
  (``!`` / ``#`` separate sections).
* Junos uses curly braces (``show configuration``) or flat ``set`` commands
  (``show configuration | display set``).

The output is a tree where each configuration statement becomes a key. The
first word is the key and the remainder the value, so
``interface GigabitEthernet0/0/0/0`` becomes
``{"interface": {"GigabitEthernet0/0/0/0": {...}}}``. Negations (``no x``,
``undo x``) are kept under a ``no``/``undo`` key and ``shutdown`` style
single-word flags become ``true``.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Tuple

from ..textutils import indent_of

_XR_NOISE = re.compile(
    r"^(?:Building configuration\.\.\.|!! IOS XR Configuration.*|!! Last configuration change.*|"
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \w{3} +\d+ \d\d:\d\d:\d\d.*|end)$"
)
_VRP_NOISE = re.compile(r"^(?:!Software Version.*|!Last configuration was .*|return|!.*)$")


def _put(node: Dict[str, Any], key: str, value: Any) -> None:
    if key not in node:
        node[key] = value
        return
    cur = node[key]
    if isinstance(cur, dict) and isinstance(value, dict):
        for k, v in value.items():
            _put(cur, k, v)
    elif cur == value:
        return
    elif isinstance(cur, list):
        if value not in cur:
            cur.append(value)
    elif isinstance(cur, dict):
        # a flag/leaf colliding with a container: keep both
        cur.setdefault("_value", value)
    elif isinstance(value, dict):
        value.setdefault("_value", cur)
        node[key] = value
    else:
        node[key] = [cur, value]


def _statement(words: List[str], children: Dict[str, Any]) -> Tuple[str, Any]:
    if not words:
        return "", children
    key = words[0]
    rest = words[1:]
    if not rest:
        return key, children if children else True
    if key in ("no", "undo") and len(rest) >= 1:
        sub_key, sub_val = _statement(rest, children)
        return key, {sub_key: sub_val}
    if children:
        # "interface Gi0/0/0/0" + body -> {"interface": {"Gi0/0/0/0": body}}
        return key, {" ".join(rest): children}
    if len(rest) == 1:
        return key, rest[0]
    return key, " ".join(rest)


def parse_indented(text: str, comment: str = "!", noise: "re.Pattern[str] | None" = None) -> Dict[str, Any]:
    """Parse an indentation based configuration (IOS XR, VRP, IOS style)."""
    raw_lines: List[str] = []
    for ln in text.splitlines():
        s = ln.rstrip()
        st = s.strip()
        if not st or st in (comment, "#", "!", "exit", "quit") or st.startswith(("!", "#")) and len(st.strip("!# ")) == 0:
            continue
        if noise and noise.match(st):
            continue
        if st.startswith("!") or (comment == "#" and st.startswith("#")):
            continue
        raw_lines.append(s)
    root: Dict[str, Any] = {}
    _build(raw_lines, [indent_of(ln) for ln in raw_lines], 0, len(raw_lines), root)
    return root


MAX_DEPTH = 64


def _build(lines: List[str], indents: List[int], start: int, end: int, node: Dict[str, Any], depth: int = 0) -> None:
    i = start
    while i < end:
        ind = indents[i]
        j = i + 1
        while j < end and indents[j] > ind:
            j += 1
        children: Dict[str, Any] = {}
        if j > i + 1 and depth < MAX_DEPTH:
            _build(lines, indents, i + 1, j, children, depth + 1)
        elif j > i + 1:
            j = i + 1  # too deep: treat the remaining lines as siblings
        words = _split_words(lines[i].strip())
        if lines[i].strip().endswith("-exit") or lines[i].strip() in ("exit", "quit", "end-policy", "end-set", "end-group"):
            i = j
            continue
        key, value = _statement(words, children)
        if key:
            _put(node, key, value)
        i = j


def _split_words(s: str) -> List[str]:
    if '"' in s:
        try:
            return shlex.split(s)
        except ValueError:
            pass
    return s.split()


# --------------------------------------------------------------------------- #
# Junos
# --------------------------------------------------------------------------- #

_JUNOS_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|##[^\n]*|[{};]|\[|\]|[^\s{};\[\]"]+', re.S)


def parse_junos_curly(text: str) -> Dict[str, Any]:
    """Parse Junos curly-brace configuration."""
    body = text
    tokens = [t for t in _JUNOS_TOKEN.findall(body) if not t.startswith(("/*", "##"))]
    pos = 0

    def block(depth: int = 0) -> Dict[str, Any]:
        nonlocal pos
        if depth > MAX_DEPTH:
            raise ValueError("configuration is nested too deeply")
        node: Dict[str, Any] = {}
        words: List[str] = []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == "{":
                child = block(depth + 1)
                _put_path(node, words, child)
                words = []
            elif t == "}":
                return node
            elif t == ";":
                if words:
                    _put_path(node, words, None)
                words = []
            elif t == "[":
                vals = []
                while pos < len(tokens) and tokens[pos] != "]":
                    vals.append(_unquote(tokens[pos]))
                    pos += 1
                pos += 1
                words.append(vals)  # type: ignore[arg-type]
            else:
                words.append(_unquote(t))
        return node

    return block()


def _unquote(t: str) -> str:
    if len(t) >= 2 and t[0] == t[-1] == '"':
        return t[1:-1]
    return t


def _put_path(node: Dict[str, Any], words: List[Any], child: Any) -> None:
    """``interfaces ge-0/0/0 { ... }`` -> ``{"interfaces": {"ge-0/0/0": {...}}}`` (via nested blocks)."""
    words = [w for w in words if w not in ("inactive:", "protect:")]
    if not words:
        return
    key = words[0]
    rest = words[1:]
    if child is None:
        # leaf statement
        if not rest:
            _put(node, key, True)
        elif len(rest) == 1:
            _put(node, key, rest[0] if isinstance(rest[0], str) else list(rest[0]))
        else:
            _put(node, key, " ".join(r if isinstance(r, str) else " ".join(r) for r in rest))
        return
    if not rest:
        _put(node, key, child)
    else:
        _put(node, key, {" ".join(r if isinstance(r, str) else " ".join(r) for r in rest): child})


def parse_junos_set(text: str) -> Dict[str, Any]:
    """Parse ``show configuration | display set`` into the same tree shape."""
    root: Dict[str, Any] = {}
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith(("set ", "deactivate ")):
            continue
        words = _split_words(s)
        if words[0] == "deactivate":
            continue
        words = words[1:]
        node = root
        for w in words[:-2]:
            nxt = node.get(w)
            if not isinstance(nxt, dict):
                nxt = {} if nxt in (None, True) else {"_value": nxt}
                node[w] = nxt
            node = nxt
        if len(words) >= 2:
            k, v = words[-2], words[-1]
            existing = node.get(k)
            if isinstance(existing, dict):
                existing.setdefault(v, True)
            else:
                _put(node, k, v)
        elif words:
            node.setdefault(words[0], True)
    return root


def parse_config(text: str, platform: str) -> Dict[str, Any]:
    """Dispatch to the right configuration parser for *platform*."""
    stripped = "\n".join(ln for ln in text.splitlines() if ln.strip())
    if platform == "junos":
        if re.search(r"^[ \t]*set ", stripped, re.M) and "{" not in stripped:
            return parse_junos_set(stripped)
        return parse_junos_curly(stripped)
    if platform == "vrp":
        return parse_indented(stripped, comment="#", noise=_VRP_NOISE)
    return parse_indented(stripped, comment="!", noise=_XR_NOISE)
