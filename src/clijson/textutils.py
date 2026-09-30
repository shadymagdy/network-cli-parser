"""Text helpers shared by all parsers.

These are deliberately small, well tested building blocks: cleaning captured
output, converting values, slicing column-aligned tables and splitting output
into blocks. Parser authors should reach for these before writing regexes.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from re import Pattern
from typing import Any

# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]")
_MORE = re.compile(
    r"[ \t]*(?:-{2,}[ \t]*\(?more(?:[ \t]+\d+%)?\)?[ \t]*-{2,}|<--- More --->|\(END\))[ \t]*",
    re.I,
)
_BACKSPACE_RUN = re.compile(r"[^\n]\x08")
XR_TIMESTAMP = re.compile(
    r"^\s*(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+"
    r"(?:\d{4}\s+)?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s*(?:[A-Z]{2,5}|[+-]\d{2}:?\d{2})?\s*$"
)
_INFO = re.compile(r"^\s*Info: |^\s*Warning: The current configuration will be written", re.I)


def clean_output(text: str) -> str:
    """Normalise newlines, drop ANSI escapes, pager prompts and backspaces."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if "\x1b" in text:
        text = _ANSI.sub("", text)
    while "\x08" in text:
        new = _BACKSPACE_RUN.sub("", text)
        if new == text:
            text = text.replace("\x08", "")
            break
        text = new
    if "ore" in text or "(END)" in text:
        text = _MORE.sub("\n", text)
    text = text.replace("\t", "    ")
    # Output pasted from logs/docs is often uniformly indented; remove that.
    text = dedent("\n".join(line.rstrip() for line in text.split("\n")))
    return text.strip("\n")


def dedent(text: str) -> str:
    """Fast ``textwrap.dedent`` for right-stripped lines (spaces only)."""
    lines = text.split("\n")
    indent = None
    for ln in lines:
        if ln:
            n = len(ln) - len(ln.lstrip(" "))
            if indent is None or n < indent:
                indent = n
                if indent == 0:
                    return text
    if not indent:
        return text
    return "\n".join(ln[indent:] for ln in lines)


def blocks(text: str, start: str | Pattern[str] | None = None) -> list[str]:
    """Split *text* into blocks.

    Without *start*, blocks are separated by blank lines. With *start* (a regex),
    a new block begins at each line matching it; text before the first match is
    discarded.
    """
    if start is None:
        return [b.strip("\n") for b in re.split(r"\n\s*\n", text) if b.strip()]
    rx = re.compile(start) if isinstance(start, str) else start
    out: list[list[str]] = []
    for ln in text.splitlines():
        if rx.search(ln):
            out.append([ln])
        elif out:
            out[-1].append(ln)
    return ["\n".join(b).rstrip() for b in out]


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

_INT = re.compile(r"^[+-]?\d+$")
_FLOAT = re.compile(r"^[+-]?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?$")
_COMMA_INT = re.compile(r"^\d{1,3}(?:,\d{3})+$")


def to_num(value: Any) -> Any:
    """``"42"`` -> 42, ``"1.5"`` -> 1.5, ``"1,024"`` -> 1024, anything else unchanged."""
    if not isinstance(value, str):
        return value
    v = value.strip()
    if _INT.match(v):
        # Keep zero-padded identifiers (e.g. "0010") as strings.
        if len(v) > 1 and v.lstrip("+-").startswith("0"):
            return v
        return int(v)
    if _COMMA_INT.match(v):
        return int(v.replace(",", ""))
    if _FLOAT.match(v):
        return float(v)
    return v


def none_if(value: Any, *empty: str) -> Any:
    """Return ``None`` for placeholder values like ``--``, ``N/A`` or ``unassigned``."""
    placeholders = {e.lower() for e in empty} or {
        "",
        "-",
        "--",
        "---",
        "n/a",
        "na",
        "none",
        "unassigned",
        "unknown",
        "*",
    }
    if isinstance(value, str) and value.strip().lower() in placeholders:
        return None
    return value


_KEY_CLEAN = re.compile(r"[^0-9a-zA-Z]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z][a-z])")


def snake(key: str) -> str:
    """``"Up Time (secs)"`` -> ``up_time_secs``; ``"IP-Address"`` -> ``ip_address``."""
    k = key.strip()
    k = k.replace("#", " num ").replace("%", " pct ").replace("/", " ").replace("+", " plus ")
    k = _CAMEL.sub("_", k)
    k = _KEY_CLEAN.sub("_", k).strip("_").lower()
    k = re.sub(r"_+", "_", k)
    if k and k[0].isdigit():
        k = "_" + k
    return k or "value"


def normalize_mac(mac: str | None) -> str | None:
    """Any MAC notation -> ``aa:bb:cc:dd:ee:ff``; returns input if it is not a MAC."""
    if not mac:
        return mac
    hexchars = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexchars) != 12 or not re.fullmatch(r"[0-9a-fA-F.:\-]+", mac.strip()):
        return mac
    h = hexchars.lower()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


_DURATION_PARTS = re.compile(
    r"(\d+)\s*(years?|y|weeks?|w|days?|d|hours?|h|minutes?|mins?|m|seconds?|secs?|s)(?![a-z])", re.I
)
_UNIT_SECONDS = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_duration(value: str | None) -> int | None:
    """Convert vendor uptime/age strings to seconds.

    Handles ``01:02:03``, ``1d02h``, ``3w4d``, ``2y10w``, ``5d 01:02:03``,
    ``1 week, 2 days, 3 hours, 4 minutes`` and plain second counts.
    Returns ``None`` for ``never``/``-`` or anything unrecognised.
    """
    if value is None:
        return None
    v = str(value).strip().lower().rstrip(".")
    if not v or v in {"never", "-", "--", "n/a", "none"}:
        return None
    if v.isdigit():
        return int(v)
    total = 0
    matched = False
    # trailing hh:mm:ss (optionally preceded by days)
    hms = re.search(r"(?:(\d+)\s*d(?:ays?)?[ ,]*)?(\d+):(\d{2}):(\d{2})(?:\.\d+)?$", v)
    if hms:
        d, h, m, s = hms.groups()
        total += int(d or 0) * 86400 + int(h) * 3600 + int(m) * 60 + int(s)
        v = v[: hms.start()]
        matched = True
    elif re.fullmatch(r"(\d+):(\d{2})", v):
        mm, ss = v.split(":")
        return int(mm) * 60 + int(ss)
    for num, unit in _DURATION_PARTS.findall(v):
        u = unit.lower()
        key = "m" if u.startswith("min") or u == "m" else ("m" if u.startswith("mo") else u[0])
        total += int(num) * _UNIT_SECONDS[key]
        matched = True
    return total if matched else None


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #

_SEPARATOR = re.compile(r"^[\s\-=_+*|:]+$")


def is_separator(line: str) -> bool:
    return bool(line.strip()) and bool(_SEPARATOR.match(line)) and sum(c in "-=_" for c in line) >= 3


def header_columns(header: str, names: Sequence[str] | None = None) -> list[tuple[str, int]]:
    """Return ``[(name, start_col), ...]`` for a header line.

    Column names are split on 2+ spaces. When *names* is given, those exact
    strings are located in the header instead (useful for headers like
    ``Local Intf  Holdtime`` where single spaces appear inside names).
    """
    cols: list[tuple[str, int]] = []
    if names:
        pos = 0
        for name in names:
            idx = header.find(name, pos)
            if idx < 0:
                raise ValueError(f"column {name!r} not in header {header!r}")
            cols.append((name, idx))
            pos = idx + len(name)
        return cols
    for m in re.finditer(r"\S+(?: \S+)*", header):
        cols.append((m.group(0), m.start()))
    return cols


def slice_row(line: str, starts: Sequence[int]) -> list[str]:
    """Cut *line* at column *starts*, nudging cuts so words are never split."""
    cells: list[str] = []
    bounds = [*list(starts[1:]), None]
    begin = 0
    for end in bounds:
        if end is None:
            cells.append(line[begin:].strip())
            break
        cut = end
        # If we'd split a word, move the cut left to the preceding space
        if 0 < cut < len(line) and line[cut - 1] != " " and line[cut] != " ":
            left = line.rfind(" ", begin, cut)
            right = line.find(" ", cut)
            if left > begin:
                cut = left
            elif right != -1:
                cut = right
        cells.append(line[begin:cut].strip())
        begin = cut
    return cells


def parse_table(
    text: str,
    header: str | Pattern[str] | None = None,
    names: Sequence[str] | None = None,
    keys: Sequence[str] | None = None,
    stop: str | Pattern[str] | None = None,
    skip: str | Pattern[str] | None = None,
    min_cells: int = 1,
    convert: bool = True,
    wrap: bool = False,
) -> list[dict[str, Any]]:
    """Parse a column-aligned table.

    :param header: regex locating the header line (default: first non-blank line)
    :param names:  exact column titles as printed (default: split header on 2+ spaces)
    :param keys:   output key names, defaults to ``snake(name)``
    :param stop:   regex; stop parsing at the first matching line
    :param skip:   regex; ignore matching data lines
    :param wrap:   treat rows whose first cell is empty as continuations of the previous row
    """
    all_lines = text.splitlines()
    hdr_idx = None
    if header is None:
        for i, ln in enumerate(all_lines):
            if ln.strip() and not is_separator(ln):
                hdr_idx = i
                break
    else:
        rx = re.compile(header) if isinstance(header, str) else header
        for i, ln in enumerate(all_lines):
            if rx.search(ln):
                hdr_idx = i
                break
    if hdr_idx is None:
        return []
    cols = header_columns(all_lines[hdr_idx], names)
    starts = [c[1] for c in cols]
    starts[0] = 0
    out_keys = list(keys) if keys else [snake(c[0]) for c in cols]
    stop_rx = re.compile(stop) if isinstance(stop, str) else stop
    skip_rx = re.compile(skip) if isinstance(skip, str) else skip
    rows: list[dict[str, Any]] = []
    for ln in all_lines[hdr_idx + 1 :]:
        if stop_rx and stop_rx.search(ln):
            break
        if not ln.strip() or is_separator(ln):
            continue
        if skip_rx and skip_rx.search(ln):
            continue
        cells = slice_row(ln, starts)
        if wrap and rows and not cells[0] and ln.startswith(" "):
            for k, c in zip(out_keys, cells):
                if c:
                    prev = rows[-1].get(k)
                    rows[-1][k] = (
                        f"{prev} {c}".strip() if isinstance(prev, str) and prev else (to_num(c) if convert else c)
                    )
            continue
        if sum(1 for c in cells if c) < min_cells:
            continue
        row = {k: (to_num(c) if convert else c) if c != "" else None for k, c in zip(out_keys, cells)}
        rows.append(row)
    return rows


def split_columns(line: str, maxsplit: int = -1) -> list[str]:
    """Split on runs of 2+ spaces (keeps single-spaced values together)."""
    parts = re.split(r"\s{2,}", line.strip(), maxsplit=maxsplit if maxsplit >= 0 else 0)
    return [p for p in parts if p != ""]


def kv_pairs(text: str, sep: str = r"\s*:\s+|\s*:\s*$", key_re: str = r"[A-Za-z][\w \-/().#'&]*?") -> dict[str, Any]:
    """Extract ``Key: value`` pairs (several per line allowed, split on 2+ spaces or commas)."""
    out: dict[str, Any] = {}
    rx = re.compile(rf"(?P<k>{key_re})(?:{sep})(?P<v>.*?)(?=\s{{2,}}{key_re}(?:{sep})|,\s+{key_re}(?:{sep})|$)")
    for ln in text.splitlines():
        for m in rx.finditer(ln.strip()):
            k = snake(m.group("k"))
            v = m.group("v").strip().rstrip(",")
            if k:
                out[k] = to_num(v) if v else None
    return out


# --------------------------------------------------------------------------- #
# Line-by-line regex state machines
# --------------------------------------------------------------------------- #


def search(pattern: str | Pattern[str], text: str, flags: int = re.M) -> dict[str, Any] | None:
    """Regex search returning a dict of converted named groups (``None`` values dropped)."""
    rx = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
    m = rx.search(text)
    if not m:
        return None
    return {k: to_num(v.strip()) for k, v in m.groupdict().items() if v is not None}


def match_lines(pattern: str | Pattern[str], text: str, flags: int = 0) -> Iterator[re.Match[str]]:
    """Like ``re.finditer`` with ``re.M`` but a match can never span lines.

    Prefer this over ``re.finditer(r"^...$", text, re.M)``: with ``\\s+``
    between fields the latter silently glues a short line to the next one.
    """
    rx = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
    for ln in text.splitlines():
        m = rx.match(ln)
        if m:
            yield m


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def compact(obj: Any) -> Any:
    """Recursively drop ``None`` values and empty containers."""
    if isinstance(obj, dict):
        out = {k: compact(v) for k, v in obj.items()}
        return {k: v for k, v in out.items() if v is not None and v != {} and v != []}
    if isinstance(obj, list):
        return [compact(v) for v in obj if v is not None]
    return obj
