"""Heuristic parser that turns *any* CLI output into structured JSON.

This is the safety net that makes ``clijson`` useful on day one for commands
nobody has written a dedicated parser for yet. It recognises three shapes that
cover the vast majority of network CLI output:

* **tables** - column aligned rows under a header, with or without ``----``
  separators. Column boundaries are inferred from vertical whitespace that is
  shared by the header and the data rows.
* **key/value pairs** - ``Key: value``, ``Key = value`` and several pairs per
  line (``BGP state = Established, up for 1d02h``).
* **indented sections** - a line followed by more-indented lines becomes a
  nested object, recursively.

Anything else is kept verbatim under ``lines`` so no information is lost.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..textutils import indent_of, is_separator, snake, to_num

_KV_SPLIT = re.compile(r"^(?P<k>[A-Za-z*][\w \-/().#'&,+]*?)\s*(?::|=|\.{3,})\s*(?P<v>.*)$")
_MULTI_KV = re.compile(
    r"(?P<k>[A-Za-z][\w\-/().#']*(?: [A-Za-z][\w\-/().#']*){0,5})\s*(?::|=)\s*(?P<v>[^,;]*?)\s*(?=(?:[,;]\s*|\s{2,})[A-Za-z][\w\-/().#' ]{0,40}\s*(?::|=)|$)"
)
_TIME_LIKE = re.compile(r"\d{1,2}:\d{2}")


def parse_generic(text: str) -> Dict[str, Any]:
    """Parse arbitrary CLI output. Returns a dict with any of
    ``fields``, ``tables``, ``sections`` and ``lines``."""
    result: Dict[str, Any] = {}
    fields: Dict[str, Any] = {}
    tables: List[Dict[str, Any]] = []
    loose: List[str] = []

    for block in _split_blocks(text):
        head, table = _find_table(block)
        if head:
            _merge(fields, _parse_tree(head, loose))
        if table:
            tables.append(table)

    if fields:
        result["fields"] = fields
    if tables:
        result["tables"] = tables
    if loose:
        result["lines"] = loose
    return result


# --------------------------------------------------------------------------- #
# blocks
# --------------------------------------------------------------------------- #


def _split_blocks(text: str) -> List[List[str]]:
    out: List[List[str]] = []
    cur: List[str] = []
    for ln in text.splitlines():
        if not ln.strip():
            if cur:
                out.append(cur)
                cur = []
            continue
        cur.append(ln.rstrip())
    if cur:
        out.append(cur)
    return out


# --------------------------------------------------------------------------- #
# tables
# --------------------------------------------------------------------------- #


def _find_table(block: List[str]) -> Tuple[List[str], Optional[Dict[str, Any]]]:
    """Return ``(prefix_lines, table)``; table is ``None`` if the block has none."""
    # 1) explicit separator line under a header
    for i, ln in enumerate(block):
        if is_separator(ln) and i >= 1:
            hdr_start = i - 1
            # allow 2-line headers
            if i >= 2 and _looks_like_header(block[i - 2]) and _looks_like_header(block[i - 1]) and _aligned_header(block[i - 2], block[i - 1]):
                hdr_start = i - 2
            header_lines = block[hdr_start:i]
            body = [b for b in block[i + 1 :] if not is_separator(b)]
            if not body:
                continue
            table = _build_table(header_lines, body)
            if table:
                return block[:hdr_start], table
    # 2) implicit, alignment based
    for s in range(0, max(0, len(block) - 1)):
        header = block[s]
        body = block[s + 1 :]
        if len(body) < 1 or not _looks_like_header(header):
            continue
        table = _build_table([header], body, strict=True)
        if table:
            return block[:s], table
    return block, None


def _is_kv_row(line: str) -> bool:
    m = _KV_SPLIT.match(line.strip())
    return bool(m) and not re.search(r"\d$", m.group("k")) and not _TIME_LIKE.match(m.group("v"))


def _looks_like_header(line: str) -> bool:
    s = line.strip()
    if not s or _KV_SPLIT.match(s) and ":" in s and not re.search(r"\s{2,}", s.split(":", 1)[1] if ":" in s else ""):
        return False
    words = s.split()
    if len(words) < 2:
        return False
    # headers are mostly alphabetic words, not numbers/addresses
    alpha = sum(1 for w in words if re.match(r"^[A-Za-z#(/*][\w\-/().#%*|.:+]*$", w))
    return alpha / len(words) >= 0.7 and not (s.endswith((".", ":")) and not s.endswith("..."))


def _aligned_header(a: str, b: str) -> bool:
    return abs(indent_of(a) - indent_of(b)) <= 2


def _gap_columns(lines: Sequence[str], header_count: int) -> List[Tuple[int, int]]:
    width = max(len(ln) for ln in lines)
    body = lines[header_count:]
    tolerance = max(0, len(body) // 10)
    blank = []
    for p in range(width):
        hdr_ok = all(p >= len(h) or h[p] == " " for h in lines[:header_count])
        misses = sum(1 for b in body if p < len(b) and b[p] != " ")
        blank.append(hdr_ok and misses <= tolerance)
    cols: List[Tuple[int, int]] = []
    start = None
    for p in range(width):
        if not blank[p] and start is None:
            start = p
        elif blank[p] and start is not None:
            cols.append((start, p))
            start = None
    if start is not None:
        cols.append((start, width))
    return cols


def _is_detail(line: str, header_indent: int) -> bool:
    """Indented ``key: value`` lines under a row (Junos style) are row details."""
    return indent_of(line) > header_indent + 1 and bool(re.match(r"^\s+\S+:\s+\S", line)) and len(line.split()) <= 4


def _build_table(header_lines: List[str], body: List[str], strict: bool = False) -> Optional[Dict[str, Any]]:
    hdr_indent = min(indent_of(h) for h in header_lines)
    details = [_is_detail(b, hdr_indent) for b in body]
    if any(details) and not all(details):
        table = _build_table(header_lines, [b for b, d in zip(body, details) if not d], strict)
        if table is None:
            return None
        # re-attach the details to the row they follow
        row_idx = -1
        for b, d in zip(body, details):
            if not d:
                row_idx += 1
            elif 0 <= row_idx < len(table["rows"]):
                k, v = b.strip().split(":", 1)
                table["rows"][row_idx].setdefault("details", {})[k.strip()] = to_num(v.strip())
        return table
    lines = header_lines + body
    cols = _gap_columns(lines, len(header_lines))
    if len(cols) < 2:
        return None
    # header words must start inside columns; name = words in the span
    names: List[str] = []
    for a, b in cols:
        parts = [h[a:b].strip() for h in header_lines if h[a:b].strip()]
        names.append(" ".join(parts))
    # merge columns without a header title into the previous one
    merged: List[Tuple[int, int, str]] = []
    for (a, b), n in zip(cols, names):
        if not n and merged:
            pa, _, pn = merged[-1]
            merged[-1] = (pa, b, pn)
        else:
            merged.append((a, b, n))
    if len(merged) < 2 or not merged[0][2]:
        return None
    if strict:
        # implicit tables need several rows or multiple well separated header columns
        if len(body) < 2 and len(merged) < 3:
            return None
        # rows that look like key: value suggest this is not a table
        kv_rows = sum(1 for b in body if _is_kv_row(b))
        if kv_rows > len(body) / 2:
            return None
        # rows must have content in at least half of the columns
        filled = [sum(1 for a, b, _ in merged if row[a:b].strip()) for row in body]
        if sum(1 for f in filled if f >= max(2, len(merged) // 2)) < max(1, int(len(body) * 0.6)):
            return None
    keys = _unique_keys([snake(n) for _, _, n in merged])
    starts = [a for a, _, _ in merged]
    starts[0] = 0
    rows: List[Dict[str, Any]] = []
    for ln in body:
        cells = _cut(ln, starts)
        if not any(cells):
            continue
        # continuation line (first column empty, indented)
        if rows and not cells[0] and ln.startswith(" ") and sum(1 for c in cells if c) == 1:
            for k, c in zip(keys, cells):
                if c:
                    prev = rows[-1].get(k)
                    rows[-1][k] = f"{prev} {c}" if prev not in (None, "") else to_num(c)
            continue
        rows.append({k: (to_num(c) if c != "" else None) for k, c in zip(keys, cells)})
    if not rows:
        return None
    return {"columns": keys, "rows": rows}


def _cut(line: str, starts: Sequence[int]) -> List[str]:
    cells = []
    for i, a in enumerate(starts):
        b = starts[i + 1] if i + 1 < len(starts) else None
        # grow a cell to the left/right edge of the word it cuts through
        if i > 0 and 0 < a < len(line) and line[a - 1] != " " and line[a] != " ":
            while a < len(line) and line[a] != " ":
                a += 1
        if b is not None and 0 < b < len(line) and line[b - 1] != " " and line[b] != " ":
            while b < len(line) and line[b] != " ":
                b += 1
        cells.append(line[a:b].strip() if b is not None else line[a:].strip())
    return cells


def _unique_keys(keys: List[str]) -> List[str]:
    seen: Dict[str, int] = {}
    out = []
    for k in keys:
        if k in seen:
            seen[k] += 1
            out.append(f"{k}_{seen[k]}")
        else:
            seen[k] = 1
            out.append(k)
    return out


# --------------------------------------------------------------------------- #
# key/value tree
# --------------------------------------------------------------------------- #


def _split_kv(line: str) -> Dict[str, Any]:
    s = line.strip()
    out: Dict[str, Any] = {}
    matches = list(_MULTI_KV.finditer(s))
    if len(matches) > 1:
        for m in matches:
            k, v = snake(m.group("k")), m.group("v").strip()
            if k:
                out[k] = to_num(v) if v else None
        return out
    m = _KV_SPLIT.match(s)
    if m and m.group("v") and not s.startswith(("http", "ftp")):
        out[snake(m.group("k"))] = to_num(m.group("v").strip())
    return out


def _parse_tree(lines: List[str], loose: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    i, n = 0, len(lines)
    while i < n:
        ln = lines[i]
        ind = indent_of(ln)
        j = i + 1
        while j < n and indent_of(lines[j]) > ind:
            j += 1
        children = lines[i + 1 : j]
        stripped = ln.strip()
        kv = _split_kv(stripped)
        if children:
            key = snake(stripped.rstrip(":")) if not kv or stripped.endswith(":") else None
            local_loose: List[str] = []
            node = _parse_tree(children, local_loose)
            if local_loose:
                node.setdefault("lines", []).extend(local_loose)
            if key is None:
                # "Key: value" line with details underneath
                first_key = next(iter(kv))
                node = {"value": kv[first_key], **node} if len(kv) == 1 else {**kv, **node}
                key = first_key
            _put(out, key, node)
        elif kv:
            for k, v in kv.items():
                _put(out, k, v)
        elif stripped.endswith(":") and len(stripped) > 1:
            _put(out, snake(stripped[:-1]), None)
        else:
            loose.append(stripped)
        i = j
    return out


def _put(d: Dict[str, Any], key: str, value: Any) -> None:
    if key in d:
        if d[key] == value:
            return
        if isinstance(d[key], list) and not isinstance(value, list):
            d[key].append(value)
        else:
            d[key] = [d[key], value]
    else:
        d[key] = value


def _merge(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        _put(dst, k, v)
