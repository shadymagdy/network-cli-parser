"""Remove the Cisco NSO ``live-status exec`` wrapping around device output.

NSO hands the device's CLI text back in a ``result`` leaf. Depending on how it was collected, that text arrives:

* bare: the Python API's ``action(inp).result``, usually with CRLF line endings;
* as JSON: RESTCONF, ``ncs_cli ... | display json``, or JSON-RPC ``run_action``, either nested
  (``{"jsonrpc": ..., "result": {"<ned>-stats:output": {"result": "..."}}}``) or as a list of
  ``{"name": "result", "value": "..."}`` pairs;
* as XML: RESTCONF, a NETCONF ``<rpc-reply>``, or ``ncs_cli ... | display xml``, with the text XML-escaped;
* as an ``ncs_cli`` transcript: NSO's prompt and command line, a ``result`` header, the text, J-style
  ``[ok][...]`` lines and NSO's prompt again;
* with literal ``\\r\\n`` sequences instead of line breaks, when copied out of a log or JSON string.

Everything here uses plain string operations (no backtracking regexes) so it stays linear on any input.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from typing import Any

SOURCE = "nso-live-status"

# NSO's own CLI prompt followed by a live-status exec command (one line, anchored, no nested quantifiers)
_NSO_EXEC_LINE = re.compile(
    r"^(?P<prompt>[\w.\-]+@[\w.\-]+[#>])[ \t]*(?:request[ \t]+)?devices[ \t]+device[ \t]+(?P<device>\S+)"
    r"[ \t]+live-status[ \t]+(?:\S+[ \t]+)??exec[ \t]+\w+(?P<args>.*)$"
)
_BARE_PROMPT = re.compile(r"^[\w.\-]+@[\w.\-]+[#>]$")


@dataclass
class Unwrapped:
    text: str
    source: str | None = None
    command: str | None = None
    device: str | None = None


def unwrap(text: str) -> Unwrapped:
    """Return the device text inside any NSO wrapping, plus the command / device when the wrapping names them."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")) and "result" in stripped[:4000]:
        inner = _from_json(stripped)
        if inner is not None:
            return Unwrapped(_unescape_literal(inner), SOURCE)
    if stripped.startswith("<") and "result" in stripped[:4000]:
        inner = _from_xml(stripped)
        if inner is not None:
            return Unwrapped(_unescape_literal(inner), SOURCE)
    transcript = _from_transcript(text)
    if transcript is not None:
        transcript.text = _unescape_literal(transcript.text)
        return transcript
    unescaped = _unescape_literal(text)
    return Unwrapped(unescaped, SOURCE if unescaped is not text else None)


# --------------------------------------------------------------------------- #
# JSON (RESTCONF, | display json, JSON-RPC)
# --------------------------------------------------------------------------- #


def _from_json(stripped: str) -> str | None:
    try:
        obj = json.loads(stripped)
    except ValueError:
        return None
    return _json_result(obj, depth=0)


def _json_result(obj: Any, depth: int) -> str | None:
    if depth > 4:
        return None
    if isinstance(obj, list):
        # JSON-RPC run_action: [{"name": "result", "value": "..."}] (names may carry a module prefix)
        for item in obj:
            if isinstance(item, dict) and str(item.get("name", "")).split(":")[-1] == "result":
                value = item.get("value")
                return value if isinstance(value, str) else None
        return None
    if not isinstance(obj, dict):
        return None
    result = obj.get("result")
    if isinstance(result, str) and len(obj) <= 2:
        return result
    if "jsonrpc" in obj:
        return _json_result(result, depth + 1)
    if len(obj) == 1:
        ((key, val),) = obj.items()
        name = str(key).split(":")[-1]
        if name == "result" and isinstance(val, str):
            return val
        if name in ("output", "exec", "any", "result"):
            return _json_result(val, depth + 1)
    return None


# --------------------------------------------------------------------------- #
# XML (RESTCONF, NETCONF rpc-reply, | display xml)
# --------------------------------------------------------------------------- #


def _from_xml(stripped: str) -> str | None:
    """Text content of the first ``<result>`` / ``<prefix:result>`` element that holds only text."""
    pos = 0
    for _ in range(50):  # bounded scan; each step is a plain find()
        start = stripped.find("result", pos)
        if start < 0:
            return None
        pos = start + 6
        lt = stripped.rfind("<", 0, start)
        if lt < 0:
            continue
        prefix = stripped[lt + 1 : start]  # "" or "prefix:"
        if prefix and not (
            prefix.endswith(":") and prefix[:-1].replace("-", "").replace("_", "").replace(".", "").isalnum()
        ):
            continue
        if stripped[start + 6 : start + 7] not in (">", " ", "/", "\t", "\r", "\n"):
            continue
        gt = stripped.find(">", start)
        if gt < 0:
            return None
        if stripped[gt - 1] == "/":  # <result/>
            return ""
        close = stripped.find(f"</{prefix}result>", gt)
        if close < 0:
            return None
        body = stripped[gt + 1 : close]
        trimmed = body.strip()
        if trimmed.startswith("<![CDATA[") and trimmed.endswith("]]>"):
            return trimmed[9:-3]
        if "<" in body:  # child elements: structured data, not wrapped CLI text
            pos = close
            continue
        return html.unescape(body)
    return None


# --------------------------------------------------------------------------- #
# ncs_cli transcripts
# --------------------------------------------------------------------------- #


def _command_from_args(args: str) -> str | None:
    s = args.strip()
    if s.startswith("args"):
        s = s[4:].strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    s = s.strip()
    return s or None


def _is_result_header(line: str) -> bool:
    return line.rstrip() == "result" or line.startswith(("result ", "result\t"))


def _from_transcript(text: str) -> Unwrapped | None:
    lines = text.split("\n")
    nso_prompt = command = device = None
    start = None
    for i, raw in enumerate(lines[:20]):  # NSO's command line and the result header come first
        line = raw.strip().rstrip("\r")
        if not line:
            continue
        m = _NSO_EXEC_LINE.match(line)
        if m:
            nso_prompt, device = m["prompt"], m["device"]
            command = _command_from_args(m["args"])
            continue
        if _is_result_header(line):
            start = i
            break
        if nso_prompt is None:
            return None  # device output that merely mentions "result" later on
    if start is None:
        return None
    first = lines[start].strip().rstrip("\r")[len("result") :].strip()
    body = ([first] if first else []) + lines[start + 1 :]
    # trailing NSO noise: blank lines, J-style "[ok][timestamp]" and NSO's own prompt
    saw_ok = False
    while body:
        last = body[-1].strip().rstrip("\r")
        if not last:
            body.pop()
        elif last.startswith(("[ok]", "[error]")):
            saw_ok = True
            body.pop()
        elif _BARE_PROMPT.match(last) and (saw_ok or last == nso_prompt):
            body.pop()
            nso_prompt = None  # only the final prompt belongs to NSO
        else:
            break
    return Unwrapped("\n".join(body), SOURCE, command, device)


# --------------------------------------------------------------------------- #
# literal escapes
# --------------------------------------------------------------------------- #


def _unescape_literal(text: str) -> str:
    """``line1\\r\\nline2`` copied from a log or JSON string -> real line breaks (only when there are none)."""
    if "\n" in text or text.count("\\n") < 2:
        return text
    return text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "").replace("\\t", "\t").replace('\\"', '"')
