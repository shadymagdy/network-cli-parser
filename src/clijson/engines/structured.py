"""Engines for output that is already structured.

Junos can emit ``| display xml`` and ``| display json``; both are verbose
(namespaces, ``junos:format`` attributes, every scalar wrapped in
``[{"data": ...}]``). These helpers flatten them into clean, idiomatic JSON
with snake_case keys so users get the same ergonomic shape as native parsers.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..textutils import to_num


def looks_like_xml(text: str) -> bool:
    s = text.lstrip()
    return s.startswith(("<?xml", "<rpc-reply")) or bool(
        re.match(r"<[\w\-:]+[ >][\s\S]*</[\w\-:]+>\s*$", s[:200000]) and s.count("<") > 2
    )


def looks_like_json(text: str) -> bool:
    s = text.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def _key(tag: str) -> str:
    tag = tag.split("}", 1)[-1]
    return tag.replace("-", "_").replace(":", "_").lower()


def _xml_to_obj(el: ET.Element) -> Any:
    children = list(el)
    text = (el.text or "").strip()
    attrs = {}
    for k, v in el.attrib.items():
        local = k.split("}", 1)[-1]
        if k.startswith("{") and local not in ("seconds",):
            continue
        attrs[local] = v
    if not children:
        value: Any = to_num(text) if text else (True if not attrs else None)
        if attrs:
            obj: dict[str, Any] = {"value": value} if text else {}
            for k, v in attrs.items():
                obj[_key(k)] = to_num(v)
            return obj if len(obj) > 1 or "value" not in obj else obj["value"]
        return value
    obj = {}
    for k, v in attrs.items():
        obj[_key(k)] = to_num(v)
    for child in children:
        k = _key(child.tag)
        v = _xml_to_obj(child)
        if k in obj:
            if not isinstance(obj[k], list) or not getattr(obj[k], "_multi", False):
                obj[k] = _Multi([obj[k]])
            obj[k].append(v)
        else:
            obj[k] = v
    return {k: (list(v) if isinstance(v, _Multi) else v) for k, v in obj.items()}


class _Multi(list[Any]):
    _multi = True


def parse_xml(text: str) -> Any:
    """Convert (Junos) XML output into plain Python data."""
    s = text.strip()
    # drop trailing prompt/cli noise after the root element closes
    end = s.rfind(">")
    s = s[: end + 1]
    # Junos sometimes prints several roots; wrap them
    try:
        root = ET.fromstring(s)
    except ET.ParseError:
        root = ET.fromstring(f"<root>{re.sub(r'<[?]xml[^>]*[?]>', '', s)}</root>")
    data = _xml_to_obj(root)
    tag = _key(root.tag)
    if tag == "rpc_reply" and isinstance(data, dict):
        data = {k: v for k, v in data.items() if k not in ("cli", "banner")}
        if len(data) == 1:
            return data
    if tag == "root":
        return data
    return {tag: data}


def simplify_junos_json(obj: Any) -> Any:
    """Collapse Junos ``[{"data": x}]`` wrappers, merge ``attributes`` and snake_case keys."""
    if isinstance(obj, list):
        items = [simplify_junos_json(v) for v in obj]
        return items[0] if len(items) == 1 else items
    if isinstance(obj, dict):
        if set(obj) <= {"data", "attributes"} and "data" in obj:
            val = to_num(obj["data"]) if isinstance(obj["data"], str) else obj["data"]
            attrs = obj.get("attributes") or {}
            secs = attrs.get("junos:seconds")
            if secs is not None:
                return {"value": val, "seconds": to_num(secs)}
            return val
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k == "attributes":
                for ak, av in (v or {}).items():
                    if ":" in ak and not ak.endswith("seconds"):
                        continue
                    out[_key(ak)] = to_num(av) if isinstance(av, str) else av
                continue
            if isinstance(v, list) and len(v) == 1 and v[0] == {"data": [None]}:
                out[_key(k)] = True
                continue
            if isinstance(v, list) and v == [{"data": [None]}]:
                out[_key(k)] = True
                continue
            out[_key(k)] = simplify_junos_json(v)
        return out
    if isinstance(obj, str):
        return to_num(obj)
    return obj


def parse_json(text: str) -> Any:
    s = text.strip()
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        # tolerate trailing prompt / cli noise
        end = max(s.rfind("}"), s.rfind("]"))
        data = json.loads(s[: end + 1])
    if _is_junos_json(data):
        return simplify_junos_json(data)
    return data


def _is_junos_json(data: Any) -> bool:
    blob = json.dumps(data)[:5000]
    return '"data":' in blob and ('"attributes"' in blob or '[{"data"' in blob)
