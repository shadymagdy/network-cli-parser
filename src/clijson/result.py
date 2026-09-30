"""The :class:`ParseResult` returned by :func:`clijson.parse`."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class ParseResult:
    """Structured output plus provenance.

    ``data`` is the parsed output. Everything else explains *how* it was
    obtained so that automation can decide how much to trust it:

    * ``engine`` - ``native`` (dedicated parser), ``xml``/``json`` (the device
      emitted structured data), ``config`` (configuration tree),
      ``ntc``/``genie``/``ttp`` (optional third-party engines) or ``generic``
      (heuristic fallback that works on any output).
    * ``confidence`` - 0..1, ``1.0`` for native parsers.
    """

    data: Any
    platform: Optional[str]
    command: Optional[str]
    engine: str
    parser: Optional[str] = None
    confidence: float = 1.0
    intent: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    normalized: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # -- convenience --------------------------------------------------------
    def __getitem__(self, key: Any) -> Any:
        return self.data[key]

    def __iter__(self) -> Iterator[Any]:
        return iter(self.data)

    def __len__(self) -> int:
        try:
            return len(self.data)
        except TypeError:
            return 0

    def get(self, key: Any, default: Any = None) -> Any:
        if isinstance(self.data, dict):
            return self.data.get(key, default)
        return default

    @property
    def ok(self) -> bool:
        return self.data not in (None, {}, [])

    def to_dict(self, meta: bool = True) -> Dict[str, Any]:
        if not meta:
            return self.normalized if self.normalized is not None else self.data
        out: Dict[str, Any] = {
            "platform": self.platform,
            "command": self.command,
            "engine": self.engine,
            "parser": self.parser,
            "confidence": self.confidence,
        }
        if self.intent:
            out["intent"] = self.intent
        if self.params:
            out["params"] = self.params
        if self.warnings:
            out["warnings"] = self.warnings
        if self.metadata:
            out["metadata"] = self.metadata
        out["data"] = self.data
        if self.normalized is not None:
            out["normalized"] = self.normalized
        return out

    def records(self) -> List[Dict[str, Any]]:
        """The most table-like view of the result as a list of flat dicts.

        Uses the normalized view when available, otherwise the largest list of records
        found in ``data`` (a dict keyed by name becomes rows with a ``name`` column).
        """
        return _rows(self.normalized if self.normalized is not None else self.data) or []

    def to_dataframe(self) -> Any:
        """``records()`` as a pandas DataFrame (requires pandas)."""
        try:
            import pandas as pd
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError("to_dataframe() needs pandas: pip install pandas") from exc
        return pd.DataFrame(self.records())

    def to_json(self, indent: Optional[int] = 2, meta: bool = False, **kwargs: Any) -> str:
        """JSON string. ``meta=True`` wraps the data with provenance fields."""
        return json.dumps(self.to_dict(meta=meta), indent=indent, default=str, **kwargs)

    def to_yaml(self, meta: bool = False) -> str:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError("YAML output needs PyYAML: pip install 'clijson[yaml]'") from exc
        return yaml.safe_dump(self.to_dict(meta=meta), sort_keys=False, allow_unicode=True)

    def __repr__(self) -> str:
        return (
            f"ParseResult(platform={self.platform!r}, command={self.command!r}, "
            f"engine={self.engine!r}, parser={self.parser!r}, confidence={self.confidence})"
        )


def _rows(obj: Any) -> Optional[List[Dict[str, Any]]]:
    """Find the most table-like list of dicts in *obj* (flattening one level of nesting)."""
    if isinstance(obj, list) and obj and all(isinstance(r, dict) for r in obj):
        return [_flat(r) for r in obj]
    if isinstance(obj, dict):
        if obj and all(isinstance(v, dict) and any(not isinstance(x, (dict, list)) for x in v.values()) for v in obj.values()):
            return [{"name": k, **_flat(v)} for k, v in obj.items()]
        best: Optional[List[Dict[str, Any]]] = None
        for v in obj.values():
            r = _rows(v)
            if r and (best is None or len(r) > len(best)):
                best = r
        return best
    return None


def _flat(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, dict) and v and all(not isinstance(x, (dict, list)) for x in v.values()):
            for kk, vv in v.items():
                out[f"{k}.{kk}"] = vv
        elif isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
            out[k] = ", ".join(map(str, v))
        elif not isinstance(v, (dict, list)):
            out[k] = v
    return out
