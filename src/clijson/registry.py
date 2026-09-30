"""Parser base class and the global registry.

Adding a parser is one decorator away::

    from clijson.registry import Parser, register


    @register("iosxr", "show clock", intent="system.clock")
    class ShowClock(Parser):
        def parse(self, text): ...

The registry indexes parsers per platform and resolves any typed command
(abbreviations included) to the best parser plus its captured parameters.
"""

from __future__ import annotations

import difflib
import importlib
import pkgutil
import warnings
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .commands import Seq, canonical, compile_pattern, match_tokens, render
from .platforms import Platform, get_platform


class Parser:
    """Base class for dedicated parsers.

    Subclasses implement :meth:`parse`, returning JSON-serialisable data
    (``dict`` or ``list``). ``self.params`` holds values captured from the
    command pattern, e.g. ``{"vrf": "CUSTOMER-A"}``.
    """

    #: Filled in by :func:`register`
    platform: str = ""
    commands: tuple[str, ...] = ()
    intent: str | None = None
    name: str = ""
    description: str = ""

    def __init__(self, params: dict[str, str] | None = None, command: str = "") -> None:
        self.params: dict[str, str] = params or {}
        self.command = command

    def parse(self, text: str) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} {self.platform}:{self.commands[0] if self.commands else '?'}>"


@dataclass
class Entry:
    parser: type[Parser]
    pattern: str
    compiled: Seq


@dataclass
class Resolution:
    parser: type[Parser]
    pattern: str
    params: dict[str, str]
    score: int


class Registry:
    def __init__(self) -> None:
        self._entries: dict[str, list[Entry]] = {}
        self._loaded = False

    # -- registration -------------------------------------------------------
    def add(self, platform: str, patterns: Iterable[str], parser: type[Parser]) -> None:
        plat = get_platform(platform).name
        for pattern in patterns:
            self._entries.setdefault(plat, []).append(Entry(parser, pattern, compile_pattern(pattern)))

    # -- discovery ----------------------------------------------------------
    def load_builtin(self) -> None:
        """Import every module under :mod:`clijson.parsers` (idempotent)."""
        if self._loaded:
            return
        self._loaded = True
        from . import parsers as pkg

        for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            importlib.import_module(mod.name)
        self._load_plugins()

    def _load_plugins(self) -> None:
        """Third-party packages can ship parsers via the ``clijson.parsers`` entry point."""
        from importlib.metadata import entry_points

        for ep in entry_points(group="clijson.parsers"):
            _load_plugin(ep)

    # -- lookup -------------------------------------------------------------
    def resolve(self, platform: str | Platform, tokens: list[str]) -> Resolution | None:
        self.load_builtin()
        plat = get_platform(platform)
        tokens = _apply_verb_alias(plat, tokens)
        best: tuple[tuple[int, int], Entry, dict[str, str], int] | None = None
        for entry in self._entries.get(plat.name, []):
            m = match_tokens(entry.compiled, tokens)
            if m is None:
                continue
            rank = (m.score, m.literals)
            if best is None or rank > best[0]:
                best = (rank, entry, m.params, m.score)
        if best is None:
            return None
        _, entry, params, score = best
        return Resolution(entry.parser, entry.pattern, params, score)

    def suggest(self, platform: str | Platform, command: str, n: int = 3) -> list[str]:
        self.load_builtin()
        plat = get_platform(platform)
        choices = sorted({canonical(e.compiled) for e in self._entries.get(plat.name, [])})
        return difflib.get_close_matches(command.lower(), choices, n=n, cutoff=0.5)

    def entries(self, platform: str | None = None) -> list[Entry]:
        self.load_builtin()
        if platform:
            return list(self._entries.get(get_platform(platform).name, []))
        return [e for es in self._entries.values() for e in es]

    def catalog(self, platform: str | None = None) -> list[dict[str, Any]]:
        """Human friendly list of supported commands (used by docs and the CLI)."""
        seen = set()
        out: list[dict[str, Any]] = []
        for plat, entries in sorted(self._iter_platform_entries(platform)):
            for e in entries:
                key = (plat, e.pattern)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "platform": plat,
                        "command": render(e.compiled),
                        "example": canonical(e.compiled),
                        "parser": e.parser.name,
                        "intent": e.parser.intent,
                        "description": e.parser.description,
                    }
                )
        return out

    def _iter_platform_entries(self, platform: str | None) -> Iterator[tuple[str, list[Entry]]]:
        self.load_builtin()
        if platform:
            name = get_platform(platform).name
            yield name, self._entries.get(name, [])
        else:
            yield from self._entries.items()


def _apply_verb_alias(plat: Platform, tokens: list[str]) -> list[str]:
    if tokens and plat.verb_aliases:
        first = tokens[0].lower()
        for alias in plat.verb_aliases:
            if len(first) >= 2 and alias.startswith(first) and not plat.verb.startswith(first):
                return [plat.verb, *list(tokens[1:])]
    return list(tokens)


def _load_plugin(ep: Any) -> None:
    """Import one plugin; a broken plugin warns instead of breaking every parse."""
    try:
        ep.load()
    except Exception as exc:  # pragma: no cover - depends on installed plugins
        warnings.warn(f"clijson plugin {ep.name!r} failed to load: {exc}", RuntimeWarning, stacklevel=2)


REGISTRY = Registry()


def register(platform: str, *patterns: str, intent: str | None = None) -> Callable[[type[Parser]], type[Parser]]:
    """Class decorator registering a :class:`Parser` for one or more command patterns."""
    if not patterns:
        raise ValueError("register() needs at least one command pattern")

    def deco(cls: type[Parser]) -> type[Parser]:
        plat = get_platform(platform).name
        cls.platform = plat
        cls.commands = tuple(patterns)
        cls.intent = intent if intent is not None else cls.intent
        cls.name = f"{plat}.{_snake(cls.__name__)}"
        doc = (cls.__doc__ or "").strip().splitlines()
        cls.description = cls.description or (doc[0] if doc else "")
        REGISTRY.add(plat, patterns, cls)
        return cls

    return deco


def _snake(name: str) -> str:
    import re

    return re.sub(r"(?<!^)(?=[A-Z][a-z])|(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
