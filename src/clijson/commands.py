"""Command grammar: turn what a human typed into a canonical command.

Parsers declare the commands they understand with a tiny grammar borrowed from
vendor documentation::

    show bgp [instance <instance>] [vrf (all|<vrf>)] [<afi> [<safi>]] summary
    show interfaces [<interface>] [(detail|extensive)]
    display ip routing-table [vpn-instance <vrf>] [<prefix...>]

* ``word``          literal keyword, abbreviations are accepted (``sh int br``)
* ``<name>``        a single-token parameter, captured into ``params['name']``
* ``<name...>``     one or more remaining tokens
* ``[ ... ]``       optional group (may nest)
* ``( a | b c )``   alternatives

Matching is fuzzy the way a router CLI is: ``sh ip int br`` resolves to
``show ip interface brief``. Every candidate gets a score and the most
specific match wins, so ``show interfaces brief`` beats
``show interfaces <interface>``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import TypeAlias

# --------------------------------------------------------------------------- #
# Grammar AST
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Literal:
    word: str


@dataclass(frozen=True)
class Param:
    name: str
    rest: bool = False


@dataclass(frozen=True)
class Optional_:
    body: Seq


@dataclass(frozen=True)
class Choice:
    options: tuple[Seq, ...]


Node: TypeAlias = Literal | Param | Optional_ | Choice
Seq: TypeAlias = tuple[Node, ...]

_TOKEN_RE = re.compile(r"\s*(<[\w\-]+(?:\.\.\.)?>|[\[\]()|]|[^\s\[\]()|<>]+)")


class GrammarError(ValueError):
    pass


def _tokenize(pattern: str) -> list[str]:
    pos, out = 0, []
    pattern = pattern.strip()
    while pos < len(pattern):
        m = _TOKEN_RE.match(pattern, pos)
        if not m:
            raise GrammarError(f"Bad command pattern near {pattern[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
        while pos < len(pattern) and pattern[pos].isspace():
            pos += 1
    return out


def compile_pattern(pattern: str) -> Seq:
    tokens = _tokenize(pattern)
    seq, idx = _parse_seq(tokens, 0, stop=())
    if idx != len(tokens):
        raise GrammarError(f"Unbalanced pattern {pattern!r}")
    return seq


def _parse_seq(tokens: list[str], idx: int, stop: tuple[str, ...]) -> tuple[Seq, int]:
    out: list[Node] = []
    while idx < len(tokens) and tokens[idx] not in stop:
        tok = tokens[idx]
        if tok == "[":
            body, idx = _parse_seq(tokens, idx + 1, stop=("]",))
            _expect(tokens, idx, "]")
            out.append(Optional_(body))
            idx += 1
        elif tok == "(":
            options: list[Seq] = []
            idx += 1
            while True:
                body, idx = _parse_seq(tokens, idx, stop=("|", ")"))
                options.append(body)
                if idx >= len(tokens):
                    raise GrammarError("Unclosed '('")
                if tokens[idx] == ")":
                    idx += 1
                    break
                idx += 1  # skip '|'
            out.append(Choice(tuple(options)))
        elif tok.startswith("<"):
            name = tok[1:-1]
            rest = name.endswith("...")
            out.append(Param(name[:-3] if rest else name, rest))
            idx += 1
        elif tok in ("]", ")", "|"):
            raise GrammarError(f"Unexpected {tok!r}")
        else:
            out.append(Literal(tok.lower()))
            idx += 1
    return tuple(out), idx


def _expect(tokens: list[str], idx: int, what: str) -> None:
    if idx >= len(tokens) or tokens[idx] != what:
        raise GrammarError(f"Expected {what!r}")


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

EXACT, PREFIX, PARAM = 100, 60, 25
MIN_PREFIX = 2

_IP_LIKE = re.compile(r"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)$")
_PREFIX_LIKE = re.compile(r"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)(?:/\d{1,3})?$")
_INTERFACE_LIKE = re.compile(r"^[A-Za-z][\w\-./:]*\d[\w\-./:]*$")

#: Parameters whose name implies a type only accept matching tokens, so typos such as
#: ``show bgp summry`` are not swallowed as a ``<prefix>``.
PARAM_TYPES = {
    "prefix": _PREFIX_LIKE,
    "neighbor": re.compile(_IP_LIKE.pattern + "|^[0-9]{1,3}(?:\\.[0-9]{1,3}){3}\\+\\d+$"),
    "address": _IP_LIKE,
    "peer": re.compile(r"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::\d+)?|[0-9a-fA-F]*:[0-9a-fA-F:.]*)$"),
    "ip": _IP_LIKE,
    "dest": _IP_LIKE,
    "interface": _INTERFACE_LIKE,
    "count": re.compile(r"^\d+$"),
    "vrid": re.compile(r"^\d+$"),
}


def _param_ok(name: str, token: str) -> bool:
    rx = PARAM_TYPES.get(name)
    return rx is None or bool(rx.match(token))


@dataclass(order=True)
class Match:
    score: int
    literals: int = 0
    params: dict[str, str] = field(default_factory=dict, compare=False)


def _literal_score(word: str, token: str) -> int:
    t = token.lower()
    if t == word:
        return EXACT
    if len(t) >= MIN_PREFIX and word.startswith(t):
        # Longer abbreviations are more trustworthy than 2-letter ones.
        return PREFIX + int(20 * len(t) / len(word))
    if len(word) <= MIN_PREFIX and len(t) >= 1 and word.startswith(t):
        return PREFIX
    return 0


def _match(seq: Seq, i: int, tokens: Sequence[str], acc: Match) -> Iterator[tuple[int, Match]]:
    if not seq:
        yield i, acc
        return
    node, rest = seq[0], seq[1:]
    if isinstance(node, Literal):
        if i < len(tokens):
            s = _literal_score(node.word, tokens[i])
            if s:
                yield from _match(rest, i + 1, tokens, Match(acc.score + s, acc.literals + 1, acc.params))
    elif isinstance(node, Param):
        if node.rest:
            for end in range(len(tokens), i, -1):
                p = dict(acc.params)
                p[node.name] = " ".join(tokens[i:end])
                yield from _match(rest, end, tokens, Match(acc.score + PARAM, acc.literals, p))
        elif i < len(tokens) and _param_ok(node.name, tokens[i]):
            p = dict(acc.params)
            p[node.name] = tokens[i]
            yield from _match(rest, i + 1, tokens, Match(acc.score + PARAM, acc.literals, p))
    elif isinstance(node, Optional_):
        for j, m in _match(node.body, i, tokens, acc):
            yield from _match(rest, j, tokens, m)
        yield from _match(rest, i, tokens, acc)
    elif isinstance(node, Choice):
        for option in node.options:
            for j, m in _match(option, i, tokens, acc):
                yield from _match(rest, j, tokens, m)


def match_tokens(seq: Seq, tokens: Sequence[str]) -> Match | None:
    """Best full match of *tokens* against a compiled pattern, or ``None``."""
    best: Match | None = None
    for end, m in _match(seq, 0, tokens, Match(0)):
        if end == len(tokens) and (best is None or m > best):
            best = m
    return best


def render(seq: Seq) -> str:
    """Pretty-print a compiled pattern (used by docs and ``clijson commands``)."""
    parts: list[str] = []
    for node in seq:
        if isinstance(node, Literal):
            parts.append(node.word)
        elif isinstance(node, Param):
            parts.append(f"<{node.name}{'...' if node.rest else ''}>")
        elif isinstance(node, Optional_):
            parts.append(f"[{render(node.body)}]")
        elif isinstance(node, Choice):
            parts.append("(" + " | ".join(render(o) for o in node.options) + ")")
    return " ".join(parts)


def literal_words(seq: Seq) -> list[str]:
    out: list[str] = []
    for node in seq:
        if isinstance(node, Literal):
            out.append(node.word)
        elif isinstance(node, Optional_):
            out.extend(literal_words(node.body))
        elif isinstance(node, Choice):
            for o in node.options:
                out.extend(literal_words(o))
    return out


def canonical(seq: Seq) -> str:
    """Shortest concrete command for a pattern: mandatory literals only."""
    parts: list[str] = []
    for node in seq:
        if isinstance(node, Literal):
            parts.append(node.word)
        elif isinstance(node, Param):
            parts.append(f"<{node.name}>")
        elif isinstance(node, Choice):
            parts.append(canonical(node.options[0]))
    return " ".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
# Command line clean-up
# --------------------------------------------------------------------------- #

#: Output modifiers that change the *format* of the output.
FORMAT_PIPES = {
    "json": re.compile(r"^(?:display\s+)?json\b|^json$", re.I),
    "xml": re.compile(r"^(?:display\s+)?xml\b|^xml$", re.I),
}
#: Filtering modifiers - the output is still parseable but may be partial.
FILTER_PIPES = re.compile(
    r"^(?:i|in|inc|incl|include|e|ex|exc|excl|exclude|b|be|beg|begin|s|se|sec|section|"
    r"match|except|find|count|last|trim|no-more|nomore|refresh|save|resolve|utility|file|"
    r"display\s+(?:set|inheritance|detail|omit|changed|commit-scripts)|compare|hold|"
    r"begin|end|exclude|include|linnum|no-more|count)\b",
    re.I,
)


@dataclass
class CommandLine:
    """A parsed command line: the base command plus any ``| modifiers``."""

    raw: str
    base: str
    tokens: list[str]
    pipes: list[str]

    @property
    def output_format(self) -> str | None:
        for p in self.pipes:
            for fmt, rx in FORMAT_PIPES.items():
                if rx.search(p.strip()):
                    return fmt
        return None

    @property
    def filtered(self) -> bool:
        return any(
            FILTER_PIPES.search(p.strip()) and not p.strip().lower().startswith(("no-more", "nomore"))
            for p in self.pipes
        )


def split_command(command: str) -> CommandLine:
    """Split ``show bgp summary | i Estab`` into base command and modifiers."""
    raw = command.strip()
    parts = [p.strip() for p in re.split(r"\s\|\s?|\|\s", raw)]
    base = " ".join(parts[0].split())
    return CommandLine(raw=raw, base=base, tokens=base.split(), pipes=[p for p in parts[1:] if p])


def slugify(command: str) -> str:
    """``show ip interface brief`` -> ``show_ip_interface_brief`` (fixture folder names)."""
    s = re.sub(r"<([\w\-]+)(?:\.\.\.)?>", r"\1", command)
    return re.sub(r"[^\w]+", "_", s).strip("_").lower()
