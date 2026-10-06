"""Check configuration statements in a parsed configuration tree, the same way on every platform.

Configuration commands (Junos ``show configuration`` in ``{ }`` or ``| display set`` form, IOS XR
``show running-config``, Huawei ``display current-configuration``) parse into nested trees. These helpers work on
any of them::

    res = clijson.parse(text, "show configuration | display set", "junos")
    clijson.config.has(res, "routing-instances VRF-B interface ae24.100")  # True / False
    clijson.config.lines(res)
    # ['routing-instances VRF-B interface ae24.100', 'routing-instances VRF-B instance-type virtual-router', ...]

Statements are compared word by word, so it does not matter how the tree grouped the words
(``"group GRP-A"`` is one key on IOS XR, two levels on Junos), how much whitespace there is, or whether a value
was quoted.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .result import ParseResult

__all__ = ["has", "lines"]


def lines(result: ParseResult | dict[str, Any]) -> list[str]:
    """Flatten a configuration tree into one full-path line per statement, in tree order.

    A leaf value becomes the last words of its line; a list gives one line per item; a flag (``True``) ends at its
    key. On Junos, values containing spaces are quoted like ``display set`` does.
    """
    tree = result.data if isinstance(result, ParseResult) else result
    quote = isinstance(result, ParseResult) and result.platform == "junos"
    if not isinstance(tree, dict):
        return []
    return [" ".join(_word(w, quote) for w in path) for path in _walk(tree, [])]


def has(result: ParseResult | dict[str, Any], statement: str, *, anchored: bool = True) -> bool:
    """Whether the configuration contains *statement*.

    :param anchored: ``True`` (default): *statement* is matched from the root of the hierarchy, on whole words,
        so ``"routing-instances VRF-B interface ae24.100"`` matches that statement and ``"routing-instances VRF-B"``
        matches the container, while ``"VRF-B interface ae24.100"`` does not. ``False``: the words may appear
        anywhere in a statement, still as whole words.
    """
    want = _words(statement)
    if not want:
        return False
    tree = result.data if isinstance(result, ParseResult) else result
    if not isinstance(tree, dict):
        return False
    n = len(want)
    for path in _walk(tree, []):
        got = [w for part in path for w in _words(part)]
        if anchored:
            if got[:n] == want:
                return True
        elif any(got[i : i + n] == want for i in range(len(got) - n + 1)):
            return True
    return False


def _walk(node: Any, path: list[str]) -> Iterator[list[str]]:
    if isinstance(node, dict):
        if not node:
            yield path
        for key, value in node.items():
            yield from _walk(value, [*path, str(key)])
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, path)
    elif node is True or node is None or node == "":
        yield path
    elif node is not False:
        yield [*path, str(node)]


def _words(text: str) -> list[str]:
    return [w.strip("\"'") for w in str(text).split() if w.strip("\"'")]


def _word(part: str, quote: bool) -> str:
    return f'"{part}"' if quote and any(c.isspace() for c in part) and not part.startswith('"') else part
