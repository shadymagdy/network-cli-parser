"""Every dedicated parser must survive every capture in the corpus (wrong command, other vendor, ...)."""

import json
import time
from pathlib import Path

import pytest

from clijson.registry import REGISTRY

FIXTURES = Path(__file__).parent / "fixtures"
TEXTS = [p.read_text(encoding="utf-8") for p in sorted(FIXTURES.rglob("*.txt"))]
PARSERS = sorted({e.parser for e in REGISTRY.entries()}, key=lambda c: c.name)


@pytest.mark.parametrize("parser", PARSERS, ids=[p.name for p in PARSERS])
def test_parser_never_crashes_and_emits_json(parser):
    start = time.perf_counter()
    for text in TEXTS + ["", "\n\n", "% Invalid input detected at '^' marker."]:
        data = parser({}, "").parse(text)
        json.dumps(data)
    assert time.perf_counter() - start < 5, "parser is too slow on the corpus"


def test_every_parser_has_a_description_and_platform():
    for p in PARSERS:
        assert p.description, p.name
        assert p.platform in ("iosxr", "junos", "vrp")


@pytest.mark.parametrize(
    "text",
    [
        "\n".join(" " * i + f"k{i}: v" for i in range(3000)),  # pathological indentation
        "a {\n" * 500 + "}\n" * 500,  # deeply nested braces
        "word " * 50000,  # one enormous line
        "x" * 100000,
        "\x1b[31m" * 1000 + "\x08" * 1000,  # control characters only
    ],
    ids=["deep-indent", "deep-braces", "long-line", "no-spaces", "control-chars"],
)
def test_pathological_inputs_do_not_crash(text):
    import clijson

    for command, platform in [("show configuration", "junos"), ("show running-config", "iosxr"), ("show something", "iosxr"), (None, None)]:
        res = clijson.parse(text, command, platform)
        json.dumps(res.to_dict())


ADVERSARIAL = {
    "deep-indent": "\n".join(" " * i + f"k{i}: v" for i in range(1500)),
    "long-line": "word " * 20000,
    "no-spaces": "x" * 50000,
    "digits": "1 " * 20000,
    "colons": "a: b " * 10000,
    "ip-soup": " ".join(f"10.0.{i % 256}.{i % 200}" for i in range(10000)),
    "blank-lines": "\n \n" * 20000 + "x",
}


@pytest.mark.parametrize("parser", PARSERS, ids=[p.name for p in PARSERS])
def test_parser_has_no_catastrophic_backtracking(parser):
    for name, text in ADVERSARIAL.items():
        start = time.perf_counter()
        parser({}, "").parse(text)
        assert time.perf_counter() - start < 2, f"{parser.name} is super-linear on {name!r}"
