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
