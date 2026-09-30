"""Regression corpus: real device output -> expected JSON (see scripts/fixture.py)."""

import pytest

import clijson
from clijson.models import SCHEMAS

from .conftest import fixture_cases, read_json


@pytest.mark.parametrize("txt,js", list(fixture_cases()))
def test_fixture(txt, js):
    meta = read_json(js)
    res = clijson.parse(txt.read_text(encoding="utf-8"), meta["command"], meta["platform"], normalize=True)
    assert res.engine == "native", res.warnings
    assert res.warnings == []
    assert res.data == meta["expected"]
    if "normalized" in meta:
        assert res.normalized == meta["normalized"]


@pytest.mark.parametrize("txt,js", list(fixture_cases()))
def test_fixture_autodetect(txt, js):
    """Without telling the library the platform, detection must not pick a wrong one."""
    meta = read_json(js)
    res = clijson.parse(txt.read_text(encoding="utf-8"), meta["command"])
    assert res.platform in (meta["platform"], None)


@pytest.mark.parametrize("txt,js", [c for c in fixture_cases() if "normalized" in read_json(c.values[1])])
def test_normalized_schema(txt, js):
    meta = read_json(js)
    res = clijson.parse(txt.read_text(encoding="utf-8"), meta["command"], meta["platform"], normalize=True)
    keys = SCHEMAS[res.intent]
    records = res.normalized if isinstance(res.normalized, list) else [res.normalized]
    for rec in records:
        assert list(rec) == keys


def test_corpus_covers_every_platform():
    platforms = {read_json(c.values[1])["platform"] for c in fixture_cases()}
    assert platforms == {"iosxr", "junos", "vrp"}
