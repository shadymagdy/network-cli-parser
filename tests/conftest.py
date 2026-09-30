import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_cases():
    for js in sorted(FIXTURES.rglob("*.json")):
        txt = js.with_suffix(".txt")
        if txt.exists():
            yield pytest.param(txt, js, id=str(js.relative_to(FIXTURES).with_suffix("")))


@pytest.fixture
def load():
    def _load(rel: str) -> str:
        return (FIXTURES / rel).read_text(encoding="utf-8")

    return _load


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
