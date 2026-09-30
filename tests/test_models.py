"""Typed normalized models and their JSON Schemas."""

import json
import typing

import pytest

from clijson.cli import main
from clijson.models import INTENTS, SCHEMAS, SINGLE_RECORD, json_schema, record, validate


@pytest.mark.parametrize("intent", list(INTENTS))
def test_schema_is_valid_draft_2020_12(intent):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json_schema(intent)
    jsonschema.Draft202012Validator.check_schema(schema)
    obj = schema if intent in SINGLE_RECORD else schema["items"]
    assert obj["required"] == SCHEMAS[intent]
    assert obj["additionalProperties"] is False
    assert schema["$id"].endswith(f"/schemas/{intent}.json")


@pytest.mark.parametrize("intent", list(INTENTS))
def test_record_helper_fills_every_typed_field(intent):
    rec = record(intent)
    assert list(rec) == list(typing.get_type_hints(INTENTS[intent]))


def test_union_and_annotated_types_map_to_json_types():
    props = json_schema("bgp.summary")["items"]["properties"]
    assert props["remote_as"]["type"] == ["integer", "string"]
    assert props["established"] == {"type": "boolean", "description": "True when the session is Established"}
    assert props["prefixes_received"]["type"] == ["integer", "null"]
    routes = json_schema("routes")
    assert routes["items"]["properties"]["next_hops"] == {"type": "array", "items": {"$ref": "#/$defs/NextHop"}}
    assert set(routes["$defs"]["NextHop"]["properties"]) == {"next_hop", "interface"}


def test_single_record_model_is_an_object():
    assert json_schema("system.version")["type"] == "object"
    assert json_schema("arp")["type"] == "array"


def test_validate_reports_problems():
    good = [record("lag", name="Bundle-Ether1", status="up", members=["Hu0/0/0/1"])]
    assert validate("lag", good) == []
    bad = [{"name": "Bundle-Ether1", "status": 1, "members": ["x", 2], "extra": True}]
    problems = validate("lag", bad)
    assert "$[0].status: expected string, got int 1" in problems
    assert "$[0].members[1]: expected string, got int 2" in problems
    assert "$[0]: unexpected field 'extra'" in problems
    assert validate("system.version", [])[0].startswith("$: expected object")
    # bool is not an integer in JSON Schema
    assert validate("cpu", [record("cpu", one_minute=True)]) == [
        "$[0].one_minute: expected integer or null, got bool True"
    ]


def test_unknown_intent():
    with pytest.raises(KeyError, match="unknown intent"):
        json_schema("nope")


def test_cli_schema_list_print_export_check(tmp_path, capsys):
    assert main(["schema", "-f", "json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [r["intent"] for r in listed] == list(INTENTS)

    assert main(["schema", "arp"]) == 0
    assert json.loads(capsys.readouterr().out) == json_schema("arp")

    assert main(["schema", "--out", str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(f"{i}.json" for i in INTENTS)

    data = tmp_path / "data.json"
    data.write_text(json.dumps([record("vrfs", name="A", rd="1:1", interfaces=[])]))
    assert main(["schema", "vrfs", "--check", str(data)]) == 0
    data.write_text(json.dumps([{"name": 1}]))
    assert main(["schema", "vrfs", "--check", str(data)]) == 1
    assert "invalid" in capsys.readouterr().err

    with pytest.raises(SystemExit, match="unknown intent"):
        main(["schema", "nope"])


def test_committed_schemas_are_current():
    from pathlib import Path

    folder = Path(__file__).resolve().parents[1] / "schemas"
    for intent in INTENTS:
        on_disk = json.loads((folder / f"{intent}.json").read_text(encoding="utf-8"))
        assert on_disk == json_schema(intent), f"run scripts/gen_docs.py to refresh schemas/{intent}.json"
