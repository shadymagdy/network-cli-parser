import json
from pathlib import Path

from clijson.cli import main
from clijson.server import handle

DATA = Path(__file__).parent / "data"


def test_cli_parse_file(capsys):
    assert main(["parse", str(DATA / "xr_session.log"), "-f", "json-compact"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [x["command"] for x in out] == ["show version", "show ipv4 interface brief", "show bgp summary"]


def test_cli_shorthand_and_normalize(capsys, tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("Neighbor ID     Pri   State           Dead Time   Address         Interface\n1.1.1.1         1     FULL/DR         00:00:39    10.1.2.1        Gi0/0/0/1\n")
    assert main([str(f), "-c", "show ospf neighbor", "-p", "xr", "-n", "-f", "json-compact"]) == 0
    assert json.loads(capsys.readouterr().out) == [{"neighbor_id": "1.1.1.1", "priority": 1, "state": "full", "address": "10.1.2.1", "interface": "Gi0/0/0/1", "dead_time": "00:00:39"}]


def test_cli_meta_and_table(capsys, tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("Interface   Admin Link Description\nge-0/0/0    up    up   uplink\n")
    assert main(["parse", str(f), "-c", "show interfaces descriptions", "-p", "junos", "-m", "-f", "json-compact"]) == 0
    meta = json.loads(capsys.readouterr().out)
    assert meta["parser"] == "junos.show_interfaces_descriptions"
    assert main(["parse", str(f), "-c", "show interfaces descriptions", "-p", "junos", "-f", "table"]) == 0
    assert "uplink" in capsys.readouterr().out


def test_cli_commands_detect_platforms_version(capsys):
    assert main(["commands", "-p", "vrp", "-s", "lldp", "-f", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows and all("lldp" in r["command"] for r in rows)
    assert main(["detect", str(DATA / "xr_session.log")]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "iosxr"
    assert main(["platforms", "-f", "json"]) == 0
    assert {p["name"] for p in json.loads(capsys.readouterr().out)} == {"iosxr", "junos", "vrp"}
    assert main(["version"]) == 0
    assert json.loads(capsys.readouterr().out)["engines"]["native"] is True


def test_cli_unknown_platform_is_reported(capsys, tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("x")
    assert main(["parse", str(f), "-p", "nope", "-c", "show x"]) == 2
    assert "Unknown platform" in capsys.readouterr().err


def test_http_handler():
    code, body = handle("GET", "/health", b"")
    assert code == 200 and body["status"] == "ok"
    code, body = handle("POST", "/parse", json.dumps({"output": "<R1>display clock\n2024-05-14 10:20:31+08:00\nTuesday\n", "normalize": True}).encode())
    assert code == 200 and body["platform"] == "vrp" and body["data"]["weekday"] == "Tuesday"
    assert handle("POST", "/parse", b"{bad json")[0] == 400
    assert handle("POST", "/parse", b'{"nope": 1}')[0] == 400
    assert handle("POST", "/parse", b'{"output": "x", "platform": "zzz"}')[0] == 422
    code, body = handle("GET", "/commands?platform=junos", b"")
    assert code == 200 and body["commands"]
    assert handle("GET", "/nowhere", b"")[0] == 404
