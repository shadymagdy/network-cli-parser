"""Live collection: library selection and the scrapli 2.x guard (no device needed)."""

import sys
import types

import pytest

import clijson.live
from clijson.exceptions import DeviceError


def _block(monkeypatch, name):
    monkeypatch.setitem(sys.modules, name, None)  # importing it raises ImportError


def test_scrapli_2_is_reported_clearly(monkeypatch):
    """scrapli 2.x (2026.10+) has no ``Scrapli`` factory; say so instead of claiming nothing is installed."""
    fake = types.ModuleType("scrapli")
    fake.Cli = object  # the 2.x entry point
    monkeypatch.setitem(sys.modules, "scrapli", fake)
    _block(monkeypatch, "netmiko")
    with pytest.raises(DeviceError, match=r"scrapli 2\.x .* pip install 'scrapli<2026\.10'"):
        clijson.live.collect("192.0.2.1", "junos", "show version")


def test_nothing_installed_message(monkeypatch):
    _block(monkeypatch, "scrapli")
    _block(monkeypatch, "netmiko")
    with pytest.raises(DeviceError, match="live collection needs scrapli or netmiko"):
        clijson.live.collect("192.0.2.1", "junos", "show version")


def test_scrapli_1_api_is_used(monkeypatch):
    calls = {}

    class Response:
        def __init__(self, result):
            self.result = result

    class Conn:
        def __init__(self, **params):
            calls["params"] = params

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_commands(self, cmds):
            calls["cmds"] = cmds
            return [Response("Hostname: pe1\nModel: mx204\nJunos: 23.4R1.9\n") for _ in cmds]

    fake = types.ModuleType("scrapli")
    fake.Scrapli = Conn
    monkeypatch.setitem(sys.modules, "scrapli", fake)
    (res,) = clijson.live.collect("192.0.2.1", "junos", "show version", username="u", password="p")
    assert calls["cmds"] == ["show version"]
    assert calls["params"]["platform"] == "juniper_junos" and calls["params"]["host"] == "192.0.2.1"
    assert res.platform == "junos" and res.metadata["hostname"] == "192.0.2.1"
