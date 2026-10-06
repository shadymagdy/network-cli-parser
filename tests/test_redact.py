"""G-2: secret redaction, and G-3: the public NSO unwrap API."""

import json
from types import SimpleNamespace

import pytest

import clijson
import clijson.nso
import clijson.textutils

SECRETS = ("$9$abcDEF123", "$6$salt$hash", "$1$aa$bb", "0822455D0A16", "public", "s3cr3t", "%^%#xyz%^%#", "$9$psk")


def _leaks(obj) -> list[str]:
    blob = json.dumps(obj) if not isinstance(obj, str) else obj
    return [s for s in SECRETS if s in blob]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # Junos set format
        (
            'set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$abcDEF123"',
            'set protocols bgp group G neighbor 198.51.100.1 authentication-key "<redacted>"',
        ),
        (
            'set system root-authentication encrypted-password "$6$salt$hash"',
            'set system root-authentication encrypted-password "<redacted>"',
        ),
        (
            'set security ike policy P pre-shared-key ascii-text "$9$psk"',
            'set security ike policy P pre-shared-key ascii-text "<redacted>"',
        ),
        ("set snmp community public authorization read-only", "set snmp community <redacted> authorization read-only"),
        ('set system services foo secret "s3cr3t"', 'set system services foo secret "<redacted>"'),
        (
            "set system login user ops authentication password s3cr3t",
            "set system login user ops authentication password <redacted>",
        ),
        # crypt strings anywhere
        ("hash $1$aa$bb end", "hash <redacted> end"),
        # IOS XR
        (" secret 10 $6$salt$hash", " secret 10 <redacted>"),
        ("  password encrypted 0822455D0A16", "  password encrypted <redacted>"),
        ("  key-string password 7 0822455D0A16", "  key-string password 7 <redacted>"),
        (" key 7 0822455D0A16", " key 7 <redacted>"),
        ("snmp-server community public RO", "snmp-server community <redacted> RO"),
        # Huawei VRP
        (" local-user admin password cipher %^%#xyz%^%#", " local-user admin password cipher <redacted>"),
        (" authentication-mode md5 cipher %^%#xyz%^%#", " authentication-mode md5 cipher <redacted>"),
        ("snmp-agent community read cipher %^%#xyz%^%#", "snmp-agent community read cipher <redacted>"),
        ("snmp-agent community write public", "snmp-agent community write <redacted>"),
    ],
)
def test_each_secret_form_is_masked(line, expected):
    assert clijson.redact(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "set policy-options community COMM-A members 65000:100",
        "ssh server cipher aes256_ctr aes128_ctr",
        " description password-policy test",
        "set protocols isis interface ae0.0 level 2 hello-authentication-key-chain KC",
        "key chain KC",
        " key 1",
    ],
)
def test_non_secrets_are_left_alone(line):
    assert clijson.redact(line) == line


JUNOS_BRACES = """system {
    root-authentication {
        encrypted-password "$6$salt$hash"; ## SECRET-DATA
    }
}
snmp {
    community public {
        authorization read-only;
    }
}
policy-options {
    community COMM-A members 65000:100;
}
protocols {
    bgp {
        group G {
            neighbor 198.51.100.1 {
                authentication-key "$9$abcDEF123"; ## SECRET-DATA
            }
        }
    }
}
"""

JUNOS_SET = """set system root-authentication encrypted-password "$6$salt$hash"
set snmp community public authorization read-only
set policy-options community COMM-A members 65000:100
set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$abcDEF123"
"""


@pytest.mark.parametrize(
    ("text", "command"), [(JUNOS_BRACES, "show configuration"), (JUNOS_SET, "show configuration | display set")]
)
def test_junos_config_parses_the_same_with_secrets_masked(text, command):
    plain = clijson.parse(text, command, "junos")
    masked = clijson.parse(text, command, "junos", redact=True)
    assert _leaks(plain.data)  # sanity: today's behaviour without redact
    assert _leaks(masked.data) == [] and _leaks(masked.raw) == []
    assert masked.metadata["redacted"] is True
    assert "redacted" not in plain.metadata
    # same tree shape; only the secret values differ
    assert json.dumps(masked.data).count("<redacted>") == 3
    bgp = masked.data["protocols"]["bgp"]["group"]["G"]["neighbor"]["198.51.100.1"]
    assert bgp["authentication-key"] == "<redacted>"
    assert "COMM-A" in json.dumps(masked.data["policy-options"])
    assert "<redacted>" in masked.data["snmp"]["community"]


def test_iosxr_and_vrp_configs_keep_parsing():
    xr = "username admin\n secret 10 $6$salt$hash\n!\nsnmp-server community public RO\n!\n"
    res = clijson.parse(xr, "show running-config", "iosxr", redact=True)
    assert _leaks(res.data) == [] and res.engine == "native"
    vrp = "#\naaa\n local-user admin password cipher %^%#xyz%^%#\n#\nsnmp-agent community read cipher %^%#xyz%^%#\n#\n"
    res = clijson.parse(vrp, "display current-configuration", "vrp", redact=True)
    assert _leaks(res.data) == [] and res.engine == "native"


def test_redact_reaches_raw_nso_show_show_many_and_parse_file(tmp_path):
    out = 'set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$abcDEF123"\r\n'

    class ExecAny:
        def get_input(self):
            return SimpleNamespace(args=None)

        def __call__(self, inp):
            return SimpleNamespace(result=out)

    device = SimpleNamespace(
        name="pe1",
        live_status=SimpleNamespace(junos_stats__exec=SimpleNamespace(any=ExecAny())),
        platform=SimpleNamespace(name="junos"),
    )
    cmd = "show configuration | display set"
    res = clijson.nso.show(device, cmd, redact=True)
    assert _leaks(res.data) == [] and _leaks(res.raw) == [] and res.metadata["redacted"] is True
    many = clijson.nso.show_many(device, [cmd], redact=True)
    assert _leaks(many[cmd].data) == []
    assert _leaks(clijson.nso.show(device, cmd).data)  # off by default

    path = tmp_path / "capture.txt"
    path.write_text(out)
    res = clijson.parse_file(path, cmd, "junos", redact=True)
    assert _leaks(res.data) == [] and res.metadata["redacted"] is True


def test_redact_inside_an_nso_json_payload():
    inner = 'set system root-authentication encrypted-password "$6$salt$hash"\r\nadmin@pe1> '
    payload = json.dumps({"junos-stats:output": {"result": inner}})
    res = clijson.parse(payload, "show configuration | display set", "junos", redact=True)
    assert _leaks(res.data) == [] and _leaks(res.raw) == []
    assert json.loads(res.raw)  # the payload is still valid JSON


def test_redact_is_linear_on_hostile_input():
    import time

    hostile = "secret " + "1 " * 100_000 + "{\n" + "password " * 50_000 + "\n" + "$9$" * 100_000
    start = time.perf_counter()
    clijson.redact(hostile)
    assert time.perf_counter() - start < 2


# --------------------------------------------------------------------------- #
# G-3: public unwrap
# --------------------------------------------------------------------------- #

BGP_ROW = "198.51.100.125        64500     711028     681994       0      29 32w2d 5:03:14 Establ"


@pytest.mark.parametrize(
    "payload",
    [
        json.dumps({"junos-stats:output": {"result": BGP_ROW + "\r\n"}}),
        f"<output><result>{BGP_ROW}</result></output>",
        f'admin@ncs# devices device pe1 live-status exec any "show bgp summary"\nresult \n{BGP_ROW}\nadmin@ncs# ',
        json.dumps({"jsonrpc": "2.0", "result": [{"name": "result", "value": BGP_ROW}]}).encode(),
    ],
    ids=["restconf-json", "xml", "ncs-cli", "json-rpc-bytes"],
)
def test_public_unwrap_returns_the_device_text(payload):
    assert clijson.nso.unwrap(payload).strip() == BGP_ROW
    assert clijson.textutils.unwrap_nso(payload).strip() == BGP_ROW


def test_unwrap_leaves_plain_text_alone_and_private_alias_still_works():
    assert clijson.nso.unwrap(BGP_ROW) == BGP_ROW
    from clijson._nso_wrap import unwrap as private_unwrap

    assert private_unwrap(json.dumps({"result": BGP_ROW})).text == BGP_ROW
