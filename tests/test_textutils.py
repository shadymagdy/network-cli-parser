import pytest

from clijson.textutils import (
    clean_output,
    compact,
    kv_pairs,
    normalize_mac,
    parse_duration,
    parse_table,
    slice_row,
    snake,
    split_columns,
    to_num,
)


@pytest.mark.parametrize(
    "value,expected",
    [("42", 42), ("-3", -3), ("1.5", 1.5), ("1,024", 1024), ("0010", "0010"), ("abc", "abc"), (7, 7), ("10.0.0.1", "10.0.0.1")],
)
def test_to_num(value, expected):
    assert to_num(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("01:02:03", 3723),
        ("1d02h", 93600),
        ("3w4d", 3 * 604800 + 4 * 86400),
        ("1y11w", 31536000 + 11 * 604800),
        ("626h43m", 626 * 3600 + 43 * 60),
        ("1d01h58m07s", 86400 + 3600 + 58 * 60 + 7),
        ("4 weeks, 6 days, 1 hour, 42 minutes", 4 * 604800 + 6 * 86400 + 3600 + 42 * 60),
        ("5 days, 3 hours, 24 minutes, 13 seconds", 5 * 86400 + 3 * 3600 + 24 * 60 + 13),
        ("3w2d 04:19:15", 3 * 604800 + 2 * 86400 + 4 * 3600 + 19 * 60 + 15),
        ("never", None),
        ("-", None),
        ("gibberish", None),
    ],
)
def test_parse_duration(value, expected):
    assert parse_duration(value) == expected


@pytest.mark.parametrize("mac", ["aabb.cc00.6500", "aa:bb:cc:00:65:00", "AABB-CC00-6500", "aa-bb-cc-00-65-00"])
def test_normalize_mac(mac):
    assert normalize_mac(mac) == "aa:bb:cc:00:65:00"


def test_normalize_mac_passthrough():
    assert normalize_mac("not-a-mac") == "not-a-mac"
    assert normalize_mac(None) is None


def test_snake():
    assert snake("Up Time (secs)") == "up_time_secs"
    assert snake("IP-Address") == "ip_address"
    assert snake("MsgRcvd") == "msg_rcvd"
    assert snake("St/PfxRcd") == "st_pfx_rcd"
    assert snake("#Active") == "num_active"


def test_clean_output_removes_noise():
    raw = "line1\r\n\x1b[32mgreen\x1b[0m\r\n --More-- \r\nline3\t tab\n"
    assert [ln for ln in clean_output(raw).splitlines() if ln] == ["line1", "green", "line3     tab"]


def test_clean_output_dedents():
    assert clean_output("    a\n      b\n") == "a\n  b"


def test_parse_table_and_slice():
    text = "Interface   Status   Description\nGi0/0/0/0   up       to core 1\nGi0/0/0/1   down\n"
    rows = parse_table(text)
    assert rows == [
        {"interface": "Gi0/0/0/0", "status": "up", "description": "to core 1"},
        {"interface": "Gi0/0/0/1", "status": "down", "description": None},
    ]
    assert slice_row("abcdef ghi jkl", [0, 5, 10]) == ["abcdef", "ghi", "jkl"]


def test_split_columns_and_kv():
    assert split_columns("a b   c d    e") == ["a b", "c d", "e"]
    assert kv_pairs("Speed: 1000  Duplex: full\nMTU: 1500") == {"speed": 1000, "duplex": "full", "mtu": 1500}


def test_compact():
    assert compact({"a": None, "b": [], "c": {"d": None}, "e": 0, "f": [1, None]}) == {"e": 0, "f": [1]}
