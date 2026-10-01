"""clijson.checks: redundancy verdicts on normalized pseudowires."""

import clijson
from clijson.models import record


def pw(neighbor, state, role=None, service="BD1", pw_id=10):
    return record(
        "l2vpn.pseudowires",
        service=service,
        neighbor=neighbor,
        pw_id=pw_id,
        state=state,
        role=role,
        active=state == "up",
    )


def test_healthy_primary_and_standby_backup():
    report = clijson.checks.pseudowire_redundancy(
        [pw("192.0.2.1", "up", "primary"), pw("192.0.2.2", "standby", "backup")]
    )
    assert report.ok
    assert report.services[0].redundant


def test_backup_down_is_reported():
    report = clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "up", "primary"), pw("192.0.2.2", "down", "backup")])
    assert not report.ok
    assert report.problems == ["BD1 (pw-id 10): backup pseudowire to 192.0.2.2 is down, expected standby"]


def test_no_forwarding_pseudowire():
    report = clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "down"), pw("192.0.2.2", "standby", "backup")])
    assert "BD1 (pw-id 10): no forwarding pseudowire" in report.problems


def test_two_forwarding_with_redundancy_configured():
    report = clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "up", "primary"), pw("192.0.2.2", "up", "backup")])
    assert any("2 pseudowires forwarding" in p for p in report.problems)


def test_vpls_full_mesh_is_fine():
    """Several forwarding PWs without redundancy roles (a VFI mesh) are normal."""
    report = clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "up"), pw("192.0.2.2", "up")])
    assert report.ok


def test_require_backup_and_empty_input():
    assert not clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "up")], require_backup=True).ok
    assert clijson.checks.pseudowire_redundancy([]).problems == ["no pseudowires found in the output"]
    assert clijson.checks.pseudowire_redundancy([pw("192.0.2.1", "up")]).to_dict()["ok"] is True
