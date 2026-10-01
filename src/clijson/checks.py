"""Health checks on normalized data, for pre/post change verification.

    >>> r = clijson.parse(text, "show l2vpn bridge-domain detail", "iosxr", normalize=True)
    >>> report = clijson.checks.pseudowire_redundancy(r.normalized)
    >>> report.ok, report.problems
    (True, [])

The checks work on the vendor-neutral models, so the same call verifies Cisco IOS XR, Juniper Junos and Huawei
VRP output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = ["RedundancyReport", "ServiceStatus", "pseudowire_redundancy"]


@dataclass
class ServiceStatus:
    """Redundancy state of one service (VSI, bridge-domain, xconnect or attachment circuit) and PW ID."""

    service: str | None
    pw_id: int | None
    active: list[str] = field(default_factory=list)
    standby: list[str] = field(default_factory=list)
    down: list[str] = field(default_factory=list)
    redundant: bool = False


@dataclass
class RedundancyReport:
    """Outcome of :func:`pseudowire_redundancy`."""

    ok: bool
    problems: list[str]
    services: list[ServiceStatus]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def pseudowire_redundancy(records: list[dict[str, Any]] | None, require_backup: bool = False) -> RedundancyReport:
    """Check ``l2vpn.pseudowires`` records: one forwarding PW per service, backups in standby, nothing down.

    :param records: ``result.normalized`` of a pseudowire command (``l2vpn.pseudowires`` model)
    :param require_backup: also report services that have no standby / backup pseudowire at all
    """
    rows = records or []
    groups: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for pw in rows:
        groups.setdefault((pw.get("service"), pw.get("pw_id")), []).append(pw)

    problems: list[str] = []
    services: list[ServiceStatus] = []
    for (service, pw_id), group in groups.items():
        label = f"{service or '?'} (pw-id {pw_id})" if pw_id is not None else str(service or "?")
        st = ServiceStatus(service=service, pw_id=pw_id)
        for pw in group:
            nbr = str(pw.get("neighbor"))
            if pw.get("active"):
                st.active.append(nbr)
            elif pw.get("state") == "standby":
                st.standby.append(nbr)
            else:
                st.down.append(nbr)
            if pw.get("role") == "backup" and pw.get("state") not in ("standby", "up"):
                problems.append(f"{label}: backup pseudowire to {nbr} is {pw.get('state')}, expected standby")
        st.redundant = len(st.active) == 1 and bool(st.standby)
        if len(st.active) == 0:
            problems.append(f"{label}: no forwarding pseudowire")
        elif len(st.active) > 1 and any(pw.get("role") for pw in group):
            problems.append(f"{label}: {len(st.active)} pseudowires forwarding at once ({', '.join(st.active)})")
        for nbr in st.down:
            if not any(f"to {nbr} is" in p and p.startswith(label) for p in problems):
                problems.append(f"{label}: pseudowire to {nbr} is down")
        if require_backup and not st.standby and len(group) < 2:
            problems.append(f"{label}: no backup pseudowire")
        services.append(st)
    if not rows:
        problems.append("no pseudowires found in the output")
    return RedundancyReport(ok=not problems, problems=problems, services=services)
