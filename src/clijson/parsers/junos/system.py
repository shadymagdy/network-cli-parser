"""Junos system and chassis commands."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import record, seconds
from ...registry import Parser, register
from ...textutils import compact, match_lines, split_columns, to_num
from .common import split_re_sections


@register("junos", "show version [(detail|brief)] [invoke-on (all-routing-engines|other-routing-engine)]", "show version (all-members|local|member <member>)", intent="system.version")
class ShowVersion(Parser):
    """Hostname, model, Junos release and installed packages (per member/RE)."""

    def parse(self, text: str) -> Dict[str, Any]:
        members: Dict[str, Any] = {}
        for name, body in split_re_sections(text):
            info: Dict[str, Any] = {}
            packages: List[Dict[str, str]] = []
            for ln in body.splitlines():
                s = ln.strip()
                m = re.match(r"^(Hostname|Model|Junos|Family|JUNOS OS Kernel|Junos Version):\s*(.+)$", s)
                if m:
                    key = {"Hostname": "hostname", "Model": "model", "Junos": "version", "Family": "family", "Junos Version": "version"}.get(m.group(1), m.group(1).lower().replace(" ", "_"))
                    info[key] = m.group(2).strip()
                    continue
                m = re.match(r"^(?P<name>(?:JUNOS|Junos|junos|JUNOS OS)[^\[]*?)\s*\[(?P<ver>[^\]]+)\]\s*$", s)
                if m:
                    packages.append({"name": m["name"].strip(), "version": m["ver"]})
                    if "version" not in info and re.match(r"^\d+\.\d+[A-Z]", m["ver"]) and re.search(r"Base OS|Software Suite|Software Release|Kernel|telemetry", m["name"]):
                        info["version"] = m["ver"]
                    continue
                m = re.match(r"^(?P<name>[A-Za-z][^\[]*?)\s*\[(?P<ver>[^\]]+)\]\s*$", s)
                if m:
                    packages.append({"name": m["name"].strip(), "version": m["ver"]})
            if packages:
                info["packages"] = packages
            if info:
                members[name or "local"] = info
        if len(members) == 1:
            return next(iter(members.values()))
        first = next(iter(members.values()), {})
        return {"hostname": first.get("hostname"), "model": first.get("model"), "version": first.get("version"), "members": members}

    def normalize(self, d: Dict[str, Any]) -> Dict[str, Any]:
        return record("system.version", hostname=d.get("hostname"), vendor="Juniper", os="Junos", version=d.get("version"), model=d.get("model"))


@register("junos", "show system uptime [(all-members|invoke-on all-routing-engines|no-forwarding)]")
class ShowSystemUptime(Parser):
    """Current time, boot/protocol start times, last commit and load averages."""

    def parse(self, text: str) -> Dict[str, Any]:
        members: Dict[str, Any] = {}
        for name, body in split_re_sections(text):
            d: Dict[str, Any] = {}
            for ln in body.splitlines():
                s = ln.strip()
                m = re.match(r"^Current time:\s*(?P<t>.+)$", s)
                if m:
                    d["current_time"] = m["t"]
                    continue
                m = re.match(r"^Time Source:\s*(?P<t>.+)$", s)
                if m:
                    d["time_source"] = m["t"].strip()
                    continue
                m = re.match(r"^(?P<what>System booted|Protocols started|Last configured):\s*(?P<t>.+?)(?:\s+\((?P<ago>[^)]+) ago\))?(?:\s+by\s+(?P<by>\S+))?$", s)
                if m:
                    key = m["what"].lower().replace(" ", "_")
                    d[key] = m["t"]
                    if m["ago"]:
                        d[key + "_ago"] = m["ago"]
                        d[key + "_ago_seconds"] = junos_ago_seconds(m["ago"])
                    if m["by"]:
                        d["last_configured_by"] = m["by"]
                    continue
                m = re.match(r"^(?P<time>\d+:\d+[AP]M)\s+up\s+(?P<up>.+?),\s+(?P<users>\d+) users?,\s+load averages?:\s*(?P<l1>[\d.]+),\s*(?P<l5>[\d.]+),\s*(?P<l15>[\d.]+)", s)
                if m:
                    d["uptime"] = m["up"]
                    d["uptime_seconds"] = _uptime_seconds(m["up"])
                    d["users"] = int(m["users"])
                    d["load_average"] = {"1min": float(m["l1"]), "5min": float(m["l5"]), "15min": float(m["l15"])}
            members[name or "local"] = compact(d)
        return next(iter(members.values())) if len(members) == 1 else {"members": members}


def junos_ago_seconds(ago: str) -> Optional[int]:
    """``29w6d 23:14`` (hh:mm) / ``11:03:05`` (hh:mm:ss) -> seconds."""
    m = re.match(r"^\s*(?:(\d+)w)?(?:(\d+)d)?\s*(?:(\d+):(\d+)(?::(\d+))?)?\s*$", ago)
    if not m or not any(m.groups()):
        return None
    w, d, h, mi, sec = (int(x) if x else 0 for x in m.groups())
    return w * 604800 + d * 86400 + h * 3600 + mi * 60 + sec


def _uptime_seconds(up: str) -> Optional[int]:
    """``209 days, 23:14`` / ``15 days, 5 mins`` / ``11:03`` -> seconds."""
    total = 0
    m = re.search(r"(\d+)\s+days?", up)
    if m:
        total += int(m.group(1)) * 86400
    m = re.search(r"(\d+):(\d+)", up)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60
    m = re.search(r"(\d+)\s+hrs?", up)
    if m:
        total += int(m.group(1)) * 3600
    m = re.search(r"(\d+)\s+mins?", up)
    if m:
        total += int(m.group(1)) * 60
    m = re.search(r"(\d+)\s+secs?", up)
    if m:
        total += int(m.group(1))
    return total


@register("junos", "show chassis hardware [(detail|extensive|models|clei-models)] [no-forwarding]", intent="inventory")
class ShowChassisHardware(Parser):
    """Hardware inventory as a component tree (chassis -> FPC -> PIC -> Xcvr)."""

    def parse(self, text: str) -> Dict[str, Any]:
        members: Dict[str, Any] = {}
        for name, body in split_re_sections(text):
            lines = body.splitlines()
            hdr = next((i for i, ln in enumerate(lines) if re.match(r"^\s*Item\s+Version\s+Part number", ln)), None)
            if hdr is None:
                continue
            header = lines[hdr]
            cols = [header.index(c) for c in ("Version", "Part number", "Serial number", "Description")]
            base = len(header) - len(header.lstrip())
            items: List[Dict[str, Any]] = []
            stack: List[tuple] = []
            for ln in lines[hdr + 1 :]:
                if not ln.strip():
                    continue
                indent = len(ln) - len(ln.lstrip()) - base
                item_name = ln[: cols[0]].strip() if len(ln) > cols[0] else ln.strip()
                # names longer than the Item column push the rest right; fall back to splitting on 2+ spaces
                if len(ln) > cols[0] and ln[cols[0] - 1] != " " and ln[cols[0]] != " ":
                    parts = split_columns(ln)
                    item_name = parts[0]
                    fields = _fields_by_regex(ln[len(ln) - len(ln.lstrip()) + len(item_name) :])
                else:
                    fields = {
                        "version": ln[cols[0] : cols[1]].strip(),
                        "part_number": ln[cols[1] : cols[2]].strip(),
                        "serial_number": ln[cols[2] : cols[3]].strip(),
                        "description": ln[cols[3] :].strip(),
                    }
                entry = {"name": item_name, **{k: (v or None) for k, v in fields.items()}}
                entry = {k: v for k, v in entry.items() if v is not None}
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                if stack:
                    stack[-1][1].setdefault("components", []).append(entry)
                else:
                    items.append(entry)
                stack.append((indent, entry))
            members[name or "local"] = items
        if len(members) == 1:
            return {"chassis": next(iter(members.values()))}
        return {"members": {k: {"chassis": v} for k, v in members.items()}}

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        def walk(items: List[Dict[str, Any]], prefix: str = "") -> None:
            for it in items:
                full = f"{prefix}{it['name']}"
                out.append(record("inventory", name=full, description=it.get("description"), part_number=it.get("part_number"), serial_number=it.get("serial_number"), version=it.get("version")))
                walk(it.get("components", []), full + " / ")

        if "chassis" in data:
            walk(data["chassis"])
        for m, v in data.get("members", {}).items():
            walk(v["chassis"], f"{m} / ")
        return out


def _fields_by_regex(rest: str) -> Dict[str, str]:
    parts = split_columns(rest)
    keys = ["version", "part_number", "serial_number", "description"]
    if len(parts) == 4:
        return dict(zip(keys, parts))
    if len(parts) == 2:
        return {"serial_number": parts[0], "description": parts[1]}
    return {"description": " ".join(parts)} if parts else {}


@register("junos", "show (chassis|system) alarms")
class ShowChassisAlarms(Parser):
    """Active chassis or system alarms."""

    def parse(self, text: str) -> Dict[str, Any]:
        alarms = []
        for m in match_lines(r"^\s*(?P<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+)\s+(?P<cls>Major|Minor|Critical|Warning|Info)\s+(?P<desc>.+?)\s*$", text):
            alarms.append({"time": m["time"], "class": m["cls"], "description": m["desc"]})
        m = re.search(r"(\d+) alarms? currently active", text)
        return {"active_count": int(m.group(1)) if m else len(alarms), "alarms": alarms}


@register("junos", "show chassis routing-engine [<slot>] [(bios|no-forwarding)]", intent="cpu")
class ShowChassisRoutingEngine(Parser):
    """Routing Engine state, CPU/memory utilisation, temperature and uptime."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        cur: Dict[str, Any] = {}
        cpu_key = "cpu_utilization"
        load_pending = False
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            m = re.match(r"^Slot (\d+):", s)
            if m:
                cur = out.setdefault(f"slot{m.group(1)}", {"slot": int(m.group(1))})
                cpu_key = "cpu_utilization"
                continue
            if s.startswith("Routing Engine status"):
                continue
            if not cur:
                cur = out.setdefault("slot0", {"slot": 0})
            m = re.match(r"^(?P<win>\d+ (?:sec|min)) CPU utilization:", s)
            if m:
                cpu_key = "cpu_utilization_" + m["win"].replace(" ", "")
                continue
            if s == "CPU utilization:":
                cpu_key = "cpu_utilization"
                continue
            m = re.match(r"^(User|Background|Kernel|Interrupt|Idle)\s+(\d+) percent", s)
            if m:
                cur.setdefault(cpu_key, {})[m.group(1).lower()] = int(m.group(2))
                continue
            if s.startswith("Load averages:"):
                load_pending = True
                continue
            if load_pending:
                vals = s.split()
                if len(vals) == 3:
                    cur["load_average"] = {"1min": float(vals[0]), "5min": float(vals[1]), "15min": float(vals[2])}
                load_pending = False
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w /-]*?)\s{2,}(?P<v>.+)$", s)
            if m:
                k = re.sub(r"[^a-z0-9]+", "_", m["k"].lower()).strip("_")
                v = m["v"].strip()
                if k in ("temperature", "cpu_temperature"):
                    tm = re.match(r"(-?\d+) degrees C", v)
                    cur[k + "_c"] = int(tm.group(1)) if tm else v
                elif k == "dram":
                    dm = re.match(r"(\d+) MB(?: \((\d+) MB installed\))?", v)
                    if dm:
                        cur["dram_mb"] = int(dm.group(1))
                        if dm.group(2):
                            cur["dram_installed_mb"] = int(dm.group(2))
                elif k.endswith("utilization") and v.endswith("percent"):
                    cur[k + "_percent"] = int(v.split()[0])
                elif k == "uptime":
                    cur["uptime"] = v
                    cur["uptime_seconds"] = seconds(v.replace(",", ""))
                else:
                    cur[k] = to_num(v)
        return out

    def normalize(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        res = []
        for v in data.values():
            cpu = v.get("cpu_utilization_1min") or v.get("cpu_utilization") or {}
            cpu5 = v.get("cpu_utilization_5min") or {}
            res.append(record("cpu", location=f"re{v.get('slot', 0)}", one_minute=(100 - cpu["idle"]) if "idle" in cpu else None, five_minute=(100 - cpu5["idle"]) if "idle" in cpu5 else None))
        return res


@register("junos", "show chassis fpc [(<slot>|pic-status|detail)]")
class ShowChassisFpc(Parser):
    """FPC state, temperature, CPU and memory utilisation (or PIC status)."""

    def parse(self, text: str) -> Any:
        if re.search(r"^[ \t]*Slot \d+\s+(Online|Offline|Empty)\s+\S", text, re.M) and "PIC" in text and "Temp" not in text:
            return self._pic_status(text)
        out = []
        for m in match_lines(
            r"^\s*(?P<slot>\d+)\s+(?P<state>Online|Offline|Empty|Present|Testing|Diag|Dead|Announce online|Spare|Fault|Resync)(?:\s+(?P<temp>\d+|Testing))?(?:\s+(?P<cpu_total>\d+)\s+(?P<cpu_int>\d+))?(?:\s+(?P<l1>\d+)\s+(?P<l5>\d+)\s+(?P<l15>\d+))?(?:\s+(?P<dram>\d+)\s+(?P<heap>\d+)\s+(?P<buf>\d+))?\s*(?P<comment>.*)$", text):
            e: Dict[str, Any] = {"slot": int(m["slot"]), "state": m["state"]}
            if m["temp"]:
                e["temperature_c"] = to_num(m["temp"])
            if m["cpu_total"]:
                e["cpu_total_percent"], e["cpu_interrupt_percent"] = int(m["cpu_total"]), int(m["cpu_int"])
            if m["l1"]:
                e["cpu_load"] = {"1min": int(m["l1"]), "5min": int(m["l5"]), "15min": int(m["l15"])}
            if m["dram"]:
                e["dram_mb"], e["heap_percent"], e["buffer_percent"] = int(m["dram"]), int(m["heap"]), int(m["buf"])
            if m["comment"].strip():
                e["comment"] = m["comment"].strip()
            out.append(e)
        return out

    def _pic_status(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            m = re.match(r"^\s*Slot (?P<slot>\d+)\s+(?P<state>\S+)\s+(?P<desc>.*)$", raw)
            if m:
                cur = {"slot": int(m["slot"]), "state": m["state"], "description": m["desc"].strip(), "pics": []}
                out.append(cur)
                continue
            m = re.match(r"^\s*PIC (?P<pic>\d+)\s+(?P<state>\S+)\s+(?P<desc>.*)$", raw)
            if m and cur is not None:
                cur["pics"].append({"pic": int(m["pic"]), "state": m["state"], "description": m["desc"].strip()})
        return out


@register("junos", "show chassis environment [(<component>|fpc|routing-engine|pem|cb)]")
class ShowChassisEnvironment(Parser):
    """Temperature, power and fan status per component."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        cls = None
        for raw in text.splitlines():
            if re.match(r"^\s*Class\s+Item\s+Status", raw) or not raw.strip():
                continue
            m = re.match(r"^(?P<cls>\S+)?\s+(?P<item>\S.*?)\s{2,}(?P<status>OK|Check|Failed|Absent|Present|Testing|Offline|Online|Empty|Warning|Critical|\S+)(?:\s+(?P<meas>.+?))?\s*$", raw)
            if m:
                if m["cls"] and not raw.startswith(" "):
                    cls = m["cls"]
                e: Dict[str, Any] = {"class": cls, "item": m["item"].strip(), "status": m["status"]}
                meas = m["meas"]
                if meas:
                    tm = re.match(r"(-?\d+) degrees C", meas)
                    if tm:
                        e["temperature_c"] = int(tm.group(1))
                    else:
                        e["measurement"] = meas
                out.append(e)
        return out


@register("junos", "show system users [no-resolve]")
class ShowSystemUsers(Parser):
    """Logged in users and system load."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"users": []}
        m = re.search(r"up\s+(?P<up>.+?),\s+(?P<n>\d+) users?,\s+load averages?:\s*(?P<l1>[\d.]+),\s*(?P<l5>[\d.]+),\s*(?P<l15>[\d.]+)", text)
        if m:
            out["uptime"] = m["up"]
            out["user_count"] = int(m["n"])
            out["load_average"] = {"1min": float(m["l1"]), "5min": float(m["l5"]), "15min": float(m["l15"])}
        for m in match_lines(r"^\s*(?P<user>\S+)\s+(?P<tty>(?:pts|tty|console|vty|d\d|p\d|u\d)\S*)\s+(?P<from>\S+)\s+(?P<login>\S+)\s+(?P<idle>\S+)\s+(?P<what>.*?)\s*$", text):
            if m["user"] == "USER":
                continue
            out["users"].append({"user": m["user"], "tty": m["tty"], "from": m["from"], "login": m["login"], "idle": None if m["idle"] == "-" else m["idle"], "what": m["what"]})
        return out


@register("junos", "show system storage [(detail|no-forwarding|invoke-on all-routing-engines)]")
class ShowSystemStorage(Parser):
    """Filesystem usage."""

    def parse(self, text: str) -> Any:
        members: Dict[str, Any] = {}
        for name, body in split_re_sections(text):
            rows = []
            for m in match_lines(r"^\s*(?P<fs>\S+)\s+(?P<size>[\d.]+[KMGTPB]?)\s+(?P<used>[\d.]+[KMGTPB]?)\s+(?P<avail>-?[\d.]+[KMGTPB]?)\s+(?P<cap>\d+)%\s+(?P<mount>\S.*?)\s*$", body):
                rows.append({"filesystem": m["fs"], "size": m["size"], "used": m["used"], "available": m["avail"], "capacity_percent": int(m["cap"]), "mounted_on": m["mount"]})
            members[name or "local"] = rows
        return next(iter(members.values())) if len(members) == 1 else members


@register("junos", "show ntp associations [no-resolve]")
class ShowNtpAssociations(Parser):
    """NTP peers with stratum, reach, delay/offset/jitter."""

    def parse(self, text: str) -> Dict[str, Any]:
        peers = []
        for m in match_lines(
            r"^(?P<tally>[ x.\-+#*o])(?P<remote>\S+)\s+(?P<refid>\S+)\s+(?P<st>\d+)\s+(?P<t>\S)\s+(?P<when>\S+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s+(?P<delay>[-\d.]+)\s+(?P<offset>[-+\d.]+)\s+(?P<jitter>[-\d.]+)\s*$", text):
            tally = m["tally"].strip()
            peers.append(
                {
                    "remote": m["remote"],
                    "refid": m["refid"],
                    "stratum": int(m["st"]),
                    "type": m["t"],
                    "when": to_num(m["when"]),
                    "poll": int(m["poll"]),
                    "reach": to_num(m["reach"]),
                    "delay": float(m["delay"]),
                    "offset": float(m["offset"]),
                    "jitter": float(m["jitter"]),
                    "tally": tally or None,
                    "synced": tally == "*",
                }
            )
        return {"peers": peers}


@register("junos", "show system commit [(revision <rev>|include <what>)]")
class ShowSystemCommit(Parser):
    """Commit history."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?P<idx>\d+)\s+(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+) by (?P<user>\S+) via (?P<client>\S+)(?:\s+(?P<comment>.+?))?\s*$", text):
            e = {"index": int(m["idx"]), "timestamp": m["ts"], "user": m["user"], "client": m["client"]}
            if m["comment"]:
                e["comment"] = m["comment"]
            out.append(e)
        return out


@register("junos", "show chassis cluster status [redundancy-group <rg>]")
class ShowChassisClusterStatus(Parser):
    """SRX cluster redundancy groups and node priorities/status."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"redundancy_groups": {}}
        m = re.search(r"Cluster ID:\s*(\d+)", text)
        if m:
            out["cluster_id"] = int(m.group(1))
        rg = None
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^Redundancy group:\s*(\d+)\s*,\s*Failover count:\s*(\d+)", s)
            if m:
                rg = out["redundancy_groups"][m.group(1)] = {"failover_count": int(m.group(2)), "nodes": []}
                continue
            m = re.match(r"^(?P<node>node\d+)\s+(?P<prio>\d+)\s+(?P<status>\S+)\s+(?P<preempt>\S+)\s+(?P<manual>\S+)(?:\s+(?P<monitor>\S+))?", s)
            if m and rg is not None:
                rg["nodes"].append({"node": m["node"], "priority": int(m["prio"]), "status": m["status"], "preempt": m["preempt"], "manual_failover": m["manual"], "monitor_failures": m["monitor"]})
        return out


@register("junos", "show system processes [(summary|brief|extensive)]")
class ShowSystemProcessesSummary(Parser):
    """Process table (``top`` style) with CPU/memory headline."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = re.search(r"last pid:\s*(\d+);\s*load averages:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", text)
        if m:
            out["last_pid"] = int(m.group(1))
            out["load_average"] = {"1min": float(m.group(2)), "5min": float(m.group(3)), "15min": float(m.group(4))}
        m = re.search(r"CPU:\s*(.+)$", text, re.M)
        if m:
            out["cpu"] = {k.strip().replace(" ", "_"): float(v) for v, k in re.findall(r"([\d.]+)% (\w+(?: \w+)?)", m.group(1))}
        m = re.search(r"^Mem:\s*(.+)$", text, re.M)
        if m:
            out["memory"] = {k.lower(): v for v, k in re.findall(r"(\S+) (\w+)", m.group(1))}
        procs = []
        for pm in match_lines(r"^\s*(?P<pid>\d+)\s+(?P<user>\S+)\s+(?:(?P<thr>\d+)\s+)?(?P<pri>-?\d+)\s+(?P<nice>-?\w+)\s+(?P<size>\S+)\s+(?P<res>\S+)\s+(?P<state>\S+)\s+(?:(?P<c>\d+)\s+)?(?P<time>\S+)\s+(?P<wcpu>[\d.]+)%\s+(?P<cmd>.+?)\s*$", text):
            procs.append({"pid": int(pm["pid"]), "user": pm["user"], "threads": int(pm["thr"]) if pm["thr"] else None, "priority": int(pm["pri"]), "nice": to_num(pm["nice"]), "size": pm["size"], "resident": pm["res"], "state": pm["state"], "time": pm["time"], "cpu_percent": float(pm["wcpu"]), "command": pm["cmd"]})
        out["processes"] = procs
        return out
