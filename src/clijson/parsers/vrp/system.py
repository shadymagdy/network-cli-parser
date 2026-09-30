"""Huawei VRP system and hardware commands."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import record, seconds
from ...registry import Parser, register
from ...textutils import compact, match_lines, none_if, snake, to_num


@register("vrp", "display version [slot <slot>]", intent="system.version")
class DisplayVersion(Parser):
    """VRP version, product, patch, uptime and per-board hardware/firmware versions."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = re.search(r"VRP \(R\) software, Version (?P<vrp>\S+)\s+\((?P<product>.+?)\s+(?P<release>V\d{3}R\d{3}\S*)\)", text)
        if m:
            out["vrp_version"] = m["vrp"]
            out["product_series"] = m["product"]
            out["version"] = m["release"]
        m = re.search(r"^(?:HUAWEI|Huawei|Quidway)\s+(?P<model>.+?)(?: Router| Terabit Routing Switch| Routing Switch| Switch)? uptime is (?P<up>.+?)\s*$", text, re.M)
        if m:
            out["model"] = m["model"].strip()
            out["uptime"] = m["up"]
            out["uptime_seconds"] = seconds(m["up"])
        m = re.search(r"^Patch Version\s*:\s*(\S+)", text, re.M)
        if m:
            out["patch_version"] = m.group(1)
        boards: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            s = raw.strip()
            bm = re.match(r"^(?P<type>[A-Z][A-Z0-9]{1,6})\s*(?:\((?P<role>Master|Slave)\)\s*)?(?P<slot>\d+)?\s*(?:\((?P<role2>Master|Slave)\))?\s*:\s*uptime is (?P<up>.+?)\s*$", s)
            if bm:
                cur = {"board": bm["type"], "slot": to_num(bm["slot"]) if bm["slot"] else None, "role": (bm["role"] or bm["role2"] or "").lower() or None, "uptime": bm["up"], "versions": {}}
                boards.append(cur)
                continue
            cm = re.match(r"^(?P<name>[A-Z][A-Za-z0-9]*?)(?:'s)?\s*(?P<slot>\d+)?(?:'s)?\s+version information\s*:?\s*$", s)
            if cm and (cur is None or cm["name"] != cur["board"]):
                cur = {"board": cm["name"], "slot": to_num(cm["slot"]) if cm["slot"] else None, "versions": {}}
                boards.append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^(?:\d+\.\s*)?(?P<k>[A-Za-z][\w ]*?)\s+Version\s*:\s*(?P<v>.+)$", s)
            if m:
                cur["versions"][snake(m["k"])] = m["v"].strip()
                continue
            m = re.match(r"^(?P<k>SDRAM|FLASH|Flash \d|Flash|NVRAM|CFCARD\d?|CF Card\d?)\s+Memory Size\s*:\s*(?P<v>\d+)\s*(?P<u>[KMG])\s*bytes", s, re.I)
            if m:
                cur[snake(m["k"]) + "_memory_" + m["u"].lower() + "b"] = int(m["v"])
                continue
            m = re.match(r"^StartupTime\s*:?\s*(?P<t>\d{4}/\d\d/\d\d\s+\d\d:\d\d:\d\d)", s)
            if m and "startup_time" not in cur:
                cur["startup_time"] = re.sub(r"\s+", " ", m["t"])
                continue
            m = re.match(r"^(?:\d+\.\s*)?Board\s+Type\s*:\s*(?P<v>.+)$", s)
            if m:
                cur["board_type"] = m["v"].strip()
        if boards:
            out["boards"] = [b for b in (compact(b) for b in boards) if len(b) > 1]
        return out

    def normalize(self, d: Dict[str, Any]) -> Dict[str, Any]:
        return record("system.version", vendor="Huawei", os="VRP", version=d.get("version") or d.get("vrp_version"), model=d.get("model"), uptime=d.get("uptime"), uptime_seconds=d.get("uptime_seconds"))


@register("vrp", "display device [(slot <slot>|pic-status|elabel|manufacture-info)]")
class DisplayDevice(Parser):
    """Boards, power supplies and fans with online/registration/alarm status."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"slots": []}
        m = re.search(r"^(?P<dev>\S+)'s Device status:", text, re.M)
        if m:
            out["device"] = m["dev"]
        for m in match_lines(r"^(?P<slot>\S+)\s+(?P<card>\S+)\s+(?P<type>\S+(?:\(\S+ \d+\))?)\s+(?P<online>Present|Absent|Online|Offline)\s+(?P<power>On|Off|-)\s+(?P<reg>Registered|Unregistered|-)\s+(?P<alarm>\S+)\s+(?P<primary>\S+)\s*$", text):
            out["slots"].append({"slot": to_num(m["slot"]), "card": none_if(m["card"]), "type": m["type"], "online": m["online"], "power": m["power"], "register": m["reg"], "alarm": m["alarm"], "primary": none_if(m["primary"], "NA")})
        if not out["slots"]:
            for m in match_lines(r"^(?P<slot>\d+/\d+)\s+(?P<type>\S+)\s+(?P<online>Present|Absent)\s+(?P<power>On|Off|-)\s+(?P<reg>Registered|Unregistered|-)\s+(?P<alarm>\S+)\s*$", text):
                out["slots"].append({"slot": m["slot"], "type": m["type"], "online": m["online"], "power": m["power"], "register": m["reg"], "alarm": m["alarm"]})
        if not out["slots"]:
            # S/AR series layout: Slot Sub Type Online Power Register Status Role
            for m in match_lines(r"^(?P<slot>\d+)\s+(?P<sub>\S+)\s+(?P<type>\S+)\s+(?P<online>Present|Absent)\s+(?P<power>PowerOn|PowerOff|On|Off)\s+(?P<reg>Registered|Unregistered|-)\s+(?P<status>\S+)\s+(?P<role>\S+)\s*$", text):
                out["slots"].append({"slot": int(m["slot"]), "sub": none_if(m["sub"]), "type": m["type"], "online": m["online"], "power": m["power"], "register": m["reg"], "status": m["status"], "role": none_if(m["role"], "NA")})
        return out


@register("vrp", "display cpu-usage [(slot <slot>|history|configuration)]", "display cpu [(slot <slot>)]", intent="cpu")
class DisplayCpuUsage(Parser):
    """CPU utilisation (current, 5 s / 1 min / 5 min, max) and top tasks."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = re.search(r"CPU Usage\s*:\s*(\d+)%\s*Max:\s*(\d+)%", text)
        if m:
            out["current_percent"], out["max_percent"] = int(m.group(1)), int(m.group(2))
        m = re.search(r"CPU utilization for five seconds:\s*(\d+)%[:,]?\s*one minute:\s*(\d+)%[:,]?\s*five minutes:\s*(\d+)%", text)
        if m:
            out["five_seconds_percent"], out["one_minute_percent"], out["five_minutes_percent"] = int(m.group(1)), int(m.group(2)), int(m.group(3))
        m = re.search(r"CPU Usage Stat\. Cycle:\s*(\d+)", text)
        if m:
            out["stat_cycle_seconds"] = int(m.group(1))
        m = re.search(r"CPU Usage Stat\. Time\s*:\s*(.+)", text)
        if m:
            out["stat_time"] = m.group(1).strip()
        m = re.search(r"Max CPU Usage Stat\. Time\s*:\s*(.+?)\.?\s*$", text, re.M)
        if m:
            out["max_stat_time"] = m.group(1).strip()
        # CE / NE layout
        m = re.search(r"System cpu use rate is\s*:\s*(\d+)%", text)
        if m:
            out["current_percent"] = int(m.group(1))
        m = re.search(r"Cpu utilization statistics at (.+?)\s*$", text, re.M | re.I)
        if m:
            out["stat_time"] = m.group(1)
        tasks = []
        for tm in match_lines(r"^\s*(?P<name>\S+)\s+(?P<cpu>\d+)%\s+(?P<rt>\S+/\s*\S+)\s*(?P<desc>.*?)\s*$", text):
            tasks.append({"task": tm["name"], "cpu_percent": int(tm["cpu"]), "runtime": re.sub(r"\s+", "", tm["rt"]), "description": tm["desc"] or None})
        if tasks:
            out["tasks"] = tasks
        return out

    def normalize(self, d: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("cpu", location=self.params.get("slot"), five_second=d.get("five_seconds_percent"), one_minute=d.get("one_minute_percent", d.get("current_percent")), five_minute=d.get("five_minutes_percent"))]


@register("vrp", "display memory-usage [(slot <slot>)]", "display memory [(slot <slot>)]")
class DisplayMemoryUsage(Parser):
    """Memory totals and utilisation."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = re.search(r"Memory utilization statistics at (.+?)\s*$", text, re.M)
        if m:
            out["stat_time"] = m.group(1)
        m = re.search(r"System Total Memory Is:?\s*(\d+)\s*(\w+)", text)
        if m:
            out["total"], out["unit"] = int(m.group(1)), m.group(2)
        m = re.search(r"Total Memory Used Is:?\s*(\d+)\s*(\w+)", text)
        if m:
            out["used"] = int(m.group(1))
        m = re.search(r"Memory Using Percentage(?: Is)?:?\s*(\d+)%", text)
        if m:
            out["used_percent"] = int(m.group(1))
        if "total" in out and "used" in out:
            out["free"] = out["total"] - out["used"]
        return out


@register("vrp", "display clock [utc]")
class DisplayClock(Parser):
    """Device date, time, weekday and time zone."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = re.search(r"(?P<date>\d{4}-\d\d-\d\d)\s+(?P<time>\d\d:\d\d:\d\d(?:\.\d+)?)(?P<off>[+-]\d\d:\d\d)?(?:\s+(?P<dst>DST))?", text)
        if m:
            out["date"], out["time"] = m["date"], m["time"]
            if m["off"]:
                out["utc_offset"] = m["off"]
            if m["dst"]:
                out["dst"] = True
        m = re.search(r"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s*$", text, re.M)
        if m:
            out["weekday"] = m.group(1)
        m = re.search(r"Time Zone(?:\((?P<name>[^)]*)\))?\s*:\s*(?P<tz>\S+)", text)
        if m:
            out["time_zone"] = m["tz"]
            if m["name"]:
                out["time_zone_name"] = m["name"]
        return out


@register("vrp", "display users [all]")
class DisplayUsers(Parser):
    """Logged in users (``+`` marks the current session)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        last: Optional[Dict[str, Any]] = None
        for raw in text.splitlines():
            m = re.match(r"^(?P<cur>[+*])?\s*(?P<idx>\d+)\s+(?P<intf>(?:VTY|CON|AUX|TTY|NCA)\s*\d+)\s+(?P<delay>\S+)\s+(?P<type>\S+)?\s+(?P<addr>[\d.:a-fA-F]+)?\s+(?P<auth>pass|fail|\S+)?\s*(?P<flag>yes|no)?\s*$", raw)
            if m:
                last = compact({"index": int(m["idx"]), "interface": re.sub(r"\s+", " ", m["intf"]), "delay": m["delay"], "type": m["type"], "address": m["addr"], "authen_status": m["auth"], "author_cmd": m["flag"], "current": bool(m["cur"])})
                out.append(last)
                continue
            m = re.match(r"^\s*Username\s*:\s*(\S+)", raw)
            if m and last is not None:
                last["username"] = m.group(1)
        return out


@register("vrp", "display startup")
class DisplayStartup(Parser):
    """Current and next-startup software, configuration, license and patch files."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        board = "main"
        for raw in text.splitlines():
            s = raw.strip()
            m = re.match(r"^(MainBoard|SlaveBoard|Board \S+)\s*:\s*$", s)
            if m:
                board = snake(m.group(1))
                continue
            m = re.match(r"^(?P<k>[A-Za-z][\w \-]*?)\s*:\s*(?P<v>\S+)\s*$", s)
            if m:
                out.setdefault(board, {})[snake(m["k"])] = none_if(m["v"], "null", "NULL")
        return next(iter(out.values())) if len(out) == 1 else out


@register("vrp", "display patch-information")
class DisplayPatchInformation(Parser):
    """Installed patch package and state."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in match_lines(r"^\s*(?P<k>[A-Za-z][\w \-]*?)\s*:\s*(?P<v>.+?)\s*$", text):
            out[snake(m["k"])] = to_num(m["v"])
        return out


@register("vrp", "display esn", "display sn license", "display license esn")
class DisplayEsn(Parser):
    """Equipment serial number(s)."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in match_lines(r"^\s*(?P<k>ESN of [\w\- ]+?|ESN|SN|Equipment serial number)\s*:\s*(?P<v>\S+)", text):
            out[snake(m["k"])] = m["v"]
        return out


@register("vrp", "display alarm (active|all|history) [verbose]", "display alarm urgent")
class DisplayAlarmActive(Parser):
    """Active / historical alarms."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?P<seq>\d+)\s+(?P<id>0x[0-9A-Fa-f]+)\s+(?P<sev>Critical|Major|Minor|Warning|Indeterminate|Cleared)\s+(?P<date>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:[+-]\d\d:\d\d)?)\s*(?P<desc>.*?)\s*$", text):
            out.append({"sequence": int(m["seq"]), "alarm_id": m["id"], "severity": m["sev"], "time": m["date"], "description": m["desc"]})
        return out


@register("vrp", "display temperature [(all|slot <slot>)]", "display environment")
class DisplayTemperature(Parser):
    """Board temperature sensors with thresholds."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        slot = None
        for raw in text.splitlines():
            m = re.match(r"^\s*SlotID\s*(\S+?)\s*:", raw)
            if m:
                slot = to_num(m.group(1))
                continue
            m = re.match(r"^\s*(?P<pcb>\S+)\s+(?P<i2c>\d+)\s+(?P<addr>\d+)\s+(?P<chl>\d+)\s+(?P<status>\S+)\s+(?P<minor>\d+)\s+(?P<major>\d+)\s+(?P<fatal>\d+)\s+(?P<tmin>\d+)\s+(?P<tmax>\d+)\s+(?P<temp>-?\d+)\s*$", raw)
            if m:
                out.append({"slot": slot, "pcb": m["pcb"], "i2c": int(m["i2c"]), "address": int(m["addr"]), "channel": int(m["chl"]), "status": m["status"], "thresholds": {"minor": int(m["minor"]), "major": int(m["major"]), "fatal": int(m["fatal"])}, "fan_adjust": {"min": int(m["tmin"]), "max": int(m["tmax"])}, "temperature_c": int(m["temp"])})
                continue
            m = re.match(r"^\s*(?P<slot>\d+)\s+(?P<name>\S+(?: \S+)?)\s+(?P<status>NORMAL|ABNORMAL|Normal|Abnormal)\s+(?P<major>\d+)\s+(?P<fatal>\d+)\s+(?P<temp>-?\d+)\s*$", raw)
            if m:
                out.append({"slot": int(m["slot"]), "name": m["name"], "status": m["status"], "thresholds": {"major": int(m["major"]), "fatal": int(m["fatal"])}, "temperature_c": int(m["temp"])})
        return out


@register("vrp", "display ntp status", "display ntp-service status")
class DisplayNtpStatus(Parser):
    """NTP synchronisation state, stratum, reference and offsets."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in match_lines(r"^\s*(?P<k>[A-Za-z][\w \-]*?)\s*:\s*(?P<v>.+?)\s*$", text):
            k, v = snake(m["k"]), m["v"]
            vm = re.match(r"^(-?[\d.]+)\s*(ms|Hz)$", v)
            if vm:
                out[f"{k}_{vm.group(2).lower()}"] = float(vm.group(1))
            else:
                out[k] = to_num(v)
        out["synchronized"] = str(out.get("clock_status", "")).lower().startswith("synchronized")
        return out


@register("vrp", "display ntp sessions [verbose]", "display ntp-service sessions [verbose]")
class DisplayNtpSessions(Parser):
    """NTP peers: reference, stratum, reach, poll, offset, delay, dispersion."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for m in match_lines(r"^\s*(?:(?P<flags>[\[\]0-9]+)\s*)?(?P<src>[\d.:a-fA-F]+|LOCAL\(\d+\))\s+(?P<ref>\S+)\s+(?P<st>\d+)\s+(?P<reach>\d+)\s+(?P<poll>\d+)\s+(?P<now>\S+)\s+(?P<offset>-?[\d.]+)\s+(?P<delay>-?[\d.]+)\s+(?P<disp>-?[\d.]+)\s*$", text):
            out.append({"source": m["src"], "reference": m["ref"], "stratum": int(m["st"]), "reach": int(m["reach"]), "poll": int(m["poll"]), "now": to_num(m["now"]), "offset": float(m["offset"]), "delay": float(m["delay"]), "dispersion": float(m["disp"]), "flags": m["flags"] or None})
        return out
