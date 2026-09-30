"""IOS XR system / platform commands."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ...models import record, seconds
from ...registry import Parser, register
from ...textutils import blocks, compact, match_lines, parse_table, search, to_num


@register("iosxr", "show version [brief]", intent="system.version")
class ShowVersion(Parser):
    """Software version, platform, uptime and packages."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = search(r"Cisco IOS XR Software, Version (?P<version>[^\s\[]+)(?:\[(?P<label>[^\]]+)\])?[ \t]*(?P<train>[^\s\[]+)?[ \t]*$", text)
        if m:
            out["software"] = "Cisco IOS XR"
            out["version"] = str(m["version"])
            if m.get("label"):
                out["image_label"] = m["label"]
            if m.get("train"):
                out["train"] = m["train"]
        m = search(r"^ Label\s*:\s*(?P<label>\S+)", text)
        if m:
            out["label"] = str(m["label"])
        build = {}
        for k, v in re.findall(r"^[ \t]+(Built By|Built On|Build Host|Built Host|Workspace|Version|Location|Label)\s*:\s*(.+)$", text, re.M):
            build[k.lower().replace(" ", "_").replace("built_host", "build_host")] = v.strip()
        if build:
            out["build_information"] = build
        m = search(r"^ROM: (?P<rom>.+?)\s*$", text)
        if m:
            out["rom"] = m["rom"]
        m = search(r"^(?P<host>\S+) uptime is (?P<uptime>.+?)\s*$", text)
        if m:
            if m["host"] != "System":
                out["hostname"] = m["host"]
            out["uptime"] = m["uptime"]
            out["uptime_seconds"] = seconds(m["uptime"])
        m = search(r'^System image file is "(?P<image>[^"]+)"', text)
        if m:
            out["system_image"] = m["image"]
        m = re.search(r"^cisco (?P<chassis>\S+(?: \S+)*?) \((?P<processor>.*)\) processor(?: with (?P<memory>\S+?(?: bytes)?) of memory)?", text, re.M | re.I)
        if m:
            out["chassis"] = m["chassis"]
            if m["processor"]:
                out["processor"] = m["processor"]
            if m["memory"]:
                out["memory"] = m["memory"]
        m = search(r"^(?P<desc>(?:ASR|NCS|Cisco|CRS|XRv|IOS-XRv)[^\n]*(?:Chassis|RU|w/IOS XR[^\n]*|Slot[^\n]*))\s*$", text)
        if m:
            out["chassis_description"] = m["desc"]
        m = search(r"^Configuration register on node (?P<node>\S+) is (?P<reg>\S+)", text)
        if m:
            out["config_register"] = str(m["reg"])
        interfaces = {}
        for count, name in re.findall(r"^(\d+) ((?:[\w/]+ )*(?:Ethernet|GigabitEthernet|TenGigE|SONET/SDH|Packet over SONET/SDH|WANPHY controller\(s\)|FastEthernet|HundredGigE|FortyGigE|serial|Serial))\s*$", text, re.M):
            interfaces[name] = int(count)
        if interfaces:
            out["interface_counts"] = interfaces
        packages = re.findall(r"^[ \t]{4,}(\S+-\S+)$", text, re.M)
        if packages:
            out["packages"] = packages
        return out

    def normalize(self, d: Dict[str, Any]) -> Dict[str, Any]:
        return record(
            "system.version",
            hostname=d.get("hostname"),
            vendor="Cisco",
            os="IOS XR",
            version=d.get("version"),
            model=d.get("chassis"),
            uptime=d.get("uptime"),
            uptime_seconds=d.get("uptime_seconds"),
        )


@register("iosxr", "show inventory [(all|raw|chassis|location <location>|details)]", "admin show inventory", intent="inventory")
class ShowInventory(Parser):
    """Hardware inventory (NAME/DESCR/PID/VID/SN)."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cur: Dict[str, Any] = {}
        for ln in text.splitlines():
            m = re.match(r'^\s*NAME:\s*"(?P<name>[^"]*)"\s*,\s*DESCR:\s*"(?P<descr>[^"]*)"', ln)
            if m:
                cur = {"name": m["name"], "description": m["descr"].strip()}
                items.append(cur)
                continue
            m = re.match(r"^\s*PID:\s*(?P<pid>.*?)\s*,\s*VID:\s*(?P<vid>.*?)\s*,\s*SN:\s*(?P<sn>.*?)\s*$", ln)
            if m and cur:
                cur["pid"] = m["pid"] or None
                cur["vid"] = m["vid"] or None
                cur["sn"] = m["sn"] or None
        return items

    def normalize(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            record("inventory", name=i["name"], description=i.get("description"), part_number=i.get("pid"), serial_number=i.get("sn"), version=i.get("vid"))
            for i in data
        ]


@register("iosxr", "show platform [(vm|location <location>)]", "admin show platform")
class ShowPlatform(Parser):
    """Line cards, RPs, fans and PSUs with their state."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        rows = parse_table(text, header=r"^\s*(?:Node|Location)\s+(?:Type|Card Type)\s", convert=False)
        out = []
        for r in rows:
            node = r.pop("node", None) or r.pop("location", None)
            if not node or not re.match(r"^\d+/", node):
                continue
            item: Dict[str, Any] = {"node": node}
            typ = r.pop("type", None) or r.pop("card_type", None)
            if typ:
                m = re.match(r"^(.*?)\((Active|Standby)\)$", typ)
                if m:
                    item["type"], item["redundancy_state"] = m.group(1), m.group(2)
                else:
                    item["type"] = typ
            for k, v in r.items():
                if v is not None:
                    item[k] = v
            out.append(item)
        return out


@register("iosxr", "show platform summary location all", "show platform summary location <location>")
class ShowPlatformSummaryLocation(Parser):
    """Detailed per-node platform summary."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        out = []
        for b in blocks(text, start=r"^\s*Platform Node\s*:"):
            item: Dict[str, Any] = {}
            last = None
            for ln in b.splitlines():
                m = re.match(r"^\s*([A-Za-z][\w /]*?)\s*:\s*(.*)$", ln)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_").replace("/", "_")
                    item[key] = m.group(2).strip()
                    last = key
                elif ln.strip().startswith(":") and last:
                    item[last] += " " + ln.strip()[1:].strip()
                elif ln.strip() and last and not set(ln.strip()) <= set("-"):
                    item[last] += " " + ln.strip()
            m = re.match(r"^(\S+)(?: \(slot (\d+)\))?", item.get("platform_node", ""))
            if m:
                item["node"] = m.group(1)
                if m.group(2):
                    item["slot"] = int(m.group(2))
            if "vid_sn" in item:
                vid, _, sn = item.pop("vid_sn").partition("/")
                item["vid"], item["serial_number"] = vid.strip(), sn.strip()
            out.append(item)
        return out


@register("iosxr", "show redundancy [(summary|location <location>)]")
class ShowRedundancySummary(Parser):
    """RP redundancy pairs and NSR readiness."""

    def parse(self, text: str) -> Dict[str, Any]:
        pairs = []
        for m in match_lines(r"^\s*(?P<active>\d+/\S+?)\((?P<ar>\w)\)\s+(?P<standby>\S+?)(?:\((?P<sr>\w)\))?\s*(?:\((?P<status>[^)]*)\))?\s*$", text):
            status = m["status"] or ""
            item: Dict[str, Any] = {
                "active": m["active"],
                "active_role": {"A": "active", "P": "primary"}.get(m["ar"], m["ar"]),
                "standby": None if m["standby"] in ("N/A", "n/a") else m["standby"],
            }
            if m["sr"]:
                item["standby_role"] = {"S": "standby", "B": "backup"}.get(m["sr"], m["sr"])
            if status:
                parts = [p.strip() for p in status.split(",")]
                item["standby_state"] = parts[0]
                for p in parts[1:]:
                    k, _, v = p.partition(":")
                    item[k.strip().lower()] = v.strip()
            pairs.append(item)
        out: Dict[str, Any] = {"pairs": pairs}
        m = search(r"Redundancy information for node (?P<node>\S+):", text)
        if m:
            out["node"] = m["node"]
        return out


@register("iosxr", "show processes cpu [(location <location>|sorted|summary)]", intent="cpu")
class ShowProcessesCpu(Parser):
    """CPU utilisation (1/5/15 minutes) and per-process usage."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = search(r"CPU utilization for one minute: (?P<one>\d+)%; five minutes: (?P<five>\d+)%; fifteen minutes: (?P<fifteen>\d+)%", text)
        if m:
            out = {"one_minute": m["one"], "five_minutes": m["five"], "fifteen_minutes": m["fifteen"]}
        procs = []
        for pm in match_lines(r"^\s*(?P<pid>\d+)\s+(?P<m1>\d+)%\s+(?P<m5>\d+)%\s+(?P<m15>\d+)%\s+(?P<name>\S.*?)\s*$", text):
            procs.append({"pid": int(pm["pid"]), "name": pm["name"], "one_minute": int(pm["m1"]), "five_minutes": int(pm["m5"]), "fifteen_minutes": int(pm["m15"])})
        out["processes"] = procs
        return out

    def normalize(self, d: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [record("cpu", location=self.params.get("location"), one_minute=d.get("one_minute"), five_minute=d.get("five_minutes"))]


@register("iosxr", "show memory summary [(location <location>|detail)]", "show memory-summary")
class ShowMemorySummary(Parser):
    """Physical/application memory per node."""

    def parse(self, text: str) -> Dict[str, Any]:
        nodes: Dict[str, Any] = {}
        cur: Dict[str, Any] = nodes.setdefault("default", {})
        for ln in text.splitlines():
            m = re.match(r"^node:\s+node(\S+)", ln)
            if m:
                cur = nodes.setdefault(m.group(1).replace("_", "/"), {})
                nodes.pop("default", None) if not nodes.get("default") else None
                continue
            m = re.match(r"^\s*(Physical Memory|Application Memory|Image|Reserved|IOMem|flashfsys|Total shared window|Total used|Free Memory|Total Memory|Used Memory)\s*:\s*(\S+)(?:\s*\((\S+) available\))?", ln, re.I)
            if m:
                key = m.group(1).lower().replace(" ", "_")
                cur[key] = m.group(2)
                if m.group(3):
                    cur[key + "_available"] = m.group(3)
        if not nodes.get("default"):
            nodes.pop("default", None)
        return nodes if len(nodes) != 1 or "default" not in nodes else nodes["default"]


@register("iosxr", "show clock [detail]")
class ShowClock(Parser):
    """Device clock."""

    def parse(self, text: str) -> Dict[str, Any]:
        m = re.search(r"(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<tz>\S+)\s+(?P<dow>\w{3})\s+(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<year>\d{4})", text)
        if not m:
            return {}
        return {k: to_num(v) for k, v in m.groupdict().items()}


@register("iosxr", "show users")
class ShowUsers(Parser):
    """Logged in users."""

    def parse(self, text: str) -> List[Dict[str, Any]]:
        rows = parse_table(text, header=r"Line\s+User\s+Service", convert=False)
        out = []
        for r in rows:
            line = r.get("line") or ""
            active = line.startswith("*")
            r["line"] = line.lstrip("* ").strip()
            r["current_session"] = active
            out.append({k: v for k, v in r.items() if v is not None})
        return out


@register("iosxr", "show install active [summary]", "show install [(active|committed)] summary")
class ShowInstallActive(Parser):
    """Active software packages per node."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = search(r"^[ \t]*Label\s*:\s*(?P<label>\S+)", text)
        if m:
            out["label"] = str(m["label"])
        m = search(r"^[ \t]*Software Hash:\s*(?P<h>\S+)", text)
        if m:
            out["software_hash"] = m["h"]
        m = search(r"Active Packages:\s+XR:\s*(?P<xr>\d+)\s+All:\s*(?P<all>\d+)", text)
        if m:
            out["package_counts"] = {"xr": m["xr"], "all": m["all"]}
        nodes: Dict[str, Any] = {}
        node = None
        packages: List[Dict[str, Any]] = []
        in_pkgs = in_table = False
        for ln in text.splitlines():
            s = ln.strip()
            m1 = re.match(r"^Node (\S+) \[(\w+)\](?: \[SDR: ([^\]]+)\])?", s)
            if m1:
                node = m1.group(1)
                nodes[node] = {"type": m1.group(2), "packages": []}
                if m1.group(3):
                    nodes[node]["sdr"] = m1.group(3)
                in_pkgs = False
                continue
            m2 = re.match(r"^(Boot Partition|Boot Device|Boot Image):\s*(\S+)", s)
            if m2 and node:
                nodes[node][m2.group(1).lower().replace(" ", "_")] = m2.group(2)
                continue
            if re.match(r"^(Optional Packages|Package)\s+Version", s):
                in_table = True
                continue
            if in_table:
                m3 = re.match(r"^(\S+)\s+(\S+)$", s)
                if m3 and not set(s) <= set("- "):
                    packages.append({"name": m3.group(1), "version": m3.group(2)})
                continue
            if re.match(r"^Active Packages:\s*(\d+)?\s*$", s):
                in_pkgs = True
                continue
            if not s or re.match(r"^(Inactive Packages|Committed Packages|Default Profile|SDRs|Secure Domain Router|Label|Software Hash)\b", s):
                in_pkgs = False
                continue
            m4 = re.match(r"^(?:disk\d:|harddisk:)?(\S+?)(?:\s+version=(\S+))?(?:\s+\[(.+)\])?$", s)
            if in_pkgs and m4:
                pkg: Dict[str, Any] = {"name": m4.group(1)}
                if m4.group(2):
                    pkg["version"] = m4.group(2)
                if m4.group(3):
                    pkg["note"] = m4.group(3)
                (nodes[node]["packages"] if node else packages).append(pkg)
        if nodes:
            out["nodes"] = nodes
        if packages:
            out["packages"] = packages
        return out


@register("iosxr", "show ntp associations [detail]", "show ntp associations vrf <vrf>")
class ShowNtpAssociations(Parser):
    """NTP peers with stratum, reach, delay/offset/dispersion."""

    def parse(self, text: str) -> Dict[str, Any]:
        peers = []
        for m in match_lines(
            r"^(?P<flags>[*#+\-~ox ]{0,3})(?P<address>[\d.:a-fA-F]+|\S+)\s+(?P<ref>\S+)\s+(?P<st>\d+)\s+(?P<when>\S+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s+(?P<delay>[-\d.]+)\s+(?P<offset>[-\d.]+)\s+(?P<disp>[-\d.]+)\s*$", text):
            flags = m["flags"].strip()
            peers.append(
                {
                    "address": m["address"],
                    "reference_clock": m["ref"],
                    "stratum": int(m["st"]),
                    "when": to_num(m["when"]),
                    "poll": int(m["poll"]),
                    "reach": to_num(m["reach"]),
                    "delay": float(m["delay"]),
                    "offset": float(m["offset"]),
                    "dispersion": float(m["disp"]),
                    "synced": "*" in flags,
                    "configured": "~" in flags,
                    "flags": flags or None,
                }
            )
        return {"peers": [compact(p) for p in peers]}


@register("iosxr", "show logging [last <count>]", "show logging [(start|end) <when...>]")
class ShowLogging(Parser):
    """Syslog configuration counters and buffered log entries."""

    def parse(self, text: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        m = search(r"Syslog logging: (?P<state>\w+)", text)
        if m:
            out["syslog_logging"] = m["state"]
        m = search(r"Buffer logging: level (?P<level>\w+), (?P<n>\d+) messages logged", text)
        if m:
            out["buffer_logging"] = {"level": m["level"], "messages_logged": m["n"]}
        entries = []
        rx = re.compile(
            r"^(?:(?P<node>(?:RP|LC)/\d+/\S+?):)?(?P<ts>\w{3}\s+\d+\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d(?:\.\d+)?)(?:\s+\w+)?\s*:\s*(?P<process>[\w\-.]+)\[(?P<pid>\d+)\]:\s*%(?P<facility>[\w\-]+)-(?P<severity>\d)-(?P<mnemonic>[\w\-]+)\s*:\s*(?P<message>.*)$"
        )
        for ln in text.splitlines():
            mm = rx.match(ln.strip())
            if mm:
                e = {k: v for k, v in mm.groupdict().items() if v is not None}
                e["severity"] = int(e["severity"])
                e["pid"] = int(e["pid"])
                entries.append(e)
        out["entries"] = entries
        return out
