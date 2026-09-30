#!/usr/bin/env python3
"""Run every supported command on live/emulated routers, save outputs and report parser coverage.

    python scripts/harvest.py lab/inventory.yml --out harvest/ [--only iosxr] [--commands-file extra.txt]

Inventory (YAML or JSON)::

    devices:
      - host: 10.0.0.1
        platform: iosxr
        username: lab            # optional, else $CLIJSON_USERNAME
        password: lab123         # optional, else $CLIJSON_PASSWORD
        extra_commands: ["show segment-routing srv6 sid"]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import clijson  # noqa: E402
from clijson.commands import slugify  # noqa: E402
from clijson.live import collect  # noqa: E402

SKIP_PREFIXES = (
    "show running-config",
    "show configuration",
    "display current-configuration",
    "display saved-configuration",
)


def load_inventory(path: Path) -> list:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yml", ".yaml"):
        import yaml

        return yaml.safe_load(text)["devices"]
    return json.loads(text)["devices"]


def commands_for(platform: str) -> list:
    seen = []
    for row in clijson.supported_commands(platform):
        cmd = row["example"]
        if "<" in cmd or cmd in seen or cmd.startswith(SKIP_PREFIXES) or cmd.split()[0] in ("admin", "dir"):
            continue
        seen.append(cmd)
    return seen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inventory", type=Path)
    ap.add_argument("--out", type=Path, default=Path("harvest"))
    ap.add_argument("--only", help="only this platform")
    ap.add_argument("--commands-file", type=Path, help="extra commands, one per line")
    args = ap.parse_args()

    extra = [c.strip() for c in args.commands_file.read_text().splitlines() if c.strip()] if args.commands_file else []
    report = []
    for dev in load_inventory(args.inventory):
        platform = clijson.get_platform(dev["platform"]).name
        if args.only and clijson.get_platform(args.only).name != platform:
            continue
        cmds = commands_for(platform) + list(dev.get("extra_commands", [])) + extra
        user = dev.get("username") or os.environ.get("CLIJSON_USERNAME")
        pwd = dev.get("password") or os.environ.get("CLIJSON_PASSWORD")
        print(f"{dev['host']}: running {len(cmds)} commands ...", file=sys.stderr)
        try:
            results = collect(dev["host"], platform, cmds, username=user, password=pwd, port=dev.get("port", 22))
        except clijson.CliJsonError as exc:
            print(f"  ! {exc}", file=sys.stderr)
            continue
        folder = args.out / dev["host"]
        folder.mkdir(parents=True, exist_ok=True)
        counts: Counter = Counter()
        for cmd, res in zip(cmds, results):
            (folder / f"{slugify(cmd)}.txt").write_text(res.raw or "", encoding="utf-8")
            if any(" failed (" in w for w in res.warnings):
                kind = "failed"
            else:
                kind = res.engine if res.engine in ("native", "generic", "device-error") else "other"
            counts[kind] += 1
            (folder / f"{slugify(cmd)}.json").write_text(res.to_json(meta=True), encoding="utf-8")
        report.append((dev["host"], platform, counts))

    print(f"\n{'host':<28}{'platform':<10}{'native':>8}{'generic':>9}{'device-error':>14}{'failed':>8}")
    for host, platform, c in report:
        print(f"{host:<28}{platform:<10}{c['native']:>8}{c['generic']:>9}{c['device-error']:>14}{c['failed']:>8}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
